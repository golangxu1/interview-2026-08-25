// mdnsmap discovers mDNS service records in an IP network.
//
// The program deliberately uses only the Go standard library. mDNS traffic is
// sent to UDP/5353 on each address in the requested network; the user supplied
// port range filters SRV service ports, it does not change the mDNS transport
// port.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	mdnsPort           = 5353
	defaultTimeout     = 1200 * time.Millisecond
	defaultConcurrency = 32
	defaultMaxHosts    = 4096
	absoluteMaxHosts   = 65536
	maxDNSPacket       = 64 * 1024
)

type cliConfig struct {
	network     *net.IPNet
	startPort   int
	endPort     int
	timeout     time.Duration
	concurrency int
	maxHosts    int
	format      string
	interfaceIP string
	zone        string
}

type output struct {
	Hosts []HostResult `json:"hosts"`
}

// HostResult contains all service records associated with one queried address.
type HostResult struct {
	IP       string         `json:"ip"`
	Services []ServiceAsset `json:"services"`
	Answers  []string       `json:"answers,omitempty"`
}

// ServiceAsset is intentionally richer than a simple port finding. TXT data
// is retained because it commonly contains paths, model names and firmware
// versions useful for asset identification.
type ServiceAsset struct {
	Port     int    `json:"port"`
	HasPort  bool   `json:"has_port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Host     string `json:"host"`
	Banner   Banner `json:"banner"`
}

type Banner struct {
	Name     string            `json:"name,omitempty"`
	IPv4     []string          `json:"ipv4,omitempty"`
	IPv6     []string          `json:"ipv6,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
	TTL      uint32            `json:"ttl,omitempty"`
	TXT      map[string]string `json:"txt,omitempty"`
	RawTXT   []string          `json:"raw_txt,omitempty"`
}

func main() {
	var (
		cidr        = flag.String("cidr", "", "target IPv4/IPv6 CIDR, for example 192.168.1.0/24")
		ports       = flag.String("ports", "1-65535", "SRV port range, for example 80 or 1-1024")
		timeout     = flag.Duration("timeout", defaultTimeout, "timeout for each mDNS discovery round")
		concurrency = flag.Int("concurrency", defaultConcurrency, "maximum concurrent hosts")
		maxHosts    = flag.Int("max-hosts", defaultMaxHosts, "maximum addresses to query")
		format      = flag.String("format", "text", "output format: text or json")
		interfaceIP = flag.String("interface", "", "local IP address to use for mDNS queries")
		zone        = flag.String("zone", "", "IPv6 interface zone for link-local targets, for example Ethernet")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "mDNS network asset mapper\n\nUsage:\n  %s [flags] CIDR [PORT-RANGE]\n  %s -cidr 192.168.1.0/24 -ports 1-65535\n\nFlags:\n", os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	targetCIDR := strings.TrimSpace(*cidr)
	portRange := strings.TrimSpace(*ports)
	args := flag.Args()
	if targetCIDR == "" && len(args) > 0 {
		targetCIDR = args[0]
	}
	if len(args) > 1 && portRange == "1-65535" {
		portRange = args[1]
	}
	if len(args) > 2 {
		fmt.Fprintln(os.Stderr, "error: too many positional arguments; use CIDR and optional port range")
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := parseConfig(targetCIDR, portRange, *timeout, *concurrency, *maxHosts, *format, *interfaceIP, *zone)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		flag.Usage()
		os.Exit(2)
	}

	results, err := scanNetwork(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		os.Exit(1)
	}
	if cfg.format == "json" {
		if err := writeJSON(os.Stdout, results); err != nil {
			fmt.Fprintln(os.Stderr, "output error:", err)
			os.Exit(1)
		}
		return
	}
	writeText(os.Stdout, results)
}

func parseConfig(cidr, portRange string, timeout time.Duration, concurrency, maxHosts int, format, interfaceIP, zone string) (cliConfig, error) {
	if strings.TrimSpace(cidr) == "" {
		return cliConfig{}, errors.New("-cidr is required (or pass CIDR as the first positional argument)")
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return cliConfig{}, fmt.Errorf("invalid CIDR: %w", err)
	}
	start, end, err := parsePortRange(portRange)
	if err != nil {
		return cliConfig{}, err
	}
	if timeout <= 0 || timeout > 5*time.Minute {
		return cliConfig{}, errors.New("-timeout must be greater than 0 and no more than 5m")
	}
	if concurrency < 1 || concurrency > 1024 {
		return cliConfig{}, errors.New("-concurrency must be between 1 and 1024")
	}
	if maxHosts < 1 || maxHosts > absoluteMaxHosts {
		return cliConfig{}, fmt.Errorf("-max-hosts must be between 1 and %d", absoluteMaxHosts)
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "text" && format != "json" {
		return cliConfig{}, errors.New("-format must be text or json")
	}
	if interfaceIP != "" {
		ip := net.ParseIP(strings.TrimSpace(interfaceIP))
		if ip == nil {
			return cliConfig{}, errors.New("-interface must be a valid local IP address")
		}
		if ip.To4() != nil {
			interfaceIP = ip.To4().String()
		} else {
			interfaceIP = ip.To16().String()
		}
	}
	return cliConfig{
		network: network, startPort: start, endPort: end, timeout: timeout,
		concurrency: concurrency, maxHosts: maxHosts, format: format,
		interfaceIP: interfaceIP, zone: strings.TrimSpace(zone),
	}, nil
}

func parsePortRange(value string) (int, int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, 0, errors.New("-ports cannot be empty")
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return 0, 0, fmt.Errorf("invalid port range %q", value)
	}
	start, err := parsePort(parts[0])
	if err != nil {
		return 0, 0, err
	}
	end := start
	if len(parts) == 2 {
		end, err = parsePort(parts[1])
		if err != nil {
			return 0, 0, err
		}
	}
	if start > end {
		return 0, 0, fmt.Errorf("port range start %d is greater than end %d", start, end)
	}
	return start, end, nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q: expected 1-65535", value)
	}
	return port, nil
}

func scanNetwork(ctx context.Context, cfg cliConfig) ([]HostResult, error) {
	addresses, err := enumerateIPs(cfg.network, cfg.maxHosts)
	if err != nil {
		return nil, err
	}
	jobs := make(chan net.IP)
	results := make(chan HostResult, len(addresses))
	workers := cfg.concurrency
	if workers > len(addresses) {
		workers = len(addresses)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				result := scanHost(ctx, ip, cfg)
				if len(result.Services) > 0 {
					results <- result
				}
			}
		}()
	}
feed:
	for _, ip := range addresses {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	outputResults := make([]HostResult, 0, len(results))
	for result := range results {
		outputResults = append(outputResults, result)
	}
	sort.Slice(outputResults, func(i, j int) bool {
		return compareIP(outputResults[i].IP, outputResults[j].IP) < 0
	})
	return outputResults, nil
}

func enumerateIPs(network *net.IPNet, maxHosts int) ([]net.IP, error) {
	if network == nil {
		return nil, errors.New("network is nil")
	}
	prefix, bits := network.Mask.Size()
	if prefix < 0 || (bits != 32 && bits != 128) {
		return nil, errors.New("invalid network mask")
	}
	ip := network.IP
	if bits == 32 {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}
	if ip == nil {
		return nil, errors.New("invalid network address")
	}
	hostBits := bits - prefix
	if hostBits >= 63 || (uint64(1)<<hostBits) > uint64(maxHosts)+2 {
		return nil, fmt.Errorf("network contains too many addresses; use a smaller CIDR or raise -max-hosts (limit %d)", maxHosts)
	}
	count := 1 << hostBits
	base := append(net.IP(nil), ip...)
	base = base.Mask(network.Mask)
	addresses := make([]net.IP, 0, count)
	for offset := 0; offset < count; offset++ {
		candidate := addIP(base, uint64(offset))
		if bits == 32 && count > 2 && (offset == 0 || offset == count-1) {
			continue
		}
		addresses = append(addresses, candidate)
		if len(addresses) > maxHosts {
			return nil, fmt.Errorf("network contains more than %d usable addresses", maxHosts)
		}
	}
	return addresses, nil
}

func addIP(base net.IP, offset uint64) net.IP {
	result := append(net.IP(nil), base...)
	for i := len(result) - 1; i >= 0 && offset > 0; i-- {
		value := uint64(result[i]) + (offset & 0xff)
		result[i] = byte(value)
		offset = (offset >> 8) + (value >> 8)
	}
	return result
}

func compareIP(left, right string) int {
	l := net.ParseIP(left)
	r := net.ParseIP(right)
	if l == nil || r == nil {
		return strings.Compare(left, right)
	}
	return bytes.Compare(l.To16(), r.To16())
}

func scanHost(ctx context.Context, ip net.IP, cfg cliConfig) HostResult {
	result := HostResult{IP: ip.String()}
	_, networkBits := cfg.network.Mask.Size()
	networkIsV4 := networkBits == 32
	networkType := "udp6"
	targetIP := ip
	if networkIsV4 {
		networkType = "udp4"
		targetIP = ip.To4()
	}
	local := net.ParseIP(cfg.interfaceIP)
	var localAddr *net.UDPAddr
	if local != nil {
		localAddr = &net.UDPAddr{IP: local}
	}
	target := &net.UDPAddr{IP: targetIP, Port: mdnsPort, Zone: cfg.zone}
	if localAddr != nil {
		localAddr.Zone = cfg.zone
	}
	conn, err := net.DialUDP(networkType, localAddr, target)
	if err != nil {
		return result
	}
	defer conn.Close()

	catalog := newCatalog(result.IP)
	first := exchange(ctx, conn, []dnsQuestion{{Name: servicesQName, Type: typePTR}}, cfg.timeout)
	catalog.addPackets(first)
	serviceTypes := catalog.serviceTypes()
	if len(serviceTypes) == 0 {
		// Some small responders do not answer the meta-query. The common service
		// probes keep discovery useful while remaining bounded and explicit.
		serviceTypes = commonServiceTypes
	}
	if len(serviceTypes) > 128 {
		serviceTypes = serviceTypes[:128]
	}
	serviceQuestions := make([]dnsQuestion, 0, len(serviceTypes))
	for _, serviceType := range serviceTypes {
		serviceQuestions = append(serviceQuestions, dnsQuestion{Name: serviceType, Type: typePTR})
	}
	second := exchange(ctx, conn, serviceQuestions, cfg.timeout)
	catalog.addPackets(second)

	instances := catalog.instances()
	if len(instances) > 256 {
		instances = instances[:256]
	}
	instanceQuestions := make([]dnsQuestion, 0, len(instances)*4)
	for _, instance := range instances {
		for _, qtype := range []uint16{typeSRV, typeTXT, typeA, typeAAAA} {
			instanceQuestions = append(instanceQuestions, dnsQuestion{Name: instance, Type: qtype})
		}
	}
	third := exchange(ctx, conn, instanceQuestions, cfg.timeout)
	catalog.addPackets(third)

	result.Services = catalog.assets(cfg.startPort, cfg.endPort)
	result.Answers = catalog.answerTypes()
	return result
}

func exchange(ctx context.Context, conn *net.UDPConn, questions []dnsQuestion, timeout time.Duration) []*dnsPacket {
	if len(questions) == 0 {
		return nil
	}
	for _, question := range questions {
		packet, err := buildQuery(question.Name, question.Type)
		if err != nil {
			continue
		}
		if _, err := conn.Write(packet); err != nil {
			continue
		}
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	packets := make([]*dnsPacket, 0, 4)
	buffer := make([]byte, maxDNSPacket)
	for {
		select {
		case <-ctx.Done():
			return packets
		default:
		}
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return packets
		}
		packet, err := parseDNSPacket(buffer[:n])
		if err == nil && packet.Header.Response {
			packets = append(packets, packet)
		}
	}
}

func writeJSON(w io.Writer, results []HostResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output{Hosts: results})
}

func writeText(w io.Writer, results []HostResult) {
	if len(results) == 0 {
		fmt.Fprintln(w, "services:")
		return
	}
	for index, host := range results {
		if len(results) > 1 {
			fmt.Fprintf(w, "host %s:\n", displayValue(host.IP))
		}
		fmt.Fprintln(w, "services:")
		for _, service := range host.Services {
			if service.HasPort {
				fmt.Fprintf(w, "  %d/%s %s:\n", service.Port, displayValue(service.Protocol), displayValue(service.Service))
			} else {
				fmt.Fprintf(w, "  %s:\n", displayValue(service.Service))
			}
			writeBanner(w, service.Banner)
		}
		if len(host.Answers) > 0 {
			fmt.Fprintln(w, "  answers:")
			fmt.Fprintln(w, "    PTR:")
			for _, answer := range host.Answers {
				fmt.Fprintf(w, "      %s\n", displayValue(answer))
			}
		}
		if index < len(results)-1 {
			fmt.Fprintln(w)
		}
	}
}

func writeBanner(w io.Writer, banner Banner) {
	if banner.Name != "" {
		fmt.Fprintf(w, "    Name=%s\n", displayValue(banner.Name))
	}
	for _, value := range banner.IPv4 {
		fmt.Fprintf(w, "    IPv4=%s\n", displayValue(value))
	}
	for _, value := range banner.IPv6 {
		fmt.Fprintf(w, "    IPv6=%s\n", displayValue(value))
	}
	if banner.Hostname != "" {
		fmt.Fprintf(w, "    Hostname=%s\n", displayValue(banner.Hostname))
	}
	if banner.TTL != 0 {
		fmt.Fprintf(w, "    TTL=%d\n", banner.TTL)
	}
	keys := make([]string, 0, len(banner.TXT))
	for key := range banner.TXT {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if banner.TXT[key] == "" {
			fmt.Fprintf(w, "    %s\n", displayValue(key))
		} else {
			fmt.Fprintf(w, "    %s=%s\n", displayValue(key), displayValue(banner.TXT[key]))
		}
	}
}

// Network metadata is untrusted. Escape terminal control bytes while keeping
// ordinary UTF-8 names readable in the human-oriented output.
func displayValue(value string) string {
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r == 0x1b:
			builder.WriteString(`\x1b`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&builder, `\x%02x`, r)
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

var commonServiceTypes = []string{
	"_http._tcp.local.", "_https._tcp.local.", "_workstation._tcp.local.",
	"_smb._tcp.local.", "_afpovertcp._tcp.local.", "_ssh._tcp.local.",
	"_device-info._tcp.local.", "_qdiscover._tcp.local.",
}
