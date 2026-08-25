package main

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

type catalog struct {
	queriedIP     string
	ptr           map[string][]string
	serviceAnswer map[string]struct{}
	srv           map[string]srvEntry
	txt           map[string]txtEntry
	a             map[string][]string
	aaaa          map[string][]string
	ttls          map[string]uint32
}

type srvEntry struct {
	data srvData
	ttl  uint32
}

type txtEntry struct {
	data txtData
	ttl  uint32
}

func newCatalog(queriedIP string) *catalog {
	return &catalog{
		queriedIP: queriedIP, ptr: make(map[string][]string), serviceAnswer: make(map[string]struct{}),
		srv: make(map[string]srvEntry), txt: make(map[string]txtEntry),
		a: make(map[string][]string), aaaa: make(map[string][]string), ttls: make(map[string]uint32),
	}
}

func (c *catalog) addPackets(packets []*dnsPacket) {
	for _, packet := range packets {
		for _, record := range packet.Records {
			owner := canonicalName(record.Name)
			if record.TTL > 0 {
				if old, ok := c.ttls[owner]; !ok || record.TTL < old {
					c.ttls[owner] = record.TTL
				}
			}
			switch record.Type {
			case typePTR:
				data, ok := record.Data.(ptrData)
				if !ok {
					continue
				}
				target := canonicalName(data.Target)
				if !containsString(c.ptr[owner], target) {
					c.ptr[owner] = append(c.ptr[owner], target)
				}
				if owner == canonicalName(servicesQName) {
					c.serviceAnswer[target] = struct{}{}
				} else if isServiceType(owner) {
					c.serviceAnswer[owner] = struct{}{}
				}
			case typeSRV:
				if data, ok := record.Data.(srvData); ok {
					c.srv[owner] = srvEntry{data: data, ttl: record.TTL}
				}
			case typeTXT:
				if data, ok := record.Data.(txtData); ok {
					c.txt[owner] = txtEntry{data: data, ttl: record.TTL}
				}
			case typeA:
				if value, ok := record.Data.(string); ok && net.ParseIP(value) != nil && !containsString(c.a[owner], value) {
					c.a[owner] = append(c.a[owner], value)
				}
			case typeAAAA:
				if value, ok := record.Data.(string); ok && net.ParseIP(value) != nil && !containsString(c.aaaa[owner], value) {
					c.aaaa[owner] = append(c.aaaa[owner], value)
				}
			}
		}
	}
}

func (c *catalog) serviceTypes() []string {
	values := make([]string, 0, len(c.serviceAnswer))
	for value := range c.serviceAnswer {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func (c *catalog) instances() []string {
	values := make([]string, 0)
	seen := make(map[string]struct{})
	for owner, targets := range c.ptr {
		if !isServiceType(owner) {
			continue
		}
		for _, target := range targets {
			if _, ok := seen[target]; !ok {
				seen[target] = struct{}{}
				values = append(values, target)
			}
		}
	}
	// A responder can return SRV records without the corresponding PTR in a
	// follow-up packet. Keeping them makes the result useful in that case.
	for owner := range c.srv {
		if _, ok := seen[owner]; !ok && isInstanceName(owner) {
			seen[owner] = struct{}{}
			values = append(values, owner)
		}
	}
	sort.Strings(values)
	return values
}

func (c *catalog) assets(startPort, endPort int) []ServiceAsset {
	assets := make([]ServiceAsset, 0)
	seen := make(map[string]struct{})
	for serviceType, instances := range c.ptr {
		if !isServiceType(serviceType) {
			continue
		}
		for _, instance := range instances {
			asset, ok := c.assetFor(serviceType, instance, startPort, endPort)
			if !ok {
				continue
			}
			key := assetKey(asset)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			assets = append(assets, asset)
		}
	}
	// Include SRV-only instances when a device omits the service PTR answer.
	for instance, srv := range c.srv {
		serviceType := inferServiceType(instance)
		if serviceType == "" {
			continue
		}
		asset, ok := c.assetForWithSRV(serviceType, instance, srv, startPort, endPort)
		if ok {
			key := assetKey(asset)
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				assets = append(assets, asset)
			}
		}
	}
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].HasPort != assets[j].HasPort {
			return assets[i].HasPort
		}
		if assets[i].Port != assets[j].Port {
			return assets[i].Port < assets[j].Port
		}
		if assets[i].Service != assets[j].Service {
			return assets[i].Service < assets[j].Service
		}
		return assets[i].Banner.Name < assets[j].Banner.Name
	})
	return assets
}

func (c *catalog) assetFor(serviceType, instance string, startPort, endPort int) (ServiceAsset, bool) {
	srv, hasSRV := c.srv[instance]
	return c.assetForWithSRVState(serviceType, instance, srv, hasSRV, startPort, endPort)
}

func (c *catalog) assetForWithSRV(serviceType, instance string, srv srvEntry, startPort, endPort int) (ServiceAsset, bool) {
	return c.assetForWithSRVState(serviceType, instance, srv, true, startPort, endPort)
}

func (c *catalog) assetForWithSRVState(serviceType, instance string, srv srvEntry, hasSRV bool, startPort, endPort int) (ServiceAsset, bool) {
	if hasSRV && (srv.data.Port < startPort || srv.data.Port > endPort) {
		return ServiceAsset{}, false
	}
	service, protocol := splitServiceType(serviceType)
	if service == "" {
		return ServiceAsset{}, false
	}
	hostname := ""
	var target string
	if hasSRV {
		target = canonicalName(srv.data.Target)
		hostname = strings.TrimSuffix(srv.data.Target, ".")
	} else {
		hostname = c.defaultHostname()
		target = canonicalName(hostname)
	}
	name := instanceDisplayName(instance, serviceType)
	addresses4 := append([]string(nil), c.a[target]...)
	addresses6 := append([]string(nil), c.aaaa[target]...)
	queried := net.ParseIP(c.queriedIP)
	if len(addresses4) == 0 && queried != nil && queried.To4() != nil {
		addresses4 = []string{queried.To4().String()}
	}
	if len(addresses6) == 0 && queried != nil && queried.To4() == nil {
		addresses6 = []string{queried.String()}
	}
	txt, hasTXT := c.txt[canonicalName(instance)]
	rawTXT, textMap := normalizeTXT(txt.data.Values)
	ttl := c.ttls[canonicalName(instance)]
	if hasSRV && (ttl == 0 || srv.ttl < ttl) {
		ttl = srv.ttl
	}
	if hasTXT && (ttl == 0 || txt.ttl < ttl) {
		ttl = txt.ttl
	}
	asset := ServiceAsset{
		Port: srv.data.Port, HasPort: hasSRV, Protocol: protocol, Service: service, Host: hostname,
		Banner: Banner{Name: name, IPv4: addresses4, IPv6: addresses6, Hostname: hostname, TTL: ttl, TXT: textMap, RawTXT: rawTXT},
	}
	return asset, true
}

func (c *catalog) defaultHostname() string {
	values := make([]string, 0, len(c.srv))
	for _, entry := range c.srv {
		if entry.data.Target != "" {
			values = append(values, strings.TrimSuffix(entry.data.Target, "."))
		}
	}
	sort.Strings(values)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (c *catalog) answerTypes() []string {
	answers := make([]string, 0, len(c.serviceAnswer))
	for value := range c.serviceAnswer {
		answers = append(answers, value)
	}
	sort.Strings(answers)
	return answers
}

func normalizeTXT(values []string) ([]string, map[string]string) {
	raw := make([]string, 0, len(values))
	fields := make(map[string]string)
	for _, value := range values {
		if value == "" {
			continue
		}
		parts := strings.SplitN(value, "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			fields[parts[0]] = parts[1]
		} else {
			fields[value] = ""
		}
		raw = append(raw, value)
	}
	return raw, fields
}

func canonicalName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "."
	}
	return strings.ToLower(strings.TrimSuffix(value, ".")) + "."
}

func isServiceType(value string) bool {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(value), "."), ".")
	if len(parts) < 3 || parts[len(parts)-1] != "local" {
		return false
	}
	service := parts[len(parts)-3]
	protocol := parts[len(parts)-2]
	return service != "_dns-sd" && strings.HasPrefix(service, "_") && (protocol == "_tcp" || protocol == "_udp")
}

func isInstanceName(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	return strings.Contains(value, "._tcp.local") || strings.Contains(value, "._udp.local")
}

func inferServiceType(instance string) string {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(instance), "."), ".")
	for i := 1; i+1 < len(parts); i++ {
		if (parts[i] == "_tcp" || parts[i] == "_udp") && parts[i+1] == "local" && strings.HasPrefix(parts[i-1], "_") {
			return parts[i-1] + "." + parts[i] + ".local."
		}
	}
	return ""
}

func splitServiceType(value string) (string, string) {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(value), "."), ".")
	if len(parts) < 3 || parts[len(parts)-1] != "local" {
		return "", ""
	}
	service := parts[len(parts)-3]
	protocol := strings.TrimPrefix(parts[len(parts)-2], "_")
	if protocol != "tcp" && protocol != "udp" {
		return "", ""
	}
	return strings.TrimPrefix(service, "_"), protocol
}

func instanceDisplayName(instance, serviceType string) string {
	instance = strings.TrimSuffix(instance, ".")
	suffix := strings.TrimSuffix(serviceType, ".")
	marker := "." + suffix
	if index := strings.LastIndex(instance, marker); index >= 0 {
		return instance[:index]
	}
	return instance
}

func assetKey(asset ServiceAsset) string {
	return strings.Join([]string{strconv.Itoa(asset.Port), asset.Protocol, asset.Service, asset.Banner.Name}, "|")
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
