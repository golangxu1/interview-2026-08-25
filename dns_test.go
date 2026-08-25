package main

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

func TestBuildQuery(t *testing.T) {
	packet, err := buildQuery("_services._dns-sd._udp.local.", typePTR)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		t.Fatalf("unexpected query header: %x", packet[:12])
	}
	binary.BigEndian.PutUint16(packet[2:4], 0x8000)
	parsed, err := parseDNSPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Questions) != 1 || parsed.Questions[0].Name != "_services._dns-sd._udp.local." {
		t.Fatalf("unexpected question: %+v", parsed.Questions)
	}
}

func TestParseCompressedRecords(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[2:4], 0x8400)
	binary.BigEndian.PutUint16(packet[6:8], 2)
	serviceName, _ := encodeName("_http._tcp.local.")
	instanceName, _ := encodeName("nas._http._tcp.local.")
	packet = appendRecord(packet, serviceName, typePTR, 10, instanceName)
	srvDataBytes := append([]byte{0, 0, 0, 0, 0, 80}, 0xc0, 12)
	packet = appendRecord(packet, instanceName, typeSRV, 10, srvDataBytes)

	parsed, err := parseDNSPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Records) != 2 {
		t.Fatalf("got %d records", len(parsed.Records))
	}
	if parsed.Records[0].Data.(ptrData).Target != "nas._http._tcp.local." {
		t.Fatalf("bad PTR: %#v", parsed.Records[0].Data)
	}
	srv := parsed.Records[1].Data.(srvData)
	if srv.Port != 80 || srv.Target != "_http._tcp.local." {
		t.Fatalf("bad SRV: %+v", srv)
	}
}

func TestParseTXTAndAddresses(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[2:4], 0x8400)
	binary.BigEndian.PutUint16(packet[6:8], 3)
	name, _ := encodeName("nas._http._tcp.local.")
	txt := append([]byte{4, 'p', 'a', 't', 'h'}, 5, 'm', 'o', 'd', 'e', 'l')
	packet = appendRecord(packet, name, typeTXT, 10, txt)
	packet = appendRecord(packet, name, typeA, 10, []byte{192, 168, 1, 2})
	ipv6 := net.ParseIP("fe80::1").To16()
	packet = appendRecord(packet, name, typeAAAA, 10, ipv6)

	parsed, err := parseDNSPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Records) != 3 {
		t.Fatalf("got %d records", len(parsed.Records))
	}
	if !reflect.DeepEqual(parsed.Records[0].Data, txtData{Values: []string{"path", "model"}}) {
		t.Fatalf("bad TXT: %#v", parsed.Records[0].Data)
	}
	if parsed.Records[1].Data != "192.168.1.2" || parsed.Records[2].Data != "fe80::1" {
		t.Fatalf("bad addresses: %#v %#v", parsed.Records[1].Data, parsed.Records[2].Data)
	}
}

func TestCatalogProducesDeepBannerAndFiltersPorts(t *testing.T) {
	catalog := newCatalog("192.168.1.20")
	packet := &dnsPacket{Header: dnsHeader{Response: true}, Records: []dnsRecord{
		{Name: "_services._dns-sd._udp.local.", Type: typePTR, TTL: 10, Data: ptrData{Target: "_http._tcp.local."}},
		{Name: "_http._tcp.local.", Type: typePTR, TTL: 10, Data: ptrData{Target: "NAS._http._tcp.local."}},
		{Name: "NAS._http._tcp.local.", Type: typeSRV, TTL: 10, Data: srvData{Port: 5000, Target: "nas.local."}},
		{Name: "NAS._http._tcp.local.", Type: typeTXT, TTL: 10, Data: txtData{Values: []string{"path=/", "model=TS-464C"}}},
		{Name: "nas.local.", Type: typeA, TTL: 10, Data: "192.168.1.20"},
		{Name: "nas.local.", Type: typeAAAA, TTL: 10, Data: "fe80::1"},
	}}
	catalog.addPackets([]*dnsPacket{packet})
	assets := catalog.assets(4000, 6000)
	if len(assets) != 1 {
		t.Fatalf("got %d assets: %+v", len(assets), assets)
	}
	asset := assets[0]
	if asset.Port != 5000 || asset.Service != "http" || asset.Host != "nas.local" {
		t.Fatalf("unexpected asset: %+v", asset)
	}
	if asset.Banner.TXT["model"] != "TS-464C" || asset.Banner.IPv4[0] != "192.168.1.20" || asset.Banner.IPv6[0] != "fe80::1" {
		t.Fatalf("incomplete banner: %+v", asset.Banner)
	}
	if !reflect.DeepEqual(catalog.answerTypes(), []string{"_http._tcp.local."}) {
		t.Fatalf("unexpected answers: %v", catalog.answerTypes())
	}
}

func TestEnumerateIPs(t *testing.T) {
	_, network, err := net.ParseCIDR("192.168.10.0/30")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := enumerateIPs(network, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{addresses[0].String(), addresses[1].String()}; !reflect.DeepEqual(got, []string{"192.168.10.1", "192.168.10.2"}) {
		t.Fatalf("unexpected addresses: %v", got)
	}
}

func TestParsePortRange(t *testing.T) {
	start, end, err := parsePortRange(" 80-443 ")
	if err != nil || start != 80 || end != 443 {
		t.Fatalf("got %d-%d, %v", start, end, err)
	}
	if _, _, err := parsePortRange("443-80"); err == nil {
		t.Fatal("expected descending range error")
	}
}

func TestReadNameRejectsPointerLoop(t *testing.T) {
	packet := []byte{0xc0, 0x00}
	if _, _, err := readName(packet, 0); err == nil {
		t.Fatal("expected compression loop error")
	}
}

func appendRecord(packet, name []byte, recordType uint16, ttl uint32, data []byte) []byte {
	packet = append(packet, name...)
	packet = append(packet, u16(recordType)...)
	packet = append(packet, u16(classIN)...)
	packet = append(packet, u32(ttl)...)
	packet = append(packet, u16(uint16(len(data)))...)
	return append(packet, data...)
}

func u16(value uint16) []byte { return []byte{byte(value >> 8), byte(value)} }

func u32(value uint32) []byte {
	return []byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
}
