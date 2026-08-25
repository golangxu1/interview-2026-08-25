package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	typeA    uint16 = 1
	typePTR  uint16 = 12
	typeTXT  uint16 = 16
	typeAAAA uint16 = 28
	typeSRV  uint16 = 33
	classIN  uint16 = 1

	servicesQName = "_services._dns-sd._udp.local."
)

type dnsHeader struct {
	Response bool
}

type dnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type dnsRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  any
}

type dnsPacket struct {
	Header    dnsHeader
	Questions []dnsQuestion
	Records   []dnsRecord
}

type ptrData struct{ Target string }

type srvData struct {
	Priority uint16
	Weight   uint16
	Port     int
	Target   string
}

type txtData struct {
	Values []string
}

func buildQuery(name string, qtype uint16) ([]byte, error) {
	labels, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 12+len(labels)+4)
	// ID=0 and flags=0 are required for a conventional multicast DNS query.
	binary.BigEndian.PutUint16(packet[4:6], 1)
	copy(packet[12:], labels)
	binary.BigEndian.PutUint16(packet[12+len(labels):], qtype)
	// The scanner sends queries directly to each target, so request a unicast
	// response with the mDNS QU bit instead of relying on multicast reception.
	binary.BigEndian.PutUint16(packet[14+len(labels):], classIN|0x8000)
	return packet, nil
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("empty DNS name")
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	result := make([]byte, 0, len(name)+2)
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label in %q", name)
		}
		if len(result)+1+len(label)+1 > 255 {
			return nil, errors.New("DNS name exceeds 255 bytes")
		}
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	return append(result, 0), nil
}

func parseDNSPacket(packet []byte) (*dnsPacket, error) {
	if len(packet) < 12 {
		return nil, errors.New("DNS packet is shorter than header")
	}
	counts := [4]uint16{
		binary.BigEndian.Uint16(packet[4:6]), binary.BigEndian.Uint16(packet[6:8]),
		binary.BigEndian.Uint16(packet[8:10]), binary.BigEndian.Uint16(packet[10:12]),
	}
	position := 12
	result := &dnsPacket{Header: dnsHeader{Response: binary.BigEndian.Uint16(packet[2:4])&0x8000 != 0}}
	for i := 0; i < int(counts[0]); i++ {
		name, next, err := readName(packet, position)
		if err != nil {
			return nil, fmt.Errorf("question %d: %w", i, err)
		}
		if next+4 > len(packet) {
			return nil, errors.New("truncated DNS question")
		}
		result.Questions = append(result.Questions, dnsQuestion{
			Name: name, Type: binary.BigEndian.Uint16(packet[next : next+2]), Class: binary.BigEndian.Uint16(packet[next+2 : next+4]),
		})
		position = next + 4
	}
	for section, count := range counts[1:] {
		for i := 0; i < int(count); i++ {
			record, next, err := readRecord(packet, position)
			if err != nil {
				return nil, fmt.Errorf("section %d record %d: %w", section, i, err)
			}
			result.Records = append(result.Records, record)
			position = next
		}
	}
	return result, nil
}

func readRecord(packet []byte, position int) (dnsRecord, int, error) {
	name, next, err := readName(packet, position)
	if err != nil {
		return dnsRecord{}, position, err
	}
	if next+10 > len(packet) {
		return dnsRecord{}, position, errors.New("truncated DNS record header")
	}
	recordType := binary.BigEndian.Uint16(packet[next : next+2])
	recordClass := binary.BigEndian.Uint16(packet[next+2:next+4]) & 0x7fff
	ttl := binary.BigEndian.Uint32(packet[next+4 : next+8])
	length := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
	dataStart := next + 10
	dataEnd := dataStart + length
	if dataEnd > len(packet) {
		return dnsRecord{}, position, errors.New("truncated DNS record data")
	}
	record := dnsRecord{Name: name, Type: recordType, Class: recordClass, TTL: ttl}
	switch recordType {
	case typePTR:
		target, targetEnd, err := readName(packet, dataStart)
		if err != nil {
			return dnsRecord{}, position, fmt.Errorf("invalid PTR data: %w", err)
		}
		if targetEnd > dataEnd {
			return dnsRecord{}, position, errors.New("PTR name exceeds record length")
		}
		record.Data = ptrData{Target: target}
	case typeSRV:
		if length < 6 {
			return dnsRecord{}, position, errors.New("SRV data is shorter than 6 bytes")
		}
		target, targetEnd, err := readName(packet, dataStart+6)
		if err != nil {
			return dnsRecord{}, position, fmt.Errorf("invalid SRV target: %w", err)
		}
		if targetEnd > dataEnd {
			return dnsRecord{}, position, errors.New("SRV target exceeds record length")
		}
		record.Data = srvData{
			Priority: binary.BigEndian.Uint16(packet[dataStart : dataStart+2]),
			Weight:   binary.BigEndian.Uint16(packet[dataStart+2 : dataStart+4]),
			Port:     int(binary.BigEndian.Uint16(packet[dataStart+4 : dataStart+6])),
			Target:   target,
		}
	case typeTXT:
		values, err := parseTXT(packet[dataStart:dataEnd])
		if err != nil {
			return dnsRecord{}, position, err
		}
		record.Data = txtData{Values: values}
	case typeA:
		if length == net.IPv4len {
			record.Data = net.IP(append([]byte(nil), packet[dataStart:dataEnd]...)).String()
		}
	case typeAAAA:
		if length == net.IPv6len {
			record.Data = net.IP(append([]byte(nil), packet[dataStart:dataEnd]...)).String()
		}
	}
	return record, dataEnd, nil
}

func parseTXT(data []byte) ([]string, error) {
	values := make([]string, 0, 4)
	for position := 0; position < len(data); {
		length := int(data[position])
		position++
		if position+length > len(data) {
			return nil, errors.New("truncated TXT string")
		}
		values = append(values, string(data[position:position+length]))
		position += length
	}
	return values, nil
}

// readName follows DNS compression pointers without allowing pointer loops or
// reads outside the packet. It returns the offset immediately after the name
// in the original stream, not the final pointer target.
func readName(packet []byte, position int) (string, int, error) {
	if position < 0 || position >= len(packet) {
		return "", position, errors.New("DNS name offset out of bounds")
	}
	labels := make([]string, 0, 4)
	current := position
	next := position
	jumped := false
	visited := make(map[int]struct{})
	for steps := 0; steps <= len(packet); steps++ {
		if current >= len(packet) {
			return "", position, errors.New("truncated DNS name")
		}
		length := int(packet[current])
		switch length & 0xc0 {
		case 0:
			current++
			if length == 0 {
				if !jumped {
					next = current
				}
				return strings.Join(labels, ".") + ".", next, nil
			}
			if length > 63 || current+length > len(packet) {
				return "", position, errors.New("invalid DNS label")
			}
			labels = append(labels, string(packet[current:current+length]))
			current += length
			if !jumped {
				next = current
			}
		case 0xc0:
			if current+1 >= len(packet) {
				return "", position, errors.New("truncated DNS compression pointer")
			}
			pointer := ((length & 0x3f) << 8) | int(packet[current+1])
			if pointer >= len(packet) {
				return "", position, errors.New("DNS compression pointer out of bounds")
			}
			if _, seen := visited[pointer]; seen {
				return "", position, errors.New("DNS compression pointer loop")
			}
			visited[pointer] = struct{}{}
			if !jumped {
				next = current + 2
				jumped = true
			}
			current = pointer
		default:
			return "", position, errors.New("invalid DNS label prefix")
		}
	}
	return "", position, errors.New("DNS name has too many labels")
}
