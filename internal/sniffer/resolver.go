package sniffer

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// resolveHostname tries four methods in order, returning the first result found.
func resolveHostname(ip, dnsServer string) string {
	if dnsServer != "" {
		if h := routerDNS(ip, dnsServer); h != "" {
			return h
		}
	}
	if h := reverseDNS(ip); h != "" {
		return h
	}
	if h := mdnsResolve(ip); h != "" {
		return h
	}
	return netbiosResolve(ip)
}

// routerDNS queries the router directly for a PTR record.
// The router's DHCP table is the most complete source of hostname information.
func routerDNS(ip, dnsServer string) string {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return ""
	}

	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)
	m.RecursionDesired = true

	c := &dns.Client{
		Net:     "udp",
		Timeout: 500 * time.Millisecond,
	}

	r, _, err := c.Exchange(m, net.JoinHostPort(dnsServer, "53"))
	if err != nil {
		return ""
	}

	for _, ans := range r.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			return strings.TrimSuffix(ptr.Ptr, ".")
		}
	}
	return ""
}

// reverseDNS queries the system resolver for a PTR record.
func reverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// mdnsResolve sends a unicast PTR query directly to the device's mDNS port.
// Works for most implementations (avahi, Apple mDNSResponder, Windows) per RFC 6762 §5.5.
func mdnsResolve(ip string) string {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return ""
	}

	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)
	m.RecursionDesired = false

	c := &dns.Client{
		Net:     "udp",
		Timeout: 500 * time.Millisecond,
	}

	r, _, err := c.Exchange(m, net.JoinHostPort(ip, "5353"))
	if err != nil {
		return ""
	}

	for _, ans := range r.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			return strings.TrimSuffix(ptr.Ptr, ".")
		}
	}
	return ""
}

// netbiosResolve sends an NBNS node-status request to the device on UDP port 137.
// Covers Windows machines that don't advertise via mDNS.
func netbiosResolve(ip string) string {
	req := buildNBNSRequest()

	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	if _, err := conn.Write(req); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	return parseNBNSResponse(buf[:n])
}

func buildNBNSRequest() []byte {
	req := make([]byte, 50)

	// Transaction ID
	rand.Read(req[0:2])

	// Flags: standard query
	req[2], req[3] = 0x00, 0x00

	// Counts: 1 question, 0 others
	req[4], req[5] = 0x00, 0x01

	// Encoded wildcard name "*" (32 bytes of CA pairs) with length prefix and null terminator
	req[12] = 0x20
	copy(req[13:], []byte("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	req[45] = 0x00

	// Type: NBSTAT (0x0021)
	binary.BigEndian.PutUint16(req[46:], 0x0021)

	// Class: IN (0x0001)
	binary.BigEndian.PutUint16(req[48:], 0x0001)

	return req
}

func parseNBNSResponse(buf []byte) string {
	// Response header is 56 bytes; byte 56 is the name count
	if len(buf) < 57 {
		return ""
	}

	numNames := int(buf[56])
	offset := 57

	for range numNames {
		if offset+18 > len(buf) {
			break
		}
		name := strings.TrimRight(string(buf[offset:offset+15]), " ")
		nameType := buf[offset+15]
		offset += 18

		// Type 0x00 = workstation name
		if nameType == 0x00 && name != "" {
			return name
		}
	}
	return ""
}
