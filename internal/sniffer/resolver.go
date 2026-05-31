package sniffer

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// resolveHostname tries reverse DNS first, then falls back to mDNS.
// Returns an empty string if the hostname cannot be determined.
func resolveHostname(ip string) string {
	if h := reverseDNS(ip); h != "" {
		return h
	}
	return mdnsResolve(ip)
}

func reverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// mdnsResolve sends a unicast PTR query directly to the device's mDNS port.
// This works for most implementations (avahi, Apple mDNSResponder, Windows)
// that respond to unicast mDNS as per RFC 6762 §5.5.
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
