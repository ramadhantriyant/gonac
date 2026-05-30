package sniffer

import (
	"net"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
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

func mdnsResolve(ip string) string {
	target := net.ParseIP(ip).To4()
	if target == nil {
		return ""
	}

	entriesCh := make(chan *mdns.ServiceEntry, 32)

	params := mdns.DefaultParams("_services._dns-sd._udp")
	params.Entries = entriesCh
	params.Timeout = 500 * time.Millisecond
	params.DisableIPv6 = true

	go func() {
		mdns.Query(params)
		close(entriesCh)
	}()

	for entry := range entriesCh {
		if entry.AddrV4 != nil && entry.AddrV4.Equal(target) {
			return strings.TrimSuffix(entry.Host, ".")
		}
	}
	return ""
}
