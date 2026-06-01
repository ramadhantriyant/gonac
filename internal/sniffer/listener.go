package sniffer

import (
	"context"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (s *Sniffer) listen(ctx context.Context) {
	src := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	packets := src.Packets()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-packets:
			if !ok {
				return
			}
			s.handlePacket(pkt)
		}
	}
}

func (s *Sniffer) handlePacket(pkt gopacket.Packet) {
	if l := pkt.Layer(layers.LayerTypeARP); l != nil {
		s.handleARP(l.(*layers.ARP))
		return
	}
	if l := pkt.Layer(layers.LayerTypeDHCPv4); l != nil {
		s.handleDHCP(l.(*layers.DHCPv4))
	}
}

func (s *Sniffer) handleARP(arp *layers.ARP) {
	if arp.Operation != layers.ARPReply {
		return
	}
	mac := net.HardwareAddr(append([]byte(nil), arp.SourceHwAddress...))
	if mac.String() == s.iface.HardwareAddr.String() {
		return
	}

	ip := net.IP(append([]byte(nil), arp.SourceProtAddress...))

	var hostname string
	if v, ok := s.dhcpNames.Load(mac.String()); ok {
		hostname = v.(string)
	} else {
		hostname = resolveHostname(ip.String(), s.dnsServer)
	}

	s.devicesCh <- Device{
		MAC:      mac,
		IP:       ip,
		Hostname: hostname,
	}
}

func (s *Sniffer) handleDHCP(dhcp *layers.DHCPv4) {
	if dhcp.Operation != layers.DHCPOpRequest {
		return
	}
	mac := dhcp.ClientHWAddr
	if len(mac) == 0 {
		return
	}
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptHostname && len(opt.Data) > 0 {
			s.dhcpNames.Store(mac.String(), string(opt.Data))
			return
		}
	}
}
