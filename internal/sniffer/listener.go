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
	l := pkt.Layer(layers.LayerTypeARP)
	if l == nil {
		return
	}
	arp := l.(*layers.ARP)

	if arp.Operation != layers.ARPReply {
		return
	}
	if net.HardwareAddr(arp.SourceHwAddress).String() == s.iface.HardwareAddr.String() {
		return
	}

	ip := net.IP(append([]byte(nil), arp.SourceProtAddress...))
	s.devicesCh <- Device{
		MAC:      net.HardwareAddr(append([]byte(nil), arp.SourceHwAddress...)),
		IP:       ip,
		Hostname: resolveHostname(ip.String()),
	}
}
