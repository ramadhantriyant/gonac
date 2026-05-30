package sniffer

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (s *Sniffer) scan(ctx context.Context) {
	for {
		if err := s.sendARPRequests(); err != nil {
			log.Printf("sniffer: scan error: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.interval):
		}
	}
}

func (s *Sniffer) sendARPRequests() error {
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.localIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	for _, ip := range ipsInSubnet(s.subnet) {
		arp.DstProtAddress = []byte(ip.To4())
		if err := buf.Clear(); err != nil {
			return err
		}
		if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
			return err
		}
		if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func ipsInSubnet(n *net.IPNet) []net.IP {
	base := binary.BigEndian.Uint32(n.IP.To4())
	mask := binary.BigEndian.Uint32(n.Mask)
	base &= mask
	broadcast := base | ^mask

	var out []net.IP
	for i := base + 1; i < broadcast; i++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], i)
		ip := make(net.IP, 4)
		copy(ip, b[:])
		out = append(out, ip)
	}
	return out
}
