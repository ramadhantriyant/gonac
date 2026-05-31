package sniffer

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

type Device struct {
	MAC      net.HardwareAddr
	IP       net.IP
	Hostname string
}

type Sniffer struct {
	handle    *pcap.Handle
	iface     *net.Interface
	localIP   net.IP
	subnet    *net.IPNet
	interval  time.Duration
	devicesCh chan Device
}

func New(ifaceName, cidr string, interval time.Duration) (*Sniffer, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("sniffer: interface %q: %w", ifaceName, err)
	}

	var localIP net.IP
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("sniffer: addrs: %w", err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if v4 := ipnet.IP.To4(); v4 != nil {
				localIP = v4
				break
			}
		}
	}
	if localIP == nil {
		return nil, fmt.Errorf("sniffer: no IPv4 address on interface %s", ifaceName)
	}

	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("sniffer: parse CIDR %q: %w", cidr, err)
	}

	handle, err := pcap.OpenLive(ifaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("sniffer: open pcap: %w", err)
	}
	if err := handle.SetBPFFilter("arp"); err != nil {
		handle.Close()
		return nil, fmt.Errorf("sniffer: BPF filter: %w", err)
	}

	return &Sniffer{
		handle:    handle,
		iface:     iface,
		localIP:   localIP,
		subnet:    subnet,
		interval:  interval,
		devicesCh: make(chan Device, 64),
	}, nil
}

func (s *Sniffer) Devices() <-chan Device {
	return s.devicesCh
}

func (s *Sniffer) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { s.scan(ctx) })
	wg.Go(func() { s.listen(ctx) })
	wg.Wait()
	close(s.devicesCh)
}

func (s *Sniffer) Close() {
	s.handle.Close()
}
