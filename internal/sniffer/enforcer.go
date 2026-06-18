package sniffer

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EnforcementEvent reports a state change for a single blocked target, for
// audit logging by the caller.
type EnforcementEvent struct {
	MAC    string
	Action string // "block_started" | "block_stopped"
}

// Enforcer blocks devices on the local segment by continuously sending
// spoofed ARP replies that tell the target the gateway's MAC address is
// the agent's own MAC address (target-only ARP poisoning). It never sends
// anything toward the gateway itself.
//
// Enforcer reuses the Sniffer's pcap handle and only learns the gateway's
// real MAC passively, from ARP replies the Sniffer already observes during
// normal discovery — it never probes for it directly.
type Enforcer struct {
	sniffer    *Sniffer
	gatewayIP  net.IP
	interval   time.Duration
	maxTargets int
	events     chan EnforcementEvent

	mu         sync.Mutex
	gatewayMAC net.HardwareAddr
	active     map[string]context.CancelFunc // key: target IP string
	closed     bool
	wg         sync.WaitGroup
}

// NewEnforcer constructs an Enforcer bound to an already-running Sniffer.
// gatewayIP is the router this agent will impersonate to blocked targets.
func NewEnforcer(s *Sniffer, gatewayIP net.IP, interval time.Duration, maxTargets int) *Enforcer {
	return &Enforcer{
		sniffer:    s,
		gatewayIP:  gatewayIP.To4(),
		interval:   interval,
		maxTargets: maxTargets,
		events:     make(chan EnforcementEvent, 64),
		active:     make(map[string]context.CancelFunc),
	}
}

// Events returns enforcement state changes for the caller to forward to the
// control plane as an audit trail.
func (e *Enforcer) Events() <-chan EnforcementEvent {
	return e.events
}

// NoteDiscovery lets the enforcer learn the gateway's real MAC address from
// ordinary scan/listen traffic so it can heal a target's ARP cache when a
// block is lifted.
func (e *Enforcer) NoteDiscovery(d Device) {
	if !d.IP.Equal(e.gatewayIP) {
		return
	}
	e.mu.Lock()
	e.gatewayMAC = append(net.HardwareAddr(nil), d.MAC...)
	e.mu.Unlock()
}

// SetTargets reconciles the desired block list against the currently active
// poisoning loops: it starts loops for newly blocked devices and stops
// (healing first) loops for devices no longer blocked. ctx bounds the
// lifetime of any newly started loop — when ctx is cancelled every active
// loop heals and exits on its own.
func (e *Enforcer) SetTargets(ctx context.Context, targets []Device) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}

	want := make(map[string]Device, len(targets))
	for _, t := range targets {
		if e.excludedLocked(t.IP) {
			continue
		}
		want[t.IP.String()] = t
	}

	for ip, cancel := range e.active {
		if _, ok := want[ip]; !ok {
			cancel()
			delete(e.active, ip)
		}
	}

	for ip, t := range want {
		if _, ok := e.active[ip]; ok {
			continue
		}
		if len(e.active) >= e.maxTargets {
			log.Printf("enforcer: at capacity (%d), ignoring MAC=%s IP=%s", e.maxTargets, t.MAC, t.IP)
			continue
		}
		tctx, cancel := context.WithCancel(ctx)
		e.active[ip] = cancel
		e.wg.Add(1)
		go e.blockLoop(tctx, t)
	}
}

// excludedLocked reports whether ip must never be targeted: the agent's own
// host, the gateway itself, or anything outside the segment this agent
// scans (ARP poisoning can't reach off-segment anyway, but policy entries
// are validated defensively rather than trusted blindly).
func (e *Enforcer) excludedLocked(ip net.IP) bool {
	if ip.Equal(e.sniffer.localIP) || ip.Equal(e.gatewayIP) {
		return true
	}
	if e.sniffer.subnet != nil && !e.sniffer.subnet.Contains(ip) {
		return true
	}
	return false
}

func (e *Enforcer) blockLoop(ctx context.Context, target Device) {
	defer e.wg.Done()
	defer e.heal(target)
	e.emit(target.MAC, "block_started")

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		if err := e.sendSpoofedReply(target, e.sniffer.iface.HardwareAddr); err != nil {
			log.Printf("enforcer: spoof MAC=%s IP=%s: %v", target.MAC, target.IP, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// heal sends one corrective ARP reply restoring the gateway's real MAC in
// the target's cache. If the real gateway MAC hasn't been observed yet, the
// target's cache entry will still self-correct once its normal ARP timeout
// expires — poisoning simply stops being refreshed.
func (e *Enforcer) heal(target Device) {
	e.mu.Lock()
	gwMAC := e.gatewayMAC
	e.mu.Unlock()
	if gwMAC == nil {
		return
	}
	if err := e.sendSpoofedReply(target, gwMAC); err != nil {
		log.Printf("enforcer: heal MAC=%s IP=%s: %v", target.MAC, target.IP, err)
		return
	}
	e.emit(target.MAC, "block_stopped")
}

// sendSpoofedReply tells target that the gateway's IP now lives at
// claimedMAC. claimedMAC is either this agent's own MAC (poison) or the
// gateway's real MAC (heal).
func (e *Enforcer) sendSpoofedReply(target Device, claimedMAC net.HardwareAddr) error {
	eth := layers.Ethernet{
		SrcMAC:       claimedMAC,
		DstMAC:       target.MAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   claimedMAC,
		SourceProtAddress: []byte(e.gatewayIP.To4()),
		DstHwAddress:      []byte(target.MAC),
		DstProtAddress:    []byte(target.IP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return e.sniffer.handle.WritePacketData(buf.Bytes())
}

func (e *Enforcer) emit(mac net.HardwareAddr, action string) {
	select {
	case e.events <- EnforcementEvent{MAC: mac.String(), Action: action}:
	default:
		log.Printf("enforcer: event channel full, dropping %s for MAC=%s", action, mac)
	}
}

// Close cancels every active poisoning loop, waits for each to send its
// healing reply, and closes the events channel. Safe to call once during
// shutdown so SIGTERM never leaves a device poisoned.
func (e *Enforcer) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	for _, cancel := range e.active {
		cancel()
	}
	e.active = make(map[string]context.CancelFunc)
	e.mu.Unlock()

	e.wg.Wait()
	close(e.events)
}
