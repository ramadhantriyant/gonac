package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ramadhantriyant/gonac/config"
	"github.com/ramadhantriyant/gonac/internal/agent"
	"github.com/ramadhantriyant/gonac/internal/sniffer"
)

func main() {
	configPath := "config-agent.yaml"
	if p := os.Getenv("GONAC_CONFIG"); p != "" {
		configPath = p
	}

	cfg, err := config.LoadAgent(configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client, err := agent.New(cfg.ControlAddress, cfg.ID, cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.CAFile)
	if err != nil {
		log.Fatalf("agent client: %v", err)
	}
	go client.Start(ctx)

	snif, err := sniffer.New(cfg.InterfaceName, cfg.SubnetCIDR, cfg.ScanInterval, cfg.DNSServer)
	if err != nil {
		log.Fatalf("sniffer: %v", err)
	}
	defer snif.Close()

	var enf *sniffer.Enforcer
	if cfg.Enforcer.Enabled {
		enf = startEnforcer(ctx, cfg.Enforcer, client, snif)
		defer enf.Close()
		log.Printf("gonac-agent: enforcer mode enabled, gateway=%s poison_interval=%s",
			cfg.Enforcer.GatewayIP, cfg.Enforcer.PoisonInterval)
	}

	go snif.Run(ctx)

	log.Printf("gonac-agent: scanning %s on %s every %s → %s",
		cfg.SubnetCIDR, cfg.InterfaceName, cfg.ScanInterval, cfg.ControlAddress)

	for device := range snif.Devices() {
		if enf != nil {
			enf.NoteDiscovery(device)
		}
		client.ReportDevice(device.MAC.String(), device.IP.String(), device.Hostname)
		log.Printf("queued MAC=%s IP=%s hostname=%q", device.MAC, device.IP, device.Hostname)
	}

	log.Println("gonac-agent: stopped")
}

// startEnforcer builds the enforcement engine and starts its background
// loops: one drains enforcement events to the control plane for audit
// logging, the other polls the control plane's block list and reconciles
// it against active ARP-poisoning loops. If the control plane becomes
// unreachable for too many consecutive polls, every active block is
// released (fail-open) rather than risk a permanent lockout caused by a
// control-plane outage.
func startEnforcer(ctx context.Context, cfg config.Enforcer, client *agent.Client, snif *sniffer.Sniffer) *sniffer.Enforcer {
	gatewayIP := net.ParseIP(cfg.GatewayIP)
	if gatewayIP == nil {
		log.Fatalf("enforcer: invalid gateway_ip %q", cfg.GatewayIP)
	}

	enf := sniffer.NewEnforcer(snif, gatewayIP, cfg.PoisonInterval, cfg.MaxTargets)

	go func() {
		for ev := range enf.Events() {
			client.ReportEnforcementEvent(ctx, ev.MAC, ev.Action)
		}
	}()

	go func() {
		const maxMissed = 5
		missed := 0

		ticker := time.NewTicker(cfg.PolicyPollInterval)
		defer ticker.Stop()

		for {
			targets, err := client.FetchPolicy(ctx)
			if err != nil {
				missed++
				log.Printf("enforcer: policy fetch failed (%d/%d): %v", missed, maxMissed, err)
				if missed >= maxMissed {
					log.Printf("enforcer: control plane unreachable, releasing all blocks")
					enf.SetTargets(ctx, nil)
				}
			} else {
				missed = 0
				enf.SetTargets(ctx, toDevices(targets))
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	return enf
}

func toDevices(targets []agent.PolicyTarget) []sniffer.Device {
	devices := make([]sniffer.Device, 0, len(targets))
	for _, t := range targets {
		mac, err := net.ParseMAC(t.MacAddress)
		if err != nil {
			log.Printf("enforcer: skipping policy entry, invalid MAC %q: %v", t.MacAddress, err)
			continue
		}
		ip := net.ParseIP(t.IPAddress)
		if ip == nil {
			log.Printf("enforcer: skipping policy entry, invalid IP %q", t.IPAddress)
			continue
		}
		devices = append(devices, sniffer.Device{MAC: mac, IP: ip})
	}
	return devices
}
