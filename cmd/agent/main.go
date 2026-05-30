package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	snif, err := sniffer.New(cfg.InterfaceName, cfg.SubnetCIDR, cfg.ScanInterval)
	if err != nil {
		log.Fatalf("sniffer: %v", err)
	}
	defer snif.Close()

	go snif.Run(ctx)

	log.Printf("gonac-agent: scanning %s on %s every %s → %s",
		cfg.SubnetCIDR, cfg.InterfaceName, cfg.ScanInterval, cfg.ControlAddress)

	for device := range snif.Devices() {
		client.ReportDevice(device.MAC.String(), device.IP.String(), device.Hostname)
		log.Printf("queued MAC=%s IP=%s hostname=%q", device.MAC, device.IP, device.Hostname)
	}

	log.Println("gonac-agent: stopped")
}
