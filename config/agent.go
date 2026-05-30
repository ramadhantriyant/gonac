package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Agent struct {
	InterfaceName  string
	SubnetCIDR     string
	ScanInterval   time.Duration
	ID             string
	ControlAddress string
	TLS            AgentTLS
}

type AgentTLS struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

func LoadAgent(path string) (*Agent, error) {
	v := viper.New()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	v.SetDefault("network.interface", "en0")
	v.SetDefault("discovery.scan_interval", 30)
	v.SetDefault("agent.id", "agent-01")
	v.SetDefault("agent.control_address", "https://localhost:8443")

	if !v.IsSet("network.subnet_cidr") {
		return nil, fmt.Errorf("config: network.subnet_cidr is required")
	}
	if !v.IsSet("tls.cert") || !v.IsSet("tls.key") || !v.IsSet("tls.ca") {
		return nil, fmt.Errorf("config: tls.cert, tls.key, and tls.ca are required")
	}

	return &Agent{
		InterfaceName:  v.GetString("network.interface"),
		SubnetCIDR:     v.GetString("network.subnet_cidr"),
		ScanInterval:   time.Duration(v.GetInt("discovery.scan_interval")) * time.Second,
		ID:             v.GetString("agent.id"),
		ControlAddress: v.GetString("agent.control_address"),
		TLS: AgentTLS{
			CertFile: v.GetString("tls.cert"),
			KeyFile:  v.GetString("tls.key"),
			CAFile:   v.GetString("tls.ca"),
		},
	}, nil
}
