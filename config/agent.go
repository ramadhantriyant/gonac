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
	DNSServer      string
	ID             string
	ControlAddress string
	TLS            AgentTLS
	Enforcer       Enforcer
}

type AgentTLS struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// Enforcer configures enforcer mode — ARP-poisoning based blocking of
// devices on this agent's segment. Disabled by default; blocking a device
// is materially more invasive than passive discovery and must be an
// explicit opt-in per agent.
type Enforcer struct {
	Enabled            bool
	GatewayIP          string
	PoisonInterval     time.Duration
	PolicyPollInterval time.Duration
	MaxTargets         int
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
	v.SetDefault("enforcer.enabled", false)
	v.SetDefault("enforcer.poison_interval", 2)
	v.SetDefault("enforcer.policy_poll_interval", 10)
	v.SetDefault("enforcer.max_targets", 64)

	if !v.IsSet("network.subnet_cidr") {
		return nil, fmt.Errorf("config: network.subnet_cidr is required")
	}
	if !v.IsSet("tls.cert") || !v.IsSet("tls.key") || !v.IsSet("tls.ca") {
		return nil, fmt.Errorf("config: tls.cert, tls.key, and tls.ca are required")
	}
	if v.GetBool("enforcer.enabled") && v.GetString("enforcer.gateway_ip") == "" {
		return nil, fmt.Errorf("config: enforcer.gateway_ip is required when enforcer.enabled is true")
	}

	return &Agent{
		InterfaceName:  v.GetString("network.interface"),
		SubnetCIDR:     v.GetString("network.subnet_cidr"),
		ScanInterval:   time.Duration(v.GetInt("discovery.scan_interval")) * time.Second,
		DNSServer:      v.GetString("discovery.dns_server"),
		ID:             v.GetString("agent.id"),
		ControlAddress: v.GetString("agent.control_address"),
		TLS: AgentTLS{
			CertFile: v.GetString("tls.cert"),
			KeyFile:  v.GetString("tls.key"),
			CAFile:   v.GetString("tls.ca"),
		},
		Enforcer: Enforcer{
			Enabled:            v.GetBool("enforcer.enabled"),
			GatewayIP:          v.GetString("enforcer.gateway_ip"),
			PoisonInterval:     time.Duration(v.GetInt("enforcer.poison_interval")) * time.Second,
			PolicyPollInterval: time.Duration(v.GetInt("enforcer.policy_poll_interval")) * time.Second,
			MaxTargets:         v.GetInt("enforcer.max_targets"),
		},
	}, nil
}
