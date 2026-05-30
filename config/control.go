package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Control struct {
	DatabaseURL   string
	ListenAddress string
	AdminAddress  string
	TLS           ControlTLS
}

type ControlTLS struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

func LoadControl(path string) (*Control, error) {
	v := viper.New()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	v.SetDefault("control.listen_address", ":8443")
	v.SetDefault("admin.listen_address", ":9090")

	if !v.IsSet("database_url") {
		return nil, fmt.Errorf("config: database_url is required")
	}
	if !v.IsSet("tls.cert") || !v.IsSet("tls.key") || !v.IsSet("tls.ca") {
		return nil, fmt.Errorf("config: tls.cert, tls.key, and tls.ca are required")
	}

	return &Control{
		DatabaseURL:   v.GetString("database_url"),
		ListenAddress: v.GetString("control.listen_address"),
		AdminAddress:  v.GetString("admin.listen_address"),
		TLS: ControlTLS{
			CertFile: v.GetString("tls.cert"),
			KeyFile:  v.GetString("tls.key"),
			CAFile:   v.GetString("tls.ca"),
		},
	}, nil
}
