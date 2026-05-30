// pki manages TLS certificates for gonac mTLS.
//
// Local CA modes (certs signed by your own CA):
//
//	pki -mode ca
//	pki -mode control -ip <control-plane-ip>
//	pki -mode agent   -id <agent-id> -ip <agent-ip>
//
// Vault mode (certs signed by HashiCorp Vault PKI):
//
//	pki -mode vault -role <vault-role> -ip <ip>              # control cert
//	pki -mode vault -role <vault-role> -ip <ip> -id <agent-id>  # agent cert
//
// Vault mode reads VAULT_ADDR and VAULT_TOKEN from the environment.
// All files are written to the certs/ directory.
package main

import (
	"flag"
	"fmt"
	"os"
)

const certsDir = "certs"

func main() {
	fs := flag.NewFlagSet("pki", flag.ExitOnError)
	fs.Usage = usage

	mode := fs.String("mode", "", "ca | control | agent | vault")
	id := fs.String("id", "", "agent ID — required for mode=agent; optional for mode=vault (omit for control cert)")
	ip := fs.String("ip", "", "IP address written into the certificate SAN — required for mode=control, agent, vault")
	pkiPath := fs.String("pki-path", "pki", "Vault PKI secrets engine mount path (mode=vault)")
	role := fs.String("role", "", "Vault PKI role name (mode=vault)")
	fs.Parse(os.Args[1:])

	if *mode == "" {
		usage()
		os.Exit(1)
	}

	if err := os.MkdirAll(certsDir, 0o700); err != nil {
		fatalf("mkdir certs: %v", err)
	}

	switch *mode {
	case "ca":
		generateCA()

	case "control":
		requireFlags(fs, map[string]string{"ip": *ip})
		generateControlCert(*ip)

	case "agent":
		requireFlags(fs, map[string]string{"id": *id, "ip": *ip})
		generateAgentCert(*id, *ip)

	case "vault":
		requireFlags(fs, map[string]string{"ip": *ip, "role": *role})
		issueFromVault(*pkiPath, *role, *id, *ip)

	default:
		fatalf("unknown mode %q — must be one of: ca, control, agent, vault", *mode)
	}
}

func requireFlags(fs *flag.FlagSet, required map[string]string) {
	for name, val := range required {
		if val == "" {
			fatalf("-%s is required for mode=%s", name, fs.Lookup("mode"))
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pki: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, `pki — certificate management for gonac mTLS

MODES
  Local CA (self-signed):
    pki -mode ca
    pki -mode control -ip <ip>
    pki -mode agent   -ip <ip> -id <agent-id>

  Vault PKI (requires VAULT_ADDR and VAULT_TOKEN):
    pki -mode vault -role <role> -ip <ip>              (control cert)
    pki -mode vault -role <role> -ip <ip> -id <agent-id>  (agent cert)

FLAGS`)
	flag.PrintDefaults()
}
