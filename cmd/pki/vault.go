package main

import (
	"context"
	"log"
	"os"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// issueFromVault issues a certificate via Vault's PKI secrets engine.
// If agentID is empty, a control plane cert (server auth) is issued.
// If agentID is set, an agent cert (client auth) is issued.
//
// Reads VAULT_ADDR and VAULT_TOKEN from the environment.
func issueFromVault(pkiPath, role, agentID, ipStr string) {
	client, err := vault.New(vault.WithAddress(os.Getenv("VAULT_ADDR")))
	if err != nil {
		log.Fatalf("vault: create client: %v", err)
	}

	if err := client.SetToken(os.Getenv("VAULT_TOKEN")); err != nil {
		log.Fatalf("vault: set token: %v", err)
	}

	commonName := "gonac-control"
	if agentID != "" {
		commonName = agentID
	}

	resp, err := client.Secrets.PkiIssueWithRole(
		context.Background(),
		role,
		schema.PkiIssueWithRoleRequest{
			CommonName: commonName,
			IpSans:     []string{ipStr},
			Ttl:        "8760h",
		},
		vault.WithMountPath(pkiPath),
	)
	if err != nil {
		log.Fatalf("vault: issue cert (mount=%s role=%s): %v", pkiPath, role, err)
	}

	cert := resp.Data.Certificate
	key := resp.Data.PrivateKey
	ca := resp.Data.IssuingCa

	if cert == "" || key == "" || ca == "" {
		log.Fatal("vault: response missing certificate, private_key, or issuing_ca")
	}

	var certName, keyName string
	if agentID != "" {
		certName = "agent-" + agentID + ".crt"
		keyName = "agent-" + agentID + ".key"
	} else {
		certName = "control.crt"
		keyName = "control.key"
	}

	writeRaw(certName, cert, 0o644)
	writeRaw(keyName, key, 0o600)
	writeRaw("ca.crt", ca, 0o644)
	log.Printf("issued certs/%s and certs/%s via Vault (mount=%s role=%s)", certName, keyName, pkiPath, role)
}
