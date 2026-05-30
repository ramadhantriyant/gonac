package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func generateCA() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "gonac-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}

	writeCert("ca.crt", certDER)
	writeKey("ca.key", key)
	log.Println("generated certs/ca.crt and certs/ca.key")
}

func generateControlCert(ipStr string) {
	caKey, caCert := loadCA()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("invalid IP: %s", ipStr)
	}

	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "gonac-control"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}

	writeCert("control.crt", certDER)
	writeKey("control.key", key)
	log.Println("generated certs/control.crt and certs/control.key")
}

func generateAgentCert(agentID, ipStr string) {
	caKey, caCert := loadCA()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("invalid IP: %s", ipStr)
	}

	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{ip},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}

	name := "agent-" + agentID
	writeCert(name+".crt", certDER)
	writeKey(name+".key", key)
	log.Printf("generated certs/%s.crt and certs/%s.key", name, name)
}

func loadCA() (*ecdsa.PrivateKey, *x509.Certificate) {
	keyPEM, err := os.ReadFile(filepath.Join(certsDir, "ca.key"))
	if err != nil {
		log.Fatalf("read ca.key: %v — run 'pki -mode ca' first", err)
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("parse ca.key: %v", err)
	}

	certPEM, err := os.ReadFile(filepath.Join(certsDir, "ca.crt"))
	if err != nil {
		log.Fatalf("read ca.crt: %v", err)
	}
	block, _ = pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("parse ca.crt: %v", err)
	}

	return key, cert
}

func writeCert(name string, der []byte) {
	f, err := os.OpenFile(filepath.Join(certsDir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		log.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeKey(name string, key *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	f, err := os.OpenFile(filepath.Join(certsDir, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func writeRaw(name, content string, perm os.FileMode) {
	if err := os.WriteFile(filepath.Join(certsDir, name), []byte(content), perm); err != nil {
		log.Fatalf("write %s: %v", name, err)
	}
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("serial: %v", err)
	}
	return n
}
