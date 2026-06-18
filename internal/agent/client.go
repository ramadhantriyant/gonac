package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type payload struct {
	MacAddress string  `json:"mac_address"`
	IPAddress  string  `json:"ip_address"`
	Hostname   *string `json:"hostname,omitempty"`
}

type Client struct {
	baseURL string
	agentID string
	queue   chan payload
	http    *http.Client
}

func New(baseURL, agentID, certFile, keyFile, caFile string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("agent: load client cert: %w", err)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("agent: read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("agent: parse CA cert")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}

	return &Client{
		baseURL: baseURL,
		agentID: agentID,
		queue:   make(chan payload, 256),
		http: &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// ReportDevice enqueues a discovery. Non-blocking — drops if queue is full.
func (c *Client) ReportDevice(mac, ip, hostname string) {
	p := payload{MacAddress: mac, IPAddress: ip}
	if hostname != "" {
		p.Hostname = &hostname
	}
	select {
	case c.queue <- p:
	default:
		log.Printf("agent: queue full, dropping MAC=%s", mac)
	}
}

// Start drains the queue and POSTs each discovery to the control plane.
// On failure it requeues the payload and backs off 5s before retrying.
// Runs until ctx is cancelled.
func (c *Client) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-c.queue:
			if err := c.post(ctx, p); err != nil {
				log.Printf("agent: report failed (will retry): %v", err)
				select {
				case c.queue <- p:
				default:
				}
				select {
				case <-time.After(5 * time.Second):
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (c *Client) post(ctx context.Context, p payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/device", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

// PolicyTarget is a single blocked device as reported by the control plane.
type PolicyTarget struct {
	MacAddress string `json:"mac_address"`
	IPAddress  string `json:"ip_address"`
}

type policyResponse struct {
	Blocked []PolicyTarget `json:"blocked"`
}

// FetchPolicy retrieves the current set of blocked devices from the
// control plane. Used by enforcer mode to decide what to poison.
func (c *Client) FetchPolicy(ctx context.Context) ([]PolicyTarget, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/policy", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var p policyResponse
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	return p.Blocked, nil
}

// ReportEnforcementEvent posts a single block/heal event for audit logging
// on the control plane. Best-effort: failures are logged and dropped, the
// event is never retried or requeued.
func (c *Client) ReportEnforcementEvent(ctx context.Context, mac, action string) {
	body, err := json.Marshal(struct {
		MacAddress string `json:"mac_address"`
		Action     string `json:"action"`
	}{MacAddress: mac, Action: action})
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/enforcement-event", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.agentID)

	resp, err := c.http.Do(req)
	if err != nil {
		log.Printf("agent: enforcement event report failed: %v", err)
		return
	}
	defer resp.Body.Close()
}
