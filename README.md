# gonac

Home network access control via active ARP scanning. Discovers devices on the local network and records them in PostgreSQL.

## Architecture

Two processes communicate over HTTPS with mutual TLS. The control plane runs two independent HTTP servers:

```
┌──────────────────────────────────┐   mTLS HTTPS :8443   ┌─────────────────────────────────────┐
│            Agent                 │ ─── POST /device ────▶│        Agent Server (mTLS)          │
│  (Raspberry Pi / edge device)    │                       │  RequireAndVerifyClientCert         │
│  ARP scanner (active probes)     │                       │  Cert CN == X-Agent-ID header       │
│  ARP listener (reply capture)    │                       │  Connection IP in cert SANs         │
│  In-memory retry queue           │                       │  Device upsert → PostgreSQL         │
│  No database access              │                       └─────────────────────────────────────┘
└──────────────────────────────────┘
                                         HTTP :9090        ┌─────────────────────────────────────┐
                                    ◀─ GET /api/devices ───│        Admin Server (HTTP)          │
                                                           │  No client cert required            │
                                                           │  Device listing, management         │
                                                           └─────────────────────────────────────┘
```

- **Agent** — runs on each network segment. Sends ARP requests to every IP in the subnet, captures replies, and POSTs discoveries to the agent server. Buffers up to 256 pending reports in memory and retries on failure. Requires elevated privileges for raw packet access.
- **Agent server** (`:8443`) — mTLS HTTPS. Every request must carry a valid client certificate. Receives device reports and upserts them into PostgreSQL.
- **Admin server** (`:9090`) — plain HTTP. No client certificate required. Exposes device data for management tools, dashboards, or scripts.

## Authentication

Both sides authenticate each other via mutual TLS using a private CA:

| Party | Holds | Shared |
|---|---|---|
| CA | `ca.key` (kept offline after setup) | `ca.crt` (distributed to all) |
| Control plane | `control.key` | `control.crt` |
| Agent | `agent-<id>.key` | `agent-<id>.crt` |

On every request the control plane verifies:
1. Client certificate is signed by the CA (TLS layer)
2. Certificate CN matches the `X-Agent-ID` header
3. Connection IP is listed in the certificate's IP SANs

Agent certificates embed the agent's IP address. If the IP changes, the certificate must be reissued. Use a DHCP reservation to keep the agent IP stable.

> **Note:** The agent server cannot sit behind a reverse proxy. mTLS termination happens at the application layer — the client certificate must reach `internal/control/server.go` directly. The admin server has no such restriction.

## Project Structure

```
gonac/
├── cmd/
│   ├── agent/main.go              # Agent binary
│   ├── control/main.go            # Control plane binary
│   └── pki/                       # Certificate management tool
│       ├── main.go                #   Flag parsing and dispatch
│       ├── local.go               #   Local CA modes (ca, control, agent)
│       └── vault.go               #   Vault PKI mode
├── config/
│   ├── agent.go                   # Agent config loader (viper)
│   └── control.go                 # Control plane config loader (viper)
├── internal/
│   ├── agent/client.go            # mTLS HTTP client + retry queue
│   ├── control/server.go          # HTTPS server (mTLS, http.Server)
│   ├── handler/                   # Echo HTTP handlers
│   ├── router/router.go           # Echo router + mTLS middleware
│   ├── sniffer/                   # ARP scanner + listener (gopacket/pcap)
│   └── store/                     # PostgreSQL persistence (pgx + sqlc)
├── db/
│   ├── embed.go                   # Embeds schema/*.sql into the binary
│   ├── schema/001_devices.sql     # Goose migration (Up + Down)
│   └── queries/devices.sql        # sqlc query definitions
├── config-agent.yaml              # Agent runtime configuration
└── config-control.yaml            # Control plane runtime configuration
```

## Prerequisites

- Go 1.26+
- PostgreSQL
- libpcap (`brew install libpcap` on macOS, `apt install libpcap-dev` on Linux)

Database migrations run automatically on control plane startup — no separate migration step required.

## Certificate Setup

Certificates are managed via the `pki` tool. Choose either local CA or Vault.

### Option A — Local CA

```sh
# 1. Build the tool
go build -o bin/pki ./cmd/pki

# 2. Generate the CA (run once, keep ca.key offline after this)
./bin/pki -mode ca

# 3. Generate the control plane certificate
./bin/pki -mode control -ip 192.168.1.1

# 4. Generate an agent certificate
./bin/pki -mode agent -id home-agent-01 -ip 192.168.1.10
```

### Option B — HashiCorp Vault PKI

```sh
# Control plane certificate
VAULT_ADDR=https://vault:8200 VAULT_TOKEN=... \
  ./bin/pki -mode vault -role control-role -ip 192.168.1.1

# Agent certificate
VAULT_ADDR=https://vault:8200 VAULT_TOKEN=... \
  ./bin/pki -mode vault -role agent-role -id home-agent-01 -ip 192.168.1.10 \
  [-pki-path custom-pki-mount]  # default: pki
```

Both modes write files to `certs/`: `control.crt`, `control.key`, `agent-<id>.crt`, `agent-<id>.key`, `ca.crt`.

Distribute to each machine:

| Machine | Files needed |
|---|---|
| Control plane | `certs/control.crt`, `certs/control.key`, `certs/ca.crt` |
| Agent (Raspberry Pi) | `certs/agent-<id>.crt`, `certs/agent-<id>.key`, `certs/ca.crt` |

## Configuration

### `config-agent.yaml`

```yaml
network:
  interface: en0              # network interface to scan on
  subnet_cidr: 192.168.1.0/24

discovery:
  scan_interval: 30           # seconds between full subnet sweeps

agent:
  id: home-agent-01           # must match the certificate CN
  control_address: https://192.168.1.1:8443

tls:
  cert: certs/agent-home-agent-01.crt
  key: certs/agent-home-agent-01.key
  ca: certs/ca.crt
```

### `config-control.yaml`

```yaml
database_url: postgres://user:pass@localhost:5432/gonac

control:
  listen_address: :8443   # agent server (mTLS)

admin:
  listen_address: :9090   # admin server (plain HTTP)

tls:
  cert: certs/control.crt
  key: certs/control.key
  ca: certs/ca.crt
```

Config file path defaults to `config-agent.yaml` / `config-control.yaml` in the working directory. Override with `GONAC_CONFIG`.

## Build and Run

```sh
go build -o bin/gonac-agent   ./cmd/agent
go build -o bin/gonac-control ./cmd/control
```

Start the control plane first, then the agent:

```sh
# Control plane (runs migrations automatically on startup)
./bin/gonac-control

# Agent (requires raw packet access)
sudo ./bin/gonac-agent
```

## Database Schema

```sql
CREATE TABLE devices (
    id          UUID        PRIMARY KEY,
    mac_address TEXT        NOT NULL UNIQUE,
    ip_address  TEXT        NOT NULL,
    hostname    TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_known    BOOLEAN     NOT NULL DEFAULT FALSE
);
```

Devices are keyed by MAC address. IP address is updated on each discovery — DHCP reassignments are handled automatically. Mark a device as trusted:

```sql
UPDATE devices SET is_known = TRUE WHERE mac_address = 'aa:bb:cc:dd:ee:ff';
```

## HTTP API

### Agent server — `:8443` (mTLS required)

| Method | Path | Description |
|---|---|---|
| `POST` | `/device` | Report a discovered device |

Request body:
```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.1.42"
}
```

### Admin server — `:9090` (plain HTTP)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/devices` | List all discovered devices |

## Privilege Note

ARP packet injection via libpcap requires elevated privileges:

| OS | Method |
|---|---|
| macOS | `sudo ./bin/gonac-agent` |
| Linux | `sudo ./bin/gonac-agent` or `sudo setcap cap_net_raw=eip ./bin/gonac-agent` |
