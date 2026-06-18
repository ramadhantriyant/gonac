# gonac

Home network access control via active ARP scanning. Discovers devices on the local network, records them in PostgreSQL, and can optionally block unwanted devices via ARP poisoning ("enforcer mode").

## Architecture

Two processes communicate over HTTPS with mutual TLS. The control plane runs two independent HTTP servers:

```
┌──────────────────────────────────┐   mTLS HTTPS :8443    ┌─────────────────────────────────────┐
│            Agent                 │ ─ POST /device ──────▶│        Agent Server (mTLS)          │
│  (Raspberry Pi / edge device)    │ ◀ GET  /policy ───────│  RequireAndVerifyClientCert         │
│  ARP scanner (active probes)     │ ─ POST /enforcement- ▶│  Cert CN == X-Agent-ID header       │
│  ARP listener (reply capture)    │       event           │  Connection IP in cert SANs         │
│  Enforcer (target-only ARP       │                       │  Device upsert → PostgreSQL         │
│   poisoning of blocked devices)  │                       │  Block list lookup, audit logging   │
│  In-memory retry queue           │                       └─────────────────────────────────────┘
│  No database access              │
└──────────────────────────────────┘
                                         HTTP :9090        ┌─────────────────────────────────────┐
                                    ◀─ GET /api/devices ───│        Admin Server (HTTP)          │
                                    ── PUT block/unblock ─▶│  Bearer token required (admin.token)│
                                                           │  Device listing, management          │
                                                           └─────────────────────────────────────┘
```

- **Agent** — runs on each network segment. Sends ARP requests to every IP in the subnet, captures replies, resolves hostnames, and POSTs discoveries to the agent server. Buffers up to 256 pending reports in memory and retries on failure. Requires elevated privileges for raw packet access. When enforcer mode is enabled, it also polls the control plane for the current block list and ARP-poisons blocked devices on its own segment.
- **Agent server** (`:8443`) — mTLS HTTPS. Every request must carry a valid client certificate. Receives device reports, serves the block list to agents, and records enforcement audit events.
- **Admin server** (`:9090`) — plain HTTP, gated by a bearer token (`admin.token`). Exposes device data and block/unblock controls for management tools, dashboards, or scripts.

## Enforcer Mode

Enforcer mode blocks a device from using the network by continuously sending it spoofed ARP replies claiming the gateway's IP address now belongs to the agent's MAC address. The target sends its traffic to the agent instead of the router, and the agent drops it. Only the target's ARP cache is poisoned — the gateway's ARP table is never touched.

This is **deterrence, not a hard ACL**:

- It only affects IPv4 traffic on the agent's own L2 segment — it cannot reach devices behind a different VLAN or subnet.
- Devices with a static ARP entry for the gateway, or switches running Dynamic ARP Inspection, are unaffected.
- It does nothing for IPv6 — a dual-stack device can route around the block over IPv6/NDP entirely.
- It is visible to anyone else capturing traffic on the segment, since the spoofed replies don't match the gateway's real MAC.

Enable it per agent via `enforcer.enabled: true` and `enforcer.gateway_ip` in `config-agent.yaml`. It is **off by default** — turning it on lets that agent disconnect devices on its segment, so it should only run on networks you control.

Safety behavior:

- The agent never targets itself or the configured gateway IP, and ignores any policy entry outside its own `subnet_cidr`.
- A capped number of devices (`enforcer.max_targets`) can be blocked concurrently per agent.
- When a block is lifted, the agent sends one corrective ("healing") ARP reply restoring the gateway's real MAC before stopping. The same healing happens on shutdown (SIGTERM) so no device is left poisoned when the agent process exits.
- If the agent can't reach the control plane for several consecutive policy polls, it fails open — every active block is released rather than risk a permanent lockout caused by a control-plane outage.

## Hostname Resolution

The agent attempts to resolve a hostname for each discovered device using four methods in order:

| Priority | Method | Covers |
|---|---|---|
| 1 | Router DNS (`dns_server:53`) | All devices with DHCP leases — most complete source |
| 2 | System reverse DNS | Devices registered in the system resolver |
| 3 | mDNS unicast (port 5353) | Apple, Linux with avahi, some IoT |
| 4 | NetBIOS NBNS (port 137) | Windows workstations |

Set `discovery.dns_server` to your router's IP to enable method 1. On a home network this is typically the most effective — routers record the hostname from the DHCP `option 12` field sent by every client.

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
│   ├── router/router.go           # Echo router + mTLS middleware + admin auth
│   ├── sniffer/                   # ARP scanner, listener, enforcer (gopacket/pcap)
│   └── store/                     # PostgreSQL persistence (pgx + sqlc)
├── db/
│   ├── embed.go                   # Embeds schema/*.sql into the binary
│   ├── schema/001_devices.sql     # Goose migration (Up + Down)
│   ├── schema/002_enforcement.sql # Adds is_blocked/blocked_at + enforcement_events
│   ├── queries/devices.sql        # sqlc query definitions
│   └── queries/enforcement_events.sql
├── config-agent.yaml.example      # Agent config template
└── config-control.yaml.example    # Control plane config template
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

Copy the example files and fill in your values:

```sh
cp config-agent.yaml.example   config-agent.yaml
cp config-control.yaml.example config-control.yaml
```

### `config-agent.yaml`

```yaml
network:
  interface: en0              # network interface to scan on
  subnet_cidr: 192.168.1.0/24

discovery:
  scan_interval: 30           # seconds between full subnet sweeps
  dns_server: 192.168.1.1     # optional: router IP for direct DNS hostname lookup

agent:
  id: home-agent-01           # must match the certificate CN
  control_address: https://192.168.1.1:8443

enforcer:
  enabled: false              # set true to let this agent block devices via ARP poisoning
  gateway_ip: 192.168.1.1     # required when enabled — router this agent impersonates
  poison_interval: 2          # seconds between spoofed ARP replies per blocked device
  policy_poll_interval: 10    # seconds between block-list fetches from the control plane
  max_targets: 64             # safety cap on concurrently blocked devices

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
  token: change-me         # required — bearer token for all /api requests

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
    is_known    BOOLEAN     NOT NULL DEFAULT FALSE,
    is_blocked  BOOLEAN     NOT NULL DEFAULT FALSE,
    blocked_at  TIMESTAMPTZ
);

CREATE TABLE enforcement_events (
    id          UUID        PRIMARY KEY,
    device_id   UUID        NOT NULL REFERENCES devices(id),
    agent_id    TEXT        NOT NULL,
    action      TEXT        NOT NULL,  -- block_started | block_stopped
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Devices are keyed by MAC address. IP address is updated on each discovery — DHCP reassignments are handled automatically. `is_known` and `is_blocked` are never overwritten by discovery, so trusted and blocked status both persist across rescans. `enforcement_events` is the audit trail of enforcement actions agents actually took, reported back asynchronously.

## HTTP API

### Agent server — `:8443` (mTLS required)

| Method | Path | Description |
|---|---|---|
| `POST` | `/device` | Report a discovered device |
| `GET` | `/policy` | Fetch the current block list (all blocked devices, control plane does not track per-agent subnets) |
| `POST` | `/enforcement-event` | Report a block/heal action for audit logging |

Request body for `POST /device`:
```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.1.42",
  "hostname": "my-laptop.local"
}
```

`hostname` is optional — omitted when the agent cannot resolve one.

`GET /policy` response:
```json
{
  "blocked": [
    { "mac_address": "aa:bb:cc:dd:ee:ff", "ip_address": "192.168.1.42" }
  ]
}
```

Request body for `POST /enforcement-event`:
```json
{ "mac_address": "aa:bb:cc:dd:ee:ff", "action": "block_started" }
```

### Admin server — `:9090` (plain HTTP, bearer token required)

Every request needs `Authorization: Bearer <admin.token>`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/devices` | List all discovered devices |
| `GET` | `/api/devices/blocked` | List currently blocked devices |
| `GET` | `/api/devices/id/:id` | Get device by UUID |
| `GET` | `/api/devices/mac/:mac` | Get device by MAC address |
| `PUT` | `/api/devices/id/:id/known` | Mark device as trusted by UUID |
| `PUT` | `/api/devices/mac/:mac/known` | Mark device as trusted by MAC address |
| `PUT` | `/api/devices/mac/:mac/blocked` | Block a device by MAC address |
| `DELETE` | `/api/devices/mac/:mac/blocked` | Unblock a device by MAC address |

Example — mark a device as trusted:
```sh
curl -X PUT http://localhost:9090/api/devices/mac/aa:bb:cc:dd:ee:ff/known \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Example — block a device (requires enforcer mode enabled on the agent covering its subnet):
```sh
curl -X PUT http://localhost:9090/api/devices/mac/aa:bb:cc:dd:ee:ff/blocked \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

> **Known limitation:** the bundled `ui/` dashboard does not yet send an `Authorization` header with its requests, so it will receive `401` responses once `admin.token` is set. The dashboard has no token-entry UI today; until that's added, use the `curl` examples above or update the dashboard's `fetch()` calls in `ui/src/api/devices.ts` to attach the bearer token.

## Privilege Note

ARP packet injection via libpcap requires elevated privileges:

| OS | Method |
|---|---|
| macOS | `sudo ./bin/gonac-agent` |
| Linux | `sudo ./bin/gonac-agent` or `sudo setcap cap_net_raw=eip ./bin/gonac-agent` |
