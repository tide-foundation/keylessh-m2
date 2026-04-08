# KeyleSSH Punchd Bridge (Rust)

NAT-traversing authenticated reverse proxy gateway. Handles WebRTC (browsers), QUIC P2P (native VPN), and HTTP relay — with full TideCloak OIDC + DPoP authentication.

## What it does

```
Browser ──WebRTC P2P (ICE hole-punched)───────────────────> Gateway ──proxy──> Local Backends
Browser ──WebRTC via TURN relay───────────────────────────> Gateway ──proxy──> Local Backends (fallback)
VPN Client ──QUIC P2P (STUN hole-punched)─────────────────> Gateway ──TUN──> LAN (192.168.x)
VPN Client ──QUIC via TURN relay──────────────────────────> Gateway ──TUN──> LAN (fallback)
```
Signal server provides signaling (WebSocket) for both WebRTC and QUIC — peers exchange addresses, then connect directly P2P.

The gateway:
1. Registers with a public signaling server (or runs offline/standalone)
2. Accepts WebRTC DataChannel connections from browsers (NAT-traversed via ICE)
3. Accepts native QUIC P2P connections from VPN clients (NAT hole-punched via STUN)
4. Falls back to TURN relay when direct P2P fails (symmetric NAT)
5. Authenticates users via TideCloak OIDC (server-side login flow)
6. Verifies JWTs and DPoP proofs (RFC 9449)
7. Proxies authorized HTTP requests to local backends (multi-backend routing)
8. Tunnels WebSocket and raw TCP connections (RDP via RDCleanPath protocol)
9. Tunnels IP packets over QUIC datagrams for VPN (unreliable, low-overhead)
10. Enforces per-session software firewall from JWT role-based rules

## Features

- **WebRTC dual DataChannels**: control (JSON) + bulk (binary streaming) with backpressure
- **QUIC P2P VPN**: NAT hole-punched direct tunnel, TURN relay fallback
- **DPoP verification**: Validates DPoP proofs on QUIC auth stream (RFC 9449)
- **VPN firewall**: Per-user rules from JWT roles (`vpn:<gw>:<allow|deny>:<cidr>:<ports>`)
- **Auto LAN detection**: Gateway discovers local subnets and pushes routes to VPN clients
- **Offline mode**: Runs without signal server — clients connect directly via Gateways tab
- **RDCleanPath protocol**: ASN.1 DER-encoded PDUs for RDP connection negotiation
- **Server-side OIDC**: TideCloak login/callback/logout/session-token endpoints
- **Path-based routing**: `/__b/<name>/` prefix system with HTML URL rewriting
- **TURN ephemeral credentials**: HMAC-SHA1 REST API credentials
- **Self-signed TLS**: In-memory cert generation via rcgen
- **Gateway info API**: `/api/info` returns gateway ID, display name, and backends

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `STUN_SERVER_URL` | WebSocket URL of the signaling server | No (offline mode if unset) |
| `API_SECRET` | Shared secret for signaling server API auth | Only with signal server |
| `BACKENDS` | Backend list: `name1=http://host:port,name2=rdp://host:3389` | Yes* |
| `BACKEND_URL` | Single backend URL (alternative to BACKENDS) | Yes* |
| `TIDECLOAK_CONFIG_B64` | Base64-encoded TideCloak config | No** |
| `TIDECLOAK_CONFIG_PATH` | Path to tidecloak.json | No** |
| `LISTEN_PORT` | HTTP/HTTPS proxy port | No (default: 7891) |
| `HEALTH_PORT` | Health check port | No (default: 7892) |
| `QUIC_PORT` | QUIC/VPN UDP port | No (default: 7893) |
| `HTTPS` | Enable HTTPS with self-signed cert | No (default: true) |
| `TLS_HOSTNAME` | Hostname for self-signed cert | No (default: localhost) |
| `GATEWAY_ID` | Unique gateway identifier | No (auto-generated) |
| `GATEWAY_DISPLAY_NAME` | Display name for portal | No |
| `GATEWAY_DESCRIPTION` | Description for portal | No |
| `TURN_SERVER` | TURN server URL (e.g. `turn:host:3478`) | No |
| `TURN_SECRET` | Shared secret for TURN REST API credentials | No |
| `ICE_SERVERS` | Comma-separated ICE servers | No (derived from STUN URL) |
| `AUTH_SERVER_PUBLIC_URL` | Public TideCloak URL for browser redirects | No |
| `TC_INTERNAL_URL` | Internal TideCloak URL for server-side requests | No |
| `TC_CLIENT_ID` | Override client ID for role lookups | No |
| `GATEWAY_ADDRESS` | Override advertised address | No |

\* Either `BACKENDS` or `BACKEND_URL` is required.
\** Defaults to `data/tidecloak.json` if neither is set.

### Backend flags

Append flags to backend URLs with `;`:
- `;eddsa` — Tide JWT validation using the tide-ssp driver
- `;noauth` — skip JWT validation (backend handles its own auth)
- `;stripauth` — remove Authorization header before proxying

Example: `BACKENDS=app=http://localhost:3000,admin=http://localhost:8080;stripauth,rdp=rdp://192.168.1.100:3389`

---

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 7891 | TCP | HTTP/HTTPS reverse proxy |
| 7892 | TCP | Health check |
| 7893 | UDP | QUIC VPN (P2P + STUN hole-punch) |

---

## Docker Deployment

### Build

```bash
docker buildx build --no-cache -t keylessh-punchd-bridge-rs .
```

### Run

```bash
docker run --rm -d \
  --name keylessh-punchd-bridge \
  -p 7891:7891 -p 7892:7892 -p 7893:7893/udp \
  -v $(pwd)/../../data:/app/data \
  -e STUN_SERVER_URL=wss://stun-server:9090 \
  -e API_SECRET=your-secret \
  -e BACKENDS=myapp=http://host.docker.internal:3000 \
  keylessh-punchd-bridge-rs
```

### Offline mode (no signal server)

```bash
docker run --rm -d \
  --name keylessh-gateway \
  -p 7891:7891 -p 7892:7892 -p 7893:7893/udp \
  -e TIDECLOAK_CONFIG_B64=$(base64 -w0 data/tidecloak.json) \
  -e BACKENDS=myapp=http://host.docker.internal:3000 \
  -e GATEWAY_DISPLAY_NAME="Office Gateway" \
  keylessh-punchd-bridge-rs
```

Clients connect directly via the Gateways tab in the web UI using the gateway's URL.

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/info` | GET | No | Gateway info (ID, name, backends) for local discovery |
| `/api/health` (port 7892) | GET | No | Health check (`{"status":"ok"}`) |

## VPN

The gateway supports native VPN clients over QUIC:

- **Protocol**: QUIC datagrams (unreliable) for IP packets, QUIC streams for control
- **Auth**: JWT + DPoP proof on QUIC auth stream (WebView2 Heimdall enclave)
- **Roles**: `vpn:<gatewayId>` required, firewall rules from `vpn:<gw>:<allow|deny>:<cidr>:<ports>`
- **NAT traversal**: STUN hole-punch on same UDP socket, TURN relay fallback
- **Subnet**: 10.66.0.0/24 by default
- **Routes**: Auto-detected LAN subnets pushed to client on tunnel open

## Local Development

### Prerequisites

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- `data/tidecloak.json` — TideCloak client adapter config
- A running signaling server (optional — works offline)

### Build and run

```bash
cd bridges/punchd-bridge-rs

# Development
STUN_SERVER_URL=ws://localhost:3478 \
API_SECRET=your-secret \
BACKENDS=myapp=http://localhost:3000 \
cargo run

# Production build
cargo build --release
./target/release/punchd-bridge-rs
```

### Build VPN client

```bash
# Windows with WebView2 DPoP support
cargo build --release --target x86_64-pc-windows-gnu --features webview --bin punchd-vpn

# Linux/macOS (browser fallback)
cargo build --release --bin punchd-vpn
```
