# Punchd VPN — Packaging & Deployment

Punchd VPN tunnels IP traffic through punchd-bridge gateways using WebRTC DataChannels. It runs as a system service, auto-connects on boot, and auto-reconnects on disconnect.

## Table of Contents

- [Config File](#config-file)
- [Windows](#windows)
  - [MSI Installer](#msi-installer-recommended)
  - [Standalone EXE (GUI)](#standalone-exe-gui)
  - [Headless / Windows Server](#headless--windows-server)
  - [CLI Mode](#cli-mode)
  - [Windows Service Management](#windows-service-management)
  - [Windows Troubleshooting](#windows-troubleshooting)
- [Linux](#linux)
  - [Debian/Ubuntu (.deb)](#debianubuntu-deb)
  - [RHEL/CentOS/Fedora](#rhelcentosfedora)
  - [Generic Linux (install script)](#generic-linux-install-script)
  - [Manual Linux Setup](#manual-linux-setup)
  - [Headless Linux Server](#headless-linux-server)
  - [Linux Service Management](#linux-service-management)
- [macOS](#macos)
- [Docker](#docker)
- [Architecture](#architecture)
- [Firewall Rules](#firewall-rules)
- [Agent HTTP API](#agent-http-api)

---

## Config File

All platforms use `vpn-config.toml`:

```toml
stun_server = "wss://punchd.example.com"
gateway_id = "my-gateway"

# Auth — one of these is required:
tidecloak_config_b64 = "eyJyZWFs..."          # base64-encoded tidecloak.json
# tidecloak_config_path = "/etc/punchd-vpn/tidecloak.json"   # or path to file

# ICE/TURN — required for NAT traversal
ice_server = "stun:turn.example.com:3478"
turn_server = "turn:turn.example.com:3478"
turn_secret = "your-turn-secret"

# Optional
default_route = false                          # true = route ALL traffic through VPN
```

### Required Fields

| Field | Description |
|---|---|
| `stun_server` | Signal server WebSocket URL (e.g. `wss://punchd.example.com`) |
| `gateway_id` | Target gateway ID to connect to |
| `tidecloak_config_b64` or `tidecloak_config_path` | TideCloak adapter config for OIDC auth |

### Optional Fields

| Field | Description | Default |
|---|---|---|
| `ice_server` | STUN server for ICE candidates | none |
| `turn_server` | TURN relay server URL | none |
| `turn_secret` | TURN shared secret for credential generation | none |
| `default_route` | Route all traffic through VPN | `false` |

### Config Locations

| Platform | Path |
|---|---|
| Windows | `C:\ProgramData\punchd-vpn\vpn-config.toml` |
| Linux | `/etc/punchd-vpn/vpn-config.toml` |
| macOS | `/etc/punchd-vpn/vpn-config.toml` |

### Getting the Config

Download from KeyleSSH admin UI:
1. Go to **Admin > Gateways**
2. Select a gateway
3. Click **Download VPN Config**

Or create manually using the template above.

---

## Windows

### MSI Installer (recommended)

**Prerequisites:** [WiX Toolset v4+](https://wixtoolset.org/)
```powershell
dotnet tool install --global wix
wix extension add WixToolset.UI.wixext
```

**Build the MSI:**
```powershell
# Cross-compile from Linux/WSL
cargo build --release --target x86_64-pc-windows-gnu --bin punchd-vpn

# Build MSI (from Windows/PowerShell)
cd wix
.\build-msi.ps1
```

**GUI install (desktop users):**
```
double-click punchd-vpn-1.0.0.msi
```
Wizard walks through install. Config file can be selected during setup.

**Silent install (no GUI — for servers, scripts, Group Policy):**
```cmd
:: Basic silent install
msiexec /i punchd-vpn-1.0.0.msi /qn /l*v install.log

:: Silent install with config file
msiexec /i punchd-vpn-1.0.0.msi /qn VPNCONFIGSOURCE=C:\path\to\vpn-config.toml

:: Silent install + custom install dir
msiexec /i punchd-vpn-1.0.0.msi /qn INSTALLFOLDER="D:\Tools\PunchdVPN" VPNCONFIGSOURCE=C:\vpn-config.toml

:: Silent install from network share
msiexec /i \\fileserver\share\punchd-vpn-1.0.0.msi /qn VPNCONFIGSOURCE=\\fileserver\share\vpn-config.toml

:: Silent uninstall
msiexec /x punchd-vpn-1.0.0.msi /qn

:: Upgrade (installs new, removes old)
msiexec /i punchd-vpn-1.1.0.msi /qn
```

**PowerShell silent install:**
```powershell
# Download and install
$msi = "punchd-vpn-1.0.0.msi"
$config = "C:\deploy\vpn-config.toml"
Start-Process msiexec -ArgumentList "/i `"$msi`" /qn VPNCONFIGSOURCE=`"$config`" /l*v install.log" -Wait -NoNewWindow

# Verify service is running
Get-Service punchd-vpn
```

**Group Policy deployment:**
1. Place MSI + config on a network share accessible by target machines
2. Group Policy > Computer Configuration > Software Settings > Software installation
3. Add the MSI package
4. Set `VPNCONFIGSOURCE=\\share\vpn-config.toml` as a transform or use a wrapper script

### Standalone EXE (GUI)

For quick single-machine setup without building an MSI:

1. Double-click `punchd-vpn.exe`
2. Native file picker asks for `vpn-config.toml`
3. Config validated and copied to `C:\ProgramData\punchd-vpn\`
4. UAC prompt for admin privileges
5. Windows Service installed and started automatically
6. Success dialog shown

### Headless / Windows Server

For Windows Server Core or headless machines with no GUI:

```cmd
:: 1. Copy the exe and config to the server
copy punchd-vpn.exe C:\Tools\
copy vpn-config.toml C:\ProgramData\punchd-vpn\

:: 2. Create the config directory
mkdir C:\ProgramData\punchd-vpn

:: 3. Copy config
copy vpn-config.toml C:\ProgramData\punchd-vpn\vpn-config.toml

:: 4. Install service (run as admin)
C:\Tools\punchd-vpn.exe --install-service

:: 5. Verify
sc query punchd-vpn
```

**Via PowerShell remoting:**
```powershell
# Remote install to a headless server
$session = New-PSSession -ComputerName SERVER01
Copy-Item punchd-vpn.exe -Destination "C:\Tools\" -ToSession $session
Copy-Item vpn-config.toml -Destination "C:\ProgramData\punchd-vpn\" -ToSession $session
Invoke-Command -Session $session {
    New-Item -ItemType Directory -Force -Path "C:\ProgramData\punchd-vpn"
    Copy-Item "C:\ProgramData\punchd-vpn\vpn-config.toml" -Force
    & "C:\Tools\punchd-vpn.exe" --install-service
}
```

**Via SSH:**
```bash
scp punchd-vpn.exe administrator@server:C:/Tools/
scp vpn-config.toml administrator@server:C:/ProgramData/punchd-vpn/
ssh administrator@server "C:\Tools\punchd-vpn.exe --install-service"
```

### CLI Mode

For temporary/testing use without installing a service:

```cmd
:: Single connection with OIDC browser login
punchd-vpn --standalone --stun-server wss://stun.example.com --gateway-id my-gateway

:: With all options
punchd-vpn --standalone ^
  --stun-server wss://punchd.example.com ^
  --gateway-id SashasKC ^
  --config C:\path\to\tidecloak.json ^
  --ice-server stun:turn.example.com:3478 ^
  --turn-server turn:turn.example.com:3478 ^
  --turn-secret your-secret ^
  --default-route
```

### Windows Service Management

```cmd
:: Status
sc query punchd-vpn
sc qc punchd-vpn          &:: show config (start type, exe path)

:: Start / Stop / Restart
sc start punchd-vpn
sc stop punchd-vpn
sc stop punchd-vpn && sc start punchd-vpn

:: Disable auto-start (keep installed but don't start on boot)
sc config punchd-vpn start=demand

:: Re-enable auto-start
sc config punchd-vpn start=auto

:: Uninstall service
punchd-vpn.exe --uninstall-service

:: View logs (Event Viewer)
eventvwr /c:Application
:: Or PowerShell:
Get-WinEvent -LogName Application -FilterXPath "*[System[Provider[@Name='punchd-vpn']]]" -MaxEvents 50
```

### Windows Troubleshooting

```cmd
:: Check if service is running
sc query punchd-vpn

:: Check config exists
type C:\ProgramData\punchd-vpn\vpn-config.toml

:: Check TUN adapter created
ipconfig /all | findstr punchd

:: Check routes
route print | findstr 10.66

:: Test connectivity through VPN
ping 10.66.0.1

:: Run manually for debug output (stop service first)
sc stop punchd-vpn
punchd-vpn.exe --standalone
```

---

## Linux

### Debian/Ubuntu (.deb)

**Build:**
```bash
cargo install cargo-deb
cargo build --release --bin punchd-vpn
cargo deb
```

**Install:**
```bash
sudo dpkg -i target/debian/punchd-vpn_1.0.0_amd64.deb

# Add config
sudo mkdir -p /etc/punchd-vpn
sudo tee /etc/punchd-vpn/vpn-config.toml << 'EOF'
stun_server = "wss://punchd.example.com"
gateway_id = "my-gateway"
tidecloak_config_b64 = "eyJyZWFs..."
ice_server = "stun:turn.example.com:3478"
turn_server = "turn:turn.example.com:3478"
turn_secret = "your-secret"
EOF

# Start
sudo systemctl start punchd-vpn
```

**Uninstall:**
```bash
sudo dpkg -r punchd-vpn
```

### RHEL/CentOS/Fedora

No RPM packaging yet — use the generic install script:

```bash
sudo ./pkg/install.sh /path/to/vpn-config.toml
```

### Generic Linux (install script)

```bash
cargo build --release --bin punchd-vpn

# Install with config
sudo ./pkg/install.sh /path/to/vpn-config.toml

# Install without config (add config later)
sudo ./pkg/install.sh
```

### Manual Linux Setup

```bash
# Copy binary
sudo cp target/release/punchd-vpn /usr/bin/
sudo chmod 755 /usr/bin/punchd-vpn

# Copy systemd service
sudo cp pkg/punchd-vpn.service /etc/systemd/system/

# Create config
sudo mkdir -p /etc/punchd-vpn
sudo nano /etc/punchd-vpn/vpn-config.toml

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable punchd-vpn
sudo systemctl start punchd-vpn
```

### Headless Linux Server

**One-liner remote install via SSH:**
```bash
# From your workstation:
scp target/release/punchd-vpn pkg/punchd-vpn.service vpn-config.toml root@server:/tmp/
ssh root@server 'cp /tmp/punchd-vpn /usr/bin/ && chmod 755 /usr/bin/punchd-vpn && \
  cp /tmp/punchd-vpn.service /etc/systemd/system/ && \
  mkdir -p /etc/punchd-vpn && cp /tmp/vpn-config.toml /etc/punchd-vpn/ && \
  systemctl daemon-reload && systemctl enable --now punchd-vpn'
```

**Ansible playbook:**
```yaml
- name: Install Punchd VPN
  hosts: vpn_clients
  become: yes
  tasks:
    - copy:
        src: punchd-vpn
        dest: /usr/bin/punchd-vpn
        mode: '0755'
    - copy:
        src: punchd-vpn.service
        dest: /etc/systemd/system/punchd-vpn.service
    - file:
        path: /etc/punchd-vpn
        state: directory
    - copy:
        src: vpn-config.toml
        dest: /etc/punchd-vpn/vpn-config.toml
        mode: '0600'
    - systemd:
        name: punchd-vpn
        enabled: yes
        state: started
        daemon_reload: yes
```

**Cloud-init (AWS, Azure, GCP):**
```yaml
#cloud-config
write_files:
  - path: /etc/punchd-vpn/vpn-config.toml
    permissions: '0600'
    content: |
      stun_server = "wss://punchd.example.com"
      gateway_id = "my-gateway"
      tidecloak_config_b64 = "eyJyZWFs..."
      turn_server = "turn:turn.example.com:3478"
      turn_secret = "your-secret"

runcmd:
  - curl -fsSL https://example.com/punchd-vpn -o /usr/bin/punchd-vpn
  - chmod 755 /usr/bin/punchd-vpn
  - curl -fsSL https://example.com/punchd-vpn.service -o /etc/systemd/system/punchd-vpn.service
  - systemctl daemon-reload
  - systemctl enable --now punchd-vpn
```

### Linux Service Management

```bash
# Status
sudo systemctl status punchd-vpn

# Start / Stop / Restart
sudo systemctl start punchd-vpn
sudo systemctl stop punchd-vpn
sudo systemctl restart punchd-vpn

# Enable/disable auto-start
sudo systemctl enable punchd-vpn
sudo systemctl disable punchd-vpn

# Live logs
journalctl -u punchd-vpn -f

# Recent logs
journalctl -u punchd-vpn --since "1 hour ago"

# Check TUN interface
ip addr show punchd-vpn0

# Check routes
ip route | grep 10.66

# Test connectivity
ping 10.66.0.1

# Uninstall
sudo ./pkg/install.sh --uninstall
# or: sudo dpkg -r punchd-vpn
```

---

## macOS

```bash
cargo build --release --bin punchd-vpn

# Install binary
sudo cp target/release/punchd-vpn /usr/local/bin/

# Create config
sudo mkdir -p /etc/punchd-vpn
sudo nano /etc/punchd-vpn/vpn-config.toml

# Install launchd service
sudo cp pkg/com.keylessh.punchd-vpn.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.keylessh.punchd-vpn.plist
```

**Service management:**
```bash
sudo launchctl list | grep punchd             # status
sudo launchctl stop com.keylessh.punchd-vpn   # stop
sudo launchctl start com.keylessh.punchd-vpn  # start
tail -f /var/log/punchd-vpn.log               # logs
```

**Uninstall:**
```bash
sudo launchctl unload /Library/LaunchDaemons/com.keylessh.punchd-vpn.plist
sudo rm /Library/LaunchDaemons/com.keylessh.punchd-vpn.plist
sudo rm /usr/local/bin/punchd-vpn
```

---

## Docker

For containerized environments:

```dockerfile
FROM debian:bookworm-slim
COPY punchd-vpn /usr/bin/punchd-vpn
COPY vpn-config.toml /etc/punchd-vpn/vpn-config.toml
RUN chmod 755 /usr/bin/punchd-vpn
# TUN device requires --cap-add NET_ADMIN --device /dev/net/tun
CMD ["punchd-vpn", "--standalone"]
```

```bash
docker run -d \
  --name punchd-vpn \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  --restart unless-stopped \
  -v /path/to/vpn-config.toml:/etc/punchd-vpn/vpn-config.toml:ro \
  punchd-vpn
```

**Docker Compose:**
```yaml
services:
  punchd-vpn:
    image: punchd-vpn
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun
    volumes:
      - ./vpn-config.toml:/etc/punchd-vpn/vpn-config.toml:ro
    restart: unless-stopped
```

---

## Architecture

```
User device                          Gateway LAN
┌──────────────┐                    ┌──────────────────┐
│  punchd-vpn  │◄──── WebRTC ─────►│  punchd-bridge   │
│  (TUN iface) │    DataChannel     │  (TUN + NAT)     │
│  10.66.0.x   │    0x04 prefix     │  10.66.0.1       │
└──────────────┘                    └──────┬───────────┘
                                           │
                                    ┌──────▼───────────┐
                                    │  LAN: 192.168.x  │
                                    │  RDP, SSH, HTTP   │
                                    └──────────────────┘
```

**How it works:**
1. Client authenticates via TideCloak OIDC (JWT with `vpn:<gatewayId>` role)
2. Connects to signal server via WebSocket for signaling
3. WebRTC peer connection established (with STUN/TURN for NAT traversal)
4. TUN interface created on both sides
5. IP packets prefixed with `0x04` and sent over the DataChannel
6. Gateway NATs packets to its LAN

**Features:**
- Auto-connect on boot, auto-reconnect on disconnect (exponential backoff: 2s → 4s → 8s → ... → 60s max)
- Role-based access control via TideCloak JWT
- Per-user software firewall with priority-ordered rules
- Split tunneling — gateway pushes LAN subnets to client
- Block notifications sent to client for denied packets
- Agent mode HTTP API on `localhost:19877` for browser UI control
- Runs as Windows Service / systemd daemon / launchd agent

---

## Firewall Rules

Firewall rules are encoded as TideCloak roles assigned to users. Format:

```
vpn:<gatewayId>:<allow|deny>:<network>/<prefix>:<ports>:<priority>
```

| Part | Description | Example |
|---|---|---|
| `gatewayId` | Target gateway | `SashaKC` |
| `allow/deny` | Action | `allow` or `deny` |
| `network/prefix` | CIDR subnet | `192.168.0.0/24` |
| `ports` | TCP/UDP ports | `*` (all), `80,443`, `3389` |
| `priority` | Higher = evaluated first | `0` to `100` |

### Behavior

- **No firewall rules** (just `vpn:SashaKC`): all traffic allowed
- **Rules exist**: evaluated highest priority first, first match wins, default deny if no match

### Examples

```
vpn:SashaKC                                         # full access, no restrictions

vpn:SashaKC:allow:192.168.0.0/24:*:10              # allow all to subnet (priority 10)

vpn:SashaKC:deny:0.0.0.0/0:*:0                     # deny everything (lowest priority base rule)
vpn:SashaKC:allow:192.168.0.0/24:80,443:10         # allow web to subnet
vpn:SashaKC:allow:192.168.0.5/32:3389:20           # allow RDP to specific host

vpn:SashaKC:allow:10.0.0.0/8:*:10                  # allow all to 10.x.x.x
vpn:SashaKC:deny:10.0.0.1/32:22:20                 # but deny SSH to gateway
```

### Common Patterns

**Web-only access:**
```
vpn:GW:deny:0.0.0.0/0:*:0
vpn:GW:allow:192.168.0.0/24:80,443:10
```

**Full subnet except one host:**
```
vpn:GW:allow:192.168.0.0/24:*:10
vpn:GW:deny:192.168.0.1/32:*:20
```

**RDP-only to specific machines:**
```
vpn:GW:deny:0.0.0.0/0:*:0
vpn:GW:allow:192.168.0.10/32:3389:10
vpn:GW:allow:192.168.0.11/32:3389:10
```

---

## Agent HTTP API

When running in agent mode (default, not `--standalone`), an HTTP API is available on `localhost:19877` for browser control:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/status` | Connection status |
| `POST` | `/connect` | Connect to a gateway |
| `POST` | `/disconnect` | Disconnect |

**Connect request body:**
```json
{
  "stunServer": "wss://punchd.example.com",
  "gatewayId": "SashaKC",
  "token": "eyJhbGci...",
  "iceServer": "stun:turn.example.com:3478",
  "turnServer": "turn:turn.example.com:3478",
  "turnSecret": "secret"
}
```

The KeyleSSH browser dashboard uses this API to provide a "Connect VPN" button.
