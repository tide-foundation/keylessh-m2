#!/bin/bash
set -e

# Punchd VPN installer for Linux
# Usage: sudo ./install.sh [path-to-vpn-config.toml]

BINARY_NAME="punchd-vpn"
INSTALL_DIR="/usr/bin"
CONFIG_DIR="/etc/punchd-vpn"
SERVICE_FILE="/etc/systemd/system/punchd-vpn.service"

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (sudo ./install.sh)"
    exit 1
fi

# Find the binary
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY=""
for candidate in \
    "$SCRIPT_DIR/$BINARY_NAME" \
    "$SCRIPT_DIR/../target/release/$BINARY_NAME" \
    "$SCRIPT_DIR/../target/x86_64-unknown-linux-gnu/release/$BINARY_NAME"; do
    if [ -f "$candidate" ]; then
        BINARY="$candidate"
        break
    fi
done

if [ -z "$BINARY" ]; then
    echo "Error: $BINARY_NAME binary not found"
    echo "Build it first: cargo build --release --bin punchd-vpn"
    exit 1
fi

echo "=== Punchd VPN Installer ==="
echo ""

# Stop existing service if running
if systemctl is-active --quiet punchd-vpn 2>/dev/null; then
    echo "Stopping existing service..."
    systemctl stop punchd-vpn
fi

# Install binary
echo "Installing binary to $INSTALL_DIR/$BINARY_NAME..."
cp "$BINARY" "$INSTALL_DIR/$BINARY_NAME"
chmod 755 "$INSTALL_DIR/$BINARY_NAME"

# Create config directory
mkdir -p "$CONFIG_DIR"

# Copy config if provided
CONFIG_SOURCE="${1:-}"
if [ -n "$CONFIG_SOURCE" ] && [ -f "$CONFIG_SOURCE" ]; then
    echo "Copying config from $CONFIG_SOURCE..."
    cp "$CONFIG_SOURCE" "$CONFIG_DIR/vpn-config.toml"
    chmod 600 "$CONFIG_DIR/vpn-config.toml"
elif [ ! -f "$CONFIG_DIR/vpn-config.toml" ]; then
    echo ""
    echo "No config file found. Create one at: $CONFIG_DIR/vpn-config.toml"
    echo ""
    echo "Example:"
    echo '  stun_server = "wss://stun.example.com"'
    echo '  gateway_id = "my-gateway"'
    echo '  tidecloak_config_b64 = "..."'
    echo '  ice_server = "stun:turn.example.com:3478"'
    echo '  turn_server = "turn:turn.example.com:3478"'
    echo '  turn_secret = "your-secret"'
    echo ""
fi

# Install systemd service
echo "Installing systemd service..."
cp "$SCRIPT_DIR/punchd-vpn.service" "$SERVICE_FILE"
systemctl daemon-reload

# Enable and start
systemctl enable punchd-vpn
if [ -f "$CONFIG_DIR/vpn-config.toml" ]; then
    echo "Starting service..."
    systemctl start punchd-vpn
    echo ""
    echo "Service started. Check status: systemctl status punchd-vpn"
else
    echo ""
    echo "Service installed but NOT started (no config file)."
    echo "Add config and start: systemctl start punchd-vpn"
fi

echo ""
echo "Commands:"
echo "  systemctl status punchd-vpn   — check status"
echo "  systemctl stop punchd-vpn     — stop"
echo "  systemctl restart punchd-vpn  — restart"
echo "  journalctl -u punchd-vpn -f   — view logs"
echo "  $0 --uninstall                — uninstall"
echo ""

# Handle uninstall flag
if [ "${1:-}" = "--uninstall" ]; then
    echo "Uninstalling Punchd VPN..."
    systemctl stop punchd-vpn 2>/dev/null || true
    systemctl disable punchd-vpn 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -f "$INSTALL_DIR/$BINARY_NAME"
    systemctl daemon-reload
    echo "Uninstalled. Config preserved at $CONFIG_DIR/"
    echo "To remove config: rm -rf $CONFIG_DIR"
fi
