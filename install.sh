#!/bin/bash
# Install script for githttps-proxy on Ubuntu/Debian
set -e

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo $0"
    exit 1
fi

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/githttps-proxy"
DATA_DIR="/var/lib/githttps-proxy"
SERVICE_USER="githttps-proxy"

echo "Installing githttps-proxy..."

# Create system user
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "Created user: $SERVICE_USER"
fi

# Create directories
mkdir -p "$CONFIG_DIR" "$DATA_DIR/certs"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 700 "$DATA_DIR" "$CONFIG_DIR"

# Install binary
if [ -f "./githttps-proxy" ]; then
    cp ./githttps-proxy "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/githttps-proxy"
    echo "Installed binary to $INSTALL_DIR/githttps-proxy"
else
    echo "Binary not found. Build first: go build -o githttps-proxy ."
    exit 1
fi

# Install example config if no config exists
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    if [ -f "./config.example.yaml" ]; then
        cp ./config.example.yaml "$CONFIG_DIR/config.yaml"
        chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/config.yaml"
        chmod 600 "$CONFIG_DIR/config.yaml"
        echo "Installed example config to $CONFIG_DIR/config.yaml"
        echo "  -> Edit this file to add your users and SSH keys!"
    fi
fi

# Install systemd service
cp ./githttps-proxy.service /etc/systemd/system/
systemctl daemon-reload
echo "Installed systemd service"

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit config:    sudo nano $CONFIG_DIR/config.yaml"
echo "  2. Enable service: sudo systemctl enable githttps-proxy"
echo "  3. Start service:  sudo systemctl start githttps-proxy"
echo "  4. Check logs:     sudo journalctl -u githttps-proxy -f"
