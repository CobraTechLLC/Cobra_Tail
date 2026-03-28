#!/bin/bash
# ─────────────────────────────────────────────────────────────
# SETUP SCRIPT — Run on BOTH the Pi 4 and Pi Zero 2 W
# Enables GPIO UART and installs dependencies
#
# Usage:
#   On Pi 4:     sudo ./setup.sh lighthouse
#   On Pi Zero:  sudo ./setup.sh vault
# ─────────────────────────────────────────────────────────────

set -e

ROLE="$1"

if [ -z "$ROLE" ] || { [ "$ROLE" != "lighthouse" ] && [ "$ROLE" != "vault" ]; }; then
    echo "Usage: sudo ./setup.sh [lighthouse|vault]"
    echo "  lighthouse = Pi 4 (coordination server)"
    echo "  vault      = Pi Zero 2 W (key manager)"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo"
    exit 1
fi

echo "============================================"
echo "Setting up: $ROLE"
echo "============================================"

# ─── Step 1: Enable GPIO UART ────────────────────────────────
echo "[1/5] Enabling GPIO UART..."

CONFIG="/boot/firmware/config.txt"
# Bookworm uses /boot/firmware/, older uses /boot/
if [ ! -f "$CONFIG" ]; then
    CONFIG="/boot/config.txt"
fi

# Enable UART
if ! grep -q "^enable_uart=1" "$CONFIG"; then
    echo "enable_uart=1" >> "$CONFIG"
    echo "  Added enable_uart=1 to $CONFIG"
else
    echo "  UART already enabled"
fi

# On Pi 4, the primary UART (ttyAMA0) is used by bluetooth by default.
# We need to either disable bluetooth or swap the UARTs.
# dtoverlay=disable-bt frees ttyAMA0 for our use (it's the better UART).
if [ "$ROLE" = "lighthouse" ]; then
    if ! grep -q "^dtoverlay=disable-bt" "$CONFIG"; then
        echo "dtoverlay=disable-bt" >> "$CONFIG"
        echo "  Added dtoverlay=disable-bt (frees ttyAMA0 for GPIO UART)"
    fi
fi

# On Pi Zero 2 W, the mini UART is the default GPIO UART.
# Swap it so we get the PL011 (ttyAMA0) which is more reliable.
if [ "$ROLE" = "vault" ]; then
    if ! grep -q "^dtoverlay=disable-bt" "$CONFIG"; then
        echo "dtoverlay=disable-bt" >> "$CONFIG"
        echo "  Added dtoverlay=disable-bt (gives GPIO the reliable PL011 UART)"
    fi
fi

# ─── Step 2: Disable serial console ─────────────────────────
# The serial console would fight with our data if left on
echo "[2/5] Disabling serial console on UART..."

# Remove console=serial0,115200 from cmdline.txt
CMDLINE="/boot/firmware/cmdline.txt"
if [ ! -f "$CMDLINE" ]; then
    CMDLINE="/boot/cmdline.txt"
fi

if grep -q "console=serial0" "$CMDLINE"; then
    sed -i 's/console=serial0,[0-9]* //g' "$CMDLINE"
    echo "  Removed serial console from cmdline.txt"
else
    echo "  Serial console already disabled"
fi

# Disable the serial-getty service
systemctl disable serial-getty@ttyAMA0.service 2>/dev/null || true
systemctl stop serial-getty@ttyAMA0.service 2>/dev/null || true
echo "  Disabled serial-getty service"

# ─── Step 3: Install system dependencies ────────────────────
echo "[3/5] Installing system packages..."

apt-get update -qq
apt-get install -y -qq python3-pip python3-venv wireguard-tools cmake build-essential

# ─── Step 4: Install Python dependencies ────────────────────
echo "[4/5] Installing Python packages..."

if [ "$ROLE" = "lighthouse" ]; then
    pip3 install --break-system-packages fastapi uvicorn pyserial pyyaml liboqs-python
fi

if [ "$ROLE" = "vault" ]; then
    pip3 install --break-system-packages pyserial liboqs-python cryptography
fi

# ─── Step 5: Create directories and service user ────────────
echo "[5/5] Creating directories..."

if [ "$ROLE" = "lighthouse" ]; then
    mkdir -p /etc/lighthouse/wg_keys
    mkdir -p /var/lib/lighthouse
    mkdir -p /var/log/lighthouse
    chmod 700 /etc/lighthouse/wg_keys
    echo "  Created /etc/lighthouse/ and /var/lib/lighthouse/"

    # Copy config if not present
    if [ ! -f /etc/lighthouse/config.yaml ]; then
        if [ -f "$(dirname "$0")/config.yaml" ]; then
            cp "$(dirname "$0")/config.yaml" /etc/lighthouse/config.yaml
            echo "  Copied default config.yaml to /etc/lighthouse/"
        fi
    fi
fi

if [ "$ROLE" = "vault" ]; then
    # Create vault user if it doesn't exist
    if ! id "vault" &>/dev/null; then
        useradd --system --no-create-home --shell /bin/false vault
        echo "  Created system user: vault"
    fi
    mkdir -p /home/vault/.crypt_vault
    chown vault:vault /home/vault/.crypt_vault
    chmod 700 /home/vault/.crypt_vault
    echo "  Created /home/vault/.crypt_vault/"

    # Add vault user to dialout group for serial access
    usermod -a -G dialout vault
    echo "  Added vault user to dialout group (serial access)"
fi

echo ""
echo "============================================"
echo "Setup complete!"
echo "============================================"
echo ""
echo "IMPORTANT: You must reboot for UART changes to take effect:"
echo "  sudo reboot"
echo ""

if [ "$ROLE" = "lighthouse" ]; then
    echo "After reboot:"
    echo "  1. Edit /etc/lighthouse/config.yaml"
    echo "     - Set server_url to your public IP or DDNS"
    echo "     - Forward ports 8443 (TCP) and 51820 (UDP) on your router"
    echo "  2. Start: python3 lighthouse.py serve --config /etc/lighthouse/config.yaml"
    echo ""
    echo "UART device will be: /dev/ttyAMA0"
    echo "Test with: stty -F /dev/ttyAMA0 115200 && echo 'PING' > /dev/ttyAMA0"
fi

if [ "$ROLE" = "vault" ]; then
    echo "After reboot:"
    echo "  1. Plug the ESP32 into the Pi Zero's USB port"
    echo "  2. Wire GPIO UART to the Pi 4:"
    echo "     Pi Zero pin 8  (TX)  →  Pi 4 pin 10 (RX)"
    echo "     Pi Zero pin 10 (RX)  →  Pi 4 pin 8  (TX)"
    echo "     Pi Zero pin 6  (GND) →  Pi 4 pin 6  (GND)"
    echo "  3. Start: sudo -u vault python3 cript_keeper.py serve"
    echo ""
    echo "ESP32 device will be: /dev/ttyACM0"
    echo "UART to Pi 4 will be: /dev/ttyAMA0"
fi