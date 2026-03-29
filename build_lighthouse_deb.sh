#!/bin/bash
# ─────────────────────────────────────────────────────────────
# BUILD SCRIPT — Builds the cobra-lighthouse .deb package
# ─────────────────────────────────────────────────────────────
# Usage:
#   ./build_lighthouse_deb.sh 1.0.0
#   ./build_lighthouse_deb.sh 1.0.0 arm64
#   ./build_lighthouse_deb.sh 1.0.0 amd64
#
# Run this from the repo root (where lighthouse.py lives).
# Outputs: cobra-lighthouse_<version>_<arch>.deb
# ─────────────────────────────────────────────────────────────

set -e

VERSION="${1:-1.0.0}"
ARCH="${2:-$(dpkg --print-architecture 2>/dev/null || echo arm64)}"
PKG_NAME="cobra-lighthouse"
PKG_DIR="${PKG_NAME}_${VERSION}_${ARCH}"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Building ${PKG_NAME} v${VERSION} (${ARCH})"
echo "═══════════════════════════════════════════════════"
echo ""

# ── Verify source files exist ────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

REQUIRED_FILES=(
    "lighthouse.py"
    "lighthouse_launcher.py"
    "config.yaml"
    "lighthouse.service"
)

for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "${SCRIPT_DIR}/${f}" ]; then
        echo "ERROR: Missing required file: ${f}"
        echo "Run this script from the repo root directory."
        exit 1
    fi
done

# ── Clean previous build ─────────────────────────────────────

rm -rf "${SCRIPT_DIR}/${PKG_DIR}"

# ── Create directory structure ────────────────────────────────

echo "[1/5] Creating package structure..."

mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/opt/lighthouse"
mkdir -p "${PKG_DIR}/etc/lighthouse"
mkdir -p "${PKG_DIR}/etc/systemd/system"
mkdir -p "${PKG_DIR}/usr/local/bin"

# ── Copy application files ────────────────────────────────────

echo "[2/5] Copying application files..."

cp "${SCRIPT_DIR}/lighthouse.py"          "${PKG_DIR}/opt/lighthouse/"
cp "${SCRIPT_DIR}/lighthouse_launcher.py" "${PKG_DIR}/opt/lighthouse/"
cp "${SCRIPT_DIR}/config.yaml"            "${PKG_DIR}/opt/lighthouse/config.yaml.template"

# Write version file
echo "${VERSION}" > "${PKG_DIR}/opt/lighthouse/version.txt"

# Set permissions on application files
chmod 755 "${PKG_DIR}/opt/lighthouse/lighthouse.py"
chmod 755 "${PKG_DIR}/opt/lighthouse/lighthouse_launcher.py"
chmod 644 "${PKG_DIR}/opt/lighthouse/config.yaml.template"
chmod 644 "${PKG_DIR}/opt/lighthouse/version.txt"

# ── Copy systemd service ─────────────────────────────────────

# We generate the service file with correct paths rather than
# copying the user's existing one (which has /home/user paths)
cat > "${PKG_DIR}/etc/systemd/system/lighthouse.service" << 'EOF'
[Unit]
Description=The Lighthouse — Post-Quantum VPN Coordination Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/lighthouse/lighthouse.py serve --config /etc/lighthouse/config.yaml
WorkingDirectory=/opt/lighthouse
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${PKG_DIR}/etc/systemd/system/lighthouse.service"

# ── Create command wrapper ────────────────────────────────────

cat > "${PKG_DIR}/usr/local/bin/lighthouse" << 'EOF'
#!/bin/bash
# Cobra Lighthouse — Management Console
# Installed by cobra-lighthouse package
exec /usr/bin/python3 /opt/lighthouse/lighthouse_launcher.py "$@"
EOF

chmod 755 "${PKG_DIR}/usr/local/bin/lighthouse"

# ── Create DEBIAN control files ───────────────────────────────

echo "[3/5] Writing package metadata..."

cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.9), python3-pip, wireguard-tools
Recommends: python3-yaml, python3-serial
Maintainer: CobraTechLLC <admin@cobratechllc.com>
Homepage: https://github.com/CobraTechLLC/Cobra_Tail
Description: The Lighthouse — Post-Quantum VPN Coordination Server
 A self-hosted post-quantum VPN coordination server built on custom
 hardware. Features ML-KEM-1024 key exchange, WireGuard tunnel
 management, automatic mesh networking, NAT traversal, and
 deterministic IPv6 identity.
 .
 Part of the Cobra Tail (PQC-Mesh) project.
 .
 Run 'lighthouse' after installation to start the setup wizard.
EOF

# ── postinst — runs after package is installed ────────────────

cat > "${PKG_DIR}/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Cobra Lighthouse — Post-Install Setup"
echo "═══════════════════════════════════════════════════"
echo ""

# ── Create directories with correct permissions ──────────────

echo "[1/4] Creating directories..."

mkdir -p /etc/lighthouse/wg_keys
mkdir -p /var/lib/lighthouse
chmod 700 /etc/lighthouse/wg_keys
chmod 755 /etc/lighthouse

echo "  Created /etc/lighthouse/"
echo "  Created /etc/lighthouse/wg_keys/"
echo "  Created /var/lib/lighthouse/"

# ── Enable GPIO UART (Pi 4 specific) ────────────────────────
# Only runs if we detect a Raspberry Pi

echo "[2/4] Checking for Raspberry Pi UART setup..."

IS_PI=false
if [ -f /proc/cpuinfo ] && grep -qi "raspberry\|BCM" /proc/cpuinfo 2>/dev/null; then
    IS_PI=true
fi

if [ "$IS_PI" = true ]; then
    CONFIG="/boot/firmware/config.txt"
    if [ ! -f "$CONFIG" ]; then
        CONFIG="/boot/config.txt"
    fi

    UART_CHANGED=false

    if [ -f "$CONFIG" ]; then
        # Enable UART
        if ! grep -q "^enable_uart=1" "$CONFIG"; then
            echo "enable_uart=1" >> "$CONFIG"
            echo "  Enabled UART in $CONFIG"
            UART_CHANGED=true
        else
            echo "  UART already enabled"
        fi

        # Disable Bluetooth to free ttyAMA0 for Vault UART link
        if ! grep -q "^dtoverlay=disable-bt" "$CONFIG"; then
            echo "dtoverlay=disable-bt" >> "$CONFIG"
            echo "  Disabled Bluetooth (frees ttyAMA0 for Vault UART)"
            UART_CHANGED=true
        else
            echo "  Bluetooth already disabled"
        fi
    fi

    # Disable serial console so it doesn't interfere with UART data
    CMDLINE="/boot/firmware/cmdline.txt"
    if [ ! -f "$CMDLINE" ]; then
        CMDLINE="/boot/cmdline.txt"
    fi

    if [ -f "$CMDLINE" ] && grep -q "console=serial0" "$CMDLINE"; then
        sed -i 's/console=serial0,[0-9]* //g' "$CMDLINE"
        echo "  Removed serial console from cmdline.txt"
        UART_CHANGED=true
    fi

    # Disable serial-getty service
    systemctl disable serial-getty@ttyAMA0.service 2>/dev/null || true
    systemctl stop serial-getty@ttyAMA0.service 2>/dev/null || true

    if [ "$UART_CHANGED" = true ]; then
        echo ""
        echo "  *** UART configuration changed — REBOOT REQUIRED ***"
        echo ""
    fi
else
    echo "  Not a Raspberry Pi — skipping UART setup"
fi

# ── Install Python dependencies ──────────────────────────────

echo "[3/4] Installing Python dependencies..."

# Try --break-system-packages first (required on Bookworm+), fall back to regular
pip3 install --break-system-packages \
    fastapi uvicorn pyserial pyyaml liboqs-python cryptography 2>/dev/null || \
pip3 install \
    fastapi uvicorn pyserial pyyaml liboqs-python cryptography 2>/dev/null || \
echo "  WARNING: pip install failed — install dependencies manually"

echo "  Python dependencies installed"

# ── Reload systemd ───────────────────────────────────────────

echo "[4/4] Configuring systemd..."

systemctl daemon-reload
echo "  systemd reloaded"

# Don't enable or start the service — the launcher wizard handles that
# The user needs to run 'lighthouse' first to set up config.yaml

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Installation complete!"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Run 'lighthouse' to start the setup wizard."
echo ""
echo "  Files installed:"
echo "    /opt/lighthouse/          — application code"
echo "    /etc/lighthouse/          — configuration (created by wizard)"
echo "    /var/lib/lighthouse/      — database"
echo "    /usr/local/bin/lighthouse — management command"
echo ""

# Remind about reboot if UART was changed
if [ "$IS_PI" = true ] && [ "${UART_CHANGED:-false}" = true ]; then
    echo "  *** IMPORTANT: Reboot required for UART changes ***"
    echo "  Run: sudo reboot"
    echo ""
fi

POSTINST

chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# ── prerm — runs before package is removed ────────────────────

cat > "${PKG_DIR}/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
set -e

echo "Stopping Lighthouse service..."

# Stop the service if running
if systemctl is-active --quiet lighthouse 2>/dev/null; then
    systemctl stop lighthouse
    echo "  Lighthouse service stopped"
fi

# Disable the service
if systemctl is-enabled --quiet lighthouse 2>/dev/null; then
    systemctl disable lighthouse
    echo "  Lighthouse service disabled"
fi

PRERM

chmod 755 "${PKG_DIR}/DEBIAN/prerm"

# ── postrm — runs after package is removed ────────────────────

cat > "${PKG_DIR}/DEBIAN/postrm" << 'POSTRM'
#!/bin/bash
set -e

# Reload systemd to forget the service
systemctl daemon-reload 2>/dev/null || true

# Only clean up data on purge, not on regular remove
# This preserves config.yaml, database, and keys on dpkg -r
# They're only deleted on dpkg -P (purge)
if [ "$1" = "purge" ]; then
    echo "Purging Lighthouse data..."

    # Remove data directory (database)
    rm -rf /var/lib/lighthouse
    echo "  Removed /var/lib/lighthouse/"

    # Remove config directory (config, certs, keys)
    rm -rf /etc/lighthouse
    echo "  Removed /etc/lighthouse/"

    echo "  Lighthouse fully purged"
else
    echo ""
    echo "  Config and data preserved at:"
    echo "    /etc/lighthouse/config.yaml"
    echo "    /etc/lighthouse/server.crt"
    echo "    /var/lib/lighthouse/lighthouse.db"
    echo ""
    echo "  To remove everything: sudo dpkg -P cobra-lighthouse"
    echo ""
fi

POSTRM

chmod 755 "${PKG_DIR}/DEBIAN/postrm"

# ── conffiles — mark config.yaml as a conffile ────────────────
# This tells dpkg to preserve the user's config on upgrade
# (only relevant if they manually created it before the wizard)

cat > "${PKG_DIR}/DEBIAN/conffiles" << 'EOF'
/etc/lighthouse/config.yaml
EOF

# ── Build the .deb ────────────────────────────────────────────

echo "[4/5] Building .deb package..."

# Ensure correct ownership (everything owned by root)
# This avoids dpkg warnings about non-root ownership
if [ "$EUID" -eq 0 ]; then
    chown -R root:root "${PKG_DIR}"
else
    echo "  Note: Run as root for correct file ownership in .deb"
    echo "  Or use: fakeroot dpkg-deb --build ..."
fi

dpkg-deb --build "${PKG_DIR}" 2>/dev/null || \
fakeroot dpkg-deb --build "${PKG_DIR}" 2>/dev/null

DEB_FILE="${PKG_DIR}.deb"

echo "[5/5] Verifying package..."

if [ -f "${DEB_FILE}" ]; then
    SIZE=$(du -h "${DEB_FILE}" | cut -f1)
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  Package built successfully!"
    echo "═══════════════════════════════════════════════════"
    echo ""
    echo "  File: ${DEB_FILE}"
    echo "  Size: ${SIZE}"
    echo ""
    echo "  Install with:"
    echo "    sudo dpkg -i ${DEB_FILE}"
    echo ""
    echo "  Then run:"
    echo "    lighthouse"
    echo ""

    # Show package info
    echo "  Package contents:"
    dpkg-deb -c "${DEB_FILE}" 2>/dev/null | grep -E "^[^.]" | head -20
    echo ""
else
    echo "ERROR: .deb file was not created"
    exit 1
fi

# ── Cleanup build directory ───────────────────────────────────

rm -rf "${PKG_DIR}"
echo "  Build directory cleaned up"
echo ""