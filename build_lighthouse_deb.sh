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
#
# Install with:
#   sudo apt install ./cobra-lighthouse_<version>_<arch>.deb
# ─────────────────────────────────────────────────────────────

set -e

VERSION=$(cat version.txt)
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
    "cobra_sentinel.py"
    "config.yaml"
)

for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "${SCRIPT_DIR}/${f}" ]; then
        echo "ERROR: Missing required file: ${f}"
        echo "Run this script from the repo root directory."
        exit 1
    fi
done

# Check for optional sentinel model file
GGUF_FILE=""
for f in "${SCRIPT_DIR}"/*.gguf; do
    if [ -f "$f" ]; then
        GGUF_FILE="$f"
        GGUF_NAME=$(basename "$f")
        echo "  Found LLM model: ${GGUF_NAME}"
        break
    fi
done

# ── Clean previous build ─────────────────────────────────────

rm -rf "${SCRIPT_DIR}/${PKG_DIR}"

# ── Create directory structure ────────────────────────────────

echo "[1/5] Creating package structure..."

mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/opt/lighthouse"
mkdir -p "${PKG_DIR}/opt/lighthouse/models"
mkdir -p "${PKG_DIR}/etc/lighthouse"
mkdir -p "${PKG_DIR}/etc/systemd/system"
mkdir -p "${PKG_DIR}/usr/local/bin"

# ── Copy application files ────────────────────────────────────

echo "[2/5] Copying application files..."

cp "${SCRIPT_DIR}/lighthouse.py"          "${PKG_DIR}/opt/lighthouse/"
cp "${SCRIPT_DIR}/lighthouse_launcher.py" "${PKG_DIR}/opt/lighthouse/"
cp "${SCRIPT_DIR}/cobra_sentinel.py"      "${PKG_DIR}/opt/lighthouse/"
cp "${SCRIPT_DIR}/config.yaml"            "${PKG_DIR}/opt/lighthouse/config.yaml.template"

# Write version file
echo "${VERSION}" > "${PKG_DIR}/opt/lighthouse/version.txt"

# Set permissions on application files
chmod 755 "${PKG_DIR}/opt/lighthouse/lighthouse.py"
chmod 755 "${PKG_DIR}/opt/lighthouse/lighthouse_launcher.py"
chmod 755 "${PKG_DIR}/opt/lighthouse/cobra_sentinel.py"
chmod 644 "${PKG_DIR}/opt/lighthouse/config.yaml.template"
chmod 644 "${PKG_DIR}/opt/lighthouse/version.txt"

# Copy LLM model if found (for Sentinel AI diagnostics)
if [ -n "$GGUF_FILE" ]; then
    echo "  Copying LLM model: ${GGUF_NAME} (this may take a moment)..."
    cp "${GGUF_FILE}" "${PKG_DIR}/opt/lighthouse/models/"
    chmod 644 "${PKG_DIR}/opt/lighthouse/models/${GGUF_NAME}"

    # Ship the Apache 2.0 license alongside the model (required for redistribution)
    if [ -f "${SCRIPT_DIR}/APACHE-2.0.txt" ]; then
        cp "${SCRIPT_DIR}/APACHE-2.0.txt" "${PKG_DIR}/opt/lighthouse/models/LICENSE"
        chmod 644 "${PKG_DIR}/opt/lighthouse/models/LICENSE"
    else
        echo "  WARNING: APACHE-2.0.txt not found — model license will not be bundled"
    fi
fi

# Ship default troubleshooting reference
if [ -f "${SCRIPT_DIR}/troubleshooting.md" ]; then
    cp "${SCRIPT_DIR}/troubleshooting.md" "${PKG_DIR}/etc/lighthouse/"
    chmod 644 "${PKG_DIR}/etc/lighthouse/troubleshooting.md"
fi

# ── Generate systemd service ─────────────────────────────────

if [ -f "${SCRIPT_DIR}/systemd_setup/lighthouse.service" ]; then
    echo "  Found lighthouse.service in systemd_setup/ (using standard paths)"
elif [ -f "${SCRIPT_DIR}/lighthouse.service" ]; then
    echo "  Found lighthouse.service in repo root (using standard paths)"
else
    echo "  Generating lighthouse.service with standard paths"
fi

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

# Sentinel service — AI diagnostic agent

cat > "${PKG_DIR}/etc/systemd/system/cobra-sentinel.service" << 'EOF'
[Unit]
Description=Cobra Sentinel — AI Network Diagnostic Agent
Documentation=https://github.com/CobraTechLLC/Cobra_Tail
After=network-online.target lighthouse.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/lighthouse/cobra_sentinel.py --config /etc/lighthouse/sentinel_config.json
WorkingDirectory=/opt/lighthouse
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cobra-sentinel
MemoryMax=2G
CPUQuota=80%

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${PKG_DIR}/etc/systemd/system/cobra-sentinel.service"

# ── Create command wrapper ────────────────────────────────────

cat > "${PKG_DIR}/usr/local/bin/lighthouse" << 'EOF'
#!/bin/bash
# Cobra Lighthouse — Management Console
# Installed by cobra-lighthouse package
exec /usr/bin/python3 /opt/lighthouse/lighthouse_launcher.py "$@"
EOF

chmod 755 "${PKG_DIR}/usr/local/bin/lighthouse"

# Sentinel command wrapper
cat > "${PKG_DIR}/usr/local/bin/cobra-sentinel" << 'EOF'
#!/bin/bash
# Cobra Sentinel — AI Network Diagnostic Agent
# Installed by cobra-lighthouse package
exec /usr/bin/python3 /opt/lighthouse/cobra_sentinel.py "$@"
EOF

chmod 755 "${PKG_DIR}/usr/local/bin/cobra-sentinel"

# ── Create DEBIAN control files ───────────────────────────────

echo "[3/5] Writing package metadata..."

cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.9), python3-pip, wireguard-tools, iptables, cmake, ninja-build, build-essential, git, libssl-dev
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
 Install with: sudo apt install ./cobra-lighthouse_${VERSION}_${ARCH}.deb
 Then run: sudo lighthouse
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

echo "[1/5] Creating directories..."

mkdir -p /etc/lighthouse/wg_keys
mkdir -p /var/lib/lighthouse
chmod 700 /etc/lighthouse/wg_keys
chmod 755 /etc/lighthouse

echo "  Created /etc/lighthouse/"
echo "  Created /etc/lighthouse/wg_keys/"
echo "  Created /var/lib/lighthouse/"

# ── Enable GPIO UART (Pi 4 specific) ────────────────────────

echo "[2/5] Checking for Raspberry Pi UART setup..."

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
        if ! grep -q "^enable_uart=1" "$CONFIG"; then
            echo "enable_uart=1" >> "$CONFIG"
            echo "  Enabled UART in $CONFIG"
            UART_CHANGED=true
        else
            echo "  UART already enabled"
        fi

        if ! grep -q "^dtoverlay=disable-bt" "$CONFIG"; then
            echo "dtoverlay=disable-bt" >> "$CONFIG"
            echo "  Disabled Bluetooth (frees ttyAMA0 for Vault UART)"
            UART_CHANGED=true
        else
            echo "  Bluetooth already disabled"
        fi
    fi

    CMDLINE="/boot/firmware/cmdline.txt"
    if [ ! -f "$CMDLINE" ]; then
        CMDLINE="/boot/cmdline.txt"
    fi

    if [ -f "$CMDLINE" ] && grep -q "console=serial0" "$CMDLINE"; then
        sed -i 's/console=serial0,[0-9]* //g' "$CMDLINE"
        echo "  Removed serial console from cmdline.txt"
        UART_CHANGED=true
    fi

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

# ── Build and install liboqs C library ───────────────────────

echo "[3/5] Checking liboqs shared library..."

LIBOQS_FOUND=false
for lib_path in /usr/local/lib/liboqs.so /usr/lib/liboqs.so /usr/local/lib64/liboqs.so; do
    if [ -f "$lib_path" ]; then
        echo "  Found: $lib_path"
        LIBOQS_FOUND=true
        break
    fi
done

if [ "$LIBOQS_FOUND" = false ]; then
    echo "  liboqs not found — building from source..."
    echo "  (This takes a few minutes on first install)"
    echo ""

    BUILD_DIR=$(mktemp -d)

    cd "$BUILD_DIR"
    echo "  Cloning liboqs..."
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git 2>&1 | tail -1
    cd liboqs
    mkdir build && cd build

    echo "  Running cmake..."
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. -Wno-dev > /dev/null 2>&1

    echo "  Compiling (this is the slow part)..."
    ninja > /dev/null 2>&1

    echo "  Installing library..."
    ninja install > /dev/null 2>&1

    # Update library cache so Python can find liboqs.so
    ldconfig

    cd /
    rm -rf "$BUILD_DIR"

    if [ -f /usr/local/lib/liboqs.so ]; then
        echo "  liboqs built and installed successfully"
    else
        echo ""
        echo "  WARNING: liboqs build may have failed"
        echo "  Post-quantum crypto will be unavailable until liboqs is installed"
        echo "  To retry manually:"
        echo "    cd /tmp && git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git"
        echo "    cd liboqs && mkdir build && cd build"
        echo "    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. -Wno-dev"
        echo "    ninja && sudo ninja install && sudo ldconfig"
        echo ""
    fi
else
    echo "  liboqs already installed"
fi

# ── Install Python dependencies ──────────────────────────────

echo "[4/5] Installing Python dependencies..."

# Install core pip packages
pip3 install --break-system-packages \
    fastapi uvicorn pyserial pyyaml cryptography psutil 2>/dev/null || \
pip3 install \
    fastapi uvicorn pyserial pyyaml cryptography psutil 2>/dev/null || \
echo "  WARNING: pip install failed for core packages"

# Install liboqs-python separately (depends on liboqs.so being present)
pip3 install --break-system-packages liboqs-python 2>/dev/null || \
pip3 install liboqs-python 2>/dev/null || \
echo "  WARNING: liboqs-python install failed — post-quantum crypto unavailable"

echo "  Python dependencies installed"

# ── Reload systemd ───────────────────────────────────────────

echo "[5/5] Configuring systemd..."

systemctl daemon-reload
echo "  systemd reloaded"

# ── Sentinel auto-detection ──────────────────────────────────

echo ""
echo "  Detecting hardware for Cobra Sentinel..."
python3 /opt/lighthouse/cobra_sentinel.py --detect 2>/dev/null || \
echo "  Sentinel detection skipped (non-fatal)"

# Move generated config to /etc/lighthouse if it landed in the wrong place
if [ -f /opt/lighthouse/config/sentinel_config.json ] && [ ! -f /etc/lighthouse/sentinel_config.json ]; then
    mv /opt/lighthouse/config/sentinel_config.json /etc/lighthouse/sentinel_config.json 2>/dev/null || true
fi

# Auto-configure model path if a .gguf model was shipped
GGUF_MODEL=$(find /opt/lighthouse/models/ -name "*.gguf" -type f 2>/dev/null | head -1)
SENTINEL_CFG="/etc/lighthouse/sentinel_config.json"
if [ -n "$GGUF_MODEL" ] && [ -f "$SENTINEL_CFG" ]; then
    python3 -c "
import json
with open('$SENTINEL_CFG') as f:
    cfg = json.load(f)
cfg['llm_model_path'] = '$GGUF_MODEL'
cfg['troubleshooting_file'] = '/etc/lighthouse/troubleshooting.md'
cfg['log_file'] = '/var/lib/lighthouse/lighthouse.log'
with open('$SENTINEL_CFG', 'w') as f:
    json.dump(cfg, f, indent=2)
print('  LLM model path set: $GGUF_MODEL')
" 2>/dev/null || true
fi

# Generate default troubleshooting.md if not present
if [ ! -f /etc/lighthouse/troubleshooting.md ]; then
    python3 -c "
import sys, textwrap
sys.path.insert(0, '/opt/lighthouse')
from cobra_sentinel import _generate_default_troubleshooting
from pathlib import Path
Path('/etc/lighthouse/troubleshooting.md').write_text(_generate_default_troubleshooting())
print('  Generated default troubleshooting.md')
" 2>/dev/null || echo "  Troubleshooting file will be generated on first run"
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Installation complete!"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Run 'sudo lighthouse' to start the setup wizard."
echo ""
echo "  Files installed:"
echo "    /opt/lighthouse/          — application code"
echo "    /etc/lighthouse/          — configuration (created by wizard)"
echo "    /var/lib/lighthouse/      — database"
echo "    /usr/local/bin/lighthouse — management command"
echo "    /usr/local/bin/cobra-sentinel — AI diagnostic agent"
if [ -n "$GGUF_MODEL" ]; then
echo "    /opt/lighthouse/models/   — LLM model ($(basename $GGUF_MODEL))"
fi
echo ""

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

if systemctl is-active --quiet lighthouse 2>/dev/null; then
    systemctl stop lighthouse
    echo "  Lighthouse service stopped"
fi

if systemctl is-enabled --quiet lighthouse 2>/dev/null; then
    systemctl disable lighthouse
    echo "  Lighthouse service disabled"
fi

# Stop sentinel service
if systemctl is-active --quiet cobra-sentinel 2>/dev/null; then
    systemctl stop cobra-sentinel 2>/dev/null || true
    echo "  Sentinel service stopped"
fi

if systemctl is-enabled --quiet cobra-sentinel 2>/dev/null; then
    systemctl disable cobra-sentinel 2>/dev/null || true
fi

PRERM

chmod 755 "${PKG_DIR}/DEBIAN/prerm"

# ── postrm — runs after package is removed ────────────────────

cat > "${PKG_DIR}/DEBIAN/postrm" << 'POSTRM'
#!/bin/bash
set -e

systemctl daemon-reload 2>/dev/null || true

if [ "$1" = "purge" ]; then
    echo "Purging Lighthouse data..."
    rm -rf /var/lib/lighthouse
    echo "  Removed /var/lib/lighthouse/"
    rm -rf /etc/lighthouse
    echo "  Removed /etc/lighthouse/"
    rm -f /etc/systemd/system/cobra-sentinel.service
    rm -f /tmp/cobra-sentinel.sock
    systemctl daemon-reload 2>/dev/null || true
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

# ── Build the .deb ────────────────────────────────────────────

echo "[4/5] Building .deb package..."

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
    echo "    sudo apt install ./${DEB_FILE}"
    echo ""
    echo "  Then run:"
    echo "    sudo lighthouse"
    echo ""
else
    echo "ERROR: .deb file was not created"
    exit 1
fi

# ── Cleanup build directory ───────────────────────────────────

rm -rf "${PKG_DIR}"
echo "  Build directory cleaned up"
echo ""