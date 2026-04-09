#!/bin/bash
# ─────────────────────────────────────────────────────────────
# BUILD SCRIPT — Builds the cobra-client .deb package
# ─────────────────────────────────────────────────────────────
# Usage:
#   ./build_client_deb.sh 1.0.0
#   ./build_client_deb.sh 1.0.0 arm64
#   ./build_client_deb.sh 1.0.0 amd64
#
# Run this from the repo root (where client.py lives).
# Outputs: cobra-client_<version>_<arch>.deb
#
# Install with:
#   sudo apt install ./cobra-client_<version>_<arch>.deb
# ─────────────────────────────────────────────────────────────

set -e

VERSION="${1:-1.0.0}"
ARCH="${2:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"
PKG_NAME="cobra-client"
PKG_DIR="${PKG_NAME}_${VERSION}_${ARCH}"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Building ${PKG_NAME} v${VERSION} (${ARCH})"
echo "═══════════════════════════════════════════════════"
echo ""

# ── Verify source files exist ────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

REQUIRED_FILES=(
    "client.py"
    "cobra_launcher.py"
    "identity_manager.py"
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
mkdir -p "${PKG_DIR}/opt/cobratail/bin"
mkdir -p "${PKG_DIR}/opt/cobratail/config"
mkdir -p "${PKG_DIR}/opt/cobratail/data"
mkdir -p "${PKG_DIR}/opt/cobratail/logs"
mkdir -p "${PKG_DIR}/etc/systemd/system"
mkdir -p "${PKG_DIR}/usr/local/bin"

# ── Copy application files ────────────────────────────────────

echo "[2/5] Copying application files..."

cp "${SCRIPT_DIR}/client.py"           "${PKG_DIR}/opt/cobratail/bin/"
cp "${SCRIPT_DIR}/cobra_launcher.py"   "${PKG_DIR}/opt/cobratail/bin/"
cp "${SCRIPT_DIR}/identity_manager.py" "${PKG_DIR}/opt/cobratail/bin/"

# Write version file
echo "${VERSION}" > "${PKG_DIR}/opt/cobratail/version.txt"

# Marker file — signals managed install to _detect_cobratail_dir()
touch "${PKG_DIR}/opt/cobratail/.cobratail"

# Set permissions on application files
chmod 755 "${PKG_DIR}/opt/cobratail/bin/client.py"
chmod 755 "${PKG_DIR}/opt/cobratail/bin/cobra_launcher.py"
chmod 755 "${PKG_DIR}/opt/cobratail/bin/identity_manager.py"
chmod 644 "${PKG_DIR}/opt/cobratail/version.txt"
chmod 644 "${PKG_DIR}/opt/cobratail/.cobratail"

# ── Generate systemd service ─────────────────────────────────
# Template — the launcher's _install_systemd_service() overwrites
# ExecStart with the real enrollment URLs when the user enables startup.

echo "  Generating cobratail.service (template — configured via 'cobra')"

cat > "${PKG_DIR}/etc/systemd/system/cobratail.service" << 'EOF'
[Unit]
Description=CobraTail VPN Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Placeholder — 'cobra' rewrites this with enrollment URLs on first enable
ExecStart=/usr/bin/python3 /opt/cobratail/bin/client.py service
Restart=on-failure
RestartSec=10
WorkingDirectory=/opt/cobratail/bin
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${PKG_DIR}/etc/systemd/system/cobratail.service"

# Identity service — runs --apply before the client starts

cat > "${PKG_DIR}/etc/systemd/system/cobra-identity.service" << 'EOF'
[Unit]
Description=CobraTail Identity Manager
Before=cobratail.service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/cobratail/bin/identity_manager.py --apply
RemainAfterExit=yes
WorkingDirectory=/opt/cobratail/bin

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${PKG_DIR}/etc/systemd/system/cobra-identity.service"

# ── Create command wrapper ────────────────────────────────────

cat > "${PKG_DIR}/usr/local/bin/cobra" << 'EOF'
#!/bin/bash
# CobraTail VPN Client — Management Console
# Installed by cobra-client package
exec /usr/bin/python3 /opt/cobratail/bin/cobra_launcher.py "$@"
EOF

chmod 755 "${PKG_DIR}/usr/local/bin/cobra"

# ── Create DEBIAN control files ───────────────────────────────

echo "[3/5] Writing package metadata..."

cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.9), python3-pip, wireguard-tools, openresolv, python3-cryptography, cmake, ninja-build, build-essential, git, libssl-dev
Recommends: wireguard
Maintainer: CobraTechLLC <admin@cobratechllc.com>
Homepage: https://github.com/CobraTechLLC/Cobra_Tail
Description: CobraTail VPN Client — Quantum-Resistant Mesh Network
 A self-hosted post-quantum VPN client with automatic mesh networking,
 NAT traversal, direct peer-to-peer connectivity, and deterministic
 IPv6 identity. Connects to a CobraTail Lighthouse server and
 establishes quantum-resistant WireGuard tunnels secured by
 ML-KEM-1024.
 .
 Part of the Cobra Tail (PQC-Mesh) project.
 .
 Install with: sudo apt install ./cobra-client_${VERSION}_${ARCH}.deb
 Then run: cobra
EOF

# ── postinst — runs after package is installed ────────────────

cat > "${PKG_DIR}/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e

echo ""
echo "═══════════════════════════════════════════════════"
echo "  CobraTail Client — Post-Install Setup"
echo "═══════════════════════════════════════════════════"
echo ""

# ── Create directories with correct permissions ──────────────

echo "[1/4] Creating directories..."

mkdir -p /opt/cobratail/config
mkdir -p /opt/cobratail/data
mkdir -p /opt/cobratail/logs

# Ensure marker exists
touch /opt/cobratail/.cobratail

echo "  Created /opt/cobratail/{config,data,logs}/"

# ── Build and install liboqs C library ───────────────────────

echo "[2/4] Checking liboqs shared library..."

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

echo "[3/4] Installing Python dependencies..."

# Install core pip packages
pip3 install --break-system-packages \
    requests 2>/dev/null || \
pip3 install \
    requests 2>/dev/null || \
echo "  WARNING: pip install failed for core packages"

# Install liboqs-python separately (depends on liboqs.so being present)
pip3 install --break-system-packages liboqs-python 2>/dev/null || \
pip3 install liboqs-python 2>/dev/null || \
echo "  WARNING: liboqs-python install failed — post-quantum crypto unavailable"

echo "  Python dependencies installed"

# Verify ML-KEM-1024
echo "  Verifying ML-KEM-1024 support..."

python3 -c "
import oqs
kem = oqs.KeyEncapsulation('ML-KEM-1024')
pub = kem.generate_keypair()
ct, ss = kem.encap_secret(pub)
print('  ML-KEM-1024 self-test: PASSED')
" 2>/dev/null || {
    echo "  WARNING: ML-KEM-1024 self-test failed"
    echo "  The client will install, but quantum key exchange won't work"
    echo "  until liboqs is properly built and liboqs-python is installed."
}

# ── Reload systemd ───────────────────────────────────────────

echo "[4/4] Configuring systemd..."

systemctl daemon-reload
echo "  systemd reloaded"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Installation complete!"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Run 'cobra' to enroll and start the VPN."
echo ""
echo "  Files installed:"
echo "    /opt/cobratail/bin/       — application code"
echo "    /opt/cobratail/config/    — enrollment & certs (created by wizard)"
echo "    /opt/cobratail/data/      — state & mesh peers"
echo "    /opt/cobratail/logs/      — client logs"
echo "    /usr/local/bin/cobra      — management command"
echo ""
echo "  Quick start:"
echo "    cobra              — Interactive menu (enrollment on first run)"
echo "    cobra --enroll     — Enrollment wizard"
echo "    cobra --start      — Start VPN service"
echo "    cobra --stop       — Stop VPN service"
echo "    cobra --status     — Connection status"
echo ""

POSTINST

chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# ── prerm — runs before package is removed ────────────────────

cat > "${PKG_DIR}/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
set -e

echo "Stopping CobraTail client..."

if systemctl is-active --quiet cobratail 2>/dev/null; then
    systemctl stop cobratail
    echo "  CobraTail service stopped"
fi

if systemctl is-enabled --quiet cobratail 2>/dev/null; then
    systemctl disable cobratail
    echo "  CobraTail service disabled"
fi

# Also handle identity service
if systemctl is-active --quiet cobra-identity 2>/dev/null; then
    systemctl stop cobra-identity 2>/dev/null || true
fi

if systemctl is-enabled --quiet cobra-identity 2>/dev/null; then
    systemctl disable cobra-identity 2>/dev/null || true
fi

PRERM

chmod 755 "${PKG_DIR}/DEBIAN/prerm"

# ── postrm — runs after package is removed ────────────────────

cat > "${PKG_DIR}/DEBIAN/postrm" << 'POSTRM'
#!/bin/bash
set -e

systemctl daemon-reload 2>/dev/null || true

if [ "$1" = "purge" ]; then
    echo "Purging CobraTail client data..."

    # Tear down WireGuard tunnels
    if command -v wg-quick &>/dev/null; then
        wg-quick down wg_quantum 2>/dev/null || true
        wg-quick down wg_mesh 2>/dev/null || true
    fi
    rm -f /etc/wireguard/wg_quantum.conf
    rm -f /etc/wireguard/wg_mesh.conf

    # Remove install directory (code + config + data + logs)
    rm -rf /opt/cobratail
    echo "  Removed /opt/cobratail/"

    # Remove service files (in case they were rewritten by launcher)
    rm -f /etc/systemd/system/cobratail.service
    rm -f /etc/systemd/system/cobra-identity.service
    systemctl daemon-reload 2>/dev/null || true

    echo "  CobraTail client fully purged"
else
    echo ""
    echo "  Config and data preserved at:"
    echo "    /opt/cobratail/config/enrollment.json"
    echo "    /opt/cobratail/data/client_state.json"
    echo "    /opt/cobratail/data/mesh_peers.json"
    echo ""
    echo "  To remove everything: sudo dpkg -P cobra-client"
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
    echo "    cobra"
    echo ""
else
    echo "ERROR: .deb file was not created"
    exit 1
fi

# ── Cleanup build directory ───────────────────────────────────

rm -rf "${PKG_DIR}"
echo "  Build directory cleaned up"
echo ""