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

VERSION=$(cat version.txt)
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
    "install_wstunnel.sh"
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
cp "${SCRIPT_DIR}/install_wstunnel.sh" "${PKG_DIR}/opt/cobratail/bin/"

# Write version file
echo "${VERSION}" > "${PKG_DIR}/opt/cobratail/version.txt"

# Marker file — signals managed install to _detect_cobratail_dir()
touch "${PKG_DIR}/opt/cobratail/.cobratail"

# Set permissions on application files
chmod 755 "${PKG_DIR}/opt/cobratail/bin/client.py"
chmod 755 "${PKG_DIR}/opt/cobratail/bin/cobra_launcher.py"
chmod 755 "${PKG_DIR}/opt/cobratail/bin/identity_manager.py"
chmod 755 "${PKG_DIR}/opt/cobratail/bin/install_wstunnel.sh"
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
Maintainer: CobraTechLLC <admin@cobratechllc.com>
Homepage: https://github.com/CobraTechLLC/Cobra_Tail
Depends: python3 (>= 3.9), python3-requests, python3-cryptography, python3-pip, wireguard-tools, systemd-resolved | openresolv, libssl-dev, ninja-build, cmake, build-essential, git
Recommends: systemd-resolved | openresolv | resolvconf, wireguard
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

echo "[1/5] Creating directories..."

mkdir -p /opt/cobratail/config
mkdir -p /opt/cobratail/data
mkdir -p /opt/cobratail/logs

# Ensure marker exists
touch /opt/cobratail/.cobratail

echo "  Created /opt/cobratail/{config,data,logs}/"

# ── Raspberry Pi Zero 2 W: low-memory install path ───────────
# The Zero 2 W has 512 MB RAM. A full parallel liboqs build runs it out
# of memory and freezes the board, so on this model only we:
#   - make sure DNS works first (installing systemd-resolved as a
#     dependency can leave name resolution dead until it is restarted)
#   - build a minimal liboqs (ML-KEM-1024 only, no tests) one job at a
#     time, with progress printed so it doesn't look hung
#   - pin liboqs + liboqs-python to matching versions
# Every other device takes the original install path unchanged.

IS_PI_ZERO2=false
NET_OK=true          # only re-checked on the Zero 2 W; always true elsewhere
ZERO_LIBOQS_VERSION="0.16.0"
ZERO_LIBOQS_PY_VERSION="0.16.0.1"

if [ -r /proc/device-tree/model ] && tr -d '\0' < /proc/device-tree/model | grep -q "Raspberry Pi Zero 2"; then
    IS_PI_ZERO2=true
    echo ""
    echo "  Detected Raspberry Pi Zero 2 W — using low-memory install path"

    zero_dns_ok() {
        getent hosts github.com >/dev/null 2>&1
    }

    echo "  Checking DNS..."
    if ! zero_dns_ok; then
        echo "  DNS not responding — restarting systemd-resolved..."
        systemctl restart systemd-resolved 2>/dev/null || true
        for _ in 1 2 3 4 5 6; do
            sleep 5
            zero_dns_ok && break
        done
    fi

    if zero_dns_ok; then
        echo "  DNS OK"
    else
        NET_OK=false
        echo ""
        echo "  WARNING: DNS still not working — skipping downloads (liboqs,"
        echo "  pip packages, wstunnel). Fix DNS, then retry with:"
        echo "    sudo systemctl restart systemd-resolved"
        echo "    getent hosts github.com"
        echo "    sudo dpkg-reconfigure cobra-client"
    fi
fi

# ── Build and install liboqs C library ───────────────────────

echo "[2/5] Checking liboqs shared library..."

LIBOQS_FOUND=false
# ldconfig knows every library path, including multiarch ones like
# /usr/local/lib/aarch64-linux-gnu that the fixed list below would miss
if ldconfig -p 2>/dev/null | grep -q 'liboqs\.so'; then
    echo "  Found: $(ldconfig -p | grep -m1 'liboqs\.so' | awk '{print $NF}')"
    LIBOQS_FOUND=true
else
    for lib_path in /usr/local/lib/liboqs.so /usr/lib/liboqs.so /usr/local/lib64/liboqs.so; do
        if [ -f "$lib_path" ]; then
            echo "  Found: $lib_path"
            LIBOQS_FOUND=true
            break
        fi
    done
fi

if [ "$LIBOQS_FOUND" = false ] && [ "$IS_PI_ZERO2" = true ] && [ "$NET_OK" = false ]; then
    echo "  liboqs not found — skipping build (no DNS, see warning above)"
    echo "  The client will use server-side ML-KEM encapsulation until it's installed."

elif [ "$LIBOQS_FOUND" = false ] && [ "$IS_PI_ZERO2" = true ]; then
    echo "  liboqs not found — building minimal liboqs ${ZERO_LIBOQS_VERSION} (ML-KEM-1024 only)..."
    echo "  On a Pi Zero 2 W this takes roughly 10–20 minutes. Progress is shown"
    echo "  below every 30 seconds — don't interrupt it."
    echo ""

    BUILD_DIR=$(mktemp -d)
    BUILD_LOG=/opt/cobratail/logs/liboqs-build.log
    : > "$BUILD_LOG"

    # Each step returns explicitly on failure because `set -e` is ignored
    # inside a function called from an `if` test.
    zero_build_liboqs() {
        cd "$BUILD_DIR" || return 1
        echo "  Downloading liboqs ${ZERO_LIBOQS_VERSION}..."
        git clone --depth 1 --branch "$ZERO_LIBOQS_VERSION" \
            https://github.com/open-quantum-safe/liboqs.git >> "$BUILD_LOG" 2>&1 || return 1
        cd liboqs && mkdir build && cd build || return 1

        echo "  Configuring..."
        cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local \
            -DOQS_BUILD_ONLY_LIB=ON \
            -DOQS_MINIMAL_BUILD="KEM_ml_kem_1024" \
            -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic \
            .. -Wno-dev >> "$BUILD_LOG" 2>&1 || return 1

        # One compile job at a time keeps memory use within 512 MB
        echo "  Compiling (1 job at a time)..."
        ninja -j1 >> "$BUILD_LOG" 2>&1 &
        local ninja_pid=$!
        local progress
        while kill -0 "$ninja_pid" 2>/dev/null; do
            sleep 30
            progress=$(grep -o '^\[[0-9]*/[0-9]*\]' "$BUILD_LOG" 2>/dev/null | tail -1)
            [ -n "$progress" ] && echo "    progress: ${progress}"
        done
        wait "$ninja_pid" || return 1

        echo "  Installing..."
        ninja install >> "$BUILD_LOG" 2>&1 || return 1
    }

    if zero_build_liboqs; then
        ldconfig
        echo "  liboqs built and installed successfully"
    else
        echo ""
        echo "  WARNING: liboqs build failed — see $BUILD_LOG"
        echo "  The client still works: it falls back to server-side ML-KEM"
        echo "  encapsulation. To retry the build:"
        echo "    sudo dpkg-reconfigure cobra-client"
        echo ""
    fi

    cd /
    rm -rf "$BUILD_DIR"

elif [ "$LIBOQS_FOUND" = false ]; then
    echo "  liboqs not found — building from source..."
    echo "  (This takes a few minutes on first install — don't interrupt it)"
    echo ""

    BUILD_DIR=$(mktemp -d)
    BUILD_LOG=/opt/cobratail/logs/liboqs-build.log

    # On ARM (Raspberry Pi) the optimized build emits SHA3 instructions
    # (e.g. eor3) that Debian 12's assembler rejects. The portable build
    # avoids them; ML-KEM speed is irrelevant for a key exchange.
    OQS_ARCH_FLAGS=""
    case "$(uname -m)" in
        aarch64|arm64|armv7l|armv6l)
            OQS_ARCH_FLAGS="-DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic" ;;
    esac

    # The build runs in a subshell whose failure is caught below. Without
    # this, `set -e` aborted the whole postinst on any build error (or a
    # Ctrl+C), leaving the package half-configured — and apt then re-ran
    # this entire build during every unrelated `apt install` afterwards.
    echo "  Building (full output in $BUILD_LOG)..."
    # (steps are chained with && because bash ignores `set -e` inside an
    # `if` test, so each step must explicitly stop the chain on failure)
    if {
        cd "$BUILD_DIR" &&
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git &&
        cd liboqs && mkdir build && cd build &&
        cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local $OQS_ARCH_FLAGS .. -Wno-dev &&
        ninja &&
        ninja install
    } > "$BUILD_LOG" 2>&1; then
        ldconfig
        echo "  liboqs built and installed successfully"
    else
        echo ""
        echo "  WARNING: liboqs build failed — see $BUILD_LOG"
        echo "  The client is installed, but post-quantum key exchange won't work"
        echo "  until liboqs is installed. To retry:"
        echo "    sudo dpkg-reconfigure cobra-client"
        echo ""
    fi

    cd /
    rm -rf "$BUILD_DIR"
else
    echo "  liboqs already installed"
fi

# ── Install Python dependencies ──────────────────────────────

echo "[3/5] Installing Python dependencies..."

if [ "$IS_PI_ZERO2" = true ]; then
    # ── Pi Zero 2 W path ──
    if [ "$NET_OK" = true ]; then
        pip3 install --break-system-packages requests psutil 2>/dev/null || \
        echo "  WARNING: pip install failed for core packages"
    else
        echo "  Skipping pip packages (no DNS)"
    fi

    # Only install liboqs-python when liboqs itself is present. Without it,
    # importing liboqs-python tries to download and compile liboqs on its
    # own, which would freeze a Zero 2 W just like the full build does.
    if ldconfig -p 2>/dev/null | grep -q 'liboqs\.so'; then
        if [ "$NET_OK" = true ]; then
            pip3 install --break-system-packages "liboqs-python==${ZERO_LIBOQS_PY_VERSION}" 2>/dev/null || \
            echo "  WARNING: liboqs-python install failed — using server-side encapsulation"
        fi

        echo "  Verifying ML-KEM-1024 support..."
        python3 -c "
import oqs
kem = oqs.KeyEncapsulation('ML-KEM-1024')
pub = kem.generate_keypair()
ct, ss = kem.encap_secret(pub)
print('  ML-KEM-1024 self-test: PASSED (client-side encapsulation enabled)')
" 2>/dev/null || {
            echo "  ML-KEM-1024 self-test failed — client will use server-side encapsulation"
        }
    else
        echo "  liboqs not installed — skipping liboqs-python"
        echo "  Client will use server-side ML-KEM encapsulation (fully supported)"
    fi

else
# ── All other devices: original path ──

# Install core pip packages
pip3 install --break-system-packages \
    requests psutil 2>/dev/null || \
pip3 install \
    requests psutil 2>/dev/null || \
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

fi  # end Pi Zero 2 W / other devices

# ── Install wstunnel (TCP fallback for UDP-hostile networks) ──
# Delegated to install_wstunnel.sh so it can be re-run by hand
# (sudo /opt/cobratail/bin/install_wstunnel.sh) without dpkg-reconfigure,
# and so a download problem can never abort this postinst under `set -e`.

echo "[4/5] Installing wstunnel TCP fallback..."

if [ "$NET_OK" = true ]; then
    /opt/cobratail/bin/install_wstunnel.sh || true
else
    echo "  Skipping wstunnel download (no DNS)"
fi

if ! /opt/cobratail/bin/wstunnel --version >/dev/null 2>&1; then
    echo ""
    echo "  WARNING: wstunnel not installed"
    echo "  The VPN will work on most networks, but public wifi and"
    echo "  corporate networks that block UDP will not be able to connect."
    echo "  Details: /opt/cobratail/logs/wstunnel-install.log"
    echo "  Retry:   sudo /opt/cobratail/bin/install_wstunnel.sh --force"
    echo ""
fi

# ── Reload systemd ───────────────────────────────────────────

echo "[5/5] Configuring systemd..."

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
echo "    /opt/cobratail/bin/       — application code + wstunnel"
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