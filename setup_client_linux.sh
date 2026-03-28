#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# QUANTUM VPN CLIENT — Linux Setup Script
# Run this ONCE with sudo:
#   chmod +x setup_client.sh
#   sudo ./setup_client.sh
# ─────────────────────────────────────────────────────────────

set -e

echo ""
echo "═══════════════════════════════════════════════════"
echo "  QUANTUM VPN CLIENT — Linux Setup"
echo "═══════════════════════════════════════════════════"
echo ""

# ── Check root ───────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run this script with sudo"
    echo "  sudo ./setup_client.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

# ── Detect distro ───────────────────────────────────────────

if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
else
    PKG_MGR="unknown"
fi
echo "Package manager: $PKG_MGR"

# ── Install system packages ──────────────────────────────────

echo ""
echo "[1/6] Installing system dependencies..."

case $PKG_MGR in
    apt)
        apt-get update -qq
        apt-get install -y -qq python3 python3-pip wireguard-tools cmake ninja-build \
            build-essential git libssl-dev 2>/dev/null
        ;;
    dnf)
        dnf install -y -q python3 python3-pip wireguard-tools cmake ninja-build \
            gcc gcc-c++ git openssl-devel 2>/dev/null
        ;;
    pacman)
        pacman -Sy --noconfirm python python-pip wireguard-tools cmake ninja \
            base-devel git openssl 2>/dev/null
        ;;
    *)
        echo "  Unknown package manager — install manually:"
        echo "    python3, pip, wireguard-tools, cmake, ninja, git, build tools"
        ;;
esac

echo "  ✓ System packages installed"

# ── Install Python packages ──────────────────────────────────

echo ""
echo "[2/6] Installing Python packages..."

pip3 install requests cryptography liboqs-python --break-system-packages -q 2>/dev/null || \
pip3 install requests cryptography liboqs-python -q 2>/dev/null

echo "  ✓ Python packages installed"

# ── Build liboqs C library ───────────────────────────────────

echo ""
echo "[3/6] Checking liboqs shared library..."

# Check if liboqs is already installed
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
    BUILD_DIR=$(mktemp -d)

    cd "$BUILD_DIR"
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git 2>/dev/null
    cd liboqs
    mkdir build && cd build

    echo "  Running cmake..."
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. -Wno-dev 2>/dev/null

    echo "  Building (this takes a few minutes)..."
    ninja 2>/dev/null

    echo "  Installing..."
    ninja install 2>/dev/null

    # Update library cache
    ldconfig

    cd /
    rm -rf "$BUILD_DIR"

    if [ -f /usr/local/lib/liboqs.so ]; then
        echo "  ✓ liboqs built and installed"
    else
        echo "  ⚠ liboqs build may have failed — client will fall back to server-side encapsulation"
    fi
else
    echo "  ✓ liboqs already installed"
fi

# ── Create client directory ──────────────────────────────────

echo ""
echo "[4/6] Creating client directory..."

CLIENT_DIR="$REAL_HOME/.quantum_vpn"
mkdir -p "$CLIENT_DIR"
chown "$REAL_USER:$REAL_USER" "$CLIENT_DIR"
chmod 700 "$CLIENT_DIR"
echo "  ✓ $CLIENT_DIR"

# ── Enable IP forwarding (needed for mesh) ───────────────────

echo ""
echo "[5/6] Enabling IP forwarding..."

if ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p -q 2>/dev/null
fi
echo "  ✓ IP forwarding enabled"

# ── Verify everything ────────────────────────────────────────

echo ""
echo "[6/6] Verification..."

ALL_GOOD=true

# Python
if command -v python3 &>/dev/null; then
    echo "  ✓ Python3 ($(python3 --version 2>&1))"
else
    echo "  ✗ Python3 not found"
    ALL_GOOD=false
fi

# Python packages
python3 -c "
import sys
ok = True
for mod in ['requests', 'cryptography']:
    try:
        __import__(mod)
        print(f'  ✓ {mod}')
    except ImportError:
        print(f'  ✗ {mod} missing')
        ok = False
try:
    import oqs
    print('  ✓ liboqs-python + liboqs.so')
except Exception as e:
    print(f'  ⚠ liboqs: {e}')
    print('    Client will fall back to server-side encapsulation (still works)')
if not ok:
    sys.exit(1)
" || ALL_GOOD=false

# WireGuard
if command -v wg &>/dev/null; then
    echo "  ✓ WireGuard ($(wg --version 2>&1 | head -1))"
else
    echo "  ✗ WireGuard not found"
    ALL_GOOD=false
fi

# Firewall
echo ""
echo "  Note: If you have a firewall, open these ports:"
echo "    UDP 51820 — WireGuard server tunnel"
echo "    UDP 51821 — WireGuard mesh tunnels"
echo "    UDP 5391  — LAN peer discovery"

echo ""
if [ "$ALL_GOOD" = true ]; then
    echo "═══════════════════════════════════════════════════"
    echo "  SETUP COMPLETE — Ready to connect!"
    echo "═══════════════════════════════════════════════════"
    echo ""
    echo "  Run (as root or with sudo):"
    echo "  sudo python3 client.py service --cert-fingerprint <fingerprint> \\"
    echo "    --lighthouse-public https://YOUR_PUBLIC_IP:9443 \\"
    echo "    --lighthouse-local https://YOUR_LIGHTHOUSE_IP:8443"
    echo ""
    echo "  Get the fingerprint from your Lighthouse:"
    echo "    python3 lighthouse.py show-fingerprint"
else
    echo "═══════════════════════════════════════════════════"
    echo "  SETUP INCOMPLETE — Fix the issues above"
    echo "═══════════════════════════════════════════════════"
fi
echo ""