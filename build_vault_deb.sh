#!/bin/bash
set -e
VERSION="${1:-1.0.0}"
ARCH="${2:-$(dpkg --print-architecture 2>/dev/null || echo amd64)}"
PKG_NAME="cobra-vault"
PKG_DIR="${PKG_NAME}_${VERSION}_${ARCH}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

[ -f "${SCRIPT_DIR}/cript_keeper.py" ] || { echo "ERROR: cript_keeper.py missing"; exit 1; }

rm -rf "${SCRIPT_DIR}/${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN" "${PKG_DIR}/opt/cobratail/bin" "${PKG_DIR}/opt/cobratail/config" \
         "${PKG_DIR}/opt/cobratail/data" "${PKG_DIR}/opt/cobratail/logs" "${PKG_DIR}/etc/systemd/system"

cp "${SCRIPT_DIR}/cript_keeper.py" "${PKG_DIR}/opt/cobratail/bin/"
echo "${VERSION}" > "${PKG_DIR}/opt/cobratail/version.txt"
touch "${PKG_DIR}/opt/cobratail/.cobratail"
chmod 755 "${PKG_DIR}/opt/cobratail/bin/cript_keeper.py"

# ─── systemd unit ───────────────────────────────────────────────────────────
cat > "${PKG_DIR}/etc/systemd/system/cobra-vault.service" << 'EOF'
[Unit]
Description=CobraTail Vault — PQC Key Manager
After=network-online.target dev-ttyAMA0.device
Wants=network-online.target
[Service]
Type=simple
User=vault
Group=vault
SupplementaryGroups=dialout
ExecStart=/usr/bin/python3 /opt/cobratail/bin/cript_keeper.py serve
Restart=on-failure
RestartSec=10
WorkingDirectory=/home/vault
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF
chmod 644 "${PKG_DIR}/etc/systemd/system/cobra-vault.service"

# ─── control file ───────────────────────────────────────────────────────────
cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.9), python3-pip, python3-serial, python3-cryptography, cmake, ninja-build, build-essential, git, libssl-dev, pkg-config
Maintainer: CobraTechLLC <admin@cobratechllc.com>
Homepage: https://github.com/CobraTechLLC/Cobra_Tail
Description: CobraTail Vault — Post-Quantum Key Manager
 ML-KEM-1024 keypair manager with ESP32 entropy harvesting.
 Part of the Cobra Tail (PQC-Mesh) project.
EOF

# ─── postinst ───────────────────────────────────────────────────────────────
cat > "${PKG_DIR}/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e

echo "════════════════════════════════════════════════════════════"
echo "  CobraTail Vault — installing"
echo "════════════════════════════════════════════════════════════"

# ─── 1. Create vault system user ────────────────────────────────────────────
if ! id vault >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /home/vault \
            --shell /usr/sbin/nologin --groups dialout vault
    echo "[1/8] Created vault system user"
else
    usermod -a -G dialout vault || true
    echo "[1/8] vault user already exists"
fi

# ─── 2. Vault directories ───────────────────────────────────────────────────
mkdir -p /opt/cobratail/{config,data,logs}
mkdir -p /home/vault/.crypt_vault
chown -R vault:vault /home/vault/.crypt_vault
chmod 700 /home/vault/.crypt_vault
touch /opt/cobratail/.cobratail
echo "[2/8] Vault directories ready"

# ─── 3. Swap guard for low-RAM boxes (Pi Zero 2 W has 512MB) ───────────────
TOTAL_RAM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
SWAP_KB=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
SWAP_FILE="/var/cobra-vault-build.swap"
SWAP_ADDED=0
if [ "$TOTAL_RAM_KB" -lt 1048576 ] && [ "$SWAP_KB" -lt 1048576 ]; then
    if [ ! -f /usr/local/lib/liboqs.so ] && [ ! -f /usr/lib/liboqs.so ]; then
        echo "[3/8] Low RAM detected — adding 1G temporary swap for liboqs build"
        fallocate -l 1G "$SWAP_FILE" 2>/dev/null || dd if=/dev/zero of="$SWAP_FILE" bs=1M count=1024
        chmod 600 "$SWAP_FILE"
        mkswap "$SWAP_FILE" >/dev/null
        swapon "$SWAP_FILE"
        SWAP_ADDED=1
    fi
else
    echo "[3/8] Swap check: OK"
fi

# ─── 4. Build liboqs from source if missing ─────────────────────────────────
if [ ! -f /usr/local/lib/liboqs.so ] && [ ! -f /usr/lib/liboqs.so ]; then
    echo "[4/8] Building liboqs (10–20 min on Pi Zero 2 W)..."
    BD=$(mktemp -d); cd "$BD"
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
    cd liboqs && mkdir build && cd build
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. -Wno-dev
    ninja
    ninja install
    ldconfig
    cd /; rm -rf "$BD"
    echo "      liboqs built and installed"
else
    echo "[4/8] liboqs already present"
fi

# Tear down temporary swap
if [ "$SWAP_ADDED" = "1" ]; then
    swapoff "$SWAP_FILE" 2>/dev/null || true
    rm -f "$SWAP_FILE"
fi

# ─── 5. Python deps ─────────────────────────────────────────────────────────
echo "[5/8] Installing Python deps"
pip3 install --break-system-packages liboqs-python pyserial cryptography 2>/dev/null || \
pip3 install liboqs-python pyserial cryptography 2>/dev/null || echo "      WARN: pip failed"

python3 -c "import oqs; oqs.KeyEncapsulation('ML-KEM-1024').generate_keypair(); print('      ML-KEM-1024 self-test OK')" \
    || echo "      WARN: ML-KEM self-test failed"

# ─── 6. Enable PL011 UART on GPIO 14/15 (Pi Zero 2 W) ───────────────────────
echo "[6/8] Configuring GPIO UART for Lighthouse link"
NEEDS_REBOOT=0
CONFIG_TXT="/boot/firmware/config.txt"
CMDLINE_TXT="/boot/firmware/cmdline.txt"
[ -f "$CONFIG_TXT" ] || CONFIG_TXT="/boot/config.txt"
[ -f "$CMDLINE_TXT" ] || CMDLINE_TXT="/boot/cmdline.txt"

if [ -f "$CONFIG_TXT" ]; then
    if ! grep -q "^enable_uart=1" "$CONFIG_TXT"; then
        echo "enable_uart=1" >> "$CONFIG_TXT"
        NEEDS_REBOOT=1
    fi
    if ! grep -q "^dtoverlay=disable-bt" "$CONFIG_TXT"; then
        echo "dtoverlay=disable-bt" >> "$CONFIG_TXT"
        NEEDS_REBOOT=1
    fi
fi

if [ -f "$CMDLINE_TXT" ]; then
    if grep -q "console=serial0" "$CMDLINE_TXT"; then
        sed -i 's/console=serial0,[0-9]* //g' "$CMDLINE_TXT"
        NEEDS_REBOOT=1
    fi
fi

systemctl disable --now serial-getty@ttyAMA0.service 2>/dev/null || true
systemctl disable --now hciuart.service 2>/dev/null || true

# ─── 7. udev rule for stable ESP32 access ───────────────────────────────────
echo "[7/8] Installing udev rule for ESP32 Tongue"
cat > /etc/udev/rules.d/99-cobra-tongue.rules << 'UDEV'
# CobraTail ESP32 Tongue — entropy source
KERNEL=="ttyACM[0-9]*", GROUP="dialout", MODE="0660", SYMLINK+="cobra-tongue"
UDEV
udevadm control --reload-rules 2>/dev/null || true
udevadm trigger 2>/dev/null || true

# ─── 8. Enable service (do not start — UART needs reboot) ───────────────────
echo "[8/8] Enabling cobra-vault.service"
systemctl daemon-reload
systemctl enable cobra-vault.service 2>/dev/null || true

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  CobraTail Vault installed successfully"
echo "════════════════════════════════════════════════════════════"
if [ "$NEEDS_REBOOT" = "1" ]; then
    echo "  ⚠  REBOOT REQUIRED — UART changes pending"
    echo "     After reboot, the service starts automatically."
    echo "     Run:  sudo reboot"
else
    echo "  UART already configured. Start the service:"
    echo "     sudo systemctl start cobra-vault"
fi
echo ""
echo "  ESP32 check:   ls -l /dev/cobra-tongue"
echo "  Service logs:  sudo journalctl -u cobra-vault -f"
echo "════════════════════════════════════════════════════════════"
POSTINST
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# ─── prerm ──────────────────────────────────────────────────────────────────
cat > "${PKG_DIR}/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
systemctl stop cobra-vault 2>/dev/null || true
systemctl disable cobra-vault 2>/dev/null || true
PRERM
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

# ─── postrm ─────────────────────────────────────────────────────────────────
cat > "${PKG_DIR}/DEBIAN/postrm" << 'POSTRM'
#!/bin/bash
systemctl daemon-reload 2>/dev/null || true
rm -f /etc/udev/rules.d/99-cobra-tongue.rules
udevadm control --reload-rules 2>/dev/null || true
if [ "$1" = "purge" ]; then
    rm -rf /opt/cobratail
    rm -rf /home/vault/.crypt_vault
    rm -f /etc/systemd/system/cobra-vault.service
    userdel vault 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
fi
POSTRM
chmod 755 "${PKG_DIR}/DEBIAN/postrm"

[ "$EUID" -eq 0 ] && chown -R root:root "${PKG_DIR}"
dpkg-deb --build "${PKG_DIR}" 2>/dev/null || fakeroot dpkg-deb --build "${PKG_DIR}"
echo "Built: ${PKG_DIR}.deb"
rm -rf "${PKG_DIR}"