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

cat > "${PKG_DIR}/etc/systemd/system/cobra-vault.service" << 'EOF'
[Unit]
Description=CobraTail Vault — PQC Key Manager
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/cobratail/bin/cript_keeper.py
Restart=on-failure
RestartSec=10
WorkingDirectory=/opt/cobratail/bin
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF
chmod 644 "${PKG_DIR}/etc/systemd/system/cobra-vault.service"

cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: python3 (>= 3.9), python3-pip, python3-serial, python3-cryptography, cmake, ninja-build, build-essential, git, libssl-dev
Maintainer: CobraTechLLC <admin@cobratechllc.com>
Homepage: https://github.com/CobraTechLLC/Cobra_Tail
Description: CobraTail Vault — Post-Quantum Key Manager
 ML-KEM-1024 keypair manager with ESP32 entropy harvesting.
 Part of the Cobra Tail (PQC-Mesh) project.
EOF

# postinst — reuse client's liboqs build block + install liboqs-python, then enable service
cat > "${PKG_DIR}/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e
mkdir -p /opt/cobratail/{config,data,logs}
touch /opt/cobratail/.cobratail
if [ ! -f /usr/local/lib/liboqs.so ] && [ ! -f /usr/lib/liboqs.so ]; then
    echo "Building liboqs (slow)..."
    BD=$(mktemp -d); cd "$BD"
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git 2>&1 | tail -1
    cd liboqs && mkdir build && cd build
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. -Wno-dev >/dev/null 2>&1
    ninja >/dev/null 2>&1 && ninja install >/dev/null 2>&1
    ldconfig; cd /; rm -rf "$BD"
fi
pip3 install --break-system-packages liboqs-python pyserial 2>/dev/null || \
pip3 install liboqs-python pyserial 2>/dev/null || echo "WARN: pip failed"
python3 -c "import oqs; oqs.KeyEncapsulation('ML-KEM-1024').generate_keypair(); print('ML-KEM-1024 OK')" || echo "WARN: ML-KEM self-test failed"
systemctl daemon-reload
systemctl enable cobra-vault.service 2>/dev/null || true
echo "Vault installed. Start with: sudo systemctl start cobra-vault"
POSTINST
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

cat > "${PKG_DIR}/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
systemctl stop cobra-vault 2>/dev/null || true
systemctl disable cobra-vault 2>/dev/null || true
PRERM
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

cat > "${PKG_DIR}/DEBIAN/postrm" << 'POSTRM'
#!/bin/bash
systemctl daemon-reload 2>/dev/null || true
if [ "$1" = "purge" ]; then
    rm -rf /opt/cobratail
    rm -f /etc/systemd/system/cobra-vault.service
    systemctl daemon-reload 2>/dev/null || true
fi
POSTRM
chmod 755 "${PKG_DIR}/DEBIAN/postrm"

[ "$EUID" -eq 0 ] && chown -R root:root "${PKG_DIR}"
dpkg-deb --build "${PKG_DIR}" 2>/dev/null || fakeroot dpkg-deb --build "${PKG_DIR}"
echo "Built: ${PKG_DIR}.deb"
rm -rf "${PKG_DIR}"