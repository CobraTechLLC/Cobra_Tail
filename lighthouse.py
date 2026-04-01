"""
THE LIGHTHOUSE — Pi 4 Coordination Server

FastAPI VPN coordination server with:
  - YAML config file (like headscale)
  - GPIO UART link to the Vault (Pi Zero 2 W)
  - SQLite persistence for peer directory
  - WireGuard tunnel automation
  - ML-KEM-1024 handshake brokering
  - Scheduled quantum PSK rotation

Dependencies:
    pip install fastapi uvicorn pyserial pyyaml liboqs-python

Run:
    python lighthouse.py serve --config /etc/lighthouse/config.yaml
"""

import base64
import hashlib
import json
import os
import sqlite3
import struct
import subprocess
import sys
import threading
import queue
import time
import uuid
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import ssl

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

try:
    import oqs
except ImportError:
    print("WARNING: liboqs-python not installed — KEM brokering will fail")
    oqs = None

try:
    import serial
except ImportError:
    print("WARNING: pyserial not installed — Vault UART link disabled")
    serial = None
# ─── Enrollment ──────────────────────────────────────────────────────────────
ENROLLMENT_TOKEN_TTL = 900  # 15 minutes in seconds
# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [LIGHTHOUSE] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("lighthouse")

# ─── Global Config ───────────────────────────────────────────────────────────

CONFIG: dict = {}

# ─── UART Frame Protocol (matches Vault's protocol) ─────────────────────────

STX = 0x02
ETX = 0x03


def frame_message(msg_type: str, data: dict) -> bytes:
    """Build a framed UART message."""
    payload = json.dumps({"type": msg_type, "data": data}).encode()
    length = struct.pack(">H", len(payload))
    return bytes([STX]) + length + payload + bytes([ETX])


def read_frame(ser, timeout: float = 5.0) -> dict | None:
    """Read a single framed UART message."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        byte = ser.read(1)
        if len(byte) == 1 and byte[0] == STX:
            break
    else:
        return None

    length_bytes = ser.read(2)
    if len(length_bytes) < 2:
        return None
    payload_len = struct.unpack(">H", length_bytes)[0]

    if payload_len > 65535:
        return None

    raw = ser.read(payload_len + 1)
    if len(raw) < payload_len + 1:
        return None

    if raw[payload_len] != ETX:
        return None

    try:
        return json.loads(raw[:payload_len].decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

# ─── Config Loader ───────────────────────────────────────────────────────────


def load_config(path: str) -> dict:
    """Load and validate the YAML config file."""
    config_path = Path(path)
    if not config_path.exists():
        log.error(f"Config file not found: {path}")
        sys.exit(1)

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    # Set defaults for optional fields
    cfg.setdefault("listen_addr", "0.0.0.0")
    cfg.setdefault("listen_port", 8443)
    cfg.setdefault("peer_timeout", 120)
    cfg.setdefault("max_clients", 25)
    cfg.setdefault("tls", {"enabled": False})
    cfg.setdefault("vault_uart", {"enabled": True, "device": "/dev/ttyAMA0", "baud_rate": 115200})
    cfg.setdefault("wireguard", {
        "listen_port": 51820, "address_pool": "10.100.0.0/24",
        "server_address": "10.100.0.1/24", "interface": "wg0",
        "dns": ["1.1.1.1"], "exit_node": True,
        "key_dir": "/etc/lighthouse/wg_keys",
    })
    cfg.setdefault("mesh", {"address_pool": "10.200.0.0/24"})
    cfg.setdefault("pqc", {"algorithm": "ML-KEM-1024", "key_rotation_hours": 24})
    cfg.setdefault("database", {"path": "/var/lib/lighthouse/lighthouse.db"})
    cfg.setdefault("discovery", {"enabled": True, "broadcast_port": 5391, "broadcast_interval": 30})
    cfg.setdefault("local_server_url", "")
    cfg.setdefault("log", {"level": "info"})

    log.info(f"Config loaded from {path}")
    return cfg

# ─── TLS Certificate Management ─────────────────────────────────────────────


def get_cert_fingerprint(cert_path: str) -> str:
    """Compute the SHA-256 fingerprint of a DER-encoded certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    cert_pem = Path(cert_path).read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    der_bytes = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(der_bytes).hexdigest()


def request_entropy_from_vault(nbytes: int = 64, timeout: float = 10.0) -> bytes | None:
    """Request entropy from the Vault over UART for TLS cert generation."""
    if vault_uart is None:
        return None

    request_id = uuid.uuid4().hex[:8]
    send_to_vault("entropy_request", {
        "request_id": request_id,
        "bytes_needed": nbytes,
    })

    deadline = time.time() + timeout
    while time.time() < deadline:
        with vault_lock:
            if vault_uart and vault_uart.in_waiting > 0:
                msg = read_frame(vault_uart, timeout=2.0)
                if msg and msg.get("type") == "entropy_response":
                    data = msg.get("data", {})
                    entropy_b64 = data.get("entropy", "")
                    if entropy_b64:
                        return base64.b64decode(entropy_b64)
        time.sleep(0.5)

    return None


def generate_self_signed_cert(config: dict) -> tuple[str, str]:
    """
    Generate a self-signed TLS certificate.
    Uses ESP32 entropy via Vault UART if available, falls back to OS entropy.
    Returns (cert_path, fingerprint).
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from ipaddress import ip_address
    import datetime as dt

    tls_cfg = config.get("tls", {})
    cert_path = tls_cfg.get("cert_file", "/etc/lighthouse/server.crt")
    key_path = tls_cfg.get("key_file", "/etc/lighthouse/server.key")
    cert_days = tls_cfg.get("cert_days", 365)
    subject_name = tls_cfg.get("cert_subject", "The Lighthouse")

    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)

    # Try to get ESP32 entropy from the Vault
    esp32_entropy = None
    log.info("Requesting ESP32 entropy from Vault for TLS cert generation...")
    try:
        esp32_entropy = request_entropy_from_vault(64, timeout=10.0)
    except Exception as e:
        log.warning(f"Could not get Vault entropy: {e}")

    if esp32_entropy:
        log.info(f"Received {len(esp32_entropy)} bytes of ESP32 hardware entropy")
        try:
            with open("/dev/urandom", "wb") as f:
                f.write(esp32_entropy)
            log.info("ESP32 entropy mixed into system pool")
        except PermissionError:
            log.warning("Cannot write to /dev/urandom — using OS entropy only")
    else:
        log.warning("Vault not available — generating cert with OS entropy only")

    # Generate EC P-256 private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Build self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Quantum Scale VPN"),
    ])

    # Include SANs for both IP addresses so TLS validates on LAN and public
    san_list = [x509.DNSName(subject_name)]
    server_url = config.get("server_url", "")
    local_url = config.get("local_server_url", "")
    for url in [server_url, local_url]:
        if url:
            try:
                host = url.split("://")[1].split(":")[0]
                san_list.append(x509.IPAddress(ip_address(host)))
            except (ValueError, IndexError):
                pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=cert_days))
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Write cert and key
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(key_path).write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)

    # Compute fingerprint
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der_bytes).hexdigest()

    log.info(f"TLS certificate written to {cert_path}")
    log.info(f"TLS private key written to {key_path}")
    log.info(f"Certificate valid for {cert_days} days")
    log.info("")
    log.info("=" * 60)
    log.info("CERTIFICATE FINGERPRINT (give this to your clients):")
    log.info(f"  {fingerprint}")
    log.info("=" * 60)
    log.info("")
    log.info("Client usage:")
    log.info(f"  python client.py service --cert-fingerprint {fingerprint} \\")
    log.info(f"    --lighthouse-public {config.get('server_url', '')} \\")
    log.info(f"    --lighthouse-local {config.get('local_server_url', '')}")

    return cert_path, fingerprint


def display_cert_fingerprint(config: dict) -> str | None:
    """Display the current cert fingerprint on startup. Returns fingerprint or None."""
    tls_cfg = config.get("tls", {})
    cert_path = tls_cfg.get("cert_file", "/etc/lighthouse/server.crt")

    if not Path(cert_path).exists():
        return None

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        import datetime as dt

        cert_pem = Path(cert_path).read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        der_bytes = cert.public_bytes(Encoding.DER)
        fingerprint = hashlib.sha256(der_bytes).hexdigest()

        now = dt.datetime.now(dt.timezone.utc)
        days_left = (cert.not_valid_after_utc - now).days

        log.info(f"TLS cert fingerprint: {fingerprint}")
        log.info(f"TLS cert expires in {days_left} days")
        if days_left < 30:
            log.warning("TLS certificate expires soon — regenerate with: python lighthouse.py generate-cert")

        return fingerprint
    except Exception as e:
        log.error(f"Failed to read TLS cert: {e}")
        return None


# ─── SQLite Database ─────────────────────────────────────────────────────────


def init_database(db_path: str) -> None:
    """Create the SQLite tables if they don't exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                device_id TEXT PRIMARY KEY,
                device_type TEXT NOT NULL,
                public_key TEXT,
                kem_algorithm TEXT,
                ip_address TEXT,
                wireguard_pubkey TEXT,
                vpn_address TEXT,
                wg_psk TEXT,
                registered_at TEXT,
                last_seen REAL,
                status TEXT DEFAULT 'online'
            )
        """)
        # Migrate: add columns if missing (existing databases)
        for col in ["wg_psk TEXT", "lan_ip TEXT", "public_ip TEXT",
                     "stun_endpoint TEXT", "nat_type TEXT",
                     "mesh_address TEXT"]:
            try:
                conn.execute(f"ALTER TABLE peers ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Phase 5B: IPv6 deterministic token columns
        for col in ["ipv6_token TEXT", "ipv6_prefix TEXT", "ipv6_token_addr TEXT"]:
            try:
                conn.execute(f"ALTER TABLE peers ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass  # Column already exists

        conn.execute("""
            CREATE TABLE IF NOT EXISTS handshakes (
                request_id TEXT PRIMARY KEY,
                client_device_id TEXT,
                vault_device_id TEXT,
                status TEXT DEFAULT 'pending',
                quantum_psk TEXT,
                created_at TEXT,
                completed_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mesh_tunnels (
                request_id TEXT PRIMARY KEY,
                initiator_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                initiator_wg_pubkey TEXT,
                target_wg_pubkey TEXT,
                initiator_endpoint TEXT,
                target_endpoint TEXT,
                initiator_wg_port INTEGER DEFAULT 51821,
                target_wg_port INTEGER DEFAULT 51821,
                initiator_mesh_ip TEXT,
                target_mesh_ip TEXT,
                quantum_psk TEXT,
                created_at TEXT,
                completed_at TEXT
            )
        """)
        # Migrate: add mesh IP columns if missing (existing databases)
        for col in ["initiator_mesh_ip TEXT", "target_mesh_ip TEXT"]:
            try:
                conn.execute(f"ALTER TABLE mesh_tunnels ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        # Migrate: add NAT traversal columns if missing (Phase 1)
        for col in ["initiator_candidates TEXT", "target_candidates TEXT",
                     "initiator_nat_type TEXT", "target_nat_type TEXT"]:
            try:
                conn.execute(f"ALTER TABLE mesh_tunnels ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        # Migrate: add Phase 2 pairing confidence column
        for col in ["pairing_confidence TEXT"]:
            try:
                conn.execute(f"ALTER TABLE mesh_tunnels ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        # ── Enrollment tokens for node authorization ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                token TEXT PRIMARY KEY,
                node_name TEXT NOT NULL,
                device_id TEXT,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used_at TEXT,
                used_by_ip TEXT,
                status TEXT DEFAULT 'pending'
            )
        """)
        conn.commit()
    log.info(f"Database ready: {db_path}")

@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(CONFIG["database"]["path"])
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ─── WireGuard Management ───────────────────────────────────────────────────


def setup_wireguard() -> tuple[str, str]:
    """
    Initialize the WireGuard interface on the Pi 4.
    Generates server keys if needed and brings up the interface.
    Returns (private_key, public_key).
    """
    wg = CONFIG["wireguard"]
    key_dir = Path(wg["key_dir"])
    key_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(key_dir, 0o700)

    priv_path = key_dir / "server_private.key"
    pub_path = key_dir / "server_public.key"

    if not priv_path.exists():
        log.info("Generating WireGuard server keypair...")
        privkey = subprocess.check_output(["wg", "genkey"]).decode().strip()
        pubkey = subprocess.check_output(
            ["wg", "pubkey"], input=privkey.encode()
        ).decode().strip()
        priv_path.write_text(privkey)
        pub_path.write_text(pubkey)
        os.chmod(priv_path, 0o600)
        log.info(f"WireGuard public key: {pubkey}")
    else:
        privkey = priv_path.read_text().strip()
        pubkey = pub_path.read_text().strip()
        log.info(f"Loaded WireGuard keys (pub: {pubkey[:20]}...)")

    # Write wg0.conf
    conf_path = Path(f"/etc/wireguard/{wg['interface']}.conf")
    conf_content = (
        "[Interface]\n"
        f"PrivateKey = {privkey}\n"
        f"Address = {wg['server_address']}\n"
        f"ListenPort = {wg['listen_port']}\n"
        "SaveConfig = false\n"
    )

    if wg.get("exit_node"):
        conf_content += (
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; "
            "iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE\n"
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; "
            "iptables -t nat -D POSTROUTING -o wlan0 -j MASQUERADE\n"
        )

    conf_path.write_text(conf_content)
    os.chmod(conf_path, 0o600)

    # Bring up the interface
    try:
        subprocess.run(["wg-quick", "down", wg["interface"]],
                       capture_output=True, timeout=10)
    except Exception:
        pass

    try:
        subprocess.run(["wg-quick", "up", wg["interface"]],
                       check=True, capture_output=True, timeout=10)
        log.info(f"WireGuard interface {wg['interface']} is up on port {wg['listen_port']}")
    except subprocess.CalledProcessError as e:
        log.error(f"Failed to bring up WireGuard: {e.stderr.decode()}")

    # Restore previously connected peers from database
    try:
        restore_wireguard_peers()
    except Exception as e:
        log.warning(f"Peer restore failed: {e}")

    return privkey, pubkey


def allocate_vpn_address() -> str:
    """Allocate the next available VPN address from the pool."""
    pool = CONFIG["wireguard"]["address_pool"]
    base = pool.split("/")[0]
    octets = base.split(".")

    with get_db() as conn:
        used = {row["vpn_address"] for row in
                conn.execute("SELECT vpn_address FROM peers WHERE vpn_address IS NOT NULL")}

    # Start from .2 (server is .1)
    for i in range(2, 255):
        addr = f"{octets[0]}.{octets[1]}.{octets[2]}.{i}"
        if addr not in used:
            return addr

    raise RuntimeError("VPN address pool exhausted")

def allocate_mesh_address(exclude: set = None) -> str:
    """Allocate the next available mesh VPN address from the mesh pool (10.200.0.0/24).
    Mesh addresses are separate from the main VPN pool to avoid routing conflicts
    on Windows where wg_quantum claims the entire 10.100.0.0/24 subnet."""
    pool = CONFIG.get("mesh", {}).get("address_pool", "10.200.0.0/24")
    base = pool.split("/")[0]
    octets = base.split(".")

    with get_db() as conn:
        # Collect all mesh IPs already in use from active/pending tunnels
        used = set()
        rows = conn.execute(
            "SELECT initiator_mesh_ip, target_mesh_ip FROM mesh_tunnels "
            "WHERE status IN ('pending', 'active')"
        ).fetchall()
        for row in rows:
            if row["initiator_mesh_ip"]:
                used.add(row["initiator_mesh_ip"])
            if row["target_mesh_ip"]:
                used.add(row["target_mesh_ip"])

        # Also collect persistently assigned mesh addresses from the peers table
        for row in conn.execute(
            "SELECT mesh_address FROM peers WHERE mesh_address IS NOT NULL"
        ).fetchall():
            used.add(row["mesh_address"])

    # Also exclude any IPs passed in (e.g., the initiator IP when allocating the target)
    if exclude:
        used.update(exclude)

    # Start from .1 (no server in mesh — all peers)
    for i in range(1, 255):
        addr = f"{octets[0]}.{octets[1]}.{octets[2]}.{i}"
        if addr not in used:
            return addr

    raise RuntimeError("Mesh address pool exhausted")

def get_or_allocate_mesh_address(device_id: str, exclude: set = None) -> str:
    """Get the device's persistent mesh address, or allocate one if it doesn't have one yet.

    Unlike allocate_mesh_address() which hands out a fresh IP every time,
    this ensures each device keeps the SAME mesh IP across all its tunnels.
    The mesh address is stored in the peers table so it survives tunnel
    teardowns and re-registrations.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT mesh_address FROM peers WHERE device_id = ?", (device_id,)
        ).fetchone()

    if row and row["mesh_address"]:
        return row["mesh_address"]

    # First time in mesh — allocate and persist
    addr = allocate_mesh_address(exclude=exclude)
    with get_db() as conn:
        conn.execute(
            "UPDATE peers SET mesh_address = ? WHERE device_id = ?",
            (addr, device_id),
        )
    log.info(f"Assigned persistent mesh address {addr} to {device_id}")
    return addr

def add_wireguard_peer(wg_pubkey: str, vpn_address: str, psk: str = None) -> None:
    """Add a peer to the live WireGuard interface and persist it."""
    iface = CONFIG["wireguard"]["interface"]

    cmd = ["wg", "set", iface, "peer", wg_pubkey, "allowed-ips", f"{vpn_address}/32"]
    if psk:
        cmd.extend(["preshared-key", "/dev/stdin"])
        subprocess.run(cmd, input=psk.encode(), check=True, capture_output=True)
    else:
        subprocess.run(cmd, check=True, capture_output=True)

    # Persist the PSK in the database so we can restore on reboot
    if psk:
        with get_db() as conn:
            conn.execute(
                "UPDATE peers SET wg_psk = ? WHERE wireguard_pubkey = ? OR vpn_address = ?",
                (psk, wg_pubkey, vpn_address),
            )

    log.info(f"Added WireGuard peer {wg_pubkey[:20]}... → {vpn_address}")


def restore_wireguard_peers() -> None:
    """Restore previously connected WireGuard peers from the database."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT wireguard_pubkey, vpn_address, wg_psk FROM peers "
            "WHERE device_type = 'client' AND wireguard_pubkey IS NOT NULL "
            "AND wireguard_pubkey != '' AND wireguard_pubkey != 'GENERATE_ME'"
        ).fetchall()

    if not rows:
        log.info("No saved WireGuard peers to restore")
        return

    restored = 0
    for row in rows:
        try:
            add_wireguard_peer(row["wireguard_pubkey"], row["vpn_address"], row["wg_psk"])
            restored += 1
        except Exception as e:
            log.warning(f"Failed to restore peer {row['vpn_address']}: {e}")

    log.info(f"Restored {restored}/{len(rows)} WireGuard peers from database")

def reset_peer_status_on_startup() -> None:
    """Mark all peers as offline on startup so stale last_seen values don't
    cause false 'online' status. Peers will re-register/heartbeat to come back."""
    with get_db() as conn:
        updated = conn.execute(
            "UPDATE peers SET status = 'offline' WHERE device_type = 'vault'"
        ).rowcount
    if updated:
        log.info(f"Reset {updated} vault peer(s) to offline — waiting for re-registration")

# ─── Key Rotation ────────────────────────────────────────────────────────────


def rotate_peer_psk(device_id: str, wg_pubkey: str, vpn_address: str) -> bool:
    """Perform a fresh KEM encap/decap cycle and update a single peer's PSK."""
    if oqs is None:
        log.error("liboqs not available — cannot rotate PSK")
        return False

    with get_db() as conn:
        vault = conn.execute(
            "SELECT * FROM peers WHERE device_type = 'vault' AND status = 'online'"
        ).fetchone()

    if not vault:
        log.error("No online vault — cannot rotate PSK")
        return False

    try:
        vault_public_key = base64.b64decode(vault["public_key"])
        kem = oqs.KeyEncapsulation(CONFIG["pqc"]["algorithm"])
        ciphertext, shared_secret = kem.encap_secret(vault_public_key)
        new_psk = base64.b64encode(shared_secret).decode()

        # Send ciphertext to Vault for decapsulation
        send_to_vault("kem_request", {
            "request_id": f"rotate-{device_id}-{int(time.time())}",
            "client_id": device_id,
            "ciphertext": base64.b64encode(ciphertext).decode(),
        })

        # Update WireGuard interface with new PSK
        add_wireguard_peer(wg_pubkey, vpn_address, new_psk)

        log.info(f"Rotated PSK for {device_id} ({vpn_address})")
        return True

    except Exception as e:
        log.error(f"PSK rotation failed for {device_id}: {e}")
        return False


def rotate_all_peers() -> dict:
    """Rotate PSKs for all connected client peers."""
    log.info("=" * 40)
    log.info("KEY ROTATION — Starting PSK rotation cycle")
    log.info("=" * 40)

    with get_db() as conn:
        clients = conn.execute(
            "SELECT device_id, wireguard_pubkey, vpn_address FROM peers "
            "WHERE device_type = 'client' AND wireguard_pubkey IS NOT NULL "
            "AND wireguard_pubkey != '' AND wireguard_pubkey != 'GENERATE_ME'"
        ).fetchall()

    if not clients:
        log.info("No clients to rotate")
        return {"rotated": 0, "failed": 0, "total": 0}

    rotated = 0
    failed = 0

    for client in clients:
        success = rotate_peer_psk(
            client["device_id"],
            client["wireguard_pubkey"],
            client["vpn_address"],
        )
        if success:
            rotated += 1
        else:
            failed += 1
        # Small delay between rotations to avoid overwhelming UART
        time.sleep(0.5)

    log.info(f"Rotation complete: {rotated} rotated, {failed} failed out of {len(clients)}")

    return {"rotated": rotated, "failed": failed, "total": len(clients)}


def request_vault_rekeygen() -> bool:
    """Ask the Vault to regenerate its ML-KEM keypair from fresh entropy."""
    log.info("Requesting Vault keypair regeneration...")
    return send_to_vault("regen_keys", {
        "reason": "scheduled_rotation",
        "timestamp": _now_iso(),
    })


def key_rotation_thread() -> None:
    """Background thread that rotates keys on the configured schedule."""
    rotation_hours = CONFIG["pqc"].get("key_rotation_hours", 0)
    if rotation_hours <= 0:
        log.info("Key rotation disabled (key_rotation_hours = 0)")
        return

    rotation_seconds = rotation_hours * 3600
    log.info(f"Key rotation enabled: every {rotation_hours} hours")

    # Wait for initial startup to complete before first rotation
    time.sleep(60)

    while True:
        try:
            # Step 1: Ask the Vault to regen its ML-KEM keypair
            rekeygen_sent = request_vault_rekeygen()
            if rekeygen_sent:
                # Give the Vault time to harvest entropy and generate new keys
                log.info("Waiting for Vault to regenerate keypair...")
                time.sleep(30)

            # Step 2: Rotate all peer PSKs using the (potentially new) public key
            result = rotate_all_peers()
            log.info(f"Rotation cycle result: {result}")

        except Exception as e:
            log.error(f"Key rotation cycle failed: {e}")

        time.sleep(rotation_seconds)


# ─── Vault UART Thread ──────────────────────────────────────────────────────

vault_uart = None
vault_lock = threading.Lock()
_vault_write_queue: queue.Queue = queue.Queue()


def vault_uart_thread() -> None:
    """
    Background thread that reads UART messages from the Vault.
    Handles: register, heartbeat, decap_result, regen_complete
    Also processes queued outbound messages to avoid UART contention.
    """
    global vault_uart

    uart_cfg = CONFIG["vault_uart"]
    if not uart_cfg.get("enabled") or serial is None:
        log.info("Vault UART link disabled")
        return

    device = uart_cfg["device"]
    baud = uart_cfg["baud_rate"]

    log.info(f"Opening Vault UART link on {device} at {baud} baud...")

    while True:
        try:
            vault_uart = serial.Serial(device, baud, timeout=0.5)
            log.info("Vault UART link established")

            # Request the Vault to re-register immediately so we get
            # a fresh public key and last_seen timestamp
            try:
                vault_uart.write(frame_message("ping", {}))
                vault_uart.flush()
                log.info("Sent ping to Vault — requesting re-registration")
            except Exception as e:
                log.warning(f"Failed to send initial ping to Vault: {e}")

            while True:
                # ── Drain write queue and track whether we sent a KEM ──
                sent_kem = False
                while not _vault_write_queue.empty():
                    try:
                        frame_data = _vault_write_queue.get_nowait()
                        vault_uart.write(frame_data)
                        vault_uart.flush()
                        # Peek at the frame to see if it's a kem_request
                        # so we can wait longer for the Vault's response
                        try:
                            payload = frame_data[3:-1]  # skip STX+len, strip ETX
                            if b'"kem_request"' in payload:
                                sent_kem = True
                        except Exception:
                            pass
                    except queue.Empty:
                        break
                    except Exception as e:
                        log.error(f"UART write from queue failed: {e}")

                # ── Read inbound messages ──
                # Short timeout (0.3s) for idle polling so the write
                # queue gets serviced promptly. After sending a
                # kem_request, extend to 5s so the Pi Zero has time
                # for AES-GCM decrypt + ML-KEM-1024 decap without
                # the thread looping back and blocking the response.
                read_timeout = 5.0 if sent_kem else 0.3
                message = read_frame(vault_uart, timeout=read_timeout)

                if message is None:
                    continue

                # Process this message, then drain any back-to-back
                # messages (e.g. two simultaneous client requests)
                while message is not None:
                    msg_type = message.get("type", "")
                    data = message.get("data", {})

                    if msg_type == "register":
                        _handle_vault_register(data)
                    elif msg_type == "heartbeat":
                        _handle_vault_heartbeat(data)
                    elif msg_type == "decap_result":
                        _handle_vault_decap_result(data)
                    elif msg_type == "regen_complete":
                        _handle_vault_regen_complete(data)
                    elif msg_type == "entropy_response":
                        pass  # Handled inline by request_entropy_from_vault()
                    else:
                        log.debug(f"Unknown UART message type: {msg_type}")

                    # Try to grab another queued message immediately
                    message = read_frame(vault_uart, timeout=0.1)

        except Exception as e:
            log.error(f"Vault UART error: {e} — reconnecting in 5s")
            if vault_uart:
                try:
                    vault_uart.close()
                except Exception:
                    pass
                vault_uart = None
            time.sleep(5)

def _handle_vault_register(data: dict) -> None:
    """Process a registration message from the Vault."""
    device_id = data["device_id"]

    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO peers
            (device_id, device_type, public_key, kem_algorithm, registered_at, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id, "vault", data["public_key"],
            data["kem_algorithm"], data["timestamp"],
            time.time(), "online",
        ))

    log.info(f"Vault registered: {device_id}")

    # Send ACK — we're already on the UART thread, write directly
    if vault_uart:
        vault_uart.write(frame_message("ack", {"status": "registered"}))
        vault_uart.flush()

def _handle_vault_heartbeat(data: dict) -> None:
    """Update the Vault's last-seen timestamp."""
    with get_db() as conn:
        conn.execute(
            "UPDATE peers SET last_seen = ?, status = 'online' WHERE device_id = ?",
            (time.time(), data["device_id"]),
        )


def _handle_vault_decap_result(data: dict) -> None:
    """Process a decapsulation result from the Vault."""
    request_id = data["request_id"]

    with get_db() as conn:
        conn.execute("""
            UPDATE handshakes SET status = ?, completed_at = ?
            WHERE request_id = ?
        """, (data["status"], datetime.now(timezone.utc).isoformat(), request_id))

    # If the Vault returned a shared secret (client-encap flow), store it
    # so the API endpoint can pick it up
    psk = data.get("quantum_psk", "")
    if psk:
        _store_pending_psk(request_id, psk)
        log.info(f"Handshake {request_id}: PSK received from Vault")
    else:
        log.info(f"Handshake {request_id}: {data['status']}")


def _handle_vault_regen_complete(data: dict) -> None:
    """Process a keypair regeneration result from the Vault."""
    device_id = data.get("device_id", "")
    new_pubkey = data.get("public_key", "")

    if not new_pubkey:
        log.error("Vault regen_complete missing public_key")
        return

    with get_db() as conn:
        conn.execute(
            "UPDATE peers SET public_key = ?, last_seen = ? WHERE device_id = ?",
            (new_pubkey, time.time(), device_id),
        )

    log.info(f"Vault keypair regenerated — new public key stored for {device_id}")


def send_to_vault(msg_type: str, data: dict) -> bool:
    """Queue a framed message for the UART thread to send to the Vault."""
    try:
        _vault_write_queue.put(frame_message(msg_type, data))
        return True
    except Exception as e:
        log.error(f"Failed to queue message for Vault: {e}")
        return False

# ─── Pending PSK Store (for client-side encap) ──────────────────────────────
# When the Vault decapsulates and returns the shared secret, it lands here
# keyed by request_id. The API endpoint polls this dict to pick it up.

_pending_psks: dict[str, str] = {}
_pending_psks_lock = threading.Lock()

# In-memory tracker for candidate change detection (heartbeat diffing)
_candidate_versions: dict[str, str] = {}  # "request_id:side" → last known candidates JSON


def _store_pending_psk(request_id: str, psk: str) -> None:
    """Store a PSK returned by the Vault for pickup by the API handler."""
    with _pending_psks_lock:
        _pending_psks[request_id] = psk


def _wait_for_vault_psk(request_id: str, timeout: float = 30.0) -> str | None:
    """
    Block until the Vault's decap_result arrives with the shared secret,
    or timeout. Returns the base64-encoded PSK or None.
    Polls every 100ms for faster pickup when the Vault responds quickly.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        with _pending_psks_lock:
            psk = _pending_psks.pop(request_id, None)
            if psk is not None:
                elapsed = timeout - (deadline - time.time())
                log.info(f"Vault PSK received for {request_id} in {elapsed:.1f}s")
                return psk
        time.sleep(0.1)
    log.warning(f"Timed out waiting for Vault PSK for request {request_id} ({timeout:.0f}s)")
    return None

# ─── Peer KEM Relay Mailbox ─────────────────────────────────────────────────
# When two peers can't reach each other directly (different networks, NAT),
# they relay their KEM handshake messages through the Lighthouse API.
# The Lighthouse only sees opaque KEM public keys and ciphertexts — it cannot
# derive the shared secret. Messages expire after 120 seconds.

_kem_relay: dict[str, list[dict]] = {}   # device_id → [messages]
_kem_relay_lock = threading.Lock()
KEM_RELAY_TTL = 120  # seconds


def _kem_relay_store(target_device_id: str, message: dict) -> None:
    """Store a KEM relay message for a target device to pick up."""
    message["_stored_at"] = time.time()
    with _kem_relay_lock:
        if target_device_id not in _kem_relay:
            _kem_relay[target_device_id] = []
        _kem_relay[target_device_id].append(message)


def _kem_relay_fetch(device_id: str) -> list[dict]:
    """Fetch and remove all pending KEM relay messages for a device."""
    with _kem_relay_lock:
        messages = _kem_relay.pop(device_id, [])
    # Filter expired messages
    now = time.time()
    return [m for m in messages if now - m.get("_stored_at", 0) < KEM_RELAY_TTL]


def _kem_relay_cleanup() -> None:
    """Remove expired KEM relay messages. Called periodically."""
    now = time.time()
    with _kem_relay_lock:
        for device_id in list(_kem_relay.keys()):
            _kem_relay[device_id] = [
                m for m in _kem_relay[device_id]
                if now - m.get("_stored_at", 0) < KEM_RELAY_TTL
            ]
            if not _kem_relay[device_id]:
                del _kem_relay[device_id]

# ─── FastAPI App ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="The Lighthouse",
    description="Post-Quantum VPN Coordination Server",
    version="0.6.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Pydantic Models ────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    device_id: str
    device_type: str = Field(..., pattern="^(vault|client)$")
    public_key: str
    kem_algorithm: str = "ML-KEM-1024"
    ip_address: Optional[str] = None
    lan_ip: Optional[str] = None
    public_ip: Optional[str] = None
    wireguard_public_key: Optional[str] = None
    timestamp: str = ""
    # Phase 5B: IPv6 deterministic identity
    ipv6_token: Optional[str] = None
    ipv6_prefix: Optional[str] = None
    ipv6_token_addr: Optional[str] = None

class HeartbeatRequest(BaseModel):
    device_id: str
    ip_address: Optional[str] = None
    lan_ip: Optional[str] = None
    public_ip: Optional[str] = None
    timestamp: str = ""
    # Phase 4 M3: fresh NAT data every heartbeat
    stun_endpoint: Optional[str] = None
    nat_type: Optional[str] = None
    # Phase 5B: IPv6 deterministic identity
    ipv6_token: Optional[str] = None
    ipv6_prefix: Optional[str] = None
    ipv6_token_addr: Optional[str] = None

class HandshakeInitRequest(BaseModel):
    client_device_id: str
    target_device_id: str

class ClientEncapHandshakeRequest(BaseModel):
    """v0.5.0 — Client performs encapsulation and sends ciphertext."""
    client_device_id: str
    target_device_id: str
    ciphertext: str  # base64-encoded KEM ciphertext from client's encap_secret()
    kem_algorithm: str = "ML-KEM-1024"


class MeshHandshakeRequest(BaseModel):
    """v0.6.0 — Request a mesh tunnel between two clients."""
    initiator_device_id: str
    target_device_id: str
    initiator_wg_pubkey: str
    initiator_lan_ip: Optional[str] = None
    initiator_public_ip: Optional[str] = None
    initiator_wg_listen_port: int = 51821
    # Phase 1: multi-candidate NAT traversal
    initiator_candidates: Optional[str] = None  # JSON-encoded candidate list
    initiator_nat_type: Optional[str] = None


class MeshAcceptRequest(BaseModel):
    """v0.6.0 — Accept a pending mesh tunnel and provide WG info."""
    request_id: str
    acceptor_device_id: str
    acceptor_wg_pubkey: str
    acceptor_lan_ip: Optional[str] = None
    acceptor_public_ip: Optional[str] = None
    acceptor_wg_listen_port: int = 51821
    # Phase 1: multi-candidate NAT traversal
    acceptor_candidates: Optional[str] = None  # JSON-encoded candidate list
    acceptor_nat_type: Optional[str] = None

class PeerKEMRelayMessage(BaseModel):
    """v0.9.0 — Relay a KEM handshake message between two peers via the Lighthouse.
    The Lighthouse only sees opaque public keys and ciphertext — it cannot derive
    the shared secret. Used when peers can't reach each other directly (NAT, etc)."""
    sender_device_id: str
    target_device_id: str
    msg_type: str       # "kem_hello", "kem_ciphertext", or "kem_confirm"
    payload: str        # base64-encoded JSON (public_key, ciphertext, etc.)

class MeshUpdateCandidatesRequest(BaseModel):
    """Phase 4 M4 — Push fresh candidate data for an existing active tunnel."""
    device_id: str
    request_id: str
    candidates: str        # JSON-encoded candidate list
    nat_type: Optional[str] = None

class EnrollRequest(BaseModel):
    """Node enrollment request — validates a one-time token."""
    token: str
    hostname: str = ""

# ─── Helper ──────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_alive(last_seen: float) -> bool:
    return (time.time() - last_seen) < CONFIG.get("peer_timeout", 120)

def _construct_peer_ipv6(peer_id: str) -> str | None:
    """Phase 5B LH3: Construct a peer's full IPv6 address from its token + prefix.
    Returns the constructed address or None if token/prefix data is missing."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT ipv6_token, ipv6_prefix, ipv6_token_addr FROM peers WHERE device_id = ?",
            (peer_id,),
        ).fetchone()

    if not row:
        return None

    # If we already have the full constructed address, return it directly
    if row["ipv6_token_addr"]:
        return row["ipv6_token_addr"]

    # Otherwise construct from prefix + token
    token = row["ipv6_token"]
    prefix = row["ipv6_prefix"]
    if not token or not prefix:
        return None

    # Combine: prefix (e.g. "2603:6000:9a01:bfe::") + token (e.g. "::c0de:1")
    # Strip the trailing :: from prefix and leading :: from token
    prefix_clean = prefix.rstrip(":")
    token_clean = token.lstrip(":")
    constructed = f"{prefix_clean}:{token_clean}" if token_clean else prefix_clean

    # Validate the constructed address
    try:
        import ipaddress
        addr = ipaddress.ip_address(constructed)
        if addr.is_global:
            log.debug(f"Constructed IPv6 for {peer_id}: {constructed}")
            return str(addr)
    except (ValueError, ImportError):
        pass

    return None

# ─── API Endpoints ───────────────────────────────────────────────────────────


@app.post("/api/v1/register")
async def register_device(req: RegisterRequest):
    """Register a remote client device."""
    try:
        base64.b64decode(req.public_key)
    except Exception:
        raise HTTPException(400, "Invalid base64 public key")

    # Verify this device was enrolled via a valid token
    with get_db() as conn:
        enrolled = conn.execute(
            "SELECT node_name FROM enrollment_tokens WHERE device_id = ? AND status = 'used'",
            (req.device_id,),
        ).fetchone()

    # Allow the vault to register without enrollment (hardware device on UART)
    if not enrolled and req.device_type != "vault":
        raise HTTPException(
            403,
            f"Device {req.device_id} is not enrolled. "
            f"Run 'python lighthouse.py add-node <n>' on the Lighthouse first."
        )

    # Check if this device already has a VPN address (and mesh address)
    with get_db() as conn:
        existing = conn.execute(
            "SELECT vpn_address, mesh_address FROM peers WHERE device_id = ?", (req.device_id,)
        ).fetchone()

    vpn_addr = existing["vpn_address"] if existing and existing["vpn_address"] else allocate_vpn_address()
    mesh_addr = existing["mesh_address"] if existing and existing["mesh_address"] else None

    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO peers
            (device_id, device_type, public_key, kem_algorithm, ip_address,
             lan_ip, public_ip, wireguard_pubkey, vpn_address, mesh_address,
             ipv6_token, ipv6_prefix, ipv6_token_addr,
             registered_at, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            req.device_id, req.device_type, req.public_key,
            req.kem_algorithm, req.ip_address, req.lan_ip, req.public_ip,
            req.wireguard_public_key,
            vpn_addr, mesh_addr,
            req.ipv6_token, req.ipv6_prefix, req.ipv6_token_addr,
            _now_iso(), time.time(), "online",
        ))

    log.info(f"Registered client: {req.device_id} → VPN {vpn_addr} (public: {req.public_ip or 'unknown'}"
             f", ipv6_token: {req.ipv6_token or 'none'})")

    # Clear any stale mesh tunnels involving this device (client restarted)
    try:
        with get_db() as conn:
            cleared = conn.execute(
                "DELETE FROM mesh_tunnels WHERE initiator_id = ? OR target_id = ?",
                (req.device_id, req.device_id),
            ).rowcount
            if cleared > 0:
                log.info(f"Cleared {cleared} stale mesh tunnel(s) for re-registering client {req.device_id}")
    except Exception:
        pass

    wg_pub = Path(CONFIG["wireguard"]["key_dir"]) / "server_public.key"
    server_pubkey = wg_pub.read_text().strip() if wg_pub.exists() else "NOT_GENERATED"

    # Include local endpoint info so client knows both options
    local_url = CONFIG.get("local_server_url", "")
    local_wg_endpoint = ""
    if local_url:
        local_host = local_url.split("://")[1].split(":")[0]
        local_wg_endpoint = f"{local_host}:{CONFIG['wireguard']['listen_port']}"

    return {
        "status": "registered",
        "device_id": req.device_id,
        "vpn_address": vpn_addr,
        "server_public_key": server_pubkey,
        "server_endpoint": f"{CONFIG['server_url'].split('://')[1].split(':')[0]}:{CONFIG['wireguard']['listen_port']}",
        "local_endpoint": local_wg_endpoint,
        "dns": CONFIG["wireguard"].get("dns", []),
        "discovery": CONFIG.get("discovery", {}),
    }

@app.post("/api/v1/enroll")
async def enroll_node(req: EnrollRequest):
    """
    Validate a one-time enrollment token and return the node's identity.
    Called once during first-time setup on a new device.
    Token must be used within 15 minutes of creation.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM enrollment_tokens WHERE token = ?", (req.token,)
        ).fetchone()

    if not row:
        raise HTTPException(403, "Invalid enrollment token")

    if row["status"] != "pending":
        raise HTTPException(
            409,
            f"Token already used by '{row['node_name']}' at {row['used_at']}"
        )

    # Check expiry
    if time.time() > row["expires_at"]:
        with get_db() as conn:
            conn.execute(
                "UPDATE enrollment_tokens SET status = 'expired' WHERE token = ?",
                (req.token,),
            )
        raise HTTPException(
            410,
            f"Token expired. Generate a new one with: "
            f"python lighthouse.py add-node {row['node_name']}"
        )

    # Generate a deterministic device_id from the node name
    node_name = row["node_name"]
    device_id = hashlib.sha256(f"cobra-{node_name}".encode()).hexdigest()[:16]

    # Mark token as used
    with get_db() as conn:
        conn.execute(
            "UPDATE enrollment_tokens SET status = 'used', device_id = ?, "
            "used_at = ?, used_by_ip = ? WHERE token = ?",
            (device_id, _now_iso(), req.hostname, req.token),
        )

    # Get the cert fingerprint so the client can pin it
    tls_cfg = CONFIG.get("tls", {})
    fingerprint = tls_cfg.get("cert_fingerprint", "")
    if not fingerprint:
        cert_path = tls_cfg.get("cert_file", "")
        if cert_path and Path(cert_path).exists():
            fingerprint = get_cert_fingerprint(cert_path)

    log.info(f"Node enrolled: {node_name} -> device_id {device_id}")

    return {
        "status": "enrolled",
        "device_id": device_id,
        "node_name": node_name,
        "cert_fingerprint": fingerprint,
        "lighthouse_public": CONFIG.get("server_url", ""),
        "lighthouse_local": CONFIG.get("local_server_url", ""),
    }

@app.post("/api/v1/heartbeat")
async def heartbeat(req: HeartbeatRequest):
    # Perform database updates and queries first
    with get_db() as conn:
        result = conn.execute(
            "UPDATE peers SET last_seen = ?, ip_address = ?, lan_ip = COALESCE(?, lan_ip), "
            "public_ip = COALESCE(?, public_ip), "
            "stun_endpoint = COALESCE(?, stun_endpoint), "
            "nat_type = COALESCE(?, nat_type), "
            "ipv6_token = COALESCE(?, ipv6_token), "
            "ipv6_prefix = COALESCE(?, ipv6_prefix), "
            "ipv6_token_addr = COALESCE(?, ipv6_token_addr), "
            "status = 'online' WHERE device_id = ?",
            (time.time(), req.ip_address, req.lan_ip, req.public_ip,
             req.stun_endpoint, req.nat_type,
             req.ipv6_token, req.ipv6_prefix, req.ipv6_token_addr,
             req.device_id),
        )
        if result.rowcount == 0:
            raise HTTPException(404, "Device not registered")

        # Check for pending mesh tunnel requests targeting this device
        pending_mesh = conn.execute(
            "SELECT COUNT(*) FROM mesh_tunnels WHERE target_id = ? AND status = 'pending'",
            (req.device_id,)
        ).fetchone()[0]

        # Check if any mesh peer has pushed fresh candidates since our last heartbeat
        # This tells the client "your peer moved networks, re-punch NOW"
        peer_candidates_updated = False
        active_tunnels = conn.execute(
            "SELECT request_id, initiator_id, target_id, "
            "initiator_candidates, target_candidates FROM mesh_tunnels "
            "WHERE status = 'active' AND (initiator_id = ? OR target_id = ?)",
            (req.device_id, req.device_id),
        ).fetchall()

        for tunnel in active_tunnels:
            # Check if the OTHER peer's candidates were updated recently
            # We piggyback on the candidates_updated_at column if it exists,
            # otherwise we use a simple in-memory tracker
            peer_side = "target" if tunnel["initiator_id"] == req.device_id else "initiator"
            tunnel_key = f"{tunnel['request_id']}:{peer_side}"
            last_known = _candidate_versions.get(tunnel_key, "")
            current = tunnel[f"{peer_side}_candidates"] or ""
            if current and current != last_known:
                _candidate_versions[tunnel_key] = current
                if last_known:  # Only flag if there WAS a previous version (not first sync)
                    peer_candidates_updated = True

    # DEDENTED: The 'with' block is closed, and the database lock is released.
    # Now it is safe to call cleanup functions that open their own connections.
    try:
        _cleanup_stale_mesh_tunnels()
        _kem_relay_cleanup()
    except Exception as e:
        log.error(f"Heartbeat cleanup failed: {e}")
        pass

    return {
        "status": "ok",
        "pending_mesh_requests": pending_mesh,
        "peer_candidates_updated": peer_candidates_updated,
    }

@app.get("/api/v1/peers")
async def list_peers():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM peers").fetchall()

    peers = []
    for row in rows:
        status = "online" if _is_alive(row["last_seen"] or 0) else "offline"
        peers.append({
            "device_id": row["device_id"],
            "device_type": row["device_type"],
            "vpn_address": row["vpn_address"],
            "status": status,
            "kem_algorithm": row["kem_algorithm"],
        })
    return {"peers": peers, "count": len(peers)}

@app.get("/api/v1/discovery/config")
async def discovery_config():
    """Return discovery settings and online peer info for LAN discovery."""
    disc = CONFIG.get("discovery", {})
    local_url = CONFIG.get("local_server_url", "")

    with get_db() as conn:
        rows = conn.execute(
            "SELECT device_id, device_type, vpn_address, lan_ip, ip_address, wireguard_pubkey "
            "FROM peers WHERE last_seen > ?",
            (time.time() - CONFIG.get("peer_timeout", 120),)
        ).fetchall()

    peers = []
    for row in rows:
        peers.append({
            "device_id": row["device_id"],
            "device_type": row["device_type"],
            "vpn_address": row["vpn_address"],
            "lan_ip": row["lan_ip"],
            "ip_address": row["ip_address"],
        })

    local_host = ""
    if local_url:
        local_host = local_url.split("://")[1].split(":")[0]

    return {
        "discovery_enabled": disc.get("enabled", False),
        "broadcast_port": disc.get("broadcast_port", 5391),
        "broadcast_interval": disc.get("broadcast_interval", 30),
        "server_lan_ip": local_host,
        "server_wg_port": CONFIG["wireguard"]["listen_port"],
        "online_peers": peers,
    }

@app.get("/api/v1/vault/public-key")
async def get_vault_public_key():
    """
    Return the Vault's ML-KEM-1024 public key so clients can perform
    encapsulation locally. The Lighthouse never sees the shared secret.
    """
    with get_db() as conn:
        vault = conn.execute(
            "SELECT device_id, public_key, kem_algorithm, last_seen "
            "FROM peers WHERE device_type = 'vault'"
        ).fetchone()

    if not vault:
        raise HTTPException(404, "No vault registered")
    if not _is_alive(vault["last_seen"] or 0):
        raise HTTPException(503, "Vault is offline")

    return {
        "device_id": vault["device_id"],
        "public_key": vault["public_key"],
        "kem_algorithm": vault["kem_algorithm"] or CONFIG["pqc"]["algorithm"],
    }


@app.post("/api/v1/handshake/client-encap")
async def client_encap_handshake(req: ClientEncapHandshakeRequest):
    """
    v0.5.0 — Client-side encapsulation handshake.

    The client has already run encap_secret() locally and sends the ciphertext.
    The Lighthouse forwards ciphertext to the Vault over UART for decapsulation.
    The Vault returns the shared secret over UART so WireGuard can be configured.
    The Lighthouse NEVER performs encapsulation — it cannot fabricate a PSK.
    """
    with get_db() as conn:
        client = conn.execute(
            "SELECT * FROM peers WHERE device_id = ?", (req.client_device_id,)
        ).fetchone()
        vault = conn.execute(
            "SELECT * FROM peers WHERE device_id = ?", (req.target_device_id,)
        ).fetchone()

    if not client:
        raise HTTPException(404, "Client not registered")
    if not vault:
        raise HTTPException(404, "Vault not registered")
    if vault["device_type"] != "vault":
        raise HTTPException(400, "Target must be a vault")
    if not _is_alive(vault["last_seen"] or 0):
        raise HTTPException(503, "Vault is offline")

    request_id = uuid.uuid4().hex[:12]

    # Store handshake record (no quantum_psk yet — Vault will provide it)
    with get_db() as conn:
        conn.execute("""
            INSERT INTO handshakes
            (request_id, client_device_id, vault_device_id, status, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (request_id, req.client_device_id, req.target_device_id,
              "forwarding", _now_iso()))

    # Forward ciphertext to Vault over UART for decapsulation
    send_to_vault("kem_request", {
        "request_id": request_id,
        "client_id": req.client_device_id,
        "ciphertext": req.ciphertext,
    })

    # Wait for the Vault to return the shared secret via UART
    psk = _wait_for_vault_psk(request_id, timeout=30.0)

    if not psk:
        raise HTTPException(504, "Vault did not respond with decapsulated secret in time")

    # Configure WireGuard with the PSK the Vault derived
    if client["wireguard_pubkey"] and client["vpn_address"]:
        try:
            add_wireguard_peer(client["wireguard_pubkey"], client["vpn_address"], psk)
        except Exception as e:
            log.error(f"Failed to add WG peer: {e}")

    # Update handshake record
    with get_db() as conn:
        conn.execute("""
            UPDATE handshakes SET status = ?, quantum_psk = ?, completed_at = ?
            WHERE request_id = ?
        """, ("complete", psk, _now_iso(), request_id))

    log.info(f"Client-encap handshake complete: {req.client_device_id} → {req.target_device_id}")

    wg = CONFIG["wireguard"]
    wg_pub = Path(wg["key_dir"]) / "server_public.key"
    server_pubkey = wg_pub.read_text().strip() if wg_pub.exists() else ""

    return {
        "request_id": request_id,
        "status": "complete",
        "vpn_address": client["vpn_address"],
        "server_public_key": server_pubkey,
        "server_endpoint": f"{CONFIG['server_url'].split('://')[1].split(':')[0]}:{wg['listen_port']}",
        "dns": wg.get("dns", []),
        "allowed_ips": "0.0.0.0/0, ::/0" if wg.get("exit_node") else client["vpn_address"] + "/32",
    }

@app.post("/api/v1/handshake/initiate")
async def initiate_handshake(req: HandshakeInitRequest):
    """
    Client requests a KEM handshake with the Vault.
    Lighthouse encapsulates against Vault's public key,
    sends ciphertext to Vault over UART for decapsulation,
    returns the shared secret (quantum PSK) to the client.
    """
    with get_db() as conn:
        client = conn.execute(
            "SELECT * FROM peers WHERE device_id = ?", (req.client_device_id,)
        ).fetchone()
        vault = conn.execute(
            "SELECT * FROM peers WHERE device_id = ?", (req.target_device_id,)
        ).fetchone()

    if not client:
        raise HTTPException(404, "Client not registered")
    if not vault:
        raise HTTPException(404, "Vault not registered")
    if vault["device_type"] != "vault":
        raise HTTPException(400, "Target must be a vault")
    if not _is_alive(vault["last_seen"] or 0):
        raise HTTPException(503, "Vault is offline")
    if oqs is None:
        raise HTTPException(500, "liboqs not available")

    vault_public_key = base64.b64decode(vault["public_key"])
    kem = oqs.KeyEncapsulation(CONFIG["pqc"]["algorithm"])
    ciphertext, shared_secret = kem.encap_secret(vault_public_key)

    request_id = uuid.uuid4().hex[:12]
    psk = base64.b64encode(shared_secret).decode()

    with get_db() as conn:
        conn.execute("""
            INSERT INTO handshakes
            (request_id, client_device_id, vault_device_id, status, quantum_psk, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (request_id, req.client_device_id, req.target_device_id,
              "encapsulated", psk, _now_iso()))

    # Send ciphertext to Vault over UART for decapsulation
    send_to_vault("kem_request", {
        "request_id": request_id,
        "client_id": req.client_device_id,
        "ciphertext": base64.b64encode(ciphertext).decode(),
    })

    # If client provided a WG pubkey, add them as a WireGuard peer
    if client["wireguard_pubkey"] and client["vpn_address"]:
        try:
            add_wireguard_peer(client["wireguard_pubkey"], client["vpn_address"], psk)
        except Exception as e:
            log.error(f"Failed to add WG peer: {e}")

    log.info(f"Handshake initiated: {req.client_device_id} → {req.target_device_id}")

    wg = CONFIG["wireguard"]
    wg_pub = Path(wg["key_dir"]) / "server_public.key"
    server_pubkey = wg_pub.read_text().strip() if wg_pub.exists() else ""

    return {
        "request_id": request_id,
        "status": "encapsulated",
        "quantum_psk": psk,
        "vpn_address": client["vpn_address"],
        "server_public_key": server_pubkey,
        "server_endpoint": f"{CONFIG['server_url'].split('://')[1].split(':')[0]}:{wg['listen_port']}",
        "dns": wg.get("dns", []),
        "allowed_ips": "0.0.0.0/0, ::/0" if wg.get("exit_node") else client["vpn_address"] + "/32",
    }


@app.get("/api/v1/handshake/status/{request_id}")
async def handshake_status(request_id: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM handshakes WHERE request_id = ?", (request_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Handshake not found")
    return dict(row)


@app.get("/api/v1/health")
async def health():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0]
        online = conn.execute(
            "SELECT COUNT(*) FROM peers WHERE last_seen > ?",
            (time.time() - CONFIG.get("peer_timeout", 120),)
        ).fetchone()[0]

    tls_cfg = CONFIG.get("tls", {})
    tls_enabled = tls_cfg.get("enabled", False)
    fingerprint = tls_cfg.get("cert_fingerprint", "")

    return {
        "status": "operational",
        "timestamp": _now_iso(),
        "peers_total": total,
        "peers_online": online,
        "vault_uart": "connected" if vault_uart else "disconnected",
        "wireguard": CONFIG["wireguard"]["interface"],
        "tls_enabled": tls_enabled,
        "cert_fingerprint": fingerprint if tls_enabled else "",
    }

@app.get("/api/v1/tls/fingerprint")
async def tls_fingerprint():
    """Return the TLS certificate fingerprint for client pinning."""
    tls_cfg = CONFIG.get("tls", {})
    if not tls_cfg.get("enabled"):
        raise HTTPException(404, "TLS not enabled")

    fingerprint = tls_cfg.get("cert_fingerprint", "")
    cert_path = tls_cfg.get("cert_file", "")

    if not fingerprint and Path(cert_path).exists():
        fingerprint = get_cert_fingerprint(cert_path)

    return {
        "fingerprint": fingerprint,
        "algorithm": "SHA-256",
        "usage": "Pass to client with: --cert-fingerprint <fingerprint>",
    }

@app.get("/api/v1/rotation/status")
async def rotation_status():
    """Check key rotation configuration and last rotation info."""
    rotation_hours = CONFIG["pqc"].get("key_rotation_hours", 0)

    with get_db() as conn:
        clients = conn.execute(
            "SELECT COUNT(*) FROM peers WHERE device_type = 'client' "
            "AND wireguard_pubkey IS NOT NULL AND wireguard_pubkey != '' "
            "AND wireguard_pubkey != 'GENERATE_ME'"
        ).fetchone()[0]
        vault = conn.execute(
            "SELECT device_id, last_seen FROM peers WHERE device_type = 'vault'"
        ).fetchone()

    return {
        "rotation_enabled": rotation_hours > 0,
        "rotation_interval_hours": rotation_hours,
        "eligible_clients": clients,
        "vault_status": "online" if vault and _is_alive(vault["last_seen"] or 0) else "offline",
        "pqc_algorithm": CONFIG["pqc"]["algorithm"],
    }


@app.post("/api/v1/rotation/trigger")
async def trigger_rotation():
    """Manually trigger a key rotation cycle."""
    if oqs is None:
        raise HTTPException(500, "liboqs not available")

    # Run rotation in background to avoid blocking the API
    def _do_rotation():
        request_vault_rekeygen()
        time.sleep(30)
        rotate_all_peers()

    t = threading.Thread(target=_do_rotation, daemon=True)
    t.start()

    return {"status": "rotation_triggered", "message": "Rotation cycle started in background"}

def _select_best_endpoint(candidates_json: str | None, fallback_endpoint: str) -> str:
    """
    Pick the best single endpoint from a JSON candidate list.
    Priority: ipv6_token > IPv6 > UPnP > STUN full_cone/restricted > any STUN > public > LAN > VPN-routed > fallback.
    """
    if not candidates_json:
        return fallback_endpoint

    try:
        candidates = json.loads(candidates_json) if isinstance(candidates_json, str) else candidates_json
    except (json.JSONDecodeError, TypeError):
        return fallback_endpoint

    if not candidates:
        return fallback_endpoint

    # Sort by priority field
    candidates.sort(key=lambda c: c.get("priority", 999))

    # 0. IPv6 token candidate (Phase 5B — deterministic, highest priority)
    for c in candidates:
        if c.get("type") == "ipv6_token":
            log.info(f"  Best endpoint: IPv6 token {c['endpoint']} (deterministic, no NAT)")
            return c["endpoint"]

    # 1. IPv6 candidate (Phase 3 — no NAT involved, direct connection)
    for c in candidates:
        if c.get("type") == "ipv6":
            log.info(f"  Best endpoint: IPv6 {c['endpoint']} (no NAT)")
            return c["endpoint"]

    # 2. UPnP candidate (guaranteed open port — highest IPv4 priority)
    for c in candidates:
        if c.get("type") == "upnp":
            log.info(f"  Best endpoint: UPnP {c['endpoint']}")
            return c["endpoint"]

    # 3. STUN candidate with easy NAT type
    for c in candidates:
        if c.get("type") == "stun" and c.get("nat_type") in ("full_cone", "restricted"):
            log.info(f"  Best endpoint: STUN {c['endpoint']} (NAT: {c['nat_type']})")
            return c["endpoint"]

    # 4. Any STUN candidate
    for c in candidates:
        if c.get("type") == "stun":
            log.info(f"  Best endpoint: STUN {c['endpoint']}")
            return c["endpoint"]

    # 5. Raw public IP candidate
    for c in candidates:
        if c.get("type") == "public":
            log.info(f"  Best endpoint: public {c['endpoint']}")
            return c["endpoint"]

    # 6. LAN candidate
    for c in candidates:
        if c.get("type") == "lan":
            log.info(f"  Best endpoint: LAN {c['endpoint']}")
            return c["endpoint"]

    # 7. VPN-routed candidate (through Lighthouse tunnel — guaranteed to work)
    for c in candidates:
        if c.get("type") == "vpn_routed":
            log.info(f"  Best endpoint: VPN-routed {c['endpoint']} (via Lighthouse tunnel)")
            return c["endpoint"]

    # 8. Fallback
    log.info(f"  Best endpoint: fallback {fallback_endpoint}")
    return fallback_endpoint

def _compute_nat_pairing(
    initiator_nat_type: str | None,
    target_nat_type: str | None,
    initiator_candidates_json: str | None,
    target_candidates_json: str | None,
) -> dict:
    """
    Phase 2 B7: Smart NAT pairing logic.
    Considers BOTH peers' NAT types together to pick optimal endpoints
    and estimate connection confidence.

    Returns:
        {
            "initiator_endpoint": str,
            "target_endpoint": str,
            "confidence": "high" | "medium" | "low",
            "strategy": str,  # human-readable description
        }
    """
    def _parse_candidates(cj):
        if not cj:
            return []
        try:
            return json.loads(cj) if isinstance(cj, str) else cj
        except (json.JSONDecodeError, TypeError):
            return []

    init_candidates = _parse_candidates(initiator_candidates_json)
    tgt_candidates = _parse_candidates(target_candidates_json)

    init_nat = (initiator_nat_type or "unknown").lower()
    tgt_nat = (target_nat_type or "unknown").lower()

    # Helper: extract candidates by type
    def _by_type(candidates, ctype):
        return [c for c in candidates if c.get("type") == ctype]

    def _best_of_type(candidates, ctype):
        matches = _by_type(candidates, ctype)
        if matches:
            matches.sort(key=lambda c: c.get("priority", 999))
            return matches[0].get("endpoint", "")
        return ""

    # ── B7d: LAN subnet match ──────────────────────────────────────────
    init_lan = _by_type(init_candidates, "lan")
    tgt_lan = _by_type(tgt_candidates, "lan")
    if init_lan and tgt_lan:
        init_lan_ip = init_lan[0]["endpoint"].split(":")[0]
        tgt_lan_ip = tgt_lan[0]["endpoint"].split(":")[0]
        init_prefix = ".".join(init_lan_ip.split(".")[:3])
        tgt_prefix = ".".join(tgt_lan_ip.split(".")[:3])
        if init_prefix == tgt_prefix:
            log.info(f"  NAT pairing: SAME LAN ({init_prefix}.x) — direct connection")
            return {
                "initiator_endpoint": init_lan[0]["endpoint"],
                "target_endpoint": tgt_lan[0]["endpoint"],
                "confidence": "high",
                "strategy": "same_lan",
            }

    # ── V1.5: Token IPv6 match (Phase 5B) ────────────────────────────
    #    When both peers have deterministic IPv6 tokens, this is highest
    #    priority after same_lan — predictable addresses, no NAT at all.
    init_token_ipv6 = _best_of_type(init_candidates, "ipv6_token")
    tgt_token_ipv6 = _best_of_type(tgt_candidates, "ipv6_token")
    if init_token_ipv6 and tgt_token_ipv6:
        log.info(f"  NAT pairing: Both have token IPv6 — deterministic direct connection")
        return {
            "initiator_endpoint": init_token_ipv6,
            "target_endpoint": tgt_token_ipv6,
            "confidence": "high",
            "strategy": "token_ipv6",
        }

    # ── V2: IPv6 match (Phase 3) ──────────────────────────────────────
    #    When both peers have public IPv6, no NAT is involved at all.
    #    This is the cleanest possible connection — direct, no hole punching.
    init_ipv6 = _best_of_type(init_candidates, "ipv6")
    tgt_ipv6 = _best_of_type(tgt_candidates, "ipv6")
    if init_ipv6 and tgt_ipv6:
        log.info(f"  NAT pairing: Both have IPv6 — direct connection, no NAT")
        return {
            "initiator_endpoint": init_ipv6,
            "target_endpoint": tgt_ipv6,
            "confidence": "high",
            "strategy": "both_ipv6",
        }

    # ── Check for UPnP candidates (Phase 2 U5) ────────────────────────
    init_upnp = _best_of_type(init_candidates, "upnp")
    tgt_upnp = _best_of_type(tgt_candidates, "upnp")

    # If either side has UPnP, it's a guaranteed open port
    if init_upnp and tgt_upnp:
        log.info(f"  NAT pairing: Both have UPnP — high confidence")
        return {
            "initiator_endpoint": init_upnp,
            "target_endpoint": tgt_upnp,
            "confidence": "high",
            "strategy": "both_upnp",
        }

    easy_nat_types = {"full_cone", "restricted"}

    # ── B7a: Both easy NAT ─────────────────────────────────────────────
    if init_nat in easy_nat_types and tgt_nat in easy_nat_types:
        init_ep = init_upnp or _best_of_type(init_candidates, "stun") or _best_of_type(init_candidates, "public")
        tgt_ep = tgt_upnp or _best_of_type(tgt_candidates, "stun") or _best_of_type(tgt_candidates, "public")
        if init_ep and tgt_ep:
            log.info(f"  NAT pairing: Both easy NAT ({init_nat} + {tgt_nat}) — high confidence")
            return {
                "initiator_endpoint": init_ep,
                "target_endpoint": tgt_ep,
                "confidence": "high",
                "strategy": "both_easy_nat",
            }

    # ── B7b: One easy, one symmetric ───────────────────────────────────
    symmetric_types = {"symmetric_predictable", "symmetric_random"}

    if init_nat in easy_nat_types and tgt_nat in symmetric_types:
        init_ep = init_upnp or _best_of_type(init_candidates, "stun") or _best_of_type(init_candidates, "public")
        # For symmetric side: prefer UPnP (bypasses symmetric NAT), then predicted ports, then VPN-routed
        tgt_ep = tgt_upnp or _best_of_type(tgt_candidates, "stun") or _best_of_type(tgt_candidates, "predicted") or _best_of_type(tgt_candidates, "vpn_routed")
        if init_ep and tgt_ep:
            confidence = "high" if tgt_upnp else "medium"
            log.info(f"  NAT pairing: Asymmetric ({init_nat} + {tgt_nat}) — {confidence} confidence")
            return {
                "initiator_endpoint": init_ep,
                "target_endpoint": tgt_ep,
                "confidence": confidence,
                "strategy": "asymmetric_nat",
            }

    if tgt_nat in easy_nat_types and init_nat in symmetric_types:
        tgt_ep = tgt_upnp or _best_of_type(tgt_candidates, "stun") or _best_of_type(tgt_candidates, "public")
        init_ep = init_upnp or _best_of_type(init_candidates, "stun") or _best_of_type(init_candidates, "predicted") or _best_of_type(init_candidates, "vpn_routed")
        if init_ep and tgt_ep:
            confidence = "high" if init_upnp else "medium"
            log.info(f"  NAT pairing: Asymmetric ({init_nat} + {tgt_nat}) — {confidence} confidence")
            return {
                "initiator_endpoint": init_ep,
                "target_endpoint": tgt_ep,
                "confidence": confidence,
                "strategy": "asymmetric_nat",
            }

    # ── B7c: Both symmetric ────────────────────────────────────────────
    if init_nat in symmetric_types and tgt_nat in symmetric_types:
        init_ep = init_upnp or _best_of_type(init_candidates, "predicted") or _best_of_type(init_candidates, "vpn_routed") or _best_of_type(init_candidates, "stun")
        tgt_ep = tgt_upnp or _best_of_type(tgt_candidates, "predicted") or _best_of_type(tgt_candidates, "vpn_routed") or _best_of_type(tgt_candidates, "stun")
        if init_ep and tgt_ep:
            has_upnp = bool(init_upnp or tgt_upnp)
            confidence = "medium" if has_upnp else "low"
            log.info(f"  NAT pairing: Both symmetric — {confidence} confidence, recommend UPnP")
            return {
                "initiator_endpoint": init_ep,
                "target_endpoint": tgt_ep,
                "confidence": confidence,
                "strategy": "both_symmetric",
            }

    # ── Fallback: use old single-side logic ────────────────────────────
    log.info(f"  NAT pairing: Fallback (init={init_nat}, tgt={tgt_nat})")
    return {
        "initiator_endpoint": "",
        "target_endpoint": "",
        "confidence": "low",
        "strategy": "fallback",
    }
# ─── Mesh Networking Endpoints (v0.6.0) ────────────────────────────────────


@app.post("/api/v1/mesh/request")
async def mesh_request(req: MeshHandshakeRequest):
    """
    v0.6.0 — Initiate a mesh tunnel between two clients.

    The initiator asks the Lighthouse to broker a direct peer-to-peer tunnel.
    The Lighthouse performs KEM encap against the Vault to generate a quantum PSK,
    then stores the tunnel metadata for both peers to pick up.
    """
    with get_db() as conn:
        initiator = conn.execute(
            "SELECT * FROM peers WHERE device_id = ?", (req.initiator_device_id,)
        ).fetchone()
        target = conn.execute(
            "SELECT * FROM peers WHERE device_id = ?", (req.target_device_id,)
        ).fetchone()

    if not initiator:
        raise HTTPException(404, "Initiator not registered")
    if not target:
        raise HTTPException(404, "Target peer not registered")
    if target["device_type"] != "client":
        raise HTTPException(400, "Mesh tunnels are between clients only")
    if not _is_alive(target["last_seen"] or 0):
        raise HTTPException(503, "Target peer is offline")

    # Check for existing active tunnel between these two peers
    with get_db() as conn:
        existing = conn.execute(
            "SELECT request_id FROM mesh_tunnels "
            "WHERE ((initiator_id = ? AND target_id = ?) OR (initiator_id = ? AND target_id = ?)) "
            "AND status IN ('pending', 'active')",
            (req.initiator_device_id, req.target_device_id,
             req.target_device_id, req.initiator_device_id),
        ).fetchone()

    if existing:
        raise HTTPException(409, f"Mesh tunnel already exists: {existing['request_id']}")

    request_id = f"mesh-{uuid.uuid4().hex[:12]}"

    # Generate a quantum PSK for this peer pair via the Vault
    psk = None
    with get_db() as conn:
        vault = conn.execute(
            "SELECT * FROM peers WHERE device_type = 'vault' AND status = 'online'"
        ).fetchone()

    if vault and oqs is not None:
        try:
            vault_public_key = base64.b64decode(vault["public_key"])
            kem = oqs.KeyEncapsulation(CONFIG["pqc"]["algorithm"])
            ciphertext, shared_secret = kem.encap_secret(vault_public_key)
            psk = base64.b64encode(shared_secret).decode()

            # Send ciphertext to Vault for decapsulation (keeps Vault in sync)
            send_to_vault("kem_request", {
                "request_id": request_id,
                "client_id": f"{req.initiator_device_id}<>{req.target_device_id}",
                "ciphertext": base64.b64encode(ciphertext).decode(),
            })

            log.info(f"Mesh PSK generated for {req.initiator_device_id} <> {req.target_device_id}")
        except Exception as e:
            log.error(f"Mesh PSK generation failed: {e}")
            raise HTTPException(500, "Failed to generate quantum PSK for mesh tunnel")
    else:
        raise HTTPException(503, "Vault offline or liboqs unavailable — cannot generate mesh PSK")

    # Allocate persistent mesh IPs — each device keeps the same IP across all tunnels
    initiator_mesh_ip = get_or_allocate_mesh_address(req.initiator_device_id)
    target_mesh_ip = get_or_allocate_mesh_address(req.target_device_id, exclude={initiator_mesh_ip})

    # Build endpoint for initiator based on network topology
    # Priority: LAN IP (same network) > public IP (cross-network) > VPN IP (fallback)
    initiator_lan_ip = req.initiator_lan_ip or initiator["lan_ip"] or ""
    initiator_public_ip = req.initiator_public_ip or (initiator["public_ip"] if "public_ip" in initiator.keys() else "") or ""
    target_lan_ip = target["lan_ip"] or ""

    # Check if both peers are on the same LAN
    same_lan = False
    if initiator_lan_ip and target_lan_ip:
        init_prefix = ".".join(initiator_lan_ip.split(".")[:3])
        tgt_prefix = ".".join(target_lan_ip.split(".")[:3])
        same_lan = (init_prefix == tgt_prefix)

    if same_lan and initiator_lan_ip:
        initiator_endpoint = f"{initiator_lan_ip}:{req.initiator_wg_listen_port}"
        log.info(f"  Mesh topology: SAME LAN (both on {init_prefix}.x)")
    elif initiator_public_ip:
        initiator_endpoint = f"{initiator_public_ip}:{req.initiator_wg_listen_port}"
        log.info(f"  Mesh topology: CROSS-NETWORK (initiator public IP: {initiator_public_ip})")
    elif initiator["vpn_address"]:
        # Last resort — VPN IP routed through the main WireGuard tunnel
        initiator_endpoint = f"{initiator['vpn_address']}:{req.initiator_wg_listen_port}"
        log.info(f"  Mesh topology: VPN-ROUTED (no public IP available)")
    elif initiator_lan_ip:
        initiator_endpoint = f"{initiator_lan_ip}:{req.initiator_wg_listen_port}"
    else:
        initiator_endpoint = ""

    # Phase 1: Use _select_best_endpoint if candidates provided
    if req.initiator_candidates:
        initiator_endpoint = _select_best_endpoint(req.initiator_candidates, initiator_endpoint)

    # Store the mesh tunnel record
    with get_db() as conn:
        conn.execute("""
            INSERT INTO mesh_tunnels
            (request_id, initiator_id, target_id, status,
             initiator_wg_pubkey, initiator_endpoint, initiator_wg_port,
             initiator_mesh_ip, target_mesh_ip,
             initiator_candidates, initiator_nat_type,
             quantum_psk, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_id, req.initiator_device_id, req.target_device_id,
            "pending", req.initiator_wg_pubkey, initiator_endpoint,
            req.initiator_wg_listen_port, initiator_mesh_ip, target_mesh_ip,
            req.initiator_candidates, req.initiator_nat_type,
            psk, _now_iso(),
        ))

    log.info(f"Mesh tunnel requested: {req.initiator_device_id} → {req.target_device_id} ({request_id})")
    log.info(f"  Mesh IPs: {initiator_mesh_ip} <> {target_mesh_ip}, endpoint: {initiator_endpoint or '(empty)'}")

    return {
        "request_id": request_id,
        "status": "pending",
        "message": "Waiting for target peer to accept",
    }

@app.post("/api/v1/mesh/accept")
async def mesh_accept(req: MeshAcceptRequest):
    """
    v0.6.0 — Target peer accepts a mesh tunnel request.

    Returns the full tunnel config to the acceptor (initiator's WG pubkey,
    endpoint, and the quantum PSK). The initiator picks up the acceptor's
    info via /mesh/status.
    """
    with get_db() as conn:
        tunnel = conn.execute(
            "SELECT * FROM mesh_tunnels WHERE request_id = ?", (req.request_id,)
        ).fetchone()

    if not tunnel:
        raise HTTPException(404, "Mesh tunnel request not found")
    if tunnel["target_id"] != req.acceptor_device_id:
        raise HTTPException(403, "You are not the target of this mesh request")
    if tunnel["status"] != "pending":
        raise HTTPException(409, f"Tunnel is already {tunnel['status']}")

    # Build acceptor endpoint
    with get_db() as conn:
        acceptor_peer = conn.execute(
            "SELECT lan_ip, public_ip, ip_address, vpn_address FROM peers WHERE device_id = ?",
            (req.acceptor_device_id,)
        ).fetchone()
        initiator_peer = conn.execute(
            "SELECT lan_ip, public_ip FROM peers WHERE device_id = ?",
            (tunnel["initiator_id"],)
        ).fetchone()

    acceptor_lan_ip = req.acceptor_lan_ip or (acceptor_peer["lan_ip"] if acceptor_peer else "")
    acceptor_public_ip = req.acceptor_public_ip or (acceptor_peer["public_ip"] if acceptor_peer and "public_ip" in acceptor_peer.keys() else "") or ""
    initiator_lan_ip = initiator_peer["lan_ip"] if initiator_peer else ""

    # Check if both peers are on the same LAN
    same_lan = False
    if acceptor_lan_ip and initiator_lan_ip:
        acc_prefix = ".".join(acceptor_lan_ip.split(".")[:3])
        init_prefix = ".".join(initiator_lan_ip.split(".")[:3])
        same_lan = (acc_prefix == init_prefix)

    if same_lan and acceptor_lan_ip:
        acceptor_endpoint = f"{acceptor_lan_ip}:{req.acceptor_wg_listen_port}"
    elif acceptor_public_ip:
        acceptor_endpoint = f"{acceptor_public_ip}:{req.acceptor_wg_listen_port}"
    elif acceptor_peer and acceptor_peer["vpn_address"]:
        acceptor_endpoint = f"{acceptor_peer['vpn_address']}:{req.acceptor_wg_listen_port}"
    elif acceptor_lan_ip:
        acceptor_endpoint = f"{acceptor_lan_ip}:{req.acceptor_wg_listen_port}"
    else:
        acceptor_endpoint = ""

    # Phase 2 B7: Smart NAT pairing — at accept time both peers' data is available
    pairing_confidence = None
    paired_initiator_endpoint = None
    if req.acceptor_candidates and tunnel["initiator_candidates"]:
        pairing = _compute_nat_pairing(
            tunnel["initiator_nat_type"], req.acceptor_nat_type,
            tunnel["initiator_candidates"], req.acceptor_candidates,
        )
        pairing_confidence = pairing["confidence"]

        # Use paired endpoints if the smart logic found them
        if pairing["target_endpoint"]:
            acceptor_endpoint = pairing["target_endpoint"]
        else:
            acceptor_endpoint = _select_best_endpoint(req.acceptor_candidates, acceptor_endpoint)

        # Also update initiator endpoint if pairing found a better one
        if pairing["initiator_endpoint"]:
            with get_db() as conn:
                conn.execute(
                    "UPDATE mesh_tunnels SET initiator_endpoint = ? WHERE request_id = ?",
                    (pairing["initiator_endpoint"], req.request_id),
                )
            # Track locally so the return dict uses the updated value
            paired_initiator_endpoint = pairing["initiator_endpoint"]

        log.info(f"  NAT pairing: strategy={pairing['strategy']}, confidence={pairing_confidence}")
    elif req.acceptor_candidates:
        # Fallback: Phase 1 single-side logic
        acceptor_endpoint = _select_best_endpoint(req.acceptor_candidates, acceptor_endpoint)

    # Update tunnel record with acceptor info + pairing confidence
    with get_db() as conn:
        conn.execute("""
            UPDATE mesh_tunnels SET
                status = 'active',
                target_wg_pubkey = ?,
                target_endpoint = ?,
                target_wg_port = ?,
                target_candidates = ?,
                target_nat_type = ?,
                pairing_confidence = ?,
                completed_at = ?
            WHERE request_id = ?
        """, (
            req.acceptor_wg_pubkey, acceptor_endpoint,
            req.acceptor_wg_listen_port,
            req.acceptor_candidates, req.acceptor_nat_type,
            pairing_confidence,
            _now_iso(), req.request_id,
        ))

    log.info(f"Mesh tunnel accepted: {tunnel['initiator_id']} <> {req.acceptor_device_id} ({req.request_id})")
    log.info(f"  Acceptor endpoint: {acceptor_endpoint or '(empty)'}")

    # Return the initiator's info + PSK to the acceptor
    return {
        "request_id": req.request_id,
        "status": "active",
        "peer_wg_pubkey": tunnel["initiator_wg_pubkey"],
        "peer_endpoint": paired_initiator_endpoint or tunnel["initiator_endpoint"],
        "peer_vpn_address": _get_peer_vpn_address(tunnel["initiator_id"]),
        "peer_mesh_ip": tunnel["initiator_mesh_ip"],
        "my_mesh_ip": tunnel["target_mesh_ip"],
        "quantum_psk": tunnel["quantum_psk"],
        "kem_algorithm": CONFIG["pqc"]["algorithm"],
        # Phase 1: send initiator's candidates to acceptor for hole punching
        "peer_candidates": tunnel["initiator_candidates"],
        # Phase 2: pairing confidence for repunch aggressiveness
        "pairing_confidence": pairing_confidence,
        # Phase 5B: constructed IPv6 for direct dialing
        "peer_constructed_ipv6": _construct_peer_ipv6(tunnel["initiator_id"]),
    }

@app.get("/api/v1/mesh/status/{request_id}")
async def mesh_status(request_id: str, device_id: str = None):
    """Check the status of a mesh tunnel and get peer info once accepted.
    Phase 4: If device_id is provided, return the OTHER side's candidates
    as peer_candidates (so both initiator and target get the right data).
    Phase 5B: Includes constructed IPv6 for direct dialing when available.
    """
    with get_db() as conn:
        tunnel = conn.execute(
            "SELECT * FROM mesh_tunnels WHERE request_id = ?", (request_id,)
        ).fetchone()

    if not tunnel:
        raise HTTPException(404, "Mesh tunnel not found")

    result = {
        "request_id": request_id,
        "status": tunnel["status"],
        "initiator_id": tunnel["initiator_id"],
        "target_id": tunnel["target_id"],
        "created_at": tunnel["created_at"],
    }

    # If active, include full tunnel config
    if tunnel["status"] == "active":
        # Phase 4: Determine which side is asking and return the OTHER side's data
        if device_id and device_id == tunnel["target_id"]:
            # Target is asking — return initiator's data
            result.update({
                "peer_wg_pubkey": tunnel["initiator_wg_pubkey"],
                "peer_endpoint": tunnel["initiator_endpoint"],
                "peer_vpn_address": _get_peer_vpn_address(tunnel["initiator_id"]),
                "peer_mesh_ip": tunnel["initiator_mesh_ip"],
                "my_mesh_ip": tunnel["target_mesh_ip"],
                "quantum_psk": tunnel["quantum_psk"],
                "completed_at": tunnel["completed_at"],
                "peer_candidates": tunnel["initiator_candidates"],
                "pairing_confidence": tunnel["pairing_confidence"],
            })
        else:
            # Initiator is asking (default, backward compatible) — return target's data
            result.update({
                "peer_wg_pubkey": tunnel["target_wg_pubkey"],
                "peer_endpoint": tunnel["target_endpoint"],
                "peer_vpn_address": _get_peer_vpn_address(tunnel["target_id"]),
                "peer_mesh_ip": tunnel["target_mesh_ip"],
                "my_mesh_ip": tunnel["initiator_mesh_ip"],
                "quantum_psk": tunnel["quantum_psk"],
                "completed_at": tunnel["completed_at"],
                "peer_candidates": tunnel["target_candidates"],
                "pairing_confidence": tunnel["pairing_confidence"],
            })

    # Phase 5B LH6: Include constructed IPv6 for direct dialing
    if tunnel["status"] == "active":
        if device_id and device_id == tunnel["target_id"]:
            peer_id_for_ipv6 = tunnel["initiator_id"]
        else:
            peer_id_for_ipv6 = tunnel["target_id"]
        constructed_ipv6 = _construct_peer_ipv6(peer_id_for_ipv6)
        if constructed_ipv6:
            result["peer_constructed_ipv6"] = constructed_ipv6

    return result

@app.get("/api/v1/mesh/pending/{device_id}")
async def mesh_pending(device_id: str):
    """Return all pending mesh tunnel requests targeting this device."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT request_id, initiator_id, created_at FROM mesh_tunnels "
            "WHERE target_id = ? AND status = 'pending'",
            (device_id,)
        ).fetchall()

    pending = []
    for row in rows:
        # Include initiator info so the target knows who's requesting
        with get_db() as conn:
            initiator = conn.execute(
                "SELECT vpn_address, lan_ip FROM peers WHERE device_id = ?",
                (row["initiator_id"],)
            ).fetchone()
        pending.append({
            "request_id": row["request_id"],
            "initiator_id": row["initiator_id"],
            "initiator_vpn_address": initiator["vpn_address"] if initiator else "",
            "initiator_lan_ip": initiator["lan_ip"] if initiator else "",
            "created_at": row["created_at"],
        })

    return {"pending": pending, "count": len(pending)}


@app.get("/api/v1/mesh/tunnels/{device_id}")
async def mesh_tunnels(device_id: str):
    """List all active mesh tunnels for a device."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM mesh_tunnels "
            "WHERE (initiator_id = ? OR target_id = ?) AND status = 'active'",
            (device_id, device_id),
        ).fetchall()

    tunnels = []
    for row in rows:
        peer_id = row["target_id"] if row["initiator_id"] == device_id else row["initiator_id"]
        my_mesh_ip = row["initiator_mesh_ip"] if row["initiator_id"] == device_id else row["target_mesh_ip"]
        peer_mesh_ip = row["target_mesh_ip"] if row["initiator_id"] == device_id else row["initiator_mesh_ip"]
        tunnels.append({
            "request_id": row["request_id"],
            "peer_id": peer_id,
            "peer_vpn_address": _get_peer_vpn_address(peer_id),
            "my_mesh_ip": my_mesh_ip,
            "peer_mesh_ip": peer_mesh_ip,
            "status": row["status"],
            "created_at": row["created_at"],
        })

    return {"tunnels": tunnels, "count": len(tunnels)}

@app.post("/api/v1/mesh/update-candidates")
async def mesh_update_candidates(req: MeshUpdateCandidatesRequest):
    """Phase 4 M4: Allow a client to push fresh candidate data for an existing
    active tunnel. The other peer picks up the new candidates on next status poll.
    """
    with get_db() as conn:
        tunnel = conn.execute(
            "SELECT * FROM mesh_tunnels WHERE request_id = ? AND status = 'active'",
            (req.request_id,),
        ).fetchone()

    if not tunnel:
        raise HTTPException(404, "Active mesh tunnel not found")

    # Determine which side this device is (initiator or target)
    if tunnel["initiator_id"] == req.device_id:
        col_candidates = "initiator_candidates"
        col_nat_type = "initiator_nat_type"
        col_endpoint = "initiator_endpoint"
    elif tunnel["target_id"] == req.device_id:
        col_candidates = "target_candidates"
        col_nat_type = "target_nat_type"
        col_endpoint = "target_endpoint"
    else:
        raise HTTPException(403, "You are not part of this mesh tunnel")

    # Pick the best endpoint from the fresh candidates
    new_endpoint = _select_best_endpoint(req.candidates, tunnel[col_endpoint] or "")

    with get_db() as conn:
        conn.execute(
            f"UPDATE mesh_tunnels SET {col_candidates} = ?, {col_nat_type} = ?, "
            f"{col_endpoint} = ? WHERE request_id = ?",
            (req.candidates, req.nat_type, new_endpoint, req.request_id),
        )

    log.info(
        f"Phase 4: Updated candidates for {req.device_id} in tunnel {req.request_id} "
        f"(new endpoint: {new_endpoint})"
    )

    return {
        "status": "ok",
        "updated_endpoint": new_endpoint,
    }

def _get_peer_vpn_address(device_id: str) -> str:
    """Look up a peer's VPN address."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT vpn_address FROM peers WHERE device_id = ?", (device_id,)
        ).fetchone()
    return row["vpn_address"] if row else ""

def _cleanup_stale_mesh_tunnels() -> None:
    """Remove mesh tunnels that have been pending too long or are between offline peers."""
    with get_db() as conn:
        # Expire pending requests older than 60 seconds
        cutoff = datetime.fromtimestamp(
            time.time() - 60, tz=timezone.utc
        ).isoformat()
        expired = conn.execute(
            "DELETE FROM mesh_tunnels WHERE status = 'pending' AND created_at < ?",
            (cutoff,)
        ).rowcount

        # Remove active tunnels where EITHER peer has been offline for over 2 minutes.
        # Previously required BOTH peers offline for 10 minutes, which left stale
        # records during testing when one peer restarted but the other was still
        # "online" from a recent heartbeat. 2 minutes = ~4 missed heartbeats,
        # enough to confirm a peer is genuinely gone.
        offline_cutoff = time.time() - 120
        stale = conn.execute("""
            DELETE FROM mesh_tunnels WHERE status = 'active' AND request_id IN (
                SELECT mt.request_id FROM mesh_tunnels mt
                LEFT JOIN peers p1 ON mt.initiator_id = p1.device_id
                LEFT JOIN peers p2 ON mt.target_id = p2.device_id
                WHERE mt.status = 'active'
                AND (p1.last_seen IS NULL OR p1.last_seen < ?
                     OR p2.last_seen IS NULL OR p2.last_seen < ?)
            )
        """, (offline_cutoff, offline_cutoff)).rowcount

        if expired > 0 or stale > 0:
            log.info(f"Mesh cleanup: {expired} expired pending, {stale} stale active tunnels removed")

# ─── Peer KEM Relay Endpoints (v0.9.0) ─────────────────────────────────────


@app.post("/api/v1/kem-relay/send")
async def kem_relay_send(req: PeerKEMRelayMessage):
    """
    v0.9.0 — Relay a KEM handshake message to another peer.

    Used when two peers can't reach each other directly (different networks,
    NAT, no port forwarding). The Lighthouse acts as a dumb relay — it stores
    the opaque message for the target peer to poll and pick up.

    Security: The Lighthouse only sees the KEM public key and ciphertext,
    which are useless without the corresponding private key. The shared secret
    is never transmitted and cannot be derived by the relay.
    """
    # Verify both peers are registered
    with get_db() as conn:
        sender = conn.execute(
            "SELECT device_id FROM peers WHERE device_id = ?",
            (req.sender_device_id,)
        ).fetchone()
        target = conn.execute(
            "SELECT device_id FROM peers WHERE device_id = ?",
            (req.target_device_id,)
        ).fetchone()

    if not sender:
        raise HTTPException(404, "Sender not registered")
    if not target:
        raise HTTPException(404, "Target not registered")

    if req.msg_type not in ("kem_hello", "kem_ciphertext", "kem_confirm"):
        raise HTTPException(400, f"Invalid KEM relay message type: {req.msg_type}")

    _kem_relay_store(req.target_device_id, {
        "sender_device_id": req.sender_device_id,
        "msg_type": req.msg_type,
        "payload": req.payload,
    })

    log.debug(f"KEM relay: {req.sender_device_id} → {req.target_device_id} ({req.msg_type})")

    return {"status": "relayed", "msg_type": req.msg_type}


@app.get("/api/v1/kem-relay/poll/{device_id}")
async def kem_relay_poll(device_id: str):
    """
    v0.9.0 — Poll for pending KEM relay messages.

    Returns all queued KEM messages for this device and removes them.
    Clients call this periodically when they have active mesh tunnels
    with remote peers that need KEM exchange.
    """
    # Clean up expired messages while we're here
    _kem_relay_cleanup()

    messages = _kem_relay_fetch(device_id)

    return {"messages": messages, "count": len(messages)}

@app.get("/")
async def root():
    return {
        "name": "The Lighthouse",
        "version": "0.9.0",
        "description": "Post-Quantum VPN Coordination Server — Remote KEM Relay",
    }

# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    import argparse
    import uvicorn
    import secrets

    parser = argparse.ArgumentParser(description="The Lighthouse")
    parser.add_argument(
        "command",
        choices=[
            "serve", "generate-cert", "show-fingerprint",
            "add-node", "list-nodes", "revoke-node",
        ],
    )
    parser.add_argument("--config", "-c", default="/etc/lighthouse/config.yaml")
    parser.add_argument(
        "node_name", nargs="?", default=None,
        help="Node name for add-node / revoke-node",
    )
    args = parser.parse_args()

    global CONFIG
    CONFIG = load_config(args.config)

    log_level = CONFIG["log"].get("level", "info").upper()
    logging.getLogger().setLevel(getattr(logging, log_level, logging.INFO))

    # ── add-node command ──
    if args.command == "add-node":
        if not args.node_name:
            print("Usage: python lighthouse.py add-node <node_name>")
            print("Example: python lighthouse.py add-node cobra3")
            sys.exit(1)

        node_name = args.node_name
        init_database(CONFIG["database"]["path"])

        # Check if already enrolled
        with get_db() as conn:
            existing = conn.execute(
                "SELECT * FROM enrollment_tokens WHERE node_name = ?",
                (node_name,),
            ).fetchone()

        if existing and existing["status"] == "used":
            print(f"\n  Node '{node_name}' is already enrolled "
                  f"(device_id: {existing['device_id']})")
            print(f"  To re-enroll: python lighthouse.py revoke-node {node_name}")
            sys.exit(1)

        # Generate a one-time token with 15-minute expiry
        token = secrets.token_urlsafe(32)
        now = time.time()
        expires_at = now + ENROLLMENT_TOKEN_TTL

        with get_db() as conn:
            conn.execute(
                "DELETE FROM enrollment_tokens "
                "WHERE node_name = ? AND status IN ('pending', 'expired')",
                (node_name,),
            )
            conn.execute(
                "INSERT INTO enrollment_tokens "
                "(token, node_name, created_at, expires_at, status) "
                "VALUES (?, ?, ?, ?, ?)",
                (token, node_name, now, expires_at, "pending"),
            )

        public_url = CONFIG.get("server_url", "https://<lighthouse-ip>:9443")
        mins = ENROLLMENT_TOKEN_TTL // 60

        print()
        print(f"  Node '{node_name}' authorized for enrollment")
        print(f"  Token expires in {mins} minutes")
        print()
        print(f"  Run this on the new device:")
        print()
        print(f"    python client.py enroll \\")
        print(f"      --token {token} \\")
        print(f"      --lighthouse-public {public_url}")
        print()
        print(f"  After enrollment, start the client with:")
        print()
        print(f"    python client.py service \\")
        print(f"      --lighthouse-public {public_url}")
        print()
        return

    # ── list-nodes command ──
    if args.command == "list-nodes":
        init_database(CONFIG["database"]["path"])

        with get_db() as conn:
            rows = conn.execute(
                "SELECT node_name, device_id, status, created_at, "
                "expires_at, used_at "
                "FROM enrollment_tokens ORDER BY created_at"
            ).fetchall()

        if not rows:
            print("\n  No nodes enrolled or pending.\n")
            return

        # Look up VPN and mesh addresses from the peers table
        peer_addrs = {}
        with get_db() as conn:
            for prow in conn.execute(
                "SELECT device_id, vpn_address, mesh_address FROM peers"
            ).fetchall():
                peer_addrs[prow["device_id"]] = {
                    "vpn": prow["vpn_address"] or "—",
                    "mesh": prow["mesh_address"] or "—",
                }

        now = time.time()
        print()
        print(f"  {'Name':<18} {'Status':<12} {'Device ID':<18} {'VPN IP':<16} {'Mesh IP':<16} {'Info'}")
        print(f"  {'─'*18} {'─'*12} {'─'*18} {'─'*16} {'─'*16} {'─'*30}")
        for row in rows:
            name = row["node_name"]
            status = row["status"]
            device_id = row["device_id"] or "—"

            addrs = peer_addrs.get(device_id, {"vpn": "—", "mesh": "—"})

            if status == "pending" and now > row["expires_at"]:
                status = "expired"

            if status == "used":
                icon = "●"
                info = f"enrolled {row['used_at'] or ''}"
            elif status == "pending":
                remaining = int(row["expires_at"] - now)
                mins = remaining // 60
                secs = remaining % 60
                icon = "○"
                info = f"token valid for {mins}m {secs}s"
            elif status == "expired":
                icon = "✗"
                info = "token expired"
            else:
                icon = "?"
                info = status

            print(f"  {icon} {name:<16} {status:<12} {device_id:<18} {addrs['vpn']:<16} {addrs['mesh']:<16} {info}")
        print()
        return

    # ── revoke-node command ──
    if args.command == "revoke-node":
        if not args.node_name:
            print("Usage: python lighthouse.py revoke-node <node_name>")
            sys.exit(1)

        node_name = args.node_name
        init_database(CONFIG["database"]["path"])

        with get_db() as conn:
            row = conn.execute(
                "SELECT device_id FROM enrollment_tokens WHERE node_name = ?",
                (node_name,),
            ).fetchone()

            if not row:
                print(f"\n  Node '{node_name}' not found.\n")
                sys.exit(1)

            device_id = row["device_id"]

            conn.execute(
                "DELETE FROM enrollment_tokens WHERE node_name = ?",
                (node_name,),
            )

            if device_id:
                conn.execute(
                    "DELETE FROM peers WHERE device_id = ?",
                    (device_id,),
                )
                conn.execute(
                    "DELETE FROM mesh_tunnels "
                    "WHERE initiator_id = ? OR target_id = ?",
                    (device_id, device_id),
                )

        print(f"\n  Node '{node_name}' revoked and removed from the network.")
        if device_id:
            print(f"  Device ID {device_id} cleared from peers and mesh tunnels.")
        print()
        return

    # ── generate-cert command ──
    if args.command == "generate-cert":
        log.info("=" * 60)
        log.info("THE LIGHTHOUSE — Post-Quantum-Cobra VPN Coordination Server v0.9.0")
        log.info("=" * 60)

        # Try to start UART so we can get ESP32 entropy
        uart_cfg = CONFIG.get("vault_uart", {})
        if uart_cfg.get("enabled") and serial is not None:
            try:
                global vault_uart
                vault_uart = serial.Serial(
                    uart_cfg["device"], uart_cfg["baud_rate"], timeout=0.5
                )
                log.info("Vault UART connected — will use ESP32 entropy")
                time.sleep(2)
            except Exception as e:
                log.warning(f"Could not open Vault UART: {e}")

        cert_path, fingerprint = generate_self_signed_cert(CONFIG)

        # Write fingerprint back to config file
        config_path = args.config
        try:
            import re
            config_text = Path(config_path).read_text()
            if 'cert_fingerprint: ""' in config_text:
                config_text = config_text.replace(
                    'cert_fingerprint: ""',
                    f'cert_fingerprint: "{fingerprint}"',
                )
            elif "cert_fingerprint:" in config_text:
                config_text = re.sub(
                    r'cert_fingerprint:\s*"[^"]*"',
                    f'cert_fingerprint: "{fingerprint}"',
                    config_text,
                )
            Path(config_path).write_text(config_text)
            log.info(f"Fingerprint written to {config_path}")
        except Exception as e:
            log.warning(f"Could not update config file: {e}")
            log.info(f"Manually set cert_fingerprint: \"{fingerprint}\" in {config_path}")

        if vault_uart:
            vault_uart.close()
        return

    # ── show-fingerprint command ──
    if args.command == "show-fingerprint":
        fp = display_cert_fingerprint(CONFIG)
        if fp:
            print(f"\nFingerprint: {fp}")
            print(f"\nClient usage:")
            print(f"  python client.py service --cert-fingerprint {fp} \\")
            print(f"    --lighthouse-public {CONFIG.get('server_url', '')} \\")
            print(f"    --lighthouse-local {CONFIG.get('local_server_url', '')}")
        else:
            print("No TLS certificate found. Run: python lighthouse.py generate-cert")
        return

    # ── serve command ──
    log.info("=" * 60)
    log.info("THE LIGHTHOUSE — Post-Quantum VPN Coordination Server v0.9.0")
    log.info("=" * 60)

    tls_cfg = CONFIG.get("tls", {})
    if tls_cfg.get("enabled"):
        cert_path = tls_cfg.get("cert_file", "")
        key_path = tls_cfg.get("key_file", "")

        if not Path(cert_path).exists() or not Path(key_path).exists():
            log.error("TLS enabled but cert/key files not found!")
            log.error(f"  cert: {cert_path} (exists: {Path(cert_path).exists()})")
            log.error(f"  key:  {key_path} (exists: {Path(key_path).exists()})")
            log.error("Generate with: python lighthouse.py generate-cert")
            sys.exit(1)

        fp = display_cert_fingerprint(CONFIG)
        if fp and not tls_cfg.get("cert_fingerprint"):
            CONFIG["tls"]["cert_fingerprint"] = fp
        log.info("TLS: ENABLED (HTTPS)")
    else:
        log.warning("TLS: DISABLED — API traffic is unencrypted!")
        log.warning("Enable TLS in config.yaml and run: python lighthouse.py generate-cert")

    init_database(CONFIG["database"]["path"])

    # Reset vault status so stale last_seen doesn't cause false positives
    reset_peer_status_on_startup()

    # Clean up stale mesh tunnels from previous runs
    try:
        _cleanup_stale_mesh_tunnels()
    except Exception:
        pass

    try:
        setup_wireguard()
    except Exception as e:
        log.error(f"WireGuard setup failed: {e}")
        log.info("Continuing without WireGuard — tunnel management disabled")

    uart_thread = threading.Thread(target=vault_uart_thread, daemon=True)
    uart_thread.start()

    rotation_thread = threading.Thread(target=key_rotation_thread, daemon=True)
    rotation_thread.start()

    ssl_kwargs = {}
    if tls_cfg.get("enabled"):
        ssl_kwargs["ssl_certfile"] = tls_cfg["cert_file"]
        ssl_kwargs["ssl_keyfile"] = tls_cfg["key_file"]

    uvicorn.run(
        app,
        host=CONFIG["listen_addr"],
        port=CONFIG["listen_port"],
        log_level=CONFIG["log"].get("level", "info"),
        **ssl_kwargs,
    )

if __name__ == "__main__":
    main()