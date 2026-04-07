"""
THE VAULT — Raspberry Pi Zero 2 W Key Manager Service

Reads hardware entropy from the ESP32 Tongue (USB serial),
generates ML-KEM-1024 (Kyber) key pairs, stores the private key,
and communicates with the Lighthouse (Pi 4) over GPIO UART.

Hardware wiring:
    ESP32-S3 USB  →  Pi Zero USB port (/dev/ttyACM0)
    Pi Zero GPIO14 (TX, pin 8)  →  Pi 4 GPIO15 (RX, pin 10)
    Pi Zero GPIO15 (RX, pin 10) →  Pi 4 GPIO14 (TX, pin 8)
    Pi Zero GND (pin 6)         →  Pi 4 GND (pin 6)

Dependencies:
    pip install pyserial liboqs-python cryptography
"""

import serial
import time
import os
import sys
import json
import hashlib
import base64
import logging
import struct
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

try:
    import oqs
except ImportError:
    print("FATAL: liboqs-python not installed. Run: pip install liboqs-python")
    sys.exit(1)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── Configuration ───────────────────────────────────────────────────────────

TONGUE_PORT = "/dev/ttyACM0"
TONGUE_BAUD = 115200
ENTROPY_TARGET = 4096

LIGHTHOUSE_PORT = "/dev/ttyAMA0"
LIGHTHOUSE_BAUD = 115200

KEM_ALGORITHM = "ML-KEM-1024"

VAULT_DIR = Path("/home/vault/.crypt_vault")
PRIVATE_KEY_PATH = VAULT_DIR / "vault_private.key"
PUBLIC_KEY_PATH = VAULT_DIR / "vault_public.key"
DEVICE_ID_PATH = VAULT_DIR / "device_id"

HEARTBEAT_INTERVAL = 30

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [VAULT] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("vault")

# ─── UART Frame Protocol ────────────────────────────────────────────────────
#
# Frame format:
#   [STX 0x02] [LENGTH 2 bytes big-endian] [JSON payload] [ETX 0x03]
#
# Vault → Lighthouse: register, heartbeat, decap_result
# Lighthouse → Vault:  kem_request, regen_keys, ack, ping

STX = 0x02
ETX = 0x03


def frame_message(msg_type: str, data: dict) -> bytes:
    """Build a framed UART message."""
    payload = json.dumps({"type": msg_type, "data": data}).encode()
    length = struct.pack(">H", len(payload))
    return bytes([STX]) + length + payload + bytes([ETX])


def read_frame(ser: serial.Serial, timeout: float = 5.0) -> dict | None:
    """Read a single framed message. Returns parsed dict or None."""
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
        log.warning(f"Frame too large: {payload_len} bytes, dropping")
        return None

    raw = ser.read(payload_len + 1)
    if len(raw) < payload_len + 1:
        return None

    payload = raw[:payload_len]
    etx = raw[payload_len]

    if etx != ETX:
        log.warning("Frame missing ETX marker, dropping")
        return None

    try:
        return json.loads(payload.decode())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        log.warning(f"Frame decode error: {e}")
        return None


# ─── Entropy Collection ──────────────────────────────────────────────────────


SYNC_BYTE = 0xAA


def collect_entropy(target_bytes: int = ENTROPY_TARGET) -> bytes:
    """Harvest framed entropy from the ESP32 Tongue over USB serial."""
    log.info(f"Connecting to Tongue on {TONGUE_PORT}...")

    with serial.Serial(TONGUE_PORT, TONGUE_BAUD, timeout=2) as ser:
        entropy_pool = bytearray()

        # Try to catch the start signal, but if the stream is already
        # running we'll detect sync bytes directly and proceed
        log.info("Waiting for entropy stream (or joining stream in progress)...")
        deadline = time.time() + 10
        stream_found = False

        while time.time() < deadline:
            byte = ser.read(1)
            if len(byte) == 0:
                continue

            # Check for start signal in text lines
            if byte[0] != SYNC_BYTE:
                # Accumulate text to check for status signals
                line = byte + ser.readline()
                if b"ENTROPY_STREAM_START" in line:
                    log.info("Caught ENTROPY_STREAM_START signal")
                    stream_found = True
                    break
            else:
                # Found a sync byte — stream is already running
                log.info("Stream already active — joining in progress")
                # Read and use this first frame
                length_bytes = ser.read(2)
                if len(length_bytes) == 2:
                    payload_len = struct.unpack(">H", length_bytes)[0]
                    if payload_len <= 1024:
                        payload = ser.read(payload_len)
                        if len(payload) == payload_len:
                            entropy_pool.extend(payload)
                stream_found = True
                break

        if not stream_found:
            raise TimeoutError("Tongue not detected — no signal or sync bytes within 10s")

        log.info(f"Harvesting {target_bytes} bytes of hardware entropy...")
        harvest_start = time.time()
        last_progress = -1

        while len(entropy_pool) < target_bytes:
            byte = ser.read(1)
            if len(byte) == 0:
                continue

            if byte[0] == SYNC_BYTE:
                # Entropy frame: read 2-byte length then payload
                length_bytes = ser.read(2)
                if len(length_bytes) < 2:
                    continue
                payload_len = struct.unpack(">H", length_bytes)[0]
                if payload_len > 1024:
                    continue
                payload = ser.read(payload_len)
                if len(payload) == payload_len:
                    entropy_pool.extend(payload)

                progress = int((len(entropy_pool) / target_bytes) * 100) // 10 * 10
                if progress != last_progress:
                    log.info(f"Entropy harvest: {progress}%")
                    last_progress = progress

            # Any other byte is part of a STATUS line — ignore it

        elapsed = time.time() - harvest_start
        entropy_pool = bytes(entropy_pool[:target_bytes])

        log.info(f"Harvest complete: {len(entropy_pool)} bytes in {elapsed:.2f}s")
        log.info(f"Throughput: {len(entropy_pool) / elapsed:.0f} bytes/sec")
        _log_entropy_quality(entropy_pool)
        return entropy_pool


def _log_entropy_quality(data: bytes) -> None:
    """Quick chi-squared smoke test on entropy quality."""
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    expected = len(data) / 256
    chi_squared = sum((c - expected) ** 2 / expected for c in byte_counts)
    log.info(f"Entropy chi-squared: {chi_squared:.1f}")
    if chi_squared < 150 or chi_squared > 350:
        log.warning("Entropy quality suspicious — outside expected range")


# ─── Key Management ──────────────────────────────────────────────────────────


def initialize_vault_directory() -> None:
    """Create the vault directory with locked-down permissions."""
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(VAULT_DIR, 0o700)
    log.info(f"Vault directory ready: {VAULT_DIR}")


def get_device_id() -> str:
    """Generate or retrieve a stable device ID."""
    if DEVICE_ID_PATH.exists():
        return DEVICE_ID_PATH.read_text().strip()

    pi_serial = "unknown"
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if line.startswith("Serial"):
                    pi_serial = line.split(":")[1].strip()
                    break
    except Exception:
        pass

    salt = os.urandom(16).hex()
    device_id = hashlib.sha256(f"vault-{pi_serial}-{salt}".encode()).hexdigest()[:16]
    DEVICE_ID_PATH.write_text(device_id)
    os.chmod(DEVICE_ID_PATH, 0o600)
    log.info(f"Generated device ID: {device_id}")
    return device_id


def generate_kem_keypair(entropy_seed: bytes) -> tuple[bytes, bytes]:
    """Generate ML-KEM-1024 keypair, mixing ESP32 entropy in first."""
    try:
        with open("/dev/urandom", "wb") as urandom:
            urandom.write(entropy_seed)
        log.info(f"Mixed {len(entropy_seed)} bytes of Tongue entropy into system pool")
    except PermissionError:
        log.warning("Cannot write to /dev/urandom — entropy mixing skipped")

    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    log.info(f"Generated {KEM_ALGORITHM} keypair ({len(public_key)}B pub, {len(private_key)}B priv)")
    return public_key, private_key


def store_private_key(private_key: bytes) -> None:
    """Encrypt and store the private key, bound to this device."""
    device_id = get_device_id()
    machine_id = _get_machine_id()
    encryption_key = hashlib.sha256(
        f"{device_id}:{machine_id}:vault-encryption-key".encode()
    ).digest()

    aesgcm = AESGCM(encryption_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_key, None)

    PRIVATE_KEY_PATH.write_bytes(nonce + ciphertext)
    os.chmod(PRIVATE_KEY_PATH, 0o600)
    log.info(f"Private key encrypted and stored: {PRIVATE_KEY_PATH}")


def load_private_key() -> bytes:
    """Load and decrypt the private key."""
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError("No private key found — run keygen first")

    device_id = get_device_id()
    machine_id = _get_machine_id()
    encryption_key = hashlib.sha256(
        f"{device_id}:{machine_id}:vault-encryption-key".encode()
    ).digest()

    raw = PRIVATE_KEY_PATH.read_bytes()
    aesgcm = AESGCM(encryption_key)
    return aesgcm.decrypt(raw[:12], raw[12:], None)


def store_public_key(public_key: bytes) -> None:
    """Store the public key."""
    PUBLIC_KEY_PATH.write_bytes(public_key)
    os.chmod(PUBLIC_KEY_PATH, 0o644)
    log.info(f"Public key stored: {PUBLIC_KEY_PATH}")


def _get_machine_id() -> str:
    try:
        return Path("/etc/machine-id").read_text().strip()
    except Exception:
        return "fallback-machine-id"

def derive_wg_psk(shared_secret: bytes, info_string: str) -> str:
    """Derive a WireGuard PSK from an ML-KEM shared secret using HKDF.
    The info_string is supplied by the caller (Lighthouse) and binds the PSK
    to whatever context the caller chooses — peer pubkey, rotation id, mesh
    pair, etc. The Vault is intentionally agnostic to the binding semantics."""
    info = info_string.encode()
    psk_bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return base64.b64encode(psk_bytes).decode()

# ─── KEM Decapsulation ──────────────────────────────────────────────────────


def decapsulate_shared_secret(ciphertext: bytes) -> bytes:
    """Decapsulate a shared secret using our private key."""
    private_key = load_private_key()
    kem = oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=private_key)
    shared_secret = kem.decap_secret(ciphertext)
    log.info(f"Decapsulated shared secret: {len(shared_secret)} bytes")
    return shared_secret


def handle_kem_request(kem_ciphertext_b64: str, info_string: str) -> str:
    """Decapsulate and return shared secret as base64 PSK, bound by HKDF info."""
    ciphertext = base64.b64decode(kem_ciphertext_b64)
    shared_secret = decapsulate_shared_secret(ciphertext)
    psk = derive_wg_psk(shared_secret, info_string)
    log.info("KEM handshake complete — quantum PSK derived via HKDF")
    return psk

def handle_regen_keys(uart: serial.Serial) -> None:
    """Regenerate ML-KEM keypair from fresh ESP32 entropy and notify Lighthouse."""
    log.info("=" * 40)
    log.info("KEY REGEN — Regenerating ML-KEM keypair")
    log.info("=" * 40)

    try:
        entropy = collect_entropy(ENTROPY_TARGET)
        public_key, private_key = generate_kem_keypair(entropy)
        store_private_key(private_key)
        store_public_key(public_key)

        # Notify the Lighthouse with the new public key
        device_id = get_device_id()
        msg = frame_message("regen_complete", {
            "device_id": device_id,
            "public_key": base64.b64encode(public_key).decode(),
            "kem_algorithm": KEM_ALGORITHM,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        uart.write(msg)
        uart.flush()
        log.info("New keypair generated and sent to Lighthouse")

    except Exception as e:
        log.error(f"Key regeneration failed: {e}")
        msg = frame_message("regen_complete", {
            "device_id": get_device_id(),
            "status": "error",
            "error": str(e),
        })
        uart.write(msg)
        uart.flush()

    # Drain any messages that arrived while we were blocked on
    # entropy harvest + keygen (kem_requests pile up here)
    process_lighthouse_messages(uart)

# ─── Lighthouse UART Communication ──────────────────────────────────────────


def register_with_lighthouse(uart: serial.Serial, public_key: bytes) -> None:
    """Send public key and device ID to the Lighthouse over UART."""
    device_id = get_device_id()
    msg = frame_message("register", {
        "device_id": device_id,
        "device_type": "vault",
        "public_key": base64.b64encode(public_key).decode(),
        "kem_algorithm": KEM_ALGORITHM,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    uart.write(msg)
    uart.flush()
    log.info(f"Sent registration to Lighthouse (device: {device_id})")

    # Short wait for ACK — don't block long or we'll miss kem_requests
    response = read_frame(uart, timeout=1.0)
    if response and response.get("type") == "ack":
        log.info("Lighthouse acknowledged registration")
    elif response:
        # Got a non-ACK message (probably a kem_request that arrived
        # while we were registering) — process it immediately
        msg_type = response.get("type", "")
        log.info(f"Got {msg_type} instead of ACK — processing it")
        _handle_message(uart, response)
    else:
        log.warning("No ACK from Lighthouse — will retry")

def send_heartbeat(uart: serial.Serial) -> None:
    """Send a heartbeat over UART."""
    msg = frame_message("heartbeat", {
        "device_id": get_device_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    uart.write(msg)
    uart.flush()

def _handle_message(uart: serial.Serial, message: dict) -> None:
    """Process a single UART message. Shared by process_lighthouse_messages
    and register_with_lighthouse to avoid duplicating dispatch logic."""
    msg_type = message.get("type", "")
    data = message.get("data", {})

    if msg_type == "ping":
        log.info("Ping from Lighthouse — sending full re-registration")
        if PUBLIC_KEY_PATH.exists():
            pub_key = PUBLIC_KEY_PATH.read_bytes()
            register_with_lighthouse(uart, pub_key)
        else:
            uart.write(frame_message("heartbeat", {
                "device_id": get_device_id(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            uart.flush()

    elif msg_type == "kem_request":
        log.info(f"KEM request from client: {data.get('client_id', 'unknown')}")
        try:
            # The Lighthouse supplies the HKDF info string that binds the PSK
            # to its context (peer pubkey + rotation id, mesh pair, etc).
            # The Vault is agnostic — it just decapsulates and HKDFs.
            hkdf_info = data.get("hkdf_info", "")
            if not hkdf_info:
                log.warning(
                    f"kem_request {data.get('request_id')} missing hkdf_info — "
                    f"caller must be updated to the HKDF-bound protocol"
                )
            psk = handle_kem_request(data["ciphertext"], hkdf_info)
            uart.write(frame_message("decap_result", {
                "request_id": data["request_id"],
                "client_id": data["client_id"],
                "device_id": get_device_id(),
                "status": "complete",
                "quantum_psk": psk,
            }))
            uart.flush()
            log.info(f"Decap result sent for request {data['request_id']}")
        except Exception as e:
            log.error(f"KEM decapsulation failed: {e}")
            uart.write(frame_message("decap_result", {
                "request_id": data.get("request_id", ""),
                "client_id": data.get("client_id", ""),
                "device_id": get_device_id(),
                "status": "error",
                "error": str(e),
            }))
            uart.flush()

    elif msg_type == "regen_keys":
        log.info("Lighthouse requested keypair regeneration")
        handle_regen_keys(uart)

    elif msg_type == "entropy_request":
        log.info("Lighthouse requested entropy for TLS cert")
        try:
            nbytes = data.get("bytes_needed", 64)
            entropy = collect_entropy(nbytes)
            uart.write(frame_message("entropy_response", {
                "request_id": data.get("request_id", ""),
                "entropy": base64.b64encode(entropy).decode(),
                "bytes": len(entropy),
            }))
            uart.flush()
            log.info(f"Sent {len(entropy)} bytes of entropy to Lighthouse")
        except Exception as e:
            log.error(f"Entropy collection failed: {e}")

def process_lighthouse_messages(uart: serial.Serial) -> None:
    """Check for and process incoming messages from the Lighthouse.
    Uses read_frame with a short timeout to catch messages that arrive
    between main loop sleep cycles, not just when bytes are already buffered.
    Drains all queued messages before returning so back-to-back KEM requests
    don't pile up in the serial buffer.
    """
    message = read_frame(uart, timeout=0.5)
    if message is None:
        return

    while message is not None:
        _handle_message(uart, message)
        message = read_frame(uart, timeout=0.1)

# ─── Main Service ────────────────────────────────────────────────────────────


def run_keygen() -> bytes:
    """Harvest entropy → generate keypair → store."""
    initialize_vault_directory()
    entropy = collect_entropy(ENTROPY_TARGET)
    public_key, private_key = generate_kem_keypair(entropy)
    store_private_key(private_key)
    store_public_key(public_key)
    return public_key


def run_service() -> None:
    """Main loop: keygen if needed → open UART → register → heartbeat + listen."""
    log.info("=" * 60)
    log.info("THE VAULT — Post-Quantum Key Manager Service")
    log.info("=" * 60)

    initialize_vault_directory()

    if not PRIVATE_KEY_PATH.exists():
        log.info("No existing keypair — generating fresh keys...")
        public_key = run_keygen()
    else:
        log.info("Loading existing public key...")
        public_key = PUBLIC_KEY_PATH.read_bytes()

    log.info(f"Opening UART to Lighthouse on {LIGHTHOUSE_PORT}...")
    try:
        uart = serial.Serial(LIGHTHOUSE_PORT, LIGHTHOUSE_BAUD, timeout=1.0)
    except serial.SerialException as e:
        log.error(f"Cannot open UART {LIGHTHOUSE_PORT}: {e}")
        log.error("Did you run setup.sh and reboot?")
        sys.exit(1)

    log.info("UART link open — registering with Lighthouse...")
    time.sleep(1)

    register_with_lighthouse(uart, public_key)

    last_heartbeat = 0
    heartbeat_count = 0
    log.info("Entering service loop...")

    try:
        while True:
            now = time.time()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                heartbeat_count += 1
                # Re-send full registration every 5th heartbeat (~2.5 min)
                # so the Lighthouse gets our public key even if it started late
                if heartbeat_count % 2 == 0:
                    # Reload public key in case it was regenerated
                    if PUBLIC_KEY_PATH.exists():
                        public_key = PUBLIC_KEY_PATH.read_bytes()
                    register_with_lighthouse(uart, public_key)
                else:
                    send_heartbeat(uart)
                last_heartbeat = now

            process_lighthouse_messages(uart)
            time.sleep(0.1)

    except KeyboardInterrupt:
        log.info("Service stopped by operator")
    finally:
        uart.close()
        log.info("UART closed")

# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="The Vault — PQC Key Manager")
    parser.add_argument(
        "command",
        choices=["keygen", "serve", "decap-test"],
        help="keygen | serve | decap-test",
    )
    args = parser.parse_args()

    if args.command == "keygen":
        run_keygen()
    elif args.command == "serve":
        run_service()
    elif args.command == "decap-test":
        initialize_vault_directory()
        log.info("Running encap/decap self-test...")
        kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
        pub = kem.generate_keypair()
        sk = kem.export_secret_key()
        kem2 = oqs.KeyEncapsulation(KEM_ALGORITHM)
        ct, ss_enc = kem2.encap_secret(pub)
        kem3 = oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=sk)
        ss_dec = kem3.decap_secret(ct)
        assert ss_enc == ss_dec, "DECAP MISMATCH!"
        log.info(f"Self-test PASSED — shared secret: {ss_enc.hex()[:32]}...")