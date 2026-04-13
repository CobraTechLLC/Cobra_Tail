"""
QUANTUM VPN CLIENT — Persistent Background Service

Connects to the Lighthouse, establishes a quantum-resistant WireGuard tunnel,
and maintains it continuously with:
  - Auto-switching endpoints (LAN vs remote)
  - LAN peer discovery via UDP broadcast
  - Periodic heartbeats to the Lighthouse
  - Network change detection and automatic reconnection
  - Cross-platform: Windows, Linux, Android (via Termux)

Dependencies:
    pip install requests

Usage:
    python client.py service --lighthouse-public https://YOUR_PUBLIC_IP:9443 \
                              --lighthouse-local  https://YOUR_LIGHTHOUSE_IP:8443 \
                              --cert-fingerprint <sha256hex>
    python client.py connect  --lighthouse https://YOUR_PUBLIC_IP:9443
    python client.py status   --lighthouse https://YOUR_PUBLIC_IP:9443
"""

import base64
import hashlib
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import time
import random
import logging
from pathlib import Path
from datetime import datetime, timezone

import requests
import requests.adapters
import ssl
import urllib3
import ctypes

# ─── Windows Subprocess Window Suppression ───────────────────────────────────
# On Windows, subprocess calls (wg, netsh, etc.) spawn visible console windows
# that flash on screen. This wraps subprocess.run and subprocess.Popen to
# automatically hide those windows when running as a background service.
_SUBPROCESS_ORIG_RUN = subprocess.run
_SUBPROCESS_ORIG_POPEN = subprocess.Popen

if platform.system() == "Windows":
    _CREATE_NO_WINDOW = 0x08000000
    _STARTUPINFO = subprocess.STARTUPINFO()
    _STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    _STARTUPINFO.wShowWindow = 0  # SW_HIDE

    def _quiet_run(*args, **kwargs):
        """subprocess.run wrapper that hides console windows on Windows."""
        if "creationflags" not in kwargs:
            kwargs["creationflags"] = _CREATE_NO_WINDOW
        if "startupinfo" not in kwargs:
            kwargs["startupinfo"] = _STARTUPINFO
        return _SUBPROCESS_ORIG_RUN(*args, **kwargs)

    class _QuietPopen(subprocess.Popen):
        """Popen wrapper that hides console windows on Windows."""
        def __init__(self, *args, **kwargs):
            if "creationflags" not in kwargs:
                kwargs["creationflags"] = _CREATE_NO_WINDOW
            if "startupinfo" not in kwargs:
                kwargs["startupinfo"] = _STARTUPINFO
            super().__init__(*args, **kwargs)

    subprocess.run = _quiet_run
    subprocess.Popen = _QuietPopen


def secure_wipe(data) -> None:
    """Zero out sensitive data in memory as best we can in Python.
    Works on bytearray and memoryview. For str/bytes (immutable),
    the caller should use bytearray intermediaries instead.
    Does nothing if data is None or not a mutable type."""
    if data is None:
        return
    try:
        if isinstance(data, bytearray):
            ctypes.memset((ctypes.c_char * len(data)).from_buffer(data), 0, len(data))
        elif isinstance(data, memoryview):
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, len(data))
    except Exception:
        # Fallback: overwrite with zeros manually
        try:
            for i in range(len(data)):
                data[i] = 0
        except Exception:
            pass

def _find_and_load_oqs():
    """Find oqs.dll and add it to PATH. Auto-persist on first find."""
    import platform
    if platform.system() != "Windows":
        return

    search_paths = [
        # CobraTail installed location
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CobraTail" / "bin" / "lib",
        # Build locations
        Path.home() / "liboqs" / "build" / "bin" / "Release",
        Path.home() / "liboqs" / "build" / "bin",
        Path("C:/Program Files/liboqs/bin"),
        Path("C:/Program Files (x86)/liboqs/bin"),
        # Dev mode — same directory as this script
        Path(__file__).parent / "lib",
        Path(__file__).parent / "oqs",
        # Legacy location
        Path.home() / ".quantum_vpn" / "lib",
    ]
    env_path = os.environ.get("OQS_INSTALL_PATH", "")
    if env_path:
        search_paths.insert(0, Path(env_path) / "bin")
        search_paths.insert(0, Path(env_path))

    for search_dir in search_paths:
        dll_path = search_dir / "oqs.dll"
        if dll_path.exists():
            dll_dir = str(search_dir)
            os.add_dll_directory(dll_dir)
            os.environ["PATH"] = dll_dir + ";" + os.environ.get("PATH", "")

            # Persist to user PATH so this only needs to happen once
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Environment", 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as key:
                    user_path, _ = winreg.QueryValueEx(key, "Path")
                    if dll_dir.lower() not in user_path.lower():
                        new_path = user_path.rstrip(";") + ";" + dll_dir
                        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                        log.info(f"Added {dll_dir} to user PATH permanently")
            except Exception:
                pass  # Non-admin or other issue — session PATH still works
            break

try:
    _find_and_load_oqs()
    import oqs
except (ImportError, RuntimeError, OSError):
    oqs = None
# ─── Configuration ───────────────────────────────────────────────────────────

KEM_ALGORITHM = "ML-KEM-1024"

# ─── CobraTail Directory Detection ──────────────────────────────────────────
# Priority: installed location → dev mode (same dir as script) → legacy fallback
def _detect_cobratail_dir() -> Path:
    """Detect the CobraTail install directory."""
    if platform.system() == "Windows":
        installed = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CobraTail"
    else:
        installed = Path("/opt/cobratail")

    # Check for managed install marker
    if (installed / ".cobratail").exists():
        return installed

    # Dev mode — config/data alongside the script
    script_dir = Path(__file__).parent.resolve()
    if (script_dir / "enrollment.json").exists() or (script_dir / "config" / "enrollment.json").exists():
        return script_dir

    # Legacy ~/.quantum_vpn
    legacy = Path.home() / ".quantum_vpn"
    if legacy.exists():
        return legacy

    # Default to installed path (will be created)
    return installed

COBRATAIL_DIR = _detect_cobratail_dir()

# Subdirectory layout (new install) vs flat layout (legacy/dev)
if (COBRATAIL_DIR / "config").is_dir() or (COBRATAIL_DIR / ".cobratail").exists():
    # New organized layout
    CONFIG_DIR = COBRATAIL_DIR / "config"
    DATA_DIR = COBRATAIL_DIR / "data"
    LOG_DIR = COBRATAIL_DIR / "logs"
else:
    # Legacy flat layout (everything in one dir)
    CONFIG_DIR = COBRATAIL_DIR
    DATA_DIR = COBRATAIL_DIR
    LOG_DIR = COBRATAIL_DIR

CLIENT_DIR = COBRATAIL_DIR  # Backward compat for mkdir calls

CLIENT_ID_PATH = CONFIG_DIR / "client_id"
WG_CONFIG_PATH = CONFIG_DIR / "wg_quantum.conf"
STATE_PATH = DATA_DIR / "client_state.json"

# Timers
HEARTBEAT_INTERVAL = 30         # Heartbeat to Lighthouse every 30s
NETWORK_CHECK_INTERVAL = 5     # Check for network changes every 5s
DISCOVERY_INTERVAL = 30         # LAN broadcast every 30s
RECONNECT_DELAY = 10            # Initial wait before reconnect attempt
RECONNECT_MAX_DELAY = 120       # Maximum backoff cap (seconds)
RECONNECT_BACKOFF_FACTOR = 2    # Multiply delay by this on each failure
ENDPOINT_PROBE_TIMEOUT = 3      # Timeout for LAN probe (seconds)

# Heartbeat jitter — spread load when many clients heartbeat simultaneously
HEARTBEAT_JITTER = 5            # ±5 seconds random offset per heartbeat cycle
# LAN Discovery
DISCOVERY_PORT = 5391
DISCOVERY_MAGIC = b"QVPN_DISC_v1"

# Mesh Networking
MESH_WG_LISTEN_PORT = 51821       # Separate WG listen port for mesh peers
MESH_CHECK_INTERVAL = 30          # Check for pending mesh requests every 30s
# Direct Peer KEM Exchange (zero-trust mesh re-keying)
PEER_KEM_PORT = 9876              # TCP port for direct KEM exchange over mesh VPN
PEER_KEM_EXCHANGE_DELAY = 10      # Seconds to wait after mesh tunnel up before starting KEM
PEER_KEM_TIMEOUT = 60             # Timeout for the full KEM exchange handshake
MESH_REKEY_INTERVAL = 86400       # Re-key mesh tunnels 120-for test. 86400-for production every 24 hours (seconds)
MESH_REKEY_CHECK_INTERVAL = 300   # Check for rekey-eligible peers every 5 minutes

# ─── NAT Traversal & Hole Punching (Phase 1) ────────────────────────────────
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
]
NAT_TYPE_FULL_CONE = "full_cone"
NAT_TYPE_RESTRICTED = "restricted"
NAT_TYPE_SYMMETRIC_PREDICTABLE = "symmetric_predictable"
NAT_TYPE_SYMMETRIC_RANDOM = "symmetric_random"
NAT_TYPE_UNKNOWN = "unknown"

HOLEPUNCH_BURST_COUNT = 8
HOLEPUNCH_BURST_INTERVAL = 0.2       # 200ms between packets in a burst
HOLEPUNCH_TIMEOUT = 30               # Total timeout for hole punch attempts
HOLEPUNCH_RETRY_DELAYS = [5, 10, 20] # Background repunch delays (seconds)
PORT_PREDICTION_SPRAY_RANGE = 10     # Ports above/below last observed STUN port

# ─── UPnP / NAT-PMP Port Mapping (Phase 2) ──────────────────────────────────
UPNP_ENABLED = os.environ.get("QVPN_UPNP_ENABLED", "0") == "1"
UPNP_MAPPING_DURATION = 3600  # seconds (1 hour), auto-renewed by heartbeat
_active_upnp_mappings = {}    # external_port → {"internal_port": int, "gateway": str}

# ─── Path Monitoring (Phase 4) ───────────────────────────────────────────────
PATH_MONITOR_INTERVAL = 30           # Check mesh handshake freshness every 30s
HANDSHAKE_STALE_THRESHOLD = 120      # Seconds since last WG handshake before considered stale (2.5 missed keepalives)
PATH_MONITOR_MAX_RETRIES = 3         # Max re-punch attempts before flagging for relay
PATH_MONITOR_RETRY_DELAYS = [5, 15, 30]  # Delays between re-punch attempts (seconds)

# ─── STUN Cache (Phase 4 optimization) ───────────────────────────────────────
STUN_CACHE_TTL = 300  # Reuse cached STUN/NAT data for 5 minutes between refreshes
_stun_cache = {
    "stun_endpoint": None,
    "nat_type": None,
    "timestamp": 0,
}

# ─── Pre-warmed Candidate Cache ─────────────────────────────────────────────
CANDIDATE_CACHE_TTL = 60          # Pre-warmed candidates valid for 60 seconds
CANDIDATE_WARM_INTERVAL = 45      # Re-warm candidates every 45s in the service loop
_candidate_cache = {
    "candidates": [],
    "nat_type": NAT_TYPE_UNKNOWN,
    "timestamp": 0,
}
_candidate_cache_lock = threading.Lock()

# ─── Enrollment ──────────────────────────────────────────────────────────────
ENROLLMENT_PATH = CONFIG_DIR / "enrollment.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("client")

# Physical IP cache — avoids spawning PowerShell on every STUN/holepunch call
_physical_ip_cache = {"ip": "", "timestamp": 0.0}
_PHYSICAL_IP_CACHE_TTL = 30.0  # Re-check every 30 seconds

# ─── TLS Certificate Pinning ────────────────────────────────────────────────

CERT_FINGERPRINT = ""
CERT_FINGERPRINT_PATH = CONFIG_DIR / "cert_fingerprint"


class CertPinningAdapter(requests.adapters.HTTPAdapter):
    """
    Custom HTTPS adapter that verifies the server certificate's SHA-256
    fingerprint matches the pinned value. Defeats MITM even with self-signed certs.
    """

    def __init__(self, fingerprint: str, **kwargs):
        self.pinned_fingerprint = fingerprint.lower().replace(":", "")
        super().__init__(**kwargs)

    def send(self, request, **kwargs):
        kwargs["verify"] = False
        response = super().send(request, **kwargs)
        self._verify_fingerprint(request.url)
        return response

    def _verify_fingerprint(self, url: str) -> None:
        """Verify the server's cert fingerprint matches our pinned value."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return

        host = parsed.hostname
        port = parsed.port or 443

        try:
            pem_cert = ssl.get_server_certificate((host, port))
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            cert = x509.load_pem_x509_certificate(pem_cert.encode())
            der_bytes = cert.public_bytes(Encoding.DER)
            actual_fp = hashlib.sha256(der_bytes).hexdigest()

            if actual_fp != self.pinned_fingerprint:
                raise ssl.SSLError(
                    f"CERTIFICATE FINGERPRINT MISMATCH — possible MITM attack!\n"
                    f"  Expected: {self.pinned_fingerprint}\n"
                    f"  Got:      {actual_fp}\n"
                    f"  Server:   {host}:{port}\n"
                    f"If you regenerated the cert, update --cert-fingerprint"
                )

            log.debug(f"Cert fingerprint verified for {host}:{port}")

        except ssl.SSLError:
            raise
        except Exception as e:
            log.warning(f"Could not verify cert fingerprint for {host}:{port}: {e}")


def create_pinned_session(fingerprint: str = None) -> requests.Session:
    """Create a requests Session with certificate pinning if a fingerprint is set."""
    session = requests.Session()
    fp = fingerprint or CERT_FINGERPRINT

    if fp:
        adapter = CertPinningAdapter(fp)
        session.mount("https://", adapter)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log.info(f"TLS certificate pinning enabled (fingerprint: {fp[:16]}...)")
    else:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log.warning("No cert fingerprint set — TLS verification disabled (vulnerable to MITM)")

    return session


def save_fingerprint(fingerprint: str) -> None:
    """Persist the cert fingerprint for future runs."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CERT_FINGERPRINT_PATH.write_text(fingerprint)


def load_fingerprint() -> str:
    """Load saved cert fingerprint."""
    if CERT_FINGERPRINT_PATH.exists():
        return CERT_FINGERPRINT_PATH.read_text().strip()
    return ""


# Module-level session
_session: requests.Session = None


def get_session() -> requests.Session:
    """Get or create the pinned HTTPS session."""
    global _session
    if _session is None:
        _session = create_pinned_session()
    return _session

# ─── Helpers ─────────────────────────────────────────────────────────────────


def get_client_id() -> str:
    """
    Get the device ID. Priority:
      1. Enrollment file (set by 'enroll' command — Lighthouse-assigned ID)
      2. Legacy client_id file (pre-enrollment installs)
      3. Generate a new one (will be rejected by Lighthouse until enrolled)
    """
    # Check enrollment first
    if ENROLLMENT_PATH.exists():
        try:
            data = json.loads(ENROLLMENT_PATH.read_text())
            if data.get("device_id"):
                return data["device_id"]
        except (json.JSONDecodeError, IOError):
            pass

    # Legacy: existing client_id file
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CLIENT_ID_PATH.exists():
        return CLIENT_ID_PATH.read_text().strip()

    # No enrollment, no legacy — generate a temporary ID
    hostname = socket.gethostname()
    salt = os.urandom(16).hex()
    raw = f"client-{hostname}-{salt}"
    client_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    CLIENT_ID_PATH.write_text(client_id)
    log.info(f"Generated client ID: {client_id}")
    log.warning("This device is not enrolled. Run 'python client.py enroll' first.")
    return client_id

def get_local_ip() -> str:
    """Get this device's primary LAN IP address.
    Uses a UDP connect trick to find the source IP for internet-bound traffic.
    Note: when WireGuard full-tunnel is active, this may return the WG interface IP.
    Use get_physical_ip() when you specifically need the real adapter IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_ipv6_address() -> str:
    """Get this device's IPv6 address."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "::1"


def _load_ipv6_token_identity() -> dict:
    """Phase 5C CL2: Load IPv6 token identity from node_identity.json.
    Returns dict with ipv6_token, ipv6_prefix, ipv6_token_addr or empty strings.
    Falls back gracefully — if identity_manager hasn't run, all values are empty.
    """
    identity_path = DATA_DIR / "node_identity.json"
    result = {"ipv6_token": "", "ipv6_prefix": "", "ipv6_token_addr": ""}

    if not identity_path.exists():
        return result

    try:
        data = json.loads(identity_path.read_text())
        result["ipv6_token"] = data.get("ipv6_token", "")
        result["ipv6_prefix"] = data.get("ipv6_prefix", "")
        result["ipv6_token_addr"] = data.get("ipv6_global_address", "") or data.get("ipv6_token_addr", "")
    except (json.JSONDecodeError, IOError) as e:
        log.debug(f"Could not load identity file: {e}")

    return result

# Cached public IP — refreshed on network changes, not every heartbeat
_cached_public_ip = ""
_cached_public_ip_time = 0
_PUBLIC_IP_CACHE_TTL = 300  # refresh every 5 minutes max


def get_public_ip(force_refresh: bool = False) -> str:
    """Get this device's public IP address via STUN or HTTP fallback.
    Results are cached to avoid hitting STUN servers on every heartbeat."""
    global _cached_public_ip, _cached_public_ip_time

    if not force_refresh and _cached_public_ip and (time.time() - _cached_public_ip_time) < _PUBLIC_IP_CACHE_TTL:
        return _cached_public_ip

    ip = _discover_public_ip()
    if ip:
        _cached_public_ip = ip
        _cached_public_ip_time = time.time()
    return ip or _cached_public_ip


def _discover_public_ip() -> str:
    """Actually query STUN/HTTP for our public IP. Uses stun_query() internally."""
    # Try STUN first (fast, no HTTP dependency)
    for host, port in [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)]:
        result = stun_query(host, port)
        if result:
            ip, _mapped_port = result
            return ip

    # Fallback to HTTP (slower, but reliable)
    try:
        import urllib.request
        ip = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip()
        if ip:
            return ip
    except Exception:
        pass

    return ""

def stun_query(host: str, port: int, timeout: float = 2.0) -> tuple[str, int] | None:
    """
    Send a single STUN Binding Request and return (public_ip, mapped_port).
    Returns None on failure. This is the reusable building block for NAT classification.
    Binds to the physical interface to bypass WireGuard full-tunnel routing.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        _bind_physical(sock)
        # STUN Binding Request (RFC 5389)
        txn_id = os.urandom(12)
        msg = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn_id
        sock.sendto(msg, (host, port))
        data, _ = sock.recvfrom(1024)
        sock.close()

        # Parse STUN Binding Response
        pos = 20  # skip 20-byte header
        while pos < len(data) - 4:
            attr_type = struct.unpack("!H", data[pos:pos+2])[0]
            attr_len = struct.unpack("!H", data[pos+2:pos+4])[0]

            if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                family = data[pos+5]
                if family == 0x01:  # IPv4
                    xor_port = struct.unpack("!H", data[pos+6:pos+8])[0]
                    mapped_port = xor_port ^ 0x2112
                    xor_ip = struct.unpack("!I", data[pos+8:pos+12])[0]
                    ip_int = xor_ip ^ 0x2112A442
                    ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                    return (ip, mapped_port)
            elif attr_type == 0x0001:  # MAPPED-ADDRESS
                family = data[pos+5]
                if family == 0x01:  # IPv4
                    mapped_port = struct.unpack("!H", data[pos+6:pos+8])[0]
                    ip = socket.inet_ntoa(data[pos+8:pos+12])
                    return (ip, mapped_port)

            pos += 4 + attr_len
            if attr_len % 4:
                pos += 4 - (attr_len % 4)  # STUN padding
    except Exception as e:
        log.debug(f"STUN query to {host}:{port} failed: {e}")
    return None

def classify_nat_type(quiet: bool = False) -> tuple[str, list[dict]]:
    """
    Query multiple STUN servers and classify NAT type by comparing mapped ports.
    Returns (nat_type_string, list_of_mapped_endpoints).
    Each endpoint is {'ip': str, 'port': int, 'stun_server': str}.
    If quiet=True, logs at DEBUG instead of INFO (used by heartbeat to avoid spam).
    Uses parallel queries to avoid sequential 3s timeouts.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    endpoints = []
    servers = STUN_SERVERS[:4]

    def _query_one(host_port):
        host, port = host_port
        result = stun_query(host, port)
        if result:
            ip, mapped_port = result
            return {
                "ip": ip,
                "port": mapped_port,
                "stun_server": f"{host}:{port}",
            }
        return None

    try:
        with ThreadPoolExecutor(max_workers=len(servers)) as pool:
            futures = {pool.submit(_query_one, s): s for s in servers}
            try:
                for fut in as_completed(futures, timeout=5):
                    try:
                        result = fut.result()
                        if result:
                            endpoints.append(result)
                    except Exception:
                        pass
            except TimeoutError:
                # Some futures didn't complete in time — collect whatever did finish
                for fut in futures:
                    if fut.done():
                        try:
                            result = fut.result()
                            if result:
                                endpoints.append(result)
                        except Exception:
                            pass
                _log = log.debug if quiet else log.info
                _log(f"STUN parallel query: {len(endpoints)}/{len(servers)} responded within timeout")
    except Exception as e:
        log.warning(f"STUN parallel query failed: {e}")

    if len(endpoints) < 2:
        log.warning(f"NAT classification: only {len(endpoints)} STUN responses (need 2+)")
        nat_type = NAT_TYPE_UNKNOWN
        return nat_type, endpoints

    ports = [ep["port"] for ep in endpoints]
    unique_ports = set(ports)

    _log = log.debug if quiet else log.info

    if len(unique_ports) == 1:
        nat_type = NAT_TYPE_FULL_CONE
        _log(f"NAT type: {nat_type} (all STUN servers returned port {ports[0]})")
    else:
        sorted_ports = sorted(ports)
        deltas = [sorted_ports[i+1] - sorted_ports[i] for i in range(len(sorted_ports)-1)]
        if all(1 <= d <= 3 for d in deltas):
            nat_type = NAT_TYPE_SYMMETRIC_PREDICTABLE
            _log(f"NAT type: {nat_type} (ports {sorted_ports}, deltas {deltas})")
        else:
            nat_type = NAT_TYPE_SYMMETRIC_RANDOM
            _log(f"NAT type: {nat_type} (ports {sorted_ports} — no predictable pattern)")

    return nat_type, endpoints

# Module-level dedupe tracker for collect_endpoint_candidates log spam.
# Stores a fingerprint of the last result so we only log loudly on change.
_last_candidate_log_fingerprint: "str | None" = None


def collect_endpoint_candidates(listen_port: int = MESH_WG_LISTEN_PORT) -> list[dict]:
    """
    Gather ALL ways a peer might be reachable: IPv6 token, IPv6, UPnP, LAN, STUN, public IP,
    port predictions, and VPN-routed (fallback through Lighthouse tunnel).
    Returns a JSON-serializable list of candidate dicts sorted by priority (lower = better).
    Uses physical interface IP to avoid reporting WireGuard tunnel IPs as candidates.
    IPv6 token candidates get the absolute highest priority when available —
    deterministic address, no NAT traversal needed.

    Logging dedupe: the "NAT type", "IPv6 candidate added", "IPv6 token
    candidate added", and "Collected N endpoint candidates" lines are emitted
    at INFO only when the result meaningfully changes. The fingerprint excludes
    per-query-volatile fields (STUN ports, predicted ports, public IP endpoint)
    because symmetric NATs hand out fresh ports per query, which would otherwise
    force an INFO log every cycle. Stable fields (NAT type, candidate type
    counts, IPv6/LAN/UPnP/VPN-routed endpoints) drive the fingerprint — these
    only change when the network state genuinely changes.
    """
    global _last_candidate_log_fingerprint

    candidates = []
    priority = 0

    # Defer INFO-level messages so we can decide loud vs quiet after seeing the full result
    pending_info_logs = []

    # 0. IPv6 token candidate (Phase 5B — deterministic, HIGHEST priority)
    identity = _load_ipv6_token_identity()
    token_addr = identity.get("ipv6_token_addr", "")
    if token_addr and token_addr != "::1" and not token_addr.startswith("fe80"):
        candidates.append({
            "type": "ipv6_token",
            "endpoint": f"[{token_addr}]:{listen_port}",
            "priority": priority,
            "ipv6_token": identity.get("ipv6_token", ""),
        })
        priority += 1
        pending_info_logs.append(
            f"IPv6 token candidate added: [{token_addr}]:{listen_port} (deterministic)"
        )

    # 1. UPnP candidate (Phase 2 — guaranteed open port)
    if UPNP_ENABLED:
        upnp_endpoint = attempt_upnp_mapping(listen_port)
        if upnp_endpoint:
            candidates.append({
                "type": "upnp",
                "endpoint": upnp_endpoint,
                "priority": priority,
            })
            priority += 1

    # 2. IPv6 candidate (Phase 3 — non-token IPv6, still no NAT)
    ipv6_addr = get_ipv6_address()
    if ipv6_addr and ipv6_addr != "::1" and not ipv6_addr.startswith("fe80"):
        # Avoid duplicate if token address is the same as generic IPv6
        ipv6_endpoint = f"[{ipv6_addr}]:{listen_port}"
        already_listed = any(c["endpoint"] == ipv6_endpoint for c in candidates)
        if not already_listed:
            candidates.append({
                "type": "ipv6",
                "endpoint": ipv6_endpoint,
                "priority": priority,
            })
            priority += 1
            pending_info_logs.append(f"IPv6 candidate added: [{ipv6_addr}]:{listen_port}")

    # 3. LAN candidate — use physical IP, not WireGuard IP
    lan_ip = get_physical_ip()
    if lan_ip and lan_ip != "127.0.0.1":
        candidates.append({
            "type": "lan",
            "endpoint": f"{lan_ip}:{listen_port}",
            "priority": priority,
        })
        priority += 1

    # 4. STUN candidates + NAT classification.
    #    Pass quiet=True so the NAT type line doesn't independently spam —
    #    the dedupe block below emits the summary on change.
    nat_type, stun_endpoints = classify_nat_type(quiet=True)
    for ep in stun_endpoints:
        candidates.append({
            "type": "stun",
            "endpoint": f"{ep['ip']}:{ep['port']}",
            "nat_type": nat_type,
            "priority": priority,
        })
        priority += 1

    # 5. Raw public IP + listen port candidate
    public_ip = get_public_ip()
    if public_ip:
        pub_endpoint = f"{public_ip}:{listen_port}"
        # Avoid duplicating an already-listed STUN endpoint
        existing = {c["endpoint"] for c in candidates}
        if pub_endpoint not in existing:
            candidates.append({
                "type": "public",
                "endpoint": pub_endpoint,
                "priority": priority,
            })
            priority += 1

    # 6. Port prediction candidates (only if symmetric NAT detected)
    if nat_type in (NAT_TYPE_SYMMETRIC_PREDICTABLE, NAT_TYPE_SYMMETRIC_RANDOM) and stun_endpoints:
        last_port = max(ep["port"] for ep in stun_endpoints)
        base_ip = stun_endpoints[0]["ip"]
        for offset in range(1, PORT_PREDICTION_SPRAY_RANGE + 1):
            for predicted_port in (last_port + offset, last_port - offset):
                if 1024 < predicted_port < 65535:
                    candidates.append({
                        "type": "predicted",
                        "endpoint": f"{base_ip}:{predicted_port}",
                        "priority": priority,
                    })
                    priority += 1

    # 7. VPN-routed candidate (fallback — route mesh traffic through Lighthouse tunnel)
    try:
        state = load_state()
        vpn_address = state.get("vpn_address", "")
        if vpn_address:
            candidates.append({
                "type": "vpn_routed",
                "endpoint": f"{vpn_address}:{listen_port}",
                "priority": priority,
            })
            priority += 1
    except Exception:
        pass

    # ── Dedupe: fingerprint only the STABLE parts of the result ──
    # Symmetric NATs hand out fresh STUN ports on every query, which makes
    # the raw (type, endpoint) set unstable across cycles even when the
    # network hasn't meaningfully changed. So we fingerprint on:
    #   - NAT type (changes rarely, and we want to hear about it)
    #   - counts of each candidate type (e.g. "4 stun, 20 predicted, 1 lan")
    #   - actual endpoints for types that DON'T drift per query
    # STUN, predicted, and public candidates are excluded from the endpoint
    # portion because their ports rotate on symmetric NATs.
    STABLE_TYPES = {"ipv6_token", "ipv6", "lan", "upnp", "vpn_routed"}
    type_counts = {}
    for c in candidates:
        t = c.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    stable_endpoints = sorted(
        (c["type"], c["endpoint"]) for c in candidates
        if c.get("type") in STABLE_TYPES and c.get("endpoint")
    )
    fingerprint = f"{nat_type}|{sorted(type_counts.items())}|{stable_endpoints}"
    changed = (fingerprint != _last_candidate_log_fingerprint)

    if changed:
        # First call, or network state changed — log at INFO so operators see it
        _last_candidate_log_fingerprint = fingerprint
        # Re-emit the NAT type line at INFO here (since classify_nat_type was silenced above)
        if nat_type != NAT_TYPE_UNKNOWN and stun_endpoints:
            log.info(f"NAT type: {nat_type} ({len(stun_endpoints)} STUN responses)")
        for msg in pending_info_logs:
            log.info(msg)
        log.info(f"Collected {len(candidates)} endpoint candidates (NAT: {nat_type})")
    else:
        # Unchanged since last call — demote to DEBUG to keep the log file clean
        if nat_type != NAT_TYPE_UNKNOWN and stun_endpoints:
            log.debug(f"NAT type: {nat_type} ({len(stun_endpoints)} STUN responses) [unchanged]")
        for msg in pending_info_logs:
            log.debug(msg)
        log.debug(f"Collected {len(candidates)} endpoint candidates (NAT: {nat_type}) [unchanged]")

    for c in candidates:
        log.debug(f"  candidate: {c['type']} {c['endpoint']} (pri={c['priority']})")

    return candidates

def collect_endpoint_candidates_cached(listen_port: int = MESH_WG_LISTEN_PORT,
                                        max_age: float = CANDIDATE_CACHE_TTL) -> list[dict]:
    """Return cached candidates if fresh enough, otherwise collect new ones.
    Used by mesh request/accept to avoid redundant 8-second STUN queries
    when candidates were recently pre-warmed by the service loop.
    """
    global _candidate_cache
    with _candidate_cache_lock:
        age = time.time() - _candidate_cache["timestamp"]
        if _candidate_cache["candidates"] and age < max_age:
            log.info(f"Using pre-warmed candidates ({len(_candidate_cache['candidates'])} candidates, {age:.0f}s old)")
            return _candidate_cache["candidates"]

    # Cache miss or stale — collect fresh
    candidates = collect_endpoint_candidates(listen_port)
    with _candidate_cache_lock:
        _candidate_cache = {
            "candidates": candidates,
            "nat_type": next((c.get("nat_type", NAT_TYPE_UNKNOWN) for c in candidates if c.get("nat_type")), NAT_TYPE_UNKNOWN),
            "timestamp": time.time(),
        }
    return candidates


def warm_candidate_cache(listen_port: int = MESH_WG_LISTEN_PORT) -> None:
    """Pre-warm the candidate cache in the background.
    Called periodically from the service loop so candidates are ready
    instantly when a mesh tunnel is requested or accepted.
    """
    global _candidate_cache
    try:
        candidates = collect_endpoint_candidates(listen_port)
        with _candidate_cache_lock:
            _candidate_cache = {
                "candidates": candidates,
                "nat_type": next((c.get("nat_type", NAT_TYPE_UNKNOWN) for c in candidates if c.get("nat_type")), NAT_TYPE_UNKNOWN),
                "timestamp": time.time(),
            }
        log.debug(f"Candidate cache warmed: {len(candidates)} candidates")
    except Exception as e:
        log.debug(f"Candidate cache warm failed: {e}")


def collect_lan_only_candidates(listen_port: int = MESH_WG_LISTEN_PORT) -> list[dict]:
    """Collect only LAN-relevant candidates, skipping STUN entirely.
    Used when both peers are known to be on the same LAN subnet,
    avoiding the ~8 second STUN query overhead.
    """
    candidates = []
    priority = 0

    # IPv6 token candidate (still useful on LAN)
    identity = _load_ipv6_token_identity()
    token_addr = identity.get("ipv6_token_addr", "")
    if token_addr and token_addr != "::1" and not token_addr.startswith("fe80"):
        candidates.append({
            "type": "ipv6_token",
            "endpoint": f"[{token_addr}]:{listen_port}",
            "priority": priority,
            "ipv6_token": identity.get("ipv6_token", ""),
        })
        priority += 1

    # IPv6 global address
    ipv6_addr = get_ipv6_address()
    if ipv6_addr and ipv6_addr != "::1" and not ipv6_addr.startswith("fe80"):
        ipv6_endpoint = f"[{ipv6_addr}]:{listen_port}"
        already_listed = any(c["endpoint"] == ipv6_endpoint for c in candidates)
        if not already_listed:
            candidates.append({
                "type": "ipv6",
                "endpoint": ipv6_endpoint,
                "priority": priority,
            })
            priority += 1

    # LAN IP (physical, not WireGuard)
    lan_ip = get_physical_ip()
    if lan_ip and lan_ip != "127.0.0.1":
        candidates.append({
            "type": "lan",
            "endpoint": f"{lan_ip}:{listen_port}",
            "priority": priority,
        })
        priority += 1

    # VPN-routed fallback
    try:
        state = load_state()
        vpn_address = state.get("vpn_address", "")
        if vpn_address:
            candidates.append({
                "type": "vpn_routed",
                "endpoint": f"{vpn_address}:{listen_port}",
                "priority": priority,
            })
            priority += 1
    except Exception:
        pass

    log.info(f"Collected {len(candidates)} LAN-only candidates (STUN skipped)")
    return candidates

def _parse_endpoint(ep_str: str) -> tuple[str, int, int]:
    """
    Parse an endpoint string into (host, port, address_family).
    Supports IPv4 ("1.2.3.4:51821") and IPv6 ("[2001:db8::1]:51821") formats.
    Returns (host, port, socket.AF_INET or socket.AF_INET6).
    """
    if ep_str.startswith("["):
        # IPv6 bracket notation: [addr]:port
        bracket_end = ep_str.index("]")
        host = ep_str[1:bracket_end]
        port = int(ep_str[bracket_end + 2:])  # skip "]:"
        return host, port, socket.AF_INET6
    else:
        host, port_str = ep_str.rsplit(":", 1)
        return host, int(port_str), socket.AF_INET

def send_holepunch_burst(target_endpoints: list[str], listen_port: int = MESH_WG_LISTEN_PORT) -> None:
    """
    Send a burst of UDP packets to all target endpoints to create NAT mappings.
    Runs HOLEPUNCH_BURST_COUNT packets per endpoint at HOLEPUNCH_BURST_INTERVAL spacing.
    Runs in a background thread so it doesn't block mesh setup.
    Binds to physical interface to bypass WireGuard full-tunnel routing.
    Supports both IPv4 and IPv6 endpoints (Phase 3 V3).
    """
    def _burst():
        # Separate endpoints by address family — can't mix on one socket
        ipv4_targets = []
        ipv6_targets = []
        for ep_str in target_endpoints:
            try:
                host, port, af = _parse_endpoint(ep_str)
                if af == socket.AF_INET6:
                    ipv6_targets.append((host, port))
                else:
                    ipv4_targets.append((host, port))
            except Exception as e:
                log.debug(f"Hole punch: failed to parse endpoint {ep_str}: {e}")

        sock4 = None
        sock6 = None

        if ipv4_targets:
            sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _bind_physical(sock4, listen_port)

        if ipv6_targets:
            try:
                sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock6.bind(("::", listen_port if not sock4 else 0))
            except Exception as e:
                log.debug(f"Hole punch: IPv6 socket setup failed: {e}")
                sock6 = None

        punch_payload = b"QVPN_PUNCH"
        for burst_num in range(HOLEPUNCH_BURST_COUNT):
            for host, port in ipv4_targets:
                try:
                    sock4.sendto(punch_payload, (host, port))
                except Exception as e:
                    log.debug(f"Hole punch send to {host}:{port} failed: {e}")
            for host, port in ipv6_targets:
                if sock6:
                    try:
                        sock6.sendto(punch_payload, (host, port, 0, 0))
                    except Exception as e:
                        log.debug(f"Hole punch send to [{host}]:{port} failed: {e}")
            time.sleep(HOLEPUNCH_BURST_INTERVAL)

        if sock4:
            sock4.close()
        if sock6:
            sock6.close()
        total = len(ipv4_targets) + len(ipv6_targets)
        log.info(f"Hole punch burst complete: {HOLEPUNCH_BURST_COUNT} rounds to {total} endpoints "
                 f"({len(ipv4_targets)} IPv4, {len(ipv6_targets)} IPv6)")

    t = threading.Thread(target=_burst, daemon=True)
    t.start()
    log.info(f"Hole punch burst started targeting {len(target_endpoints)} endpoints")

def attempt_upnp_mapping(internal_port: int, external_port: int = 0,
                          duration: int = UPNP_MAPPING_DURATION) -> str | None:
    """
    Phase 2 U2: Attempt to create a UPnP IGD port mapping.
    Discovers the UPnP gateway on the LAN and requests a port mapping from
    external_port → internal_ip:internal_port for the specified duration.

    Args:
        internal_port: Local port to map (e.g., 51821 for WireGuard mesh)
        external_port: Requested external port (0 = same as internal)
        duration: Mapping duration in seconds (default 3600)

    Returns:
        "external_ip:external_port" on success, None on failure.
    """
    if not UPNP_ENABLED:
        return None

    try:
        import miniupnpc
    except ImportError:
        log.debug("miniupnpc not installed — UPnP disabled")
        return None

    if external_port == 0:
        external_port = internal_port

    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 2000  # 2 second discovery timeout
        devices = upnp.discover()
        if devices == 0:
            log.debug("UPnP: No IGD devices found on LAN")
            return None

        upnp.selectigd()
        external_ip = upnp.externalipaddress()
        if not external_ip:
            log.debug("UPnP: Could not determine external IP from gateway")
            return None

        # Get local IP that the gateway sees
        lan_ip = upnp.lanaddr or get_local_ip()

        # Try to add the port mapping
        result = upnp.addportmapping(
            external_port,     # external port
            "UDP",             # protocol
            lan_ip,            # internal host
            internal_port,     # internal port
            "QuantumVPN Mesh", # description
            "",                # remote host (empty = any)
            duration,          # lease duration
        )

        if result:
            endpoint = f"{external_ip}:{external_port}"
            _active_upnp_mappings[external_port] = {
                "internal_port": internal_port,
                "gateway": external_ip,
                "lan_ip": lan_ip,
            }
            log.info(f"UPnP mapping created: {endpoint} → {lan_ip}:{internal_port} (TTL={duration}s)")
            return endpoint
        else:
            log.debug(f"UPnP: addportmapping returned failure for port {external_port}")
            return None

    except Exception as e:
        log.debug(f"UPnP mapping failed: {e}")
        return None


def release_upnp_mapping(external_port: int) -> bool:
    """
    Phase 2 U3: Remove a UPnP port mapping.
    Called during shutdown or when a mesh peer is removed.
    """
    if not UPNP_ENABLED:
        return False

    try:
        import miniupnpc
    except ImportError:
        return False

    try:
        upnp = miniupnpc.UPnP()
        upnp.discoverdelay = 2000
        if upnp.discover() == 0:
            return False
        upnp.selectigd()

        result = upnp.deleteportmapping(external_port, "UDP")
        if external_port in _active_upnp_mappings:
            del _active_upnp_mappings[external_port]

        if result:
            log.info(f"UPnP mapping released: port {external_port}/UDP")
        return bool(result)

    except Exception as e:
        log.debug(f"UPnP release failed for port {external_port}: {e}")
        return False


def renew_upnp_mappings() -> None:
    """
    Phase 2 U7: Renew all active UPnP mappings.
    Called from the heartbeat loop to keep mappings alive.
    """
    if not UPNP_ENABLED or not _active_upnp_mappings:
        return

    for ext_port, info in list(_active_upnp_mappings.items()):
        result = attempt_upnp_mapping(
            info["internal_port"], ext_port, UPNP_MAPPING_DURATION
        )
        if result:
            log.debug(f"UPnP mapping renewed: port {ext_port}/UDP")
        else:
            log.warning(f"UPnP mapping renewal failed: port {ext_port}/UDP")

def get_default_gateway_ip() -> str:
    """Get the default gateway — used to detect network changes."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select -First 1).NextHop"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip()
        else:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            parts = result.stdout.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def get_physical_ip() -> str:
    """
    Get this device's physical (non-WireGuard) LAN IP address.
    When a full-tunnel WireGuard is active, get_local_ip() may return
    the WG interface IP or route through the tunnel. This function
    explicitly finds the real physical adapter IP by querying the
    default gateway's interface.
    Caches the result to avoid spawning PowerShell on every STUN/holepunch call.
    Cache is invalidated on network change via invalidate_physical_ip_cache().
    """
    global _physical_ip_cache

    now = time.time()
    if _physical_ip_cache["ip"] and (now - _physical_ip_cache["timestamp"]) < _PHYSICAL_IP_CACHE_TTL:
        return _physical_ip_cache["ip"]

    ip = _discover_physical_ip()
    if ip:
        _physical_ip_cache = {"ip": ip, "timestamp": now}
    return ip


def invalidate_physical_ip_cache() -> None:
    """Clear the physical IP cache — call on network change."""
    global _physical_ip_cache
    _physical_ip_cache = {"ip": "", "timestamp": 0.0}


def _discover_physical_ip() -> str:
    """Internal: actually query the OS for the physical adapter IP."""
    try:
        if platform.system() == "Windows":
            # Use $PSItem instead of $_ to avoid Python 3.14 stripping the variable.
            # Exclude WireGuard adapters that may claim the default route.
            ps_script = (
                '$configs = Get-NetIPConfiguration | '
                'ForEach-Object { if ($PSItem.IPv4DefaultGateway -ne $null -and '
                '$PSItem.InterfaceDescription -notlike "*WireGuard*" -and '
                '$PSItem.InterfaceDescription -notlike "*wg_quantum*" -and '
                '$PSItem.InterfaceDescription -notlike "*wg_mesh*") '
                '{ $PSItem } }; '
                'if ($configs) { ($configs | Select-Object -First 1).IPv4Address.IPAddress }'
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout.strip()
            if output and not output.startswith("10.100.") and not output.startswith("10.200."):
                return output

            # Fallback: find a physical adapter by filtering Get-NetAdapter directly
            ps_fallback = (
                '$a = Get-NetAdapter | ForEach-Object { '
                'if ($PSItem.Status -eq "Up" -and '
                '$PSItem.InterfaceDescription -notlike "*WireGuard*") '
                '{ $PSItem } } | Select-Object -First 1; '
                'if ($a) { (Get-NetIPAddress -InterfaceIndex $a.ifIndex '
                '-AddressFamily IPv4 -ErrorAction SilentlyContinue | '
                'Select-Object -First 1).IPAddress }'
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_fallback],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout.strip()
            if output and not output.startswith("10.100.") and not output.startswith("10.200."):
                return output
        else:
            # Linux: get the source IP for the default route
            result = subprocess.run(
                ["ip", "route", "get", "1.1.1.1"],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout
            if "src " in output:
                src_ip = output.split("src ")[1].split()[0]
                if not src_ip.startswith("10.100.") and not src_ip.startswith("10.200."):
                    return src_ip
    except Exception as e:
        log.debug(f"get_physical_ip failed: {e}")

    # Fallback to get_local_ip() — may be WG IP but better than nothing
    return get_local_ip()

def _bind_physical(sock: socket.socket, port: int = 0) -> None:
    """
    Bind a UDP socket to the physical (non-WireGuard) interface.
    This ensures STUN queries and hole-punch packets go out on the real
    network adapter, bypassing the WireGuard full-tunnel (0.0.0.0/0) routing.

    If binding to the physical IP fails (e.g., no tunnel active, or can't
    determine the interface), falls back to default binding.
    """
    physical_ip = get_physical_ip()
    try:
        sock.bind((physical_ip, port))
        log.debug(f"Socket bound to physical interface: {physical_ip}:{port}")
    except OSError as e:
        log.debug(f"Failed to bind to {physical_ip}:{port}: {e} — using default")
        if port:
            try:
                sock.bind(("0.0.0.0", port))
            except OSError:
                pass  # Port in use, let OS pick

def generate_wireguard_keypair() -> tuple[str, str]:
    """Generate a WireGuard Curve25519 keypair."""
    try:
        if platform.system() == "Windows":
            wg_path = _find_wg_windows()
            result = subprocess.run([wg_path, "genkey"], capture_output=True, timeout=10)
            privkey = result.stdout.decode().strip()
            result = subprocess.run(
                [wg_path, "pubkey"], input=privkey.encode(), capture_output=True, timeout=10
            )
            pubkey = result.stdout.decode().strip()
        else:
            result = subprocess.run(["wg", "genkey"], capture_output=True, timeout=10)
            privkey = result.stdout.decode().strip()
            result = subprocess.run(
                ["wg", "pubkey"], input=privkey.encode(), capture_output=True, timeout=10
            )
            pubkey = result.stdout.decode().strip()
        return privkey, pubkey
    except FileNotFoundError:
        log.warning("wg command not found — install wireguard-tools")
        return "GENERATE_ME", "GENERATE_ME"


def _find_wg_windows() -> str:
    """Find the wg.exe path on Windows."""
    candidates = [
        r"C:\Program Files\WireGuard\wg.exe",
        r"C:\Program Files (x86)\WireGuard\wg.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    # Try PATH
    return "wg"

def _find_wireguard_windows() -> str:
    """Find wireguard.exe on Windows (the tunnel service manager, not wg.exe)."""
    candidates = [
        r"C:\Program Files\WireGuard\wireguard.exe",
        r"C:\Program Files (x86)\WireGuard\wireguard.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return "wireguard.exe"  # Last resort — hope it's in PATH

# ─── State Persistence ───────────────────────────────────────────────────────


def save_state(state: dict) -> None:
    """Save client state to disk so we survive restarts."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2))


def load_state() -> dict:
    """Load saved client state."""
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return {}


# ─── Endpoint Auto-Switching ─────────────────────────────────────────────────


def probe_lighthouse(url: str) -> bool:
    """Check if a Lighthouse URL is reachable."""
    try:
        resp = get_session().get(f"{url}/api/v1/health", timeout=ENDPOINT_PROBE_TIMEOUT)
        return resp.status_code == 200
    except Exception:
        return False


def select_lighthouse(public_url: str, local_url: str = None) -> tuple[str, bool]:
    """
    Pick the best Lighthouse endpoint.
    Returns (url, is_local).
    Tries local first — if it responds, we're on the home LAN.
    """
    if local_url:
        log.info(f"Probing local Lighthouse at {local_url}...")
        if probe_lighthouse(local_url):
            log.info("Local Lighthouse reachable — using LAN endpoint")
            return local_url, True
        log.info("Local Lighthouse not reachable — falling back to public")

    log.info(f"Using public Lighthouse at {public_url}")
    return public_url, False


def get_wireguard_endpoint(is_local: bool, public_url: str, local_url: str,
                           wg_port: int) -> str:
    """
    Determine the correct WireGuard endpoint based on network location.
    On LAN: use the Pi 4's local IP directly.
    Remote: use the public IP.
    """
    if is_local and local_url:
        # Extract IP from local_url (e.g., "http://YOUR_LIGHTHOUSE_IP:8443" → "YOUR_LIGHTHOUSE_IP")
        host = local_url.split("://")[1].split(":")[0]
        return f"{host}:{wg_port}"
    else:
        host = public_url.split("://")[1].split(":")[0]
        return f"{host}:{wg_port}"


# ─── Lighthouse Communication ────────────────────────────────────────────────


def register(lighthouse_url: str, wg_pubkey: str, lan_ip: str = None) -> dict:
    """Register this client with the Lighthouse."""
    client_id = get_client_id()

    # Detect public IP for cross-network mesh endpoint resolution
    public_ip = get_public_ip()
    if public_ip:
        log.info(f"Detected public IP: {public_ip}")

    # Phase 5C CL2: Load IPv6 token identity
    identity = _load_ipv6_token_identity()

    payload = {
        "device_id": client_id,
        "device_type": "client",
        "public_key": base64.b64encode(b"client-no-kem-key").decode(),
        "kem_algorithm": KEM_ALGORITHM,
        "ip_address": get_ipv6_address(),
        "wireguard_public_key": wg_pubkey,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "public_ip": public_ip,
        # Phase 5C: IPv6 deterministic identity
        "ipv6_token": identity["ipv6_token"],
        "ipv6_prefix": identity["ipv6_prefix"],
        "ipv6_token_addr": identity["ipv6_token_addr"],
    }

    if lan_ip:
        payload["lan_ip"] = lan_ip

    log.info(f"Registering with Lighthouse at {lighthouse_url}...")
    if identity["ipv6_token_addr"]:
        log.info(f"  IPv6 token identity: {identity['ipv6_token_addr']} (token: {identity['ipv6_token']})")
    resp = get_session().post(f"{lighthouse_url}/api/v1/register", json=payload, timeout=10)
    resp.raise_for_status()
    result = resp.json()

    log.info(f"Registered — VPN address: {result.get('vpn_address', 'unknown')}")
    return result

def discover_vault(lighthouse_url: str) -> dict:
    """Find the Vault in the peer directory."""
    resp = get_session().get(f"{lighthouse_url}/api/v1/peers", timeout=10)
    resp.raise_for_status()
    peers = resp.json()["peers"]

    vaults = [p for p in peers if p["device_type"] == "vault" and p["status"] == "online"]
    if not vaults:
        log.error("No online vault found in peer directory")
        return None

    vault = vaults[0]
    log.info(f"Found vault: {vault['device_id']}")
    return vault

def initiate_handshake(lighthouse_url: str, vault_device_id: str) -> dict:
    """Request a KEM handshake with the Vault."""
    client_id = get_client_id()

    payload = {
        "client_device_id": client_id,
        "target_device_id": vault_device_id,
    }

    log.info(f"Initiating KEM handshake with vault {vault_device_id}...")
    resp = get_session().post(
        f"{lighthouse_url}/api/v1/handshake/initiate",
        json=payload,
        timeout=15,
    )
    resp.raise_for_status()
    result = resp.json()

    log.info(f"Handshake complete: {result['request_id']}")
    log.info(f"Quantum PSK received ({result.get('status', 'unknown')})")
    return result

def fetch_vault_public_key(lighthouse_url: str) -> tuple[str, bytes]:
    """Fetch the Vault's ML-KEM public key from the Lighthouse."""
    log.info("Fetching Vault public key from Lighthouse...")
    resp = get_session().get(f"{lighthouse_url}/api/v1/vault/public-key", timeout=10)
    resp.raise_for_status()
    result = resp.json()

    vault_device_id = result["device_id"]
    public_key = base64.b64decode(result["public_key"])
    log.info(f"Got Vault public key ({len(public_key)}B) for device {vault_device_id}")
    return vault_device_id, public_key


def initiate_client_encap_handshake(lighthouse_url: str, vault_device_id: str,
                                     vault_pubkey: bytes) -> tuple[dict, str]:
    """
    Client-side KEM encapsulation — the shared secret is derived HERE,
    on this machine, not on the Lighthouse. The Lighthouse only relays
    the ciphertext to the Vault.

    NOTE: As of the HKDF binding update, the Vault derives the WG PSK by
    running HKDF over the shared secret with a context string that binds it
    to the client's WG pubkey + request_id. The client does not know that
    full info string in advance, so it accepts the PSK the Lighthouse returns
    (which the Lighthouse received from the Vault). TLS + cert pinning protect
    the PSK in transit. The locally-derived shared secret is wiped without
    being used as the PSK directly.

    Returns (handshake_result_dict, quantum_psk).
    """
    if oqs is None:
        raise RuntimeError(
            "liboqs-python required for client-side encapsulation. "
            "Install with: pip install liboqs-python"
        )

    client_id = get_client_id()

    # Perform encapsulation locally — proves the client controls a fresh KEM
    # exchange and prevents the Lighthouse from substituting its own ciphertext.
    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
    ciphertext, shared_secret = kem.encap_secret(vault_pubkey)

    # Wipe the locally-derived shared secret immediately. We're not using it
    # as the PSK directly — the Vault's HKDF-derived PSK is authoritative.
    secret_buf = bytearray(shared_secret)
    secure_wipe(secret_buf)

    log.info(f"Client-side KEM encapsulation complete ({len(ciphertext)}B ciphertext)")

    # Send ciphertext to Lighthouse for forwarding to Vault
    payload = {
        "client_device_id": client_id,
        "target_device_id": vault_device_id,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "kem_algorithm": KEM_ALGORITHM,
    }

    log.info("Sending ciphertext to Lighthouse for Vault decapsulation...")
    resp = get_session().post(
        f"{lighthouse_url}/api/v1/handshake/client-encap",
        json=payload,
        timeout=35,
    )
    resp.raise_for_status()
    result = resp.json()

    # The Lighthouse response includes the HKDF-derived PSK (via the Vault).
    # The client-encap endpoint sets the PSK in the handshake DB row but
    # currently does not echo it in the response body — check for it and
    # fall back to fetching the handshake status if needed.
    psk = result.get("quantum_psk", "")
    if not psk:
        # Fallback: query handshake status to get the PSK the Vault derived
        log.info("Fetching derived PSK from handshake status endpoint...")
        status_resp = get_session().get(
            f"{lighthouse_url}/api/v1/handshake/status/{result['request_id']}",
            timeout=10,
        )
        status_resp.raise_for_status()
        status = status_resp.json()
        psk = status.get("quantum_psk", "")

    if not psk:
        raise RuntimeError(
            f"client-encap handshake {result['request_id']} completed but "
            f"Lighthouse did not return a PSK"
        )

    log.info(f"Client-encap handshake complete: {result['request_id']}")
    log.info("PSK derived by Vault via HKDF binding")

    result["quantum_psk"] = psk
    return result, psk

def send_heartbeat(lighthouse_url: str) -> dict | bool:
    """Send a heartbeat to the Lighthouse. Returns response dict or False.
    Phase 4 M3: includes STUN endpoint + NAT type so the Lighthouse always has
    fresh NAT data per peer, not just at mesh request time.
    Phase 5C CL2: includes IPv6 token identity data.
    Uses a cache (STUN_CACHE_TTL) to avoid hitting STUN servers every 30s.
    """
    try:
        global _stun_cache
        now = time.time()

        # Only refresh STUN data if cache is expired
        if now - _stun_cache["timestamp"] >= STUN_CACHE_TTL:
            stun_endpoint = None
            nat_type = None
            try:
                result = stun_query(*STUN_SERVERS[0])
                if result:
                    pub_ip, mapped_port = result
                    stun_endpoint = f"{pub_ip}:{mapped_port}"
            except Exception:
                pass
            try:
                nat_type, _ = classify_nat_type(quiet=True)
            except Exception:
                pass

            _stun_cache = {
                "stun_endpoint": stun_endpoint,
                "nat_type": nat_type,
                "timestamp": now,
            }
            log.debug(f"STUN cache refreshed: endpoint={stun_endpoint}, nat={nat_type}")
        else:
            log.debug("STUN cache still fresh — reusing cached NAT data")

        # Phase 5C CL2: Load fresh IPv6 token identity
        identity = _load_ipv6_token_identity()

        payload = {
            "device_id": get_client_id(),
            "ip_address": get_local_ip(),
            "lan_ip": get_local_ip(),
            "public_ip": get_public_ip(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            # Phase 4 M3: fresh NAT data every heartbeat (cached)
            "stun_endpoint": _stun_cache["stun_endpoint"],
            "nat_type": _stun_cache["nat_type"],
            # Phase 5C CL2: IPv6 deterministic identity
            "ipv6_token": identity["ipv6_token"],
            "ipv6_prefix": identity["ipv6_prefix"],
            "ipv6_token_addr": identity["ipv6_token_addr"],
        }
        resp = get_session().post(
            f"{lighthouse_url}/api/v1/heartbeat",
            json=payload,
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
        return False
    except Exception as e:
        log.debug(f"Heartbeat failed: {e}")
        return False

def fetch_discovery_config(lighthouse_url: str) -> dict:
    """Fetch discovery settings and peer info from the Lighthouse."""
    try:
        resp = get_session().get(f"{lighthouse_url}/api/v1/discovery/config", timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


# ─── Mesh Networking ────────────────────────────────────────────────────────


def fetch_pending_mesh_requests(lighthouse_url: str) -> list:
    """Check for pending mesh tunnel requests targeting this client."""
    try:
        client_id = get_client_id()
        resp = get_session().get(
            f"{lighthouse_url}/api/v1/mesh/pending/{client_id}", timeout=5
        )
        if resp.status_code == 200:
            return resp.json().get("pending", [])
    except Exception as e:
        log.debug(f"Mesh pending check failed: {e}")
    return []

def fetch_online_clients(lighthouse_url: str) -> list:
    """Fetch all online client peers from the Lighthouse."""
    try:
        resp = get_session().get(f"{lighthouse_url}/api/v1/peers", timeout=5)
        if resp.status_code == 200:
            peers = resp.json().get("peers", [])
            client_id = get_client_id()
            return [
                p for p in peers
                if p["device_type"] == "client"
                and p["device_id"] != client_id
                and p["status"] == "online"
            ]
    except Exception as e:
        log.debug(f"Failed to fetch online clients: {e}")
    return []


def request_mesh_tunnel(lighthouse_url: str, target_device_id: str,
                         wg_pubkey: str, wg_listen_port: int = MESH_WG_LISTEN_PORT,
                         peer_is_lan: bool = False) -> dict:
    """Request a mesh tunnel with another client through the Lighthouse.
    If peer_is_lan=True, uses LAN-only candidates (skips ~8s STUN).
    Otherwise uses pre-warmed cached candidates when available.
    """
    client_id = get_client_id()
    public_ip = get_public_ip()

    # Collect candidates: LAN-only fast path or cached full path
    if peer_is_lan:
        candidates = collect_lan_only_candidates(wg_listen_port)
    else:
        candidates = collect_endpoint_candidates_cached(wg_listen_port)

    nat_type = NAT_TYPE_UNKNOWN
    for c in candidates:
        if c.get("nat_type"):
            nat_type = c["nat_type"]
            break

    payload = {
        "initiator_device_id": client_id,
        "target_device_id": target_device_id,
        "initiator_wg_pubkey": wg_pubkey,
        "initiator_lan_ip": get_local_ip(),
        "initiator_public_ip": public_ip,
        "initiator_wg_listen_port": wg_listen_port,
        # Phase 1: multi-candidate NAT traversal fields
        "initiator_candidates": json.dumps(candidates),
        "initiator_nat_type": nat_type,
    }
    log.info(f"Requesting mesh tunnel with {target_device_id} ({len(candidates)} candidates, NAT: {nat_type})...")
    resp = get_session().post(
        f"{lighthouse_url}/api/v1/mesh/request", json=payload, timeout=10
    )
    resp.raise_for_status()
    return resp.json()

def accept_mesh_tunnel(lighthouse_url: str, request_id: str,
                        wg_pubkey: str, wg_listen_port: int = MESH_WG_LISTEN_PORT,
                        peer_is_lan: bool = False) -> dict:
    """Accept a pending mesh tunnel request.
    If peer_is_lan=True, uses LAN-only candidates (skips ~8s STUN).
    Otherwise uses pre-warmed cached candidates when available.
    """
    client_id = get_client_id()
    public_ip = get_public_ip()

    # Collect candidates: LAN-only fast path or cached full path
    if peer_is_lan:
        candidates = collect_lan_only_candidates(wg_listen_port)
    else:
        candidates = collect_endpoint_candidates_cached(wg_listen_port)

    nat_type = NAT_TYPE_UNKNOWN
    for c in candidates:
        if c.get("nat_type"):
            nat_type = c["nat_type"]
            break

    payload = {
        "request_id": request_id,
        "acceptor_device_id": client_id,
        "acceptor_wg_pubkey": wg_pubkey,
        "acceptor_lan_ip": get_local_ip(),
        "acceptor_public_ip": public_ip,
        "acceptor_wg_listen_port": wg_listen_port,
        # Phase 1: multi-candidate NAT traversal fields
        "acceptor_candidates": json.dumps(candidates),
        "acceptor_nat_type": nat_type,
    }
    log.info(f"Accepting mesh tunnel {request_id} ({len(candidates)} candidates, NAT: {nat_type})...")
    resp = get_session().post(
        f"{lighthouse_url}/api/v1/mesh/accept", json=payload, timeout=10
    )
    resp.raise_for_status()
    return resp.json()

def poll_mesh_status(lighthouse_url: str, request_id: str,
                      timeout: float = 60.0) -> dict | None:
    """Poll until a mesh tunnel request is accepted or times out."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = get_session().get(
                f"{lighthouse_url}/api/v1/mesh/status/{request_id}", timeout=5
            )
            if resp.status_code == 200:
                result = resp.json()
                if result["status"] == "active":
                    return result
        except Exception:
            pass
        time.sleep(3)
    return None

def update_mesh_candidates(lighthouse_url: str, request_id: str,
                           candidates_json: str, nat_type: str) -> bool:
    """Phase 4 M4: Push fresh candidate data for an existing active tunnel.
    Called when path monitor detects a stale handshake and re-collects candidates.
    """
    try:
        payload = {
            "device_id": get_client_id(),
            "request_id": request_id,
            "candidates": candidates_json,
            "nat_type": nat_type,
        }
        resp = get_session().post(
            f"{lighthouse_url}/api/v1/mesh/update-candidates",
            json=payload,
            timeout=5,
        )
        if resp.status_code == 200:
            log.info(f"Updated candidates for tunnel {request_id}")
            return True
        log.warning(f"Update candidates failed: {resp.status_code}")
        return False
    except Exception as e:
        log.debug(f"Update candidates failed: {e}")
        return False


def fetch_peer_latest_candidates(lighthouse_url: str, request_id: str,
                                  peer_device_id: str) -> list[dict] | None:
    """Phase 4 M2: Fetch the peer's latest candidates from the Lighthouse.
    Passes our device_id so the Lighthouse returns the OTHER side's candidates,
    regardless of whether we are the initiator or target.
    """
    try:
        my_device_id = get_client_id()
        resp = get_session().get(
            f"{lighthouse_url}/api/v1/mesh/status/{request_id}",
            params={"device_id": my_device_id},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            candidates_json = data.get("peer_candidates")
            if candidates_json:
                return json.loads(candidates_json) if isinstance(candidates_json, str) else candidates_json
    except Exception as e:
        log.debug(f"Fetch peer candidates failed: {e}")
    return None

def generate_mesh_wireguard_keypair() -> tuple[str, str]:
    """Generate a separate WireGuard keypair for mesh tunnels."""
    return generate_wireguard_keypair()

def _rewrite_mesh_conf(mesh_conf_path: Path, wg_privkey: str,
                        listen_port: int, my_mesh_ip: str,
                        existing_peers: dict) -> None:
    """Write the full wg_mesh.conf from current peer state."""
    config = (
        "[Interface]\n"
        f"PrivateKey = {wg_privkey}\n"
        f"ListenPort = {listen_port}\n"
    )
    if my_mesh_ip:
        config += f"Address = {my_mesh_ip}/32\n"

    for pubkey, peer_info in existing_peers.items():
        allowed_ip = peer_info.get("allowed_ip", peer_info.get("vpn_address", ""))
        config += (
            "\n[Peer]\n"
            f"PublicKey = {pubkey}\n"
            f"PresharedKey = {peer_info['psk']}\n"
            f"Endpoint = {peer_info['endpoint']}\n"
            f"AllowedIPs = {allowed_ip}/32\n"
            "PersistentKeepalive = 25\n"
        )
    mesh_conf_path.write_text(config)
    try:
        os.chmod(mesh_conf_path, 0o600)
    except Exception:
        pass


def apply_mesh_peer(peer_wg_pubkey: str, peer_endpoint: str,
                     peer_vpn_address: str, psk: str,
                     wg_privkey: str, listen_port: int = MESH_WG_LISTEN_PORT,
                     my_mesh_ip: str = "", peer_mesh_ip: str = "",
                     peer_candidates: list[dict] = None) -> bool:
    """
    Add or update a mesh peer on the mesh WireGuard interface.

    Uses separate mesh IPs (10.200.0.x) for Address and AllowedIPs to avoid
    routing conflicts with the main wg_quantum tunnel (10.100.0.0/24).

    On Windows: uses 'wg set' for live PSK updates (no service restart needed),
    and only reinstalls the tunnel service for initial peer setup.
    On Linux: uses 'wg set' to add/update peers dynamically.
    """
    # Phase 1: Multi-candidate hole punching
    if peer_candidates:
        all_endpoints = [c["endpoint"] for c in peer_candidates if c.get("endpoint")]
        if all_endpoints:
            log.info(f"Hole punching {len(all_endpoints)} candidate endpoints before WG config...")
            send_holepunch_burst(all_endpoints, listen_port)
            time.sleep(2)

    iface = "wg_mesh"
    mesh_conf_path = CONFIG_DIR / "wg_mesh.conf"
    mesh_peers_path = DATA_DIR / "mesh_peers.json"

    # Determine the AllowedIPs — use mesh IP if available, fall back to VPN address
    peer_allowed_ip = peer_mesh_ip or peer_vpn_address

    # Load existing mesh peers from disk
    existing_peers = {}
    if mesh_peers_path.exists():
        try:
            existing_peers = json.loads(mesh_peers_path.read_text())
        except Exception:
            pass

    # Check if this is a rekey of an existing peer or a brand new peer.
    # Match by mesh_ip or vpn_address — pubkey changes on every rekey so
    # we can't use it as the identity key here.
    is_existing_peer = peer_wg_pubkey in existing_peers
    old_pubkey = None
    if not is_existing_peer:
        for pk, info in existing_peers.items():
            if (peer_mesh_ip and info.get("mesh_ip") == peer_mesh_ip) or \
               (peer_vpn_address and info.get("vpn_address") == peer_vpn_address):
                # Same peer, new pubkey — rekey detected, remove stale entry
                old_pubkey = pk
                is_existing_peer = True
                break

    if old_pubkey:
        del existing_peers[old_pubkey]

    # Add/update the peer under the current pubkey
    existing_peers[peer_wg_pubkey] = {
        "endpoint": peer_endpoint,
        "vpn_address": peer_vpn_address,
        "mesh_ip": peer_mesh_ip,
        "allowed_ip": peer_allowed_ip,
        "psk": psk,
    }

    # Save peers to disk so they survive restarts
    mesh_peers_path.write_text(json.dumps(existing_peers, indent=2))

    if platform.system() == "Windows":
        wg_dir = r"C:\Program Files\WireGuard"
        wg_exe = os.path.join(wg_dir, "wg.exe")
        if not os.path.exists(wg_exe):
            wg_exe = "wg"
        wireguard_exe = os.path.join(wg_dir, "wireguard.exe")
        if not os.path.exists(wireguard_exe):
            wireguard_exe = "wireguard.exe"

        # Check if the tunnel service is already running
        check = subprocess.run(
            ["sc", "query", f"WireGuardTunnel${iface}"],
            capture_output=True, text=True,
        )
        tunnel_running = "RUNNING" in check.stdout

        if tunnel_running and is_existing_peer:
            # PSK rekey on existing peer — use 'wg set' for live update,
            # no service restart needed, no admin required for set operation
            import tempfile
            psk_file = Path(tempfile.gettempdir()) / "cobratail_psk.tmp"
            try:
                psk_file.write_text(psk)
                # If this is a rekey, remove the old pubkey from WireGuard first
                if old_pubkey:
                    subprocess.run(
                        [wg_exe, "set", iface, "peer", old_pubkey, "remove"],
                        capture_output=True, text=True, timeout=10,
                    )
                result = subprocess.run(
                    [wg_exe, "set", iface,
                     "peer", peer_wg_pubkey,
                     "preshared-key", str(psk_file),
                     "endpoint", peer_endpoint,
                     "allowed-ips", f"{peer_allowed_ip}/32",
                     "persistent-keepalive", "25"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    _rewrite_mesh_conf(mesh_conf_path, wg_privkey, listen_port,
                                       my_mesh_ip, existing_peers)
                    log.info(f"Mesh peer updated via wg set: {peer_wg_pubkey[:20]}... -> {peer_allowed_ip} via {peer_endpoint}")
                    return True
                else:
                    log.warning(f"wg set failed ({result.stderr.strip()}), falling back to tunnel reinstall")
            except Exception as e:
                log.warning(f"wg set failed ({e}), falling back to tunnel reinstall")
            finally:
                psk_file.unlink(missing_ok=True)

        # Full tunnel reinstall — for new peers or if wg set failed
        _rewrite_mesh_conf(mesh_conf_path, wg_privkey, listen_port,
                           my_mesh_ip, existing_peers)

        try:
            subprocess.run(
                [wireguard_exe, "/uninstalltunnelservice", iface],
                capture_output=True, timeout=10,
            )
            time.sleep(3)

            for _ in range(5):
                check = subprocess.run(
                    [wireguard_exe, "/uninstalltunnelservice", iface],
                    capture_output=True, text=True, timeout=5,
                )
                stderr = (check.stderr or "").lower()
                if "not found" in stderr or "not installed" in stderr or \
                   "already" not in stderr:
                    break
                time.sleep(1)
        except Exception:
            pass

        try:
            subprocess.run(
                [wireguard_exe, "/installtunnelservice", str(mesh_conf_path)],
                check=True, capture_output=True, timeout=15,
            )
            log.info(f"Mesh peer added: {peer_wg_pubkey[:20]}... -> {peer_allowed_ip} via {peer_endpoint}")
            return True
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode() if e.stderr else str(e)
            if "already" in stderr.lower():
                log.warning("Tunnel service still running — forcing restart...")
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/FI", f"SERVICES eq WireGuardTunnel$wg_mesh"],
                        capture_output=True, timeout=10,
                    )
                    time.sleep(3)
                    subprocess.run(
                        [wireguard_exe, "/uninstalltunnelservice", iface],
                        capture_output=True, timeout=10,
                    )
                    time.sleep(2)
                    subprocess.run(
                        [wireguard_exe, "/installtunnelservice", str(mesh_conf_path)],
                        check=True, capture_output=True, timeout=15,
                    )
                    log.info(f"Mesh peer added (after forced restart): {peer_wg_pubkey[:20]}... -> {peer_allowed_ip} via {peer_endpoint}")
                    return True
                except Exception as e2:
                    log.error(f"Failed to force restart mesh tunnel: {e2}")
                    return False
            else:
                log.error(f"Failed to install mesh tunnel service: {stderr}")
                return False
        except FileNotFoundError:
            log.error("wireguard.exe not found — install WireGuard from https://www.wireguard.com/install/")
            return False

def _mesh_interface_is_up(iface: str = "wg_mesh") -> bool:
    """Check if the mesh WireGuard interface is running."""
    try:
        if platform.system() == "Windows":
            wg_path = _find_wg_windows()
            result = subprocess.run(
                [wg_path, "show", iface], capture_output=True, timeout=5
            )
        else:
            result = subprocess.run(
                ["sudo", "wg", "show", iface], capture_output=True, timeout=5
            )
        return result.returncode == 0
    except Exception:
        return False


def send_kem_relay(lighthouse_url: str, sender_id: str, target_id: str,
                   msg_type: str, payload: dict) -> bool:
    """Send a KEM handshake message to a peer via the Lighthouse relay."""
    try:
        data = {
            "sender_device_id": sender_id,
            "target_device_id": target_id,
            "msg_type": msg_type,
            "payload": base64.b64encode(json.dumps(payload).encode()).decode(),
        }
        resp = get_session().post(
            f"{lighthouse_url}/api/v1/kem-relay/send", json=data, timeout=10
        )
        return resp.status_code == 200
    except Exception as e:
        log.debug(f"KEM relay send failed: {e}")
        return False


def poll_kem_relay(lighthouse_url: str, device_id: str) -> list[dict]:
    """Poll the Lighthouse for pending KEM relay messages."""
    try:
        resp = get_session().get(
            f"{lighthouse_url}/api/v1/kem-relay/poll/{device_id}", timeout=5
        )
        if resp.status_code == 200:
            messages = resp.json().get("messages", [])
            # Decode the base64 payloads
            for m in messages:
                try:
                    m["payload"] = json.loads(base64.b64decode(m["payload"]).decode())
                except Exception:
                    pass
            return messages
    except Exception as e:
        log.debug(f"KEM relay poll failed: {e}")
    return []

# ─── Direct Peer KEM Exchange (Zero-Trust Mesh) ────────────────────────────


class PeerKEMExchange:
    """
    Direct ML-KEM-1024 key exchange between two mesh peers.

    Once a mesh tunnel is up (brokered by the Lighthouse), both peers run
    this protocol over their encrypted VPN connection to derive a new PSK
    that only they know. The Lighthouse and Vault are never involved.

    Protocol (over TCP on PEER_KEM_PORT via mesh VPN IPs):
      1. Initiator connects to responder's VPN IP
      2. Initiator sends: {"type": "kem_hello", "public_key": <base64 ML-KEM pubkey>}
      3. Responder performs encap_secret(initiator_pubkey) locally
      4. Responder sends: {"type": "kem_ciphertext", "ciphertext": <base64>}
      5. Initiator performs decap_secret(ciphertext) to get shared secret
      6. Both sides derive identical PSK — neither the Lighthouse nor Vault saw it
      7. Both sides update their mesh WireGuard peer with the new PSK

    Tie-breaking: If both peers try to initiate simultaneously, the peer with
    the lexicographically lower device_id becomes the initiator, the other
    becomes the responder. The responder closes its outbound connection and
    waits for the initiator.
    """

    def __init__(self, service: 'QuantumVPNService'):
        self.service = service
        self._server_socket = None
        self._running = False
        self._completed_exchanges = {}   # device_id → timestamp of last exchange
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the KEM exchange listener on the mesh VPN interface."""
        if oqs is None:
            log.info("Direct peer KEM exchange disabled (liboqs not available)")
            return

        self._running = True

        # Ensure firewall allows inbound connections on the KEM port
        self._ensure_firewall_rule()

        listener = threading.Thread(target=self._listen_loop, daemon=True)
        listener.start()
        log.info(f"Direct peer KEM exchange listener started on port {PEER_KEM_PORT}")

    @staticmethod
    def _ensure_firewall_rule() -> None:
        """Add a Windows Firewall rule for the peer KEM exchange port if needed."""
        if platform.system() != "Windows":
            return
        rule_name = "Quantum VPN - Peer KEM Exchange"
        try:
            # Check if rule already exists
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={rule_name}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and rule_name in result.stdout:
                log.debug("Firewall rule for peer KEM exchange already exists")
                return

            # Add inbound TCP rule
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}",
                 "dir=in", "action=allow", "protocol=TCP",
                 f"localport={PEER_KEM_PORT}",
                 "profile=any",
                 "description=Allow direct ML-KEM-1024 key exchange between mesh peers"],
                capture_output=True, text=True, timeout=10,
            )
            log.info(f"Added firewall rule for peer KEM exchange (TCP port {PEER_KEM_PORT})")
        except Exception as e:
            log.warning(f"Could not add firewall rule for port {PEER_KEM_PORT}: {e}")
            log.warning("You may need to manually allow TCP port 9876 in Windows Firewall")

    def stop(self) -> None:
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None

    def initiate_exchange(self, peer_device_id: str, peer_vpn_address: str,
                          peer_wg_pubkey: str, peer_endpoint: str,
                          is_rekey: bool = False) -> None:
        """
        Start a direct KEM exchange with a mesh peer in a background thread.
        Called after a mesh tunnel is successfully established, or periodically
        for re-keying active mesh tunnels.
        """
        if oqs is None:
            log.debug("Skipping direct KEM exchange (liboqs not available)")
            return

        with self._lock:
            if peer_device_id in self._completed_exchanges and not is_rekey:
                log.debug(f"Already completed KEM exchange with {peer_device_id}")
                return

        t = threading.Thread(
            target=self._do_initiate,
            args=(peer_device_id, peer_vpn_address, peer_wg_pubkey, peer_endpoint),
            daemon=True,
        )
        t.start()

    def _do_initiate(self, peer_device_id: str, peer_vpn_address: str,
                     peer_wg_pubkey: str, peer_endpoint: str) -> None:
        """Background thread: attempt direct KEM exchange as initiator.
        Tries direct TCP first (LAN peers), falls back to Lighthouse relay (remote peers)."""
        # Wait for the mesh tunnel to stabilize
        time.sleep(PEER_KEM_EXCHANGE_DELAY)

        my_device_id = get_client_id()

        # Tie-breaking: lower device_id initiates, higher waits
        if my_device_id > peer_device_id:
            log.info(f"Peer KEM: {peer_device_id} has priority — waiting as responder")
            return  # The other peer will connect to us

        # Determine the best IP to reach the peer for the KEM exchange.
        # On LAN: use the peer's LAN IP from the mesh endpoint (avoids
        # routing conflict where wg_quantum claims the entire 10.100.0.0/24).
        # Remote: try mesh IP first (10.200.0.x routes through wg_mesh),
        # then LAN IP, then relay if unreachable.
        connect_ip = peer_vpn_address
        is_lan_peer = False

        if peer_endpoint and ":" in peer_endpoint:
            endpoint_ip = peer_endpoint.split(":")[0]
            if (endpoint_ip.startswith("192.168.") or
                endpoint_ip.startswith("172.")):
                # Clearly a LAN IP — use it directly
                connect_ip = endpoint_ip
                is_lan_peer = True
            elif endpoint_ip.startswith("10.100."):
                # Remote peer — endpoint is a VPN IP through the main tunnel.
                # For the KEM exchange, use the peer's mesh IP (10.200.0.x)
                # which routes through wg_mesh without conflicting with wg_quantum.
                peer_mesh_ip = self._get_peer_mesh_ip(peer_device_id)
                if peer_mesh_ip:
                    connect_ip = peer_mesh_ip
                    log.debug(f"Peer KEM: using mesh IP {peer_mesh_ip} for {peer_device_id}")
                else:
                    # No mesh IP yet — use the VPN address and hope for the best,
                    # or fall back to relay
                    connect_ip = peer_vpn_address

        log.info(f"Peer KEM: initiating exchange with {peer_device_id} ({connect_ip})")

        # Generate a fresh ML-KEM keypair just for this exchange
        kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
        my_kem_pubkey = kem.generate_keypair()
        my_kem_privkey = kem.export_secret_key()

        # Try direct TCP connection first (works for LAN peers and
        # remote peers with port 9876 reachable via mesh tunnel)
        direct_success = self._try_direct_initiate(
            peer_device_id, connect_ip, my_device_id,
            my_kem_pubkey, my_kem_privkey, peer_wg_pubkey,
            peer_endpoint, peer_vpn_address,
        )

        if direct_success:
            return

        # Direct connection failed — fall back to Lighthouse relay.
        # This works for remote peers across different networks/NATs
        # where direct TCP isn't possible. The Lighthouse only sees
        # opaque KEM public keys and ciphertext — it cannot derive
        # the shared secret.
        if not is_lan_peer and self.service.lighthouse_url:
            log.info(f"Peer KEM: direct TCP failed, falling back to Lighthouse relay")
            self._try_relay_initiate(
                peer_device_id, my_device_id,
                my_kem_pubkey, my_kem_privkey, peer_wg_pubkey,
                peer_endpoint, peer_vpn_address,
            )
        else:
            log.info(f"Peer KEM: {peer_device_id} not reachable yet — will retry on next cycle")


    def _try_direct_initiate(self, peer_device_id: str, connect_ip: str,
                             my_device_id: str, my_kem_pubkey: bytes,
                             my_kem_privkey: bytes, peer_wg_pubkey: str,
                             peer_endpoint: str, peer_vpn_address: str) -> bool:
        """Attempt direct TCP KEM exchange. Returns True on success."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PEER_KEM_TIMEOUT)
            sock.connect((connect_ip, PEER_KEM_PORT))

            # Send our KEM public key
            hello = json.dumps({
                "type": "kem_hello",
                "device_id": my_device_id,
                "public_key": base64.b64encode(my_kem_pubkey).decode(),
                "kem_algorithm": KEM_ALGORITHM,
            }).encode()
            sock.sendall(struct.pack(">I", len(hello)) + hello)

            # Receive ciphertext from responder
            resp_data = self._recv_message(sock)
            if not resp_data or resp_data.get("type") != "kem_ciphertext":
                log.warning(f"Peer KEM: unexpected response from {peer_device_id}")
                sock.close()
                return False

            ciphertext = base64.b64decode(resp_data["ciphertext"])

            # Decapsulate to get the shared secret
            kem_decap = oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=my_kem_privkey)
            shared_secret = kem_decap.decap_secret(ciphertext)
            secret_buf = bytearray(shared_secret)
            psk_buf = bytearray(base64.b64encode(secret_buf))
            secure_wipe(secret_buf)
            new_psk = psk_buf.decode()
            secure_wipe(psk_buf)

            # Send confirmation
            confirm = json.dumps({
                "type": "kem_confirm",
                "device_id": my_device_id,
                "status": "complete",
            }).encode()
            sock.sendall(struct.pack(">I", len(confirm)) + confirm)
            sock.close()

            log.info(f"Peer KEM: direct exchange complete with {peer_device_id}")
            log.info(f"Peer KEM: new PSK derived — Lighthouse never saw it")

            self._apply_new_psk(peer_wg_pubkey, peer_endpoint,
                                peer_vpn_address, new_psk)

            with self._lock:
                self._completed_exchanges[peer_device_id] = time.time()
            return True

        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            log.info(f"Peer KEM: direct TCP to {peer_device_id} failed ({e})")
            return False
        except Exception as e:
            log.warning(f"Peer KEM: direct exchange error with {peer_device_id}: {e}")
            return False

    def _try_relay_initiate(self, peer_device_id: str, my_device_id: str,
                            my_kem_pubkey: bytes, my_kem_privkey: bytes,
                            peer_wg_pubkey: str, peer_endpoint: str,
                            peer_vpn_address: str) -> None:
        """Attempt KEM exchange via Lighthouse relay. Used for remote peers."""
        lighthouse_url = self.service.lighthouse_url

        try:
            # Step 1: Send our KEM public key via relay
            hello_payload = {
                "type": "kem_hello",
                "device_id": my_device_id,
                "public_key": base64.b64encode(my_kem_pubkey).decode(),
                "kem_algorithm": KEM_ALGORITHM,
            }
            sent = send_kem_relay(lighthouse_url, my_device_id,
                                  peer_device_id, "kem_hello", hello_payload)
            if not sent:
                log.warning(f"Peer KEM relay: failed to send kem_hello to {peer_device_id}")
                return

            log.info(f"Peer KEM relay: sent kem_hello to {peer_device_id}, waiting for ciphertext...")

            # Step 2: Poll for the ciphertext response
            deadline = time.time() + PEER_KEM_TIMEOUT
            ciphertext_msg = None
            while time.time() < deadline:
                messages = poll_kem_relay(lighthouse_url, my_device_id)
                for m in messages:
                    if (m.get("sender_device_id") == peer_device_id and
                            m.get("msg_type") == "kem_ciphertext"):
                        ciphertext_msg = m.get("payload", {})
                        break
                if ciphertext_msg:
                    break
                time.sleep(1)

            if not ciphertext_msg:
                log.warning(f"Peer KEM relay: timed out waiting for ciphertext from {peer_device_id}")
                return

            ciphertext = base64.b64decode(ciphertext_msg["ciphertext"])

            # Step 3: Decapsulate to get the shared secret
            kem_decap = oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=my_kem_privkey)
            shared_secret = kem_decap.decap_secret(ciphertext)
            secret_buf = bytearray(shared_secret)
            psk_buf = bytearray(base64.b64encode(secret_buf))
            secure_wipe(secret_buf)
            new_psk = psk_buf.decode()
            secure_wipe(psk_buf)

            # Step 4: Send confirmation via relay
            confirm_payload = {
                "type": "kem_confirm",
                "device_id": my_device_id,
                "status": "complete",
            }
            send_kem_relay(lighthouse_url, my_device_id,
                           peer_device_id, "kem_confirm", confirm_payload)

            log.info(f"Peer KEM relay: exchange complete with {peer_device_id}")
            log.info(f"Peer KEM relay: new PSK derived — Lighthouse only saw opaque KEM data")

            self._apply_new_psk(peer_wg_pubkey, peer_endpoint,
                                peer_vpn_address, new_psk)

            with self._lock:
                self._completed_exchanges[peer_device_id] = time.time()

        except Exception as e:
            log.warning(f"Peer KEM relay: exchange failed with {peer_device_id}: {e}")

    def _listen_loop(self) -> None:
        """Listen for incoming KEM exchange connections from mesh peers."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to all interfaces — the mesh VPN IP will route here
            self._server_socket.bind(("0.0.0.0", PEER_KEM_PORT))
            self._server_socket.listen(5)
            self._server_socket.settimeout(2.0)

            while self._running:
                try:
                    conn, addr = self._server_socket.accept()
                    log.info(f"Peer KEM: incoming connection from {addr[0]}")
                    t = threading.Thread(
                        target=self._handle_incoming,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        except OSError:
            if self._running:
                log.error("Peer KEM listener socket error")
        except Exception as e:
            if self._running:
                log.error(f"Peer KEM listener failed: {e}")

    def _handle_incoming(self, conn: socket.socket, addr: tuple) -> None:
        """Handle an incoming KEM exchange as the responder."""
        try:
            conn.settimeout(PEER_KEM_TIMEOUT)

            # Receive the initiator's KEM public key
            msg = self._recv_message(conn)
            if not msg or msg.get("type") != "kem_hello":
                log.warning(f"Peer KEM: invalid hello from {addr[0]}")
                conn.close()
                return

            peer_device_id = msg["device_id"]
            peer_kem_pubkey = base64.b64decode(msg["public_key"])

            with self._lock:
                last_exchange = self._completed_exchanges.get(peer_device_id)
                if last_exchange and (time.time() - last_exchange) < MESH_REKEY_INTERVAL:
                    log.debug(f"Peer KEM: recently exchanged with {peer_device_id}")
                    conn.close()
                    return

            log.info(f"Peer KEM: performing encapsulation for {peer_device_id}")

            # Encapsulate against the initiator's public key
            kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
            ciphertext, shared_secret = kem.encap_secret(peer_kem_pubkey)
            secret_buf = bytearray(shared_secret)
            psk_buf = bytearray(base64.b64encode(secret_buf))
            secure_wipe(secret_buf)
            new_psk = psk_buf.decode()
            secure_wipe(psk_buf)

            # Send ciphertext back
            resp = json.dumps({
                "type": "kem_ciphertext",
                "device_id": get_client_id(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }).encode()
            conn.sendall(struct.pack(">I", len(resp)) + resp)

            # Wait for confirmation
            confirm = self._recv_message(conn)
            conn.close()

            if not confirm or confirm.get("type") != "kem_confirm":
                log.warning(f"Peer KEM: no confirmation from {peer_device_id}")
                return

            log.info(f"Peer KEM: direct exchange complete with {peer_device_id}")
            log.info(f"Peer KEM: new PSK derived — zero-trust achieved")

            # Find this peer's WG info and apply the new PSK
            peer_info = self._find_peer_info(peer_device_id)
            if peer_info:
                self._apply_new_psk(
                    peer_info["wg_pubkey"], peer_info["endpoint"],
                    peer_info["vpn_address"], new_psk,
                )

            with self._lock:
                self._completed_exchanges[peer_device_id] = time.time()

        except Exception as e:
            log.warning(f"Peer KEM: incoming exchange failed from {addr[0]}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_relay_messages(self) -> None:
        """Process incoming KEM relay messages (responder side for remote peers).
        Called periodically from the service loop."""
        if oqs is None or not self.service.lighthouse_url:
            return

        my_device_id = get_client_id()
        messages = poll_kem_relay(self.service.lighthouse_url, my_device_id)

        for msg in messages:
            sender_id = msg.get("sender_device_id", "")
            msg_type = msg.get("msg_type", "")
            payload = msg.get("payload", {})

            if msg_type == "kem_hello" and isinstance(payload, dict):
                # We're the responder — perform encapsulation and relay back
                threading.Thread(
                    target=self._handle_relay_hello,
                    args=(sender_id, payload),
                    daemon=True,
                ).start()

    def _handle_relay_hello(self, peer_device_id: str, payload: dict) -> None:
        """Handle a relayed kem_hello as the responder."""
        try:
            with self._lock:
                last_exchange = self._completed_exchanges.get(peer_device_id)
                if last_exchange and (time.time() - last_exchange) < MESH_REKEY_INTERVAL:
                    log.debug(f"Peer KEM relay: recently exchanged with {peer_device_id}")
                    return

            peer_kem_pubkey = base64.b64decode(payload["public_key"])
            log.info(f"Peer KEM relay: performing encapsulation for {peer_device_id}")

            # Encapsulate against the initiator's public key
            kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
            ciphertext, shared_secret = kem.encap_secret(peer_kem_pubkey)
            secret_buf = bytearray(shared_secret)
            psk_buf = bytearray(base64.b64encode(secret_buf))
            secure_wipe(secret_buf)
            new_psk = psk_buf.decode()
            secure_wipe(psk_buf)

            # Send ciphertext back via relay
            ct_payload = {
                "type": "kem_ciphertext",
                "device_id": get_client_id(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }
            sent = send_kem_relay(
                self.service.lighthouse_url, get_client_id(),
                peer_device_id, "kem_ciphertext", ct_payload,
            )
            if not sent:
                log.warning(f"Peer KEM relay: failed to send ciphertext to {peer_device_id}")
                return

            # Wait for confirmation via relay
            deadline = time.time() + PEER_KEM_TIMEOUT
            confirmed = False
            while time.time() < deadline:
                messages = poll_kem_relay(self.service.lighthouse_url, get_client_id())
                for m in messages:
                    if (m.get("sender_device_id") == peer_device_id and
                            m.get("msg_type") == "kem_confirm"):
                        confirmed = True
                        break
                if confirmed:
                    break
                time.sleep(1)

            if not confirmed:
                log.warning(f"Peer KEM relay: no confirmation from {peer_device_id}")
                return

            log.info(f"Peer KEM relay: exchange complete with {peer_device_id}")
            log.info(f"Peer KEM relay: new PSK derived — zero-trust achieved via relay")

            peer_info = self._find_peer_info(peer_device_id)
            if peer_info:
                self._apply_new_psk(
                    peer_info["wg_pubkey"], peer_info["endpoint"],
                    peer_info["vpn_address"], new_psk,
                )

            with self._lock:
                self._completed_exchanges[peer_device_id] = time.time()

        except Exception as e:
            log.warning(f"Peer KEM relay: responder exchange failed for {peer_device_id}: {e}")

    def _recv_message(self, sock: socket.socket) -> dict | None:
        """Receive a length-prefixed JSON message from a socket."""
        try:
            length_bytes = self._recv_exact(sock, 4)
            if not length_bytes:
                return None
            length = struct.unpack(">I", length_bytes)[0]
            if length > 65536:
                return None
            data = self._recv_exact(sock, length)
            if not data:
                return None
            return json.loads(data.decode())
        except Exception:
            return None

    def _recv_exact(self, sock: socket.socket, n: int) -> bytes | None:
        """Receive exactly n bytes from a socket."""
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _apply_new_psk(self, peer_wg_pubkey: str, peer_endpoint: str,
                       peer_vpn_address: str, new_psk: str) -> None:
        """Update the mesh WireGuard peer with the new directly-derived PSK.
        Preserves mesh IPs so the AllowedIPs don't revert from 10.200.0.x to 10.100.0.x.
        On Windows, retries if the tunnel service is still being released."""
        # Look up the mesh IP and my mesh IP so apply_mesh_peer uses the right AllowedIPs
        peer_mesh_ip = ""
        my_mesh_ip = ""
        for req_id, peer in self.service.mesh_peers.items():
            if peer.get("vpn_address") == peer_vpn_address or peer.get("endpoint") == peer_endpoint:
                peer_mesh_ip = peer.get("mesh_ip", "")
                break

        try:
            state = load_state()
            my_mesh_ip = state.get("mesh_ip", "")
        except Exception:
            pass

        # Retry loop for Windows service timing issues
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            success = apply_mesh_peer(
                peer_wg_pubkey, peer_endpoint, peer_vpn_address,
                new_psk, self.service.mesh_wg_privkey, MESH_WG_LISTEN_PORT,
                my_mesh_ip=my_mesh_ip, peer_mesh_ip=peer_mesh_ip,
            )
            if success:
                log.info(f"Peer KEM: mesh WireGuard updated with direct PSK for {peer_mesh_ip or peer_vpn_address}")
                # Wipe the PSK string now that it's been consumed by WireGuard
                psk_buf = bytearray(new_psk.encode())
                secure_wipe(psk_buf)
                return

            if attempt < max_attempts and platform.system() == "Windows":
                log.info(f"Peer KEM: retrying PSK apply (attempt {attempt}/{max_attempts})...")
                time.sleep(3)
            else:
                log.error(f"Peer KEM: failed to apply new PSK for {peer_mesh_ip or peer_vpn_address}")

    def _find_peer_info(self, device_id: str) -> dict | None:
        """Look up a mesh peer's WG info from our tracked peers."""
        mesh_peers_path = DATA_DIR / "mesh_peers.json"
        if not mesh_peers_path.exists():
            return None

        try:
            peers_data = json.loads(mesh_peers_path.read_text())
        except Exception:
            return None

        # Also check in-memory mesh_peers for device_id → vpn_address mapping
        for req_id, peer in self.service.mesh_peers.items():
            if peer.get("peer_id") == device_id:
                vpn_addr = peer.get("vpn_address", "")
                endpoint = peer.get("endpoint", "")
                mesh_ip = peer.get("mesh_ip", "")
                # Find the WG pubkey from mesh_peers.json
                for pubkey, info in peers_data.items():
                    if info.get("vpn_address") == vpn_addr or info.get("mesh_ip") == mesh_ip:
                        return {
                            "wg_pubkey": pubkey,
                            "endpoint": endpoint or info.get("endpoint", ""),
                            "vpn_address": vpn_addr,
                            "mesh_ip": mesh_ip or info.get("mesh_ip", ""),
                        }
        return None

    def _get_peer_mesh_ip(self, device_id: str) -> str:
        """Look up a mesh peer's 10.200.0.x mesh IP from our tracked peers."""
        for req_id, peer in self.service.mesh_peers.items():
            if peer.get("peer_id") == device_id:
                mesh_ip = peer.get("mesh_ip", "")
                if mesh_ip:
                    return mesh_ip
        return ""

    def reset_for_peer(self, device_id: str) -> None:
        """Allow re-exchange with a peer (e.g., after mesh tunnel re-establishment or rekey)."""
        with self._lock:
            self._completed_exchanges.pop(device_id, None)

    def get_rekey_eligible_peers(self) -> list:
        """Return device_ids whose last KEM exchange is older than MESH_REKEY_INTERVAL."""
        now = time.time()
        eligible = []
        with self._lock:
            for device_id, last_exchange in self._completed_exchanges.items():
                if now - last_exchange >= MESH_REKEY_INTERVAL:
                    eligible.append(device_id)
        return eligible

# ─── WireGuard Config ────────────────────────────────────────────────────────


def build_wireguard_config(handshake_result: dict, wg_privkey: str,
                           endpoint_override: str = None, is_local: bool = False) -> str:
    """Generate a WireGuard config file from handshake result.
    Uses split-tunnel routing — only VPN and mesh subnet traffic goes through
    WireGuard. Internet, STUN, and hole-punch traffic stays on the device's
    own connection. Full-tunnel exit-node routing will be a future opt-in
    feature where users select a specific peer to route through."""
    vpn_addr = handshake_result.get("vpn_address", "10.100.0.2")
    server_pubkey = handshake_result.get("server_public_key", "MISSING")
    endpoint = endpoint_override or handshake_result.get("server_endpoint", "MISSING:51820")
    dns_servers = handshake_result.get("dns", ["1.1.1.1"])
    psk = handshake_result.get("quantum_psk", "")

    # Split-tunnel: only route VPN and mesh subnet traffic through WireGuard.
    # All other traffic (internet, STUN, hole punching) goes direct.
    # This ensures NAT traversal works correctly on any network and avoids
    # funneling all internet traffic through the Lighthouse's bandwidth.
    # Full-tunnel exit-node routing (0.0.0.0/0) will be a future opt-in
    # feature where users select a specific peer to route traffic through.
    allowed_ips = "10.100.0.0/24"

    # Build config as bytearray so we can wipe the PSK from memory after use
    config = (
        "[Interface]\n"
        f"PrivateKey = {wg_privkey}\n"
        f"Address = {vpn_addr}/32\n"
        f"DNS = {', '.join(dns_servers)}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_pubkey}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {allowed_ips}\n"
        "PersistentKeepalive = 25\n"
    )

    # Wipe the PSK from the handshake dict now that it's embedded in the config
    if "quantum_psk" in handshake_result:
        handshake_result["quantum_psk"] = "WIPED"

    return config

def apply_wireguard_config(config_text: str) -> bool:
    """Write the WG config and bring up the tunnel.
    Wipes the config string from memory after writing to disk."""
    # Write config as bytes via bytearray so we can wipe after
    config_buf = bytearray(config_text.encode())
    WG_CONFIG_PATH.write_bytes(config_buf)
    secure_wipe(config_buf)

    # Note: os.chmod doesn't do much on Windows, but doesn't hurt.
    try:
        os.chmod(WG_CONFIG_PATH, 0o600)
    except Exception:
        pass

    log.info(f"WireGuard config written to {WG_CONFIG_PATH}")

    # Bring down existing tunnel if any
    _wireguard_down()

    # Pass the WG_CONFIG_PATH variable to bring the tunnel up
    return _wireguard_up(WG_CONFIG_PATH)

def _wireguard_up(config_path):
    log.info(f"Bringing up WireGuard tunnel using {config_path}...")
    try:
        if platform.system() == "Windows":
            wireguard_exe = _find_wireguard_windows()
            if not os.path.exists(wireguard_exe):
                log.error("wireguard.exe not found — install WireGuard from https://www.wireguard.com/install/")
                return False
            cmd = [wireguard_exe, "/installtunnelservice", str(config_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                err = result.stderr.lower()
                if "already" in err and ("installed" in err or "running" in err or "exists" in err):
                    log.info("WireGuard service is already installed and running.")
                    return True
                log.error(f"WG install failed: {result.stderr}")
                return False
        else:
            subprocess.run(["wg-quick", "up", str(config_path)], check=True)

        log.info("WireGuard tunnel UP")
        return True
    except Exception as e:
        log.error(f"WireGuard up failed: {e}")
        return False

def _wireguard_down():
    """Bring down the WireGuard tunnel."""
    log.info("Bringing down WireGuard tunnel...")
    interface_name = "wg_quantum"
    try:
        if platform.system() == "Windows":
            wireguard_exe = _find_wireguard_windows()
            subprocess.run([wireguard_exe, "/uninstalltunnelservice", interface_name],
                           capture_output=True)
            time.sleep(2)
            wg_path = _find_wg_windows()
            subprocess.run([wg_path, "setconf", interface_name, "NUL"], capture_output=True)
        else:
            subprocess.run(["wg-quick", "down", interface_name], capture_output=True)
    except Exception:
        pass  # Ignore errors if it's already down

def update_wireguard_endpoint(new_endpoint: str) -> bool:
    """Update the WireGuard peer endpoint without tearing down the tunnel."""
    try:
        state = load_state()
        server_pubkey = state.get("server_public_key", "")
        if not server_pubkey:
            log.warning("No server public key in state — cannot update endpoint")
            return False

        if platform.system() == "Windows":
            wg_path = _find_wg_windows()
            subprocess.run(
                [wg_path, "set", "wg_quantum", "peer", server_pubkey,
                 "endpoint", new_endpoint],
                check=True, capture_output=True, timeout=10,
            )
        else:
            subprocess.run(
                ["sudo", "wg", "set", "wg_quantum", "peer", server_pubkey,
                 "endpoint", new_endpoint],
                check=True, capture_output=True, timeout=10,
            )
        log.info(f"WireGuard endpoint updated to {new_endpoint}")
        return True
    except Exception as e:
        log.error(f"Failed to update WireGuard endpoint: {e}")
        return False


# ─── LAN Peer Discovery ─────────────────────────────────────────────────────


class LANDiscovery:
    """UDP broadcast-based LAN peer discovery."""

    def __init__(self, port: int = DISCOVERY_PORT):
        self.port = port
        self.lan_peers = {}  # device_id → {vpn_address, lan_ip, last_seen}
        self._lock = threading.Lock()
        self._running = False

    def start(self, vpn_address: str, device_id: str) -> None:
        """Start the discovery listener and broadcaster."""
        self._running = True
        self._vpn_address = vpn_address
        self._device_id = device_id

        listener = threading.Thread(target=self._listen_loop, daemon=True)
        listener.start()
        log.info(f"LAN discovery listening on UDP port {self.port}")

    def stop(self) -> None:
        self._running = False

    def broadcast(self) -> None:
        """Send a LAN discovery announcement."""
        try:
            msg = {
                "magic": DISCOVERY_MAGIC.decode(),
                "device_id": self._device_id,
                "vpn_address": self._vpn_address,
                "lan_ip": get_local_ip(),
                "timestamp": time.time(),
            }
            data = json.dumps(msg).encode()

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(data, ("255.255.255.255", self.port))
            sock.close()
        except Exception as e:
            log.debug(f"LAN broadcast failed: {e}")

    def get_lan_peers(self) -> dict:
        """Return a copy of discovered LAN peers."""
        with self._lock:
            # Prune stale peers (not seen in 90 seconds)
            now = time.time()
            self.lan_peers = {
                k: v for k, v in self.lan_peers.items()
                if now - v["last_seen"] < 90
            }
            return dict(self.lan_peers)

    def _listen_loop(self) -> None:
        """Background listener for LAN discovery broadcasts."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # SO_REUSEPORT not available on Windows
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass

            sock.bind(("", self.port))
            sock.settimeout(2.0)

            while self._running:
                try:
                    data, addr = sock.recvfrom(4096)
                    msg = json.loads(data.decode())

                    # Verify it's our protocol
                    if msg.get("magic") != DISCOVERY_MAGIC.decode():
                        continue

                    # Don't discover ourselves
                    if msg["device_id"] == self._device_id:
                        continue

                    with self._lock:
                        self.lan_peers[msg["device_id"]] = {
                            "vpn_address": msg["vpn_address"],
                            "lan_ip": msg.get("lan_ip", addr[0]),
                            "last_seen": time.time(),
                        }
                    log.debug(f"LAN peer discovered: {msg['device_id']} at {msg.get('lan_ip', addr[0])}")

                except socket.timeout:
                    continue
                except Exception as e:
                    log.debug(f"Discovery listener error: {e}")

        except Exception as e:
            log.error(f"Discovery listener failed to start: {e}")


# ─── Service Main Loop ──────────────────────────────────────────────────────


class QuantumVPNService:
    """Persistent VPN client service."""

    def __init__(self, public_url: str, local_url: str = None):
        self.public_url = public_url
        self.local_url = local_url
        self.lighthouse_url = None
        self.is_local = False
        self.connected = False
        self.wg_privkey = None
        self.wg_pubkey = None
        self.vpn_address = None
        self.wg_port = 51820
        self.last_gateway = None
        self.discovery = LANDiscovery()
        self._running = False
        # Mesh networking state
        self.mesh_wg_privkey = None
        self.mesh_wg_pubkey = None
        self.mesh_peers = {}  # request_id → {peer_id, vpn_address, ...}
        self._repunch_active: dict[str, bool] = {}  # peer_id → True if re-punch in progress
        self._mesh_pending_initiations = {}  # device_id → request_id (in-flight requests)
        self.auto_accept_mesh = True  # Auto-accept mesh requests from registered peers
        self.peer_kem = PeerKEMExchange(self)
        self._path_monitor_thread = None  # Phase 4: mesh path monitor thread
        # Resilience: exponential backoff tracking
        self._reconnect_delay = RECONNECT_DELAY  # Current backoff delay (resets on success)
        self._consecutive_failures = 0            # Count of consecutive reconnect failures

    def run(self) -> None:
        """Main service entry point."""
        self._running = True
        CLIENT_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        log.info("=" * 60)
        log.info("QUANTUM VPN CLIENT — Service Mode")
        log.info("=" * 60)
        log.info(f"Public endpoint:  {self.public_url}")
        log.info(f"Local endpoint:   {self.local_url or 'not configured'}")
        log.info(f"Client ID:        {get_client_id()}")
        log.info(f"Platform:         {platform.system()} {platform.release()}")
        log.info("=" * 60)

        # Load saved state (WG keys, VPN address) if we have them
        state = load_state()
        if state.get("wg_privkey") and state.get("wg_pubkey"):
            self.wg_privkey = state["wg_privkey"]
            self.wg_pubkey = state["wg_pubkey"]
            log.info("Loaded saved WireGuard keypair")
        else:
            self.wg_privkey, self.wg_pubkey = generate_wireguard_keypair()
            log.info("Generated new WireGuard keypair")

        # Load or generate mesh WireGuard keypair (separate from server tunnel)
        if state.get("mesh_wg_privkey") and state.get("mesh_wg_pubkey"):
            self.mesh_wg_privkey = state["mesh_wg_privkey"]
            self.mesh_wg_pubkey = state["mesh_wg_pubkey"]
            log.info("Loaded saved mesh WireGuard keypair")
        else:
            self.mesh_wg_privkey, self.mesh_wg_pubkey = generate_mesh_wireguard_keypair()
            log.info("Generated new mesh WireGuard keypair")

        # Initial connection with retry — don't enter service loop dead
        startup_delay = RECONNECT_DELAY
        while self._running and not self._full_connect():
            log.warning(f"Initial connection failed — retrying in {startup_delay:.0f}s...")
            time.sleep(startup_delay)
            startup_delay = min(startup_delay * RECONNECT_BACKOFF_FACTOR, RECONNECT_MAX_DELAY)

        if not self._running:
            return

        # Start LAN discovery if we have a VPN address
        if self.vpn_address:
            self.discovery.start(self.vpn_address, get_client_id())

        # Start the direct peer KEM exchange listener
        self.peer_kem.start()

        # Track current gateway for network change detection
        self.last_gateway = get_default_gateway_ip()

        # Phase 4: Start mesh path monitor background thread
        self._path_monitor_thread = threading.Thread(
            target=self._mesh_path_monitor, daemon=True, name="path-monitor"
        )
        self._path_monitor_thread.start()

        last_heartbeat = time.time()  # Grace period: skip immediate heartbeat after connect
        last_network_check = 0
        last_discovery_broadcast = 0
        last_mesh_check = 0
        last_rekey_check = 0
        last_candidate_warm = 0

        # Heartbeat jitter: randomize the interval each cycle so N clients
        # don't all hit the Lighthouse in the same second window
        next_heartbeat_interval = HEARTBEAT_INTERVAL + random.uniform(-HEARTBEAT_JITTER, HEARTBEAT_JITTER)

        log.info("Entering service loop...")

        try:
            while self._running:
                now = time.time()

                # Heartbeat to Lighthouse (with jitter)
                if now - last_heartbeat >= next_heartbeat_interval:
                    if self.lighthouse_url and self.connected:
                        hb_result = send_heartbeat(self.lighthouse_url)
                        if not hb_result:
                            log.warning("Heartbeat failed — connection may be lost")
                            self._handle_connection_loss()
                        else:
                            # Heartbeat succeeded — reset backoff state
                            if self._consecutive_failures > 0:
                                log.info(f"Connection stable — resetting backoff (was {self._reconnect_delay:.0f}s after {self._consecutive_failures} failures)")
                            self._reconnect_delay = RECONNECT_DELAY
                            self._consecutive_failures = 0

                            if isinstance(hb_result, dict):
                                if hb_result.get("pending_mesh_requests", 0) > 0:
                                    # Heartbeat told us there are pending mesh requests — check immediately
                                    self._process_pending_mesh()
                                # If a mesh peer pushed new candidates, re-punch immediately
                                if hb_result.get("peer_candidates_updated") and self.mesh_peers:
                                    log.info("Heartbeat: peer candidates updated — triggering re-punch")
                                    for req_id, p_info in list(self.mesh_peers.items()):
                                        threading.Thread(
                                            target=self._path_monitor_repunch,
                                            args=(req_id, p_info),
                                            daemon=True,
                                            name=f"hb-repunch-{req_id[:8]}",
                                        ).start()
                        # Phase 2 U7: Renew UPnP mappings on heartbeat
                        renew_upnp_mappings()
                    last_heartbeat = now
                    # Pick a fresh jittered interval for next cycle
                    next_heartbeat_interval = HEARTBEAT_INTERVAL + random.uniform(-HEARTBEAT_JITTER, HEARTBEAT_JITTER)

                # Network change detection
                if now - last_network_check >= NETWORK_CHECK_INTERVAL:
                    self._check_network_change()
                    last_network_check = now

                # LAN discovery broadcast
                if now - last_discovery_broadcast >= DISCOVERY_INTERVAL:
                    if self.vpn_address:
                        self.discovery.broadcast()
                        # After broadcasting, check if any discovered peers need mesh tunnels
                        if self.lighthouse_url and self.connected:
                            self._auto_mesh_with_lan_peers()
                    last_discovery_broadcast = now

                # Periodic mesh tunnel check (acceptor side) + KEM relay poll
                if now - last_mesh_check >= MESH_CHECK_INTERVAL:
                    if self.lighthouse_url and self.connected:
                        self._reconcile_mesh_state()
                        self._process_pending_mesh()
                        # Poll for relayed KEM messages (remote peer exchanges)
                        self.peer_kem._handle_relay_messages()
                    last_mesh_check = now

                # Pre-warm candidate cache in background so mesh requests are instant
                if now - last_candidate_warm >= CANDIDATE_WARM_INTERVAL:
                    if self.lighthouse_url and self.connected:
                        threading.Thread(
                            target=warm_candidate_cache,
                            daemon=True,
                            name="candidate-warm",
                        ).start()
                    last_candidate_warm = now

                # Periodic mesh PSK re-keying (peer-to-peer, no server involvement)
                if now - last_rekey_check >= MESH_REKEY_CHECK_INTERVAL:
                    if self.lighthouse_url and self.connected:
                        self._check_mesh_rekey()
                    last_rekey_check = now

                time.sleep(1)

        except KeyboardInterrupt:
            log.info("Service stopped by operator")
        finally:
            self._shutdown()

    def _full_connect(self) -> bool:
        """Complete connection flow: select endpoint → register + fetch vault key (parallel) → handshake → tunnel."""
        try:
            from concurrent.futures import ThreadPoolExecutor

            # If WireGuard tunnel is currently up with full-tunnel routing (0.0.0.0/0),
            # skip the LAN probe — it would succeed falsely because traffic routes
            # through the VPN to the Pi's LAN. Only probe LAN when tunnel is down.
            tunnel_is_up = self.connected
            if tunnel_is_up and not self.is_local:
                log.info(f"Using public Lighthouse at {self.public_url} (tunnel active, skipping LAN probe)")
                self.lighthouse_url = self.public_url
                self.is_local = False
            else:
                # Step 1: Select the best Lighthouse endpoint
                self.lighthouse_url, self.is_local = select_lighthouse(
                    self.public_url, self.local_url
                )

            lan_ip = get_local_ip()

            # Step 2: Register + fetch vault public key in parallel
            # These are independent API calls — running them concurrently
            # saves ~200-300ms on every connect.
            reg_result = None
            vault_result = None
            reg_error = None
            vault_error = None

            def _do_register():
                return register(self.lighthouse_url, self.wg_pubkey, lan_ip)

            def _do_fetch_vault_key():
                return fetch_vault_public_key(self.lighthouse_url)

            with ThreadPoolExecutor(max_workers=2) as pool:
                reg_future = pool.submit(_do_register)
                vault_future = pool.submit(_do_fetch_vault_key)

                try:
                    reg_result = reg_future.result(timeout=15)
                except Exception as e:
                    reg_error = e

                try:
                    vault_result = vault_future.result(timeout=15)
                except Exception as e:
                    vault_error = e

            if reg_error:
                raise reg_error

            self.vpn_address = reg_result.get("vpn_address")
            self.wg_port = int(reg_result.get("server_endpoint", ":51820").split(":")[-1])

            # Step 3: Client-side KEM encapsulation (v0.5.0) with retry
            handshake = None
            if vault_error is None and oqs is not None:
                vault_device_id, vault_pubkey = vault_result
                for encap_attempt in range(2):
                    try:
                        handshake, _ = initiate_client_encap_handshake(
                            self.lighthouse_url, vault_device_id, vault_pubkey
                        )
                        break  # Success
                    except Exception as e:
                        if encap_attempt == 0:
                            log.warning(f"Client-side encap attempt 1 failed ({e}), retrying in 2s...")
                            time.sleep(2)
                        else:
                            log.warning(f"Client-side encap attempt 2 failed ({e}), falling back to server-side")

            # Fallback to server-side encapsulation if client-side didn't produce a result
            if handshake is None:
                if vault_error:
                    log.warning(f"Vault key fetch failed ({vault_error}), using server-side encap")
                vault = discover_vault(self.lighthouse_url)
                if not vault:
                    log.error("No vault available — will retry")
                    return False
                handshake = initiate_handshake(self.lighthouse_url, vault["device_id"])

            # Step 4: Determine the correct WireGuard endpoint
            wg_endpoint = get_wireguard_endpoint(
                self.is_local, self.public_url, self.local_url, self.wg_port
            )

            # Step 5: Build and apply WireGuard config
            wg_config = build_wireguard_config(handshake, self.wg_privkey, wg_endpoint, self.is_local)
            tunnel_up = apply_wireguard_config(wg_config)

            if tunnel_up:
                self.connected = True

                # Step 6: Once tunnel is up with full routing (remote/public mode),
                # switch Lighthouse URL to the VPN-internal address.
                if not self.is_local:
                    api_port = 8443
                    if self.local_url:
                        try:
                            api_port = int(self.local_url.split(":")[-1])
                        except (ValueError, IndexError):
                            pass
                    vpn_server_ip = "10.100.0.1"
                    self.lighthouse_url = f"https://{vpn_server_ip}:{api_port}"
                    log.info(f"Switched Lighthouse URL to VPN-internal: {self.lighthouse_url}")

                log.info(f"Connected via {'LAN' if self.is_local else 'public'} endpoint")
                log.info(f"VPN address: {self.vpn_address}")
                log.info(f"WireGuard endpoint: {wg_endpoint}")
                log.info(f"Quantum PSK: {KEM_ALGORITHM}")

                # Save state for restarts
                save_state({
                    "wg_privkey": self.wg_privkey,
                    "wg_pubkey": self.wg_pubkey,
                    "mesh_wg_privkey": self.mesh_wg_privkey,
                    "mesh_wg_pubkey": self.mesh_wg_pubkey,
                    "vpn_address": self.vpn_address,
                    "lighthouse_url": self.lighthouse_url,
                    "is_local": self.is_local,
                    "server_public_key": handshake.get("server_public_key", ""),
                    "wg_endpoint": wg_endpoint,
                    "connected_at": datetime.now(timezone.utc).isoformat(),
                })
                return True
            else:
                log.error("Tunnel failed to come up")
                return False

        except Exception as e:
            log.error(f"Connection failed: {e}")
            return False

    def _check_network_change(self) -> None:
        """Detect if we've switched networks and re-evaluate endpoint."""
        current_gateway = get_default_gateway_ip()

        if current_gateway != self.last_gateway and self.last_gateway is not None:
            log.info(f"Network change detected: {self.last_gateway} → {current_gateway}")
            self.last_gateway = current_gateway

            # Force public IP refresh since network changed
            get_public_ip(force_refresh=True)

            # Invalidate STUN cache — NAT type may have changed with new network
            global _stun_cache
            _stun_cache["timestamp"] = 0
            log.info("STUN cache invalidated due to network change")
            invalidate_physical_ip_cache()

            # Re-probe and possibly switch endpoints
            new_url, new_is_local = select_lighthouse(self.public_url, self.local_url)

            if new_is_local != self.is_local:
                old_location = "LAN" if self.is_local else "remote"
                new_location = "LAN" if new_is_local else "remote"
                log.info(f"Switching endpoint: {old_location} → {new_location}")

                self.lighthouse_url = new_url
                self.is_local = new_is_local

                # Update WireGuard endpoint without full reconnect
                new_wg_endpoint = get_wireguard_endpoint(
                    self.is_local, self.public_url, self.local_url, self.wg_port
                )
                if update_wireguard_endpoint(new_wg_endpoint):
                    state = load_state()
                    state["is_local"] = self.is_local
                    state["lighthouse_url"] = self.lighthouse_url
                    state["wg_endpoint"] = new_wg_endpoint
                    save_state(state)
                else:
                    # Endpoint update failed — do a full reconnect
                    log.info("Endpoint update failed — doing full reconnect")
                    self._full_connect()

            # Immediately re-punch all mesh peers on ANY network change
            # Don't wait for the path monitor's 30s poll + 150s staleness threshold
            if self.mesh_peers:
                log.info(f"Network change: immediately re-punching {len(self.mesh_peers)} mesh peer(s)")
                for request_id, peer_info in list(self.mesh_peers.items()):
                    threading.Thread(
                        target=self._path_monitor_repunch,
                        args=(request_id, peer_info),
                        daemon=True,
                        name=f"netchange-repunch-{request_id[:8]}",
                    ).start()
        else:
            self.last_gateway = current_gateway

    def _handle_connection_loss(self) -> None:
        """Handle a lost connection to the Lighthouse with exponential backoff.
        Escalates: 10s → 20s → 40s → 60s → 120s (capped).
        Resets to base delay on successful reconnect.
        """
        self.connected = False
        self._consecutive_failures += 1

        delay = self._reconnect_delay
        log.info(f"Attempting reconnect in {delay:.0f}s (attempt #{self._consecutive_failures})...")
        time.sleep(delay)

        # Try to reconnect — endpoint might have changed
        if self._full_connect():
            log.info(f"Reconnected successfully after {self._consecutive_failures} attempt(s)")
            self._reconnect_delay = RECONNECT_DELAY
            self._consecutive_failures = 0
        else:
            # Escalate the backoff for next time, capped at RECONNECT_MAX_DELAY
            self._reconnect_delay = min(
                self._reconnect_delay * RECONNECT_BACKOFF_FACTOR,
                RECONNECT_MAX_DELAY,
            )
            log.warning(
                f"Reconnect failed — next attempt in {self._reconnect_delay:.0f}s "
                f"(will retry on next heartbeat cycle)"
            )

    def _shutdown(self) -> None:
        """Clean shutdown."""
        log.info("Shutting down VPN service...")
        self.discovery.stop()
        self.peer_kem.stop()
        self._running = False

        # Phase 2 U7: Release all UPnP port mappings
        if UPNP_ENABLED and _active_upnp_mappings:
            log.info("Releasing UPnP port mappings...")
            for ext_port in list(_active_upnp_mappings.keys()):
                release_upnp_mapping(ext_port)

        _wireguard_down()
        # Tear down mesh interface
        try:
            if platform.system() == "Windows":
                wg_dir = r"C:\Program Files\WireGuard"
                wireguard_exe = os.path.join(wg_dir, "wireguard.exe")
                if not os.path.exists(wireguard_exe):
                    wireguard_exe = "wireguard.exe"
                subprocess.run(
                    [wireguard_exe, "/uninstalltunnelservice", "wg_mesh"],
                    capture_output=True, timeout=10,
                )
            else:
                mesh_conf = CONFIG_DIR / "wg_mesh.conf"
                if mesh_conf.exists():
                    subprocess.run(
                        ["sudo", "wg-quick", "down", str(mesh_conf)],
                        capture_output=True, timeout=10,
                    )
        except Exception:
            pass
        log.info("VPN service stopped")

    def _process_pending_mesh(self) -> None:
        """Check for and auto-accept pending mesh tunnel requests."""
        try:
            pending = fetch_pending_mesh_requests(self.lighthouse_url)
            if not pending:
                return

            for req in pending:
                request_id = req["request_id"]
                initiator_id = req["initiator_id"]

                log.info(f"Pending mesh request from {initiator_id} ({request_id})")

                if self.auto_accept_mesh:
                    try:
                        # Detect if initiator is on the same LAN to skip STUN
                        initiator_lan_ip = req.get("initiator_lan_ip", "")
                        my_lan_ip = get_physical_ip()
                        peer_is_lan = False
                        if initiator_lan_ip and my_lan_ip:
                            # Same /24 subnet = same LAN
                            try:
                                init_parts = initiator_lan_ip.rsplit(".", 1)[0]
                                my_parts = my_lan_ip.rsplit(".", 1)[0]
                                peer_is_lan = (init_parts == my_parts)
                            except (ValueError, IndexError):
                                pass

                        result = accept_mesh_tunnel(
                            self.lighthouse_url, request_id,
                            self.mesh_wg_pubkey, MESH_WG_LISTEN_PORT,
                            peer_is_lan=peer_is_lan,
                        )

                        if result.get("status") == "active":
                            peer_pubkey = result["peer_wg_pubkey"]
                            peer_endpoint = result["peer_endpoint"]
                            peer_vpn = result["peer_vpn_address"]
                            psk = result["quantum_psk"]
                            my_mesh_ip = result.get("my_mesh_ip", "")
                            peer_mesh_ip = result.get("peer_mesh_ip", "")

                            # Save our mesh IP to state for restarts
                            if my_mesh_ip:
                                state = load_state()
                                state["mesh_ip"] = my_mesh_ip
                                save_state(state)

                            # Phase 1: Extract initiator's candidate list
                            peer_candidates = None
                            if result.get("peer_candidates"):
                                try:
                                    peer_candidates = json.loads(result["peer_candidates"]) if isinstance(result["peer_candidates"], str) else result["peer_candidates"]
                                except (json.JSONDecodeError, TypeError):
                                    pass

                            success = apply_mesh_peer(
                                peer_pubkey, peer_endpoint, peer_vpn,
                                psk, self.mesh_wg_privkey, MESH_WG_LISTEN_PORT,
                                my_mesh_ip=my_mesh_ip, peer_mesh_ip=peer_mesh_ip,
                                peer_candidates=peer_candidates,
                            )

                            if success:
                                self.mesh_peers[request_id] = {
                                    "peer_id": initiator_id,
                                    "vpn_address": peer_vpn,
                                    "mesh_ip": peer_mesh_ip,
                                    "endpoint": peer_endpoint,
                                    "peer_wg_pubkey": peer_pubkey,
                                }
                                log.info(f"Mesh tunnel active: {initiator_id} (mesh: {peer_mesh_ip or peer_vpn})")

                                # Initiate direct peer KEM exchange to replace
                                # Lighthouse-brokered PSK with zero-trust one
                                self.peer_kem.initiate_exchange(
                                    initiator_id, peer_vpn,
                                    peer_pubkey, peer_endpoint,
                                )

                                # Phase 1: Start background repunch monitor
                                self._start_background_repunch(
                                    peer_endpoint, peer_candidates, peer_pubkey,
                                )

                    except Exception as e:
                        log.warning(f"Failed to accept mesh tunnel {request_id}: {e}")

        except Exception as e:
            log.debug(f"Mesh check failed: {e}")

    def _reconcile_mesh_state(self) -> None:
        """
        Reconcile local mesh state with the Lighthouse.
        If the Lighthouse has no record of an active tunnel (e.g., peer restarted
        and re-registered, which clears stale tunnels), remove local state so
        auto-mesh can re-establish the connection.
        """
        if not self.mesh_peers or not self.lighthouse_url:
            return

        try:
            my_device_id = get_client_id()
            resp = get_session().get(
                f"{self.lighthouse_url}/api/v1/mesh/tunnels/{my_device_id}",
                timeout=5,
            )
            if resp.status_code != 200:
                return

            active_request_ids = {t["request_id"] for t in resp.json().get("tunnels", [])}

            stale = []
            for request_id, info in self.mesh_peers.items():
                if request_id not in active_request_ids:
                    stale.append(request_id)

            for request_id in stale:
                peer_id = self.mesh_peers[request_id].get("peer_id", "unknown")
                log.info(f"Mesh tunnel {request_id} with {peer_id} no longer on Lighthouse — clearing local state")
                del self.mesh_peers[request_id]

            # Also clean up pending initiations that reference gone peers
            gone_peers = {info["peer_id"] for rid, info in [(r, self.mesh_peers.get(r, {})) for r in stale] if info}
            for device_id in list(self._mesh_pending_initiations.keys()):
                if device_id in gone_peers:
                    del self._mesh_pending_initiations[device_id]

        except Exception as e:
            log.debug(f"Mesh state reconciliation failed: {e}")

    def _auto_mesh_with_lan_peers(self) -> None:
        """Automatically request mesh tunnels with discovered LAN and remote peers."""
        try:
            my_device_id = get_client_id()

            # Collect peers from both LAN discovery and the Lighthouse peer list
            peers_to_mesh = {}

            # LAN-discovered peers (already have LAN IP)
            lan_peers = self.discovery.get_lan_peers()
            for device_id, peer_info in lan_peers.items():
                peers_to_mesh[device_id] = {
                    "source": "lan",
                    "lan_ip": peer_info.get("lan_ip", ""),
                    "is_lan": True,
                }

            # Remote peers from Lighthouse (not already found on LAN)
            try:
                online_clients = fetch_online_clients(self.lighthouse_url)
                for peer in online_clients:
                    device_id = peer["device_id"]
                    if device_id not in peers_to_mesh:
                        peers_to_mesh[device_id] = {
                            "source": "lighthouse",
                            "lan_ip": "",
                            "is_lan": False,
                        }
            except Exception:
                pass  # LAN peers still work if Lighthouse fetch fails

            if not peers_to_mesh:
                return

            for device_id, peer_info in peers_to_mesh.items():
                # Tie-breaking: only the lower device_id initiates mesh requests.
                # The higher device_id waits for the incoming request and accepts it.
                # This prevents both peers from creating duplicate mesh requests.
                if my_device_id > device_id:
                    continue

                # Skip if we already have a mesh tunnel or pending request with this peer
                if any(m["peer_id"] == device_id for m in self.mesh_peers.values()):
                    continue
                if device_id in self._mesh_pending_initiations:
                    continue

                source = peer_info["source"]
                is_lan = peer_info["is_lan"]
                log.info(f"Peer {device_id} found via {source} -- requesting mesh tunnel")

                try:
                    result = request_mesh_tunnel(
                        self.lighthouse_url, device_id,
                        self.mesh_wg_pubkey, MESH_WG_LISTEN_PORT,
                        peer_is_lan=is_lan,
                    )
                    request_id = result.get("request_id", "")
                    if result.get("status") == "pending" and request_id:
                        self._mesh_pending_initiations[device_id] = request_id
                        log.info(f"Mesh request sent to {device_id}: {request_id}")

                        # Poll for acceptance in a background thread
                        t = threading.Thread(
                            target=self._poll_mesh_initiation,
                            args=(request_id, device_id),
                            daemon=True,
                        )
                        t.start()

                except Exception as e:
                    # Mark this peer as handled so we don't retry every cycle
                    self._mesh_pending_initiations[device_id] = "failed"
                    err_msg = str(e)
                    if "409" in err_msg or "already exists" in err_msg.lower():
                        log.debug(f"Mesh tunnel already exists with {device_id}")
                    else:
                        log.warning(f"Failed to request mesh tunnel with {device_id}: {e}")

        except Exception as e:
            log.debug(f"Auto-mesh check failed: {e}")

    def _check_mesh_rekey(self) -> None:
        """Check if any mesh tunnels need PSK re-keying via direct peer KEM exchange."""
        try:
            eligible = self.peer_kem.get_rekey_eligible_peers()
            if not eligible:
                return

            for device_id in eligible:
                # Find this peer's current mesh info
                peer_info = self.peer_kem._find_peer_info(device_id)
                if not peer_info:
                    log.debug(f"Rekey: no mesh info found for {device_id}, skipping")
                    continue

                log.info(f"Mesh re-key: initiating PSK rotation with {device_id}")

                # Reset the exchange state so initiate_exchange proceeds
                self.peer_kem.reset_for_peer(device_id)

                # Find the endpoint from our tracked mesh peers
                endpoint = peer_info.get("endpoint", "")
                vpn_address = peer_info.get("vpn_address", "")

                self.peer_kem.initiate_exchange(
                    device_id, vpn_address,
                    peer_info["wg_pubkey"], endpoint,
                    is_rekey=True,
                )

        except Exception as e:
            log.debug(f"Mesh rekey check failed: {e}")

    def _start_background_repunch(self, peer_endpoint: str,
                                  peer_candidates: list[dict] | None,
                                  peer_wg_pubkey: str) -> None:
        """
        After mesh tunnel is configured, start a background thread that monitors
        WireGuard handshake status and retries hole punching if needed.
        """
        if not peer_candidates:
            return

        def _repunch_loop():
            all_endpoints = [c["endpoint"] for c in peer_candidates if c.get("endpoint")]
            if not all_endpoints:
                return

            for delay in HOLEPUNCH_RETRY_DELAYS:
                time.sleep(delay)

                # Check if WireGuard shows a successful handshake
                try:
                    if platform.system() == "Windows":
                        wg_path = _find_wg_windows()
                        result = subprocess.run(
                            [wg_path, "show", "wg_mesh", "latest-handshakes"],
                            capture_output=True, timeout=5,
                        )
                    else:
                        result = subprocess.run(
                            ["sudo", "wg", "show", "wg_mesh", "latest-handshakes"],
                            capture_output=True, timeout=5,
                        )

                    if result.returncode == 0:
                        output = result.stdout.decode()
                        for line in output.strip().split("\n"):
                            parts = line.split("\t")
                            if len(parts) == 2 and parts[0].strip() == peer_wg_pubkey:
                                handshake_ts = int(parts[1].strip())
                                if handshake_ts > 0:
                                    log.info(f"Background repunch: handshake confirmed with {peer_wg_pubkey[:20]}...")
                                    return
                except Exception as e:
                    log.debug(f"Background repunch: handshake check failed: {e}")

                # No handshake yet — send another burst
                log.info(
                    f"Background repunch: no handshake after {delay}s, retrying burst to {len(all_endpoints)} endpoints")
                send_holepunch_burst(all_endpoints)

            log.warning(f"Background repunch: exhausted retries for {peer_wg_pubkey[:20]}... — may need relay fallback")

        t = threading.Thread(target=_repunch_loop, daemon=True)
        t.start()

    def _mesh_path_monitor(self) -> None:
        """Phase 4 M1/M2: Continuous path monitoring thread (magicsock-style).
        Periodically checks WireGuard handshake timestamps for all mesh peers.
        If a handshake is stale (NAT mapping expired, peer changed networks),
        re-collects candidates, pushes them to the Lighthouse, fetches peer's
        latest candidates, and re-punches.
        """
        log.info("Path monitor: started")
        while self._running:
            try:
                time.sleep(PATH_MONITOR_INTERVAL)
                if not self._running or not self.mesh_peers or not self.lighthouse_url:
                    continue

                # Read all mesh handshake timestamps in one call
                handshake_map = self._get_mesh_handshake_times()
                log.info(
                    f"Path monitor: checking {len(self.mesh_peers)} mesh peer(s), "
                    f"WG reports {len(handshake_map)} handshake(s)"
                )

                if not handshake_map:
                    log.info("Path monitor: no handshake data from WireGuard — wg_mesh may be down")
                    continue

                now = time.time()
                for request_id, peer_info in list(self.mesh_peers.items()):
                    peer_id = peer_info.get("peer_id", "unknown")
                    # Look up the pubkey from the handshake map by matching against
                    # what WireGuard knows — mesh_peers may not store peer_wg_pubkey
                    peer_wg_pubkey = peer_info.get("peer_wg_pubkey", "")

                    if not peer_wg_pubkey:
                        # Fallback: if only one peer in handshake_map, it's likely ours
                        if len(handshake_map) == 1:
                            peer_wg_pubkey = list(handshake_map.keys())[0]
                            log.debug(f"Path monitor: inferred pubkey for {peer_id} from WG: {peer_wg_pubkey[:20]}...")
                        else:
                            log.info(f"Path monitor: no pubkey stored for {peer_id} — skipping")
                            continue

                    last_hs = handshake_map.get(peer_wg_pubkey, 0)
                    if last_hs == 0:
                        log.info(f"Path monitor: {peer_id} handshake timestamp is 0 — peer may not have completed handshake yet")
                        continue

                    age = now - last_hs
                    if age < HANDSHAKE_STALE_THRESHOLD:
                        log.info(f"Path monitor: {peer_id} healthy — handshake {age:.0f}s ago")
                        continue

                    log.warning(
                        f"Path monitor: stale handshake for {peer_id} "
                        f"({peer_wg_pubkey[:20]}...) — {age:.0f}s old, threshold {HANDSHAKE_STALE_THRESHOLD}s"
                    )

                    # M2: Re-collect, push, fetch, re-punch
                    self._path_monitor_repunch(request_id, peer_info)

            except Exception as e:
                log.warning(f"Path monitor error: {e}")

        log.info("Path monitor: stopped")

    def _get_mesh_handshake_times(self) -> dict[str, float]:
        """Read WireGuard latest-handshakes for the mesh interface.
        Returns {pubkey: unix_timestamp} for all peers.
        """
        try:
            if platform.system() == "Windows":
                wg_path = _find_wg_windows()
                result = subprocess.run(
                    [wg_path, "show", "wg_mesh", "latest-handshakes"],
                    capture_output=True, timeout=5,
                )
            else:
                result = subprocess.run(
                    ["sudo", "wg", "show", "wg_mesh", "latest-handshakes"],
                    capture_output=True, timeout=5,
                )

            if result.returncode != 0:
                return {}

            handshakes = {}
            for line in result.stdout.decode().strip().split("\n"):
                parts = line.split("\t")
                if len(parts) == 2:
                    pubkey = parts[0].strip()
                    ts = int(parts[1].strip())
                    handshakes[pubkey] = float(ts)
            return handshakes

        except Exception as e:
            log.debug(f"Path monitor: failed to read handshakes: {e}")
            return {}

    def _path_monitor_repunch(self, request_id: str, peer_info: dict) -> None:
        """Phase 4 M2: Re-collect candidates, push to Lighthouse, fetch peer's
        latest candidates, and send hole-punch bursts. Retries up to
        PATH_MONITOR_MAX_RETRIES times with increasing delays.
        Also updates WireGuard mesh endpoint to peer's best fresh candidate.
        Guarded: only one re-punch per peer at a time.
        Graceful STUN degradation: if STUN fails completely, only punch
        non-STUN candidates (IPv6, LAN, UPnP, VPN-routed) instead of
        wasting time on stale port predictions.
        """
        peer_id = peer_info.get("peer_id", "unknown")
        peer_wg_pubkey = peer_info.get("peer_wg_pubkey", "")

        # Guard against concurrent re-punch for the same peer
        if self._repunch_active.get(peer_id):
            log.info(f"Path monitor: re-punch already active for {peer_id} — skipping")
            return
        self._repunch_active[peer_id] = True

        # Candidate types that are valid without any STUN data
        STUN_INDEPENDENT_TYPES = {"ipv6_token", "ipv6", "lan", "upnp", "vpn_routed"}

        try:
            for attempt, delay in enumerate(PATH_MONITOR_RETRY_DELAYS[:PATH_MONITOR_MAX_RETRIES], 1):
                if not self._running:
                    return

                log.info(f"Path monitor: re-punch attempt {attempt}/{PATH_MONITOR_MAX_RETRIES} for {peer_id}")

                try:
                    # Step 1: Re-collect fresh candidates (fresh STUN, fresh IPs)
                    fresh_candidates = collect_endpoint_candidates()
                    candidates_json = json.dumps(fresh_candidates)
                    nat_type = NAT_TYPE_UNKNOWN
                    stun_succeeded = False
                    for c in fresh_candidates:
                        if c.get("nat_type"):
                            nat_type = c["nat_type"]
                        if c.get("type") == "stun":
                            stun_succeeded = True
                    log.info(f"Path monitor: collected {len(fresh_candidates)} fresh candidates")

                    if not stun_succeeded:
                        log.info("Path monitor: STUN failed — will only punch non-STUN candidates")

                    # Step 2: Push our fresh candidates to the Lighthouse (M4)
                    update_mesh_candidates(
                        self.lighthouse_url, request_id,
                        candidates_json, nat_type,
                    )

                    # Step 3: Fetch peer's latest candidates from the Lighthouse
                    peer_candidates = fetch_peer_latest_candidates(
                        self.lighthouse_url, request_id, peer_id,
                    )

                    # Step 4: Hole-punch with combined endpoints
                    all_endpoints = []
                    if peer_candidates:
                        # Graceful STUN degradation: if our STUN failed,
                        # filter out the peer's STUN/predicted/public candidates too —
                        # our NAT mappings won't match so punching those is wasted effort
                        if stun_succeeded:
                            all_endpoints = [c["endpoint"] for c in peer_candidates if c.get("endpoint")]
                        else:
                            all_endpoints = [
                                c["endpoint"] for c in peer_candidates
                                if c.get("endpoint") and c.get("type") in STUN_INDEPENDENT_TYPES
                            ]
                            log.info(
                                f"Path monitor: filtered to {len(all_endpoints)} non-STUN endpoints "
                                f"(skipped {sum(1 for c in peer_candidates if c.get('type') not in STUN_INDEPENDENT_TYPES)} STUN-dependent)"
                            )

                        log.info(f"Path monitor: got {len(all_endpoints)} peer endpoints, punching...")

                        # Step 5: Update WireGuard mesh endpoint to the best fresh candidate
                        best_endpoint = self._pick_best_candidate_endpoint(peer_candidates)
                        if best_endpoint:
                            current_ep = peer_info.get("endpoint", "")
                            if best_endpoint != current_ep:
                                log.info(f"Path monitor: updating WG mesh endpoint: {current_ep} → {best_endpoint}")
                                self._update_mesh_wg_endpoint(peer_wg_pubkey, best_endpoint)
                                peer_info["endpoint"] = best_endpoint
                    else:
                        # Fallback: use whatever endpoint WireGuard currently has
                        current_ep = peer_info.get("endpoint", "")
                        if current_ep:
                            all_endpoints = [current_ep]
                        log.info(f"Path monitor: no peer candidates, punching current endpoint")

                    if all_endpoints:
                        send_holepunch_burst(all_endpoints)

                except Exception as e:
                    log.warning(f"Path monitor: re-punch attempt {attempt} failed: {e}")

                # Wait, then check if handshake recovered
                time.sleep(delay)

                handshake_map = self._get_mesh_handshake_times()
                last_hs = handshake_map.get(peer_wg_pubkey, 0)
                if last_hs > 0 and (time.time() - last_hs) < HANDSHAKE_STALE_THRESHOLD:
                    log.info(f"Path monitor: handshake recovered for {peer_id} after attempt {attempt}")
                    return

            log.warning(
                f"Path monitor: exhausted {PATH_MONITOR_MAX_RETRIES} retries for {peer_id} "
                f"— path may need relay fallback"
            )
        finally:
            self._repunch_active.pop(peer_id, None)

    def _pick_best_candidate_endpoint(self, candidates: list[dict]) -> str | None:
        """Pick the best endpoint from a candidate list.
        Priority: IPv6 > UPnP > STUN > public > LAN > VPN-routed.
        """
        priority_order = ["ipv6", "upnp", "stun", "public", "lan", "vpn_routed"]
        for ptype in priority_order:
            for c in candidates:
                if c.get("type") == ptype and c.get("endpoint"):
                    return c["endpoint"]
        # Fallback: return first candidate with an endpoint
        for c in candidates:
            if c.get("endpoint"):
                return c["endpoint"]
        return None

    def _update_mesh_wg_endpoint(self, peer_wg_pubkey: str, new_endpoint: str) -> bool:
        """Update WireGuard mesh peer endpoint without tearing down the tunnel."""
        try:
            if platform.system() == "Windows":
                wg_path = _find_wg_windows()
                result = subprocess.run(
                    [wg_path, "set", "wg_mesh", "peer", peer_wg_pubkey,
                     "endpoint", new_endpoint],
                    capture_output=True, timeout=5,
                )
            else:
                result = subprocess.run(
                    ["sudo", "wg", "set", "wg_mesh", "peer", peer_wg_pubkey,
                     "endpoint", new_endpoint],
                    capture_output=True, timeout=5,
                )

            if result.returncode == 0:
                log.info(f"Path monitor: WG mesh endpoint updated to {new_endpoint}")
                return True
            else:
                log.warning(f"Path monitor: WG endpoint update failed: {result.stderr.decode().strip()}")
                return False
        except Exception as e:
            log.warning(f"Path monitor: WG endpoint update error: {e}")
            return False

    def _poll_mesh_initiation(self, request_id: str, peer_device_id: str) -> None:
        """Background thread: poll until our mesh request is accepted, then configure WG."""
        try:
            tunnel = poll_mesh_status(self.lighthouse_url, request_id, timeout=120)

            if tunnel and tunnel.get("status") == "active":
                my_mesh_ip = tunnel.get("my_mesh_ip", "")
                peer_mesh_ip = tunnel.get("peer_mesh_ip", "")

                # Save our mesh IP to state for restarts
                if my_mesh_ip:
                    state = load_state()
                    state["mesh_ip"] = my_mesh_ip
                    save_state(state)

                # Phase 1: Extract peer's candidate list from tunnel response
                peer_candidates = None
                if tunnel.get("peer_candidates"):
                    try:
                        peer_candidates = json.loads(tunnel["peer_candidates"]) if isinstance(tunnel["peer_candidates"], str) else tunnel["peer_candidates"]
                    except (json.JSONDecodeError, TypeError):
                        pass

                success = apply_mesh_peer(
                    tunnel["peer_wg_pubkey"],
                    tunnel["peer_endpoint"],
                    tunnel["peer_vpn_address"],
                    tunnel["quantum_psk"],
                    self.mesh_wg_privkey,
                    MESH_WG_LISTEN_PORT,
                    my_mesh_ip=my_mesh_ip,
                    peer_mesh_ip=peer_mesh_ip,
                    peer_candidates=peer_candidates,
                )

                if success:
                    self.mesh_peers[request_id] = {
                        "peer_id": peer_device_id,
                        "vpn_address": tunnel["peer_vpn_address"],
                        "mesh_ip": peer_mesh_ip,
                        "endpoint": tunnel["peer_endpoint"],
                        "peer_wg_pubkey": tunnel["peer_wg_pubkey"],
                    }
                    log.info(f"Mesh tunnel active with {peer_device_id} (mesh: {peer_mesh_ip or tunnel['peer_vpn_address']})")

                    # Initiate direct peer KEM exchange to replace the
                    # Lighthouse-brokered PSK with a zero-trust one
                    self.peer_kem.initiate_exchange(
                        peer_device_id,
                        tunnel["peer_vpn_address"],
                        tunnel["peer_wg_pubkey"],
                        tunnel["peer_endpoint"],
                    )

                    # Phase 1: Start background repunch monitor
                    self._start_background_repunch(
                        tunnel["peer_endpoint"],
                        peer_candidates,
                        tunnel["peer_wg_pubkey"],
                    )
                else:
                    self.mesh_peers[request_id] = {
                        "peer_id": peer_device_id,
                        "vpn_address": tunnel.get("peer_vpn_address", ""),
                        "endpoint": tunnel.get("peer_endpoint", ""),
                        "peer_wg_pubkey": tunnel.get("peer_wg_pubkey", ""),
                        "failed": True,
                    }
                    log.warning(f"Mesh tunnel accepted but WG config failed for {peer_device_id}")
            else:
                log.info(f"Mesh request {request_id} timed out or rejected")

        except Exception as e:
            log.warning(f"Mesh poll failed for {request_id}: {e}")
        finally:
            # Clean up pending tracking regardless of outcome
            self._mesh_pending_initiations.pop(peer_device_id, None)

# ─── One-Shot Connect (Legacy) ───────────────────────────────────────────────


def connect(lighthouse_url: str) -> None:
    """One-shot connection flow for manual use."""
    CLIENT_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    log.info("=" * 50)
    log.info("QUANTUM VPN CLIENT — One-Shot Connect")
    log.info("=" * 50)

    wg_privkey, wg_pubkey = generate_wireguard_keypair()

    reg = register(lighthouse_url, wg_pubkey)

    # Try client-side encap (v0.5.0), fall back to server-side
    try:
        vault_device_id, vault_pubkey = fetch_vault_public_key(lighthouse_url)
        handshake, _ = initiate_client_encap_handshake(
            lighthouse_url, vault_device_id, vault_pubkey
        )
    except Exception as e:
        log.warning(f"Client-side encap failed ({e}), falling back to server-side")
        vault = discover_vault(lighthouse_url)
        if not vault:
            sys.exit(1)
        handshake = initiate_handshake(lighthouse_url, vault["device_id"])

    wg_config = build_wireguard_config(handshake, wg_privkey)

    WG_CONFIG_PATH.write_text(wg_config)
    os.chmod(WG_CONFIG_PATH, 0o600)
    log.info(f"WireGuard config written to: {WG_CONFIG_PATH}")
    log.info(f"VPN address: {handshake.get('vpn_address', 'unknown')}")
    log.info(f"Server endpoint: {handshake.get('server_endpoint', 'unknown')}")
    log.info(f"PresharedKey: quantum-resistant ({KEM_ALGORITHM})")
    log.info("")
    log.info("To connect:")
    log.info(f"  sudo wg-quick up {WG_CONFIG_PATH}")

# ─── Entry Point ─────────────────────────────────────────────────────────────

def _do_enroll(args) -> None:
    """
    Enroll this device with the Lighthouse using a one-time token.
    Saves the device_id and cert fingerprint permanently so subsequent
    'service' runs use the enrolled identity automatically.
    """
    token = args.token
    lighthouse_url = args.lighthouse_public or args.lighthouse

    if not token:
        print("ERROR: --token is required for enrollment")
        print("Get a token from the Lighthouse operator:")
        print("  (on Lighthouse) python lighthouse.py add-node <node_name>")
        sys.exit(1)

    if not lighthouse_url:
        print("ERROR: --lighthouse-public is required for enrollment")
        sys.exit(1)

    print()
    print("  COBRA NODE ENROLLMENT")
    print("  " + "=" * 40)
    print(f"  Lighthouse: {lighthouse_url}")
    print(f"  Token:      {token[:8]}...{token[-8:]}")
    print()

    # Call enroll endpoint (no cert pinning yet — we're getting the fingerprint)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        resp = requests.post(
            f"{lighthouse_url}/api/v1/enroll",
            json={
                "token": token,
                "hostname": socket.gethostname(),
            },
            verify=False,
            timeout=15,
        )
    except requests.ConnectionError:
        print(f"  ERROR: Cannot reach Lighthouse at {lighthouse_url}")
        print(f"  Check the URL and make sure the Lighthouse is running.")
        sys.exit(1)

    if resp.status_code == 410:
        print(f"  ERROR: Token expired!")
        print(f"  Ask the Lighthouse operator to generate a new one.")
        sys.exit(1)
    elif resp.status_code == 409:
        print(f"  ERROR: Token already used!")
        print(f"  Each token can only be used once.")
        sys.exit(1)
    elif resp.status_code == 403:
        print(f"  ERROR: Invalid token!")
        sys.exit(1)
    elif resp.status_code != 200:
        print(f"  ERROR: Enrollment failed (HTTP {resp.status_code})")
        try:
            print(f"  {resp.json().get('detail', resp.text)}")
        except Exception:
            print(f"  {resp.text}")
        sys.exit(1)

    result = resp.json()
    device_id = result["device_id"]
    node_name = result["node_name"]
    fingerprint = result.get("cert_fingerprint", "")
    lh_public = result.get("lighthouse_public", lighthouse_url)
    lh_local = result.get("lighthouse_local", "")

    # Save enrollment data permanently
    CLIENT_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    enrollment_data = {
        "device_id": device_id,
        "node_name": node_name,
        "cert_fingerprint": fingerprint,
        "lighthouse_public": lh_public,
        "lighthouse_local": lh_local,
        "enrolled_at": datetime.now(timezone.utc).isoformat(),
    }
    ENROLLMENT_PATH.write_text(json.dumps(enrollment_data, indent=2))

    # Also save fingerprint to standard location
    if fingerprint:
        save_fingerprint(fingerprint)

    # Write device_id to legacy path for compatibility
    CLIENT_ID_PATH.write_text(device_id)

    print(f"  Enrolled successfully!")
    print()
    print(f"  Node name:        {node_name}")
    print(f"  Device ID:        {device_id}")
    if fingerprint:
        print(f"  Cert fingerprint: {fingerprint[:16]}...")
    print(f"  Lighthouse:       {lh_public}")
    print()
    print(f"  Enrollment saved to: {ENROLLMENT_PATH}")
    print()
    print(f"  Start the client with:")
    print()
    cmd = f"    python client.py service --lighthouse-public {lh_public}"
    if lh_local:
        cmd += f" \\\n      --lighthouse-local {lh_local}"
    print(cmd)
    print()

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Quantum VPN Client")
    parser.add_argument("command", choices=["service", "connect", "status", "discover", "mesh", "enroll"])

    parser.add_argument(
        "--lighthouse",
        default="https://<lighthouse-public-ip>:<external-port>",
        help="Lighthouse public URL",
    )
    parser.add_argument(
        "--lighthouse-public",
        default="https://<lighthouse-public-ip>:<external-port>",
        help="Lighthouse public URL (for service mode)",
    )
    parser.add_argument(
        "--lighthouse-local",
        default="https://<lighthouse-local-ip>:<internal-port>",
        help="Lighthouse local LAN URL (for service mode)",
    )
    parser.add_argument(
        "--cert-fingerprint",
        default="",
        help="SHA-256 fingerprint of Lighthouse TLS cert (MITM protection)",
    )
    parser.add_argument(
        "--enable-upnp",
        action="store_true",
        default=False,
        help="Enable UPnP/NAT-PMP port mapping for better NAT traversal",
    )
    parser.add_argument(
        "--token",
        default="",
        help="One-time enrollment token (for enroll command)",
    )

    args = parser.parse_args()

    # Load enrollment data if it exists (auto-fills fingerprint + URLs)
    _enrollment = {}
    if ENROLLMENT_PATH.exists():
        try:
            _enrollment = json.loads(ENROLLMENT_PATH.read_text())
        except (json.JSONDecodeError, IOError):
            pass

    # Initialize TLS pinning — enrollment fingerprint takes priority
    global CERT_FINGERPRINT, _session
    CERT_FINGERPRINT = (
        args.cert_fingerprint
        or _enrollment.get("cert_fingerprint", "")
        or load_fingerprint()
    )
    if CERT_FINGERPRINT:
        save_fingerprint(CERT_FINGERPRINT)
        log.info(f"Cert fingerprint: {CERT_FINGERPRINT[:16]}...")
    _session = create_pinned_session(CERT_FINGERPRINT)

    # Phase 2 U6: Enable UPnP if requested
    global UPNP_ENABLED
    if args.enable_upnp:
        UPNP_ENABLED = True
        log.info("UPnP port mapping: ENABLED")

    # Helper: resolve a URL arg — returns empty string if it's still a placeholder
    def _resolve_url(arg_val, enrollment_key):
        if arg_val and "://<" not in arg_val:
            return arg_val
        return _enrollment.get(enrollment_key, "")

    # ── enroll command (must run before service/connect) ──
    if args.command == "enroll":
        _do_enroll(args)
        return

    if args.command == "service":
        public_url = _resolve_url(args.lighthouse_public, "lighthouse_public")
        local_url = _resolve_url(args.lighthouse_local, "lighthouse_local")

        if not public_url:
            print("ERROR: No Lighthouse URL configured.")
            print("  Either enroll first:  python client.py enroll --token <TOKEN> --lighthouse-public <URL>")
            print("  Or pass it directly:  python client.py service --lighthouse-public https://<ip>:<port>")
            sys.exit(1)

        svc = QuantumVPNService(
            public_url=public_url,
            local_url=local_url,
        )
        svc.run()

    elif args.command == "connect":
        lighthouse_url = _resolve_url(args.lighthouse, "lighthouse_public")
        if not lighthouse_url:
            print("ERROR: No Lighthouse URL. Enroll first or pass --lighthouse <URL>")
            sys.exit(1)
        connect(lighthouse_url)

    elif args.command == "status":
        state = load_state()
        if state:
            print(f"Client ID:      {get_client_id()}")
            print(f"VPN address:    {state.get('vpn_address', 'unknown')}")
            print(f"Lighthouse:     {state.get('lighthouse_url', 'unknown')}")
            print(f"Local network:  {state.get('is_local', 'unknown')}")
            print(f"WG endpoint:    {state.get('wg_endpoint', 'unknown')}")
            print(f"Connected at:   {state.get('connected_at', 'unknown')}")
        else:
            print("No saved state — client has not connected yet")

        lighthouse_url = _resolve_url(args.lighthouse, "lighthouse_public")
        if lighthouse_url:
            try:
                resp = get_session().get(f"{lighthouse_url}/api/v1/health", timeout=5)
                print(f"\nLighthouse:     {json.dumps(resp.json(), indent=2)}")
            except Exception:
                print(f"\nLighthouse at {lighthouse_url} not reachable")

    elif args.command == "mesh":
        public_url = _resolve_url(args.lighthouse_public, "lighthouse_public")
        local_url = _resolve_url(args.lighthouse_local, "lighthouse_local")
        lighthouse_url = public_url or _resolve_url(args.lighthouse, "lighthouse_public")

        if not lighthouse_url:
            print("ERROR: No Lighthouse URL. Enroll first or pass --lighthouse-public <URL>")
            sys.exit(1)

        svc_url, _ = select_lighthouse(lighthouse_url, local_url)

        # List available peers
        try:
            resp = get_session().get(f"{svc_url}/api/v1/peers", timeout=10)
            peers = resp.json()["peers"]
            clients = [p for p in peers if p["device_type"] == "client"
                       and p["device_id"] != get_client_id()
                       and p["status"] == "online"]

            if not clients:
                print("No other online clients found")
                sys.exit(0)

            print("Available peers:")
            for i, p in enumerate(clients):
                print(f"  [{i}] {p['device_id']} — VPN: {p['vpn_address']}")

            choice = int(input("\nSelect peer number: "))
            target = clients[choice]

            # Generate mesh keys and request tunnel
            mesh_priv, mesh_pub = generate_mesh_wireguard_keypair()
            result = request_mesh_tunnel(svc_url, target["device_id"], mesh_pub)
            print(f"Mesh request sent: {result['request_id']}")
            print("Waiting for peer to accept...")

            tunnel = poll_mesh_status(svc_url, result["request_id"], timeout=120)
            if tunnel and tunnel["status"] == "active":
                apply_mesh_peer(
                    tunnel["peer_wg_pubkey"], tunnel["peer_endpoint"],
                    tunnel["peer_vpn_address"], tunnel["quantum_psk"],
                    mesh_priv, MESH_WG_LISTEN_PORT,
                )
                print(f"\nMesh tunnel active!")
                print(f"  Peer: {target['device_id']}")
                print(f"  VPN address: {tunnel['peer_vpn_address']}")
                print(f"  Endpoint: {tunnel['peer_endpoint']}")
                print(f"  PSK: quantum-resistant ({KEM_ALGORITHM})")
            else:
                print("Mesh tunnel request timed out or was rejected")

        except KeyboardInterrupt:
            print("\nCancelled")
        except Exception as e:
            print(f"Mesh tunnel failed: {e}")

    elif args.command == "discover":
        print(f"Listening for LAN peers on UDP port {DISCOVERY_PORT}...")
        print("Press Ctrl+C to stop\n")

        disc = LANDiscovery()
        disc.start("0.0.0.0", get_client_id())
        disc.broadcast()

        try:
            while True:
                time.sleep(5)
                peers = disc.get_lan_peers()
                if peers:
                    print(f"Discovered {len(peers)} LAN peer(s):")
                    for did, info in peers.items():
                        print(f"  {did}: VPN {info['vpn_address']} at LAN {info['lan_ip']}")
                else:
                    print("No LAN peers found yet...")
                disc.broadcast()
        except KeyboardInterrupt:
            disc.stop()
            print("\nDiscovery stopped")

if __name__ == "__main__":
    main()