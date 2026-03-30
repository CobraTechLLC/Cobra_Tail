#!/usr/bin/env python3
"""
THE LIGHTHOUSE — Launcher & Management Console

Interactive setup wizard and command center for the Lighthouse
post-quantum VPN coordination server.

First run:  Walks through guided setup → writes config.yaml → generates TLS cert
After that: Management menu for node management, service control, logs, etc.

Standard paths:
    /opt/lighthouse/lighthouse.py          — server code
    /opt/lighthouse/lighthouse_launcher.py — this file
    /etc/lighthouse/config.yaml            — configuration
    /etc/lighthouse/server.crt             — TLS certificate
    /etc/lighthouse/server.key             — TLS private key
    /etc/lighthouse/wg_keys/               — WireGuard keypair
    /var/lib/lighthouse/lighthouse.db      — SQLite database
    /etc/systemd/system/lighthouse.service — systemd unit

Usage:
    sudo python3 lighthouse_launcher.py
"""

import os
import sys
import json
import shutil
import signal
import socket
import struct
import subprocess
import textwrap
import time
from pathlib import Path

# ─── Standard Paths ──────────────────────────────────────────────────────────

LIGHTHOUSE_DIR = Path("/opt/lighthouse")
LIGHTHOUSE_PY = LIGHTHOUSE_DIR / "lighthouse.py"
LAUNCHER_PY = LIGHTHOUSE_DIR / "lighthouse_launcher.py"

CONFIG_DIR = Path("/etc/lighthouse")
CONFIG_PATH = CONFIG_DIR / "config.yaml"
CERT_PATH = CONFIG_DIR / "server.crt"
KEY_PATH = CONFIG_DIR / "server.key"
WG_KEY_DIR = CONFIG_DIR / "wg_keys"

DATA_DIR = Path("/var/lib/lighthouse")
DB_PATH = DATA_DIR / "lighthouse.db"

SERVICE_NAME = "lighthouse"
SERVICE_PATH = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")

VERSION = "1.0.0"
VERSION_FILE = LIGHTHOUSE_DIR / "version.txt"

# ─── GitHub Update Config ────────────────────────────────────────────────────

GITHUB_REPO = "CobraTechLLC/Cobra_Tail"
GITHUB_BRANCH = "main"
GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}"

# Files that the updater will pull from GitHub
UPDATABLE_FILES = {
    "lighthouse.py": LIGHTHOUSE_PY,
    "lighthouse_launcher.py": LAUNCHER_PY,
}


# ─── Terminal Helpers ────────────────────────────────────────────────────────

class Colors:
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    UNDERLINE = "\033[4m"


def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def print_banner(subtitle: str = ""):
    """Print the Lighthouse banner."""
    c = Colors
    print()
    print(f"  {c.CYAN}{'═' * 56}{c.RESET}")
    print(f"  {c.CYAN}║{c.RESET}  {c.BOLD}THE LIGHTHOUSE{c.RESET} — Post-Quantum VPN Coordination Server")
    if subtitle:
        print(f"  {c.CYAN}║{c.RESET}  {c.DIM}{subtitle}{c.RESET}")
    print(f"  {c.CYAN}{'═' * 56}{c.RESET}")
    print()


def print_step(current: int, total: int, text: str):
    c = Colors
    print(f"\n  {c.YELLOW}[{current}/{total}]{c.RESET} {c.BOLD}{text}{c.RESET}")
    print(f"  {c.DIM}{'─' * 50}{c.RESET}")


def print_success(text: str):
    print(f"  {Colors.GREEN}✓{Colors.RESET} {text}")


def print_warn(text: str):
    print(f"  {Colors.YELLOW}!{Colors.RESET} {text}")


def print_error(text: str):
    print(f"  {Colors.RED}✗{Colors.RESET} {text}")


def print_info(text: str):
    print(f"  {Colors.DIM}→{Colors.RESET} {text}")


def prompt(question: str, default: str = "") -> str:
    """Ask the user a question with an optional default."""
    c = Colors
    if default:
        display = f"  {question} {c.DIM}[{default}]{c.RESET}: "
    else:
        display = f"  {question}: "
    answer = input(display).strip()
    return answer if answer else default


def prompt_confirm(question: str, default_yes: bool = True) -> bool:
    """Ask a yes/no question."""
    suffix = "[Y/n]" if default_yes else "[y/N]"
    answer = input(f"  {question} {suffix}: ").strip().lower()
    if not answer:
        return default_yes
    return answer in ("y", "yes")


def prompt_choice(options: list[str], question: str = "Select an option") -> int:
    """Show numbered options and return the selected index."""
    for i, opt in enumerate(options):
        print(f"  [{i + 1}] {opt}")
    print()
    while True:
        try:
            choice = int(input(f"  {question}: "))
            if 1 <= choice <= len(options):
                return choice - 1
        except (ValueError, EOFError):
            pass
        print_error(f"Enter a number between 1 and {len(options)}")


def wait_for_key():
    """Pause until the user presses Enter."""
    input(f"\n  {Colors.DIM}Press Enter to continue...{Colors.RESET}")


# ─── Network Detection ──────────────────────────────────────────────────────


def detect_lan_ip() -> str:
    """Auto-detect the device's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def detect_public_ip() -> str:
    """Auto-detect public IP via STUN, with HTTP fallback."""
    # Try STUN first (fast, no dependencies)
    for host, port in [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            txn_id = os.urandom(12)
            msg = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn_id
            sock.sendto(msg, (host, port))
            data, _ = sock.recvfrom(1024)
            sock.close()

            pos = 20
            while pos < len(data) - 4:
                attr_type = struct.unpack("!H", data[pos:pos + 2])[0]
                attr_len = struct.unpack("!H", data[pos + 2:pos + 4])[0]
                if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                    if data[pos + 5] == 0x01:
                        xor_ip = struct.unpack("!I", data[pos + 8:pos + 12])[0]
                        ip_int = xor_ip ^ 0x2112A442
                        return socket.inet_ntoa(struct.pack("!I", ip_int))
                pos += 4 + attr_len
                if attr_len % 4:
                    pos += 4 - (attr_len % 4)
        except Exception:
            continue

    # HTTP fallback
    try:
        import urllib.request
        return urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode().strip()
    except Exception:
        return ""


# ─── Service Management ─────────────────────────────────────────────────────


def is_service_installed() -> bool:
    """Check if the systemd service unit file exists."""
    return SERVICE_PATH.exists()


def is_service_running() -> bool:
    """Check if the Lighthouse systemd service is currently running."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


def is_service_enabled() -> bool:
    """Check if the service is enabled for boot."""
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", SERVICE_NAME],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.strip() == "enabled"
    except Exception:
        return False


def get_peer_counts() -> tuple[int, int]:
    """Query the database for total and online peer counts. Returns (total, online)."""
    if not DB_PATH.exists():
        return 0, 0
    try:
        import sqlite3
        conn = sqlite3.connect(str(DB_PATH))
        total = conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0]
        cutoff = time.time() - 120
        online = conn.execute(
            "SELECT COUNT(*) FROM peers WHERE last_seen > ?", (cutoff,)
        ).fetchone()[0]
        conn.close()
        return total, online
    except Exception:
        return 0, 0


def get_cert_fingerprint() -> str:
    """Read the TLS cert fingerprint."""
    if not CERT_PATH.exists():
        return ""
    try:
        import hashlib
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        cert_pem = CERT_PATH.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        der_bytes = cert.public_bytes(Encoding.DER)
        return hashlib.sha256(der_bytes).hexdigest()
    except Exception:
        return ""


def get_cert_days_remaining() -> int:
    """Get days until TLS cert expires."""
    try:
        from cryptography import x509
        import datetime as dt
        cert_pem = CERT_PATH.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        now = dt.datetime.now(dt.timezone.utc)
        return (cert.not_valid_after_utc - now).days
    except Exception:
        return -1


# ─── Config Generation ───────────────────────────────────────────────────────


def generate_config(
    public_ip: str,
    lan_ip: str,
    external_port: int,
    internal_port: int,
    wg_port: int,
) -> str:
    """Generate a complete config.yaml from user inputs."""
    return textwrap.dedent(f"""\
        # ─────────────────────────────────────────────────────────────
        # THE LIGHTHOUSE — Configuration
        # Post-Quantum VPN Coordination Server
        # ─────────────────────────────────────────────────────────────
        # Generated by lighthouse_launcher.py
        # Edit with: lighthouse_launcher.py → Edit Config

        # ─── Server ──────────────────────────────────────────────────
        server_url: "https://{public_ip}:{external_port}"
        local_server_url: "https://{lan_ip}:{internal_port}"
        listen_addr: "0.0.0.0"
        listen_port: {internal_port}

        # ─── TLS ─────────────────────────────────────────────────────
        tls:
          enabled: true
          cert_file: "{CERT_PATH}"
          key_file: "{KEY_PATH}"
          cert_fingerprint: ""
          cert_days: 365
          cert_subject: "The Lighthouse"

        # ─── Vault UART Link ────────────────────────────────────────
        vault_uart:
          enabled: true
          device: "/dev/ttyAMA0"
          baud_rate: 115200

        # ─── WireGuard ───────────────────────────────────────────────
        wireguard:
          listen_port: {wg_port}
          address_pool: "10.100.0.0/24"
          server_address: "10.100.0.1/24"
          interface: "wg0"
          dns:
            - "1.1.1.1"
            - "9.9.9.9"
          exit_node: true
          key_dir: "{WG_KEY_DIR}"

        # ─── Post-Quantum Crypto ────────────────────────────────────
        pqc:
          algorithm: "ML-KEM-1024"
          key_rotation_hours: 24

        # ─── Persistence ─────────────────────────────────────────────
        database:
          path: "{DB_PATH}"

        # ─── LAN Peer Discovery ─────────────────────────────────────
        discovery:
          enabled: true
          broadcast_port: 5391
          broadcast_interval: 30

        # ─── Peers ───────────────────────────────────────────────────
        peer_timeout: 120
        max_clients: 25

        # ─── Mesh Networking ─────────────────────────────────────────
        mesh:
          enabled: true
          address_pool: "10.200.0.0/24"
          wg_listen_port: 51821
          auto_accept: true
          max_peers: 10

        # ─── Logging ─────────────────────────────────────────────────
        log:
          level: "info"
    """)


def generate_service_unit() -> str:
    """Generate the systemd service unit file."""
    return textwrap.dedent(f"""\
        [Unit]
        Description=The Lighthouse — Post-Quantum VPN Coordination Server
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        ExecStart=/usr/bin/python3 {LIGHTHOUSE_PY} serve --config {CONFIG_PATH}
        WorkingDirectory={LIGHTHOUSE_DIR}
        Restart=on-failure
        RestartSec=5
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
    """)


# ─── First-Run Wizard (A1) ──────────────────────────────────────────────────


def run_wizard():
    """Interactive first-time setup wizard."""
    clear_screen()
    print_banner("First-Time Setup")

    c = Colors
    print(f"  Welcome! This wizard will configure your Lighthouse server.")
    print(f"  It will create the config file, generate a TLS certificate,")
    print(f"  and get everything ready for your first client to connect.")
    print()
    print(f"  {c.DIM}Standard file locations:{c.RESET}")
    print(f"  {c.DIM}  Config:      {CONFIG_PATH}{c.RESET}")
    print(f"  {c.DIM}  TLS cert:    {CERT_PATH}{c.RESET}")
    print(f"  {c.DIM}  Database:    {DB_PATH}{c.RESET}")
    print(f"  {c.DIM}  WG keys:     {WG_KEY_DIR}{c.RESET}")
    print()

    if not prompt_confirm("Ready to begin?"):
        print_info("Setup cancelled.")
        return False

    total_steps = 7

    # ── Step 1: LAN IP ───────────────────────────────────────────────────
    print_step(1, total_steps, "Device LAN IP")
    detected_lan = detect_lan_ip()
    if detected_lan:
        print_info(f"Auto-detected LAN IP: {c.BOLD}{detected_lan}{c.RESET}")
        lan_ip = prompt("Confirm or enter a different LAN IP", detected_lan)
    else:
        print_warn("Could not auto-detect LAN IP.")
        lan_ip = prompt("Enter this device's LAN IP (e.g., YOUR_LIGHTHOUSE_IP)")

    if not lan_ip:
        print_error("LAN IP is required.")
        return False

    print()
    print(f"  {c.YELLOW}ACTION REQUIRED:{c.RESET} Reserve this IP ({c.BOLD}{lan_ip}{c.RESET}) as a static/DHCP")
    print(f"  reservation on your router so it never changes.")
    print()
    if not prompt_confirm("Have you reserved (or will you reserve) this IP?"):
        print_warn("You should reserve this IP before connecting clients.")

    # ── Step 2: Public IP ────────────────────────────────────────────────
    print_step(2, total_steps, "Router Public IPv4")
    print_info("Detecting public IP via STUN...")
    detected_public = detect_public_ip()
    if detected_public:
        print_info(f"Auto-detected public IP: {c.BOLD}{detected_public}{c.RESET}")
        public_ip = prompt("Confirm or enter a different public IP", detected_public)
    else:
        print_warn("Could not auto-detect public IP.")
        print_info("Find it at https://whatismyip.com or your router admin page.")
        public_ip = prompt("Enter your router's public IPv4")

    if not public_ip:
        print_error("Public IP is required.")
        return False

    # ── Step 3: API Port Forwarding (TCP) ────────────────────────────────
    print_step(3, total_steps, "API Port Forwarding (TCP)")
    print()
    print(f"  You need to forward a {c.BOLD}TCP{c.RESET} port on your router to this device.")
    print(f"  This is how remote clients reach the Lighthouse API.")
    print()
    print(f"  Example: Router forwards external port 9443 → {lan_ip}:8443")
    print()

    external_port_str = prompt("What EXTERNAL TCP port did you (or will you) forward?", "9443")
    external_port = int(external_port_str)

    internal_port_str = prompt("What INTERNAL TCP port does it forward TO?", "8443")
    internal_port = int(internal_port_str)

    print()
    print(f"  {c.YELLOW}ACTION REQUIRED:{c.RESET} Forward TCP port {c.BOLD}{external_port}{c.RESET} on your")
    print(f"  router to {c.BOLD}{lan_ip}:{internal_port}{c.RESET}")

    # ── Step 4: WireGuard Port (UDP) ─────────────────────────────────────
    print_step(4, total_steps, "WireGuard Port Forwarding (UDP)")
    print()
    print(f"  WireGuard needs a {c.BOLD}UDP{c.RESET} port forwarded for the VPN tunnel.")
    print()

    wg_port_str = prompt("What UDP port for WireGuard?", "51820")
    wg_port = int(wg_port_str)

    print()
    print(f"  {c.YELLOW}ACTION REQUIRED:{c.RESET} Forward UDP port {c.BOLD}{wg_port}{c.RESET} on your")
    print(f"  router to {c.BOLD}{lan_ip}:{wg_port}{c.RESET}")

    # ── Step 5: Summary & Confirmation ───────────────────────────────────
    print_step(5, total_steps, "Configuration Summary")
    print()
    print(f"  {c.BOLD}Public URL:{c.RESET}       https://{public_ip}:{external_port}")
    print(f"  {c.BOLD}Local URL:{c.RESET}        https://{lan_ip}:{internal_port}")
    print(f"  {c.BOLD}Listen port:{c.RESET}      {internal_port} (TCP)")
    print(f"  {c.BOLD}WireGuard port:{c.RESET}   {wg_port} (UDP)")
    print(f"  {c.BOLD}VPN subnet:{c.RESET}       10.100.0.0/24")
    print(f"  {c.BOLD}Mesh subnet:{c.RESET}      10.200.0.0/24")
    print(f"  {c.BOLD}PQC algorithm:{c.RESET}    ML-KEM-1024")
    print(f"  {c.BOLD}Key rotation:{c.RESET}     Every 24 hours")
    print()

    port_summary = (
        f"\n  {c.BOLD}Port forwarding checklist:{c.RESET}\n"
        f"    TCP {external_port} → {lan_ip}:{internal_port}  (API)\n"
        f"    UDP {wg_port} → {lan_ip}:{wg_port}  (WireGuard)\n"
    )
    print(port_summary)

    if not prompt_confirm("Write this configuration?"):
        print_info("Setup cancelled. No files were changed.")
        return False

    # ── Step 6: Create Directories & Write Config ────────────────────────
    print_step(6, total_steps, "Writing Configuration")

    # Create all directories
    for d in [LIGHTHOUSE_DIR, CONFIG_DIR, WG_KEY_DIR, DATA_DIR]:
        d.mkdir(parents=True, exist_ok=True)
        print_success(f"Created {d}")

    # Lock down sensitive directories
    os.chmod(WG_KEY_DIR, 0o700)
    os.chmod(CONFIG_DIR, 0o755)

    # Write config.yaml
    config_text = generate_config(public_ip, lan_ip, external_port, internal_port, wg_port)
    CONFIG_PATH.write_text(config_text)
    os.chmod(CONFIG_PATH, 0o600)
    print_success(f"Config written to {CONFIG_PATH}")

    # Copy lighthouse.py to /opt/lighthouse/ if not already there
    _ensure_lighthouse_installed()

    # ── Step 7: Generate TLS Certificate ─────────────────────────────────
    print_step(7, total_steps, "Generating TLS Certificate")
    print_info("Generating self-signed TLS certificate...")

    try:
        result = subprocess.run(
            ["python3", str(LIGHTHOUSE_PY), "generate-cert", "--config", str(CONFIG_PATH)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            print_success("TLS certificate generated")
        else:
            print_error(f"Certificate generation failed: {result.stderr.strip()}")
            print_info("You can generate it later from the management menu.")
    except FileNotFoundError:
        print_error(f"lighthouse.py not found at {LIGHTHOUSE_PY}")
        print_info("Copy lighthouse.py to /opt/lighthouse/ and try again.")
        return False
    except Exception as e:
        print_error(f"Certificate generation failed: {e}")
        return False

    # Read and display the fingerprint
    fingerprint = get_cert_fingerprint()

    # ── Setup Complete ───────────────────────────────────────────────────
    print()
    print(f"  {c.GREEN}{'═' * 56}{c.RESET}")
    print(f"  {c.GREEN}║{c.RESET}  {c.BOLD}SETUP COMPLETE{c.RESET}")
    print(f"  {c.GREEN}{'═' * 56}{c.RESET}")
    print()

    if fingerprint:
        print(f"  {c.BOLD}TLS Certificate Fingerprint:{c.RESET}")
        print(f"  {c.CYAN}{fingerprint}{c.RESET}")
        print()
        print(f"  {c.DIM}Give this fingerprint to your clients — it's how they{c.RESET}")
        print(f"  {c.DIM}verify they're talking to your Lighthouse.{c.RESET}")

    print()
    print(f"  {c.BOLD}Next steps:{c.RESET}")
    print(f"    1. Forward the ports listed above on your router")
    print(f"    2. Start the Lighthouse from the management menu")
    print(f"    3. Add your first node with 'Add Node'")
    print(f"    4. Run the enrollment command on your client device")
    print()

    wait_for_key()
    return True


def _ensure_lighthouse_installed():
    """Copy lighthouse.py to /opt/lighthouse/ if it's not already there."""
    if LIGHTHOUSE_PY.exists():
        return

    # Look for lighthouse.py in common locations
    search_paths = [
        Path(__file__).parent / "lighthouse.py",
        Path.cwd() / "lighthouse.py",
        Path.home() / "lighthouse.py",
    ]

    for src in search_paths:
        if src.exists():
            LIGHTHOUSE_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, LIGHTHOUSE_PY)
            os.chmod(LIGHTHOUSE_PY, 0o755)
            print_success(f"Copied lighthouse.py from {src} to {LIGHTHOUSE_PY}")
            return

    print_warn(f"lighthouse.py not found. Copy it to {LIGHTHOUSE_PY} manually.")


# ─── GitHub Update Mechanism ─────────────────────────────────────────────────


def get_local_version() -> str:
    """Read the locally installed version."""
    if VERSION_FILE.exists():
        return VERSION_FILE.read_text().strip()
    return VERSION


def get_remote_version() -> str | None:
    """Fetch the latest version string from GitHub."""
    url = f"{GITHUB_RAW_BASE}/version.txt"
    try:
        import urllib.request
        resp = urllib.request.urlopen(url, timeout=10)
        return resp.read().decode().strip()
    except Exception as e:
        log_debug(f"Failed to check remote version: {e}")
        return None


def log_debug(msg: str):
    """Debug logging helper — only prints if LIGHTHOUSE_DEBUG is set."""
    if os.environ.get("LIGHTHOUSE_DEBUG"):
        print(f"  {Colors.DIM}[debug] {msg}{Colors.RESET}")


def download_github_file(filename: str, dest: Path) -> bool:
    """Download a single file from the GitHub repo to the destination path."""
    url = f"{GITHUB_RAW_BASE}/{filename}"
    try:
        import urllib.request
        # Download to a temp file first, then validate and move
        tmp_path = dest.with_suffix(".tmp")
        urllib.request.urlretrieve(url, str(tmp_path))

        # Validate Python files by parsing them
        if filename.endswith(".py"):
            import ast
            try:
                ast.parse(tmp_path.read_text())
            except SyntaxError as e:
                print_error(f"Downloaded {filename} has syntax errors: {e}")
                tmp_path.unlink(missing_ok=True)
                return False

        # Backup existing file
        if dest.exists():
            backup = dest.with_suffix(f".bak.{int(time.time())}")
            shutil.copy2(dest, backup)
            log_debug(f"Backed up {dest} → {backup}")

        # Move temp file into place
        shutil.move(str(tmp_path), str(dest))
        os.chmod(dest, 0o755)
        return True

    except Exception as e:
        print_error(f"Failed to download {filename}: {e}")
        # Clean up temp file if it exists
        tmp_path = dest.with_suffix(".tmp")
        if tmp_path.exists():
            tmp_path.unlink()
        return False


def check_for_updates() -> tuple[str, str, bool]:
    """
    Check if updates are available from GitHub.
    Returns (local_version, remote_version, update_available).
    """
    local = get_local_version()
    remote = get_remote_version()

    if remote is None:
        return local, "unknown", False

    # Simple string comparison — assumes semantic versioning
    update_available = remote != local
    return local, remote, update_available


def perform_update() -> bool:
    """
    Download and install the latest files from GitHub.
    Returns True if any files were updated.
    """
    c = Colors
    updated_count = 0
    failed_count = 0

    print_info("Downloading latest files from GitHub...")
    print_info(f"Repository: {GITHUB_REPO} ({GITHUB_BRANCH} branch)")
    print()

    for filename, dest_path in UPDATABLE_FILES.items():
        print(f"  Updating {filename}...", end=" ", flush=True)
        if download_github_file(filename, dest_path):
            print(f"{c.GREEN}OK{c.RESET}")
            updated_count += 1
        else:
            print(f"{c.RED}FAILED{c.RESET}")
            failed_count += 1

    # Update version.txt
    remote_version = get_remote_version()
    if remote_version:
        VERSION_FILE.write_text(remote_version)
        print(f"  Updating version.txt...", end=" ")
        print(f"{c.GREEN}OK{c.RESET} (v{remote_version})")

    print()
    if failed_count == 0:
        print_success(f"Updated {updated_count} file(s) successfully.")
    else:
        print_warn(f"Updated {updated_count} file(s), {failed_count} failed.")

    return updated_count > 0


def menu_check_updates():
    """Check for available updates from GitHub."""
    clear_screen()
    print_banner("Check for Updates")

    c = Colors
    print_info("Checking GitHub for updates...")
    print()

    local_ver, remote_ver, available = check_for_updates()

    print(f"  {c.BOLD}Installed version:{c.RESET}  {local_ver}")
    print(f"  {c.BOLD}Latest version:{c.RESET}     {remote_ver}")
    print()

    if remote_ver == "unknown":
        print_error("Could not reach GitHub. Check your internet connection.")
    elif available:
        print(f"  {c.GREEN}Update available!{c.RESET} ({local_ver} → {remote_ver})")
        print()
        if prompt_confirm("Download and install the update?"):
            menu_update_from_github()
            return
    else:
        print_success("You're running the latest version.")

    wait_for_key()


def menu_update_from_github():
    """Download and install the latest files from GitHub."""
    clear_screen()
    print_banner("Update from GitHub")

    c = Colors
    running = is_service_running()

    if running:
        print_warn("The Lighthouse is currently running.")
        print_info("It will be restarted after the update.")
        print()

    if not prompt_confirm("Download latest files from GitHub?"):
        return

    print()
    updated = perform_update()

    if updated and running:
        print()
        if prompt_confirm("Restart the Lighthouse to apply updates?"):
            if is_service_installed():
                subprocess.run(["systemctl", "restart", SERVICE_NAME], timeout=15)
                time.sleep(2)
                if is_service_running():
                    print_success("Lighthouse restarted with updated code.")
                else:
                    print_error("Restart failed. Check: journalctl -u lighthouse -e")
            else:
                print_info("Kill the running process and start it again from the menu.")

    if updated:
        print()
        print_warn("The launcher itself was updated. Restart it to use the new version.")
        print_info("Just exit and run 'lighthouse' again.")

    wait_for_key()


# ─── Management Menu (A2) ───────────────────────────────────────────────────


def show_menu():
    """Main management menu loop."""
    while True:
        clear_screen()
        _draw_menu_header()
        _draw_menu_options()

        choice = prompt("Select an option")

        if choice == "1":
            menu_start_stop_service()
        elif choice == "2":
            menu_add_node()
        elif choice == "3":
            menu_list_nodes()
        elif choice == "4":
            menu_remove_node()
        elif choice == "5":
            menu_show_fingerprint()
        elif choice == "6":
            menu_regen_cert()
        elif choice == "7":
            menu_view_logs()
        elif choice == "8":
            menu_edit_config()
        elif choice == "9":
            menu_install_service()
        elif choice == "10":
            menu_rerun_wizard()
        elif choice == "11":
            menu_check_updates()
        elif choice == "12":
            menu_update_from_github()
        elif choice == "0":
            print_info("Goodbye.")
            break
        else:
            print_error("Invalid option.")
            time.sleep(0.5)


def _draw_menu_header():
    """Draw the menu header with live status."""
    c = Colors

    # Gather status
    running = is_service_running()
    installed = is_service_installed()
    total_peers, online_peers = get_peer_counts()
    fingerprint = get_cert_fingerprint()
    cert_days = get_cert_days_remaining()

    # Status line
    if running:
        if installed:
            status_str = f"{c.GREEN}RUNNING{c.RESET} {c.DIM}(systemd){c.RESET}"
        else:
            status_str = f"{c.GREEN}RUNNING{c.RESET}"
    else:
        status_str = f"{c.RED}STOPPED{c.RESET}"

    # Cert status
    if fingerprint:
        fp_short = fingerprint[:16] + "..."
        if cert_days < 30:
            cert_str = f"{fp_short} {c.YELLOW}({cert_days}d remaining){c.RESET}"
        else:
            cert_str = f"{fp_short} {c.DIM}({cert_days}d remaining){c.RESET}"
    else:
        cert_str = f"{c.RED}NOT GENERATED{c.RESET}"

    print()
    print(f"  {c.CYAN}{'═' * 56}{c.RESET}")
    print(f"  {c.CYAN}║{c.RESET}  {c.BOLD}THE LIGHTHOUSE{c.RESET} — Command Center  {c.DIM}v{get_local_version()}{c.RESET}")
    print(f"  {c.CYAN}║{c.RESET}")
    print(f"  {c.CYAN}║{c.RESET}  Status:       {status_str}")
    print(f"  {c.CYAN}║{c.RESET}  Peers:        {online_peers} online / {total_peers} total")
    print(f"  {c.CYAN}║{c.RESET}  Fingerprint:  {cert_str}")
    if installed:
        enabled = is_service_enabled()
        boot_str = f"{c.GREEN}ON{c.RESET}" if enabled else f"{c.DIM}OFF{c.RESET}"
        print(f"  {c.CYAN}║{c.RESET}  Start on boot: {boot_str}")
    print(f"  {c.CYAN}{'═' * 56}{c.RESET}")
    print()


def _draw_menu_options():
    """Draw the menu options."""
    c = Colors
    running = is_service_running()
    installed = is_service_installed()

    # Dynamic start/stop label
    if running:
        start_label = f"{c.RED}Stop Lighthouse{c.RESET}"
    else:
        start_label = f"{c.GREEN}Start Lighthouse{c.RESET}"

    print(f"  [1]  {start_label}")
    print(f"  [2]  Add Node")
    print(f"  [3]  List Nodes")
    print(f"  [4]  Remove Node")
    print(f"  [5]  Show Cert Fingerprint")
    print(f"  [6]  Regenerate TLS Certificate")
    print(f"  [7]  View Logs")
    print(f"  [8]  Edit Config")

    if installed:
        print(f"  [9]  Manage System Service")
    else:
        print(f"  [9]  Install as System Service")

    print(f"  [10] Re-run Setup Wizard")
    print(f"  {c.DIM}─────────────────────────────{c.RESET}")
    print(f"  [11] Check for Updates")
    print(f"  [12] Update from GitHub")
    print(f"  [0]  Exit")
    print()


# ─── Menu Actions ────────────────────────────────────────────────────────────


def menu_start_stop_service():
    """Start or stop the Lighthouse."""
    running = is_service_running()
    installed = is_service_installed()

    if running:
        # Stop
        if not prompt_confirm("Stop the Lighthouse?"):
            return

        if installed:
            subprocess.run(["systemctl", "stop", SERVICE_NAME], timeout=10)
        else:
            # Try to find and kill the process
            subprocess.run(["pkill", "-f", "lighthouse.py serve"], timeout=5)

        time.sleep(1)
        if not is_service_running():
            print_success("Lighthouse stopped.")
        else:
            print_error("Failed to stop. Try: sudo systemctl stop lighthouse")
    else:
        # Start
        if installed:
            print_info("Starting via systemd...")
            subprocess.run(["systemctl", "start", SERVICE_NAME], timeout=10)
            time.sleep(2)
            if is_service_running():
                print_success("Lighthouse is running.")
                print_info("View logs: journalctl -u lighthouse -f")
            else:
                print_error("Failed to start. Check: journalctl -u lighthouse -e")
        else:
            # Start as foreground process
            print_info("Starting Lighthouse in foreground...")
            print_info("Press Ctrl+C to stop and return to menu.")
            print()
            try:
                proc = subprocess.Popen(
                    ["python3", str(LIGHTHOUSE_PY), "serve", "--config", str(CONFIG_PATH)],
                    cwd=str(LIGHTHOUSE_DIR),
                )
                proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                proc.wait(timeout=5)
                print()
                print_success("Lighthouse stopped.")
            return  # Skip wait_for_key since we're coming back from live output

    wait_for_key()


def menu_add_node():
    """Add a new node to the network."""
    clear_screen()
    print_banner("Add Node")

    name = prompt("Enter a name for this node (e.g., cobra1, laptop, phone)")
    if not name:
        print_error("Node name is required.")
        wait_for_key()
        return

    # Validate name: alphanumeric, hyphens, underscores
    if not all(c.isalnum() or c in "-_" for c in name):
        print_error("Node name can only contain letters, numbers, hyphens, and underscores.")
        wait_for_key()
        return

    print()
    print_info(f"Adding node '{name}'...")

    try:
        result = subprocess.run(
            ["python3", str(LIGHTHOUSE_PY), "add-node", "--config", str(CONFIG_PATH), name],
            capture_output=True, text=True, timeout=15,
        )
        print()
        # Print the output which includes the enrollment token and instructions
        for line in result.stdout.strip().split("\n"):
            print(f"  {line}")
        if result.stderr.strip():
            for line in result.stderr.strip().split("\n"):
                print(f"  {Colors.DIM}{line}{Colors.RESET}")
    except Exception as e:
        print_error(f"Failed to add node: {e}")

    print()
    wait_for_key()


def menu_list_nodes():
    """List all enrolled and pending nodes."""
    clear_screen()
    print_banner("Node List")

    try:
        result = subprocess.run(
            ["python3", str(LIGHTHOUSE_PY), "list-nodes", "--config", str(CONFIG_PATH)],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.strip().split("\n"):
            print(f"  {line}")
    except Exception as e:
        print_error(f"Failed to list nodes: {e}")

    print()
    wait_for_key()


def menu_remove_node():
    """Remove a node from the network."""
    clear_screen()
    print_banner("Remove Node")

    # Show current nodes first
    try:
        result = subprocess.run(
            ["python3", str(LIGHTHOUSE_PY), "list-nodes", "--config", str(CONFIG_PATH)],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.strip().split("\n"):
            print(f"  {line}")
    except Exception:
        pass

    print()
    name = prompt("Enter the node name to remove (or leave blank to cancel)")
    if not name:
        return

    c = Colors
    print()
    print(f"  {c.RED}WARNING:{c.RESET} This will disconnect '{name}' from the network.")
    print(f"  Their device ID, VPN address, and mesh tunnels will be deleted.")
    if not prompt_confirm("Proceed?", default_yes=False):
        print_info("Cancelled.")
        wait_for_key()
        return

    try:
        result = subprocess.run(
            ["python3", str(LIGHTHOUSE_PY), "revoke-node", "--config", str(CONFIG_PATH), name],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.strip().split("\n"):
            print(f"  {line}")
    except Exception as e:
        print_error(f"Failed to remove node: {e}")

    wait_for_key()


def menu_show_fingerprint():
    """Display the TLS certificate fingerprint."""
    clear_screen()
    print_banner("TLS Certificate")

    fingerprint = get_cert_fingerprint()
    cert_days = get_cert_days_remaining()
    c = Colors

    if fingerprint:
        print(f"  {c.BOLD}SHA-256 Fingerprint:{c.RESET}")
        print(f"  {c.CYAN}{fingerprint}{c.RESET}")
        print()
        print(f"  {c.BOLD}Expires in:{c.RESET} {cert_days} days")
        if cert_days < 30:
            print_warn("Certificate expires soon — regenerate with option [6].")
        print()
        print(f"  {c.BOLD}Client enrollment command:{c.RESET}")
        print()

        # Read config for URLs
        try:
            import yaml
            cfg = yaml.safe_load(CONFIG_PATH.read_text())
            public_url = cfg.get("server_url", "https://<ip>:<port>")
            local_url = cfg.get("local_server_url", "")
        except Exception:
            public_url = "https://<ip>:<port>"
            local_url = ""

        print(f"    python3 client.py enroll \\")
        print(f"      --token <TOKEN> \\")
        print(f"      --lighthouse-public {public_url}")
    else:
        print_error("No TLS certificate found.")
        print_info("Generate one with option [6] or re-run the setup wizard.")

    print()
    wait_for_key()


def menu_regen_cert():
    """Regenerate the TLS certificate."""
    c = Colors
    print()
    print(f"  {c.RED}WARNING:{c.RESET} Regenerating the certificate changes the fingerprint.")
    print(f"  All connected clients will need the new fingerprint to reconnect.")
    print()
    if not prompt_confirm("Regenerate the TLS certificate?", default_yes=False):
        return

    print_info("Regenerating TLS certificate...")
    try:
        result = subprocess.run(
            ["python3", str(LIGHTHOUSE_PY), "generate-cert", "--config", str(CONFIG_PATH)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            print_success("Certificate regenerated.")
            fingerprint = get_cert_fingerprint()
            if fingerprint:
                print()
                print(f"  {c.BOLD}New fingerprint:{c.RESET}")
                print(f"  {c.CYAN}{fingerprint}{c.RESET}")
                print()
                print_warn("Update the fingerprint on all client devices.")
        else:
            print_error(f"Failed: {result.stderr.strip()}")
    except Exception as e:
        print_error(f"Failed: {e}")

    wait_for_key()


def menu_view_logs():
    """View Lighthouse logs."""
    clear_screen()
    print_banner("Logs")

    if is_service_installed():
        print_info("Showing live logs from journalctl. Press Ctrl+C to stop.")
        print()
        try:
            subprocess.run(
                ["journalctl", "-u", SERVICE_NAME, "-f", "--no-hostname", "-n", "50"],
            )
        except KeyboardInterrupt:
            pass
    else:
        # Check for log file from config
        try:
            import yaml
            cfg = yaml.safe_load(CONFIG_PATH.read_text())
            log_file = cfg.get("log", {}).get("file", "")
            if log_file and Path(log_file).exists():
                print_info(f"Tailing {log_file}. Press Ctrl+C to stop.")
                print()
                try:
                    subprocess.run(["tail", "-f", "-n", "50", log_file])
                except KeyboardInterrupt:
                    pass
                return
        except Exception:
            pass

        print_info("No logs available. Start the Lighthouse first.")
        wait_for_key()


def menu_edit_config():
    """Open the config file in an editor."""
    if not CONFIG_PATH.exists():
        print_error(f"Config not found at {CONFIG_PATH}. Run setup wizard first.")
        wait_for_key()
        return

    editor = os.environ.get("EDITOR", "nano")
    print_info(f"Opening {CONFIG_PATH} in {editor}...")

    if is_service_running():
        print_warn("Lighthouse is running. Restart required for changes to take effect.")

    try:
        subprocess.run([editor, str(CONFIG_PATH)])
    except FileNotFoundError:
        # Fallback editors
        for fallback in ["nano", "vi", "vim"]:
            try:
                subprocess.run([fallback, str(CONFIG_PATH)])
                break
            except FileNotFoundError:
                continue
        else:
            print_error(f"No text editor found. Edit manually: {CONFIG_PATH}")
            wait_for_key()
            return

    # Validate YAML after editing
    try:
        import yaml
        yaml.safe_load(CONFIG_PATH.read_text())
        print_success("Config syntax is valid.")
    except Exception as e:
        print_error(f"YAML syntax error: {e}")
        print_warn("Fix the error before starting the Lighthouse.")

    if is_service_running():
        if prompt_confirm("Restart the Lighthouse to apply changes?"):
            subprocess.run(["systemctl", "restart", SERVICE_NAME], timeout=10)
            time.sleep(2)
            if is_service_running():
                print_success("Lighthouse restarted with new config.")
            else:
                print_error("Restart failed. Check: journalctl -u lighthouse -e")

    wait_for_key()


def menu_install_service():
    """Install, manage, or remove the systemd service."""
    installed = is_service_installed()
    c = Colors

    if installed:
        # Show management submenu
        clear_screen()
        print_banner("System Service Management")

        enabled = is_service_enabled()
        running = is_service_running()

        print(f"  Service:  {c.GREEN}INSTALLED{c.RESET}")
        print(f"  Running:  {c.GREEN + 'YES' + c.RESET if running else c.RED + 'NO' + c.RESET}")
        print(f"  On boot:  {c.GREEN + 'ENABLED' + c.RESET if enabled else c.DIM + 'DISABLED' + c.RESET}")
        print()

        options = []
        if enabled:
            options.append("Disable start on boot")
        else:
            options.append("Enable start on boot")
        options.append("Remove system service")
        options.append("Back")

        idx = prompt_choice(options)

        if options[idx] == "Enable start on boot":
            subprocess.run(["systemctl", "enable", SERVICE_NAME], timeout=5)
            print_success("Lighthouse will start automatically on boot.")
        elif options[idx] == "Disable start on boot":
            subprocess.run(["systemctl", "disable", SERVICE_NAME], timeout=5)
            print_success("Lighthouse will NOT start on boot.")
        elif options[idx] == "Remove system service":
            if prompt_confirm("Remove the system service?", default_yes=False):
                if is_service_running():
                    subprocess.run(["systemctl", "stop", SERVICE_NAME], timeout=10)
                subprocess.run(["systemctl", "disable", SERVICE_NAME], timeout=5,
                               capture_output=True)
                SERVICE_PATH.unlink(missing_ok=True)
                subprocess.run(["systemctl", "daemon-reload"], timeout=5)
                print_success("System service removed.")
        # "Back" just returns

        wait_for_key()
    else:
        # Install
        clear_screen()
        print_banner("Install System Service")

        print(f"  This will install the Lighthouse as a systemd service so it")
        print(f"  starts automatically on boot and runs in the background.")
        print()
        print(f"  {c.BOLD}Service file:{c.RESET} {SERVICE_PATH}")
        print(f"  {c.BOLD}Runs:{c.RESET}         python3 {LIGHTHOUSE_PY} serve")
        print(f"  {c.BOLD}Restarts:{c.RESET}     Automatically on failure (5s delay)")
        print()

        if not prompt_confirm("Install the system service?"):
            return

        # Write the service file
        unit_content = generate_service_unit()
        SERVICE_PATH.write_text(unit_content)
        print_success(f"Service file written to {SERVICE_PATH}")

        # Reload and enable
        subprocess.run(["systemctl", "daemon-reload"], timeout=5)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], timeout=5)
        print_success("Service enabled — Lighthouse will start on boot.")

        if prompt_confirm("Start the Lighthouse now?"):
            subprocess.run(["systemctl", "start", SERVICE_NAME], timeout=10)
            time.sleep(2)
            if is_service_running():
                print_success("Lighthouse is running.")
                print_info("View logs: journalctl -u lighthouse -f")
            else:
                print_error("Failed to start. Check: journalctl -u lighthouse -e")

        wait_for_key()


def menu_rerun_wizard():
    """Re-run the setup wizard."""
    c = Colors

    if CONFIG_PATH.exists():
        print()
        print(f"  {c.YELLOW}WARNING:{c.RESET} A config already exists at {CONFIG_PATH}.")
        print(f"  Re-running the wizard will back it up and create a new one.")
        print()
        if not prompt_confirm("Proceed?", default_yes=False):
            return

        # Backup existing config
        backup = CONFIG_PATH.with_suffix(f".yaml.bak.{int(time.time())}")
        shutil.copy2(CONFIG_PATH, backup)
        print_success(f"Existing config backed up to {backup}")

    if is_service_running():
        print_warn("Stopping the Lighthouse before reconfiguration...")
        if is_service_installed():
            subprocess.run(["systemctl", "stop", SERVICE_NAME], timeout=10)
        else:
            subprocess.run(["pkill", "-f", "lighthouse.py serve"], timeout=5)
        time.sleep(1)

    run_wizard()


# ─── Entry Point ─────────────────────────────────────────────────────────────


def main():
    # Check for root
    if os.geteuid() != 0:
        print(f"\n  {Colors.RED}ERROR:{Colors.RESET} The Lighthouse launcher requires root privileges.")
        print(f"  Run with: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    # Check if lighthouse.py exists (or can be found)
    if not LIGHTHOUSE_PY.exists():
        _ensure_lighthouse_installed()

    # First-run detection: does config.yaml exist?
    if not CONFIG_PATH.exists():
        success = run_wizard()
        if not success:
            sys.exit(1)

    # Enter the management menu
    show_menu()


if __name__ == "__main__":
    main()