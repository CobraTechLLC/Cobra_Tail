"""
COBRATAIL — Client Launcher & Management Menu

Cross-platform interactive launcher for the CobraTail VPN client.
Provides enrollment wizard, service management, identity manager,
mesh peer display, connection details, settings, and updates.

Works on both Windows and Linux. Designed to be the single entry point
for users — the "cobra" command.

Usage:
    cobra                     → Main menu (or enrollment wizard on first run)
    cobra --enroll            → Force enrollment wizard
    cobra --start             → Start client service directly
    cobra --stop              → Stop client service
    cobra --status            → Show connection status
"""

import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import textwrap
from pathlib import Path
from datetime import datetime, timezone

# ─── Platform Detection ──────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# ─── CobraTail Directory Detection ───────────────────────────────────────────
def _detect_cobratail_dir() -> Path:
    """Detect the CobraTail install directory."""
    if IS_WINDOWS:
        installed = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CobraTail"
    else:
        installed = Path("/opt/cobratail")

    if (installed / ".cobratail").exists():
        return installed

    # Dev mode
    script_dir = Path(__file__).parent.resolve()
    if (script_dir / "enrollment.json").exists() or (script_dir / "config" / "enrollment.json").exists():
        return script_dir

    # Legacy
    legacy = Path.home() / ".quantum_vpn"
    if legacy.exists():
        return legacy

    return installed

COBRATAIL_DIR = _detect_cobratail_dir()

# Subdirectory layout (new install) vs flat layout (legacy/dev)
if (COBRATAIL_DIR / "config").is_dir() or (COBRATAIL_DIR / ".cobratail").exists():
    BIN_DIR = COBRATAIL_DIR / "bin"
    CONFIG_DIR = COBRATAIL_DIR / "config"
    DATA_DIR = COBRATAIL_DIR / "data"
    LOG_DIR = COBRATAIL_DIR / "logs"
else:
    BIN_DIR = COBRATAIL_DIR
    CONFIG_DIR = COBRATAIL_DIR
    DATA_DIR = COBRATAIL_DIR
    LOG_DIR = COBRATAIL_DIR

# ─── File Paths ──────────────────────────────────────────────────────────────
ENROLLMENT_PATH = CONFIG_DIR / "enrollment.json"
STATE_PATH = DATA_DIR / "client_state.json"
IDENTITY_PATH = DATA_DIR / "node_identity.json"
IDENTITY_BACKUP_PATH = DATA_DIR / "identity_backup.json"
MESH_PEERS_PATH = DATA_DIR / "mesh_peers.json"
CERT_FINGERPRINT_PATH = CONFIG_DIR / "cert_fingerprint"

# ─── Script Paths ────────────────────────────────────────────────────────────
CLIENT_SCRIPT = BIN_DIR / "client.py"
IDENTITY_SCRIPT = BIN_DIR / "identity_manager.py"

_SCRIPT_DIR = Path(__file__).parent.resolve()
if not CLIENT_SCRIPT.exists():
    CLIENT_SCRIPT = _SCRIPT_DIR / "client.py"
if not IDENTITY_SCRIPT.exists():
    IDENTITY_SCRIPT = _SCRIPT_DIR / "identity_manager.py"

VERSION = "1.0.0"
SERVICE_NAME = "cobratail"              # systemd service name (Linux)
TASK_NAME = "CobraTailClient"           # Scheduled Task name (Windows)
IDENTITY_TASK_NAME = "CobraTailIdentity"  # Identity scheduled task (Windows)

# ─── Colors ──────────────────────────────────────────────────────────────────
# ANSI codes — Windows Terminal and modern terminals support these
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

# Disable colors if not a real terminal
if not sys.stdout.isatty():
    BOLD = DIM = GREEN = RED = YELLOW = CYAN = RESET = ""


# =============================================================================
# UTILITIES
# =============================================================================

def clear_screen():
    os.system("cls" if IS_WINDOWS else "clear")


def pause(msg="Press Enter to continue..."):
    try:
        input(f"\n  {DIM}{msg}{RESET}")
    except (EOFError, KeyboardInterrupt):
        pass


def print_header(title: str):
    clear_screen()
    print()
    print(f"  {BOLD}COBRATAIL — {title}{RESET}")
    print(f"  {'=' * 50}")
    print()


def print_banner():
    clear_screen()
    print()
    print(f"  {BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"  {BOLD}║         COBRATAIL VPN  v{VERSION}           ║{RESET}")
    print(f"  {BOLD}║    Quantum-Resistant Mesh Network        ║{RESET}")
    print(f"  {BOLD}╚══════════════════════════════════════════╝{RESET}")
    print()


def run_cmd(cmd: list[str], timeout: int = 60, capture: bool = True,
            shell: bool = False) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    try:
        return subprocess.run(
            cmd, capture_output=capture, text=True,
            timeout=timeout, shell=shell,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, "", "Timed out")
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 1, "", f"Not found: {cmd[0]}")


def get_python() -> str:
    """Get the correct Python executable for the platform."""
    if IS_WINDOWS:
        return sys.executable
    # Linux: prefer python3
    for p in ["python3", "python"]:
        if shutil.which(p):
            return p
    return sys.executable


def is_admin() -> bool:
    """Check if running with elevated privileges."""
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def request_admin(reason: str) -> bool:
    """Warn the user if not running as admin. Returns True if admin."""
    if is_admin():
        return True
    print(f"  {YELLOW}This action requires {'Administrator' if IS_WINDOWS else 'root'} privileges.{RESET}")
    print(f"  {DIM}Reason: {reason}{RESET}")
    if IS_WINDOWS:
        print(f"  {DIM}Right-click the terminal and 'Run as Administrator'{RESET}")
    else:
        print(f"  {DIM}Re-run with: sudo cobra{RESET}")
    return False


# =============================================================================
# ENROLLMENT STATE
# =============================================================================

def load_enrollment() -> dict:
    """Load enrollment data from disk."""
    if ENROLLMENT_PATH.exists():
        try:
            return json.loads(ENROLLMENT_PATH.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def is_enrolled() -> bool:
    """Check if this device has been enrolled."""
    enrollment = load_enrollment()
    return bool(enrollment.get("device_id"))


def load_state() -> dict:
    """Load client state from disk."""
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def load_identity() -> dict:
    """Load identity config from disk."""
    if IDENTITY_PATH.exists():
        try:
            return json.loads(IDENTITY_PATH.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return {}


# =============================================================================
# SERVICE MANAGEMENT
# =============================================================================

def get_service_status() -> str:
    """
    Get the current client service status.
    Returns: 'running', 'stopped', or 'unknown'
    """
    if IS_LINUX:
        result = run_cmd(["systemctl", "is-active", SERVICE_NAME])
        status = result.stdout.strip()
        if status == "active":
            return "running"
        elif status in ("inactive", "dead", "failed"):
            return "stopped"
        return "unknown"
    else:
        # Windows: check PID file first — fastest and works regardless of process name
        pid_path = DATA_DIR / "client.pid"
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text().strip())
                # Verify the PID is actually still alive
                result = run_cmd([
                    "powershell", "-NoProfile", "-Command",
                    f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Select-Object -First 1 Id"
                ])
                if result.returncode == 0 and str(pid) in result.stdout:
                    return "running"
                else:
                    # PID file is stale — clean it up
                    pid_path.unlink(missing_ok=True)
            except (ValueError, OSError):
                pass

        # Fallback: check scheduled task state
        result = run_cmd([
            "powershell", "-NoProfile", "-Command",
            f"(Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue).State"
        ])
        if result.stdout.strip() == "Running":
            return "running"

        return "stopped"

def get_client_pid() -> int | None:
    """Get the PID of the running client process."""
    if IS_LINUX:
        result = run_cmd(["systemctl", "show", SERVICE_NAME, "--property=MainPID"])
        if result.returncode == 0:
            try:
                pid = int(result.stdout.strip().split("=")[1])
                return pid if pid > 0 else None
            except (ValueError, IndexError):
                pass
    else:
        # Read from PID file — works for both python and exe launches
        pid_path = DATA_DIR / "client.pid"
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text().strip())
                result = run_cmd([
                    "powershell", "-NoProfile", "-Command",
                    f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Select-Object -First 1 Id"
                ])
                if result.returncode == 0 and str(pid) in result.stdout:
                    return pid
                pid_path.unlink(missing_ok=True)
            except (ValueError, OSError):
                pass
    return None

def start_service() -> bool:
    """Start the client service."""
    enrollment = load_enrollment()
    public_url = enrollment.get("lighthouse_public", "")
    local_url = enrollment.get("lighthouse_local", "")

    if not public_url:
        print(f"  {RED}No Lighthouse URL configured. Enroll first.{RESET}")
        return False

    if IS_LINUX:
        # Check if systemd service exists
        service_file = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
        if service_file.exists():
            result = run_cmd(["sudo", "systemctl", "start", SERVICE_NAME])
            if result.returncode == 0:
                print(f"  {GREEN}Service started{RESET}")
                return True
            else:
                print(f"  {RED}Failed to start service: {result.stderr.strip()}{RESET}")
                return False
        else:
            # Run directly in background
            python = get_python()
            cmd = [python, str(CLIENT_SCRIPT), "service",
                   "--lighthouse-public", public_url]
            if local_url:
                cmd.extend(["--lighthouse-local", local_url])

            log_path = LOG_DIR / "client.log"
            log_file = open(log_path, "a")
            proc = subprocess.Popen(
                cmd, stdout=log_file, stderr=log_file,
                start_new_session=True,
            )
            # Save PID for later
            pid_path = DATA_DIR / "client.pid"
            pid_path.write_text(str(proc.pid))
            print(f"  {GREEN}Client started (PID {proc.pid}){RESET}")
            print(f"  {DIM}Log: {log_path}{RESET}")
            return True
    else:
        # Windows: start as background process
        python = get_python()
        cmd = [python, str(CLIENT_SCRIPT), "service",
               "--lighthouse-public", public_url]
        if local_url:
            cmd.extend(["--lighthouse-local", local_url])

        log_path = LOG_DIR / "client.log"
        log_file = open(log_path, "a")

        # Use CREATE_NEW_PROCESS_GROUP so it survives terminal close
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        DETACHED_PROCESS = 0x00000008
        proc = subprocess.Popen(
            cmd, stdout=log_file, stderr=log_file,
            creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
        )
        pid_path = DATA_DIR / "client.pid"
        pid_path.write_text(str(proc.pid))
        print(f"  {GREEN}Client started (PID {proc.pid}){RESET}")
        print(f"  {DIM}Log: {log_path}{RESET}")
        return True


def stop_service() -> bool:
    """Stop the client service."""
    if IS_LINUX:
        service_file = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
        if service_file.exists():
            result = run_cmd(["sudo", "systemctl", "stop", SERVICE_NAME])
            if result.returncode == 0:
                print(f"  {GREEN}Service stopped{RESET}")
                return True
            else:
                print(f"  {RED}Failed to stop service: {result.stderr.strip()}{RESET}")
                return False

    # Manual PID-based stop (both platforms, or Linux without systemd)
    pid = get_client_pid()
    if not pid:
        # Try saved PID
        pid_path = DATA_DIR / "client.pid"
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text().strip())
            except (ValueError, IOError):
                pid = None

    if pid:
        try:
            if IS_WINDOWS:
                run_cmd(["taskkill", "/F", "/PID", str(pid)])
            else:
                os.kill(pid, signal.SIGTERM)
            print(f"  {GREEN}Client stopped (PID {pid}){RESET}")
        except (ProcessLookupError, PermissionError) as e:
            print(f"  {YELLOW}Process {pid} already gone or access denied: {e}{RESET}")

        # Clean up PID file — try directly, fall back to shell for admin-owned files
        pid_path = DATA_DIR / "client.pid"
        if pid_path.exists():
            try:
                pid_path.unlink()
            except PermissionError:
                if IS_WINDOWS:
                    run_cmd(["cmd", "/c", "del", "/f", str(pid_path)])
                else:
                    run_cmd(["sudo", "rm", "-f", str(pid_path)])
        return True
    else:
        print(f"  {YELLOW}No running client found{RESET}")
        return False

def restart_service() -> bool:
    """Restart the client service."""
    stop_service()
    time.sleep(1)
    return start_service()


# =============================================================================
# STARTUP ON BOOT
# =============================================================================

def is_startup_enabled() -> bool:
    """Check if the client is configured to start on boot."""
    if IS_LINUX:
        result = run_cmd(["systemctl", "is-enabled", SERVICE_NAME])
        return result.stdout.strip() == "enabled"
    else:
        result = run_cmd([
            "powershell", "-Command",
            f"(Get-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue).State"
        ])
        return result.returncode == 0 and result.stdout.strip() != ""


def enable_startup() -> bool:
    """Enable client to start on boot."""
    enrollment = load_enrollment()
    public_url = enrollment.get("lighthouse_public", "")
    local_url = enrollment.get("lighthouse_local", "")

    if not public_url:
        print(f"  {RED}Enroll first before enabling startup.{RESET}")
        return False

    if IS_LINUX:
        service_file = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
        if not service_file.exists():
            if not is_admin():
                print(f"  {YELLOW}Need root to install systemd service.{RESET}")
                return False
            _install_systemd_service(public_url, local_url)

        result = run_cmd(["sudo", "systemctl", "enable", SERVICE_NAME])
        if result.returncode == 0:
            print(f"  {GREEN}Startup enabled (systemd){RESET}")
            return True
        else:
            print(f"  {RED}Failed: {result.stderr.strip()}{RESET}")
            return False
    else:
        # Windows: create Scheduled Task with admin elevation
        # Use pythonw.exe for windowless background execution
        python = get_python()
        if IS_WINDOWS:
            pythonw = Path(python).parent / "pythonw.exe"
            if pythonw.exists():
                python = str(pythonw)

        args = f'"{CLIENT_SCRIPT}" service --lighthouse-public {public_url}'
        if local_url:
            args += f" --lighthouse-local {local_url}"

        # Get current username for the task principal
        username = os.environ.get("USERNAME", "")
        userdomain = os.environ.get("USERDOMAIN", "")
        if userdomain and username:
            principal_user = f"{userdomain}\\{username}"
        else:
            principal_user = username

        ps_commands = [
            f'$action = New-ScheduledTaskAction -Execute "{python}" '
            f'-Argument \'{args}\' '
            f'-WorkingDirectory "{CLIENT_SCRIPT.parent}"',
            '$trigger = New-ScheduledTaskTrigger -AtLogon',
            f'$principal = New-ScheduledTaskPrincipal -UserId "{principal_user}" '
            f'-RunLevel Highest',
            '$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries '
            '-DontStopIfGoingOnBatteries -StartWhenAvailable '
            '-ExecutionTimeLimit (New-TimeSpan -Hours 0) '
            '-RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)',
            f'Register-ScheduledTask -TaskName "{TASK_NAME}" '
            f'-Action $action -Trigger $trigger -Principal $principal '
            f'-Settings $settings '
            f'-Description "CobraTail VPN Client" -Force',
        ]
        result = run_cmd([
            "powershell", "-Command", "; ".join(ps_commands)
        ])
        if result.returncode == 0:
            print(f"  {GREEN}Startup enabled (Scheduled Task at logon, elevated){RESET}")
            return True
        else:
            print(f"  {RED}Failed: {result.stderr.strip()}{RESET}")
            return False

def disable_startup() -> bool:
    """Disable client from starting on boot."""
    if IS_LINUX:
        result = run_cmd(["sudo", "systemctl", "disable", SERVICE_NAME])
        if result.returncode == 0:
            print(f"  {GREEN}Startup disabled{RESET}")
            return True
        print(f"  {RED}Failed: {result.stderr.strip()}{RESET}")
        return False
    else:
        result = run_cmd([
            "powershell", "-Command",
            f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false"
        ])
        if result.returncode == 0:
            print(f"  {GREEN}Startup disabled{RESET}")
            return True
        print(f"  {RED}Failed: {result.stderr.strip()}{RESET}")
        return False


def _install_systemd_service(public_url: str, local_url: str):
    """Install systemd service file for the client."""
    python = get_python()
    cmd_line = f"{python} {CLIENT_SCRIPT} service --lighthouse-public {public_url}"
    if local_url:
        cmd_line += f" --lighthouse-local {local_url}"

    service_content = textwrap.dedent(f"""\
        [Unit]
        Description=CobraTail VPN Client
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        ExecStart={cmd_line}
        Restart=on-failure
        RestartSec=10
        WorkingDirectory={CLIENT_SCRIPT.parent}

        [Install]
        WantedBy=multi-user.target
    """)

    service_path = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
    service_path.write_text(service_content)
    run_cmd(["sudo", "systemctl", "daemon-reload"])


# =============================================================================
# ENROLLMENT WIZARD
# =============================================================================

def probe_lighthouse(url: str) -> bool:
    """Check if a Lighthouse is reachable (no cert pinning — pre-enrollment)."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        resp = requests.get(f"{url}/api/v1/health", verify=False, timeout=8)
        return resp.status_code == 200
    except Exception:
        return False


def decode_enrollment_key(key_input: str) -> dict | None:
    """
    Decode a smart enrollment key (ct_...) into its components.
    Returns {"token": ..., "public_url": ..., "local_url": ...} or None if not a smart key.
    """
    import base64
    key_input = key_input.strip()
    if not key_input.startswith("ct_"):
        return None

    try:
        b64_part = key_input[3:]  # Strip ct_ prefix
        # Add back padding
        padding = 4 - (len(b64_part) % 4)
        if padding != 4:
            b64_part += "=" * padding
        decoded = base64.urlsafe_b64decode(b64_part).decode("utf-8")
        data = json.loads(decoded)
        return {
            "token": data.get("t", ""),
            "public_url": data.get("p", ""),
            "local_url": data.get("l", ""),
        }
    except Exception:
        return None


def enrollment_wizard():
    """Interactive enrollment wizard — guides the user through first-time setup."""
    print_header("Enrollment Wizard")

    print(f"  Welcome to CobraTail! Let's get your device connected.\n")
    print(f"  You'll need an enrollment key from the network admin.")
    print(f"  It looks like:  ct_eyJ0Ijoi...")
    print()

    # Get enrollment key or manual token
    while True:
        key_input = input(f"  Enrollment key: ").strip()
        if key_input:
            break
        print(f"  {RED}Cannot be empty{RESET}")

    # Try to decode as smart enrollment key
    decoded = decode_enrollment_key(key_input)

    if decoded and decoded["token"] and decoded["public_url"]:
        # Smart key — everything we need is in the key
        token = decoded["token"]
        public_url = decoded["public_url"]
        local_url = decoded["local_url"]

        print()
        print(f"  {GREEN}Enrollment key decoded:{RESET}")
        print(f"    Public URL: {public_url}")
        if local_url:
            print(f"    LAN URL:    {local_url}")
        print()
    else:
        # Not a smart key — treat as a raw token and ask for URLs manually
        token = key_input
        print()
        print(f"  {DIM}That looks like a raw token. Enter the Lighthouse URLs:{RESET}")
        print()

        # Get public URL
        print(f"  {DIM}Public URL is the internet-reachable address.{RESET}")
        print(f"  {DIM}Example: https://YOUR_PUBLIC_IP:9443{RESET}")
        while True:
            public_url = input(f"  Lighthouse public URL: ").strip()
            if public_url and public_url.startswith("https://"):
                break
            if public_url and not public_url.startswith("https://"):
                print(f"  {RED}URL must start with https://{RESET}")
            else:
                print(f"  {RED}URL cannot be empty{RESET}")

        # Get local URL (optional)
        print()
        print(f"  {DIM}LAN URL is the local network address (skip if remote only).{RESET}")
        print(f"  {DIM}Example: https://YOUR_LIGHTHOUSE_IP:8443{RESET}")
        local_url = input(f"  Lighthouse LAN URL (Enter to skip): ").strip()
        if local_url and not local_url.startswith("https://"):
            print(f"  {YELLOW}Adding https:// prefix{RESET}")
            local_url = f"https://{local_url}"

    # Try to reach the Lighthouse — smart URL selection
    print(f"  Connecting to Lighthouse...")

    enroll_url = None
    if local_url:
        print(f"  {DIM}Trying LAN: {local_url}...{RESET}", end=" ", flush=True)
        if probe_lighthouse(local_url):
            print(f"{GREEN}reachable{RESET}")
            enroll_url = local_url
        else:
            print(f"{YELLOW}not reachable{RESET}")

    if not enroll_url:
        print(f"  {DIM}Trying public: {public_url}...{RESET}", end=" ", flush=True)
        if probe_lighthouse(public_url):
            print(f"{GREEN}reachable{RESET}")
            enroll_url = public_url
        else:
            print(f"{RED}not reachable{RESET}")
            print()
            print(f"  {RED}Cannot reach Lighthouse at either URL.{RESET}")
            print(f"  Check that the Lighthouse is running and the URLs are correct.")
            pause()
            return False

    # Perform enrollment via client.py
    print()
    print(f"  Enrolling via {enroll_url}...")
    print()

    python = get_python()
    cmd = [python, str(CLIENT_SCRIPT), "enroll",
           "--token", token,
           "--lighthouse-public", public_url]

    # If we're enrolling via LAN URL, we need to pass it as the reachable URL
    # but still save the public URL for remote access
    if enroll_url != public_url:
        # Enrolling via LAN — pass the LAN URL as the --lighthouse-public
        # for the enrollment HTTP call, but the Lighthouse response will
        # contain both URLs from its config
        cmd = [python, str(CLIENT_SCRIPT), "enroll",
               "--token", token,
               "--lighthouse-public", enroll_url]

    result = subprocess.run(cmd, text=True)

    if result.returncode != 0:
        print(f"\n  {RED}Enrollment failed.{RESET}")
        pause()
        return False

    # Post-enrollment: ensure both URLs are saved
    # The Lighthouse returns its configured URLs, but if the user provided
    # a local URL that differs, update the enrollment file
    enrollment = load_enrollment()
    updated = False
    if public_url and enrollment.get("lighthouse_public") != public_url:
        enrollment["lighthouse_public"] = public_url
        updated = True
    if local_url and enrollment.get("lighthouse_local") != local_url:
        enrollment["lighthouse_local"] = local_url
        updated = True
    if updated:
        ENROLLMENT_PATH.write_text(json.dumps(enrollment, indent=2))

    print(f"\n  {GREEN}Enrollment complete!{RESET}")
    print()

    # Offer to start the service
    start_now = input(f"  Start the VPN client now? [Y/n]: ").strip().lower()
    if start_now in ("", "y", "yes"):
        start_service()

    # Offer to generate identity
    if not IDENTITY_PATH.exists():
        print()
        gen_id = input(f"  Generate IPv6 identity for deterministic addressing? [Y/n]: ").strip().lower()
        if gen_id in ("", "y", "yes"):
            _generate_identity()

    pause()
    return True


# =============================================================================
# IDENTITY MANAGER
# =============================================================================

def _run_identity_cmd(args: list[str], need_admin: bool = False) -> bool:
    """Run an identity_manager.py command."""
    if need_admin and not is_admin():
        request_admin("Identity changes require elevated privileges")
        return False

    python = get_python()
    cmd = [python, str(IDENTITY_SCRIPT)] + args
    if IS_LINUX and need_admin and not is_admin():
        cmd = ["sudo"] + cmd

    result = subprocess.run(cmd, text=True)
    return result.returncode == 0


def _generate_identity():
    """Generate a new identity config."""
    enrollment = load_enrollment()
    device_id = enrollment.get("device_id", "")

    python = get_python()
    cmd = [python, str(IDENTITY_SCRIPT), "--generate"]
    if device_id:
        cmd.extend(["--device-id", enrollment.get("node_name", device_id)])

    subprocess.run(cmd, text=True)


def identity_menu():
    """Identity manager submenu."""
    while True:
        print_header("Identity Manager")

        identity = load_identity()
        has_identity = bool(identity)
        has_backup = IDENTITY_BACKUP_PATH.exists()

        # Show current state summary
        if has_identity:
            print(f"  Config:     {GREEN}found{RESET} ({IDENTITY_PATH})")
            print(f"  IPv6 Token: {identity.get('ipv6_token', 'not set')}")
            print(f"  MAC:        {identity.get('mac_address', 'not set')}")
            print(f"  Hostname:   {identity.get('hostname', 'not set')}")
        else:
            print(f"  Config:     {YELLOW}not generated{RESET}")
        print()

        # Two-tier menu
        print(f"  {BOLD}Quick Actions:{RESET}")
        print(f"  [1] Show identity status")
        print(f"  [2] Generate identity config")
        print(f"  [3] Apply IPv6 token only {DIM}(recommended for Cobra){RESET}")
        print()
        print(f"  {BOLD}Full Network Identity:{RESET}")
        print(f"  [4] Apply full identity {DIM}(MAC + hostname + IPv6 + DHCP + TTL){RESET}")
        print(f"  [5] Restore original identity")
        print()
        print(f"  {BOLD}Startup:{RESET}")
        print(f"  [6] Enable identity on boot")
        print(f"  [7] Disable identity on boot")
        print()
        print(f"  [0] Back to main menu")
        print()

        choice = input(f"  Select: ").strip()

        if choice == "1":
            print()
            _run_identity_cmd(["--status"])
            pause()

        elif choice == "2":
            _generate_identity()
            pause()

        elif choice == "3":
            # Apply IPv6 token only — lighter touch
            if not has_identity:
                print(f"\n  {YELLOW}No identity config found. Generating...{RESET}")
                _generate_identity()
                identity = load_identity()
                if not identity:
                    print(f"  {RED}Failed to generate identity config{RESET}")
                    pause()
                    continue

            token = identity.get("ipv6_token", "")
            interface = identity.get("interface", "")
            if not token:
                print(f"  {RED}No IPv6 token in config{RESET}")
                pause()
                continue

            print(f"\n  Applying IPv6 token: {token}")
            print(f"  Interface: {interface}")

            if IS_WINDOWS:
                # Windows: use netsh to set token
                result = run_cmd([
                    "netsh", "interface", "ipv6", "set", "global",
                    f"randomizeidentifiers=disabled"
                ])
                result = run_cmd([
                    "powershell", "-Command",
                    f"Set-NetIPv6Protocol -RandomizeIdentifiers Disabled; "
                    f"Set-NetIPv6Protocol -UseTemporaryAddresses Disabled"
                ])
                result = run_cmd([
                    "netsh", "interface", "ipv6", "set", "privacy",
                    "state=disabled"
                ])
                # Set the token via identity manager (it handles platform details)
                _run_identity_cmd(["--apply"], need_admin=True)
                print(f"\n  {GREEN}IPv6 token applied{RESET}")
                print(f"  {DIM}Run 'identity status' to verify{RESET}")
            else:
                _run_identity_cmd(["--apply"], need_admin=True)
                print(f"\n  {GREEN}IPv6 token applied{RESET}")
            pause()

        elif choice == "4":
            if not has_identity:
                print(f"\n  {YELLOW}No identity config found. Generating...{RESET}")
                _generate_identity()
            print(f"\n  {BOLD}Applying full network identity...{RESET}")
            print(f"  {DIM}This changes: MAC, hostname, IPv6 token, MTU, DHCP, TTL{RESET}")
            confirm = input(f"  Continue? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                _run_identity_cmd(["--apply"], need_admin=True)
            pause()

        elif choice == "5":
            if not has_backup:
                print(f"\n  {YELLOW}No backup found — nothing to restore{RESET}")
            else:
                confirm = input(f"\n  Restore original identity? [y/N]: ").strip().lower()
                if confirm in ("y", "yes"):
                    _run_identity_cmd(["--restore"], need_admin=True)
            pause()

        elif choice == "6":
            _enable_identity_startup()
            pause()

        elif choice == "7":
            _disable_identity_startup()
            pause()

        elif choice == "0":
            break


def _enable_identity_startup():
    """Enable identity apply on boot."""
    if IS_LINUX:
        # Create a systemd service that runs before cobratail
        if not is_admin():
            request_admin("Installing systemd service")
            return

        python = get_python()
        service_content = textwrap.dedent(f"""\
            [Unit]
            Description=Cobra Identity Manager
            Before={SERVICE_NAME}.service
            After=network-online.target

            [Service]
            Type=oneshot
            ExecStart={python} {IDENTITY_SCRIPT} --apply
            RemainAfterExit=yes
            WorkingDirectory={IDENTITY_SCRIPT.parent}

            [Install]
            WantedBy=multi-user.target
        """)
        service_path = Path("/etc/systemd/system/cobra-identity.service")
        service_path.write_text(service_content)
        run_cmd(["sudo", "systemctl", "daemon-reload"])
        run_cmd(["sudo", "systemctl", "enable", "cobra-identity.service"])
        print(f"  {GREEN}Identity will apply on boot (before client starts){RESET}")
    else:
        # Windows: Scheduled Task as SYSTEM at startup
        python = get_python()
        ps_commands = [
            f'$action = New-ScheduledTaskAction -Execute "{python}" '
            f'-Argument "{IDENTITY_SCRIPT} --apply" '
            f'-WorkingDirectory "{IDENTITY_SCRIPT.parent}"',
            '$trigger = New-ScheduledTaskTrigger -AtStartup',
            '$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries '
            '-DontStopIfGoingOnBatteries -StartWhenAvailable '
            '-ExecutionTimeLimit (New-TimeSpan -Minutes 5)',
            '$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" '
            '-LogonType ServiceAccount -RunLevel Highest',
            f'Register-ScheduledTask -TaskName "{IDENTITY_TASK_NAME}" '
            f'-Action $action -Trigger $trigger -Settings $settings '
            f'-Principal $principal '
            f'-Description "Applies Cobra network identity at startup" -Force',
        ]
        result = run_cmd(["powershell", "-Command", "; ".join(ps_commands)])
        if result.returncode == 0:
            print(f"  {GREEN}Identity will apply on boot (as SYSTEM, before login){RESET}")
        else:
            print(f"  {RED}Failed: {result.stderr.strip()}{RESET}")


def _disable_identity_startup():
    """Disable identity apply on boot."""
    if IS_LINUX:
        run_cmd(["sudo", "systemctl", "disable", "cobra-identity.service"])
        service_path = Path("/etc/systemd/system/cobra-identity.service")
        if service_path.exists() and is_admin():
            service_path.unlink()
            run_cmd(["sudo", "systemctl", "daemon-reload"])
        print(f"  {GREEN}Identity startup disabled{RESET}")
    else:
        result = run_cmd([
            "powershell", "-Command",
            f"Unregister-ScheduledTask -TaskName '{IDENTITY_TASK_NAME}' -Confirm:$false"
        ])
        if result.returncode == 0:
            print(f"  {GREEN}Identity startup disabled{RESET}")
        else:
            print(f"  {RED}Failed or task not found: {result.stderr.strip()}{RESET}")


# =============================================================================
# CONNECTION STATUS & INFO
# =============================================================================

def show_connection_details():
    """Display detailed connection information."""
    print_header("Connection Details")

    enrollment = load_enrollment()
    state = load_state()
    status = get_service_status()

    # Service status
    if status == "running":
        status_str = f"{GREEN}● running{RESET}"
    elif status == "stopped":
        status_str = f"{RED}● stopped{RESET}"
    else:
        status_str = f"{YELLOW}● {status}{RESET}"

    print(f"  Service:        {status_str}")
    pid = get_client_pid()
    if pid:
        print(f"  PID:            {pid}")
    print()

    # Enrollment info
    print(f"  {BOLD}Enrollment{RESET}")
    print(f"  Node name:      {enrollment.get('node_name', 'not enrolled')}")
    print(f"  Device ID:      {enrollment.get('device_id', 'not enrolled')}")
    print(f"  Enrolled at:    {enrollment.get('enrolled_at', 'never')}")
    print()

    # Connection info
    print(f"  {BOLD}Connection{RESET}")
    print(f"  VPN address:    {state.get('vpn_address', 'not connected')}")
    print(f"  Lighthouse:     {state.get('lighthouse_url', 'n/a')}")
    print(f"  Local network:  {state.get('is_local', 'unknown')}")
    print(f"  WG endpoint:    {state.get('wg_endpoint', 'n/a')}")
    print(f"  Connected at:   {state.get('connected_at', 'never')}")
    print()

    # URLs
    print(f"  {BOLD}Lighthouse URLs{RESET}")
    print(f"  Public:         {enrollment.get('lighthouse_public', 'not set')}")
    print(f"  LAN:            {enrollment.get('lighthouse_local', 'not set')}")
    print()

    # Cert fingerprint
    fp = enrollment.get("cert_fingerprint", "")
    if fp:
        print(f"  {BOLD}TLS{RESET}")
        print(f"  Cert pin:       {fp[:32]}...")
    print()

    # Mesh peers
    if MESH_PEERS_PATH.exists():
        try:
            peers = json.loads(MESH_PEERS_PATH.read_text())
            if peers:
                print(f"  {BOLD}Mesh Peers ({len(peers)}){RESET}")
                for pubkey, info in peers.items():
                    mesh_ip = info.get("mesh_ip", info.get("vpn_address", "?"))
                    endpoint = info.get("endpoint", "?")
                    print(f"  {mesh_ip:18s} → {endpoint}")
                print()
        except Exception:
            pass

    pause()


def show_logs():
    """Show recent client logs."""
    print_header("Client Logs")

    if IS_LINUX:
        service_file = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")
        if service_file.exists():
            print(f"  {DIM}Showing last 50 lines from journalctl...{RESET}\n")
            subprocess.run(
                ["journalctl", "-u", SERVICE_NAME, "-n", "50", "--no-pager"],
                text=True,
            )
        else:
            log_path = LOG_DIR / "client.log"
            if log_path.exists():
                print(f"  {DIM}Showing last 50 lines from {log_path}...{RESET}\n")
                subprocess.run(["tail", "-50", str(log_path)], text=True)
            else:
                print(f"  {YELLOW}No log file found{RESET}")
    else:
        log_path = LOG_DIR / "client.log"
        if log_path.exists():
            print(f"  {DIM}Showing last 50 lines from {log_path}...{RESET}\n")
            # Read last 50 lines
            lines = log_path.read_text(errors="replace").splitlines()
            for line in lines[-50:]:
                print(f"  {line}")
        else:
            print(f"  {YELLOW}No log file found{RESET}")

    pause()


# =============================================================================
# SETTINGS
# =============================================================================

def settings_menu():
    """Settings submenu."""
    while True:
        print_header("Settings")

        enrollment = load_enrollment()

        print(f"  {BOLD}Lighthouse URLs{RESET}")
        print(f"  [1] Change public URL  {DIM}(current: {enrollment.get('lighthouse_public', 'not set')}){RESET}")
        print(f"  [2] Change LAN URL     {DIM}(current: {enrollment.get('lighthouse_local', 'not set')}){RESET}")
        print()
        print(f"  {BOLD}Service{RESET}")
        startup = f"{GREEN}enabled{RESET}" if is_startup_enabled() else f"{DIM}disabled{RESET}"
        print(f"  [3] Toggle run on startup  {DIM}(current: {startup}){RESET}")
        print()
        print(f"  {BOLD}Advanced{RESET}")
        print(f"  [4] Re-enroll this device")
        print(f"  [5] Reset all data {DIM}(removes enrollment, state, keys){RESET}")
        print()
        print(f"  [0] Back to main menu")
        print()

        choice = input(f"  Select: ").strip()

        if choice == "1":
            new_url = input(f"\n  New public URL: ").strip()
            if new_url and new_url.startswith("https://"):
                enrollment["lighthouse_public"] = new_url
                ENROLLMENT_PATH.write_text(json.dumps(enrollment, indent=2))
                print(f"  {GREEN}Updated. Restart service to apply.{RESET}")
            elif new_url:
                print(f"  {RED}URL must start with https://{RESET}")
            pause()

        elif choice == "2":
            new_url = input(f"\n  New LAN URL (empty to clear): ").strip()
            if new_url and not new_url.startswith("https://"):
                new_url = f"https://{new_url}"
            enrollment["lighthouse_local"] = new_url
            ENROLLMENT_PATH.write_text(json.dumps(enrollment, indent=2))
            print(f"  {GREEN}Updated. Restart service to apply.{RESET}")
            pause()

        elif choice == "3":
            if is_startup_enabled():
                disable_startup()
            else:
                enable_startup()
            pause()

        elif choice == "4":
            print(f"\n  {YELLOW}This will re-enroll your device with a new token.{RESET}")
            confirm = input(f"  Continue? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                # Stop service first
                if get_service_status() == "running":
                    stop_service()
                enrollment_wizard()

        elif choice == "5":
            print(f"\n  {RED}WARNING: This will delete ALL Cobra data:{RESET}")
            print(f"    - Enrollment credentials")
            print(f"    - WireGuard keys and configs")
            print(f"    - Client state and mesh peers")
            print(f"    - Identity config and backup")
            confirm = input(f"\n  Type 'DELETE' to confirm: ").strip()
            if confirm == "DELETE":
                # Stop service
                if get_service_status() == "running":
                    stop_service()
                # Remove data
                if COBRATAIL_DIR.exists():
                    shutil.rmtree(COBRATAIL_DIR, ignore_errors=True)
                # Also clean up legacy dir
                legacy = Path.home() / ".quantum_vpn"
                if legacy.exists():
                    shutil.rmtree(legacy, ignore_errors=True)
                print(f"  {GREEN}All data removed. Run 'cobra' to re-enroll.{RESET}")
            else:
                print(f"  {DIM}Cancelled{RESET}")
            pause()

        elif choice == "0":
            break


# =============================================================================
# UPDATE FROM GITHUB
# =============================================================================

def check_for_updates():
    """Check GitHub for newer version and update if available."""
    print_header("Check for Updates")

    print(f"  Current version: {VERSION}")
    print(f"  {DIM}Checking GitHub...{RESET}")

    # Try to read version from installed location
    version_path = COBRATAIL_DIR / "version.txt"
    if not version_path.exists():
        version_path = _SCRIPT_DIR / "version.txt"

    # Check GitHub (requires git)
    if not shutil.which("git"):
        print(f"\n  {YELLOW}git not installed — cannot check for updates{RESET}")
        pause()
        return

    # Try to pull updates
    repo_dir = _SCRIPT_DIR
    if (repo_dir / ".git").exists():
        print(f"  Repository: {repo_dir}")
        result = run_cmd(["git", "-C", str(repo_dir), "remote", "update"])
        if result.returncode != 0:
            print(f"  {RED}Failed to contact GitHub{RESET}")
            pause()
            return

        # Check if behind
        result = run_cmd([
            "git", "-C", str(repo_dir), "status", "-uno"
        ])
        output = result.stdout
        if "behind" in output.lower():
            print(f"\n  {GREEN}Update available!{RESET}")
            update = input(f"  Pull latest? [Y/n]: ").strip().lower()
            if update in ("", "y", "yes"):
                result = run_cmd(["git", "-C", str(repo_dir), "pull"])
                if result.returncode == 0:
                    print(f"  {GREEN}Updated successfully!{RESET}")
                    print(f"  {DIM}Restart the client service for changes to take effect.{RESET}")
                else:
                    print(f"  {RED}Update failed: {result.stderr.strip()}{RESET}")
        elif "up to date" in output.lower() or "up-to-date" in output.lower():
            print(f"  {GREEN}Already up to date{RESET}")
        else:
            print(f"  {DIM}{output.strip()}{RESET}")
    else:
        print(f"  {YELLOW}Not a git repository — cannot auto-update{RESET}")
        print(f"  {DIM}Download the latest from GitHub manually{RESET}")

    pause()


# =============================================================================
# MAIN MENU
# =============================================================================

def main_menu():
    """Main interactive menu loop."""
    while True:
        print_banner()

        enrollment = load_enrollment()
        status = get_service_status()

        # Status bar
        node_name = enrollment.get("node_name", "not enrolled")
        vpn_addr = load_state().get("vpn_address", "—")

        if status == "running":
            status_str = f"{GREEN}● Connected{RESET}"
        elif status == "stopped":
            status_str = f"{RED}● Disconnected{RESET}"
        else:
            status_str = f"{YELLOW}● {status}{RESET}"

        print(f"  Node: {BOLD}{node_name}{RESET}    VPN: {BOLD}{vpn_addr}{RESET}    {status_str}")
        print()

        # Menu options
        if status == "running":
            print(f"  [1] {RED}Stop{RESET} client")
            print(f"  [2] Restart client")
        else:
            print(f"  [1] {GREEN}Start{RESET} client")
            print(f"  [2] —")

        print(f"  [3] Connection details")
        print(f"  [4] Mesh peers")
        print(f"  [5] Identity manager")
        print(f"  [6] View logs")
        print(f"  [7] Settings")
        print(f"  [8] Check for updates")
        print()
        print(f"  [0] Exit")
        print()

        choice = input(f"  Select: ").strip()

        if choice == "1":
            if status == "running":
                stop_service()
                pause()
            else:
                start_service()
                pause()

        elif choice == "2":
            if status == "running":
                restart_service()
                pause()

        elif choice == "3":
            show_connection_details()

        elif choice == "4":
            show_mesh_peers()

        elif choice == "5":
            identity_menu()

        elif choice == "6":
            show_logs()

        elif choice == "7":
            settings_menu()

        elif choice == "8":
            check_for_updates()

        elif choice == "0":
            print(f"\n  {DIM}Goodbye!{RESET}\n")
            break


def show_mesh_peers():
    """Display current mesh peer information."""
    print_header("Mesh Peers")

    if not MESH_PEERS_PATH.exists():
        print(f"  {DIM}No mesh peers configured yet.{RESET}")
        print(f"  {DIM}Mesh tunnels are established automatically when the client is running.{RESET}")
        pause()
        return

    try:
        peers = json.loads(MESH_PEERS_PATH.read_text())
    except Exception:
        print(f"  {RED}Failed to read mesh peers file{RESET}")
        pause()
        return

    if not peers:
        print(f"  {DIM}No active mesh peers.{RESET}")
        pause()
        return

    print(f"  {BOLD}Active Mesh Peers ({len(peers)}){RESET}")
    print()
    print(f"  {'Mesh IP':<18s}  {'Endpoint':<28s}  {'VPN IP'}")
    print(f"  {'─' * 18}  {'─' * 28}  {'─' * 16}")

    for pubkey, info in peers.items():
        mesh_ip = info.get("mesh_ip", "—")
        vpn_ip = info.get("vpn_address", "—")
        endpoint = info.get("endpoint", "—")
        print(f"  {mesh_ip:<18s}  {endpoint:<28s}  {vpn_ip}")

    print()

    # Also try to show WireGuard handshake status
    if IS_WINDOWS:
        wg_path = r"C:\Program Files\WireGuard\wg.exe"
        if not Path(wg_path).exists():
            wg_path = "wg"
    else:
        wg_path = "wg"

    result = run_cmd([wg_path, "show", "wg_mesh", "latest-handshakes"])
    if result.returncode == 0 and result.stdout.strip():
        print(f"  {BOLD}Handshakes{RESET}")
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                pubkey_short = parts[0][:16] + "..."
                ts = int(parts[1]) if parts[1].isdigit() else 0
                if ts > 0:
                    age = int(time.time()) - ts
                    if age < 120:
                        health = f"{GREEN}healthy{RESET} ({age}s ago)"
                    elif age < 300:
                        health = f"{YELLOW}stale{RESET} ({age}s ago)"
                    else:
                        health = f"{RED}dead{RESET} ({age}s ago)"
                else:
                    health = f"{DIM}no handshake{RESET}"
                print(f"  {pubkey_short}  {health}")
        print()

    pause()


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    """CLI entry point — handles both direct commands and interactive menu."""
    import argparse

    parser = argparse.ArgumentParser(
        description="CobraTail VPN — Client Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              cobra                  Interactive menu
              cobra --start          Start the VPN client
              cobra --stop           Stop the VPN client
              cobra --status         Show connection status
              cobra --enroll         Run enrollment wizard
        """),
    )
    parser.add_argument("--start", action="store_true", help="Start client service")
    parser.add_argument("--stop", action="store_true", help="Stop client service")
    parser.add_argument("--restart", action="store_true", help="Restart client service")
    parser.add_argument("--status", action="store_true", help="Show connection status")
    parser.add_argument("--enroll", action="store_true", help="Run enrollment wizard")
    parser.add_argument("--version", action="store_true", help="Show version")

    args = parser.parse_args()

    # Direct commands (non-interactive)
    if args.version:
        print(f"CobraTail VPN Client v{VERSION}")
        return

    if args.start:
        if not is_enrolled():
            print(f"  {RED}Not enrolled. Run 'cobra --enroll' first.{RESET}")
            sys.exit(1)
        start_service()
        return

    if args.stop:
        stop_service()
        return

    if args.restart:
        if not is_enrolled():
            print(f"  {RED}Not enrolled. Run 'cobra --enroll' first.{RESET}")
            sys.exit(1)
        restart_service()
        return

    if args.status:
        enrollment = load_enrollment()
        state = load_state()
        status = get_service_status()

        if status == "running":
            print(f"  {GREEN}● Connected{RESET}")
        else:
            print(f"  {RED}● Disconnected{RESET}")

        print(f"  Node:       {enrollment.get('node_name', 'not enrolled')}")
        print(f"  VPN IP:     {state.get('vpn_address', '—')}")
        print(f"  Lighthouse: {state.get('lighthouse_url', '—')}")
        print(f"  Local:      {state.get('is_local', '—')}")
        pid = get_client_pid()
        if pid:
            print(f"  PID:        {pid}")
        return

    if args.enroll:
        enrollment_wizard()
        return

    # Interactive mode — enrollment wizard on first run, otherwise main menu
    try:
        if not is_enrolled():
            print_banner()
            print(f"  {YELLOW}This device is not enrolled yet.{RESET}")
            print()
            if enrollment_wizard():
                main_menu()
        else:
            main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {DIM}Goodbye!{RESET}\n")


if __name__ == "__main__":
    main()