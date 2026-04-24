#!/usr/bin/env python3
"""
COBRA SENTINEL — AI-Powered Self-Healing Network Diagnostic Agent

An optional, toggleable service that monitors Cobra Tail VPN logs for
networking errors and uses a local LLM (llama.cpp) to diagnose and
automatically apply corrective CLI commands.

Architecture-aware: detects ARM64 (Raspberry Pi) vs x86_64 vs Windows
and selects the appropriate system commands accordingly.

Designed to run as a systemd service on a Raspberry Pi 4 or any Linux
node in the Cobra Tail mesh. Can be toggled on/off via config.json,
and includes hardware guards that auto-disable under high CPU/RAM load.

Modes:
    - always-on:   Continuously monitors logs (for capable hardware)
    - on-demand:   Wakes only when a connection failure is detected
    - disabled:    Logs errors for manual review, no AI overhead

Dependencies:
    pip install psutil requests

Usage:
    python cobra_sentinel.py                   → Run with defaults
    python cobra_sentinel.py --config /path    → Custom config location
    python cobra_sentinel.py --detect          → Detect hardware and exit
    python cobra_sentinel.py --install         → Install as systemd service
    python cobra_sentinel.py --uninstall       → Remove systemd service

Developed by: Cobra Tech LLC
"""

import argparse
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── Platform & Architecture Detection ───────────────────────────────────────

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"
ARCH = platform.machine().lower()  # aarch64, x86_64, amd64, armv7l, etc.
IS_ARM64 = ARCH in ("aarch64", "arm64")
IS_X86_64 = ARCH in ("x86_64", "amd64")
IS_ARM32 = ARCH in ("armv7l", "armv6l")
IS_PI = IS_LINUX and IS_ARM64 and Path("/proc/device-tree/model").exists()

# ─── Directory Layout ────────────────────────────────────────────────────────

def _detect_cobratail_dir() -> Path:
    """Detect the CobraTail install directory (mirrors client.py logic)."""
    if IS_WINDOWS:
        installed = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CobraTail"
    else:
        installed = Path("/opt/cobratail")

    if (installed / ".cobratail").exists():
        return installed

    script_dir = Path(__file__).parent.resolve()
    if (script_dir / "enrollment.json").exists() or (script_dir / "config" / "enrollment.json").exists():
        return script_dir

    legacy = Path.home() / ".quantum_vpn"
    if legacy.exists():
        return legacy

    return installed

COBRATAIL_DIR = _detect_cobratail_dir()

if (COBRATAIL_DIR / "config").is_dir() or (COBRATAIL_DIR / ".cobratail").exists():
    CONFIG_DIR = COBRATAIL_DIR / "config"
    DATA_DIR = COBRATAIL_DIR / "data"
    LOG_DIR = COBRATAIL_DIR / "logs"
else:
    CONFIG_DIR = COBRATAIL_DIR
    DATA_DIR = COBRATAIL_DIR
    LOG_DIR = COBRATAIL_DIR

SENTINEL_CONFIG_PATH = CONFIG_DIR / "sentinel_config.json"
SENTINEL_LOG_PATH = LOG_DIR / "cobra-sentinel.log"
TROUBLESHOOTING_PATH = CONFIG_DIR / "troubleshooting.md"
FIX_HISTORY_PATH = DATA_DIR / "sentinel_fix_history.json"

# Which log file to watch for errors
COBRATAIL_LOG_PATH = LOG_DIR / "cobra-tail.log"

# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(log_path: Path, verbose: bool = False) -> logging.Logger:
    """Configure dual-output logging: file + console."""
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("cobra-sentinel")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [SENTINEL] %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(str(log_path), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger

log = setup_logging(SENTINEL_LOG_PATH)

# ─── Default Configuration ───────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "ai_enabled": True,
    "mode": "on-demand",               # "always-on", "on-demand", "disabled"
    "llm_endpoint": "http://127.0.0.1:8080/completion",  # llama.cpp server
    "llm_model": "default",
    "llm_timeout_seconds": 120,
    "log_file": str(COBRATAIL_LOG_PATH),
    "troubleshooting_file": str(TROUBLESHOOTING_PATH),
    "poll_interval_seconds": 5,
    "max_retries_per_error": 3,
    "auto_execute": True,              # False = suggest only, True = apply fix
    "require_confirmation": False,      # True = prompt user before applying
    "hardware_guard": {
        "enabled": True,
        "cpu_threshold_percent": 90,
        "ram_threshold_percent": 85,
        "temp_threshold_celsius": 80,
        "cooldown_seconds": 300,
    },
    "error_patterns": [
        r"ERROR.*connection.*(?:refused|reset|timed?\s*out|lost|failed)",
        r"ERROR.*WireGuard.*(?:handshake|timeout|unreachable)",
        r"ERROR.*DNS.*(?:resolution|lookup|failed)",
        r"ERROR.*tunnel.*(?:down|failed|broken|dropped)",
        r"ERROR.*lighthouse.*(?:unreachable|connection|failed)",
        r"CRITICAL.*network",
        r"ERROR.*mesh.*(?:failed|timeout|rejected)",
        r"ERROR.*endpoint.*(?:unreachable|failed)",
        r"ERROR.*heartbeat.*(?:failed|timeout)",
        r"ERROR.*PSK.*(?:rotation|expired|failed)",
        r"WARNING.*NAT classification.*only \d+ STUN",
        r"WARNING.*Path monitor.*stale handshake",
        r"WARNING.*Path monitor.*exhausted.*retries",
        r"WARNING.*STUN.*(?:failed|DNS|resolution)",
    ],
    "safe_commands_whitelist": [
        "systemctl restart",
        "systemctl start",
        "systemctl stop",
        "systemctl status",
        "wg",
        "wg-quick",
        "ip link",
        "ip addr",
        "ip route",
        "ping",
        "resolvectl",
        "systemd-resolve",
        "nslookup",
        "dig",
        "netstat",
        "ss",
        "iptables -L",
        "ufw status",
        "nmcli",
        "ifconfig",
        "route",
        "traceroute",
        "tracert",
        "nft list",
        "journalctl",
        "cat /etc/resolv.conf",
        "ipconfig",
        "netsh",
    ],
    "blocked_commands": [
        "rm -rf /",
        "dd if=",
        "mkfs",
        "fdisk",
        "parted",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "passwd",
        "useradd",
        "userdel",
        "chmod 777",
        "> /dev/sd",
        "curl | sh",
        "wget | sh",
        "eval",
        "python -c",
        "base64 -d",
    ],
}


# ─── Hardware Detection ──────────────────────────────────────────────────────

class HardwareProfile:
    """Detect and store device hardware characteristics."""

    def __init__(self):
        self.system = platform.system()
        self.arch = platform.machine()
        self.hostname = platform.node()
        self.python_version = platform.python_version()
        self.model = self._detect_model()
        self.ram_total_mb = self._get_total_ram_mb()
        self.cpu_count = os.cpu_count() or 1
        self.is_pi = IS_PI
        self.pi_model = self._detect_pi_model()
        self.ai_capable = self._assess_ai_capability()

    def _detect_model(self) -> str:
        """Read device model string."""
        model_path = Path("/proc/device-tree/model")
        if model_path.exists():
            try:
                return model_path.read_text().strip().rstrip("\x00")
            except Exception:
                pass
        if IS_WINDOWS:
            try:
                r = subprocess.run(
                    ["wmic", "computersystem", "get", "model"],
                    capture_output=True, text=True, timeout=5,
                )
                lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip() and l.strip() != "Model"]
                if lines:
                    return lines[0]
            except Exception:
                pass
        return f"{self.system} {self.arch}"

    def _detect_pi_model(self) -> str:
        """Identify specific Raspberry Pi model."""
        if not self.is_pi:
            return "N/A"
        model = self.model.lower()
        if "pi 5" in model:
            return "pi5"
        elif "pi 4" in model:
            return "pi4"
        elif "pi 3" in model:
            return "pi3"
        elif "pi zero 2" in model:
            return "pi_zero_2w"
        elif "pi zero" in model:
            return "pi_zero"
        return "pi_unknown"

    def _get_total_ram_mb(self) -> int:
        """Get total system RAM in MB."""
        if HAS_PSUTIL:
            return int(psutil.virtual_memory().total / (1024 * 1024))
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) // 1024
        except Exception:
            pass
        return 0

    def _assess_ai_capability(self) -> bool:
        """Determine if this device can run a local LLM."""
        if self.ram_total_mb < 1500:
            return False
        if self.pi_model in ("pi_zero", "pi_zero_2w"):
            return False
        if IS_ARM32:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "system": self.system,
            "arch": self.arch,
            "hostname": self.hostname,
            "model": self.model,
            "pi_model": self.pi_model,
            "ram_total_mb": self.ram_total_mb,
            "cpu_count": self.cpu_count,
            "is_pi": self.is_pi,
            "ai_capable": self.ai_capable,
        }

    def __str__(self) -> str:
        return (
            f"Device: {self.model}\n"
            f"Arch: {self.arch} | OS: {self.system}\n"
            f"RAM: {self.ram_total_mb} MB | CPUs: {self.cpu_count}\n"
            f"Pi Model: {self.pi_model}\n"
            f"AI Capable: {'Yes' if self.ai_capable else 'No'}"
        )


# ─── Configuration Manager ──────────────────────────────────────────────────

class SentinelConfig:
    """Load, save, and manage sentinel configuration."""

    def __init__(self, config_path: Path = SENTINEL_CONFIG_PATH):
        self.config_path = config_path
        self.data: dict = {}
        self.load()

    def load(self) -> dict:
        """Load config from disk, merging with defaults."""
        self.data = dict(DEFAULT_CONFIG)
        if self.config_path.exists():
            try:
                user_cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
                self._deep_merge(self.data, user_cfg)
                log.info(f"Config loaded from {self.config_path}")
            except (json.JSONDecodeError, IOError) as e:
                log.warning(f"Config load failed ({e}), using defaults")
        else:
            log.info("No config file found, using defaults")
        return self.data

    def save(self) -> None:
        """Persist current config to disk."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(self.data, indent=2, default=str),
            encoding="utf-8",
        )
        log.info(f"Config saved to {self.config_path}")

    def get(self, key: str, default=None):
        """Get a top-level config value."""
        return self.data.get(key, default)

    def set(self, key: str, value) -> None:
        """Set a top-level config value and save."""
        self.data[key] = value
        self.save()

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> None:
        """Recursively merge override into base."""
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                SentinelConfig._deep_merge(base[k], v)
            else:
                base[k] = v


# ─── Architecture-Aware Command Builder ──────────────────────────────────────

class CommandBuilder:
    """Generate platform-correct CLI commands for common network fixes."""

    def __init__(self, hw: HardwareProfile):
        self.hw = hw

    def get_platform_context(self) -> str:
        """Return a description string for the LLM so it picks the right commands."""
        if IS_WINDOWS:
            return (
                "TARGET PLATFORM: Windows (x86_64)\n"
                "Use Windows commands: netsh, ipconfig, route, powershell, "
                "net start/stop, sc.exe.\n"
                "WireGuard CLI: 'wireguard /installtunnelservice', 'net stop WireGuardTunnel$wg_quantum'.\n"
                "Do NOT use Linux commands (ip, systemctl, wg-quick)."
            )
        elif IS_LINUX and IS_ARM64:
            init_sys = "systemd" if shutil.which("systemctl") else "sysvinit"
            return (
                f"TARGET PLATFORM: Linux ARM64 (Raspberry Pi — {self.hw.pi_model})\n"
                f"Init system: {init_sys}\n"
                "Use Linux commands: ip, wg, wg-quick, systemctl, resolvectl, journalctl.\n"
                "Network manager: likely NetworkManager or dhcpcd depending on OS.\n"
                "WireGuard interface names: wg_quantum (coordination), wg_mesh (data).\n"
                "Service names: cobratail.service (VPN client), lighthouse.service (Lighthouse server), cobra-sentinel.service (AI agent), cobra-identity.service (identity spoof).\n"
                "Do NOT use Windows commands (netsh, ipconfig)."
            )
        elif IS_LINUX and IS_X86_64:
            return (
                "TARGET PLATFORM: Linux x86_64 (amd64)\n"
                "Use Linux commands: ip, wg, wg-quick, systemctl, resolvectl, journalctl.\n"
                "WireGuard interface names: wg_quantum (coordination), wg_mesh (data).\n"
                "Do NOT use Windows commands."
            )
        else:
            return (
                f"TARGET PLATFORM: {self.hw.system} {self.hw.arch}\n"
                "Use standard POSIX commands where possible."
            )

    def restart_wireguard(self, interface: str = "wg_quantum") -> str:
        """Platform-correct WireGuard restart command."""
        if IS_WINDOWS:
            svc = f"WireGuardTunnel${interface}"
            return f'net stop "{svc}" & net start "{svc}"'
        return f"sudo wg-quick down {interface} && sudo wg-quick up {interface}"

    def restart_service(self, service_name: str) -> str:
        """Platform-correct service restart."""
        if IS_WINDOWS:
            return f'net stop "{service_name}" & net start "{service_name}"'
        return f"sudo systemctl restart {service_name}"

    def flush_dns(self) -> str:
        """Platform-correct DNS flush."""
        if IS_WINDOWS:
            return "ipconfig /flushdns"
        return "sudo resolvectl flush-caches 2>/dev/null || sudo systemd-resolve --flush-caches 2>/dev/null"

    def check_interface(self, interface: str = "wg_quantum") -> str:
        """Platform-correct interface check."""
        if IS_WINDOWS:
            return f"netsh interface show interface {interface}"
        return f"ip link show {interface}"

    def check_dns(self) -> str:
        if IS_WINDOWS:
            return "nslookup google.com"
        return "dig google.com +short 2>/dev/null || nslookup google.com"

    def ping_gateway(self) -> str:
        if IS_WINDOWS:
            return "ping -n 1 -w 3000 10.100.0.1"
        return "ping -c 1 -W 3 10.100.0.1"


# ─── Command Safety Validator ────────────────────────────────────────────────

class CommandValidator:
    """Validates that LLM-suggested commands are safe to execute."""

    def __init__(self, config: SentinelConfig):
        self.whitelist = config.get("safe_commands_whitelist", [])
        self.blocklist = config.get("blocked_commands", [])

    def is_safe(self, command: str) -> Tuple[bool, str]:
        """
        Validate a command against whitelist/blocklist.
        Returns (is_safe: bool, reason: str).
        """
        cmd_lower = command.lower().strip()

        # Block empty commands
        if not cmd_lower:
            return False, "Empty command"

        # Check blocklist first (takes priority)
        for blocked in self.blocklist:
            if blocked.lower() in cmd_lower:
                return False, f"Blocked pattern detected: '{blocked}'"

        # Check for shell injection attempts
        injection_patterns = [
            r";\s*rm\s",
            r"\$\(",
            r"`[^`]+`",
            r"\|\s*sh\b",
            r"\|\s*bash\b",
            r"&&\s*rm\s",
            r">\s*/dev/[sh]d",
            r">\s*/etc/",
            r"chmod\s+[0-7]*7[0-7]*\s+/",
        ]
        for pattern in injection_patterns:
            if re.search(pattern, cmd_lower):
                return False, f"Potential injection detected: pattern '{pattern}'"

        # Verify at least one whitelist prefix matches
        cmd_base = cmd_lower.split("|")[0].strip()
        # Strip leading sudo
        if cmd_base.startswith("sudo "):
            cmd_base = cmd_base[5:].strip()

        matched = False
        for allowed in self.whitelist:
            if cmd_base.startswith(allowed.lower()):
                matched = True
                break

        if not matched:
            return False, f"Command '{cmd_base[:40]}...' not in whitelist"

        return True, "OK"

    def validate_multi(self, commands: List[str]) -> List[Tuple[str, bool, str]]:
        """Validate multiple commands. Returns list of (cmd, is_safe, reason)."""
        results = []
        for cmd in commands:
            # Handle chained commands (&&, ||, ;)
            sub_cmds = re.split(r'\s*(?:&&|\|\||;)\s*', cmd)
            all_safe = True
            reason = "OK"
            for sub in sub_cmds:
                sub = sub.strip()
                if not sub:
                    continue
                safe, r = self.is_safe(sub)
                if not safe:
                    all_safe = False
                    reason = r
                    break
            results.append((cmd, all_safe, reason))
        return results


# ─── Log Watcher (fallback) ──────────────────────────────────────────────────

class LogWatcher:
    """
    Watches the Cobra Tail log file for error patterns.
    Uses file position tracking to only process new lines (like tail -f).
    Kept as a fallback alongside the event-driven SentinelListener
    to catch errors from sources that don't have notify_sentinel wired in.
    """

    def __init__(self, log_path: Path, patterns: List[str]):
        self.log_path = log_path
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self._position: int = 0
        self._inode: int = 0
        self._initialize_position()

    def _initialize_position(self) -> None:
        """Start at end of file so we only catch new errors."""
        try:
            stat = self.log_path.stat()
            self._position = stat.st_size
            self._inode = stat.st_ino
        except FileNotFoundError:
            self._position = 0
            self._inode = 0

    def _check_rotation(self) -> bool:
        """Detect if the log file was rotated (inode change or shrinkage)."""
        try:
            stat = self.log_path.stat()
            if stat.st_ino != self._inode or stat.st_size < self._position:
                self._inode = stat.st_ino
                self._position = 0
                return True
        except FileNotFoundError:
            self._position = 0
            self._inode = 0
        return False

    def poll(self) -> List[Dict]:
        """
        Read new lines from log file. Returns list of matched errors:
        [{"line": str, "pattern": str, "timestamp": str}, ...]
        """
        if not self.log_path.exists():
            return []

        self._check_rotation()
        errors = []

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._position)
                for line in f:
                    line = line.rstrip("\n")
                    for pat in self.patterns:
                        if pat.search(line):
                            errors.append({
                                "line": line,
                                "pattern": pat.pattern,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })
                            break  # One match per line is enough
                self._position = f.tell()
        except (IOError, OSError) as e:
            log.warning(f"Log read error: {e}")

        return errors


# ─── Event Listener (replaces LogWatcher) ────────────────────────────────────

SENTINEL_SOCKET_PATH = Path("/tmp/cobra-sentinel.sock")
SENTINEL_TCP_PORT = 9877  # Fallback for Windows


class SentinelListener:
    """
    Listens for error events pushed directly from client.py / lighthouse.py
    via a Unix domain socket (Linux) or localhost TCP (Windows).

    Protocol: one JSON object per line, newline-terminated.
    {
        "source": "client" | "lighthouse",
        "severity": "error" | "critical" | "warning",
        "error": "the error message text",
        "context": {
            "consecutive_failures": 3,
            "component": "heartbeat",
            "lighthouse_url": "https://...",
            ...any extra context the caller wants to pass
        },
        "timestamp": "2025-06-15T12:34:56Z"
    }
    """

    def __init__(self):
        self._server = None
        self._thread = None
        self._queue: list = []
        self._lock = threading.Lock()
        self._running = False

    def start(self) -> None:
        """Start the listener in a background thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._listen, daemon=True, name="sentinel-listener",
        )
        self._thread.start()

    def stop(self) -> None:
        """Shut down the listener."""
        self._running = False
        if self._server:
            self._server.close()
        # Clean up socket file
        if not IS_WINDOWS and SENTINEL_SOCKET_PATH.exists():
            try:
                SENTINEL_SOCKET_PATH.unlink()
            except OSError:
                pass

    def poll(self) -> List[Dict]:
        """Drain and return all queued error events."""
        with self._lock:
            events = list(self._queue)
            self._queue.clear()
        return events

    def _listen(self) -> None:
        """Main listener loop — accepts connections and reads error events."""
        if IS_WINDOWS:
            self._listen_tcp()
        else:
            self._listen_unix()

    def _listen_unix(self) -> None:
        """Listen on a Unix domain socket."""
        # Clean up stale socket
        if SENTINEL_SOCKET_PATH.exists():
            try:
                SENTINEL_SOCKET_PATH.unlink()
            except OSError:
                pass

        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.settimeout(2.0)

        try:
            self._server.bind(str(SENTINEL_SOCKET_PATH))
            # Make socket world-writable so client running as different user can connect
            os.chmod(str(SENTINEL_SOCKET_PATH), 0o777)
            self._server.listen(5)
            log.info(f"Sentinel listening on {SENTINEL_SOCKET_PATH}")
        except OSError as e:
            log.error(f"Failed to bind sentinel socket: {e}")
            return

        self._accept_loop()

    def _listen_tcp(self) -> None:
        """Listen on localhost TCP (Windows fallback)."""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.settimeout(2.0)

        try:
            self._server.bind(("127.0.0.1", SENTINEL_TCP_PORT))
            self._server.listen(5)
            log.info(f"Sentinel listening on 127.0.0.1:{SENTINEL_TCP_PORT}")
        except OSError as e:
            log.error(f"Failed to bind sentinel TCP port: {e}")
            return

        self._accept_loop()

    def _accept_loop(self) -> None:
        """Accept connections and read events."""
        while self._running:
            try:
                conn, addr = self._server.accept()
                threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    log.warning("Sentinel listener socket closed")
                break

    def _handle_connection(self, conn: socket.socket) -> None:
        """Read a single event from a connection."""
        try:
            conn.settimeout(5.0)
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break

            if data:
                for line in data.decode("utf-8", errors="replace").strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        # Normalize into the format CobraSentinel expects
                        normalized = {
                            "line": event.get("error", ""),
                            "source": event.get("source", "unknown"),
                            "severity": event.get("severity", "error"),
                            "context": event.get("context", {}),
                            "timestamp": event.get(
                                "timestamp",
                                datetime.now(timezone.utc).isoformat(),
                            ),
                            "pattern": "direct_event",
                        }
                        with self._lock:
                            self._queue.append(normalized)
                        log.info(
                            f"Received event from {normalized['source']}: "
                            f"{normalized['line'][:100]}"
                        )
                        # Send ACK
                        conn.sendall(b'{"status":"received"}\n')
                    except json.JSONDecodeError:
                        log.warning(f"Invalid JSON from sender: {line[:100]}")
        except Exception as e:
            log.debug(f"Connection handler error: {e}")
        finally:
            conn.close()

# ─── LLM Client (llama.cpp) ─────────────────────────────────────────────────

class LLMClient:
    """Communicates with a local llama.cpp server to get diagnostic commands."""

    def __init__(self, config: SentinelConfig, cmd_builder: CommandBuilder):
        self.endpoint = config.get("llm_endpoint", "http://127.0.0.1:8080/completion")
        self.timeout = config.get("llm_timeout_seconds", 120)
        self.cmd_builder = cmd_builder
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if the llama.cpp server is running."""
        if not HAS_REQUESTS:
            log.error("'requests' module not installed — cannot contact LLM")
            return False
        try:
            health_url = self.endpoint.rsplit("/", 1)[0] + "/health"
            r = requests.get(health_url, timeout=5)
            self._available = r.status_code == 200
        except Exception:
            # Try the /completion endpoint directly with a minimal prompt
            try:
                r = requests.post(
                    self.endpoint,
                    json={"prompt": "ping", "n_predict": 1},
                    timeout=5,
                )
                self._available = r.status_code == 200
            except Exception:
                self._available = False
        return self._available

    def diagnose(self, error_text: str, troubleshooting_md: str) -> Optional[Dict]:
        """
        Send error + troubleshooting doc to the LLM.
        Returns: {"diagnosis": str, "commands": [str], "explanation": str}
        """
        platform_ctx = self.cmd_builder.get_platform_context()

        prompt = self._build_prompt(error_text, troubleshooting_md, platform_ctx)

        try:
            payload = {
                "prompt": prompt,
                "n_predict": 1024,
                "temperature": 0.1,
                "top_p": 0.9,
                "stop": ["```\n\n", "---", "END"],
                "stream": False,
            }
            r = requests.post(self.endpoint, json=payload, timeout=self.timeout)
            r.raise_for_status()
            response = r.json()
            content = response.get("content", "") or response.get("choices", [{}])[0].get("text", "")

            return self._parse_response(content)

        except requests.exceptions.Timeout:
            log.error("LLM request timed out")
            return None
        except requests.exceptions.ConnectionError:
            log.error("Cannot reach LLM server — is llama.cpp running?")
            self._available = False
            return None
        except Exception as e:
            log.error(f"LLM request failed: {e}")
            return None

    def _build_prompt(self, error: str, troubleshooting: str, platform: str) -> str:
        """Construct the diagnostic prompt for the LLM."""
        return textwrap.dedent(f"""\
            You are a network diagnostic agent for the Cobra Tail post-quantum mesh VPN.
            Your job is to read an error from the VPN log, consult the troubleshooting
            documentation, and output the exact CLI command(s) to fix the issue.

            {platform}

            RULES:
            1. Output ONLY the fix commands — one per line, inside a ```bash code block.
            2. Use the correct commands for the TARGET PLATFORM above.
            3. Each command must be a single, complete shell command.
            4. Do NOT use destructive commands (rm -rf, dd, mkfs, reboot, shutdown).
            5. Prefer restarting the specific failing service over rebooting.
            6. If the error involves DNS, flush DNS caches and check /etc/resolv.conf.
            7. If a WireGuard interface is down, bring it back up with wg-quick.
            8. If the Lighthouse is unreachable, check the local network first.
            9. Include a one-line DIAGNOSIS before the code block.
            10. Include a one-line EXPLANATION after the code block.

            TROUBLESHOOTING REFERENCE:
            {troubleshooting[:4000]}

            ERROR FROM LOG:
            {error[:1000]}

            DIAGNOSIS:
        """)

    def _parse_response(self, text: str) -> Dict:
        """Extract diagnosis, commands, and explanation from LLM output."""
        result = {
            "diagnosis": "",
            "commands": [],
            "explanation": "",
            "raw_response": text,
        }

        lines = text.strip().splitlines()

        # Extract diagnosis (first non-empty line before code block)
        in_code = False
        diag_lines = []
        cmd_lines = []
        expl_lines = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                if stripped:
                    cmd_lines.append(stripped)
            elif not cmd_lines:
                # Before code block = diagnosis
                if stripped:
                    diag_lines.append(stripped)
            else:
                # After code block = explanation
                if stripped:
                    expl_lines.append(stripped)

        result["diagnosis"] = " ".join(diag_lines).strip()
        result["commands"] = cmd_lines
        result["explanation"] = " ".join(expl_lines).strip()

        # If no code block found, try to extract commands from lines starting with $
        if not result["commands"]:
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("$ "):
                    result["commands"].append(stripped[2:])
                elif stripped.startswith("sudo ") or stripped.startswith("systemctl "):
                    result["commands"].append(stripped)

        return result


# ─── Hardware Guard ──────────────────────────────────────────────────────────

class HardwareGuard:
    """
    Monitors system resources and auto-disables the sentinel
    when CPU, RAM, or temperature exceed thresholds.
    """

    def __init__(self, config: dict, hw: HardwareProfile):
        self.enabled = config.get("enabled", True)
        self.cpu_threshold = config.get("cpu_threshold_percent", 90)
        self.ram_threshold = config.get("ram_threshold_percent", 85)
        self.temp_threshold = config.get("temp_threshold_celsius", 80)
        self.cooldown = config.get("cooldown_seconds", 300)
        self.hw = hw
        self._throttled_until: float = 0
        self._last_check: float = 0
        self._check_interval: float = 10  # Don't check more than every 10s

    def should_throttle(self) -> Tuple[bool, str]:
        """Check if the sentinel should be throttled to save resources."""
        if not self.enabled or not HAS_PSUTIL:
            return False, ""

        now = time.time()

        # Still in cooldown from a previous throttle?
        if now < self._throttled_until:
            remaining = int(self._throttled_until - now)
            return True, f"Cooling down ({remaining}s remaining)"

        # Rate-limit checks
        if now - self._last_check < self._check_interval:
            return False, ""
        self._last_check = now

        # CPU check
        cpu = psutil.cpu_percent(interval=1)
        if cpu > self.cpu_threshold:
            self._throttled_until = now + self.cooldown
            return True, f"CPU at {cpu:.0f}% (threshold: {self.cpu_threshold}%)"

        # RAM check
        ram = psutil.virtual_memory().percent
        if ram > self.ram_threshold:
            self._throttled_until = now + self.cooldown
            return True, f"RAM at {ram:.0f}% (threshold: {self.ram_threshold}%)"

        # Temperature check (Pi-specific)
        temp = self._get_cpu_temp()
        if temp is not None and temp > self.temp_threshold:
            self._throttled_until = now + self.cooldown
            return True, f"CPU temp at {temp:.0f}°C (threshold: {self.temp_threshold}°C)"

        return False, ""

    def _get_cpu_temp(self) -> Optional[float]:
        """Read CPU temperature (Linux / Raspberry Pi)."""
        if not IS_LINUX:
            return None
        try:
            temps = psutil.sensors_temperatures()
            for name in ("cpu_thermal", "cpu-thermal", "coretemp", "soc_thermal"):
                if name in temps and temps[name]:
                    return temps[name][0].current
        except Exception:
            pass
        # Fallback: direct sysfs read (Pi)
        thermal_path = Path("/sys/class/thermal/thermal_zone0/temp")
        if thermal_path.exists():
            try:
                return int(thermal_path.read_text().strip()) / 1000.0
            except Exception:
                pass
        return None


# ─── Fix History ─────────────────────────────────────────────────────────────

class FixHistory:
    """Track applied fixes to avoid infinite retry loops."""

    def __init__(self, path: Path = FIX_HISTORY_PATH):
        self.path = path
        self.entries: List[Dict] = []
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self.entries = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, IOError):
                self.entries = []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Keep last 500 entries
        self.entries = self.entries[-500:]
        self.path.write_text(
            json.dumps(self.entries, indent=2, default=str),
            encoding="utf-8",
        )

    def record(self, error: str, commands: List[str], success: bool, diagnosis: str = "") -> None:
        """Record a fix attempt."""
        error_hash = hashlib.sha256(error.encode()).hexdigest()[:16]
        self.entries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_hash": error_hash,
            "error_snippet": error[:200],
            "diagnosis": diagnosis,
            "commands": commands,
            "success": success,
        })
        self._save()

    def recent_attempts(self, error: str, window_seconds: int = 3600) -> int:
        """Count how many times we've tried to fix this same error recently."""
        error_hash = hashlib.sha256(error.encode()).hexdigest()[:16]
        cutoff = time.time() - window_seconds
        count = 0
        for entry in reversed(self.entries):
            try:
                ts = datetime.fromisoformat(entry["timestamp"]).timestamp()
                if ts < cutoff:
                    break
                if entry.get("error_hash") == error_hash:
                    count += 1
            except (KeyError, ValueError):
                continue
        return count


# ─── Command Executor ────────────────────────────────────────────────────────

class CommandExecutor:
    """Safely execute validated commands."""

    def __init__(self, validator: CommandValidator):
        self.validator = validator

    def execute(self, command: str, dry_run: bool = False) -> Dict:
        """
        Execute a single command after validation.
        Returns {"command": str, "safe": bool, "reason": str,
                 "returncode": int, "stdout": str, "stderr": str}
        """
        safe, reason = self.validator.is_safe(command)
        result = {
            "command": command,
            "safe": safe,
            "reason": reason,
            "returncode": -1,
            "stdout": "",
            "stderr": "",
        }

        if not safe:
            log.warning(f"BLOCKED unsafe command: {command} — {reason}")
            return result

        if dry_run:
            log.info(f"DRY RUN — would execute: {command}")
            result["returncode"] = 0
            result["stdout"] = "[dry run]"
            return result

        log.info(f"Executing: {command}")
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
            result["returncode"] = proc.returncode
            result["stdout"] = proc.stdout.strip()
            result["stderr"] = proc.stderr.strip()

            if proc.returncode == 0:
                log.info(f"Command succeeded: {command}")
            else:
                log.warning(f"Command exited {proc.returncode}: {command}")
                if proc.stderr:
                    log.warning(f"  stderr: {proc.stderr[:200]}")

        except subprocess.TimeoutExpired:
            log.error(f"Command timed out (60s): {command}")
            result["stderr"] = "Timed out after 60 seconds"
        except Exception as e:
            log.error(f"Command execution error: {e}")
            result["stderr"] = str(e)

        return result

    def execute_batch(self, commands: List[str], dry_run: bool = False) -> List[Dict]:
        """Execute a list of commands in order. Stop on first unsafe command."""
        results = []
        for cmd in commands:
            r = self.execute(cmd, dry_run=dry_run)
            results.append(r)
            if not r["safe"]:
                log.warning("Halting batch — unsafe command encountered")
                break
        return results


# ─── Troubleshooting Loader ─────────────────────────────────────────────────

def load_troubleshooting(path: Path) -> str:
    """Load the troubleshooting.md reference document."""
    if not path.exists():
        log.warning(f"Troubleshooting file not found: {path}")
        return _generate_default_troubleshooting()
    try:
        text = path.read_text(encoding="utf-8")
        log.info(f"Loaded troubleshooting reference ({len(text)} bytes)")
        return text
    except IOError as e:
        log.error(f"Failed to read {path}: {e}")
        return _generate_default_troubleshooting()


def _generate_default_troubleshooting() -> str:
    """Provide a minimal built-in troubleshooting reference."""
    return textwrap.dedent("""\
        # Cobra Tail Troubleshooting Reference

        ## WireGuard Tunnel Down
        - Check if interface exists: `ip link show wg_quantum`
        - Restart interface: `sudo wg-quick down wg_quantum && sudo wg-quick up wg_quantum`
        - Check WireGuard status: `sudo wg show`
        - Verify config file: `cat /etc/wireguard/wg_quantum.conf`

        ## Lighthouse Unreachable
        - Ping lighthouse VPN IP: `ping -c 3 10.100.0.1`
        - Check DNS resolution: `dig lighthouse.local`
        - Restart client service: `sudo systemctl restart cobratail`
        - Check firewall: `sudo iptables -L -n | grep 8443`

        ## DNS Resolution Failure
        - Flush DNS cache: `sudo resolvectl flush-caches`
        - Check resolv.conf: `cat /etc/resolv.conf`
        - Test external DNS: `dig @8.8.8.8 google.com`

        ## Mesh Peer Connection Failed
        - Check mesh interface: `ip link show wg_mesh`
        - Verify mesh peers: `sudo wg show wg_mesh`
        - Restart mesh: `sudo wg-quick down wg_mesh && sudo wg-quick up wg_mesh`
        - Check NAT traversal: `ss -ulnp | grep 51821`

        ## High Latency / Packet Loss
        - Check endpoint: `sudo wg show wg_quantum endpoints`
        - MTU issues: `ping -c 5 -M do -s 1400 10.100.0.1`
        - Reduce MTU: edit wg_quantum.conf, set MTU = 1280

        ## PSK Rotation Failure
        - Check Vault connectivity (Lighthouse only): `sudo journalctl -u cobra-vault -n 20`
        - Check time sync: `timedatectl status`
        - Force manual rotation via Lighthouse API

        ## Service Won't Start
        - Check logs: `sudo journalctl -u cobratail -n 50 --no-pager`
        - Verify enrollment: `ls -la /opt/cobratail/config/enrollment.json`
        - Check permissions: `ls -la /etc/wireguard/`
    """)


# ─── On-Demand LLM Manager ──────────────────────────────────────────────────

class LLMManager:
    """
    Manages the lifecycle of the llama.cpp server process for on-demand mode.
    Starts the server when needed, stops it after the fix is applied.
    """

    def __init__(self, config: SentinelConfig):
        self.config = config
        self._process: Optional[subprocess.Popen] = None
        self._model_path = config.get("llm_model_path", "")
        self._server_binary = self._find_server_binary()

    def _find_server_binary(self) -> str:
        """Locate the llama.cpp server binary."""
        candidates = [
            "llama-server",
            "llama-cli",
            "server",  # older llama.cpp naming
        ]
        for name in candidates:
            path = shutil.which(name)
            if path:
                return path

        # Check common install locations
        common_paths = [
            Path("/usr/local/bin/llama-server"),
            Path.home() / "llama.cpp" / "build" / "bin" / "llama-server",
            Path.home() / "llama.cpp" / "llama-server",
            Path("/opt/llama.cpp/llama-server"),
        ]
        for p in common_paths:
            if p.exists():
                return str(p)

        return ""

    def start(self) -> bool:
        """Start the llama.cpp server if not already running."""
        if self.is_running():
            log.info("LLM server already running")
            return True

        if not self._server_binary:
            log.error("llama.cpp server binary not found")
            return False

        if not self._model_path:
            log.error("No LLM model path configured (set 'llm_model_path' in config)")
            return False

        log.info(f"Starting LLM server: {self._server_binary}")
        try:
            cmd = [
                self._server_binary,
                "-m", self._model_path,
                "--host", "127.0.0.1",
                "--port", "8080",
                "-ngl", "0",      # No GPU layers (CPU only on Pi)
                "-c", "4096",     # Context size
                "-t", str(max(1, (os.cpu_count() or 2) - 1)),  # Leave 1 core free
            ]
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Wait for server to become ready
            for _ in range(30):
                time.sleep(1)
                if self._health_check():
                    log.info("LLM server is ready")
                    return True

            log.error("LLM server failed to start within 30 seconds")
            self.stop()
            return False

        except Exception as e:
            log.error(f"Failed to start LLM server: {e}")
            return False

    def stop(self) -> None:
        """Stop the llama.cpp server process."""
        if self._process:
            log.info("Stopping LLM server")
            try:
                self._process.terminate()
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            self._process = None
            log.info("LLM server stopped")

    def is_running(self) -> bool:
        """Check if the server process is alive."""
        if self._process and self._process.poll() is None:
            return True
        return self._health_check()

    def _health_check(self) -> bool:
        """Ping the server's health endpoint."""
        if not HAS_REQUESTS:
            return False
        try:
            base = self.config.get("llm_endpoint", "").rsplit("/", 1)[0]
            r = requests.get(f"{base}/health", timeout=3)
            return r.status_code == 200
        except Exception:
            return False


# ─── The Sentinel Engine ────────────────────────────────────────────────────

class CobraSentinel:
    """
    Main sentinel engine. Ties together log watching, LLM diagnosis,
    command validation, execution, and hardware guarding.
    """

    def __init__(self, config: SentinelConfig, hw: HardwareProfile):
        self.config = config
        self.hw = hw
        self.cmd_builder = CommandBuilder(hw)
        self.validator = CommandValidator(config)
        self.executor = CommandExecutor(self.validator)
        self.fix_history = FixHistory()
        self.guard = HardwareGuard(config.get("hardware_guard", {}), hw)
        self.llm = LLMClient(config, self.cmd_builder)
        self.llm_manager = LLMManager(config)

        # Primary: event-driven listener (client/lighthouse push errors to us)
        self.listener = SentinelListener()

        # Fallback: also watch the log file for errors from other sources
        log_path = Path(config.get("log_file", str(COBRATAIL_LOG_PATH)))
        patterns = config.get("error_patterns", DEFAULT_CONFIG["error_patterns"])
        self.watcher = LogWatcher(log_path, patterns)

        self.troubleshooting_text = load_troubleshooting(
            Path(config.get("troubleshooting_file", str(TROUBLESHOOTING_PATH)))
        )

        self._running = False
        self._stop_event = threading.Event()
        self._mode = config.get("mode", "on-demand")
        self._max_retries = config.get("max_retries_per_error", 3)
        self._auto_execute = config.get("auto_execute", True)
        self._poll_interval = config.get("poll_interval_seconds", 5)

    def run(self) -> None:
        """Main loop — monitors logs and engages the AI when errors are detected."""
        self._running = True
        ai_enabled = self.config.get("ai_enabled", True)

        log.info("=" * 60)
        log.info("COBRA SENTINEL STARTING")
        log.info(f"  Mode:        {self._mode}")
        log.info(f"  AI Enabled:  {ai_enabled}")
        log.info(f"  Auto-exec:   {self._auto_execute}")
        log.info(f"  Platform:    {self.hw.system} {self.hw.arch}")
        log.info(f"  Device:      {self.hw.model}")
        log.info(f"  AI Capable:  {self.hw.ai_capable}")
        log.info(f"  Log file:    {self.config.get('log_file')}")
        log.info("=" * 60)

        if not ai_enabled or self._mode == "disabled":
            log.info("AI is disabled — running in log-only mode")
            self._run_passive()
            return

        if self._mode == "always-on":
            self._start_llm_if_needed()

        self._run_active()

    def _run_passive(self) -> None:
        """Passive mode: just log errors, no AI engagement."""
        while not self._stop_event.is_set():
            errors = self.watcher.poll()
            for err in errors:
                log.warning(f"[PASSIVE] Network error detected: {err['line'][:120]}")
            self._stop_event.wait(self._poll_interval)

    def _run_active(self) -> None:
        """Active mode: listen for pushed events + fallback log polling."""
        # Start the socket listener
        self.listener.start()
        log.info("Event listener started — waiting for error events from client/lighthouse")

        while not self._stop_event.is_set():
            # Hardware guard check
            throttled, reason = self.guard.should_throttle()
            if throttled:
                log.warning(f"Hardware guard: THROTTLED — {reason}")
                if self._mode == "on-demand":
                    self.llm_manager.stop()
                self._stop_event.wait(30)
                continue

            # Check for pushed events (primary — instant, zero-latency)
            events = self.listener.poll()

            # Also check log file (fallback — catches errors from other sources)
            log_errors = self.watcher.poll()
            events.extend(log_errors)

            if not events:
                self._stop_event.wait(self._poll_interval)
                continue

            # Deduplicate
            seen = set()
            unique = []
            for err in events:
                key = err.get("line", "")[:100]
                if key and key not in seen:
                    seen.add(key)
                    unique.append(err)

            for err in unique:
                self._handle_error(err)

    def _handle_error(self, error: Dict) -> None:
        """Process a single detected error."""
        error_line = error["line"]
        log.warning(f"Error detected: {error_line[:150]}")

        # Check retry limit
        attempts = self.fix_history.recent_attempts(error_line)
        if attempts >= self._max_retries:
            log.error(
                f"Max retries ({self._max_retries}) exceeded for this error. "
                f"Skipping AI — manual intervention required."
            )
            return

        # For on-demand mode, start the LLM now
        if self._mode == "on-demand":
            if not self._start_llm_if_needed():
                log.error("Cannot start LLM — logging error for manual review")
                self.fix_history.record(error_line, [], False, "LLM unavailable")
                return

        # Check LLM availability
        if not self.llm.is_available():
            log.error("LLM server not reachable — logging error for manual review")
            self.fix_history.record(error_line, [], False, "LLM unreachable")
            return

        # Send to LLM for diagnosis
        log.info("Consulting AI for diagnosis...")
        result = self.llm.diagnose(error_line, self.troubleshooting_text)

        if not result or not result.get("commands"):
            log.warning("LLM returned no actionable commands")
            self.fix_history.record(error_line, [], False, result.get("diagnosis", "") if result else "No response")
            return

        log.info(f"Diagnosis: {result.get('diagnosis', 'N/A')}")
        log.info(f"Suggested commands: {result['commands']}")
        if result.get("explanation"):
            log.info(f"Explanation: {result['explanation']}")

        # Validate commands
        validations = self.validator.validate_multi(result["commands"])
        safe_cmds = [cmd for cmd, safe, _ in validations if safe]
        blocked_cmds = [(cmd, reason) for cmd, safe, reason in validations if not safe]

        for cmd, reason in blocked_cmds:
            log.warning(f"BLOCKED command: {cmd} — {reason}")

        if not safe_cmds:
            log.error("All suggested commands were blocked by safety validator")
            self.fix_history.record(error_line, result["commands"], False, "All commands blocked")
            return

        # Execute
        if self._auto_execute:
            log.info(f"Executing {len(safe_cmds)} validated command(s)...")
            exec_results = self.executor.execute_batch(safe_cmds)
            success = all(r["returncode"] == 0 for r in exec_results)
            self.fix_history.record(
                error_line, safe_cmds, success,
                result.get("diagnosis", ""),
            )
            if success:
                log.info("Fix applied successfully")
            else:
                log.warning("Some commands failed — check logs")
        else:
            log.info("Auto-execute disabled. Suggested commands:")
            for cmd in safe_cmds:
                log.info(f"  → {cmd}")
            self.fix_history.record(error_line, safe_cmds, False, "Auto-execute disabled")

        # For on-demand mode, stop the LLM after fixing
        if self._mode == "on-demand":
            log.info("On-demand mode: shutting down LLM to free resources")
            time.sleep(5)  # Brief pause in case more errors follow
            if not self.watcher.poll():  # No more errors queued
                self.llm_manager.stop()

    def _start_llm_if_needed(self) -> bool:
        """Start the LLM server if not already running."""
        if self.llm.is_available():
            return True
        log.info("Starting LLM server (on-demand)...")
        return self.llm_manager.start()

    def stop(self) -> None:
        """Gracefully stop the sentinel."""
        log.info("Sentinel shutting down...")
        self._stop_event.set()
        self._running = False
        self.listener.stop()
        self.llm_manager.stop()
        log.info("Sentinel stopped")

# ─── systemd Service Installer ──────────────────────────────────────────────

SERVICE_UNIT = textwrap.dedent("""\
    [Unit]
    Description=Cobra Sentinel — AI Network Diagnostic Agent
    Documentation=https://github.com/CobraTechLLC/Cobra_Tail
    After=network-online.target cobratail.service
    Wants=network-online.target

    [Service]
    Type=simple
    ExecStart={python} {script} --config {config}
    WorkingDirectory={workdir}
    Restart=on-failure
    RestartSec=30
    StandardOutput=journal
    StandardError=journal
    SyslogIdentifier=cobra-sentinel

    # Resource limits
    MemoryMax=2G
    CPUQuota=80%

    # Security hardening
    ProtectSystem=strict
    ProtectHome=read-only
    ReadWritePaths={data_dir} {log_dir}
    NoNewPrivileges=false
    PrivateTmp=true

    [Install]
    WantedBy=multi-user.target
""")

SERVICE_PATH = Path("/etc/systemd/system/cobra-sentinel.service")


def install_service() -> None:
    """Install cobra-sentinel as a systemd service."""
    if IS_WINDOWS:
        print("systemd service installation is Linux-only.")
        print("On Windows, use Task Scheduler or NSSM to run as a service.")
        return

    if os.geteuid() != 0:
        print("ERROR: Must run as root to install systemd service.")
        print("  sudo python cobra_sentinel.py --install")
        sys.exit(1)

    python_path = sys.executable
    script_path = Path(__file__).resolve()

    unit = SERVICE_UNIT.format(
        python=python_path,
        script=script_path,
        config=SENTINEL_CONFIG_PATH,
        workdir=script_path.parent,
        data_dir=DATA_DIR,
        log_dir=LOG_DIR,
    )

    SERVICE_PATH.write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "cobra-sentinel.service"], check=True)
    print(f"Installed: {SERVICE_PATH}")
    print("Start with:  sudo systemctl start cobra-sentinel")
    print("Logs:        sudo journalctl -u cobra-sentinel -f")


def uninstall_service() -> None:
    """Remove the cobra-sentinel systemd service."""
    if os.geteuid() != 0:
        print("ERROR: Must run as root.")
        sys.exit(1)

    subprocess.run(["systemctl", "stop", "cobra-sentinel.service"], check=False)
    subprocess.run(["systemctl", "disable", "cobra-sentinel.service"], check=False)
    if SERVICE_PATH.exists():
        SERVICE_PATH.unlink()
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("Cobra Sentinel service removed.")


# ─── Interactive Hardware Detection ──────────────────────────────────────────

def detect_and_recommend() -> None:
    """Detect hardware and recommend sentinel configuration."""
    hw = HardwareProfile()
    print()
    print("═" * 50)
    print("  COBRA SENTINEL — Hardware Detection")
    print("═" * 50)
    print()
    print(hw)
    print()

    if hw.ai_capable:
        print("✅ This device CAN run the AI Sentinel.")
        if hw.ram_total_mb >= 8000:
            print("   Recommended mode: always-on")
            print("   (Plenty of RAM for persistent LLM)")
        elif hw.ram_total_mb >= 4000:
            print("   Recommended mode: on-demand")
            print("   (Start LLM only when errors occur)")
        else:
            print("   Recommended mode: on-demand")
            print("   (Limited RAM — LLM should not run continuously)")
    else:
        print("⚠️  This device should NOT run the AI Sentinel.")
        print("   Recommended mode: disabled")
        print("   (Insufficient RAM or unsupported architecture)")
        if hw.pi_model in ("pi_zero", "pi_zero_2w"):
            print(f"   Reason: {hw.pi_model} has too little RAM for LLM inference")
        elif hw.ram_total_mb < 1500:
            print(f"   Reason: Only {hw.ram_total_mb} MB RAM available")

    print()

    # Generate recommended config
    config = dict(DEFAULT_CONFIG)
    if hw.ai_capable:
        config["ai_enabled"] = True
        if hw.ram_total_mb >= 8000:
            config["mode"] = "always-on"
        else:
            config["mode"] = "on-demand"
    else:
        config["ai_enabled"] = False
        config["mode"] = "disabled"

    SENTINEL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    SENTINEL_CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(f"Config written to: {SENTINEL_CONFIG_PATH}")
    print()


# ─── Default Troubleshooting File Generator ──────────────────────────────────

def ensure_troubleshooting_file() -> None:
    """Create the troubleshooting.md file if it doesn't exist."""
    if TROUBLESHOOTING_PATH.exists():
        return
    TROUBLESHOOTING_PATH.parent.mkdir(parents=True, exist_ok=True)
    TROUBLESHOOTING_PATH.write_text(
        _generate_default_troubleshooting(),
        encoding="utf-8",
    )
    log.info(f"Generated default troubleshooting file: {TROUBLESHOOTING_PATH}")


# ─── Signal Handling ─────────────────────────────────────────────────────────

_sentinel_instance: Optional[CobraSentinel] = None

def _signal_handler(signum, frame):
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    if _sentinel_instance:
        _sentinel_instance.stop()
    sys.exit(0)


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    global _sentinel_instance

    parser = argparse.ArgumentParser(
        description="Cobra Sentinel — AI-Powered Self-Healing Network Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              cobra-sentinel                    Run with defaults
              cobra-sentinel --detect           Detect hardware capabilities
              cobra-sentinel --install          Install as systemd service
              cobra-sentinel --config /path     Use custom config file
              cobra-sentinel --dry-run          Test without executing fixes
        """),
    )
    parser.add_argument("--config", type=Path, default=SENTINEL_CONFIG_PATH,
                        help="Path to sentinel_config.json")
    parser.add_argument("--detect", action="store_true",
                        help="Detect hardware and generate recommended config")
    parser.add_argument("--install", action="store_true",
                        help="Install as a systemd service")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove the systemd service")
    parser.add_argument("--dry-run", action="store_true",
                        help="Diagnose but don't execute commands")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        global log
        log = setup_logging(SENTINEL_LOG_PATH, verbose=True)

    if args.detect:
        detect_and_recommend()
        return

    if args.install:
        install_service()
        return

    if args.uninstall:
        uninstall_service()
        return

    # Load config
    config = SentinelConfig(args.config)

    if args.dry_run:
        config.data["auto_execute"] = False
        log.info("DRY RUN mode — commands will be suggested but not executed")

    # Detect hardware
    hw = HardwareProfile()

    # Ensure troubleshooting file exists
    ensure_troubleshooting_file()

    # Ensure required directories exist
    for d in (CONFIG_DIR, DATA_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # Register signal handlers
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Create and run sentinel
    _sentinel_instance = CobraSentinel(config, hw)

    try:
        _sentinel_instance.run()
    except KeyboardInterrupt:
        _sentinel_instance.stop()
    except Exception as e:
        log.critical(f"Sentinel crashed: {e}", exc_info=True)
        _sentinel_instance.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()