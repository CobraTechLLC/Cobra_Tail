#!/usr/bin/env python3
"""
COBRA IDENTITY MANAGER — Full-Stack Network Spoofing

Applies a deterministic network identity from a single config file so that:
  - The device has a predictable IPv6 address (SLAAC token)
  - The device appears as an Apple/macOS machine to all network observers
  - The Cobra client can read the identity for registration with the Lighthouse

Spoofing layers:
  Layer 1 (Physical):     MAC address → Apple OUI
  Layer 2 (Network):      Hostname, MTU, IPv6 SLAAC token
  Layer 3 (Application):  /etc/machine-id, DHCP Client ID, Vendor Class, Parameter Request List
  Layer 4 (Kernel):       IP TTL / IPv6 Hop Limit

Config file:  <CobraTail install>/data/node_identity.json
Backup file:  <CobraTail install>/data/identity_backup.json

Platform:     Linux (ARM/x86) and Windows 10/11
Dependencies:
  Linux:   iproute2, systemd (hostnamectl), dhclient or dhcpcd or NetworkManager
  Windows: PowerShell 5+, Administrator privileges

Usage:
  Linux:
    sudo python3 identity_manager.py --apply
    sudo python3 identity_manager.py --restore
    sudo python3 identity_manager.py --status
    sudo python3 identity_manager.py --generate
    sudo python3 identity_manager.py --generate --device-id cobra3
    sudo python3 identity_manager.py --wait-v6
    sudo python3 identity_manager.py --monitor

  Windows (Administrator PowerShell):
    python identity_manager.py --apply
    python identity_manager.py --restore
    python identity_manager.py --status
    python identity_manager.py --generate
    python identity_manager.py --generate --device-id cobra3
    python identity_manager.py --wait-v6

Run BEFORE the Cobra client:
    [Unit]
    Before=cobra-client.service
    Before=lighthouse.service
"""

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import threading
import argparse
from pathlib import Path
from datetime import datetime, timezone

# ─── Platform Detection ──────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# ─── Windows Subprocess Window Suppression ───────────────────────────────────
if IS_WINDOWS:
    _CREATE_NO_WINDOW = 0x08000000
    _STARTUPINFO = subprocess.STARTUPINFO()
    _STARTUPINFO.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    _STARTUPINFO.wShowWindow = 0  # SW_HIDE
    _ORIG_RUN = subprocess.run

    def _quiet_run(*args, **kwargs):
        if "creationflags" not in kwargs:
            kwargs["creationflags"] = _CREATE_NO_WINDOW
        if "startupinfo" not in kwargs:
            kwargs["startupinfo"] = _STARTUPINFO
        return _ORIG_RUN(*args, **kwargs)

    subprocess.run = _quiet_run

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

# Subdirectory layout vs flat layout
if (COBRATAIL_DIR / "config").is_dir() or (COBRATAIL_DIR / ".cobratail").exists():
    CONFIG_DIR = COBRATAIL_DIR / "config"
    DATA_DIR = COBRATAIL_DIR / "data"
else:
    CONFIG_DIR = COBRATAIL_DIR
    DATA_DIR = COBRATAIL_DIR

IDENTITY_PATH = DATA_DIR / "node_identity.json"
BACKUP_PATH = DATA_DIR / "identity_backup.json"
ENROLLMENT_PATH = CONFIG_DIR / "enrollment.json"

# ─── Apple OUI Prefixes ─────────────────────────────────────────────────────
APPLE_OUIS = [
    "A4:83:E7", "3C:22:FB", "14:98:77", "F0:18:98",
    "8C:85:90", "6C:96:CF", "A8:88:08", "DC:A4:CA",
    "F4:5C:89", "78:7B:8A",
]

# ─── macOS DHCP Fingerprint (Option 55 parameter request list) ───────────────
# This is the exact order macOS sends DHCP parameter requests.
# Fingerprinting databases like fingerbank.org match on this ordering.
MACOS_DHCP_PARAM_LIST = [1, 121, 3, 6, 15, 119, 252, 95, 44, 46]
# Translations: subnet-mask, classless-static-routes, routers, dns,
#               domain-name, domain-search, wpad, ldap, netbios-ns, netbios-node-type

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [IDENTITY] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("identity_manager")


# =============================================================================
# CONFIG GENERATION
# =============================================================================

def generate_mac_from_device_id(device_id: str) -> str:
    """
    Generate a deterministic Apple-looking MAC address from a device_id.
    Uses an Apple OUI prefix + 3 bytes derived from hash(device_id).
    Same device_id always produces the same MAC.
    """
    h = hashlib.sha256(f"cobra-mac-{device_id}".encode()).hexdigest()
    oui_index = int(h[:2], 16) % len(APPLE_OUIS)
    oui = APPLE_OUIS[oui_index]
    suffix = f"{h[2:4]}:{h[4:6]}:{h[6:8]}".upper()
    return f"{oui}:{suffix}"


def generate_token_from_device_id(device_id: str) -> str:
    """
    Generate a deterministic IPv6 SLAAC token from a device_id.
    Produces a short, memorable token like ::c0de:1, ::cafe:2, etc.
    """
    h = hashlib.sha256(f"cobra-token-{device_id}".encode()).hexdigest()
    word1 = h[:4]
    word2 = h[4:8]
    return f"::{word1}:{word2}"


def generate_hostname_from_device_id(device_id: str) -> str:
    """Generate a macOS-style hostname from a device_id.
    Windows NetBIOS limit is 15 characters, so keep it short."""
    h = hashlib.sha256(f"cobra-host-{device_id}".encode()).hexdigest()[:4]
    return f"Users-MBP-{h.upper()}"


def generate_default_config(device_id: str = None, interface: str = None) -> dict:
    """
    Generate a default node_identity.json config.
    If device_id is provided, derives MAC/token/hostname deterministically.
    If not, reads from enrollment.json.
    """
    if not device_id and ENROLLMENT_PATH.exists():
        try:
            enrollment = json.loads(ENROLLMENT_PATH.read_text())
            device_id = enrollment.get("device_id", "")
        except (json.JSONDecodeError, IOError):
            pass

    if not device_id:
        device_id = f"cobra-{socket.gethostname()}"

    if not interface:
        interface = _detect_primary_interface()

    mac = generate_mac_from_device_id(device_id)
    token = generate_token_from_device_id(device_id)
    hostname = generate_hostname_from_device_id(device_id)

    return {
        "device_id": device_id,
        "mac_address": mac,
        "hostname": hostname,
        "ipv6_token": token,
        "interface": interface,
        "mtu": 1280,
        "dhcp_client_id": f"01:{mac}",
        "dhcp_vendor_class": "",
        "dhcp_param_request_list": "apple",
        "os_ttl": 64,
    }


def _detect_primary_interface() -> str:
    """Auto-detect the primary network interface (the one with a default route)."""
    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Where-Object {$PSItem.Status -eq 'Up'} | "
                 "Select-Object -First 1 -ExpandProperty Name"],
                capture_output=True, text=True, timeout=10,
            )
            name = result.stdout.strip()
            if name:
                return name
        except Exception:
            pass
        return "Wi-Fi"

    # Linux
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    for iface in ["wlan0", "eth0", "enp0s3", "wlp2s0"]:
        if Path(f"/sys/class/net/{iface}").exists():
            return iface

    return "wlan0"

# =============================================================================
# WINDOWS HELPERS
# =============================================================================

def _win_get_adapter_name(interface: str) -> str:
    """Get the Windows network adapter display name from interface hint.
    On Windows, 'interface' in the config can be 'Wi-Fi', 'Ethernet', etc.
    If it looks like a Linux name (wlan0, eth0), try to find the Windows equivalent."""
    if not IS_WINDOWS:
        return interface

    if interface in ("Wi-Fi", "Ethernet", "Local Area Connection"):
        return interface

    linux_to_win = {
        "wlan0": "Wi-Fi", "wlan1": "Wi-Fi 2",
        "eth0": "Ethernet", "eth1": "Ethernet 2",
    }
    if interface in linux_to_win:
        return linux_to_win[interface]

    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetAdapter | Where-Object {$PSItem.Status -eq 'Up'} | "
             "Select-Object -First 1 -ExpandProperty Name"],
            capture_output=True, text=True, timeout=10,
        )
        name = result.stdout.strip()
        if name:
            return name
    except Exception:
        pass

    return "Wi-Fi"

def _win_get_current_mac(adapter_name: str) -> str:
    """Get the current MAC address of a Windows adapter."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"(Get-NetAdapter -Name '{adapter_name}').MacAddress"],
            capture_output=True, text=True, timeout=10,
        )
        mac = result.stdout.strip().replace("-", ":")
        return mac
    except Exception:
        return ""


def _win_get_adapter_guid(adapter_name: str) -> str:
    """Get the registry GUID for a Windows network adapter."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"(Get-NetAdapter -Name '{adapter_name}').InterfaceGuid"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _win_get_current_mtu(adapter_name: str) -> str:
    """Get the current MTU of a Windows adapter."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"(Get-NetIPInterface -InterfaceAlias '{adapter_name}' "
             f"-AddressFamily IPv6).NlMtu"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return "1500"


def _win_get_current_ttl() -> str:
    """Get the current default TTL on Windows."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-NetIPv4Protocol).DefaultHopLimit"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return "128"


# =============================================================================
# BACKUP & RESTORE
# =============================================================================

def _save_backup(interface: str) -> None:
    """Save the original identity on first run so we can restore later."""
    if BACKUP_PATH.exists():
        log.debug("Backup already exists, skipping")
        return

    backup = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "interface": interface,
        "platform": platform.system(),
    }

    if IS_WINDOWS:
        adapter = _win_get_adapter_name(interface)
        backup["original_mac"] = _win_get_current_mac(adapter)
        backup["original_hostname"] = socket.gethostname()
        backup["original_mtu"] = _win_get_current_mtu(adapter)
        backup["original_ttl"] = _win_get_current_ttl()
        backup["original_machine_id"] = ""
    else:
        try:
            result = subprocess.run(
                ["cat", f"/sys/class/net/{interface}/address"],
                capture_output=True, text=True, timeout=5,
            )
            backup["original_mac"] = result.stdout.strip().upper()
        except Exception:
            backup["original_mac"] = ""

        backup["original_hostname"] = socket.gethostname()

        try:
            backup["original_machine_id"] = Path("/etc/machine-id").read_text().strip()
        except Exception:
            backup["original_machine_id"] = ""

        try:
            result = subprocess.run(
                ["cat", f"/sys/class/net/{interface}/mtu"],
                capture_output=True, text=True, timeout=5,
            )
            backup["original_mtu"] = result.stdout.strip()
        except Exception:
            backup["original_mtu"] = "1500"

        try:
            result = subprocess.run(
                ["sysctl", "-n", "net.ipv4.ip_default_ttl"],
                capture_output=True, text=True, timeout=5,
            )
            backup["original_ttl"] = result.stdout.strip()
        except Exception:
            backup["original_ttl"] = "64"

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_PATH.write_text(json.dumps(backup, indent=2))
    log.info(f"Original identity backed up to {BACKUP_PATH}")


# =============================================================================
# IDENTITY APPLICATION FUNCTIONS
# =============================================================================

def _run(cmd: list[str], desc: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command with logging."""
    log.debug(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if check and result.returncode != 0:
            log.warning(f"{desc} failed (rc={result.returncode}): {result.stderr.strip()}")
        return result
    except subprocess.TimeoutExpired:
        log.warning(f"{desc} timed out")
        return subprocess.CompletedProcess(cmd, 1, "", "timeout")
    except FileNotFoundError:
        log.warning(f"{desc}: command not found ({cmd[0]})")
        return subprocess.CompletedProcess(cmd, 1, "", "not found")


def _detect_dhcp_client() -> str:
    """Detect which DHCP client is active on this system."""
    if IS_WINDOWS:
        return "windows"

    if shutil.which("nmcli"):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "NetworkManager"],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout.strip() == "active":
                return "networkmanager"
        except Exception:
            pass

    if shutil.which("dhcpcd"):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "dhcpcd"],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout.strip() == "active":
                return "dhcpcd"
        except Exception:
            pass

    if shutil.which("dhclient"):
        return "dhclient"

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "systemd-networkd"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip() == "active":
            return "networkd"
    except Exception:
        pass

    return "unknown"

def _win_check_mac_support(adapter_name: str) -> bool:
    """Check if the Windows adapter driver supports MAC address spoofing.
    Intel Wi-Fi 6/6E/7 drivers (22.x+) block MAC changes in firmware.
    Returns False if the adapter is known to reject MAC spoofing."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"(Get-NetAdapter -Name '{adapter_name}').InterfaceDescription"],
            capture_output=True, text=True, timeout=10,
        )
        desc = result.stdout.strip().lower()

        # Intel Wi-Fi 6E/7 chipsets with driver 22.x+ block MAC spoofing
        # Known unsupported: AX200, AX201, AX210, AX211, AX411, BE200, BE202
        intel_blocked = ["ax200", "ax201", "ax210", "ax211", "ax411",
                         "be200", "be202", "wi-fi 6e", "wi-fi 7"]
        if "intel" in desc:
            for chip in intel_blocked:
                if chip in desc:
                    return False
    except Exception:
        pass
    return True

def apply_mac(interface: str, mac_address: str) -> bool:
    """IM1: Spoof the MAC address on the given interface."""
    log.info(f"Applying MAC: {mac_address} on {interface}")

    if IS_WINDOWS:
        adapter = _win_get_adapter_name(interface)

        # Check if this adapter is known to block MAC spoofing
        if not _win_check_mac_support(adapter):
            try:
                result = subprocess.run(
                    ["powershell", "-Command",
                     f"(Get-NetAdapter -Name '{adapter}').InterfaceDescription"],
                    capture_output=True, text=True, timeout=10,
                )
                desc = result.stdout.strip()
            except Exception:
                desc = "unknown adapter"
            log.warning(f"MAC spoofing skipped — {desc} does not support MAC "
                        f"changes (Intel Wi-Fi 6E/7 firmware restriction)")
            log.info("Other identity layers (hostname, IPv6 token, MTU, TTL, "
                     "DHCP) are still applied. MAC spoofing works on Linux "
                     "and on Windows with Ethernet or older Wi-Fi adapters.")
            return False

        # Format MAC as XX-XX-XX-XX-XX-XX for Set-NetAdapter
        mac_dashed = mac_address.replace(":", "-")
        mac_nocolon = mac_address.replace(":", "").replace("-", "")

        # Method 1: Set-NetAdapter -MacAddress (NDIS path)
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"Set-NetAdapter -Name '{adapter}' "
                 f"-MacAddress '{mac_dashed}' -Confirm:$false"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                time.sleep(3)
                current = _win_get_current_mac(adapter)
                if current.upper().replace("-", ":") == mac_address.upper():
                    log.info(f"MAC set to {mac_address} via Set-NetAdapter")
                    return True
                else:
                    log.debug(f"Set-NetAdapter returned OK but MAC is {current}, "
                              f"trying registry method")
        except Exception as e:
            log.debug(f"Set-NetAdapter not available or failed: {e}")

        # Method 2: Registry NetworkAddress + adapter restart (fallback)
        guid = _win_get_adapter_guid(adapter)
        if not guid:
            log.warning(f"Could not find adapter GUID for '{adapter}'")
            return False

        reg_path = (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Class"
            r"\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        )

        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-ChildItem 'Registry::{reg_path}' | "
                 f"Where-Object {{ (Get-ItemProperty $PSItem.PSPath -Name NetCfgInstanceId "
                 f"-ErrorAction SilentlyContinue).NetCfgInstanceId -eq '{guid}' }} | "
                 f"Select-Object -ExpandProperty PSPath"],
                capture_output=True, text=True, timeout=10,
            )
            reg_key = result.stdout.strip()
            if not reg_key:
                log.warning("Could not find adapter registry key")
                return False

            subprocess.run(
                ["powershell", "-Command",
                 f"Set-ItemProperty -Path '{reg_key}' "
                 f"-Name 'NetworkAddress' -Value '{mac_nocolon}'"],
                capture_output=True, text=True, timeout=10,
            )

            subprocess.run(
                ["powershell", "-Command",
                 f"Disable-NetAdapter -Name '{adapter}' -Confirm:$false; "
                 f"Start-Sleep -Seconds 2; "
                 f"Enable-NetAdapter -Name '{adapter}' -Confirm:$false"],
                capture_output=True, text=True, timeout=30,
            )

            time.sleep(3)
            current = _win_get_current_mac(adapter)
            if current.upper().replace("-", ":") == mac_address.upper():
                log.info(f"MAC set to {mac_address} via registry (adapter restarted)")
                return True
            else:
                log.warning(f"MAC spoofing failed — driver does not honor "
                            f"NetworkAddress registry key (got {current}). "
                            f"This Wi-Fi adapter may not support MAC spoofing.")
                return False

        except Exception as e:
            log.warning(f"Windows MAC spoofing failed: {e}")
            return False

    # Linux
    dhcp_client = _detect_dhcp_client()

    if dhcp_client == "networkmanager":
        _run(["nmcli", "device", "disconnect", interface],
             "NM disconnect", check=False)
        time.sleep(1)

    _run(["ip", "link", "set", "dev", interface, "down"], "Interface down")
    result = _run(["ip", "link", "set", "dev", interface, "address", mac_address],
                  "Set MAC address")
    _run(["ip", "link", "set", "dev", interface, "up"], "Interface up")

    if dhcp_client == "networkmanager":
        time.sleep(1)
        _run(["nmcli", "device", "connect", interface],
             "NM reconnect", check=False)

    if result.returncode == 0:
        log.info(f"MAC set to {mac_address}")
        return True
    return False

def apply_hostname(hostname: str) -> bool:
    """IM2: Spoof the system hostname."""
    log.info(f"Applying hostname: {hostname}")

    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"$comp = Get-WmiObject Win32_ComputerSystem; "
                 f"$comp.Rename('{hostname}')"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                subprocess.run(
                    ["powershell", "-Command",
                     f"Rename-Computer -NewName '{hostname}' -Force"],
                    capture_output=True, text=True, timeout=15,
                )
            log.info(f"Hostname set to {hostname} (full effect after restart)")
            return True
        except Exception as e:
            log.warning(f"Windows hostname change failed: {e}")
            return False

    # Linux
    _run(["hostnamectl", "set-hostname", hostname], "Set hostname")

    try:
        Path("/etc/hostname").write_text(hostname + "\n")
    except PermissionError:
        _run(["bash", "-c", f'echo "{hostname}" > /etc/hostname'],
             "Write /etc/hostname")

    try:
        hosts = Path("/etc/hosts").read_text()
        hosts = re.sub(r"127\.0\.1\.1\s+.*", f"127.0.1.1\t{hostname}", hosts)
        if "127.0.1.1" not in hosts:
            hosts += f"\n127.0.1.1\t{hostname}\n"
        Path("/etc/hosts").write_text(hosts)
    except Exception as e:
        log.warning(f"Could not update /etc/hosts: {e}")

    log.info(f"Hostname set to {hostname}")
    return True


def apply_ipv6_token(interface: str, token: str) -> bool:
    """IM3: Set the IPv6 SLAAC token for deterministic addressing."""
    log.info(f"Applying IPv6 token: {token} on {interface}")

    if IS_WINDOWS:
        adapter = _win_get_adapter_name(interface)
        try:
            subprocess.run(
                ["netsh", "interface", "ipv6", "set", "privacy",
                 "state=disabled"],
                capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["netsh", "interface", "ipv6", "set", "global",
                 "randomizeidentifiers=disabled"],
                capture_output=True, text=True, timeout=10,
            )

            log.info("Waiting for SLAAC prefix assignment...")
            time.sleep(5)

            result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-NetIPAddress -InterfaceAlias '{adapter}' "
                 f"-AddressFamily IPv6 -PrefixOrigin RouterAdvertisement "
                 f"-ErrorAction SilentlyContinue | "
                 f"Select-Object -First 1 -ExpandProperty IPAddress"],
                capture_output=True, text=True, timeout=10,
            )
            existing_addr = result.stdout.strip()

            if existing_addr:
                import ipaddress
                addr = ipaddress.IPv6Address(existing_addr)
                # Extract the /64 prefix by zeroing out the last 64 bits
                prefix_int = int(addr) & (0xFFFFFFFFFFFFFFFF << 64)

                # Parse the token into a 64-bit integer
                # Token is like "::f23d:4095" — parse as a full IPv6 to get the lower 64 bits
                token_addr_obj = ipaddress.IPv6Address(token)
                token_int = int(token_addr_obj)

                # Combine prefix (upper 64) + token (lower 64)
                full_int = prefix_int | token_int
                token_addr = str(ipaddress.IPv6Address(full_int))

                subprocess.run(
                    ["netsh", "interface", "ipv6", "add", "address",
                     adapter, f"{token_addr}/64"],
                    capture_output=True, text=True, timeout=10,
                )
                log.info(f"IPv6 token address added: {token_addr}")
                return True
            else:
                log.warning("No SLAAC address found to extract prefix from")
                return False

        except Exception as e:
            log.warning(f"Windows IPv6 token failed: {e}")
            return False

    # Linux
    result = _run(["ip", "token", "set", token, "dev", interface], "Set IPv6 token")

    _run(["sysctl", "-w", f"net.ipv6.conf.{interface}.use_tempaddr=0"],
         "Disable privacy extensions")
    _run(["sysctl", "-w", f"net.ipv6.conf.{interface}.addr_gen_mode=0"],
         "Set addr_gen_mode")

    _run(["sysctl", "-w", f"net.ipv6.conf.{interface}.disable_ipv6=1"],
         "Disable IPv6 temporarily")
    time.sleep(1)
    _run(["sysctl", "-w", f"net.ipv6.conf.{interface}.disable_ipv6=0"],
         "Re-enable IPv6")

    if result.returncode == 0:
        log.info(f"IPv6 token set to {token}")
        return True
    return False

def set_mtu(interface: str, mtu: int) -> bool:
    """IM4: Set the interface MTU."""
    log.info(f"Setting MTU: {mtu} on {interface}")

    if IS_WINDOWS:
        adapter = _win_get_adapter_name(interface)
        try:
            subprocess.run(
                ["netsh", "interface", "ipv6", "set", "subinterface",
                 adapter, f"mtu={mtu}"],
                capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "subinterface",
                 adapter, f"mtu={mtu}"],
                capture_output=True, text=True, timeout=10,
            )
            log.info(f"MTU set to {mtu}")
            return True
        except Exception as e:
            log.warning(f"Windows MTU change failed: {e}")
            return False

    # Linux
    result = _run(["ip", "link", "set", "dev", interface, "mtu", str(mtu)],
                  "Set MTU")
    if result.returncode == 0:
        log.info(f"MTU set to {mtu}")
        return True
    return False


def spoof_machine_id(device_id: str) -> bool:
    """IM5: Overwrite /etc/machine-id with a deterministic value.
    On Windows: not needed — DHCP client ID is already MAC-based."""
    if IS_WINDOWS:
        log.info("machine-id spoofing: skipped on Windows (DHCP uses MAC-based ID)")
        return True

    log.info("Spoofing /etc/machine-id")
    new_id = hashlib.sha256(f"cobra-{device_id}".encode()).hexdigest()[:32]

    try:
        Path("/etc/machine-id").write_text(new_id + "\n")
        log.info(f"machine-id set to {new_id[:16]}...")
    except PermissionError:
        _run(["bash", "-c", f'echo "{new_id}" > /etc/machine-id'],
             "Write machine-id")

    for lease_path in [
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhclient/dhclient.leases",
    ]:
        if Path(lease_path).exists():
            try:
                Path(lease_path).unlink()
                log.debug(f"Cleared old lease: {lease_path}")
            except Exception:
                pass

    return True


def apply_dhcp_fingerprint(interface: str, config: dict) -> bool:
    """IM6: Configure DHCP client to impersonate macOS."""
    log.info("Applying DHCP fingerprint (macOS impersonation)")

    if IS_WINDOWS:
        adapter = _win_get_adapter_name(interface)
        guid = _win_get_adapter_guid(adapter)
        if guid:
            try:
                reg_path = (
                    f"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\"
                    f"Parameters\\Interfaces\\{guid}"
                )
                subprocess.run(
                    ["powershell", "-Command",
                     f"Remove-ItemProperty -Path '{reg_path}' "
                     f"-Name 'DhcpVendorClassId' -ErrorAction SilentlyContinue"],
                    capture_output=True, text=True, timeout=10,
                )
                log.info("Windows DHCP: vendor class suppressed (registry)")
                log.info("Windows DHCP: parameter request list cannot be changed "
                         "(OS limitation, MAC+hostname+TTL still provide spoofing)")
                return True
            except Exception as e:
                log.warning(f"Windows DHCP fingerprint partially applied: {e}")
                return False
        return False

    # Linux — full DHCP fingerprint spoofing
    dhcp_client = _detect_dhcp_client()
    mac = config.get("mac_address", "")
    client_id = config.get("dhcp_client_id", f"01:{mac}")
    vendor_class = config.get("dhcp_vendor_class", "")
    param_list = config.get("dhcp_param_request_list", "apple")

    log.info(f"Detected DHCP client: {dhcp_client}")

    if dhcp_client == "dhcpcd":
        return _apply_dhcp_dhcpcd(interface, client_id, vendor_class, param_list)
    elif dhcp_client == "dhclient":
        return _apply_dhcp_dhclient(interface, client_id, vendor_class, param_list)
    elif dhcp_client == "networkmanager":
        return _apply_dhcp_networkmanager(interface, client_id, vendor_class, param_list)
    elif dhcp_client == "networkd":
        return _apply_dhcp_networkd(interface, client_id)
    else:
        log.warning(f"Unknown DHCP client: {dhcp_client} — skipping fingerprint spoofing")
        return False


def _apply_dhcp_dhcpcd(interface: str, client_id: str, vendor_class: str,
                       param_list: str) -> bool:
    """Configure dhcpcd (Raspberry Pi OS default)."""
    conf_path = Path("/etc/dhcpcd.conf")

    try:
        existing = conf_path.read_text() if conf_path.exists() else ""
    except Exception:
        existing = ""

    existing = re.sub(
        r"# --- Cobra Identity Start ---.*?# --- Cobra Identity End ---\n?",
        "", existing, flags=re.DOTALL,
    )

    if param_list == "apple":
        param_str = "classless_static_routes, domain_name_servers, domain_name, domain_search"
    else:
        param_str = param_list

    cobra_block = f"""
# --- Cobra Identity Start ---
# Auto-generated by identity_manager.py — do not edit manually
interface {interface}
  clientid {client_id}
  vendorclassid
  option {param_str}
# --- Cobra Identity End ---
"""

    try:
        conf_path.write_text(existing.rstrip() + "\n" + cobra_block)
        log.info("dhcpcd.conf updated with macOS fingerprint")
        return True
    except Exception as e:
        log.warning(f"Could not write dhcpcd.conf: {e}")
        return False


def _apply_dhcp_dhclient(interface: str, client_id: str, vendor_class: str,
                         param_list: str) -> bool:
    """Configure dhclient."""
    conf_path = Path("/etc/dhcp/dhclient.conf")
    conf_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        existing = conf_path.read_text() if conf_path.exists() else ""
    except Exception:
        existing = ""

    existing = re.sub(
        r"# --- Cobra Identity Start ---.*?# --- Cobra Identity End ---\n?",
        "", existing, flags=re.DOTALL,
    )

    if param_list == "apple":
        request_block = (
            "request subnet-mask,\n"
            "        classless-static-routes,\n"
            "        routers,\n"
            "        domain-name-servers,\n"
            "        domain-name,\n"
            "        domain-search;"
        )
    else:
        request_block = f"request {param_list};"

    cobra_block = f"""
# --- Cobra Identity Start ---
send dhcp-client-identifier {client_id};
{request_block}
# --- Cobra Identity End ---
"""

    try:
        conf_path.write_text(existing.rstrip() + "\n" + cobra_block)
        log.info("dhclient.conf updated with macOS fingerprint")
        return True
    except Exception as e:
        log.warning(f"Could not write dhclient.conf: {e}")
        return False


def _apply_dhcp_networkmanager(interface: str, client_id: str, vendor_class: str,
                               param_list: str) -> bool:
    """Configure NetworkManager connection."""
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"],
            capture_output=True, text=True, timeout=5,
        )
        conn_name = None
        for line in result.stdout.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == interface:
                conn_name = parts[0]
                break
    except Exception:
        conn_name = None

    if not conn_name:
        log.warning(f"No active NM connection found for {interface}")
        return False

    _run(["nmcli", "con", "modify", conn_name,
          "ipv4.dhcp-client-id", client_id],
         "NM set client-id")

    log.info(f"NetworkManager connection '{conn_name}' updated")
    return True


def _apply_dhcp_networkd(interface: str, client_id: str) -> bool:
    """Configure systemd-networkd."""
    conf_dir = Path("/etc/systemd/network")
    conf_dir.mkdir(parents=True, exist_ok=True)

    conf_path = conf_dir / f"10-cobra-{interface}.network"
    content = f"""# Cobra Identity Manager — auto-generated
[Match]
Name={interface}

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
ClientIdentifier=mac
"""

    try:
        conf_path.write_text(content)
        log.info(f"systemd-networkd config written to {conf_path}")
        return True
    except Exception as e:
        log.warning(f"Could not write networkd config: {e}")
        return False


def apply_ttl(os_ttl: int) -> bool:
    """IM7: Set the default IP TTL / IPv6 hop limit."""
    log.info(f"Setting TTL/Hop Limit: {os_ttl}")

    if IS_WINDOWS:
        try:
            subprocess.run(
                ["powershell", "-Command",
                 f"Set-NetIPv4Protocol -DefaultHopLimit {os_ttl}"],
                capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["powershell", "-Command",
                 f"Set-NetIPv6Protocol -DefaultHopLimit {os_ttl}"],
                capture_output=True, text=True, timeout=10,
            )
            subprocess.run(
                ["reg", "add",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "DefaultTTL", "/t", "REG_DWORD",
                 "/d", str(os_ttl), "/f"],
                capture_output=True, text=True, timeout=10,
            )
            log.info(f"TTL set to {os_ttl}")
            return True
        except Exception as e:
            log.warning(f"Windows TTL change failed: {e}")
            return False

    # Linux
    _run(["sysctl", "-w", f"net.ipv4.ip_default_ttl={os_ttl}"], "Set IPv4 TTL")
    _run(["sysctl", "-w", f"net.ipv6.conf.all.hop_limit={os_ttl}"], "Set IPv6 hop limit (all)")
    _run(["sysctl", "-w", f"net.ipv6.conf.default.hop_limit={os_ttl}"], "Set IPv6 hop limit (default)")

    sysctl_conf = Path("/etc/sysctl.d/99-cobra-ttl.conf")
    try:
        sysctl_conf.write_text(
            f"# Cobra Identity Manager — TTL spoofing\n"
            f"net.ipv4.ip_default_ttl = {os_ttl}\n"
            f"net.ipv6.conf.all.hop_limit = {os_ttl}\n"
            f"net.ipv6.conf.default.hop_limit = {os_ttl}\n"
        )
    except Exception:
        pass

    log.info(f"TTL set to {os_ttl}")
    return True


# =============================================================================
# IPV6 ADDRESS MANAGEMENT
# =============================================================================

def wait_for_global_v6(interface: str, token: str, timeout: int = 60) -> str:
    """
    IM8: Wait for a Global Unicast IPv6 address matching our token to appear.
    Returns the full address (e.g., "2603:6000:9a01:bfe::c0de:1").
    """
    log.info(f"Waiting for global IPv6 with token {token} on {interface}...")

    token_suffix = token.lstrip(":")

    start = time.time()
    while time.time() - start < timeout:
        try:
            if IS_WINDOWS:
                adapter = _win_get_adapter_name(interface)
                result = subprocess.run(
                    ["powershell", "-Command",
                     f"Get-NetIPAddress -InterfaceAlias '{adapter}' "
                     f"-AddressFamily IPv6 -ErrorAction SilentlyContinue | "
                     f"Where-Object {{ $PSItem.PrefixOrigin -ne 'WellKnown' -and "
                     f"$PSItem.SuffixOrigin -ne 'WellKnown' -and "
                     f"$PSItem.IPAddress -notlike 'fe80*' }} | "
                     f"Select-Object -ExpandProperty IPAddress"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.strip().split("\n"):
                    addr = line.strip()
                    if addr and addr.endswith(token_suffix):
                        log.info(f"Global IPv6 address found: {addr}")
                        return addr
            else:
                result = subprocess.run(
                    ["ip", "-6", "addr", "show", "dev", interface, "scope", "global"],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line.startswith("inet6 "):
                        addr = line.split()[1].split("/")[0]
                        if addr.endswith(token_suffix):
                            log.info(f"Global IPv6 address found: {addr}")
                            return addr
        except Exception:
            pass

        time.sleep(2)

    log.warning(f"No global IPv6 with token {token} found within {timeout}s")
    return ""


def get_current_prefix(interface: str, token: str) -> str:
    """Extract the current /64 prefix from the token-based address."""
    addr = wait_for_global_v6(interface, token, timeout=5)
    if not addr:
        return ""

    token_suffix = token.lstrip(":")
    idx = addr.find(token_suffix)
    if idx > 0:
        return addr[:idx]
    return ""


def monitor_prefix_changes(interface: str, token: str, callback=None,
                           interval: int = 30) -> None:
    """
    IM9: Background thread that watches for IPv6 prefix changes.
    Calls callback(new_full_address, new_prefix) when a change is detected.
    """
    log.info("Starting IPv6 prefix monitor")

    last_prefix = get_current_prefix(interface, token)
    if last_prefix:
        log.info(f"Initial prefix: {last_prefix}")

    while True:
        time.sleep(interval)
        current_prefix = get_current_prefix(interface, token)

        if current_prefix and current_prefix != last_prefix:
            token_suffix = token.lstrip(":")
            new_addr = current_prefix + token_suffix
            log.info(f"Prefix changed: {last_prefix} → {current_prefix}")
            log.info(f"New address: {new_addr}")
            last_prefix = current_prefix

            if callback:
                try:
                    callback(new_addr, current_prefix)
                except Exception as e:
                    log.warning(f"Prefix change callback failed: {e}")


# =============================================================================
# MASTER APPLY / RESTORE
# =============================================================================

def apply_all(config_path: str = None) -> str:
    """
    IM10: Apply the complete spoofed identity in the correct order.
    Returns the final global IPv6 address (or "" if no IPv6 available).
    """
    path = Path(config_path) if config_path else IDENTITY_PATH
    if not path.exists():
        log.error(f"Identity config not found: {path}")
        log.info("Generate one with: python3 identity_manager.py --generate")
        return ""

    config = json.loads(path.read_text())
    log.info(f"Loaded identity config from {path}")

    interface = config.get("interface", "wlan0" if IS_LINUX else "Wi-Fi")
    device_id = config.get("device_id", "unknown")

    # Save originals on first run
    _save_backup(interface)

    log.info("=" * 60)
    log.info("APPLYING COBRA IDENTITY")
    log.info("=" * 60)
    log.info(f"Platform:   {platform.system()}")
    log.info(f"Device ID:  {device_id}")
    log.info(f"Interface:  {interface}")
    log.info(f"MAC:        {config.get('mac_address', '?')}")
    log.info(f"Hostname:   {config.get('hostname', '?')}")
    log.info(f"IPv6 Token: {config.get('ipv6_token', '?')}")
    log.info(f"MTU:        {config.get('mtu', '?')}")
    log.info(f"TTL:        {config.get('os_ttl', '?')}")
    log.info("=" * 60)

    results = {}
    mtu_val = config.get("mtu", 1280)
    mac_applied = False

    # ── Order matters ────────────────────────────────────────────
    # 1. MAC first (may cycle the adapter on Windows — everything set
    #    before this will be lost, so we do it first)
    results["mac"] = apply_mac(interface, config["mac_address"])
    mac_applied = results["mac"]

    if IS_WINDOWS and mac_applied:
        # apply_mac cycled the adapter, wait for it to stabilize
        # before applying the rest so settings don't get wiped.
        log.info("Waiting for adapter to stabilize after MAC change...")
        time.sleep(3)

    # 2. Hostname
    results["hostname"] = apply_hostname(config["hostname"])

    # 3. MTU (after MAC on Windows so adapter cycle doesn't reset it)
    results["mtu"] = set_mtu(interface, mtu_val)

    # 4. IPv6 token (after MAC on Windows for same reason)
    results["ipv6_token"] = apply_ipv6_token(interface, config["ipv6_token"])

    # 5. machine-id (must be before DHCP)
    results["machine_id"] = spoof_machine_id(device_id)

    # 6. DHCP fingerprint
    results["dhcp"] = apply_dhcp_fingerprint(interface, config)

    # 7. TTL
    results["ttl"] = apply_ttl(config.get("os_ttl", 64))

    # 8. Reconnect — on Windows, skip if MAC was applied (adapter already
    #    cycled). On Linux, always reconnect to pick up DHCP config changes.
    if IS_WINDOWS:
        # No reconnect needed — apply_mac already cycled the adapter
        # (or MAC was skipped so no cycle happened at all).
        # Just re-verify MTU hasn't drifted.
        current_mtu = _win_get_current_mtu(_win_get_adapter_name(interface))
        if current_mtu != str(mtu_val):
            log.debug(f"MTU drifted to {current_mtu}, re-applying {mtu_val}")
            set_mtu(interface, mtu_val)
    else:
        log.info("Reconnecting interface to apply spoofed identity...")
        _reconnect_interface(interface)

    # Log results
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    log.info(f"Identity applied: {passed}/{total} steps succeeded")

    for step, ok in results.items():
        status = "✓" if ok else "✗"
        log.info(f"  {status} {step}")

    # 9. Wait for IPv6
    ipv6_token = config.get("ipv6_token", "")
    global_v6 = ""
    if ipv6_token:
        global_v6 = wait_for_global_v6(interface, ipv6_token, timeout=60)
        if global_v6:
            log.info(f"Final IPv6 address: {global_v6}")
            config["ipv6_global_address"] = global_v6
            config["ipv6_prefix"] = get_current_prefix(interface, ipv6_token)
            path.write_text(json.dumps(config, indent=2))
        else:
            log.warning("No global IPv6 address obtained — client will use fallback methods")

    return global_v6

def _reconnect_interface(interface: str, reapply_mtu: int = None) -> None:
    """Force the interface to reconnect with the new identity."""
    if IS_WINDOWS:
        adapter = _win_get_adapter_name(interface)
        # Do NOT release+renew — releasing can cause some drivers to reset
        # the spoofed MAC from the registry. Instead just renew, which
        # triggers a new DHCP handshake with the already-active adapter.
        try:
            subprocess.run(
                ["powershell", "-Command",
                 f"ipconfig /renew '{adapter}'"],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as e:
            log.warning(f"Windows DHCP renew failed: {e}")

        log.info("Waiting for network to re-establish...")
        time.sleep(5)

        # Re-apply MTU — netsh subinterface MTU can revert after DHCP renew
        if reapply_mtu:
            try:
                subprocess.run(
                    ["netsh", "interface", "ipv6", "set", "subinterface",
                     adapter, f"mtu={reapply_mtu}"],
                    capture_output=True, text=True, timeout=10,
                )
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "subinterface",
                     adapter, f"mtu={reapply_mtu}"],
                    capture_output=True, text=True, timeout=10,
                )
                log.debug(f"MTU re-applied to {reapply_mtu} after reconnect")
            except Exception:
                pass
        return

    # Linux
    dhcp_client = _detect_dhcp_client()

    if dhcp_client == "networkmanager":
        _run(["nmcli", "device", "disconnect", interface], "NM disconnect", check=False)
        time.sleep(2)
        _run(["nmcli", "device", "connect", interface], "NM reconnect", check=False)
    elif dhcp_client == "dhcpcd":
        _run(["systemctl", "restart", "dhcpcd"], "Restart dhcpcd", check=False)
    elif dhcp_client == "dhclient":
        _run(["dhclient", "-r", interface], "Release DHCP", check=False)
        time.sleep(1)
        _run(["dhclient", interface], "Request DHCP", check=False)
    elif dhcp_client == "networkd":
        _run(["systemctl", "restart", "systemd-networkd"], "Restart networkd", check=False)
    else:
        _run(["ip", "link", "set", "dev", interface, "down"], "Interface down")
        time.sleep(1)
        _run(["ip", "link", "set", "dev", interface, "up"], "Interface up")

    log.info("Waiting for network to re-establish...")
    time.sleep(5)

def restore_all() -> bool:
    """Restore the original identity from backup."""
    if not BACKUP_PATH.exists():
        log.error(f"No backup found at {BACKUP_PATH}")
        return False

    backup = json.loads(BACKUP_PATH.read_text())
    interface = backup.get("interface", "wlan0" if IS_LINUX else "Wi-Fi")

    log.info("=" * 60)
    log.info("RESTORING ORIGINAL IDENTITY")
    log.info("=" * 60)

    if backup.get("original_mac"):
        apply_mac(interface, backup["original_mac"])

    if backup.get("original_hostname"):
        apply_hostname(backup["original_hostname"])

    if IS_LINUX and backup.get("original_machine_id"):
        try:
            Path("/etc/machine-id").write_text(backup["original_machine_id"] + "\n")
            log.info("machine-id restored")
        except Exception:
            pass

    original_mtu = int(backup["original_mtu"]) if backup.get("original_mtu") else None
    if original_mtu:
        set_mtu(interface, original_mtu)

    if backup.get("original_ttl"):
        apply_ttl(int(backup["original_ttl"]))

    if IS_LINUX:
        for conf_path in ["/etc/dhcpcd.conf", "/etc/dhcp/dhclient.conf"]:
            p = Path(conf_path)
            if p.exists():
                try:
                    content = p.read_text()
                    content = re.sub(
                        r"# --- Cobra Identity Start ---.*?# --- Cobra Identity End ---\n?",
                        "", content, flags=re.DOTALL,
                    )
                    p.write_text(content)
                except Exception:
                    pass

        sysctl_conf = Path("/etc/sysctl.d/99-cobra-ttl.conf")
        if sysctl_conf.exists():
            sysctl_conf.unlink()

    _reconnect_interface(interface, reapply_mtu=original_mtu if IS_WINDOWS else None)

    log.info("Original identity restored")
    return True

# =============================================================================
# STATUS
# =============================================================================

def show_status() -> None:
    """Show current identity vs configured identity."""
    config = {}
    if IDENTITY_PATH.exists():
        try:
            config = json.loads(IDENTITY_PATH.read_text())
        except Exception:
            pass

    interface = config.get("interface", _detect_primary_interface())

    print()
    print("  COBRA IDENTITY STATUS")
    print("  " + "=" * 50)
    print(f"  Platform: {platform.system()}")

    # Current MAC
    if IS_WINDOWS:
        adapter = _win_get_adapter_name(interface)
        current_mac = _win_get_current_mac(adapter)
        mac_supported = _win_check_mac_support(adapter)
    else:
        try:
            current_mac = Path(f"/sys/class/net/{interface}/address").read_text().strip().upper()
        except Exception:
            current_mac = "unknown"
        mac_supported = True
    configured_mac = config.get("mac_address", "not configured").upper()
    if current_mac.upper() == configured_mac.upper():
        match = "✓"
    elif not mac_supported:
        match = "—"  # hardware limitation, not a failure
    else:
        match = "✗"
    mac_line = f"  {match} MAC:        current={current_mac}  configured={configured_mac}"
    if match == "—":
        mac_line += "  (driver blocks MAC changes)"
    print(mac_line)

    # Current hostname — on Windows, check both live and pending (registry)
    current_host = socket.gethostname()
    configured_host = config.get("hostname", "not configured")
    pending_host = None
    if IS_WINDOWS and current_host != configured_host:
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName').ComputerName"],
                capture_output=True, text=True, timeout=10,
            )
            pending_host = result.stdout.strip()
        except Exception:
            pass
    if current_host == configured_host:
        match = "✓"
    elif pending_host and pending_host.upper() == configured_host.upper():
        match = "~"  # pending reboot
    else:
        match = "✗"
    host_line = f"  {match} Hostname:   current={current_host}  configured={configured_host}"
    if match == "~":
        host_line += "  (pending reboot)"
    print(host_line)

    # IPv6 token
    configured_token = config.get("ipv6_token", "not configured")
    current_v6 = config.get("ipv6_global_address", "")
    if not current_v6:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(("2001:4860:4860::8888", 80))
            current_v6 = s.getsockname()[0]
            s.close()
        except Exception:
            current_v6 = "none"
    token_suffix = configured_token.lstrip(":") if configured_token != "not configured" else ""
    match = "✓" if token_suffix and current_v6.endswith(token_suffix) else "✗"
    print(f"  {match} IPv6:       current={current_v6}  token={configured_token}")

    # MTU
    if IS_WINDOWS:
        current_mtu = _win_get_current_mtu(_win_get_adapter_name(interface))
    else:
        try:
            current_mtu = Path(f"/sys/class/net/{interface}/mtu").read_text().strip()
        except Exception:
            current_mtu = "unknown"
    configured_mtu = str(config.get("mtu", "not configured"))
    match = "✓" if current_mtu == configured_mtu else "✗"
    print(f"  {match} MTU:        current={current_mtu}  configured={configured_mtu}")

    # TTL
    if IS_WINDOWS:
        current_ttl = _win_get_current_ttl()
    else:
        try:
            result = subprocess.run(["sysctl", "-n", "net.ipv4.ip_default_ttl"],
                                    capture_output=True, text=True, timeout=5)
            current_ttl = result.stdout.strip()
        except Exception:
            current_ttl = "unknown"
    configured_ttl = str(config.get("os_ttl", "not configured"))
    match = "✓" if current_ttl == configured_ttl else "✗"
    print(f"  {match} TTL:        current={current_ttl}  configured={configured_ttl}")

    print(f"    Interface:  {interface}")

    if IS_LINUX:
        print(f"    DHCP:       {_detect_dhcp_client()}")
    else:
        print(f"    DHCP:       Windows DHCP client")

    if config:
        print(f"    Config:     {IDENTITY_PATH}")
    else:
        print(f"    Config:     NOT FOUND — run --generate first")

    if BACKUP_PATH.exists():
        print(f"    Backup:     {BACKUP_PATH}")
    else:
        print(f"    Backup:     none (created on first --apply)")

    print()

# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Cobra Identity Manager — Full-Stack Network Spoofing"
    )
    parser.add_argument("--apply", action="store_true",
                        help="Apply the full spoofed identity")
    parser.add_argument("--restore", action="store_true",
                        help="Restore the original identity from backup")
    parser.add_argument("--status", action="store_true",
                        help="Show current vs configured identity")
    parser.add_argument("--generate", action="store_true",
                        help="Generate a default node_identity.json")
    parser.add_argument("--wait-v6", action="store_true",
                        help="Apply identity and print the final IPv6 address")
    parser.add_argument("--monitor", action="store_true",
                        help="Apply identity then monitor for prefix changes")
    parser.add_argument("--device-id", default=None,
                        help="Device ID for config generation (reads enrollment.json if not set)")
    parser.add_argument("--interface", default=None,
                        help="Network interface override")
    parser.add_argument("--config", default=None,
                        help="Path to node_identity.json (default: auto-detected CobraTail dir)")
    args = parser.parse_args()

    if args.status:
        show_status()
        return

    if args.generate:
        config = generate_default_config(
            device_id=args.device_id,
            interface=args.interface,
        )
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        IDENTITY_PATH.write_text(json.dumps(config, indent=2))
        print(f"\n  Identity config generated: {IDENTITY_PATH}")
        print(f"  Device ID:  {config['device_id']}")
        print(f"  MAC:        {config['mac_address']}")
        print(f"  Hostname:   {config['hostname']}")
        print(f"  IPv6 Token: {config['ipv6_token']}")
        print(f"  Interface:  {config['interface']}")
        if IS_WINDOWS:
            print(f"\n  Edit the file to customize, then run (as Administrator):")
            print(f"    python identity_manager.py --apply\n")
        else:
            print(f"\n  Edit the file to customize, then run:")
            print(f"    sudo python3 identity_manager.py --apply\n")
        return

    if args.restore:
        if IS_LINUX and os.geteuid() != 0:
            print("ERROR: Must run as root (sudo)")
            sys.exit(1)
        if IS_WINDOWS:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("ERROR: Must run as Administrator")
                sys.exit(1)
        restore_all()
        return

    if args.apply or args.wait_v6 or args.monitor:
        if IS_LINUX and os.geteuid() != 0:
            print("ERROR: Must run as root (sudo)")
            sys.exit(1)
        if IS_WINDOWS:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("ERROR: Must run as Administrator")
                sys.exit(1)

        global_v6 = apply_all(config_path=args.config)

        if args.wait_v6:
            if global_v6:
                print(global_v6)
            else:
                sys.exit(1)

        if args.monitor:
            config = json.loads(IDENTITY_PATH.read_text())
            interface = config.get("interface", "wlan0" if IS_LINUX else "Wi-Fi")
            token = config.get("ipv6_token", "")
            if token:
                try:
                    monitor_prefix_changes(interface, token)
                except KeyboardInterrupt:
                    log.info("Prefix monitor stopped")
            else:
                log.warning("No IPv6 token configured — nothing to monitor")
        return

    # No command given
    parser.print_help()


if __name__ == "__main__":
    main()