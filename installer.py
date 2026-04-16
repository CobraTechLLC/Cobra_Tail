"""
COBRATAIL INSTALLER
====================
This script is bundled into CobraTailSetup.exe by PyInstaller.
When the user runs the .exe, this script:
  1. Checks for admin privileges
  2. Installs program files to C:\Program Files\CobraTail\
  3. Creates config/data/logs directories
  4. Installs dependencies (Python packages, WireGuard, oqs.dll)
  5. Creates Start Menu + Desktop shortcuts
  6. Registers in Apps & Features (Add/Remove Programs)
  7. Creates 'cobra' command in PATH
  8. Launches the CobraTail launcher

Also handles uninstall when called with --uninstall flag.
"""

import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import winreg
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

APP_NAME = "CobraTail"
DISPLAY_NAME = "CobraTail VPN"
PUBLISHER = "CobraTail Project"
DESCRIPTION = "Quantum-Resistant Mesh VPN"
HELP_URL = "https://github.com/your-org/cobratail"
UPDATE_URL = "https://github.com/your-org/cobratail/releases"

# Single source of truth: fetch version from GitHub at runtime.
GITHUB_REPO = "CobraTechLLC/Cobra_Tail"
GITHUB_BRANCH = "main"
GITHUB_RAW_BASE = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}"

def _fetch_version() -> str:
    """Fetch the latest version from GitHub's version.txt.
    Falls back to the bundled version.txt (baked into the .exe at build time)
    if GitHub is unreachable. Final fallback is '0.0.0'."""
    import urllib.request
    # Try GitHub first
    try:
        url = f"{GITHUB_RAW_BASE}/version.txt"
        with urllib.request.urlopen(url, timeout=10) as resp:
            v = resp.read().decode("utf-8").strip()
            if v:
                return v
    except Exception:
        pass
    # Fall back to bundled version.txt
    try:
        if hasattr(sys, "_MEIPASS"):
            bundled = Path(sys._MEIPASS) / "version.txt"
        else:
            bundled = Path(__file__).parent / "version.txt"
        if bundled.exists():
            v = bundled.read_text().strip()
            if v:
                return v
    except Exception:
        pass
    return "0.0.0"

VERSION = _fetch_version()

# Installation paths
INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / APP_NAME
BIN_DIR = INSTALL_DIR / "bin"
CONFIG_DIR = INSTALL_DIR / "config"
DATA_DIR = INSTALL_DIR / "data"
LOG_DIR = INSTALL_DIR / "logs"
LIB_DIR = BIN_DIR / "lib"

# Registry keys
UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CobraTail"
APP_PATHS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cobra.exe"

# Shortcuts
START_MENU_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / APP_NAME
DESKTOP_SHORTCUT = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Desktop" / f"{APP_NAME}.lnk"

# What we're installing
PAYLOAD_PY_FILES = ["client.py", "cobra_launcher.py", "identity_manager.py"]
PAYLOAD_DEPS_SCRIPT = "setup_deps.ps1"

# WireGuard
WG_EXE = Path(r"C:\Program Files\WireGuard\wg.exe")

# ─── ANSI Colors ──────────────────────────────────────────────────────────────

BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
DIM = "\033[2m"
RESET = "\033[0m"

if not sys.stdout.isatty():
    BOLD = GREEN = RED = YELLOW = CYAN = DIM = RESET = ""


# ─── Helpers ──────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_payload_dir() -> Path:
    """Get the directory where PyInstaller extracted our payload files."""
    # PyInstaller extracts --add-data files to sys._MEIPASS
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "payload"
    # Dev mode — look in same directory as this script
    return Path(__file__).parent / "payload"


def step(num: int, total: int, msg: str):
    print(f"\n  {CYAN}[{num}/{total}]{RESET} {BOLD}{msg}{RESET}")


def ok(msg: str):
    print(f"    {GREEN}✓{RESET} {msg}")


def warn(msg: str):
    print(f"    {YELLOW}!{RESET} {msg}")


def fail(msg: str):
    print(f"    {RED}✗{RESET} {msg}")


def info(msg: str):
    print(f"    {msg}")


def run_quiet(cmd, **kwargs):
    """Run a command and suppress output unless it fails."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 300)
    return subprocess.run(cmd, **kwargs)


# ─── Migration ────────────────────────────────────────────────────────────────

def migrate_old_installation():
    """
    Migrate data from the old ~/.quantum_vpn directory to the new layout.
    Preserves enrollment, keys, identity — user doesn't have to re-enroll.
    """
    old_dir = Path.home() / ".quantum_vpn"
    if not old_dir.exists():
        return False

    print(f"\n  {CYAN}Found existing installation at {old_dir}{RESET}")
    print(f"  Migrating to {INSTALL_DIR}...")

    # Config files → config/
    config_files = {
        "enrollment.json": CONFIG_DIR / "enrollment.json",
        "cert_fingerprint": CONFIG_DIR / "cert_fingerprint",
        "wg_private.key": CONFIG_DIR / "wg_private.key",
        "wg_quantum.conf": CONFIG_DIR / "wg_quantum.conf",
        "client_id": CONFIG_DIR / "client_id",
    }

    # Data files → data/
    data_files = {
        "client_state.json": DATA_DIR / "client_state.json",
        "node_identity.json": DATA_DIR / "node_identity.json",
        "identity_backup.json": DATA_DIR / "identity_backup.json",
        "mesh_peers.json": DATA_DIR / "mesh_peers.json",
    }

    # Log files → logs/
    log_files = {
        "client.log": LOG_DIR / "client.log",
    }

    migrated = 0
    for mapping in [config_files, data_files, log_files]:
        for old_name, new_path in mapping.items():
            old_path = old_dir / old_name
            if old_path.exists():
                new_path.parent.mkdir(parents=True, exist_ok=True)
                if not new_path.exists():
                    shutil.copy2(str(old_path), str(new_path))
                    migrated += 1

    # Also check for lib/oqs.dll
    old_dll = old_dir / "lib" / "oqs.dll"
    if old_dll.exists() and not (LIB_DIR / "oqs.dll").exists():
        LIB_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(old_dll), str(LIB_DIR / "oqs.dll"))
        migrated += 1

    if migrated > 0:
        ok(f"Migrated {migrated} files from old installation")

        # Rename old dir so it doesn't confuse things
        backup = old_dir.parent / ".quantum_vpn.backup"
        try:
            if backup.exists():
                shutil.rmtree(backup, ignore_errors=True)
            old_dir.rename(backup)
            ok(f"Old directory renamed to .quantum_vpn.backup")
        except Exception:
            warn(f"Could not rename old directory — you can delete {old_dir} manually")

    return migrated > 0


# ─── Installation Steps ──────────────────────────────────────────────────────

def install_directories():
    """Create the CobraTail directory structure."""
    for d in [INSTALL_DIR, BIN_DIR, LIB_DIR, CONFIG_DIR, DATA_DIR, LOG_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    # Write a marker so we know this is a managed install
    marker = INSTALL_DIR / ".cobratail"
    marker.write_text(json.dumps({
        "version": VERSION,
        "installed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "install_dir": str(INSTALL_DIR),
    }, indent=2))

    ok(f"Created {INSTALL_DIR}")
    ok(f"  bin/     — program files")
    ok(f"  config/  — enrollment, certs, keys")
    ok(f"  data/    — runtime state")
    ok(f"  logs/    — client logs")


def install_program_files():
    """Copy Python scripts and oqs.dll from the payload."""
    payload = get_payload_dir()

    for filename in PAYLOAD_PY_FILES:
        src = payload / filename
        dst = BIN_DIR / filename
        if src.exists():
            shutil.copy2(str(src), str(dst))
            ok(f"Installed {filename}")
        else:
            fail(f"Missing from package: {filename}")

    # Copy oqs.dll if bundled
    oqs_src = payload / "lib" / "oqs.dll"
    if oqs_src.exists():
        LIB_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(oqs_src), str(LIB_DIR / "oqs.dll"))
        ok("Installed oqs.dll")
    else:
        warn("oqs.dll not bundled — will attempt to build during dependency setup")

    # Write version file
    version_file = INSTALL_DIR / "version.txt"
    version_file.write_text(VERSION)


def install_python_packages():
    """Install required Python packages."""
    packages = ["requests", "cryptography", "liboqs-python"]

    # Find python
    python = shutil.which("python") or shutil.which("python3")
    if not python:
        fail("Python not found in PATH")
        info("Download from: https://www.python.org/downloads/")
        info("IMPORTANT: Check 'Add Python to PATH' during install")
        return False

    # Verify it's real Python, not the Windows Store stub
    try:
        result = run_quiet([python, "--version"])
        version_str = result.stdout.strip()
        ok(f"Found {version_str}")
    except Exception:
        fail("Python found but not working")
        return False

    for pkg in packages:
        info(f"Installing {pkg}...")
        result = run_quiet([python, "-m", "pip", "install", pkg, "--quiet"])
        if result.returncode == 0:
            ok(f"  {pkg}")
        else:
            warn(f"  {pkg} — may need manual install")

    return True


def install_wireguard():
    """Check for WireGuard, install if missing."""
    if WG_EXE.exists():
        ok("WireGuard already installed")
        return True

    warn("WireGuard not found — attempting install...")

    # Try winget first
    winget = shutil.which("winget")
    if winget:
        info("Installing via winget...")
        result = run_quiet([
            winget, "install", "WireGuard.WireGuard",
            "--accept-package-agreements", "--accept-source-agreements"
        ])
        if result.returncode == 0 and WG_EXE.exists():
            ok("WireGuard installed via winget")
            return True

    # Fallback: download installer
    info("Downloading WireGuard installer...")
    try:
        import urllib.request
        wg_url = "https://download.wireguard.com/windows-client/wireguard-installer.exe"
        wg_installer = Path(tempfile.gettempdir()) / "wireguard-installer.exe"
        urllib.request.urlretrieve(wg_url, str(wg_installer))

        info("Running WireGuard installer (follow prompts)...")
        subprocess.run([str(wg_installer)], check=False)

        if WG_EXE.exists():
            ok("WireGuard installed")
            return True
        else:
            warn("WireGuard may not have installed — check manually")
            return False
    except Exception as e:
        fail(f"Could not download WireGuard: {e}")
        info("Install manually: https://www.wireguard.com/install/")
        return False


def build_oqs_dll():
    """Build oqs.dll if not already present."""
    if (LIB_DIR / "oqs.dll").exists():
        ok("oqs.dll already present")
        return True

    # Check if it exists in the old location
    old_locations = [
        Path.home() / "liboqs" / "build" / "bin" / "Release" / "oqs.dll",
        Path.home() / "liboqs" / "build" / "bin" / "oqs.dll",
    ]
    for loc in old_locations:
        if loc.exists():
            shutil.copy2(str(loc), str(LIB_DIR / "oqs.dll"))
            ok(f"Copied oqs.dll from {loc.parent}")
            return True

    warn("oqs.dll not found — checking build prerequisites...")

    # Check for git, cmake, VS Build Tools
    git = shutil.which("git")
    cmake = shutil.which("cmake")
    if not cmake:
        cmake_default = Path(r"C:\Program Files\CMake\bin\cmake.exe")
        if cmake_default.exists():
            cmake = str(cmake_default)

    if not git:
        warn("Git not installed — cannot build oqs.dll automatically")
        info("Install Git from: https://git-scm.com/download/win")
        info("Then re-run this installer")
        return False

    if not cmake:
        warn("CMake not installed — cannot build oqs.dll automatically")
        info("Install CMake from: https://cmake.org/download/")
        return False

    # Clone and build
    oqs_dir = Path.home() / "liboqs"
    oqs_build = oqs_dir / "build"

    if not (oqs_dir / ".git").exists():
        info("Cloning liboqs from GitHub...")
        result = run_quiet([git, "clone", "--depth", "1",
                           "https://github.com/open-quantum-safe/liboqs.git",
                           str(oqs_dir)])
        if result.returncode != 0:
            fail("git clone failed")
            return False
        ok("liboqs cloned")

    oqs_build.mkdir(exist_ok=True)

    info("Configuring liboqs with CMake...")
    result = run_quiet([
        cmake, "-S", str(oqs_dir), "-B", str(oqs_build),
        "-DBUILD_SHARED_LIBS=ON",
        "-DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE",
        "-DOQS_BUILD_ONLY_LIB=ON"
    ])
    if result.returncode != 0:
        fail("CMake configure failed — need Visual Studio Build Tools with C++")
        info("Install from: https://visualstudio.microsoft.com/visual-cpp-build-tools/")
        return False

    info("Building oqs.dll (this takes 2-5 minutes)...")
    result = run_quiet([
        cmake, "--build", str(oqs_build), "--config", "Release", "--parallel"
    ], timeout=600)
    if result.returncode != 0:
        fail("Build failed")
        return False

    # Find the built DLL
    for loc in old_locations:
        if loc.exists():
            shutil.copy2(str(loc), str(LIB_DIR / "oqs.dll"))
            ok(f"oqs.dll built and installed")
            return True

    fail("Build completed but oqs.dll not found")
    return False


def create_cobra_command():
    """
    Create a cobra.bat wrapper in a PATH directory so users can type 'cobra'
    from any terminal to launch the management menu.
    """
    python = shutil.which("python") or "python"
    launcher = BIN_DIR / "cobra_launcher.py"

    # Create a .bat wrapper
    bat_content = f'@echo off\r\n"{python}" "{launcher}" %*\r\n'
    bat_path = INSTALL_DIR / "cobra.bat"
    bat_path.write_text(bat_content)

    # Add INSTALL_DIR to system PATH if not already there
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                            0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            current_path, _ = winreg.QueryValueEx(key, "Path")
            install_str = str(INSTALL_DIR)
            if install_str.lower() not in current_path.lower():
                new_path = current_path.rstrip(";") + ";" + install_str
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                ok(f"Added {install_str} to system PATH")

                # Notify running programs of PATH change
                import ctypes
                HWND_BROADCAST = 0xFFFF
                WM_SETTINGCHANGE = 0x001A
                ctypes.windll.user32.SendMessageTimeoutW(
                    HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", 0x0002, 5000, None
                )
            else:
                ok("Already in system PATH")
    except PermissionError:
        warn("Could not add to system PATH (need admin)")
    except Exception as e:
        warn(f"PATH update failed: {e}")

    ok(f"Created cobra command: {bat_path}")


def create_shortcuts():
    """Create Start Menu and Desktop shortcuts using PowerShell."""
    python = shutil.which("python") or "python"
    launcher = BIN_DIR / "cobra_launcher.py"

    # Create Start Menu directory
    START_MENU_DIR.mkdir(parents=True, exist_ok=True)

    # PowerShell script to create .lnk files
    def make_shortcut(lnk_path: Path, target: str, arguments: str,
                      description: str, working_dir: str, icon: str = None):
        ps_script = f"""
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut('{lnk_path}')
$Shortcut.TargetPath = '{target}'
$Shortcut.Arguments = '{arguments}'
$Shortcut.Description = '{description}'
$Shortcut.WorkingDirectory = '{working_dir}'
"""
        if icon:
            ps_script += f"$Shortcut.IconLocation = '{icon}'\n"
        ps_script += "$Shortcut.Save()\n"

        run_quiet(["powershell", "-NoProfile", "-Command", ps_script])

    # Start Menu — CobraTail launcher
    make_shortcut(
        START_MENU_DIR / "CobraTail.lnk",
        target=python,
        arguments=f'"{launcher}"',
        description="CobraTail VPN — Management Menu",
        working_dir=str(BIN_DIR),
    )

    # Start Menu — Uninstall
    make_shortcut(
        START_MENU_DIR / "Uninstall CobraTail.lnk",
        target=sys.executable if hasattr(sys, "_MEIPASS") else python,
        arguments="--uninstall" if hasattr(sys, "_MEIPASS") else f'"{Path(__file__)}" --uninstall',
        description="Uninstall CobraTail VPN",
        working_dir=str(INSTALL_DIR),
    )

    # Desktop shortcut — point to the EXE if it exists, otherwise python launcher
    exe_path = INSTALL_DIR / "CobraTailSetup.exe"
    if exe_path.exists():
        make_shortcut(
            DESKTOP_SHORTCUT,
            target=str(exe_path),
            arguments="",
            description="CobraTail VPN",
            working_dir=str(INSTALL_DIR),
        )
    else:
        make_shortcut(
            DESKTOP_SHORTCUT,
            target=python,
            arguments=f'"{launcher}"',
            description="CobraTail VPN",
            working_dir=str(BIN_DIR),
        )

    ok(f"Start Menu: {START_MENU_DIR}")
    ok(f"Desktop: {DESKTOP_SHORTCUT}")


def register_uninstall():
    """Register CobraTail in Apps & Features (Add/Remove Programs)."""
    # Determine uninstall command
    if hasattr(sys, "_MEIPASS"):
        # Running from .exe — copy the exe to install dir for uninstall
        exe_src = Path(sys.executable)
        exe_dst = INSTALL_DIR / "CobraTailSetup.exe"
        try:
            shutil.copy2(str(exe_src), str(exe_dst))
        except Exception:
            pass
        uninstall_cmd = f'"{exe_dst}" --uninstall'
    else:
        python = shutil.which("python") or "python"
        uninstall_cmd = f'"{python}" "{Path(__file__)}" --uninstall'

    # Calculate install size in KB
    total_size = 0
    for root, dirs, files in os.walk(str(INSTALL_DIR)):
        for f in files:
            total_size += os.path.getsize(os.path.join(root, f))
    size_kb = total_size // 1024

    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY,
                                0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, DISPLAY_NAME)
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, VERSION)
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, PUBLISHER)
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(INSTALL_DIR))
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, uninstall_cmd)
            winreg.SetValueEx(key, "QuietUninstallString", 0, winreg.REG_SZ,
                              uninstall_cmd + " --quiet")
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ,
                              str(INSTALL_DIR / "CobraTailSetup.exe"))
            winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD, size_kb)
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "HelpLink", 0, winreg.REG_SZ, HELP_URL)
            winreg.SetValueEx(key, "URLUpdateInfo", 0, winreg.REG_SZ, UPDATE_URL)
            winreg.SetValueEx(key, "Comments", 0, winreg.REG_SZ, DESCRIPTION)

        ok("Registered in Apps & Features")
    except PermissionError:
        fail("Could not register in Apps & Features (need admin)")
    except Exception as e:
        fail(f"Registry error: {e}")


def run_mlkem_selftest() -> bool:
    """Run ML-KEM-1024 self-test to verify oqs.dll works."""
    python = shutil.which("python") or "python"
    lib_dir = str(LIB_DIR)

    test_code = f"""
import os, sys
dll_dirs = [
    r'{lib_dir}',
    str(__import__('pathlib').Path.home() / 'liboqs' / 'build' / 'bin' / 'Release'),
    str(__import__('pathlib').Path.home() / 'liboqs' / 'build' / 'bin'),
]
for d in dll_dirs:
    if os.path.isdir(d):
        try: os.add_dll_directory(d)
        except: pass
        os.environ['PATH'] = d + ';' + os.environ.get('PATH', '')
try:
    import oqs
    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    pub = kem.generate_keypair()
    sk = kem.export_secret_key()
    kem2 = oqs.KeyEncapsulation('ML-KEM-1024')
    ct, ss_enc = kem2.encap_secret(pub)
    kem3 = oqs.KeyEncapsulation('ML-KEM-1024', secret_key=sk)
    ss_dec = kem3.decap_secret(ct)
    assert ss_enc == ss_dec, 'MISMATCH'
    print('PASSED')
    sys.exit(0)
except Exception as e:
    print('FAILED: ' + str(e))
    sys.exit(1)
"""
    result = run_quiet([python, "-c", test_code])
    return result.returncode == 0


# ─── Uninstall ────────────────────────────────────────────────────────────────

def uninstall(quiet: bool = False):
    """Remove CobraTail completely."""
    if not quiet:
        print()
        print(f"  {BOLD}COBRATAIL — Uninstaller{RESET}")
        print(f"  {'=' * 40}")
        print()
        print(f"  This will remove CobraTail from your system.")
        print(f"  Install directory: {INSTALL_DIR}")
        print()

        try:
            confirm = input(f"  {YELLOW}Remove CobraTail? [y/N]{RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.")
            sys.exit(0)

        if confirm not in ("y", "yes"):
            print("  Cancelled.")
            sys.exit(0)

    print()

    # Stop any running service
    info("Stopping CobraTail service...")
    run_quiet(["taskkill", "/F", "/IM", "python.exe", "/FI",
               f"WINDOWTITLE eq *cobra*"], timeout=10)

    # Remove scheduled tasks
    info("Removing scheduled tasks...")
    run_quiet(["schtasks", "/Delete", "/TN", "CobraVPNClient", "/F"], timeout=10)
    run_quiet(["schtasks", "/Delete", "/TN", "CobraIdentityManager", "/F"], timeout=10)

    # Remove from PATH
    info("Removing from system PATH...")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                            0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            current_path, _ = winreg.QueryValueEx(key, "Path")
            install_str = str(INSTALL_DIR)
            parts = [p for p in current_path.split(";") if p.strip().lower() != install_str.lower()]
            new_path = ";".join(parts)
            if new_path != current_path:
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                ok("Removed from PATH")
    except Exception:
        pass

    # Remove registry entry
    info("Removing from Apps & Features...")
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY)
        ok("Unregistered from Apps & Features")
    except FileNotFoundError:
        pass
    except Exception:
        warn("Could not remove registry entry")

    # Remove shortcuts
    info("Removing shortcuts...")
    if START_MENU_DIR.exists():
        shutil.rmtree(str(START_MENU_DIR), ignore_errors=True)
    if DESKTOP_SHORTCUT.exists():
        DESKTOP_SHORTCUT.unlink(missing_ok=True)
    ok("Shortcuts removed")

    # Ask about config/data
    keep_data = False
    if not quiet:
        try:
            keep = input(f"\n  {YELLOW}Keep your enrollment data and config? [Y/n]{RESET} ").strip().lower()
            keep_data = keep not in ("n", "no")
        except (EOFError, KeyboardInterrupt):
            keep_data = True

    # Remove install directory
    info("Removing program files...")
    if keep_data:
        # Remove only bin/ and leave config/data/logs
        if BIN_DIR.exists():
            shutil.rmtree(str(BIN_DIR), ignore_errors=True)
        # Remove non-data files
        for f in INSTALL_DIR.glob("*"):
            if f.is_file():
                f.unlink(missing_ok=True)
        ok(f"Program files removed (config/data kept in {INSTALL_DIR})")
    else:
        if INSTALL_DIR.exists():
            shutil.rmtree(str(INSTALL_DIR), ignore_errors=True)
        ok("All files removed")

    # Also clean up old .quantum_vpn if it exists
    old_dir = Path.home() / ".quantum_vpn"
    old_backup = Path.home() / ".quantum_vpn.backup"
    if not keep_data:
        for d in [old_dir, old_backup]:
            if d.exists():
                shutil.rmtree(str(d), ignore_errors=True)

    print()
    print(f"  {GREEN}CobraTail has been uninstalled.{RESET}")
    if keep_data:
        print(f"  {DIM}Your config is still at {INSTALL_DIR}{RESET}")
        print(f"  {DIM}Delete that folder to remove everything.{RESET}")
    print()

    if not quiet:
        try:
            input("  Press Enter to close...")
        except (EOFError, KeyboardInterrupt):
            pass


# ─── Main Install Flow ───────────────────────────────────────────────────────

def install():
    total = 9

    print()
    print(f"  {BOLD}{'=' * 52}{RESET}")
    print(f"  {BOLD}  COBRATAIL VPN — Installer v{VERSION}{RESET}")
    print(f"  {BOLD}  Quantum-Resistant Mesh Network{RESET}")
    print(f"  {BOLD}{'=' * 52}{RESET}")
    print()
    print(f"  Install location: {CYAN}{INSTALL_DIR}{RESET}")
    print()

    # ── Step 1: Admin check ──
    step(1, total, "Checking privileges...")
    if not is_admin():
        fail("Administrator privileges required")
        info("Right-click the installer and select 'Run as administrator'")
        input("\n  Press Enter to exit...")
        sys.exit(1)
    ok("Running as Administrator")

    # ── Step 2: Create directories ──
    step(2, total, "Creating directory structure...")
    install_directories()

    # ── Step 3: Migrate old install ──
    step(3, total, "Checking for existing installation...")
    migrated = migrate_old_installation()
    if not migrated:
        ok("Clean install")

    # ── Step 4: Install program files ──
    step(4, total, "Installing program files...")
    install_program_files()

    # ── Step 5: Python packages ──
    step(5, total, "Installing Python packages...")
    install_python_packages()

    # ── Step 6: WireGuard ──
    step(6, total, "Checking WireGuard...")
    install_wireguard()

    # ── Step 7: oqs.dll (quantum crypto) ──
    step(7, total, "Setting up quantum cryptography (oqs.dll)...")
    oqs_ok = build_oqs_dll()

    # ── Step 8: Shortcuts, PATH, Apps & Features ──
    step(8, total, "Registering CobraTail...")
    create_cobra_command()
    register_uninstall()
    create_shortcuts()

    # ── Step 9: Self-test ──
    step(9, total, "Running ML-KEM-1024 self-test...")
    if oqs_ok or (LIB_DIR / "oqs.dll").exists():
        if run_mlkem_selftest():
            ok("ML-KEM-1024 encap/decap: PASSED")
            ok("Client-side quantum encryption: ENABLED")
        else:
            warn("Self-test failed — client will use server-side encryption (still quantum-safe)")
    else:
        warn("oqs.dll not available — client will use server-side encryption (still quantum-safe)")

    # ── Summary ──
    print()
    print(f"  {GREEN}{'=' * 52}{RESET}")
    print(f"  {GREEN}  INSTALLATION COMPLETE{RESET}")
    print(f"  {GREEN}{'=' * 52}{RESET}")
    print()
    print(f"  {BOLD}Installed to:{RESET}  {INSTALL_DIR}")
    print(f"  {BOLD}Command:{RESET}       Open any terminal and type: {CYAN}cobra{RESET}")
    print(f"  {BOLD}Desktop:{RESET}       CobraTail shortcut on your Desktop")
    print(f"  {BOLD}Start Menu:{RESET}    {START_MENU_DIR.name}")
    print(f"  {BOLD}Uninstall:{RESET}     Apps & Features → CobraTail VPN")
    print()

    # Ask to launch
    try:
        launch = input(f"  {CYAN}Launch CobraTail now? [Y/n]{RESET} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        launch = "n"

    if launch not in ("n", "no"):
        python = shutil.which("python") or "python"
        launcher = BIN_DIR / "cobra_launcher.py"
        if launcher.exists():
            print(f"\n  Launching CobraTail...\n")
            # Launch in a new window so the installer can exit
            subprocess.Popen(
                [python, str(launcher)],
                cwd=str(BIN_DIR),
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            fail(f"Launcher not found at {launcher}")
    else:
        print()
        print(f"  To start CobraTail later, open a terminal and type: {CYAN}cobra{RESET}")
        print()

def is_already_installed() -> bool:
    """Check if CobraTail is already installed and functional."""
    marker = INSTALL_DIR / ".cobratail"
    launcher = BIN_DIR / "cobra_launcher.py"
    return marker.exists() and launcher.exists()


def launch_existing():
    """CobraTail is already installed — launch the management menu directly."""
    print()
    print(f"  {BOLD}COBRATAIL VPN{RESET} — Already installed (v{VERSION})")
    print(f"  {DIM}Install location: {INSTALL_DIR}{RESET}")
    print()

    # Always refresh program files from payload in case this is a newer build
    payload = get_payload_dir()
    if payload.exists():
        updated = 0
        for filename in PAYLOAD_PY_FILES:
            src = payload / filename
            dst = BIN_DIR / filename
            if src.exists():
                try:
                    if not dst.exists() or src.read_bytes() != dst.read_bytes():
                        shutil.copy2(str(src), str(dst))
                        updated += 1
                except PermissionError:
                    pass
        if updated:
            print(f"  {GREEN}Updated {updated} file(s){RESET}")
            print()

    python = shutil.which("python") or "python"
    launcher = BIN_DIR / "cobra_launcher.py"

    # If we're running from the .exe (PyInstaller), launch the menu
    # in the same console window so it replaces the installer cleanly
    if hasattr(sys, "_MEIPASS"):
        try:
            result = subprocess.run(
                [python, str(launcher)],
                cwd=str(BIN_DIR),
            )
            sys.exit(result.returncode)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        subprocess.Popen(
            [python, str(launcher)],
            cwd=str(BIN_DIR),
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    # Enable ANSI on Windows
    if platform.system() == "Windows":
        os.system("")  # Enables ANSI escape codes in cmd.exe

    if "--uninstall" in sys.argv:
        quiet = "--quiet" in sys.argv
        uninstall(quiet=quiet)
    elif is_already_installed():
        # Already installed — just launch the management menu
        launch_existing()
    else:
        install()


if __name__ == "__main__":
    main()