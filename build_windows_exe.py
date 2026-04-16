"""
BUILD COBRATAIL WINDOWS INSTALLER
==================================
Run this on your dev machine (or any Windows box with PyInstaller) to produce
CobraTailSetup.exe — a single-file installer that bundles:
  - installer.py (the install wizard)
  - client.py, cobra_launcher.py, identity_manager.py
  - oqs.dll (if present)
  - version.txt (offline fallback for the installer)
  - Icon and version info

The resulting .exe is what you distribute. Users double-click it,
it installs CobraTail to C:\\Program Files\\CobraTail, registers in
Apps & Features, creates shortcuts, and launches the cobra menu.

Requirements (on the build machine):
    pip install pyinstaller

Usage:
    python build_windows_exe.py
    python build_windows_exe.py --skip-oqs       # don't bundle oqs.dll
    python build_windows_exe.py --output-dir dist # custom output folder

Version management:
    Edit version.txt (single source of truth). This script reads it at build
    time and bakes the value into the .exe's Windows metadata AND bundles the
    file itself so the installer has an offline fallback.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ─── Build Configuration ─────────────────────────────────────────────────────

APP_NAME = "CobraTail"

def _load_build_version() -> str:
    """Read version from version.txt next to this build script.
    This is the single source of truth — edit version.txt to bump the release."""
    vf = Path(__file__).parent / "version.txt"
    if not vf.exists():
        print(f"  ERROR: version.txt not found at {vf}")
        print(f"  Create it with a single line containing the version (e.g., '1.0.3')")
        sys.exit(1)
    v = vf.read_text().strip()
    if not v:
        print(f"  ERROR: version.txt is empty")
        sys.exit(1)
    return v

VERSION = _load_build_version()
DESCRIPTION = "CobraTail VPN - Quantum-Resistant Mesh Network"
COMPANY = "CobraTail"
COPYRIGHT = "Copyright (c) 2025 CobraTail Project"

# Files to bundle into the installer
PAYLOAD_FILES = [
    "client.py",
    "cobra_launcher.py",
    "identity_manager.py",
]

# Directories to search for oqs.dll
OQS_DLL_SEARCH = [
    Path.home() / "liboqs" / "build" / "bin" / "Release" / "oqs.dll",
    Path.home() / "liboqs" / "build" / "bin" / "oqs.dll",
    Path.home() / ".quantum_vpn" / "lib" / "oqs.dll",
    Path("C:/Program Files/liboqs/bin/oqs.dll"),
]


def find_oqs_dll() -> Path | None:
    """Locate oqs.dll on the build machine."""
    for p in OQS_DLL_SEARCH:
        if p.exists():
            return p
    # Also check same directory as this script
    local = Path(__file__).parent / "lib" / "oqs.dll"
    if local.exists():
        return local
    local2 = Path(__file__).parent / "oqs.dll"
    if local2.exists():
        return local2
    return None


def create_version_file(tmp_dir: Path) -> Path:
    """Create a PyInstaller version-info file for the .exe metadata."""
    version_tuple = tuple(int(x) for x in VERSION.split(".")) + (0,)
    vt = ", ".join(str(x) for x in version_tuple)

    content = f"""
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({vt}),
    prodvers=({vt}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'{COMPANY}'),
            StringStruct(u'FileDescription', u'{DESCRIPTION}'),
            StringStruct(u'FileVersion', u'{VERSION}'),
            StringStruct(u'InternalName', u'{APP_NAME}'),
            StringStruct(u'OriginalFilename', u'{APP_NAME}.exe'),
            StringStruct(u'ProductName', u'CobraTail VPN'),
            StringStruct(u'ProductVersion', u'{VERSION}'),
            StringStruct(u'LegalCopyright', u'{COPYRIGHT}'),
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""
    vf = tmp_dir / "version_info.py"
    vf.write_text(content.strip(), encoding="utf-8")
    return vf


def build(args):
    script_dir = Path(__file__).parent.resolve()

    # Verify installer.py exists
    installer_py = script_dir / "installer.py"
    if not installer_py.exists():
        print(f"ERROR: installer.py not found in {script_dir}")
        print("  Make sure installer.py is in the same folder as this script.")
        sys.exit(1)

    # Verify version.txt exists (it's required — _load_build_version already
    # checked, but the bundling step below needs it to still be there)
    version_txt = script_dir / "version.txt"
    if not version_txt.exists():
        print(f"ERROR: version.txt not found in {script_dir}")
        sys.exit(1)

    # Verify payload files exist
    missing = []
    for f in PAYLOAD_FILES:
        if not (script_dir / f).exists():
            missing.append(f)
    if missing:
        print(f"ERROR: Missing payload files: {', '.join(missing)}")
        print(f"  Expected in: {script_dir}")
        print("  Copy client.py, cobra_launcher.py, identity_manager.py here.")
        sys.exit(1)

    # Find oqs.dll
    oqs_dll = None
    if not args.skip_oqs:
        oqs_dll = find_oqs_dll()
        if oqs_dll:
            print(f"  Found oqs.dll: {oqs_dll}")
        else:
            print("  WARNING: oqs.dll not found — installer will build it on target")
            print("  (Use --skip-oqs to suppress this warning)")

    # Create temp build dir
    with tempfile.TemporaryDirectory(prefix="cobratail_build_") as tmp:
        tmp_dir = Path(tmp)

        # Write version info
        version_file = create_version_file(tmp_dir)

        # Build --add-data arguments for payload files
        sep = ";"  # Windows path separator for PyInstaller
        add_data_args = []
        for f in PAYLOAD_FILES:
            src = script_dir / f
            add_data_args.extend(["--add-data", f"{src}{sep}payload"])

        # Bundle version.txt at the root of the extracted payload so
        # installer.py's _fetch_version() can fall back to it when
        # GitHub is unreachable at install time.
        add_data_args.extend(["--add-data", f"{version_txt}{sep}."])

        # Also bundle version.txt inside the payload/ dir so it gets installed
        # alongside the launcher scripts into C:\Program Files\CobraTail\bin
        # (the launcher's _load_version() can find it there too)
        add_data_args.extend(["--add-data", f"{version_txt}{sep}payload"])

        # Bundle oqs.dll if found
        if oqs_dll:
            add_data_args.extend(["--add-data", f"{oqs_dll}{sep}payload/lib"])

        # Bundle the setup_deps.ps1 helper if it exists
        deps_script = script_dir / "setup_deps.ps1"
        if deps_script.exists():
            add_data_args.extend(["--add-data", f"{deps_script}{sep}payload"])

        # Output directory
        output_dir = Path(args.output_dir).resolve() if args.output_dir else script_dir / "dist"

        # Check for icon
        icon_arg = []
        for icon_name in ["cobratail.ico", "cobra.ico", "icon.ico"]:
            icon_path = script_dir / icon_name
            if icon_path.exists():
                icon_arg = ["--icon", str(icon_path)]
                print(f"  Using icon: {icon_path}")
                break

        # Build the PyInstaller command
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--name", APP_NAME,
            "--distpath", str(output_dir),
            "--workpath", str(tmp_dir / "build"),
            "--specpath", str(tmp_dir),
            "--version-file", str(version_file),
            "--uac-admin",              # Request admin on launch
            "--console",                # Show console for install progress
            *icon_arg,
            *add_data_args,
            # Hidden imports the installer might need
            "--hidden-import", "json",
            "--hidden-import", "shutil",
            "--hidden-import", "winreg",
            "--hidden-import", "subprocess",
            str(installer_py),
        ]

        print()
        print("=" * 60)
        print(f"  Building {APP_NAME}.exe")
        print(f"  Version: {VERSION}  (from version.txt)")
        print(f"  Payload: {', '.join(PAYLOAD_FILES)}")
        print(f"  OQS DLL: {'bundled' if oqs_dll else 'not bundled (will build on target)'}")
        print(f"  Output:  {output_dir}")
        print("=" * 60)
        print()

        result = subprocess.run(cmd, cwd=str(script_dir))

        if result.returncode != 0:
            print()
            print("BUILD FAILED — check PyInstaller output above")
            sys.exit(1)

        exe_path = output_dir / f"{APP_NAME}.exe"
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print()
            print("=" * 60)
            print(f"  BUILD SUCCESSFUL")
            print(f"  {exe_path}")
            print(f"  Size: {size_mb:.1f} MB")
            print(f"  Version: {VERSION}")
            print("=" * 60)
        else:
            print("BUILD FAILED — .exe not found in output directory")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Build CobraTail Windows installer")
    parser.add_argument("--skip-oqs", action="store_true",
                        help="Don't bundle oqs.dll (installer will build on target)")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Output directory for the .exe (default: ./dist)")
    args = parser.parse_args()

    print()
    print("  COBRATAIL — Windows Installer Builder")
    print("  " + "=" * 40)
    print()

    # Check PyInstaller
    try:
        import PyInstaller
        print(f"  PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("  ERROR: PyInstaller not installed")
        print("  Run: pip install pyinstaller")
        sys.exit(1)

    build(args)


if __name__ == "__main__":
    main()