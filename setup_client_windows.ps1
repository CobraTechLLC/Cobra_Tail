# -------------------------------------------------------------
# QUANTUM VPN CLIENT -- Complete Windows Setup Script
# Run this ONCE in an Administrator PowerShell terminal
# -------------------------------------------------------------
# Installs everything needed for the Quantum VPN client:
#   - Python packages (requests, cryptography, liboqs-python)
#   - WireGuard
#   - Git (if missing)
#   - CMake (if missing)
#   - Visual Studio Build Tools with C++ (if missing)
#   - Builds liboqs from source (oqs.dll)
#   - Copies oqs.dll to client lib/ for auto-discovery
#   - Runs ML-KEM-1024 self-test to verify everything works
#
# Usage: Right-click PowerShell -> Run as Administrator -> paste:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\setup_client_windows.ps1
#
# Flags:
#   .\setup_client_windows.ps1 -SkipVS      # skip VS Build Tools install
#   .\setup_client_windows.ps1 -Clean        # wipe old liboqs build
#   .\setup_client_windows.ps1 -TestOnly     # just run the self-test
# -------------------------------------------------------------

param(
    [switch]$SkipVS,
    [switch]$Clean,
    [switch]$TestOnly
)

$ErrorActionPreference = "Continue"

# --- Helpers ------------------------------------------------------------------

function Write-Step($num, $total, $msg) {
    Write-Host ""
    Write-Host "[$num/$total] $msg" -ForegroundColor Yellow
}

function Write-Ok($msg) {
    Write-Host "  OK: $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
    Write-Host "  FAIL: $msg" -ForegroundColor Red
}

function Write-Note($msg) {
    Write-Host "  $msg" -ForegroundColor Yellow
}

function Write-Detail($msg) {
    Write-Host "  $msg" -ForegroundColor White
}

function Test-CommandExists($cmd) {
    try {
        $null = & $cmd --version 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    catch { return $false }
}

function Refresh-SessionPath {
    $machinePath = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine')
    $userPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User')
    $env:PATH = $machinePath + ";" + $userPath
}

# --- Paths --------------------------------------------------------------------

$oqsDir        = "$env:USERPROFILE\liboqs"
$oqsBuildDir   = "$oqsDir\build"
$oqsDll        = "$oqsBuildDir\bin\Release\oqs.dll"
$oqsDllAlt     = "$oqsBuildDir\bin\oqs.dll"
$clientDir     = "$env:USERPROFILE\.quantum_vpn"
$scriptDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$clientLibDir  = "$scriptDir\lib"
$clientLibDll  = "$clientLibDir\oqs.dll"
$wgExe         = "C:\Program Files\WireGuard\wg.exe"

$totalSteps    = 8

# --- Banner -------------------------------------------------------------------

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  QUANTUM VPN CLIENT -- Complete Windows Setup" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

# --- Admin Check --------------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail "Run this script as Administrator"
    Write-Detail "Right-click PowerShell -> Run as Administrator"
    exit 1
}
Write-Ok "Running as Administrator"

# --- Test-Only Mode -----------------------------------------------------------

if ($TestOnly) {
    Write-Host ""
    Write-Host "=== ML-KEM-1024 SELF-TEST ===" -ForegroundColor Cyan
    Write-Host ""

    $testScript = @"
import os, sys
from pathlib import Path
dll_dirs = [
    str(Path.home() / 'liboqs' / 'build' / 'bin' / 'Release'),
    str(Path.home() / 'liboqs' / 'build' / 'bin'),
    str(Path(r'$clientLibDir')),
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
    print('PASSED: ML-KEM-1024 encap/decap OK (%dB pubkey, %dB ciphertext)' % (len(pub), len(ct)))
    print('  Secret: ' + ss_enc.hex()[:32] + '...')
    sys.exit(0)
except Exception as e:
    print('FAILED: ' + str(e))
    sys.exit(1)
"@

    python -c $testScript
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Ok "Self-test passed"
    }
    else {
        Write-Host ""
        Write-Fail "Self-test failed"
    }
    exit $LASTEXITCODE
}

# ==============================================================================
# STEP 1: Python
# ==============================================================================

Write-Step 1 $totalSteps "Checking Python..."

try {
    $pyVersion = (python --version 2>&1).ToString().Trim()
    Write-Ok $pyVersion
}
catch {
    Write-Fail "Python not found"
    Write-Detail "Download from: https://www.python.org/downloads/"
    Write-Detail "IMPORTANT: Check 'Add Python to PATH' during install"
    exit 1
}

# Verify pip
try {
    $null = pip --version 2>&1
    Write-Ok "pip available"
}
catch {
    Write-Note "pip not found -- trying to bootstrap..."
    python -m ensurepip 2>&1 | Out-Null
}

# ==============================================================================
# STEP 2: Python packages
# ==============================================================================

Write-Step 2 $totalSteps "Installing Python packages..."

$packages = @("requests", "cryptography", "liboqs-python")
foreach ($pkg in $packages) {
    Write-Host "  Installing $pkg..." -NoNewline
    pip install $pkg --quiet 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " OK" -ForegroundColor Green
    }
    else {
        Write-Host " WARN" -ForegroundColor Yellow
    }
}

# ==============================================================================
# STEP 3: WireGuard
# ==============================================================================

Write-Step 3 $totalSteps "Checking WireGuard..."

if (Test-Path $wgExe) {
    Write-Ok "WireGuard found at $wgExe"
}
else {
    Write-Note "WireGuard not found -- installing..."

    # Try winget first
    $wgInstalled = $false
    try {
        winget install WireGuard.WireGuard --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        if (Test-Path $wgExe) {
            Write-Ok "WireGuard installed via winget"
            $wgInstalled = $true
        }
    }
    catch {}

    if (-not $wgInstalled) {
        Write-Note "Downloading WireGuard installer..."
        $wgDl = "$env:TEMP\wireguard-installer.exe"
        try {
            Invoke-WebRequest -Uri "https://download.wireguard.com/windows-client/wireguard-installer.exe" -OutFile $wgDl -UseBasicParsing
            Write-Note "Running installer (follow the prompts)..."
            Start-Process -FilePath $wgDl -Wait
            if (Test-Path $wgExe) {
                Write-Ok "WireGuard installed"
            }
            else {
                Write-Fail "WireGuard install may have failed -- check manually"
            }
            Remove-Item $wgDl -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Fail "Download failed. Install manually: https://www.wireguard.com/install/"
        }
    }
}

# ==============================================================================
# STEP 4: Git
# ==============================================================================

Write-Step 4 $totalSteps "Checking Git..."

# Common install locations that might not be in PATH
$gitCandidates = @(
    "C:\Program Files\Git\cmd\git.exe",
    "C:\Program Files (x86)\Git\cmd\git.exe",
    "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe"
)

if (Test-CommandExists "git") {
    $gitVer = (git --version 2>&1).ToString().Trim()
    Write-Ok $gitVer
}
else {
    # Check common locations before trying to install
    $gitFound = $false
    foreach ($gp in $gitCandidates) {
        if (Test-Path $gp) {
            $gitDir = Split-Path -Parent $gp
            $env:PATH = $gitDir + ";" + $env:PATH
            Write-Ok "Git found at $gp (added to PATH)"
            $gitFound = $true
            break
        }
    }

    if (-not $gitFound) {
        Write-Note "Git not found -- installing..."

        $gitInstalled = $false

        # Try winget first
        try {
            $null = winget --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                winget install Git.Git --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
                Refresh-SessionPath
                if (Test-CommandExists "git") {
                    Write-Ok "Git installed via winget"
                    $gitInstalled = $true
                }
            }
        }
        catch {}

        # Fallback: download Git installer directly
        if (-not $gitInstalled) {
            Write-Note "Downloading Git installer from github.com..."
            $gitDl = "$env:TEMP\git-installer.exe"
            try {
                Invoke-WebRequest -Uri "https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.2/Git-2.47.1.2-64-bit.exe" -OutFile $gitDl -UseBasicParsing
                Write-Note "Running Git installer (silent)..."
                $proc = Start-Process -FilePath $gitDl -ArgumentList "/VERYSILENT /NORESTART /SP- /NOCANCEL /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS" -Wait -PassThru
                Remove-Item $gitDl -Force -ErrorAction SilentlyContinue

                # Add to PATH for this session
                $gitSearchPaths = @(
                    "C:\Program Files\Git\cmd",
                    "C:\Program Files (x86)\Git\cmd",
                    "$env:LOCALAPPDATA\Programs\Git\cmd"
                )
                foreach ($gp in $gitSearchPaths) {
                    if (Test-Path "$gp\git.exe") {
                        $env:PATH = $gp + ";" + $env:PATH
                        break
                    }
                }
                Refresh-SessionPath

                if (Test-CommandExists "git") {
                    Write-Ok "Git installed successfully"
                    $gitInstalled = $true
                }
                else {
                    # One more try with common paths
                    foreach ($gp in $gitCandidates) {
                        if (Test-Path $gp) {
                            $env:PATH = (Split-Path -Parent $gp) + ";" + $env:PATH
                            Write-Ok "Git found at $gp"
                            $gitInstalled = $true
                            break
                        }
                    }
                }
            }
            catch {
                Write-Fail "Git download failed: $_"
            }
        }

        if (-not $gitInstalled) {
            Write-Fail "Could not install Git automatically"
            Write-Detail "Install from: https://git-scm.com/download/win"
            Write-Detail "Then restart this script."
            exit 1
        }
    }
}

# ==============================================================================
# STEP 5: CMake
# ==============================================================================

Write-Step 5 $totalSteps "Checking CMake..."

# Check PATH and common locations
$cmakeExe = $null
if (Test-CommandExists "cmake") {
    $cmakeExe = "cmake"
}
elseif (Test-Path "C:\Program Files\CMake\bin\cmake.exe") {
    $cmakeExe = "C:\Program Files\CMake\bin\cmake.exe"
    $env:PATH = "C:\Program Files\CMake\bin;" + $env:PATH
}

if ($cmakeExe) {
    $cmakeVer = (& $cmakeExe --version 2>&1 | Select-Object -First 1).ToString().Trim()
    Write-Ok "cmake: $cmakeVer"
}
else {
    Write-Note "CMake not found -- installing..."

    $cmakeInstalled = $false
    try {
        winget install Kitware.CMake --accept-package-agreements --accept-source-agreements 2>&1 | Out-Null
        # Refresh PATH
        Refresh-SessionPath
        # Also check default location
        if (Test-Path "C:\Program Files\CMake\bin\cmake.exe") {
            $env:PATH = "C:\Program Files\CMake\bin;" + $env:PATH
        }
        if (Test-CommandExists "cmake") {
            Write-Ok "CMake installed via winget"
            $cmakeExe = "cmake"
            $cmakeInstalled = $true
        }
    }
    catch {}

    if (-not $cmakeInstalled) {
        Write-Note "winget failed -- downloading CMake MSI installer..."
        $cmakeMsi = "$env:TEMP\cmake-installer.msi"
        try {
            Invoke-WebRequest -Uri "https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-windows-x86_64.msi" -OutFile $cmakeMsi -UseBasicParsing
            Write-Note "Installing CMake..."
            Start-Process msiexec -ArgumentList "/i `"$cmakeMsi`" /quiet /norestart ADD_CMAKE_TO_PATH=System" -Wait
            $env:PATH = "C:\Program Files\CMake\bin;" + $env:PATH
            Remove-Item $cmakeMsi -Force -ErrorAction SilentlyContinue

            if (Test-CommandExists "cmake") {
                Write-Ok "CMake installed"
                $cmakeExe = "cmake"
            }
            else {
                Write-Fail "CMake installed but not found in PATH"
                Write-Detail "Restart your terminal and run this script again."
                exit 1
            }
        }
        catch {
            Write-Fail "Could not install CMake"
            Write-Detail "Install from: https://cmake.org/download/"
            Write-Detail "Check 'Add CMake to system PATH' during install."
            exit 1
        }
    }
}

# ==============================================================================
# STEP 6: Visual Studio Build Tools (C++ compiler)
# ==============================================================================

Write-Step 6 $totalSteps "Checking Visual Studio Build Tools (C++ compiler)..."

# Use vswhere to find VS with C++ tools
$vsPath = $null
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"

if (Test-Path $vswhere) {
    try {
        $vsResult = & $vswhere -latest -property installationPath -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 2>&1
        $vsCandidate = $vsResult.ToString().Trim()
        if (Test-Path $vsCandidate -ErrorAction SilentlyContinue) {
            $vsPath = $vsCandidate
        }
    }
    catch {}

    # Fallback: try without requires filter
    if (-not $vsPath) {
        try {
            $vsResult = & $vswhere -latest -property installationPath 2>&1
            $vsCandidate = $vsResult.ToString().Trim()
            if (Test-Path $vsCandidate -ErrorAction SilentlyContinue) {
                $vcvars = "$vsCandidate\VC\Auxiliary\Build\vcvars64.bat"
                if (Test-Path $vcvars) {
                    $vsPath = $vsCandidate
                }
            }
        }
        catch {}
    }
}

if ($vsPath) {
    try {
        $vsVersion = (& $vswhere -latest -property catalog_productDisplayVersion 2>&1).ToString().Trim()
    }
    catch { $vsVersion = "found" }
    Write-Ok "Visual Studio Build Tools: $vsVersion"
    Write-Ok "  Path: $vsPath"
}
elseif ($SkipVS) {
    Write-Note "Skipping VS Build Tools install (-SkipVS flag)"
    Write-Note "Build will rely on any existing compiler in PATH"
}
else {
    Write-Note "Visual Studio Build Tools with C++ not found"
    Write-Note "This is required to compile liboqs (oqs.dll)"
    Write-Note ""
    Write-Note "This is a ~2-4 GB download and takes 10-20 minutes to install."
    Write-Host ""

    $confirm = Read-Host "  Install VS Build Tools now? [Y/n]"
    if ($confirm -eq "" -or $confirm -match "^[Yy]") {

        $vsInstaller = "$env:TEMP\vs_BuildTools.exe"
        Write-Note "Downloading Visual Studio Build Tools installer..."

        try {
            Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_BuildTools.exe" -OutFile $vsInstaller -UseBasicParsing
            Write-Ok "Downloaded installer"
        }
        catch {
            Write-Fail "Download failed"
            Write-Detail "Install manually: https://visualstudio.microsoft.com/visual-cpp-build-tools/"
            Write-Detail "Select: Desktop development with C++"
            exit 1
        }

        Write-Note "Installing VS Build Tools with C++ workload..."
        Write-Note "A Visual Studio Installer window will appear -- please wait."
        Write-Host ""

        try {
            $vsArgs = "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --passive --wait --norestart"
            $proc = Start-Process -FilePath $vsInstaller -ArgumentList $vsArgs -Wait -PassThru

            # Exit code 3010 = success but reboot needed
            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                Write-Ok "Visual Studio Build Tools installed"
                if ($proc.ExitCode -eq 3010) {
                    Write-Note "A reboot is recommended but not required to continue."
                }
            }
            else {
                Write-Fail "Installer exited with code $($proc.ExitCode)"
                Write-Detail "Try installing manually from:"
                Write-Detail "https://visualstudio.microsoft.com/visual-cpp-build-tools/"
            }
        }
        catch {
            Write-Fail "Installation failed: $_"
        }
        finally {
            Remove-Item $vsInstaller -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        Write-Note "Skipped. Install manually and re-run this script."
        Write-Detail "https://visualstudio.microsoft.com/visual-cpp-build-tools/"
        Write-Detail "Select: Desktop development with C++"
    }
}

# ==============================================================================
# STEP 7: Build liboqs (oqs.dll)
# ==============================================================================

Write-Step 7 $totalSteps "Building liboqs (oqs.dll)..."

# Check if DLL already exists
$dllExists = (Test-Path $oqsDll) -or (Test-Path $oqsDllAlt) -or (Test-Path $clientLibDll)

if ($dllExists -and -not $Clean) {
    if (Test-Path $oqsDll) { $dllLocation = $oqsDll }
    elseif (Test-Path $clientLibDll) { $dllLocation = $clientLibDll }
    else { $dllLocation = $oqsDllAlt }
    Write-Ok "oqs.dll already exists: $dllLocation"
    Write-Note "Use -Clean flag to rebuild from scratch"
}
else {
    # Clean old build if requested
    if ($Clean -and (Test-Path $oqsDir)) {
        Write-Note "Cleaning old liboqs directory..."
        Remove-Item $oqsDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Clone
    if (-not (Test-Path "$oqsDir\.git")) {
        Write-Note "Cloning liboqs from GitHub..."
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git $oqsDir 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "git clone failed"
            exit 1
        }
        Write-Ok "liboqs cloned"
    }
    else {
        Write-Note "liboqs already cloned -- pulling latest..."
        Push-Location $oqsDir
        git pull 2>&1 | Out-Null
        Pop-Location
    }

    # Create build directory
    if (-not (Test-Path $oqsBuildDir)) {
        New-Item -ItemType Directory -Path $oqsBuildDir -Force | Out-Null
    }

    # Configure with cmake
    Write-Note "Configuring with cmake..."
    Write-Detail "  BUILD_SHARED_LIBS=ON (creates oqs.dll)"
    Write-Detail "  CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE"

    & $cmakeExe -S $oqsDir -B $oqsBuildDir -DBUILD_SHARED_LIBS=ON -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE -DOQS_BUILD_ONLY_LIB=ON 2>&1 | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "cmake configure failed"
        Write-Detail "Make sure Visual Studio Build Tools is fully installed"
        Write-Detail "with the Desktop development with C++ workload."
        Write-Detail "You may need to restart your terminal after installing VS."
        exit 1
    }
    Write-Ok "cmake configure complete"

    # Build
    Write-Note "Building liboqs (this takes 2-5 minutes)..."

    & $cmakeExe --build $oqsBuildDir --config Release --parallel 2>&1 | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "cmake build failed"
        Write-Detail "Check the build output above for errors."
        Write-Detail "Common fix: restart terminal after VS Build Tools install."
        exit 1
    }

    # Verify DLL was created
    if (Test-Path $oqsDll) {
        $dllSize = [math]::Round((Get-Item $oqsDll).Length / 1MB, 1)
        Write-Ok "oqs.dll built: $oqsDll ($dllSize MB)"
    }
    elseif (Test-Path $oqsDllAlt) {
        $dllSize = [math]::Round((Get-Item $oqsDllAlt).Length / 1MB, 1)
        Write-Ok "oqs.dll built: $oqsDllAlt ($dllSize MB)"
    }
    else {
        Write-Fail "Build completed but oqs.dll not found"
        Write-Detail "Searching build tree..."
        Get-ChildItem -Path $oqsBuildDir -Recurse -Filter "oqs.dll" | ForEach-Object {
            Write-Detail "  Found: $($_.FullName)"
        }
        exit 1
    }

    # Copy DLL to client lib/ folder for auto-discovery
    if (-not (Test-Path $clientLibDir)) {
        New-Item -ItemType Directory -Path $clientLibDir -Force | Out-Null
    }

    $sourceDll = if (Test-Path $oqsDll) { $oqsDll } else { $oqsDllAlt }
    Copy-Item $sourceDll $clientLibDll -Force
    Write-Ok "oqs.dll copied to $clientLibDll"
}

# ==============================================================================
# STEP 8: Create client directory and verify everything
# ==============================================================================

Write-Step 8 $totalSteps "Final verification..."

# Create client directory
if (-not (Test-Path $clientDir)) {
    New-Item -ItemType Directory -Path $clientDir -Force | Out-Null
}
Write-Ok "Client directory: $clientDir"

# Verify Python packages
$allGood = $true

python -c "import requests" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Ok "Python: requests" }
else { Write-Fail "Python: requests"; $allGood = $false }

python -c "import cryptography" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Ok "Python: cryptography" }
else { Write-Fail "Python: cryptography"; $allGood = $false }

# Verify WireGuard
if (Test-Path $wgExe) { Write-Ok "WireGuard: installed" }
else { Write-Fail "WireGuard: not found"; $allGood = $false }

# Verify liboqs with a full ML-KEM-1024 self-test
Write-Host ""
Write-Host "  Running ML-KEM-1024 self-test..." -ForegroundColor Cyan

$selfTest = @"
import os, sys
from pathlib import Path
dll_dirs = [
    str(Path.home() / 'liboqs' / 'build' / 'bin' / 'Release'),
    str(Path.home() / 'liboqs' / 'build' / 'bin'),
    str(Path(r'$clientLibDir')),
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
    assert ss_enc == ss_dec, 'DECAP MISMATCH'
    print('  PASSED: ML-KEM-1024 encap/decap OK')
    print('    Public key:   %d bytes' % len(pub))
    print('    Ciphertext:   %d bytes' % len(ct))
    print('    Shared secret: ' + ss_enc.hex()[:32] + '...')
    sys.exit(0)
except Exception as e:
    print('  FAILED: ' + str(e))
    sys.exit(1)
"@

python -c $selfTest
$oqsWorking = ($LASTEXITCODE -eq 0)

if ($oqsWorking) {
    Write-Ok "liboqs: ML-KEM-1024 self-test passed"
    Write-Ok "Client-side encapsulation: ENABLED"
    Write-Ok "Direct peer KEM exchange:  ENABLED"
}
else {
    Write-Note "liboqs: not working"
    Write-Note "Client will fall back to server-side encapsulation (still quantum-resistant)"
    Write-Note "Direct peer KEM exchange will be disabled on this machine"
}

# ==============================================================================
# Summary
# ==============================================================================

Write-Host ""

if ($allGood) {
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "  SETUP COMPLETE -- Ready to connect!" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
}
else {
    Write-Host "===========================================================" -ForegroundColor Yellow
    Write-Host "  SETUP PARTIALLY COMPLETE -- Fix the issues above" -ForegroundColor Yellow
    Write-Host "===========================================================" -ForegroundColor Yellow
}

Write-Host ""

if ($oqsWorking) {
    Write-Host "  Security features on this machine:" -ForegroundColor White
    Write-Host "    Client-side ML-KEM-1024 encapsulation  [ENABLED]" -ForegroundColor Green
    Write-Host "    Direct peer KEM exchange (zero-trust)  [ENABLED]" -ForegroundColor Green
    Write-Host "    TLS certificate pinning                [ENABLED]" -ForegroundColor Green
}
else {
    Write-Host "  Security features on this machine:" -ForegroundColor White
    Write-Host "    Client-side ML-KEM-1024 encapsulation  [FALLBACK -- server-side]" -ForegroundColor Yellow
    Write-Host "    Direct peer KEM exchange (zero-trust)  [DISABLED -- no liboqs]" -ForegroundColor Yellow
    Write-Host "    TLS certificate pinning                [ENABLED]" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Run the client (as Administrator):" -ForegroundColor White
Write-Host ""
Write-Host "    python client.py service ``" -ForegroundColor Cyan
Write-Host "      --lighthouse-public https://YOUR_PUBLIC_IP:9443 ``" -ForegroundColor Cyan
Write-Host "      --lighthouse-local https://YOUR_LIGHTHOUSE_IP:8443" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Get the cert fingerprint from your Lighthouse:" -ForegroundColor White
Write-Host "    python lighthouse.py show-fingerprint" -ForegroundColor Cyan
Write-Host ""

if (-not $oqsWorking) {
    Write-Host "  To fix liboqs later:" -ForegroundColor White
    Write-Host "    1. Restart your terminal" -ForegroundColor Yellow
    Write-Host "    2. Run: .\setup_client_windows.ps1 -Clean" -ForegroundColor Yellow
    Write-Host "    3. Or just: .\setup_client_windows.ps1 -TestOnly" -ForegroundColor Yellow
    Write-Host ""
}