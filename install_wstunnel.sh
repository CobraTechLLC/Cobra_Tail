#!/bin/bash
# ─────────────────────────────────────────────────────────────
# install_wstunnel.sh — install/repair the wstunnel TCP fallback
# ─────────────────────────────────────────────────────────────
# Shipped by cobra-client at /opt/cobratail/bin/install_wstunnel.sh
# and called from postinst. Safe to re-run by hand any time:
#
#   sudo /opt/cobratail/bin/install_wstunnel.sh          # install if missing
#   sudo /opt/cobratail/bin/install_wstunnel.sh --force  # reinstall
#
# Destination defaults to /opt/cobratail/bin/wstunnel; override with
# WSTUNNEL_DEST=/path/to/wstunnel.
#
# Never exits non-zero on a download/extract problem, so it can't
# break the surrounding dpkg postinst (which runs under `set -e`).
# Full detail goes to /opt/cobratail/logs/wstunnel-install.log.
# ─────────────────────────────────────────────────────────────

DEST="${WSTUNNEL_DEST:-/opt/cobratail/bin/wstunnel}"
LOG="${WSTUNNEL_LOG:-/opt/cobratail/logs/wstunnel-install.log}"
FORCE=false
[ "$1" = "--force" ] && FORCE=true

# Pinned fallback used when the GitHub API is unreachable or rate-limited
# (unauthenticated API = 60 req/hour per IP, shared by everything on the LAN).
PINNED_VERSION="11.1.0"

mkdir -p "$(dirname "$LOG")" "$(dirname "$DEST")" 2>/dev/null || true
echo "=== $(date -Is) install_wstunnel.sh ===" >> "$LOG" 2>/dev/null || LOG=/dev/null

say() { echo "  $*"; echo "$*" >> "$LOG"; }

# An existing binary only counts if it actually runs on this CPU.
# (A wrong-arch binary "exists", so the launcher used to report it as
# installed while the client got "Exec format error" at fallback time.)
works() { [ -x "$1" ] && "$1" --version >/dev/null 2>&1; }

if [ "$FORCE" = false ] && works "$DEST"; then
    say "wstunnel already installed: $("$DEST" --version 2>&1 | head -1)"
    exit 0
fi
if [ "$FORCE" = false ] && works /usr/local/bin/wstunnel; then
    ln -sf /usr/local/bin/wstunnel "$DEST"
    say "Using existing /usr/local/bin/wstunnel (symlinked to $DEST)"
    exit 0
fi

# ── Map the CPU to wstunnel's release naming ─────────────────
# wstunnel publishes linux_386, linux_amd64, linux_arm64 and linux_armv6.
# There is no armv7 build: the old mapping armv7l → "armv7" matched nothing,
# so every 32-bit Raspberry Pi OS install silently skipped wstunnel.
# The armv6 build runs fine on armv7 CPUs (Pi 2/3/Zero 2 W on 32-bit OS).
# The binaries are static, so the kernel arch (uname -m) is what matters.
MACHINE="$(uname -m)"
case "$MACHINE" in
    x86_64|amd64)          WS_ARCH="amd64" ;;
    aarch64|arm64)         WS_ARCH="arm64" ;;
    armv7l|armv7*|armv6l|armhf) WS_ARCH="armv6" ;;
    i386|i686)             WS_ARCH="386" ;;
    *)
        say "WARNING: unsupported architecture ($MACHINE) — skipping wstunnel"
        say "Download manually from https://github.com/erebe/wstunnel/releases and place at $DEST"
        exit 0 ;;
esac
say "Architecture: $MACHINE → wstunnel linux_${WS_ARCH}"

# ── Download + extract in Python (no wget/curl dependency) ───
# Neither wget nor curl is in the package's Depends, and the old script
# discarded their errors with 2>/dev/null, so a missing tool looked
# exactly like "download failed" with no clue why.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 - "$WS_ARCH" "$PINNED_VERSION" "$TMP" >> "$LOG" 2>&1 <<'PY'
import json, os, sys, tarfile, urllib.request

arch, pinned, tmp = sys.argv[1], sys.argv[2], sys.argv[3]
suffix = f"_linux_{arch}.tar.gz"
hdrs = {"User-Agent": "CobraTail-Installer", "Accept": "application/vnd.github+json"}

url = ""
try:
    req = urllib.request.Request(
        "https://api.github.com/repos/erebe/wstunnel/releases/latest", headers=hdrs)
    data = json.loads(urllib.request.urlopen(req, timeout=20).read())
    for a in data.get("assets", []):
        if a["name"].lower().endswith(suffix):
            url = a["browser_download_url"]
            break
    print(f"GitHub API latest={data.get('tag_name')} match={url or 'none'}")
except Exception as e:
    print(f"GitHub API lookup failed: {e}")

if not url:
    url = (f"https://github.com/erebe/wstunnel/releases/download/"
           f"v{pinned}/wstunnel_{pinned}{suffix}")
    print(f"Falling back to pinned release: {url}")

archive = os.path.join(tmp, "wstunnel.tar.gz")
try:
    req = urllib.request.Request(url, headers={"User-Agent": "CobraTail-Installer"})
    with urllib.request.urlopen(req, timeout=60) as r, open(archive, "wb") as f:
        f.write(r.read())
except Exception as e:
    print(f"Download failed: {e}")
    sys.exit(2)

try:
    with tarfile.open(archive, "r:gz") as tf:
        member = next((m for m in tf.getmembers()
                       if m.isfile() and os.path.basename(m.name) == "wstunnel"), None)
        if member is None:
            print("No 'wstunnel' binary inside archive: "
                  + ", ".join(m.name for m in tf.getmembers()))
            sys.exit(3)
        src = tf.extractfile(member)
        with open(os.path.join(tmp, "wstunnel"), "wb") as out:
            out.write(src.read())
except Exception as e:
    print(f"Extract failed: {e}")
    sys.exit(3)
print("Downloaded and extracted OK")
PY
RC=$?

if [ $RC -ne 0 ] || [ ! -f "$TMP/wstunnel" ]; then
    say "WARNING: wstunnel download/extract failed (code $RC) — see $LOG"
    say "TCP fallback stays unavailable. Retry: sudo $0 --force"
    exit 0
fi

chmod 755 "$TMP/wstunnel"
if ! "$TMP/wstunnel" --version >/dev/null 2>&1; then
    say "WARNING: downloaded wstunnel won't run on this CPU ($MACHINE) — not installing it"
    "$TMP/wstunnel" --version >> "$LOG" 2>&1
    exit 0
fi

# Atomic replace (works even if an old copy is currently running)
install -m 755 "$TMP/wstunnel" "${DEST}.new" && mv -f "${DEST}.new" "$DEST"
say "wstunnel installed: $DEST ($("$DEST" --version 2>&1 | head -1))"
exit 0
