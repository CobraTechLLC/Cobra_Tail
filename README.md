# 🐍 Cobra Tail — Post-Quantum Mesh VPN

**Version:** 1.0.0
**Developed by:** Cobra Tech LLC
**License:** See [LICENSE](LICENSE)

Cobra Tail is a self-hosted post-quantum mesh VPN built from scratch on custom hardware. It works like Tailscale — any device can securely connect to any other device across the internet — but with every key exchange protected against both current and future quantum computer attacks. The coordination server never sees your shared secrets, peers negotiate their own keys directly, and the entire crypto path is rooted in a physical hardware random number generator.

If you're tired of trusting someone else's cloud to broker your VPN, and you want a VPN that will still be secure after a cryptographically-relevant quantum computer exists, this is for you.

---

## 🛡️ Key Features

- **Post-quantum secure by default** — Every tunnel, both client-to-server and peer-to-peer, uses NIST-standardized ML-KEM-1024 (FIPS 203) layered on top of WireGuard. Your traffic is protected against "harvest now, decrypt later" attacks.
- **Hardware-backed entropy** — An ESP32-S3 with a physical True Random Number Generator feeds raw entropy into the key generation path. No software PRNGs, no `/dev/urandom` for the crypto seed material.
- **Zero-trust mesh** — Peers perform direct ML-KEM key exchanges with each other. The coordination server relays ciphertext but never learns the shared secret, and mesh tunnel rekeys happen purely peer-to-peer with no server involvement at all.
- **Automatic key rotation** — Client PSKs rotate every 4 hours via HKDF-SHA256 with per-peer binding. Mesh tunnel PSKs rotate every 24 hours directly between peers.
- **Full NAT traversal stack** — Multi-candidate STUN hole punching, NAT type classification, UPnP/NAT-PMP, native IPv6 direct connectivity, continuous path monitoring with self-healing, and guaranteed VPN-routed relay fallback.
- **Deterministic IPv6 identity** — The Cobra-Dicyanin layer gives every node a predictable globally-routable IPv6 address, allowing the Lighthouse to mathematically construct peer addresses and enable direct dialing without any NAT traversal at all.
- **Full-stack identity spoofing** — MAC address, hostname, IPv6 SLAAC token, DHCP fingerprint, and OS TTL can all be spoofed to impersonate an Apple/macOS machine at every layer of the stack.
- **Cross-platform clients** — Native support for Linux (amd64/arm64 .deb packages) and Windows (.exe installer). Android client planned.

---

## 🔐 How the Crypto Works

Cobra Tail does **not** invent any new cryptography. It composes well-understood, audited primitives in a layered defense-in-depth model. If you're going to trust a VPN with your traffic, you should understand exactly what's protecting it:

**Transport layer — WireGuard.** The actual tunnel is a standard WireGuard interface. WireGuard is the audited, battle-tested VPN protocol shipped in the Linux kernel since 5.6, using Curve25519, ChaCha20-Poly1305, and BLAKE2s. If Cobra Tail's post-quantum layer were somehow bypassed, you'd fall back to WireGuard's native security, which is already excellent against non-quantum adversaries.

**Post-quantum layer — ML-KEM-1024 (Kyber).** Layered on top of WireGuard as the PSK source. ML-KEM is the [NIST-standardized Module-Lattice Key Encapsulation Mechanism (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final), selected in August 2024 after nearly a decade of public cryptanalysis. We use the 1024-bit parameter set, which targets NIST Security Category 5 (equivalent to AES-256). The implementation comes from [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe project's reference C library, built from source during install.

**Key derivation — HKDF-SHA256 with domain separation.** The raw shared secret from ML-KEM is not used directly as a WireGuard PSK. Instead, it's passed through HKDF-SHA256 with context binding: the peer's public key, a unique rotation ID, and a caller-supplied info string are all mixed in. This gives us cryptographic domain separation between rotations, transcript binding to prevent replay, and proper key derivation hygiene per [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).

**Entropy — hardware TRNG.** The ML-KEM keypair on the Vault is generated from entropy streamed over USB serial from an ESP32-S3's physical TRNG, not from a software PRNG. Each 32-byte entropy chunk is framed with a sync byte and length header to detect corruption. The same hardware entropy source is used to seed TLS certificate generation on the Lighthouse.

**Coordination channel — TLS with certificate pinning.** Clients talk to the Lighthouse over HTTPS with pinned certificate fingerprints baked into the enrollment record. A rogue CA cannot MITM the coordination channel because clients refuse to connect to any fingerprint they didn't enroll with.

**Client-side encapsulation.** This is the "zero-trust" part. When a client wants to establish a tunnel, the Lighthouse forwards it the Vault's public key. The client performs ML-KEM encapsulation **on its own machine**, generates the shared secret locally, and sends the ciphertext back to the Lighthouse, which relays it to the Vault for decapsulation. The Lighthouse never learns the shared secret — it only sees ciphertext in transit. A compromised Lighthouse cannot decrypt tunnel traffic because it never had the key material in the first place.

### Trust but verify

All the code is in this repo. All the build scripts are in this repo. You can (and should) build your own `.deb` and `.exe` from source rather than trusting the pre-built binaries in the Releases page:

```bash
# Build the Lighthouse .deb yourself
git clone https://github.com/CobraTechLLC/Cobra_Tail.git
cd Cobra_Tail
sudo ./build_lighthouse_deb.sh 1.0.0 arm64

# Build the client .deb yourself
sudo ./build_client_deb.sh 1.0.0 arm64   # or amd64
```

The pre-built binaries in GitHub Releases are provided as a convenience. If you have any reason to distrust them, build from source. `SHA256SUMS` files are published alongside each release so you can verify the binaries you download match what the build scripts would produce.

---

## 🎯 Threat Model

Being honest about what a VPN can and cannot protect against matters — especially one that calls itself "quantum-resistant." Here's the breakdown:

### ✅ What Cobra Tail protects against

- **Harvest-now-decrypt-later attacks.** An adversary recording your encrypted traffic today, planning to decrypt it in 10–15 years when quantum computers mature, gets nothing. The ML-KEM layer means even a quantum adversary cannot recover past session keys.
- **Compromised coordination server.** Because the Lighthouse never sees shared secrets, a full compromise of the Lighthouse does not expose past or future tunnel traffic. The worst an attacker can do is deny service or add rogue peers, not decrypt existing traffic.
- **Man-in-the-middle on the coordination channel.** TLS with pinned certificate fingerprints means a rogue CA or a compromised upstream network cannot insert themselves into the enrollment or PSK rotation flow.
- **Passive network observation.** Standard WireGuard properties apply: tunnel contents are encrypted and authenticated with ChaCha20-Poly1305.
- **Peer impersonation via identity leaks.** The full-stack identity spoofing layer means your MAC address, hostname, and DHCP fingerprint don't reveal your actual device to observers on the local network.

### ❌ What Cobra Tail does NOT protect against

- **A compromised endpoint.** If malware is running as root on your client or Lighthouse, it can read your tunnel traffic directly — no VPN protects against this. Use endpoint security hygiene.
- **A malicious Vault operator.** The Vault holds the ML-KEM private key. If you don't physically control your Vault hardware, you don't control your keys. This is not a hosted service — you run the whole stack yourself.
- **Traffic analysis.** Even with encrypted content, an adversary watching the network can see packet sizes and timing. Cobra Tail does not implement padding or cover traffic. If you need protection against traffic analysis, use Tor or a mixnet.
- **Legal compulsion of the Lighthouse operator.** If you run a Lighthouse and someone shows up with a court order demanding you add their node to the mesh, you are the weak link, not the cryptography.
- **Physical attacks on hardware.** No side-channel resistance, no tamper-evident enclosures, no HSM. The Vault's on-disk private key is encrypted with a device-bound AES-GCM key, but a sufficiently motivated attacker with physical access to your Pi Zero can extract it.
- **Vulnerabilities in liboqs or WireGuard.** Cobra Tail depends on upstream crypto libraries. If a CVE is found in either, Cobra Tail is affected. Keep your installs updated.

---

## 🏗️ Hardware Architecture

The full Cobra Tail stack consists of three dedicated devices working together. This is the **Lighthouse operator** side — if you're just a client connecting to an existing mesh, skip ahead to the [Client Installation](#-client-installation) section.

**The Tongue — ESP32-S3.** A microcontroller with a hardware true random number generator. Streams raw entropy over USB serial in framed 32-byte chunks to the Vault, and provides hardware entropy on demand for TLS certificate generation on the Lighthouse. Runs `main.py`.

**The Vault — Raspberry Pi Zero 2 W.** Receives entropy from the ESP32 over USB, generates ML-KEM-1024 keypairs, encrypts the private key with AES-GCM bound to its hardware ID, and stores it on disk. Communicates with the Lighthouse over a direct GPIO UART wire — no network involved in the crypto path. Runs `cript_keeper.py` as a systemd service.

**The Lighthouse — Raspberry Pi 4 or Pi 5.** The coordination server. Runs a FastAPI HTTPS API with TLS certificate pinning, manages WireGuard tunnel configuration, brokers peer-to-peer mesh tunnels, handles NAT traversal, and rotates keys on a schedule. Connected to the Vault by a direct UART wire and to the Tongue by USB. Runs `lighthouse.py` as a systemd service.

### Supported Raspberry Pi models for the Lighthouse

| Board | Supported? | Notes |
|---|---|---|
| Raspberry Pi 5 (any RAM) | ✅ Recommended | Fastest option. May need minor UART path config. |
| Raspberry Pi 4 (2 GB+) | ✅ Recommended | Current reference platform, fully tested. |
| Raspberry Pi 4 (1 GB) | ⚠️ Marginal | Will run but tight on RAM once clients connect. |
| Raspberry Pi 3 | ⚠️ Not recommended | Only 1 GB RAM, slower CPU. Works but will swap. |
| Raspberry Pi 2 | ❌ Not supported | 32-bit armhf, package incompatible. |
| Raspberry Pi Zero / Zero W (original) | ❌ Not supported | armv6, too slow for liboqs. |

The Vault **must** be a Raspberry Pi Zero 2 W specifically (arm64, dual-core, 512 MB is sufficient for its lightweight crypto-only role). The Tongue **must** be an ESP32-S3 with TRNG support — other ESP32 variants may work but are untested.

---

## 🚀 Quick Start

### Client installation

If you just want to connect to an existing Cobra Tail mesh as a client, you don't need any special hardware. Grab the right package for your OS from the [Releases page](https://github.com/CobraTechLLC/Cobra_Tail/releases) and install it.

**Linux (Debian/Ubuntu — amd64):**
```bash
wget https://github.com/CobraTechLLC/Cobra_Tail/releases/latest/download/cobra-client_1.0.0_amd64.deb
sudo apt install ./cobra-client_1.0.0_amd64.deb
sudo cobra
```

**Linux (Debian/Ubuntu — arm64 / Raspberry Pi):**
```bash
wget https://github.com/CobraTechLLC/Cobra_Tail/releases/latest/download/cobra-client_1.0.0_arm64.deb
sudo apt install ./cobra-client_1.0.0_arm64.deb
sudo cobra
```

**Windows:**
Download `CobraTailSetup.exe` from the [Releases page](https://github.com/CobraTechLLC/Cobra_Tail/releases), run it, and accept the UAC prompt. The installer handles WireGuard, oqs.dll, and everything else automatically.

After install, running `cobra` (Linux) or launching from the Start Menu (Windows) starts the enrollment wizard. You'll need:

- Your Lighthouse URL (e.g. `https://lighthouse.example.com:8443`)
- The Lighthouse's TLS certificate fingerprint (ask whoever runs the Lighthouse)
- A unique node name for your device

### Lighthouse installation (operators only)

If you're standing up your own mesh, you need the full hardware stack described above. On your Pi 4 or Pi 5:

```bash
git clone https://github.com/CobraTechLLC/Cobra_Tail.git
cd Cobra_Tail
chmod +x build_lighthouse_deb.sh
sudo ./build_lighthouse_deb.sh 1.0.0 arm64
sudo apt install ./cobra-lighthouse_1.0.0_arm64.deb
sudo lighthouse
```

The `sudo lighthouse` command launches the interactive setup wizard on first run, then drops into the management menu on subsequent runs. From there you can start/stop the service, add nodes, view logs, manage certificates, and check for updates from GitHub.

### Vault and Tongue installation

See [`setup.sh`](setup.sh) for the Pi Zero 2 W Vault bootstrap and [`main.py`](main.py) for the ESP32-S3 Tongue firmware. A dedicated Vault `.deb` package is planned but not yet required — the shell-based setup on Pi Zero 2 W works fine for now.

---

## 📁 Repository Layout

| File | Purpose |
|---|---|
| `lighthouse.py` | The Lighthouse FastAPI coordination server |
| `lighthouse_launcher.py` | Setup wizard + management menu for the Lighthouse |
| `build_lighthouse_deb.sh` | Builds `cobra-lighthouse_*.deb` |
| `client.py` | Persistent background client service |
| `cobra_launcher.py` | Cross-platform client launcher + menu |
| `identity_manager.py` | Full-stack network identity spoofing |
| `build_client_deb.sh` | Builds `cobra-client_*.deb` |
| `installer.py` | Windows installer entry point |
| `build_windows_exe.py` | PyInstaller build script for `CobraTailSetup.exe` |
| `cript_keeper.py` | Runs on the Pi Zero Vault — ML-KEM key management |
| `main.py` | Runs on the ESP32 Tongue — entropy streaming |
| `config.yaml` | Lighthouse configuration template |
| `systemd_setup/` | systemd service unit files |

---

## 🗺️ Roadmap

**v1.0.0 — Current release**
- ✅ Full post-quantum tunnel stack with ML-KEM-1024
- ✅ HKDF-SHA256 PSK derivation with domain separation
- ✅ Zero-trust mesh networking with peer-to-peer KEM exchange
- ✅ Full NAT traversal (STUN, UPnP, IPv6, self-healing)
- ✅ Deterministic IPv6 identity (Cobra)
- ✅ Lighthouse .deb (arm64)
- ✅ Client .deb (arm64 + amd64)
- ✅ Windows .exe installer

**Planned**
- 🔲 Full-tunnel exit node support
- 🔲 GUI client (currently CLI/TUI only)
- 🔲 Android client
- 🔲 Vault .deb package for Pi Zero 2 W
- 🔲 TURN-style relay for the most restrictive NATs
- 🔲 Signed Windows binaries via SignPath Foundation

---

## 🤝 Contributing

Cobra Tail is developed by Cobra Tech LLC. Issues, discussions, and pull requests are welcome. For security-sensitive issues, please do not open a public issue — contact the maintainers directly at the email in the LICENSE file.

If you find a bug in the cryptographic path specifically (HKDF binding, KEM encapsulation flow, PSK derivation, TLS pinning), please flag it as high priority. Crypto bugs are the kind of thing this project absolutely cannot ship with.

---

## 📜 License

See [LICENSE](LICENSE) for the full license text.

The cryptographic primitives Cobra Tail depends on are licensed separately:
- [liboqs](https://github.com/open-quantum-safe/liboqs) — MIT
- [WireGuard](https://www.wireguard.com/) — GPLv2 (kernel module), various (userspace tools)
- [cryptography](https://github.com/pyca/cryptography) — Apache 2.0 / BSD-3-Clause

---

*Built on custom hardware. Secured against tomorrow's computers.*