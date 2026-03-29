	🐍 Cobra Tail: Post-Quantum Mesh VPNVersion: 0.9.5  | Developed by: Cobra Tech LLC 

Cobra Tail is a high-performance, self-hosted Post-Quantum Mesh VPN. It provides secure, peer-to-peer connectivity across complex network topologies, utilizing a "privacy-first" and "zero-trust" philosophy. Unlike traditional VPNs, Cobra Tail protects against both current and future quantum computing threats by layering ML-KEM-1024 (Kyber) encryption over standard WireGuard tunnels.

	🛡️ Key Advantages

Post-Quantum Security: Every tunnel—client-to-server and peer-to-peer—is secured with NIST-standardized ML-KEM-1024 for all key exchanges.

Hardware-Backed Trust: The system uses a dedicated ESP32-S3 Physical TRNG to feed high-quality entropy to the cryptographic vault.

True Zero-Trust Mesh: Peers perform direct, hardware-backed KEM exchanges that bypass the coordination server entirely.

Deterministic IPv6 Identity: Through the Cobra-Dicyanin layer, the system provides predictable, globally routable IPv6 addresses while masking device identity.

	🏗️ Hardware Architecture

The system operates across three specialized hardware tiers to ensure total cryptographic isolation:

The Tongue (ESP32-S3): Provides hardware-validated entropy using a physical True Random Number Generator (TRNG).

The Vault (Raspberry Pi Zero 2 W): Manages all private keys in a secure, non-networked cryptographic path.

The Lighthouse (Raspberry Pi 4): Functions as the central coordination server for peer discovery and NAT pairing.

	🌐 Networking & Identity (Cobra Tech)

Cobra Tail features an advanced networking stack designed for stealth and near 100% connectivity:

Identity Spoofing: The device impersonates an Apple/macOS machine at the Physical (MAC), Network (Hostname), Application (DHCP), and Kernel (TTL) layers.

Deterministic IPv6: The Lighthouse can mathematically construct a peer's IPv6 address from its known token, enabling direct dialing before a peer even checks in.

NAT Traversal: Multi-candidate STUN hole punching with NAT type classification for Full Cone, Symmetric Predictable, and Symmetric Random NATs.

Self-Healing: A continuous path monitor detects network changes and updates endpoints live without dropping active connections.

	🚀 Deployment

1.Configure: Edit config.yaml to set your network parameters and identity spoofing preferences.

2.Initialize Hardware: Ensure the Tongue is connected via UART to provide physical entropy.

3.Launch Lighthouse: Run the coordination server on the Pi 4 to begin brokering secure, quantum-resistant connections.