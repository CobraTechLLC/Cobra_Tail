\# 🐍 Cobra Tail (formerly The Quantum Scale Project)

\[cite\_start]\*\*Version:\*\* 0.9.5 \[cite: 1]  

\[cite\_start]\*\*Owner:\*\* Cobra Tech LLC \[cite: 2]



\## 🌐 Overview

\[cite\_start]Cobra Tail is a high-performance, self-hosted \*\*Post-Quantum Mesh VPN\*\*\[cite: 1]. \[cite\_start]It provides secure, peer-to-peer connectivity across complex network topologies, utilizing a "privacy-first" and "zero-trust" philosophy\[cite: 1]. \[cite\_start]Unlike traditional VPNs, Cobra Tail protects against both current and future quantum computing threats by layering \*\*ML-KEM-1024 (Kyber)\*\* encryption over standard WireGuard tunnels\[cite: 1].



\## 🛠 Hardware Architecture

The system operates across three specialized hardware tiers to ensure total cryptographic isolation:



\* \[cite\_start]\*\*The Tongue (ESP32-S3):\*\* Provides hardware-validated entropy using a physical True Random Number Generator (TRNG)\[cite: 1].

\* \[cite\_start]\*\*The Vault (Raspberry Pi Zero 2 W):\*\* Manages all private keys in a secure, non-networked cryptographic path\[cite: 1].

\* \[cite\_start]\*\*The Lighthouse (Raspberry Pi 4):\*\* Functions as the central coordination server for peer discovery and NAT pairing\[cite: 1].



\## 🔒 Security \& Cryptography

\* \[cite\_start]\*\*Post-Quantum Resistance:\*\* Every tunnel is secured with \*\*ML-KEM-1024\*\* for key exchanges\[cite: 1].

\* \[cite\_start]\*\*Zero-Trust Upgrades:\*\* Peers perform direct, hardware-backed exchanges to upgrade to private shared secrets that the Lighthouse never sees\[cite: 1].

\* \[cite\_start]\*\*Automated Rotation:\*\* All quantum keys and mesh tunnel Pre-Shared Keys (PSKs) are rotated every \*\*24 hours\*\* to maintain forward secrecy\[cite: 1].



\## 📡 Networking Stack

Cobra Tail features an advanced NAT traversal engine designed for near 100% connectivity:

\* \[cite\_start]\*\*Direct Path:\*\* Prioritizes IPv6 and local LAN discovery\[cite: 1].

\* \[cite\_start]\*\*Hole Punching:\*\* Utilizes STUN for UDP hole punching through restrictive firewalls\[cite: 1].

\* \[cite\_start]\*\*Fallback:\*\* Includes a guaranteed VPN-routed relay if peer-to-peer connection is impossible\[cite: 1].

\* \[cite\_start]\*\*Self-Healing:\*\* A continuous path monitor detects network changes and updates endpoints live without dropping connections\[cite: 1].



\## 🚀 Deployment

1\.  \[cite\_start]\*\*Configure:\*\* Edit `config.yaml` with your specific network parameters\[cite: 1].

2\.  \[cite\_start]\*\*Initialize Hardware:\*\* Ensure the "Tongue" is connected via UART to provide entropy\[cite: 1].

3\.  \[cite\_start]\*\*Launch Lighthouse:\*\* Run the coordination server on the Pi 4 to begin brokering peer connections\[cite: 1].



\---

\*\*Confidentiality Notice:\*\* This project is proprietary to Cobra Tech LLC. \[cite\_start]Unauthorized distribution is prohibited\[cite: 2].

