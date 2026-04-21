# Cobra Tail — Troubleshooting Reference

This document is consumed by the Cobra Sentinel AI diagnostic agent. Each section
maps to a category of network error that appears in the Cobra Tail VPN logs. For
every problem, the **Symptoms** describe what the Sentinel will see, the **Diagnostics**
list commands to confirm the root cause, and the **Fix** lists the corrective commands
in execution order.

WireGuard interface names used by Cobra Tail:
- `wg_quantum` — coordination tunnel to the Lighthouse (10.100.0.0/24)
- `wg_mesh` — peer-to-peer data plane (10.200.0.0/24)

Service names:
- `cobratail.service` — main VPN client
- `lighthouse.service` — Lighthouse coordination server
- `cobra-sentinel.service` — AI diagnostic agent
- `cobra-identity.service` — identity spoofing (runs before client)
- `cobra-vault.service` — ML-KEM key management (Vault Pi only)

---

## 1. WireGuard Tunnel Down

**Symptoms:**
- `ERROR tunnel down` or `ERROR tunnel failed`
- `ERROR WireGuard handshake timeout`
- No response from `10.100.0.x` addresses
- `wg show` reports no recent handshake

**Diagnostics:**
```bash
ip link show wg_quantum
sudo wg show wg_quantum
ip addr show wg_quantum
```

**Fix:**
```bash
sudo wg-quick down wg_quantum && sudo wg-quick up wg_quantum
```

If the interface does not exist at all:
```bash
sudo wg-quick up wg_quantum
```

If the config file is missing or corrupt, verify it exists:
```bash
cat /etc/wireguard/wg_quantum.conf
```

---

## 2. Lighthouse Unreachable

**Symptoms:**
- `ERROR lighthouse unreachable`
- `ERROR lighthouse connection failed`
- `ERROR connection refused` on port 8443
- `ERROR heartbeat failed` or `ERROR heartbeat timeout`
- Consecutive heartbeat failures in logs

**Diagnostics:**
```bash
ping -c 3 10.100.0.1
ss -tlnp | grep 8443
sudo wg show wg_quantum
journalctl -u cobratail --no-pager -n 30
```

**Fix — client side (Lighthouse is remote):**
```bash
sudo wg-quick down wg_quantum && sudo wg-quick up wg_quantum
sudo systemctl restart cobratail
```

**Fix — Lighthouse side (if you are the Lighthouse operator):**
```bash
sudo systemctl restart lighthouse
sudo wg-quick down wg_quantum && sudo wg-quick up wg_quantum
journalctl -u lighthouse --no-pager -n 50
```

If the underlying internet connection is down, check the default route and upstream:
```bash
ip route show default
ping -c 3 1.1.1.1
```

---

## 3. DNS Resolution Failure

**Symptoms:**
- `ERROR DNS resolution failed`
- `ERROR DNS lookup failed`
- Cannot resolve Lighthouse hostname
- `dig` or `nslookup` returns SERVFAIL or timeout

**Diagnostics:**
```bash
cat /etc/resolv.conf
dig google.com +short
dig @8.8.8.8 google.com +short
resolvectl status
```

**Fix:**
```bash
sudo resolvectl flush-caches 2>/dev/null || sudo systemd-resolve --flush-caches 2>/dev/null
```

If `/etc/resolv.conf` is empty or pointing at a dead nameserver:
```bash
sudo systemctl restart systemd-resolved
```

If DNS works for external domains but not for the Lighthouse hostname, the issue
is likely that the Lighthouse is referenced by IP in the enrollment, not by name.
Check the enrollment config:
```bash
cat /opt/cobratail/config/enrollment.json
```

---

## 4. Mesh Peer Connection Failed

**Symptoms:**
- `ERROR mesh failed` or `ERROR mesh timeout`
- `ERROR mesh rejected`
- `ERROR endpoint unreachable`
- `ERROR endpoint failed`
- Cannot ping `10.200.0.x` addresses between peers

**Diagnostics:**
```bash
ip link show wg_mesh
sudo wg show wg_mesh
ss -ulnp | grep 51821
```

**Fix:**
```bash
sudo wg-quick down wg_mesh && sudo wg-quick up wg_mesh
```

If the mesh interface is up but peers show no recent handshake, the NAT traversal
may have failed. Restart the client to re-trigger hole punching:
```bash
sudo systemctl restart cobratail
```

If a specific peer is unreachable but others work, the problem is likely on the
remote peer's side or a NAT issue between you and that peer specifically.

---

## 5. PSK Rotation Failure

**Symptoms:**
- `ERROR PSK rotation failed`
- `ERROR PSK expired`
- Handshake succeeds initially then fails after 4 hours
- Tunnel works then suddenly drops

**Diagnostics:**
```bash
sudo wg show wg_quantum latest-handshakes
journalctl -u cobratail --no-pager -n 50 | grep -i psk
timedatectl status
```

**Fix:**
```bash
sudo systemctl restart cobratail
```

If time is out of sync (PSK rotation is time-bound via HKDF):
```bash
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd
```

On the Lighthouse side, check that the Vault is responding:
```bash
sudo journalctl -u cobra-vault --no-pager -n 20
```

---

## 6. Connection Refused / Reset / Lost

**Symptoms:**
- `ERROR connection refused`
- `ERROR connection reset`
- `ERROR connection timed out`
- `ERROR connection lost`
- `ERROR connection failed`

**Diagnostics:**
```bash
sudo wg show
ip route show default
ping -c 3 1.1.1.1
ss -tlnp | grep -E '8443|51820|51821'
```

**Fix — if WireGuard is up but connections fail:**
```bash
sudo systemctl restart cobratail
```

**Fix — if WireGuard interfaces are missing:**
```bash
sudo wg-quick up wg_quantum
sudo wg-quick up wg_mesh
```

**Fix — if firewall is blocking traffic:**
```bash
sudo iptables -L -n | grep -E '8443|51820|51821'
sudo ufw status
```

---

## 7. Service Won't Start

**Symptoms:**
- `systemctl status cobratail` shows `failed` or `inactive`
- Python traceback in journalctl output
- `CRITICAL network` errors on startup

**Diagnostics:**
```bash
sudo systemctl status cobratail
sudo journalctl -u cobratail --no-pager -n 50
ls -la /opt/cobratail/config/enrollment.json
ls -la /etc/wireguard/
python3 -c "import oqs; print('liboqs OK')"
```

**Fix — if enrollment.json is missing (not yet enrolled):**
Run the enrollment wizard:
```bash
sudo cobra --enroll
```

**Fix — if liboqs import fails:**
```bash
pip3 install --break-system-packages liboqs-python
sudo ldconfig
```

**Fix — if permissions are wrong on WireGuard configs:**
```bash
sudo chmod 600 /etc/wireguard/wg_quantum.conf
sudo chmod 600 /etc/wireguard/wg_mesh.conf
```

---

## 8. High Latency or Packet Loss

**Symptoms:**
- Slow transfers between mesh peers
- Intermittent timeouts
- `ping 10.200.0.x` shows >200ms or packet loss

**Diagnostics:**
```bash
sudo wg show wg_mesh endpoints
ping -c 10 10.200.0.1
ping -c 5 -M do -s 1400 10.100.0.1
```

**Fix — if MTU is the issue (packets >1400 bytes fail):**
Edit `/etc/wireguard/wg_quantum.conf` and `/etc/wireguard/wg_mesh.conf`, set:
```
MTU = 1280
```
Then restart:
```bash
sudo wg-quick down wg_quantum && sudo wg-quick up wg_quantum
sudo wg-quick down wg_mesh && sudo wg-quick up wg_mesh
```

---

## 9. Sentinel / LLM Specific Issues

**Symptoms:**
- Sentinel logs show `Cannot reach LLM server`
- `cobra-sentinel.service` is running but not diagnosing
- Hardware guard is throttling (`THROTTLED` in logs)

**Diagnostics:**
```bash
sudo systemctl status cobra-sentinel
journalctl -u cobra-sentinel --no-pager -n 30
cat /opt/cobratail/config/sentinel_config.json
```

**Fix — if llama.cpp server isn't running (on-demand mode starts it automatically):**
```bash
sudo systemctl restart cobra-sentinel
```

**Fix — if hardware guard is throttling due to high load:**
Wait for load to drop, or temporarily increase thresholds in
`/opt/cobratail/config/sentinel_config.json`:
```json
{
  "hardware_guard": {
    "cpu_threshold_percent": 95,
    "ram_threshold_percent": 90
  }
}
```
Then:
```bash
sudo systemctl restart cobra-sentinel
```

---

## 10. Identity Service Issues

**Symptoms:**
- `cobra-identity.service` fails on boot
- MAC address or hostname not spoofed
- Network interface goes down after identity apply

**Diagnostics:**
```bash
sudo systemctl status cobra-identity
journalctl -u cobra-identity --no-pager -n 20
ip link show
```

**Fix:**
```bash
sudo systemctl restart cobra-identity
```

If the identity service is interfering with connectivity, disable it:
```bash
sudo systemctl stop cobra-identity
sudo systemctl disable cobra-identity
```

---

## Quick Reference — Common One-Liners

| Problem | Command |
|---|---|
| Restart coordination tunnel | `sudo wg-quick down wg_quantum && sudo wg-quick up wg_quantum` |
| Restart mesh tunnel | `sudo wg-quick down wg_mesh && sudo wg-quick up wg_mesh` |
| Restart client service | `sudo systemctl restart cobratail` |
| Restart Lighthouse | `sudo systemctl restart lighthouse` |
| Check WireGuard status | `sudo wg show` |
| Flush DNS | `sudo resolvectl flush-caches` |
| Check logs (client) | `journalctl -u cobratail --no-pager -n 50` |
| Check logs (Lighthouse) | `journalctl -u lighthouse --no-pager -n 50` |
| Check logs (Sentinel) | `journalctl -u cobra-sentinel --no-pager -n 30` |
| Verify enrollment | `cat /opt/cobratail/config/enrollment.json` |
| Verify liboqs | `python3 -c "import oqs; print('OK')"` |
| Check time sync | `timedatectl status` |
| Check firewall | `sudo iptables -L -n` |