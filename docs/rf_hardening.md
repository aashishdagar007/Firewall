# RF & Physical Layer Hardening Guide
## AEGIS XII — Phase 3 Security Hardening

> **Scope**: This document covers threats 1–14 and 28–37 from the AEGIS XII threat model.
> These involve physical-layer signals, RF emissions, and human factors that a software
> firewall **cannot** directly intercept. Each section provides OS-level and hardware-level
> mitigations plus network-visible side-effect detection that the firewall CAN enforce.

---

## Threat 1–7: Passive RF Sensing (WiFi CSI, mmWave, Acoustic, TEMPEST)

These attacks infer presence, keystrokes, or activity by analyzing **physical signals** leaking
from hardware — radio frequency energy, acoustic vibrations, or electromagnetic emanations.

### Mitigations
| Control | Level | Action |
|---------|-------|--------|
| Faraday cage / RF shielding | Hardware | Enclose sensitive equipment in shielded enclosures |
| Acoustic dampening | Physical | Use acoustic foam; avoid hard surfaces near keyboards |
| TEMPEST-rated equipment | Hardware | NSA/NATO TEMPEST-certified hardware suppresses EM leakage |
| Distance | Physical | Keep sensitive devices ≥ 3m from exterior walls |
| Disable unused radios | OS | See WiFi/BT section below |
| Random inter-keystroke delays | Software | Keyboard latency randomization thwarts keystroke inference |

### Firewall-detectable side effects
- `mmWave radar` devices (Google Soli-class) communicate over Wi-Fi → DPI blocks unusual 802.11 management frames
- Any attacker-controlled sensing device on the network → firewall blocks C2 callbacks via known C2 port rules

---

## Threat 10: Probe Request Sniffing (802.11 Passive)

A passive receiver captures 802.11 probe requests your device broadcasts when scanning for
known networks — revealing your location history and device identity.

### Mitigation (Windows)
```powershell
# Enable MAC randomization in Windows 10/11
netsh wlan set randomization interface="Wi-Fi" mode=random

# Verify
netsh wlan show interface
```

### Mitigation (Linux)
```bash
# iwd (systemd-based) — recommended
echo "[Network]
AddressRandomization=random" >> /etc/iwd/main.conf

# NetworkManager
nmcli dev wifi set wifi.cloned-mac-address random
```

### Firewall side-effect detection
The firewall blocks **probe-style scanner user-agents** at Layer 7 (DPI signatures added in Phase 3):
`Kismet`, `Wireshark`, `tshark`, `airodump-ng` HTTP management interfaces.

---

## Threat 12: Bluetooth / BLE Scanning & Tracking

BLE advertisements are broadcast at regular intervals and carry a stable MAC address
(unless MAC randomization is enabled), enabling passive tracking.

### Mitigation (Windows)
```powershell
# Disable Bluetooth entirely when not in use
Disable-PnpDevice -InstanceId (Get-PnpDevice -Class Bluetooth).InstanceId -Confirm:$false

# Or via Device Manager → Bluetooth adapters → Disable
```

### Mitigation (Linux)
```bash
# Block Bluetooth kernel module
echo "install bluetooth /bin/false" >> /etc/modprobe.d/blacklist.conf

# Or with rfkill
rfkill block bluetooth
```

### Firewall side-effect detection
BLE → IP gateways (Bluetooth smart home hubs) communicate on known ports;
the firewall blocks their C2 callback ports. Any BLE gateway making unexpected
outbound connections to port 4444/1337/31337 is auto-banned.

---

## Threat 13: Wardriving (Kismet, WiGLE)

Wardriving maps your network's SSID and BSSID (AP MAC), geolocating it to databases.

### Mitigation
- **Use a hidden SSID** (reduces visibility in passive scans; not a security boundary)
- **Enable WPA3-SAE** (prevents offline cracking of captured handshakes)
- **Disable WPS** (Wi-Fi Protected Setup is exploitable via PIN brute-force)
- **Disable 2.4GHz if unused** (fewer channels to scan)

### Firewall Rules Applied
The hardened `rules.conf` blocks:
- UDP/1900 (UPnP SSDP) — prevents device discovery from wardriving tools
- UDP/5353 (mDNS) — prevents `.local` service discovery

---

## Threat 14: SDR-Based Spectrum Recon (RTL-SDR, HackRF)

SDR tools capture raw RF spectrum and can decode wireless protocols passively.
The firewall blocks their **network management interfaces**:

| Tool | Port Blocked |
|------|-------------|
| RTL-SDR web server | TCP 8888 |
| GNU Radio Companion web UI | TCP 8888 |
| gqrx HTTP API | TCP 8080 |
| OpenWebRX | TCP 8073 |

Add to `rules.conf` if using OpenWebRX:
```
BLOCK  TCP  *  *  8073  "Block OpenWebRX SDR web interface"
```

---

## Threat 28–29: Evil Twin / Rogue AP + WPA Handshake Capture

### Mitigation
1. **Enable WPA3-SAE** on your router (prevents offline dictionary attacks on captured handshakes)
2. **Enable 802.11w PMF** (Protected Management Frames) — prevents deauthentication attacks (threat 30)
3. **Use 802.1X / RADIUS** for enterprise environments (individual per-device authentication)
4. **Validate AP certificates** if using EAP-TLS

### Router Configuration (typical home router)
```
Security: WPA3-SAE (or WPA2/WPA3 mixed mode)
PMF: Required
WPS: Disabled
```

---

## Threat 30: Deauthentication Attacks (802.11 Deauth)

Deauth frames are unauthenticated in WPA2. An attacker can force clients offline.

### Mitigation
- **802.11w PMF (Management Frame Protection)** — cryptographically authenticates mgmt frames
  - Set PMF to **Required** (not Optional) on WPA3
- **Detect**: unusual deauth floods appear as connection drops; the firewall logs all
  subsequent SYN floods from the reconnection storm under the Port Scan Detector

---

## Threat 32: RFID / NFC Cloning (Proxmark3-class)

### Mitigation
- **Shielded wallets** (RFID-blocking sleeves) for access cards
- **Disable NFC on phone** when not in use:
  ```powershell
  # Windows: Device Manager → NFC → Disable
  ```
  ```bash
  # Linux
  rfkill block nfc
  ```
- Use **HID iCLASS SE or SEOS** credentials (cryptographically authenticated, clone-resistant)

---

## Threat 33: Zigbee / Z-Wave Sniffing

Zigbee (IEEE 802.15.4) and Z-Wave operate on 868/915 MHz and 2.4 GHz bands.

### Firewall Rules Applied
Zigbee gateways communicate over known ports — all blocked in hardened `rules.conf`:
```
BLOCK  TCP  *  *  8888   "Block Zigbee/RTL-SDR web server"
BLOCK  UDP  *  *  5353   "Block mDNS (Zigbee gateway discovery)"
```

### Additional Mitigations
- Enable **Zigbee 3.0 security** (AES-128 link keys)
- Use **Z-Wave S2 security mode** (strongest: Access Control class)

---

## Threats 34–37: Social Engineering, USB Drops, Lock Picking, Dumpster Diving

These are human-factors and physical security threats entirely outside the firewall's scope.

### USB Drop (Threat 35 — Rubber Ducky)
```powershell
# Windows: Enable USB Restricted Mode (blocks HID keyboards from new USB devices)
# Group Policy: Computer Config → Admin Templates → System → Removable Storage Access
# Set "All Removable Storage classes: Deny all access" = Enabled

# Or via registry:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v DenyRemovableDevices /t REG_DWORD /d 1 /f
```

### Lock Picking (Threat 36)
- Use **high-security locks** (Medeco, Abloy Protec2)
- Install **door contacts / tamper sensors** on server rooms

### Dumpster Diving / OSINT (Threats 15, 37)
- **Shred documents** before disposal
- **Disable WHOIS privacy opt-out** — use WHOIS privacy services
- **Remove personal info from LinkedIn/GitHub** commit history
- Run `git-secrets` or `truffleHog` on all commits to prevent credential leaks

---

## Threat 34: Social Engineering / Phishing

- **Enable DMARC/DKIM/SPF** on your email domain
- **Use a hardware security key** (YubiKey) for all privileged accounts
- **Train users**: no firewall rule protects against a human clicking a malicious link

---

*Last updated: Phase 3 Hardening (July 2026)*
*Document maintained by: AEGIS XII Security Team*
