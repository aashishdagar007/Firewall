# Firewall v2 — Real Kernel Firewall + Live Web Dashboard
# Cross-platform: Windows (CLion) + Linux

An in-development C++17 firewall prototype with a live dashboard, Deep Packet Inspection (DPI), port scan detection, and process monitoring. Linux v1 builds require NFQUEUE; enterprise production readiness and real-traffic qualification are not yet complete.

## Architecture

```
[Kernel / Network Layer]
       │
       ▼  (Linux: Netfilter NFQUEUE)  (Windows: Winsock2 SIO_RCVALL / WinDivert)
[NfqCapture]  ──→  [RuleEngine] ──→ NF_ACCEPT / NF_DROP (Linux)
                        │           Observe + log / WinDivert block (Windows)
                        ├── [DPI Engine] (Deep Packet Inspection)
                        ├── [Port Scan Detector]
                        └── [Process Monitor] (Windows: iphlpapi/psapi)
                        │
                  [LiveStats] + [RingBuffer<PacketRecord>] + [Tamper-Proof Ledger]
                        │
                  [ApiServer (cpp-httplib, OpenSSL HTTPS support)]
                        │  JSON / HTTP(S) on :8080
                  [Dashboard (index.html)]
                   Live feed · Charts · Rule CRUD · Process Traffic · Threat Alerts
```

## Core Features
- **Cross-Platform Capture**: Netfilter (NFQUEUE) on Linux, raw sockets (Winsock2) or WinDivert on Windows.
- **Deep Packet Inspection (DPI)**: Analyzes packet payloads for application-layer threats.
- **Port Scan Detection**: Automatically detects and alerts on port scanning attempts.
- **Process Monitoring**: Maps network activity to running processes on Windows.
- **Tamper-Proof Hash-Chain Ledger**: Cryptographically secure logging (SHA-256).
- **Cloud Control Plane**: Integration with centralized API via `AEGIS_CONTROL_URL`.
- **BVUDP**: Batch-Verified UDP protocol stack.
- **Embedded REST API**: Built-in cpp-httplib server, with optional OpenSSL support for HTTPS.
- **Live Web Dashboard**: Dark-theme dashboard with real-time stats, rule management, and process traffic.

## Platform Support

| Feature           | Linux v1 (NFQ required) | Linux (no NFQ) | Windows           |
|-------------------|-------------------------|----------------|-------------------|
| Packet capture    | NFQUEUE                 | Startup fails  | SIO_RCVALL (obs)  |
| Packet blocking   | NF_ACCEPT / NF_DROP     | Unavailable    | ❌ (WinDivert opt)|
| Process Monitor   | ❌                  | ❌                 | ✅ (iphlpapi)      |
| REST API          | ✅                  | ✅                 | ✅                 |
| Web dashboard     | ✅                  | ✅                 | ✅                 |
| Admin required    | ✅ (root/sudo)      | ✅                 | ✅ (Administrator) |

---

## Build — Windows + CLion

### Prerequisites

1. **CLion** (2023.1+) — https://www.jetbrains.com/clion/
2. **MinGW-w64** (recommended toolchain for CLion on Windows):
   - Install via MSYS2: https://www.msys2.org/
   - In MSYS2 UCRT64 shell: `pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake`
   - Or use **MSVC** (Visual Studio Build Tools 2019/2022) — also works
3. **CMake** ≥ 3.20 (bundled with CLion)
4. *(Optional)* **OpenSSL** — For HTTPS API Server

### Steps in CLion

1. Open CLion → **File → Open** → select `d:\AASHISH\Projects\Firewall`
2. CLion auto-detects `CMakeLists.txt`
3. Go to **Settings → Build, Execution, Deployment → Toolchains**
   - Add **MinGW** toolchain pointing to your MSYS2 UCRT64 installation
   - Or use bundled MSVC if Visual Studio is installed
4. Go to **Settings → Build, Execution, Deployment → CMake**
   - Set **Generator**: `MinGW Makefiles` (for MinGW) or `Ninja` (universal)
   - Build type: `Debug`
5. Click the **hammer** (Build) or press **Ctrl+F9**
6. The `firewall.exe` will appear in `cmake-build-debug/`

### Run on Windows (PowerShell as Administrator)

```powershell
# Navigate to the build directory
cd D:\AASHISH\Projects\Firewall\cmake-build-debug

# Run the firewall (must be Administrator for raw sockets)
.\firewall.exe

# Optional arguments:
.\firewall.exe config\rules.conf logs\firewall.log dashboard\ 8080
```

Then open **http://localhost:8080** in your browser.

> **Note**: On Windows, the firewall runs in **observer mode** — it captures
> and logs packets but cannot block them (that requires WinDivert). All
> REST API and dashboard features work normally.

### Enable Real Blocking on Windows (Optional — WinDivert)

For kernel-level packet blocking on Windows, integrate **WinDivert**:

1. Download WinDivert 2.x from https://reqrypt.org/windivert.html
2. Extract to e.g. `C:\WinDivert`
3. In CLion CMake settings add: `-DWINDIVERT_DIR=C:\WinDivert`
4. Rebuild — the `HAVE_WINDIVERT` macro will be defined

---

## Build — Linux

### Prerequisites

```bash
# Ubuntu / Debian (NFQUEUE is required for Linux builds)
sudo apt update
sudo apt install build-essential cmake nftables libnetfilter-queue-dev

# Optional: OpenSSL for HTTPS
sudo apt install libssl-dev
```

### Compile

```bash
cd /path/to/Firewall
mkdir -p cmake-build-debug && cd cmake-build-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### Run on Linux

```bash
# Install the managed v1 ruleset. IPv4 is queued; IPv6 is blocked until
# equivalent IPv6 rule evaluation is implemented and qualified.
sudo bash ./scripts/linux-nfq-guard.sh install

# Start the daemon only after installing the ruleset. Until its NFQUEUE
# listener is ready, queued IPv4 packets are dropped by the kernel.
cd cmake-build-debug
sudo ./firewall

# Maintenance/recovery only: stopping enforcement removes the IPv6 guard too.
# Stop the daemon first, then explicitly restore normal host networking.
sudo bash ./scripts/linux-nfq-guard.sh remove
```

The Linux daemon also verifies that the owned nftables table contains the IPv4
queue and IPv6 drop rules. It refuses to start or report enforcement if the
guard is absent or incomplete.

The helper owns only the `inet aegisxii` nftables table and leaves unrelated
firewall tables untouched. Do not run `remove` while relying on the appliance
for IPv4 enforcement or IPv6 blocking. Automated packaging, a machine-readable
readiness check, and tested rollback are still required before pilot use.

### Run as a systemd service

The repository includes a fail-closed service unit. Install the built program
and runtime assets under `/opt/aegisxii` before enabling it:

```bash
sudo install -d -m 0750 /opt/aegisxii
sudo install -m 0755 build/AegisXII /opt/aegisxii/AegisXII
sudo cp -a config dashboard scripts /opt/aegisxii/
sudo install -D -m 0644 packaging/systemd/aegisxii.service \
  /etc/systemd/system/aegisxii.service
sudo systemctl daemon-reload
sudo systemctl enable --now aegisxii.service
sudo systemctl status aegisxii.service
sudo bash /opt/aegisxii/scripts/linux-nfq-guard.sh status
```

The unit installs the guard before launch and restarts failures with a bounded
rate. `systemctl stop` and crash exhaustion intentionally leave the guard in
place: IPv4 stays queued (and drops without a listener), while IPv6 stays
dropped. Recover locally after start-limit exhaustion with
`sudo systemctl reset-failed aegisxii.service` then
`sudo systemctl start aegisxii.service`; removing the guard with its helper is
an explicit break-glass action that restores unfiltered
network paths. This unit runs as root and has not yet received independent
systemd hardening or reboot/failure-injection qualification.

## Management API access

The management API listens only on `127.0.0.1` by default. Non-loopback bind
addresses are rejected; remote administration is disabled until administrator
bootstrap, token lifecycle, and role-based authorization are implemented.
The served dashboard uses the same origin, so the API does not grant wildcard
cross-origin access. There is no unauthenticated token endpoint: enter the
current token from `logs/api.token` when prompted. On Linux the token file is
created with owner-only read/write permissions, and the API refuses to start
if it cannot store the token securely. The token rotates when the daemon
restarts, so reload the dashboard and enter the current token after recovery.

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/stats | Live counters (total/allowed/blocked/bytes) |
| GET | /api/stats/history | 60-second rolling stats history |
| GET | /api/packets?n=100 | Last N packet records (JSON array) |
| GET | /api/rules | Current rule chain |
| POST | /api/rules | Add rule (JSON body) |
| DELETE | /api/rules/:id | Remove rule by ID |
| POST | /api/policy | Set default policy |
| GET | /api/processes | All processes with network activity |
| GET | /api/processes/apps | Process snapshot sorted by traffic |
| GET | /api/anomalies | Hit counts for all 20 anomaly rules |
| GET | /api/connections | Snapshot of live connection tracking table |
| GET | /api/ledger?n=N | Last N lines from tamper-proof ledger |
| GET | /api/scans | Queue of port scan alerts |
| GET | /api/stealth | Get stealth mode status |

### Add Rule (POST /api/rules)

```json
{
  "action": "BLOCK",
  "proto": "TCP",
  "src_ip": "192.168.1.66",
  "dst_ip": "*",
  "dst_port": 0,
  "description": "Block attacker"
}
```

## Rule Syntax (config/rules.conf)

```
ACTION  PROTO  SRC_IP  DST_IP  DST_PORT  "Description"
BLOCK  ANY   192.168.1.66  *   *    "Block attacker"
ALLOW  TCP   *             *   443  "HTTPS"
ALLOW  UDP   *             *   53   "DNS"
BLOCK  TCP   *             *   23   "Block Telnet"
ALLOW  ICMP  *             *   *    "Allow ping"
```

---

## Phase 2 Architecture (Scaling & Security)

The firewall has been upgraded with a **Phase 2 Architecture**, laying the foundation for enterprise and cloud deployments:

- **Pillar 1 — Port Demux**: WinDivert DPI interceptor for advanced application layer filtering.
- **Pillar 2 — BVUDP**: Batch-Verified UDP protocol stack for high-performance, validated datagram transmission.
- **Pillar 3 — Cloud Control Plane**: Client to sync config with a central management server (`AEGIS_CONTROL_URL`).
- **Pillar 4 — Tamper-Proof Ledger**: Uses a header-only SHA-256 implementation to cryptographically chain logs, preventing undetected modifications.

## License
MIT
