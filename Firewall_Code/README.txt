# Firewall v2 — Real Kernel Firewall + Live Web Dashboard
# Cross-platform: Windows (CLion) + Linux

A production-grade C++17 network firewall with a live, dark-theme web dashboard.

## Architecture

```
[Kernel / Network Layer]
       │
       ▼  (Linux: Netfilter NFQUEUE)  (Windows: Winsock2 SIO_RCVALL)
[NfqCapture]  ──→  [RuleEngine] ──→ NF_ACCEPT / NF_DROP (Linux)
                        │               Observe + log     (Windows)
                  [LiveStats] + [RingBuffer<PacketRecord>]
                        │
                  [ApiServer (cpp-httplib)]
                        │  JSON / HTTP on :8080
                  [Dashboard (index.html)]
                   Live feed · Charts · Rule CRUD
```

## Platform Support

| Feature           | Linux (NFQ)        | Linux (no NFQ)    | Windows           |
|-------------------|--------------------|-------------------|-------------------|
| Packet capture    | NFQUEUE (blocking) | Raw socket (obs)  | SIO_RCVALL (obs)  |
| Packet blocking   | ✅ NF_DROP          | ❌ observe only    | ❌ (WinDivert opt)|
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
# Ubuntu / Debian
sudo apt update
sudo apt install build-essential cmake

# Optional: enable real packet blocking
sudo apt install libnetfilter-queue-dev
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
# Step 1 — Insert iptables rules (redirects packets to NFQUEUE)
sudo iptables -I INPUT   -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT  -j NFQUEUE --queue-num 0
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

# Step 2 — Launch
cd cmake-build-debug
sudo ./firewall

# Step 4 — Cleanup iptables when done
sudo iptables -D INPUT   -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT  -j NFQUEUE --queue-num 0
sudo iptables -D FORWARD -j NFQUEUE --queue-num 0
```

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/stats | Live counters (total/allowed/blocked/bytes) |
| GET | /api/packets?n=100 | Last N packet records (JSON array) |
| GET | /api/rules | Current rule chain |
| POST | /api/rules | Add rule (JSON body) |
| DELETE | /api/rules/:id | Remove rule by ID |
| POST | /api/policy | Set default policy |

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

## Scaling to a Higher Level

The current architecture is single-node. Here are the natural scaling paths:

### Phase 1 — Performance (Local)
- Add a worker thread pool in `NfqCapture` to process packets in parallel
- Replace the `std::vector<Rule>` in `RuleEngine` with a hash-map for O(1) IP lookups
- Use lock-free ring buffer (already in place via `RingBuffer`)

### Phase 2 — Real Blocking on Windows
- Integrate **WinDivert** (set `WINDIVERT_DIR` in CMake) for kernel-level blocking
- Or use **Windows Filtering Platform (WFP)** callout driver for production-grade enforcement

### Phase 3 — Distributed / Cloud
- Replace the embedded `httplib` REST API with **gRPC** for low-latency remote management
- Forward `PacketRecord`s from multiple firewall nodes to a central **time-series database** (InfluxDB, ClickHouse)
- Add a **Kafka** or **ZeroMQ** message bus between capture nodes and the central analytics engine
- Deploy via Docker + Kubernetes — the binary is statically linked (MinGW `-static`) and has no runtime deps

### Phase 4 — ML-based Threat Detection
- Export the ring buffer as a feature stream to a Python/PyTorch threat model
- Add anomaly scoring per `PacketRecord` returned via the REST API
- Store PCAP replay captures for offline model training

## License
MIT