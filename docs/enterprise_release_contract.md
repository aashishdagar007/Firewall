# Enterprise Release Contract — Linux Appliance v1

**Status:** Proposed v1 product baseline for implementation and qualification. This document defines intended behavior; it is not evidence that the current code already meets it.

## Product boundary

- **Product:** single-node, on-premises Linux network firewall appliance. It is not an endpoint EDR agent or a multi-tenant hosted service in v1.
- **Qualification baseline:** Ubuntu Server 24.04 LTS, x86-64, using the distribution-supported kernel and `libnetfilter_queue` packages. CI and lab qualification must enumerate exact kernel/package revisions before general availability.
- **Enforcement:** NFQUEUE is mandatory in the supported enforcement profile. Raw-socket observer mode is a diagnostic mode and must never be reported as protected/enforcing.
- **Traffic coverage:** IPv4 TCP/UDP/ICMP initially. IPv6 must either receive equivalent tested filtering or be explicitly blocked at the managed host boundary. An unfiltered IPv6 path is a release blocker.
- **Management:** local administration first. Remote/fleet management is not a v1 requirement; if enabled later, it must use the authenticated control-plane requirements in the enterprise roadmap.
- **Explicitly out of v1 scope:** Windows enforcement, Linux kernels/distributions outside the qualified matrix, automatic malware remediation, and claims of regulatory certification or ML detection accuracy without independent evidence.

## Security objectives

1. Packets covered by the managed policy cannot bypass evaluation because the daemon is absent, restarting, overloaded, or unable to parse them.
2. Only an authorized local administrator can change policy, select observer mode, stop enforcement, or access sensitive telemetry.
3. A failed, malformed, stale, or unauthenticated policy/update cannot weaken the active policy silently.
4. Security events and policy changes are attributable and integrity-checked across daemon and host restarts.
5. The appliance reports whether enforcement is active, degraded, or unavailable; it does not label a passive capture state as protected.

## Threat model for v1

### Protected assets

- Network availability and the integrity of the active rule set.
- Administrator credentials, update/configuration signing keys, and local API/IPC access.
- Packet metadata, process attribution, threat records, and the integrity of the event ledger.
- The host's network configuration and the ability to recover safely after failure.

### Trust boundaries and adversaries

- **Untrusted input:** arbitrary network packets, fragments, malformed protocol messages, high-rate floods, and crafted payloads.
- **Local boundary:** unprivileged local users or processes attempting to alter rules, access the API, tamper with logs, or exhaust resources.
- **Remote management boundary:** a compromised network path, control-plane endpoint, or replayed/stale policy document.
- **Supply-chain boundary:** modified dependencies, build artifacts, packages, update metadata, or signing credentials.
- **Operational failure:** process crash, queue loss, partial startup, disk full, host reboot, corrupted configuration, and interrupted upgrade.

The appliance does not claim to withstand a compromised kernel, root account, or trusted signing authority. Such events remain detectable/operational-response concerns, not guarantees of the user-space firewall.

## Enforcement and lifecycle contract

### Startup and readiness

- The service validates configuration and the supported platform before changing host packet rules.
- It installs its managed NFQUEUE rules atomically and verifies the queue is open before reporting **ready/enforcing**.
- If NFQUEUE support, privileges, ruleset installation, or required policy validation fails, enforcement startup fails. It must not silently fall back to raw-socket observer mode.
- An observer-only mode requires an explicit operator-selected diagnostic setting, a prominent degraded/unprotected status, and no claim that traffic is blocked.

### Runtime packet decisions

- Matched allow/block rules, default policy, parser failures, and unsupported traffic have deterministic documented outcomes.
- Until equivalent IPv6 parsing/enforcement is qualified, managed enforcement must prevent IPv6 bypass rather than silently pass IPv6 outside the rules.
- Queue saturation, internal evaluation errors, and incomplete packet data are counted and surfaced. Packets must follow the chosen fail-secure policy; the appliance must not silently accept them.
- Policy updates are validated completely before activation, then swapped atomically. Failed updates leave the last known-good policy active.

### Crash, restart, and shutdown

- Kernel queue rules must not use a bypass option that allows packets through when the userspace queue listener is unavailable.
- On crash or forced termination, traffic covered by those rules is fail-closed until the service is recovered or an administrator explicitly invokes break-glass recovery.
- The service manager restarts the daemon with bounded backoff and alerts when enforcement is unavailable. Readiness remains false until NFQUEUE and policy state are verified again.
- A graceful stop is an explicit maintenance action. It must audit the action, remove only firewall-owned rules, and restore the recorded pre-install host ruleset without deleting unrelated administrator rules.
- Upgrade/rollback must preserve a last-known-good policy and restore a tested enforcement state if any upgrade stage fails.

### Audit and recovery

- Policy change, mode change, startup failure, queue failure, service stop, emergency override, and update result are auditable.
- Ledger chain index/hash are restored and verified at startup; partial final writes are detected and handled without accepting a broken chain as valid.
- Emergency recovery is local-admin controlled, rate-limited where relevant, documented, and tested on an isolated host before pilot rollout.

## Acceptance evidence required

This contract is satisfied only when CI/lab evidence demonstrates all of the following on the qualified matrix:

- Real-traffic allow and block tests through NFQUEUE, including INPUT, OUTPUT, and FORWARD paths that the product claims to protect.
- No traffic bypass during service crash, listener loss, restart, queue overflow, invalid configuration, partial startup, and interrupted upgrade.
- IPv6 is equivalently filtered or demonstrably blocked at the managed host boundary.
- Observer mode cannot be entered accidentally and is shown as unprotected in the API/UI/health status.
- Last-known-good configuration survives invalid updates and rollback; the ledger verifies across restarts and detects tampering/torn writes.
- Reboot, graceful stop, emergency recovery, and uninstall preserve unrelated host firewall configuration.
- Throughput, latency, packet loss, CPU, and memory are measured under baseline and stress traffic against budgets approved before pilot.

## Current implementation gaps to close

The Linux build now requires NFQUEUE and capture startup fails when NFQUEUE initialization is unavailable rather than falling back to raw sockets. The API currently listens on all interfaces, HTTPS depends on build-time OpenSSL/certificate configuration, and observer/enforcement status needs a single authoritative health contract. The README still uses manually installed iptables rules rather than a managed, reversible service ruleset. IPv6 is not parsed by the current packet parser. The ledger's documented restart path does not restore the previous hash/index. Real-traffic enforcement and lifecycle failure injection remain unqualified. These are gaps against this contract, not accepted launch exceptions.
