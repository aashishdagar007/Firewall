# Device Security, UX, and Unified Launch Plan

## Objective

Deliver a Windows endpoint experience in which one desktop shortcut starts the
Aegis XII service when needed, waits for a verified ready state, and opens the
desktop UI. The same release work must improve the protection of the device
hosting Aegis XII and provide evidence that every shipped capability works from
installation through recovery.

The current installer already ships the native UI, service executable, web
dashboard assets, and configuration as one payload. This plan turns those
pieces into one dependable user flow and strengthens the device boundary before
calling the product an endpoint firewall.

## Release principles

- Treat Windows as an endpoint-monitoring product until a supported,
  production packet-enforcement backend is installed and verified.
- Keep the firewall service separate from the interactive UI. The service runs
  with only the privileges it needs; the UI remains a standard user process.
- A click must never show a dashboard that implies protection when the service
  is stopped, unhealthy, or in observer-only mode.
- Every externally supplied policy, update, driver, and executable must have a
  verified origin, integrity check, rollback path, and audit record.
- Ship each linked implementation unit in its own commit. Target at least five
  meaningful, independently reviewable commits per active development day;
  never create empty commits merely to meet the count.

## Workstream A — Device security

### A1. Establish the supported Windows security baseline

Define supported Windows editions, architecture, minimum patch level, required
hardware features, and which protections are mandatory: Secure Boot, TPM 2.0,
BitLocker, Microsoft Defender, SmartScreen, firewall policy, and automatic
updates. Add a startup health report that distinguishes *required and missing*,
*recommended and missing*, and *verified* controls.

**Acceptance:** the UI and support bundle report the device posture without
exposing secrets; policy can block activation when mandatory controls are
absent.

### A2. Deliver real Windows packet enforcement

Replace the optional observer-only path with a supported, signed filtering
backend and explicit capability state. The packaged driver must be signed,
versioned, compatible with the supported Windows matrix, and removable through
the installer. Add integration tests for inbound, outbound, loopback, spoofed
source, service restart, driver loss, and default-deny behavior.

**Acceptance:** a test host proves that configured ALLOW and BLOCK rules affect
real traffic. If enforcement cannot initialize, the UI says *Protection
unavailable* and records the reason.

### A3. Harden privilege, service, and local data boundaries

Run the service under a dedicated service account where the enforcement backend
allows it. Apply a restricted service token, service SID ACLs, recovery policy,
protected log/config directories, Windows event logging, and size/retention
limits. Move mutable state out of the application directory into a protected
ProgramData location. Replace image-name IPC checks with authenticated client
identity and an allow-listed, versioned message protocol.

**Acceptance:** non-administrators cannot alter policy, logs, service binaries,
or privileged IPC; service recovery and corrupted-state behavior are tested.

### A4. Protect supply chain and updates

Sign the executable, installer, driver, and update metadata with an
organization-controlled certificate. Verify a signed update manifest, hashes,
publisher identity, minimum version, expiry, and rollback eligibility before
installation. Generate an SBOM, dependency/vulnerability report, provenance
record, and offline installer verification procedure.

**Acceptance:** a tampered package, invalid signer, downgrade attempt, or
interrupted update is rejected and leaves the previous working version intact.

### A5. Improve detection and incident response

Add high-confidence device events for service tampering, disabled enforcement,
policy changes, driver failure, repeated management authentication failures,
unexpected listener exposure, and audit-ledger failures. Provide a privacy
controlled support bundle, local event timeline, and administrator recovery
runbook.

**Acceptance:** support can diagnose a simulated incident from the exported
bundle without direct access to the device.

## Workstream B — Single-click application startup

### B1. Define the launch contract

The desktop shortcut launches `AegisXII.exe --ui`. This mode must:

1. resolve paths from the executable location rather than the current folder;
2. query the Windows Service Control Manager for `AegisXII`;
3. request service start when it is installed but stopped;
4. wait with a bounded timeout for the service and authenticated IPC health
   check;
5. start one UI process only; and
6. show recovery actions when service start or health verification fails.

The service mode (`--service`) owns packet capture, API/IPC, logs, and policy.
The installer mode (`--install`) only registers the service. No normal user
action should need separate frontend or backend commands.

### B2. Implement a launch coordinator

Create a small coordinator shared by the shortcut/UI entry point and installer
smoke test. It should use SCM status, named-pipe `PING`, a time-bounded retry
policy, a single-instance mutex, and structured result codes. Do not run a
second in-process firewall when the service is already present.

**Acceptance:** clean install, stopped service, already-running service,
delayed start, unhealthy service, denied start, and double-click scenarios all
produce one deterministic UI result.

### B3. Align installer, shortcut, and uninstall behavior

Make Inno Setup create a Start Menu shortcut and optional desktop shortcut that
invoke `--ui`. Install and start the service before offering launch, record
service failures in the installer log, and verify the UI-to-service handshake
in a clean virtual-machine smoke test. Uninstall must stop the service, remove
the driver only after user confirmation where applicable, and preserve or erase
audit data according to a clearly presented choice.

**Acceptance:** install, launch from icon, reboot, upgrade, repair, and
uninstall all pass on a clean supported Windows image.

## Workstream C — UI and UX correction

### C1. Make protection state the primary screen

Replace raw counters as the first screen with a plain-language protection card:
**Protected**, **Monitoring only**, **Starting**, **Needs attention**, or
**Protection unavailable**. Show the enforcement backend, last policy update,
service health, and a single recommended action.

### C2. Make controls safe and understandable

Group actions into Protection, Network activity, Rules, Device health, Events,
and Settings. Require confirmation for actions that reduce protection, explain
the duration and recovery path, and keep safe actions one click away. Add
keyboard navigation, visible focus, scalable text, sufficient contrast, and
screen-reader labels.

### C3. Improve observability without overwhelming the operator

Use a searchable event timeline with severity, reason, process, destination,
rule, and remediation. Provide empty states, loading states, offline states,
and error states. Avoid security jargon where a clear action is available; keep
technical details in an expandable panel and the support bundle.

### C4. Validate with representative users

Run task-based tests with administrators and standard users: first launch,
recognize protection state, investigate a blocked event, update policy, recover
from an unhealthy service, and export support evidence. Track task completion,
time, error rate, and comprehension rather than visual preference alone.

**Acceptance:** users can tell whether protection is active and complete the
critical tasks without developer assistance.

## Delivery sequence and commit cadence

| Day | Linked implementation units and commit intent |
|---|---|
| 1 | Baseline device posture model; service health contract; launch coordinator interface; UI status model; tests/docs. |
| 2 | SCM service discovery/start; authenticated readiness handshake; bounded retry and single-instance handling; installer shortcut update; integration tests. |
| 3 | Protection-state dashboard; service and error states; accessible navigation; event timeline foundations; UI tests. |
| 4 | Windows enforcement backend packaging; capability reporting; real-traffic test harness; failure-mode tests; operator documentation. |
| 5 | Service privilege/ACL hardening; protected state storage; IPC authorization; tamper events; security tests. |
| 6 | Signed release/update verification; rollback behavior; SBOM/provenance; installer upgrade/repair tests; release runbook. |
| 7 | Usability validation fixes; support bundle; performance and reliability tests; pilot checklist; release evidence review. |

Each row is broken into at least five linked commits during the active day:
implementation foundation, integration, user-facing surface, automated tests,
and documentation/release evidence. A commit message must state the behavior
changed and remain buildable on its own where practical.

## Release gates

1. **Single-click gate:** the installed icon starts or connects to one healthy
   service and opens one UI without manual frontend/backend steps.
2. **Truthful-state gate:** the UI never reports active protection when the
   enforcement backend is absent, degraded, or stopped.
3. **Security gate:** signed artifacts, least-privilege service boundaries,
   protected local state, authenticated IPC, and update rollback pass attack
   simulations.
4. **Usability gate:** representative users complete the launch, status,
   investigation, recovery, and support-bundle tasks successfully.
5. **Operations gate:** a clean VM proves install, reboot, upgrade, repair,
   rollback, and uninstall; CI archives the evidence for the exact release.
