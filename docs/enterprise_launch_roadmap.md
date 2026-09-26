# Enterprise Launch Roadmap

## Purpose

This roadmap describes the work required to turn the current Aegis XII codebase into a supportable enterprise firewall product. It treats a successful build, repeatable tests, secure packet enforcement, safe upgrades, and operational support as launch requirements. Feature names or prototype code do not count as launch evidence until behavior is tested on the supported operating systems.

## Current readiness

The repository is a feature-rich prototype, not yet an enterprise release candidate. The current checkout could not be compiled or tested in the available environment: its cached compiler points to a different user profile, no compiler is installed on PATH, and CTest has no current test executable. The existing binaries predate the current source and are not validation evidence.

Source and documentation review found these launch risks:

- Linux builds now require NFQUEUE and fail startup instead of silently degrading to observer-only mode; managed ruleset installation, IPv6 bypass prevention, and real-traffic qualification remain open. Windows remains observer-only unless its optional WinDivert integration is configured.
- The API binds to `0.0.0.0`; TLS is optional, CORS permits every origin, and `/api/token` is exempt from bearer authentication. A token is written to a local file and printed. This needs a deliberate enterprise authentication and exposure model.
- The hash-chain ledger documents that restart recovery does not restore the last index and hash. It must be corrected and tested before calling the ledger tamper-evident across restarts.
- The cloud control plane uses a hand-written JSON parser. It needs strict schema validation, authenticated configuration, atomic application, rollback, and replay protection.
- Startup creates more than one IPC server and keeps the REST API active. IPC ownership, protocols, access control, and intended platform behavior need to be consolidated.
- The README platform matrix is stale in places, and several advanced security/model claims need reproducible evidence before release or sales use.
- The repository has multiple test files, but the CMake test section registers only a subset. Current tests cannot be executed until a supported toolchain is restored.

## Product direction decision

Choose one initial product before investing in cross-platform polish. Supporting multiple operating systems means separately validating enforcement, installers, privilege boundaries, upgrades, and recovery on each.

**Selected planning baseline for v1:** Option A, a Linux NFQUEUE network appliance. The proposed qualification baseline and enforcement/failure contract are in [enterprise_release_contract.md](enterprise_release_contract.md). This selects the first product direction; it does not represent completed platform qualification.

| Option | Initial product | Benefits | Main work and risk |
|---|---|---|---|
| A. Linux network appliance (recommended first) | A supported Linux distribution using NFQUEUE for enforcement | The repository already has an active-blocking path; a focused release is easier to validate | Harden NFQUEUE lifecycle, boot/service integration, ruleset setup and rollback, kernel/distribution compatibility, and Linux operations |
| B. Windows endpoint firewall | A supported Windows release with a production-grade packet-filter driver | Fits endpoint deployment and process attribution already present in the code | Select and package a supported filtering platform, driver signing and servicing, service recovery, code signing, Windows security review, and upgrade rollback |
| C. Cross-platform release | Linux and Windows as equal enterprise targets | Broad deployment coverage | Highest schedule and support risk; requires two enforcement backends and two complete qualification programs |

Do not advertise a platform as an enforcement firewall when its default capture mode only observes traffic. Treat observer mode as a separately named monitoring product or a clearly disclosed diagnostic mode.

## Phased development plan

### Phase 0 — Scope and release contract

**Deliverables**

- Select Option A, B, or C, and state exact supported OS versions, kernel/driver versions, deployment form, and operator audience.
- Write a threat model covering packet bypass, privileged code, API/IPC access, control-plane compromise, update compromise, log tampering, and denial of service.
- Define the enforcement contract: startup failure behavior, queue/socket failure behavior, shutdown behavior, emergency recovery, and what happens when rules cannot be loaded.
- Create a feature inventory separating implemented, tested, platform-limited, experimental, and removed claims.
- Replace unsupported compliance/performance claims with evidence requirements.

**Exit gate**: product owner approves the supported-platform matrix, threat model, and fail-open/fail-closed behavior. Every marketed feature has an owner and a verification method.

### Phase 1 — Reproducible build and trustworthy verification

**Deliverables**

- Restore native toolchains for every supported OS and create clean CI builds from a fresh checkout.
- Pin all third-party dependencies to immutable releases or commits; generate an SBOM and license inventory.
- Replace fragile source globs with explicit targets or `CONFIGURE_DEPENDS`; split core, platform capture, API, UI, and tests into separately buildable targets.
- Register every supported test in CTest and make CI fail on compiler warnings appropriate to each compiler.
- Add static analysis, formatting checks, dependency scanning, and sanitizer jobs. Add fuzzing for packet parsing and configuration parsing.
- Make build artifacts reproducible enough to identify the exact source, toolchain, and dependency versions that produced them.

**Exit gate**: clean Linux and/or Windows builds pass in CI; all registered tests execute; parser fuzz targets run for a defined minimum corpus/time; no known high-severity static-analysis or dependency findings remain unresolved.

### Phase 2 — Data-plane correctness and safe enforcement

**Deliverables**

- Implement and test one production enforcement backend end to end. Verify rule changes affect real traffic, not only simulated packets.
- Define queue overflow, capture restart, interface changes, partial initialization, and shutdown behavior. Ensure the host does not silently become unprotected.
- Consolidate rule semantics: CIDR, port ranges, protocol, direction, process identity where supported, priority/order, and default policy. Version and validate the on-disk rule schema.
- Test malformed, truncated, fragmented, IPv4, IPv6, TCP, UDP, and ICMP traffic. Define IPv6 support explicitly rather than counting it as groundwork while leaving it unfiltered.
- Establish concurrency safety for rule updates, packet evaluation, callbacks, telemetry, and lifecycle transitions. Exercise with ThreadSanitizer where supported.
- Set measured throughput, latency, memory, and packet-loss budgets under normal load and attack traffic.

**Exit gate**: integration tests demonstrate allow and block behavior on real isolated interfaces; restart and failure injection prove the documented protection state; no unhandled parser crashes or data races in supported test runs.

### Phase 3 — Security boundary and enterprise control

**Deliverables**

- Bind the management API to loopback by default. Require explicit configuration for remote access; use verified TLS for remote access.
- Replace the self-service token endpoint with administrator bootstrap, rotation, revocation, expiration, audit, and role-based authorization. Restrict CORS to configured trusted origins.
- Consolidate IPC to one documented protocol per platform, with OS access controls, message-size limits, schema validation, and authenticated/authorized operations.
- Replace hand-written cloud JSON parsing with a maintained parser and strict schema/version validation. Require authenticated and integrity-protected configuration; apply updates atomically and support rollback/replay protection.
- Repair ledger restart recovery, torn-write handling, disk-full behavior, queue overflow visibility, retention, export, and verification. Protect files with least-privilege ACLs.
- Secure update delivery: signed metadata and packages, verified hashes/signatures, staged rollout, rollback, and an auditable update result. Do not provide a weaker platform path.
- Review fail-open/fail-closed options, crash behavior, privilege separation, secrets, and local file permissions with an independent security reviewer.

**Exit gate**: security review and penetration test have no unresolved critical/high findings; API and IPC authorization tests pass; restart/tamper tests verify ledger integrity; update signature failure and rollback tests pass.

### Phase 4 — Fleet operations, packaging, and support

**Deliverables**

- Ship a signed installer/package, managed service, upgrade/uninstall flow, configuration migration, health checks, and recovery procedure.
- Add centralized fleet enrollment, policy groups, staged policy rollout, drift reporting, offline behavior, and administrator audit trails.
- Define privacy-minimized telemetry, support bundles, log rotation/retention, export formats, and customer-controlled data collection.
- Publish runbooks for install, upgrade, rollback, lockout recovery, emergency disablement, packet-path diagnosis, and incident response.
- Define compatibility and support windows, severity response targets, vulnerability disclosure intake, and release cadence.

**Exit gate**: install/upgrade/rollback/uninstall pass on clean and upgraded systems; service survives reboot and controlled failure; support can diagnose a test incident using documented tools without developer access.

### Phase 5 — Controlled pilot and general availability

**Pilot**

- Deploy to a small, consenting internal or design-partner fleet in monitor mode first, then limited enforcement with a rollback plan.
- Measure false positives, false negatives on the agreed test corpus, CPU/memory, packet drops, policy drift, upgrade success, and support burden.
- Review every enforcement exception and incident; obtain operator approval before expanding the rollout.

**GA requirements**

- All previous exit gates are met for each advertised platform.
- No unresolved critical/high security findings, data-loss issues, or reproducible enforcement bypasses.
- Release artifacts are signed, provenance/SBOM are published, recovery procedures are exercised, and support/on-call ownership is staffed.
- Marketing and technical documentation match tested behavior, including explicit observer-only limitations.

## Proposed sequencing and rough effort

For a small experienced team focused on one platform, plan roughly **4–6 months** to reach a defensible pilot, followed by a pilot period sized to customer risk. This is a planning range, not a commitment; driver/platform selection and security findings can extend it substantially.

1. Weeks 1–2: Phase 0 scope, threat model, and platform decision.
2. Weeks 2–6: Phase 1 CI/build repair and test coverage.
3. Weeks 5–11: Phase 2 enforcement and data-plane validation.
4. Weeks 8–14: Phase 3 security boundary and configuration/update work.
5. Weeks 12–18: Phase 4 packaging and fleet operations.
6. After gates: Phase 5 pilot; promote to GA only after operational evidence is accepted.

Phases can overlap only when their interfaces and ownership are clear. Do not overlap broad feature additions with unverified packet enforcement or security-boundary changes.

## First 30-day action list

1. Review and approve the selected Linux/NFQUEUE v1 scope and release contract.
2. Create a clean, working CI build and make the full test suite executable.
3. Run an architecture and threat-model workshop; close the API exposure and duplicate IPC design decisions.
4. Add real-traffic integration tests for block, allow, default policy, restart, overload, and shutdown.
5. Audit ledger restart behavior, cloud configuration parsing, and update verification; write acceptance criteria for each.
6. Correct README and model documentation so the supported behavior is not overstated.

## Current launch decision

**Recommendation: do not begin a broad enterprise launch or promise cross-platform enforcement yet.** The planning baseline is Linux/NFQUEUE; restore a reproducible build/test environment and prove active packet blocking and its recovery behavior before pilot. The current repository is suitable for focused product hardening and a controlled lab pilot after those gates, not for an unqualified enterprise GA claim.
