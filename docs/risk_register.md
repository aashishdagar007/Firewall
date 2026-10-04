# Risk Register

## Identified Risks
| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Zero‑day vulnerability discovered post‑launch | Medium | Critical | Real‑time CVE feed → automated patch pipeline; 24 h SLA for critical fixes |
| Capacity shortfall under traffic surge | Low | High | Auto‑scaling policies (target CPU < 60 %); pre‑warm extra nodes 48 h before launch |
| Data‑loss during DR failover | Low | Critical | End‑to‑end snapshot testing every sprint; checksum verification |
| Regulatory compliance gap (e.g., GDPR) | Low | High | Pre‑launch audit by external advisor; compliance checklist in CI |
| Customer onboarding bottleneck | Medium | Medium | Dedicated onboarding engineer; self‑service portal with API key generation |

## Tracking
- Owner: Project Manager
- Review cadence: weekly
