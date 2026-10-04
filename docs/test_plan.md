# Test Plan for Firewall Project

## Scope
- Unit tests for core packet‑filter engine (C++/Python bindings)
- Integration tests for management API (REST)
- End‑to‑end tests using Docker Compose emulating multi‑node deployment

## Test Matrix
| Layer | Framework | Coverage Goal |
|-------|-----------|---------------|
| Unit  | GoogleTest / pytest | 85 % |
| Integration | pytest + requests | 80 % |
| E2E | Testcontainers (Java) or Docker Compose + k6 | 75 % |

## Execution
```bash
# Run unit tests
cd core && make test

# Run integration tests
cd ../api && pytest -m integration

# Run E2E tests (requires Docker)
docker compose -f tests/e2e/docker-compose.yml up --abort-on-container-exit
```

## Reporting
- JUnit XML reports stored in `reports/` directory
- CI job uploads artifacts to GitHub Actions
