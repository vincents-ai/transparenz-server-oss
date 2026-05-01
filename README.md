# Transparenz Server OSS

**Open-source EU CRA/NIS2 Compliance Reporting Server**

AGPL-3.0 licensed edition of the Transparenz compliance server. Provides core CRA Art. 10 functionality: SBOM management, vulnerability scanning, VEX lifecycle, CSAF 2.0 advisories, SLA tracking, and coordinated disclosure.

This repo is also the **single source of truth** for shared code used by the commercial edition (`transparenz-server`), which imports models, repositories, services, middleware, interfaces, and jobs via Go module dependency.

## Features

- **SBOM Management** — Upload CycloneDX/SPDX SBOMs, track vulnerability status
- **Vulnerability Scanning** — VulnzMatcher-based scanning (no Grype dependency)
- **VEX Lifecycle** — Create, approve, publish Vulnerability Exploitability eXchange statements
- **CSAF 2.0** — Generate and distribute security advisories per Common Security Advisory Framework
- **SLA Tracking** — Automated deadline enforcement: 24h exploited, 72h critical (CRA Art. 10)
- **Coordinated Disclosure** — Upstream notification workflow with 90-day response window
- **Audit Trail** — Compliance event tracking with verification
- **Real-time Alerts** — SSE-based vulnerability and SLA alerts
- **Multi-Tenant Isolation** — Row-Level Security (RLS) and schema-per-org
- **ENISA Read-Only** — List and download ENISA submissions
- **Metrics** — Prometheus `/metrics` endpoint with basic auth

## Commercial Edition

The commercial edition (`transparenz-server`) layers on top of this repo:
- ENISA EVD API submission pipeline
- Greenbone vulnerability scanner integration
- SBOM webhook ingestion (CI/CD)
- Usage telemetry and analytics
- PDF report generation (BSI TR-03116)
- Ed25519 signing key management
- Per-org rate limiting and billing tiers
- NixOS airgap appliance deployment

See [Architecture: OSS vs Commercial](#oss-vs-commercial-architecture) below.

## Quickstart

### Prerequisites

- Go 1.25+
- PostgreSQL 14+
- Podman or Docker (for integration tests)

### Setup

```bash
# Clone
git clone https://github.com/transparenz/transparenz-server-oss.git
cd transparenz-server-oss

# Configure environment
export DATABASE_URL="postgres://user:pass@localhost:5432/transparenz?sslmode=disable"
export JWT_SECRET="change-me-to-at-least-32-characters"
export PORT=8080

# Create database and schema
psql -c "CREATE DATABASE transparenz;"
psql -d transparenz -c "CREATE SCHEMA IF NOT EXISTS compliance;"

# Run migrations
go run ./cmd/migrate ./migrations

# Start the server
go run ./cmd/server
```

### Verify

```bash
curl http://localhost:8080/health
curl http://localhost:8080/readyz
```

## Project Structure

```
transparenz-server-oss/
├── cmd/
│   ├── server/main.go          # Application entrypoint (Cobra + Gin)
│   └── migrate/main.go         # Standalone migration runner
├── pkg/                        # Public packages (importable by commercial edition)
│   ├── models/                 # GORM database models
│   ├── repository/             # Data access layer (TenantBackend, scopes)
│   ├── services/               # Business logic
│   ├── interfaces/             # Service interfaces + mocks
│   ├── middleware/              # JWT, RBAC, tenant, rate limiting
│   └── jobs/                   # Background job queue
├── internal/
│   ├── api/rest/               # REST API handlers (OSS routes only)
│   └── config/                 # Configuration (Viper, Zap logger)
├── migrations/                 # SQL migrations (000001–000041)
├── bdd/                        # BDD test suite (godog)
│   ├── features/               # Gherkin feature files (13 features, 82 scenarios)
│   ├── testcontext/            # Test infrastructure (container, DB, auth, app wiring)
│   └── *_steps.go              # Step definitions
├── tests/integration/          # Integration tests (42 tests)
├── Makefile                    # Build, test, lint commands
├── flake.nix                   # Nix flake for reproducible builds
├── go.mod                      # github.com/transparenz/transparenz-server-oss
└── LICENSE                     # AGPL-3.0
```

### Why `pkg/` instead of `internal/`?

Go's `internal/` package restriction prevents other modules from importing internal packages. Since the commercial `transparenz-server` imports shared code from this repo, all shared packages live in `pkg/`. Only the REST handlers and configuration remain in `internal/` — these are OSS-specific and not imported by the commercial edition.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Gin HTTP Router                  │
│            (JWT + Tenant Middleware)              │
├─────────┬───────────┬──────────┬───────────┬───────┤
│ Scan   │ Compli-    │ VEX      │ Export    │Alerts │
│ API    │ ance API   │ API      │ API       │ SSE   │
├─────────┴───────────┴──────────┴───────────┴───────┤
│              Service Layer (pkg/services)          │
│  CSAF Generator · SLA Calculator · VEX Service   │
│  VulnzMatcher · Disclosure Service · ScanWorker  │
├───────────────────────────────────────────────────┤
│           Repository Layer (pkg/repository)        │
│     TenantBackend: RLS / Schema-per-Org           │
├───────────────────────────────────────────────────┤
│              PostgreSQL 14+                        │
│     compliance schema · multi-tenant isolation    │
└───────────────────────────────────────────────────┘
```

## OSS vs Commercial Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ transparenz-server (commercial)                               │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ Commercial-only REST handlers:                           │ │
│  │ greenbone.go · sbom_webhook.go · signing.go              │ │
│  │ telemetry.go · pdf export · rate limiting                │ │
│  └─────────────────────────────────────────────────────────┘ │
│                           │                                   │
│                           ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ transparenz-server-oss (this repo) via go.mod replace   │ │
│  │                                                          │ │
│  │ pkg/models · pkg/repository · pkg/services               │ │
│  │ pkg/interfaces · pkg/middleware · pkg/jobs               │ │
│  │                                                          │ │
│  │ Also includes: OSS REST handlers + config + migrations   │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

The commercial `go.mod` contains:
```
replace github.com/transparenz/transparenz-server-oss => ../transparenz-server-oss
```

All shared code is maintained in this repo. The commercial edition only contains:
- Commercial-only REST handlers (Greenbone, webhooks, signing, telemetry, PDF)
- Commercial BDD tests
- cmd/server/main.go with full route wiring
- Repository and service test files

## API Endpoints

### Public (no auth)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness probe |
| GET | `/readyz` | Readiness probe |
| GET | `/.well-known/csaf/:org/provider-metadata.json` | CSAF provider discovery |
| GET | `/.well-known/csaf/:org/changes.csv` | CSAF change tracking |
| GET | `/.well-known/csaf/:org/:id.json` | CSAF advisory document |

### Authenticated (JWT required)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/sboms/upload` | Upload SBOM (CycloneDX/SPDX) |
| GET | `/api/sboms` | List SBOMs |
| GET | `/api/sboms/:id` | Get SBOM |
| GET | `/api/sboms/:id/download` | Download SBOM |
| DELETE | `/api/sboms/:id` | Delete SBOM |
| POST | `/api/scan` | Trigger vulnerability scan |
| GET | `/api/scans` | List scans |
| GET | `/api/scans/:id/vulnerabilities` | Get scan vulnerabilities |
| GET | `/api/vulnerabilities` | List vulnerabilities |
| GET | `/api/vulnerabilities/:cve` | Get vulnerability by CVE |
| GET | `/api/compliance/status` | Compliance status and SLA tracking |
| GET | `/api/compliance/sla` | List SLA tracking entries |
| POST | `/api/compliance/exploited` | Report exploited vulnerability |
| POST | `/api/vex` | Create VEX statement |
| GET | `/api/vex` | List VEX statements |
| PUT | `/api/vex/:id/approve` | Approve VEX statement |
| PUT | `/api/vex/:id/publish` | Publish VEX statement |
| POST | `/api/disclosures` | Create disclosure |
| GET | `/api/disclosures` | List disclosures |
| GET | `/api/disclosures/:id` | Get disclosure |
| PUT | `/api/disclosures/:id/status` | Update disclosure status |
| GET | `/api/csaf/provider-metadata.json` | CSAF provider metadata |
| GET | `/api/csaf/advisories` | List CSAF advisories |
| GET | `/api/csaf/advisories/:id` | Get CSAF advisory |
| GET | `/api/csaf/changes.csv` | Download changes.csv |
| GET | `/api/enisa/submissions` | List ENISA submissions |
| GET | `/api/enisa/submissions/:id` | Get ENISA submission |
| GET | `/api/enisa/submissions/:id/download` | Download ENISA submission |
| POST | `/api/enisa/submit` | **Returns 403** (commercial only) |
| GET | `/api/audit/verify` | Verify audit chain |
| GET | `/api/export/audit` | Export audit trail (CSV) |
| GET | `/api/export/enriched-sbom/:id` | Export enriched SBOM |
| GET | `/api/alerts/stream` | SSE alert stream |
| GET | `/api/orgs/support-period` | Get support period |
| PUT | `/api/orgs/support-period` | Update support period |
| GET | `/api/feeds/status` | Feed sync status |
| GET | `/metrics` | Prometheus metrics (basic auth) |

## Testing

### BDD Tests (82 scenarios)

```bash
# Run BDD tests (requires Podman/Docker)
DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" \
  go test -count=1 -timeout 15m -v ./bdd/...
```

Feature files cover: audit/auth, scan/vulnerability, VEX lifecycle, compliance/SLA, disclosure workflow, CSAF provider, CSAF well-known, export, alerts, edge cases, coordinated disclosure, admin org management.

### Integration Tests (42 tests)

```bash
# Run integration tests (requires Podman/Docker + auth-service)
DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" \
INTEGRATION_AUTH_ROOT=../auth-service \
  go test -count=1 -timeout 40m -tags integration ./tests/integration/...
```

### Unit Tests

```bash
make test
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `JWT_SECRET` | Yes | — | JWT signing secret (min 32 chars) |
| `PORT` | No | `8080` | HTTP listen port |
| `ENCRYPTION_KEY` | No | — | Data encryption at rest |
| `GIN_MODE` | No | `debug` | Gin mode (`release` for production) |
| `METRICS_USER` | No | — | Basic auth user for /metrics |
| `METRICS_PASSWORD` | No | — | Basic auth password for /metrics |

## EU CRA Compliance Mapping

| Article | Requirement | Implementation |
|---------|-------------|----------------|
| Art. 10(1) | Report exploited vulnerabilities within 24h | SLA tracking + compliance events |
| Art. 10(2) | Address critical vulnerabilities within 72h | SLA calculator + deadline enforcement |
| Art. 10(4) | Notify ENISA/CSIRT | ENISA submission (commercial), read-only listing (OSS) |
| Art. 11 | Document vulnerability handling | Compliance event audit trail |
| Art. 13 | Publish support period | Organization support period endpoint |
| Art. 14 | Coordinate vulnerability disclosure | Coordinated disclosure workflow |
| Art. 20 | Provide SBOM to authorities | SBOM upload/download + enriched export |
| Annex I | CSAF vulnerability advisories | CSAF 2.0 provider + well-known endpoints |

## License

AGPL-3.0. See [LICENSE](LICENSE).

Commercial licensing is available for those who do not wish to comply with AGPL-3.0 requirements. Contact the maintainers for details.
