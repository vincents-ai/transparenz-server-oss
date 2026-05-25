# Transparenz Server OSS

**Open-source EU CRA/NIS2 Compliance Reporting Server**

AGPL-3.0 licensed edition of the Transparenz compliance server. Provides core CRA Art. 10 functionality: SBOM management, vulnerability scanning, VEX lifecycle, CSAF 2.0 advisories, SLA tracking, and coordinated disclosure.

This repo is also the **single source of truth** for shared code used by the commercial edition (`transparenz-server`), which imports models, repositories, services, middleware, interfaces, and jobs via Go module dependency.

## Vulnerability Disclosure Pipeline

The OSS server provides manual-scan vulnerability detection:

```
  Feed API     VulnzSync   [manual]     Scan       SLA Calc    Alert
  (NVD/OSV/ ──▶ Service  ──▶ trigger ──▶ Worker ──▶ Service ──▶ Service
   EUVD/KEV)    (6h tick)   required     (5s poll)  (1m tick)   (30s tick)
       ↓            ↓            ↓            ↓           ↓          ↓
  Published    Ingested     Operator     Matched    Deadline   Operator
   (T-0)        (T-1)      must act (T-2) (T-3)    set (T-4)  alerted (T-5)
```

| Stage | Component | Default Interval | Latency |
|-------|-----------|-----------------|----------|
| Feed sync | `VulnzSyncService` | **6 hours** | 0–6h |
| Scan trigger | Manual `POST /api/scan` | — | **∞ (operator)** |
| Scan processing | `ScanWorker` | 5s queue poll | 5–60s |
| SLA calculation | `SlaCalculator` | 1 minute | 0–60s |
| Alert notification | `AlertService` | 30 seconds | 0–30s |
| **Total worst case** | | | **≥6h + manual** |

### Differences from Commercial Edition

| Feature | OSS | Commercial |
|---------|-----|------------|
| Feed sync interval | 6 hours | **15 minutes** |
| Auto-rescan on feed update | ❌ Manual scan required | ✅ `AutoRescanHook` |
| SLA erosion (Critical 72h) | 8.4% ⚠️ | **0.4%** ✅ |
| SLA erosion (KEV 24h) | 25.2% ❌ | **1.2%** ✅ |
| KEV-only rescan mode | N/A | Configurable |
| Rescan cooldown | N/A | 30 min per SBOM |
| Greenbone integration | ❌ | ✅ |
| SBOM webhook ingestion | ❌ | ✅ |
| ENISA API submission | Read-only | Full submit |
| Usage telemetry | Basic | Full analytics |

### SLA Deadline Fix (v0.1.6+)

SLA deadlines are now anchored to the CVE's `discovered_at` timestamp, not
`time.Now()`. This ensures ENISA/NIS2/CRA compliance — the SLA clock starts
when the CVE is published, not when the calculator happens to run.

### E2E Pipeline Test

```bash
cd tests/k6
nix-shell -p k6 -p postgresql --run './run-e2e.sh'
```

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
│  │ transparenz-server-oss (this repo) via go.mod require   │ │
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
require github.com/transparenz-server-oss v0.1.6
```

Published versions are consumed via `go get` -- no `replace` directive is needed.

Commercial extensions (not in OSS):
- `internal/services/auto_rescan.go` — PostSyncHook that auto-triggers scans after feed sync
- `internal/config/config.go` — 15m sync interval, `AUTO_RESCAN` flag
- `cmd/server/main.go` — Wires AutoRescanHook into VulnzSyncService

See [Pipeline Differences](#differences-from-commercial-edition) for the full comparison.

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
| GET | `/api/audit/verify` | Verify audit chain integrity |
| GET | `/api/alerts/stream` | SSE real-time alert stream |
| GET | `/api/orgs/support-period` | Get support period |
| GET | `/api/feeds/status` | Vulnerability feed sync status |
| GET | `/api/disclosures` | List disclosures |
| GET | `/api/disclosures/:id` | Get disclosure |
| GET | `/api/csaf/provider-metadata.json` | CSAF provider metadata |
| GET | `/api/csaf/advisories` | List CSAF advisories |
| GET | `/api/csaf/advisories/:id` | Get CSAF advisory |
| GET | `/api/csaf/changes.csv` | Download changes.csv |
| GET | `/api/enisa/submissions` | List ENISA submissions |
| GET | `/api/enisa/submissions/:id` | Get ENISA submission |
| GET | `/api/enisa/submissions/:id/download` | Download ENISA submission |
| POST | `/api/enisa/submit` | **Returns 403** (commercial only) |
| POST | `/api/vex` | Create VEX statement |
| GET | `/api/vex` | List VEX statements |
| GET | `/api/metrics` | Prometheus metrics (basic auth) |

### Compliance Officer (requires compliance_officer role)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/compliance/exploited` | Report exploited vulnerability |
| GET | `/api/export/audit` | Export audit trail (CSV) |
| GET | `/api/export/enriched-sbom/:sbom_id` | Export enriched SBOM |
| POST | `/api/vex/:id/approve` | Approve VEX statement |
| POST | `/api/vex/:id/publish` | Publish VEX statement |
| POST | `/api/disclosures` | Create disclosure |
| PUT | `/api/disclosures/:id/status` | Update disclosure status |
| GET | `/api/disclosures/sla-compliance` | Check SLA compliance |

### Admin (requires admin role)
| Method | Path | Description |
|--------|------|-------------|
| PUT | `/api/orgs/support-period` | Update support period |
| POST | `/api/csaf/feeds/ingest` | Trigger CSAF feed ingestion |

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

See `.env.example` for the complete list with descriptions and defaults.

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (add `?sslmode=require` for production) |
| `JWT_SECRET` | JWT signing secret (min 32 chars). Generate: `openssl rand -hex 32` |
| `ENCRYPTION_KEY` | AES-256 key for data at rest (exactly 32 chars). Generate: `openssl rand -hex 16` |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `LOG_LEVEL` | `info` | Logging verbosity: `debug`, `info`, `warn`, `error` |
| `BASE_URL` | | Public base URL for CSAF canonical URLs |
| `MAX_SBOM_SIZE` | `10485760` | Max SBOM upload size in bytes (10 MB) |
| `MULTI_TENANT_MODE` | `shared` | Tenant isolation: `shared`, `schema_per_org`, `instance_per_org` |
| `GIN_MODE` | `debug` | Gin mode (`release` for production) |

### Multi-Tenancy

| Variable | Description |
|----------|-------------|
| `INSTANCE_DSN_FILE` | Path to JSON file mapping org IDs to DSNs (0600 perms) |
| `INSTANCE_DSNS` | Inline JSON org ID to DSN mapping |

### Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `GREENBONE_ENABLED` | `false` | Greenbone scanner integration |
| `SBOM_WEBHOOK_ENABLED` | `false` | SBOM ingestion webhooks |
| `TELEMETRY_ENABLED` | `true` | OpenTelemetry analytics |
| `VULNZ_DISABLED` | `false` | Disable vulnerability feed syncing |
| `RATE_LIMIT_DISABLED` | `false` | Disable per-IP rate limiting |

### Feeds & SLA

| Variable | Default | Description |
|----------|---------|-------------|
| `VULNZ_WORKSPACE_PATH` | `/var/lib/vulnz/workspace` | Vulnerability feed data directory |
| `VULNZ_SYNC_INTERVAL` | `6h` | Feed sync interval (commercial default: 15m) |
| `ALERT_TICK_INTERVAL` | `30s` | Alert check interval |
| `SLA_TICK_INTERVAL` | `1m` | SLA calculator interval |
| `APPROACHING_SLA_THRESHOLD` | `6h` | Warning threshold for approaching deadlines |
| `ENISA_TIMEOUT` | `30s` | ENISA API timeout |
| `ENISA_RETRY_INTERVAL` | `15m` | ENISA retry backoff |
| `ENISA_MAX_RETRIES` | `5` | Max ENISA submission retries |
| `JOB_QUEUE_POLL_INTERVAL` | `5s` | Background job poll interval |

### Metrics

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_USER` | | Basic auth user for `/metrics` |
| `METRICS_PASSWORD` | | Basic auth password for `/metrics` |

### CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | `http://localhost:8080` | Comma-separated allowed origins |

### Enrichment

| Variable | Default | Description |
|----------|---------|-------------|
| `ENRICHMENT_DB_PATH` | `/var/lib/enrichment/enrichment.db` | Enrichment database path |
| `ENRICHMENT_AUTO_INIT` | `true` | Auto-initialize enrichment DB |

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
