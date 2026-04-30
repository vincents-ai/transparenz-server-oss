# Transparenz Server OSS

**Open-source EU CRA/NIS2 Compliance Reporting Server**

AGPL-3.0 licensed edition of the Transparenz compliance server. Provides core CRA Art. 10 functionality: SBOM management, vulnerability scanning, VEX lifecycle, CSAF 2.0 advisories, SLA tracking, and coordinated disclosure.

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

## Commercial Edition

The commercial edition (`transparenz-server`) adds:
- ENISA EVD API submission pipeline
- Greenbone vulnerability scanner integration
- SBOM webhook ingestion (CI/CD)
- Usage telemetry and analytics
- PDF report generation (BSI TR-03116)
- Ed25519 signing key management
- Per-org rate limiting and billing tiers
- NixOS airgap appliance deployment

## Quickstart

### Prerequisites

- Go 1.25+
- PostgreSQL 14+
- [golang-migrate](https://github.com/golang-migrate/migrate)

### Setup

```bash
# Clone and enter development environment
nix develop

# Configure environment
cp .env.example .env
# Edit .env — set DATABASE_URL, JWT_SECRET

# Create database and schema
psql -U postgres -c "CREATE DATABASE transparenz;"
psql -U postgres -d transparenz -c "CREATE SCHEMA IF NOT EXISTS compliance;"

# Run database migrations
make migrate-up

# Start the server
make dev
```

### Verify

```bash
curl http://localhost:8080/health
curl http://localhost:8080/readyz
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Gin HTTP Router                  │
│            (JWT + Tenant Middleware)              │
├─────────┬───────────┬──────────┬───────────┬───────┤
│ Scan   │ Compli-    │ VEX      │ Export    │Alerts │
│ API    │ ance API   │ API      │ API       │ SSE   │
├─────────┴───────────┴──────────┴───────────┴───────┤
│              Service Layer                          │
│  (CSAF Generator, SLA Calculator, VEX Service,    │
│   VulnzMatcher, Disclosure Service)               │
├───────────────────────────────────────────────────┤
│              Repository Layer                       │
│  (TenantBackend: RLS / Schema-per-Org)            │
├───────────────────────────────────────────────────┤
│              PostgreSQL 16                         │
│  (compliance schema, multi-tenant isolation)     │
└───────────────────────────────────────────────────┘
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/scan | Create vulnerability scan |
| GET | /api/scans | List scans |
| GET | /api/scans/:id/vulnerabilities | Get scan vulnerabilities |
| POST | /api/sboms/upload | Upload SBOM |
| GET | /api/sboms | List SBOMs |
| GET | /api/sboms/:id | Get SBOM |
| GET | /api/sboms/:id/download | Download SBOM |
| DELETE | /api/sboms/:id | Delete SBOM |
| GET | /api/vulnerabilities | List vulnerabilities |
| GET | /api/vulnerabilities/:cve | Get vulnerability |
| GET | /api/compliance/status | Compliance status |
| GET | /api/compliance/sla | SLA tracking |
| GET | /api/enisa/submissions | List ENISA submissions |
| GET | /api/enisa/submissions/:id | Get ENISA submission |
| GET | /api/alerts/stream | SSE alert stream |
| POST | /api/disclosures | Create disclosure |
| GET | /api/disclosures | List disclosures |
| GET | /api/feeds/status | Feed sync status |
| GET | /api/csaf/provider-metadata.json | CSAF provider metadata |
| GET | /api/csaf/advisories | List CSAF advisories |
| POST | /api/vex | Create VEX statement |
| GET | /api/vex | List VEX statements |
| GET | /api/audit/verify | Verify audit chain |
| GET | /api/export/audit | Export audit CSV |
| GET | /api/export/enriched-sbom/:id | Export enriched SBOM |

## Testing

```bash
# Unit tests
make test

# Integration tests (requires Docker/Podman + PostgreSQL)
DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" \
INTEGRATION_SERVER_ROOT=$(pwd) \
INTEGRATION_AUTH_ROOT=../auth-service \
go test -tags integration -count=1 -timeout 40m ./tests/integration/...
```

## License

AGPL-3.0. See [LICENSE](LICENSE).

Commercial licensing is available for those who do not wish to comply with AGPL-3.0 requirements.
