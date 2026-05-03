# Contributing to Transparenz Server OSS

Thank you for your interest in contributing! This project implements EU CRA/NIS2 compliance tooling and quality matters.

## Prerequisites

- **Go 1.25+** — [go.dev/dl](https://go.dev/dl/)
- **PostgreSQL 16** — for integration tests
- **Nix** (optional) — reproducible builds via `nix develop`

## Building

```bash
# With Nix (recommended)
nix develop --command bash -c "go build ./..."

# Without Nix
go build ./...
```

## Testing

```bash
# Unit tests
go test ./...

# Integration tests (requires PostgreSQL)
DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" \
go test -tags integration -count=1 -timeout 10m ./tests/integration/...

# BDD tests (godog)
go test -tags bdd -count=1 -timeout 10m ./bdd/...

# E2E test
DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" \
go test -tags e2e -count=1 -timeout 5m ./tests/e2e/...

# Lint
golangci-lint run ./...
```

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ENISA submission retry logic
fix: correct severity normalization for CVSS scores
docs: update API reference for VEX endpoints
test: add integration test for SBOM upload
refactor: extract scan worker interface
chore: update dependencies
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make changes and add tests
4. Ensure all tests pass: `make test`
5. Commit with conventional commit format
6. Open a PR against `main`

### PR Requirements

- All tests pass (unit + integration)
- `golangci-lint` passes
- New features include tests
- Bug fixes include regression tests
- Documentation updated if needed

## Code Style

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Error messages should not start with a capital letter
- All functions that do I/O must accept `context.Context` as first parameter
- Use `pkg/` for shared code, `internal/` for private code
- GORM column tags required for fields with acronyms (e.g., `gorm:"column:sbom_component_purl"`)

## Architecture

```
internal/          # Private to this binary
  api/rest/        # HTTP handlers
  config/          # Configuration loading
pkg/               # Shared across modules
  models/          # GORM models
  repository/      # Data access layer
  services/        # Business logic
  middleware/       # Gin middleware
  interfaces/      # DI interfaces
```

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.

## Questions?

Open a [GitHub Discussion](https://github.com/vincents-ai/transparenz-server-oss/discussions) or reach out at security@vincents.ai.
