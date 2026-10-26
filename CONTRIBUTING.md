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

### Every commit references a task

A conventional-commit subject is not sufficient. Each commit must carry an engram
task reference, conventionally as a trailer:

```
feat: derive package fields from the stored report

Refs: [e8daa2e9-8bb2-44a8-8248-08a9b097920e]
```

Two measured facts about the tooling, because both surprise people:

- `engram validate commit` checks that a *referenced* task exists in **this
  repository's** engram workspace and has context and reasoning attached. It does
  **not** require the message to reference anything — a message with no task UUID
  passes. `transparenz-server-oss` and `transparenz-server` have separate
  workspaces, so an OSS task UUID does not validate in the other repo.
- The engram hook installed by `engram validate hook install` lands in
  `.git/hooks`, which is per-clone: it does not survive a fresh checkout, and it
  is not used at all in a repository that sets `core.hooksPath`. Because of that,
  the task-reference check is enforced by hand in the local `commit-msg` hook
  here, and by a version-controlled `.githooks/commit-msg` in
  `transparenz-server`.

If a commit is rejected for a missing reference, add the trailer. Do not use
`--no-verify`: the reference is what makes the reasoning reviewable later.

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
