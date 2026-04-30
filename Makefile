.PHONY: run build test lint migrate-up migrate-down migrate-create migrate-force migrate-version clean docker-build docker-run k8s-apply k8s-delete help self-sbom self-scan self-report dev grype-db generate-mocks

## generate-mocks: Generate mocks for interfaces
generate-mocks:
	@echo "Generating mocks..."
	@mkdir -p internal/interfaces/mocks
	@$(go env GOPATH)/bin/mockgen -source=internal/interfaces/interfaces.go -destination=internal/interfaces/mocks/mocks.go -package=mocks
	@echo "Mocks generated at internal/interfaces/mocks/mocks.go"

# Variables
BINARY_NAME=transparenz-server
MAIN_PATH=./cmd/server
MIGRATIONS_PATH=./migrations
DATABASE_URL ?= postgres://user:pass@localhost:5432/transparenz?search_path=compliance

## help: Display this help message
help:
	@echo "Available commands:"
	@echo "  make run             - Run the server in development mode"
	@echo "  make dev             - Start full dev environment (process-compose)"
	@echo "  make build           - Build the server binary"
	@echo "  make test            - Run all tests"
	@echo "  make lint            - Run linter (golangci-lint)"
	@echo "  make grype-db        - Download Grype vulnerability database"
	@echo "  make migrate-up      - Run database migrations"
	@echo "  make migrate-down    - Rollback database migrations"
	@echo "  make migrate-create  - Create new migration (interactive)"
	@echo "  make migrate-force   - Force migration version (recovery)"
	@echo "  make migrate-version - Show current migration version"
	@echo "  make clean           - Clean build artifacts"

## run: Run the server
run:
	@echo "Starting $(BINARY_NAME)..."
	go run $(MAIN_PATH)/main.go

## dev: Start full dev environment
dev:
	@command -v process-compose >/dev/null 2>&1 || \
		(echo "process-compose not found. Install with: nix profile install nixpkgs#process-compose" && exit 1)
	process-compose up

## grype-db: Download Grype vulnerability database
grype-db:
	@echo "Downloading Grype vulnerability database..."
	go run ./cmd/grype-db-update/main.go

## build: Build the server binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	go build -o bin/$(BINARY_NAME) $(MAIN_PATH)/main.go
	@echo "Binary created at bin/$(BINARY_NAME)"

## test: Run all tests
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...
	@echo "Coverage report written to coverage.out"

## test-coverage: Run tests with coverage report
test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

## lint: Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Install with:"; \
		echo "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

## migrate-up: Run database migrations
migrate-up:
	@echo "Running migrations..."
	@if command -v migrate >/dev/null 2>&1; then \
		migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" up; \
	else \
		echo "golang-migrate not found. Install with:"; \
		echo "  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"; \
		echo "Or use full path: /home/shift/go/bin/migrate"; \
		exit 1; \
	fi

## migrate-down: Rollback database migrations
migrate-down:
	@echo "Rolling back migrations..."
	@if command -v migrate >/dev/null 2>&1; then \
		migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" down 1; \
	else \
		echo "golang-migrate not found. Install with:"; \
		echo "  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"; \
		echo "Or use full path: /home/shift/go/bin/migrate"; \
		exit 1; \
	fi

## migrate-create: Create new migration
migrate-create:
	@read -p "Enter migration name: " name; \
	if command -v migrate >/dev/null 2>&1; then \
		migrate create -ext sql -dir $(MIGRATIONS_PATH) -seq $$name; \
	else \
		echo "golang-migrate not found. Install with:"; \
		echo "  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"; \
		echo "Or use full path: /home/shift/go/bin/migrate"; \
		exit 1; \
	fi

## migrate-force: Force migration version (recovery only)
migrate-force:
	@read -p "Enter version to force: " version; \
	if command -v migrate >/dev/null 2>&1; then \
		migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" force $$version; \
	else \
		echo "golang-migrate not found. Install with:"; \
		echo "  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"; \
		echo "Or use full path: /home/shift/go/bin/migrate"; \
		exit 1; \
	fi

## migrate-version: Show current migration version
migrate-version:
	@if command -v migrate >/dev/null 2>&1; then \
		migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" version; \
	else \
		echo "golang-migrate not found. Install with:"; \
		echo "  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"; \
		echo "Or use full path: /home/shift/go/bin/migrate"; \
		exit 1; \
	fi

## clean: Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -f coverage.out
	@echo "Clean complete"

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t transparenz-server:latest .

## docker-run: Run with docker-compose
docker-run:
	@echo "Starting services with docker compose..."
	docker compose up -d

## k8s-apply: Apply Kubernetes manifests
k8s-apply:
	@echo "Applying Kubernetes manifests..."
	kubectl apply -k deploy/kubernetes

## k8s-delete: Delete Kubernetes manifests
k8s-delete:
	@echo "Deleting Kubernetes manifests..."
	kubectl delete -k deploy/kubernetes

release-manifest:
	@echo '{"version":"$(shell git describe --tags --always --dirty)","git_sha":"$(shell git rev-parse HEAD)","go_module_hash":"$(shell go mod graph | sha256sum | cut -d' ' -f1)","binary_sha256":"$(shell CGO_ENABLED=0 go build -o /tmp/transparenz-server ./cmd/server/ && sha256sum /tmp/transparenz-server | cut -d' ' -f1)"}' > release-manifest.json

verify-release: release-manifest
	@if [ -z "$$(cat release-manifest.json 2>/dev/null)" ]; then echo "Error: release-manifest.json not found"; exit 1; fi
	@echo "Verifying release against manifest..."
	CGO_ENABLED=0 go build -o /tmp/transparenz-server-verify ./cmd/server/ && \
		VERIFY_HASH=$$(sha256sum /tmp/transparenz-server-verify | cut -d' ' -f1) && \
		EXPECTED_HASH=$$(python3 -c "import json; print(json.load(open('release-manifest.json'))['binary_sha256'])") && \
		if [ "$$VERIFY_HASH" = "$$EXPECTED_HASH" ]; then echo "OK: binary matches manifest"; else echo "FAIL: hash mismatch"; exit 1; fi
	@rm -f /tmp/transparenz-server /tmp/transparenz-server-verify

self-sbom:
	@echo "=== Generating Transparenz Server Self-SBOM ==="
	@chmod +x scripts/self-sbom.sh
	./scripts/self-sbom.sh ./transparenz-server cyclonedx-json sbom-output.json

self-scan:
	@echo "=== Scanning Transparenz Server itself ==="
	@echo "Prerequisites: Server running at localhost:8080, SBOM generated via 'make self-sbom'"
	@echo ""
	@echo "Steps:"
	@echo "  1. Start the server:  make run"
	@echo "  2. Generate SBOM:     make self-sbom"
	@echo "  3. Get JWT token:     curl -sf -X POST http://localhost:8080/api/auth/token -H 'Content-Type: application/json' -d '{\"email\":\"demo@transparenz.local\",\"password\":\"dev\"}' | jq -r .token"
	@echo "  4. Upload SBOM:       curl -sf -X POST -H 'Authorization: Bearer <TOKEN>' -F 'file=@sbom-output.json' -F 'format=cyclonedx-json' http://localhost:8080/api/sboms/upload"
	@echo "  5. Trigger scan:      curl -sf -X POST -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{\"sbom_id\":\"<SBOM_ID>\"}' http://localhost:8080/api/scan"
	@echo ""

self-report:
	@echo "=== Generating Self-Compliance Report ==="
	@echo "Prerequisites: Server running, scan completed with vulnerabilities found"
	@echo ""
	@echo "Steps:"
	@echo "  1. List vulnerabilities: curl -sf -H 'Authorization: Bearer <TOKEN>' http://localhost:8080/api/vulnerabilities"
	@echo "  2. Check compliance:     curl -sf -H 'Authorization: Bearer <TOKEN>' http://localhost:8080/api/compliance/status"
	@echo "  3. Export audit trail:   curl -sf -H 'Authorization: Bearer <TOKEN>' http://localhost:8080/api/export/audit -o audit-report.pdf"
	@echo ""

.PHONY: self-sbom self-scan self-report

## migrate: Run database migrations
migrate: migrate-up
