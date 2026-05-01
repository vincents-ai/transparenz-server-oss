//go:build integration

package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

const (
	testJWTSecret     = "integration-test-secret-key-32chars!"
	testEncryptionKey = "01234567890123456789012345678901"
	authServicePort   = "18090"

	// env vars for custom paths (useful in nix develop)
	envServerRoot   = "INTEGRATION_SERVER_ROOT"
	envAuthRoot     = "INTEGRATION_AUTH_ROOT"
	envBSIDataPath  = "INTEGRATION_BSI_DATA_PATH"

	// Default evidence subdirectory name
	evidenceDirName = "evidence"
)

// ServerRoot returns the transparenz-server source directory.
func ServerRoot() string {
	if v := os.Getenv(envServerRoot); v != "" {
		return v
	}
	// Default: walk up from test directory to find go.mod
	wd, _ := os.Getwd()
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	return "."
}

// AuthRoot returns the auth-service source directory.
func AuthRoot() string {
	if v := os.Getenv(envAuthRoot); v != "" {
		return v
	}
	return "/home/shift/code/auth-service"
}

// BSIDataPath returns the path to BSI feed seed data (empty = skip seeding).
func BSIDataPath() string {
	return os.Getenv(envBSIDataPath)
}

// ---------------------------------------------------------------------------
// TestEnvironment — holds all running infrastructure for a test
// ---------------------------------------------------------------------------

// TestEnvironment manages the full stack: PostgreSQL + auth-service + transparenz-server.
// Create one per TestMain or per top-level test, then defer Teardown().
type TestEnvironment struct {
	PGContainer   testcontainers.Container
	PGURL         string
	AuthCmd       *exec.Cmd
	ServerCmd     *exec.Cmd
	ServerBaseURL string
	ServerPort    int
	AccessToken   string
	EvidenceDir   string
	T             *testing.T

	mu     sync.Mutex
	closed bool
}

// SetupTestEnvironment starts the full stack and returns a ready-to-use TestEnvironment.
// It:
//  1. Starts a PostgreSQL container
//  2. Runs migrations
//  3. Creates the auth schema
//  4. Optionally seeds BSI data
//  5. Starts auth-service
//  6. Starts transparenz-server
//  7. Registers a test user and obtains a JWT
//  8. Creates an evidence directory
func SetupTestEnvironment(t *testing.T, opts ...EnvOption) *TestEnvironment {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test")
	}

	if _, err := exec.LookPath("docker"); err != nil {
		if _, err := exec.LookPath("podman"); err != nil {
			t.Skip("Docker/Podman not available: skipping integration test")
		}
	}

	cfg := defaultEnvConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.SetupTimeout)
	defer cancel()

	// Evidence directory
	evidenceDir := filepath.Join(t.TempDir(), evidenceDirName)
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		t.Fatalf("failed to create evidence dir: %v", err)
	}

	// 1. PostgreSQL
	t.Log("=== Starting PostgreSQL container ===")
	pgContainer, pgURL := startPostgres(ctx, t)

	// 2. Migrations
	t.Log("=== Running database migrations ===")
	runMigrations(t, pgURL)

	// 3. Auth schema
	t.Log("=== Creating auth schema ===")
	createAuthSchema(t, pgURL)

	// 4. Optional BSI seed data
	if cfg.SeedBSIData {
		t.Log("=== Loading BSI feed seed data ===")
		loadSeedData(t, pgURL)
	}

	// 5. Auth service
	t.Log("=== Starting auth-service ===")
	authCmd := startAuthService(t, pgURL)
	waitForHealth(t, "http://127.0.0.1:"+authServicePort+"/health", 30*time.Second)

	// 6. Transparenz server
	serverPort := getFreePort(t)
	serverBaseURL := fmt.Sprintf("http://127.0.0.1:%d", serverPort)

	t.Log("=== Starting transparenz-server ===")
	serverCmd := startTransparenzServer(t, pgURL, serverPort, cfg.ExtraEnv)
	waitForHealth(t, serverBaseURL+"/health", 60*time.Second)

	// 7. Register user
	t.Log("=== Registering test user ===")
	accessToken := registerAndGetToken(t, cfg.UserName, cfg.UserEmail, cfg.UserPassword, cfg.OrgName)

	env := &TestEnvironment{
		PGContainer:   pgContainer,
		PGURL:         pgURL,
		AuthCmd:       authCmd,
		ServerCmd:     serverCmd,
		ServerBaseURL: serverBaseURL,
		ServerPort:    serverPort,
		AccessToken:   accessToken,
		EvidenceDir:   evidenceDir,
		T:             t,
	}

	// Write initial evidence manifest
	env.WriteJSONEvidence("manifest.json", map[string]interface{}{
		"created_at":      time.Now().UTC().Format(time.RFC3339),
		"test_name":       t.Name(),
		"server_base_url": serverBaseURL,
		"pg_url":          maskDBURL(pgURL),
		"server_root":     ServerRoot(),
	})

	t.Cleanup(func() { env.Teardown() })
	return env
}

// Teardown stops all services and the database container.
func (env *TestEnvironment) Teardown() {
	env.mu.Lock()
	defer env.mu.Unlock()
	if env.closed {
		return
	}
	env.closed = true

	if env.ServerCmd.Process != nil {
		env.ServerCmd.Process.Kill()
		env.ServerCmd.Wait()
	}
	if env.AuthCmd.Process != nil {
		env.AuthCmd.Process.Kill()
		env.AuthCmd.Wait()
	}
	if env.PGContainer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		env.PGContainer.Terminate(ctx)
	}
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// AuthedGet performs an authenticated GET request.
func (env *TestEnvironment) AuthedGet(path string) *http.Response {
	env.T.Helper()
	return env.authedRequest("GET", path, nil, "")
}

// AuthedGetWithToken performs a GET request with a specific token.
func (env *TestEnvironment) AuthedGetWithToken(path, token string) *http.Response {
	env.T.Helper()
	return env.authedRequestWithToken("GET", path, nil, "", token)
}

// AuthedPost performs an authenticated POST request with a JSON body.
func (env *TestEnvironment) AuthedPost(path string, body interface{}) *http.Response {
	env.T.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(MustMarshalJSON(body))
	}
	return env.authedRequest("POST", path, bodyReader, "application/json")
}

// AuthedPostRaw performs an authenticated POST with raw body and content type.
func (env *TestEnvironment) AuthedPostRaw(path string, body io.Reader, contentType string) *http.Response {
	env.T.Helper()
	return env.authedRequest("POST", path, body, contentType)
}

// AuthedPut performs an authenticated PUT request with a JSON body.
func (env *TestEnvironment) AuthedPut(path string, body interface{}) *http.Response {
	env.T.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(MustMarshalJSON(body))
	}
	return env.authedRequest("PUT", path, bodyReader, "application/json")
}

// AuthedDelete performs an authenticated DELETE request.
func (env *TestEnvironment) AuthedDelete(path string) *http.Response {
	env.T.Helper()
	return env.authedRequest("DELETE", path, nil, "")
}

// UnauthedGet performs an unauthenticated GET request.
func (env *TestEnvironment) UnauthedGet(path string) *http.Response {
	env.T.Helper()
	url := env.ServerBaseURL + path
	resp, err := http.Get(url)
	if err != nil {
		env.T.Fatalf("GET %s failed: %v", path, err)
	}
	return resp
}

func (env *TestEnvironment) authedRequest(method, path string, body io.Reader, contentType string) *http.Response {
	env.T.Helper()
	return env.authedRequestWithToken(method, path, body, contentType, env.AccessToken)
}

func (env *TestEnvironment) authedRequestWithToken(method, path string, body io.Reader, contentType, token string) *http.Response {
	env.T.Helper()
	url := env.ServerBaseURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		env.T.Fatalf("failed to create %s %s request: %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		env.T.Fatalf("%s %s request failed: %v", method, path, err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

// DecodeResponse decodes a response body into target and closes it.
func DecodeResponse(t *testing.T, resp *http.Response, target interface{}) {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("failed to decode response (%d): %s\nbody: %s", resp.StatusCode, err, string(body))
	}
}

// ReadBody reads and closes the response body, returning the bytes.
func ReadBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	return body
}

// AssertStatus asserts the HTTP status code and reads the body for error messages.
func AssertStatus(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		body := "<empty>"
		if resp.Body != nil {
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(data)
		}
		t.Fatalf("expected status %d, got %d: %s", expected, resp.StatusCode, body)
	}
}

// AssertStatusInRange asserts the status code is within [min, max].
func AssertStatusInRange(t *testing.T, resp *http.Response, min, max int) {
	t.Helper()
	if resp.StatusCode < min || resp.StatusCode > max {
		body := "<empty>"
		if resp.Body != nil {
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(data)
		}
		t.Fatalf("expected status %d-%d, got %d: %s", min, max, resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// Evidence collection helpers
// ---------------------------------------------------------------------------

// WriteEvidence writes a file to the evidence directory.
func (env *TestEnvironment) WriteEvidence(filename string, data []byte) {
	env.T.Helper()
	path := filepath.Join(env.EvidenceDir, filename)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		env.T.Fatalf("failed to create evidence subdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		env.T.Fatalf("failed to write evidence file %s: %v", filename, err)
	}
	env.T.Logf("Evidence written: %s (%d bytes)", filename, len(data))
}

// WriteJSONEvidence writes a JSON-marshaled file to the evidence directory.
func (env *TestEnvironment) WriteJSONEvidence(filename string, v interface{}) {
	env.T.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		env.T.Fatalf("failed to marshal evidence JSON %s: %v", filename, err)
	}
	env.WriteEvidence(filename, data)
}

// CaptureEvidence wraps a test action: performs the action, captures the response
// as JSON evidence, and asserts the status code. Returns the raw body bytes.
func (env *TestEnvironment) CaptureEvidence(evidenceName string, resp *http.Response) []byte {
	env.T.Helper()
	body := ReadBody(env.T, resp)
	env.WriteEvidence(evidenceName, body)
	return body
}

// EvidencePath returns the full path for an evidence file.
func (env *TestEnvironment) EvidencePath(filename string) string {
	return filepath.Join(env.EvidenceDir, filename)
}

// ---------------------------------------------------------------------------
// SBOM helpers
// ---------------------------------------------------------------------------

// UploadSBOM uploads an SBOM and returns the parsed response.
func (env *TestEnvironment) UploadSBOM(filename string, sbomData []byte) uploadResponse {
	env.T.Helper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		env.T.Fatalf("failed to create form file: %v", err)
	}
	if _, err := part.Write(sbomData); err != nil {
		env.T.Fatalf("failed to write SBOM data: %v", err)
	}
	if err := writer.Close(); err != nil {
		env.T.Fatalf("failed to close multipart writer: %v", err)
	}

	resp := env.AuthedPostRaw("/api/sboms/upload", &buf, writer.FormDataContentType())
	body := ReadBody(env.T, resp)
	AssertStatus(env.T, resp, http.StatusCreated)

	var upResp uploadResponse
	if err := json.Unmarshal(body, &upResp); err != nil {
		env.T.Fatalf("failed to decode upload response: %v\nbody: %s", err, string(body))
	}

	env.WriteJSONEvidence(fmt.Sprintf("upload-%s.json", upResp.ID), upResp)
	env.T.Logf("SBOM uploaded: id=%s filename=%s format=%s sha256=%s",
		upResp.ID, upResp.Filename, upResp.Format, upResp.SHA256)
	return upResp
}

// ListSBOMs lists all SBOMs.
func (env *TestEnvironment) ListSBOMs() listSBOMsResponse {
	env.T.Helper()
	resp := env.AuthedGet("/api/sboms")
	var result listSBOMsResponse
	DecodeResponse(env.T, resp, &result)
	return result
}

// DownloadSBOM downloads an SBOM by ID.
func (env *TestEnvironment) DownloadSBOM(sbomID string) json.RawMessage {
	env.T.Helper()
	resp := env.AuthedGet("/api/sboms/" + sbomID + "/download")
	body := ReadBody(env.T, resp)
	AssertStatus(env.T, resp, http.StatusOK)
	env.WriteEvidence(fmt.Sprintf("download-%s.json", sbomID), body)
	return json.RawMessage(body)
}

// DeleteSBOM deletes an SBOM by ID.
func (env *TestEnvironment) DeleteSBOM(sbomID string) {
	env.T.Helper()
	resp := env.AuthedDelete("/api/sboms/" + sbomID)
	AssertStatus(env.T, resp, http.StatusNoContent)
}

// CreateScan creates a scan for an SBOM.
func (env *TestEnvironment) CreateScan(sbomID string) createScanResponse {
	env.T.Helper()
	resp := env.AuthedPost("/api/scan", map[string]string{"sbom_id": sbomID})
	body := ReadBody(env.T, resp)

	if resp.StatusCode != http.StatusAccepted {
		env.T.Fatalf("create scan returned status %d: %s", resp.StatusCode, string(body))
	}

	var scanResp createScanResponse
	if err := json.Unmarshal(body, &scanResp); err != nil {
		env.T.Fatalf("failed to decode scan response: %v\nbody: %s", err, string(body))
	}

	env.WriteJSONEvidence(fmt.Sprintf("scan-%s.json", scanResp.ScanID), scanResp)
	return scanResp
}

// WaitForScanCompletion polls until the scan is completed or failed.
// Returns the number of vulnerabilities found.
func (env *TestEnvironment) WaitForScanCompletion(scanID string, timeout time.Duration) int {
	env.T.Helper()

	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 5 * time.Second}

	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", env.ServerBaseURL+"/api/scans?limit=100", nil)
		if err != nil {
			env.T.Fatalf("failed to create list scans request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+env.AccessToken)

		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			time.Sleep(2 * time.Second)
			continue
		}

		var listResp listScansResponse
		if err := json.Unmarshal(body, &listResp); err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		for _, scan := range listResp.Data {
			if scan.ID == scanID {
				switch scan.Status {
				case "completed":
					env.WriteJSONEvidence(fmt.Sprintf("scan-completed-%s.json", scanID), listResp)
					env.T.Logf("Scan %s completed with %d vulnerabilities", scanID, scan.VulnerabilitiesFound)
					return scan.VulnerabilitiesFound
				case "failed":
					env.T.Logf("Scan %s failed", scanID)
					return -1
				}
			}
		}
		time.Sleep(3 * time.Second)
	}

	env.T.Logf("Scan %s did not complete within %v", scanID, timeout)
	return -1
}

// ---------------------------------------------------------------------------
// Response type definitions (shared across all test files)
// ---------------------------------------------------------------------------

type uploadResponse struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type sbomListItem struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	Format    string `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type listSBOMsResponse struct {
	Data   []sbomListItem `json:"data"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
	Count  int            `json:"count"`
	Total  int            `json:"total"`
}

type createScanResponse struct {
	ScanID string `json:"scan_id"`
	OrgID  string `json:"org_id"`
	Status string `json:"status"`
	SbomID string `json:"sbom_id"`
}

type scanListItem struct {
	ID                   string `json:"id"`
	OrgID                string `json:"org_id"`
	SbomID               string `json:"sbom_id"`
	Status               string `json:"status"`
	VulnerabilitiesFound int    `json:"vulnerabilities_found"`
}

type listScansResponse struct {
	Data   []scanListItem `json:"data"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
	Count  int            `json:"count"`
	Total  int            `json:"total"`
}

type sbomResult struct {
	Name           string
	UploadResp     uploadResponse
	ScanResp       *createScanResponse
	DownloadedJSON json.RawMessage
	VulnCount      int
	ComponentCount int
}

// ---------------------------------------------------------------------------
// Infrastructure functions
// ---------------------------------------------------------------------------

func getFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve tcp addr: %v", err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startPostgres(ctx context.Context, t *testing.T) (testcontainers.Container, string) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("Docker not available or failed to start container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("failed to get container host: %v", err)
	}

	mappedPort, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("failed to get mapped port: %v", err)
	}

	pgURL := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, mappedPort.Port())
	t.Logf("PostgreSQL started at %s", pgURL)
	return container, pgURL
}

func runMigrations(t *testing.T, pgURL string) {
	t.Helper()
	serverRoot := ServerRoot()
	// Build the migrate helper first, then run it.
	absMigrations, _ := filepath.Abs(filepath.Join(serverRoot, "migrations"))
	binPath := filepath.Join(t.TempDir(), "migrate-helper")
	buildCmd := exec.Command("go", "build", "-o", binPath, "github.com/vincents-ai/transparenz-server-oss/cmd/migrate")
	buildCmd.Dir = serverRoot
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build migrate helper: %v\n%s", err, string(output))
	}
	cmd := exec.Command(binPath, absMigrations)
	cmd.Env = append(os.Environ(), "DATABASE_URL="+pgURL)
	cmd.Dir = serverRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run migrations: %v\n%s", err, string(output))
	}
	t.Logf("Migrations applied: %s", strings.TrimSpace(string(output)))
}

func createAuthSchema(t *testing.T, pgURL string) {
	t.Helper()

	db, err := sql.Open("postgres", pgURL)
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	statements := []string{
		`CREATE SCHEMA IF NOT EXISTS auth`,
		`CREATE TABLE IF NOT EXISTS auth.users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email_verified_at TIMESTAMPTZ,
			mfa_enabled BOOLEAN DEFAULT false,
			mfa_secret TEXT,
			last_login_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS auth.org_members (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			org_id UUID NOT NULL,
			role TEXT NOT NULL,
			invited_at TIMESTAMPTZ DEFAULT NOW(),
			accepted_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS auth.sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			refresh_token_hash TEXT UNIQUE NOT NULL,
			user_agent TEXT,
			ip_address TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS auth.email_verification_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			token TEXT UNIQUE NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS auth.password_reset_tokens (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			token TEXT UNIQUE NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON auth.sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_org_members_user_id ON auth.org_members(user_id)`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("failed to execute DDL: %v\nSQL: %s", err, stmt)
		}
	}
	t.Log("Auth schema created")
}

func loadSeedData(t *testing.T, pgURL string) {
	t.Helper()
	bsiPath := BSIDataPath()
	if bsiPath == "" {
		t.Log("No BSI data path configured, skipping seed data")
		return
	}

	storageDir := filepath.Join(bsiPath, "storage", "bsi-cert-bund")
	entries, err := os.ReadDir(storageDir)
	if err != nil {
		t.Fatalf("failed to read BSI storage directory %s: %v", storageDir, err)
	}

	db, err := sql.Open("postgres", pgURL)
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO compliance.vulnerability_feeds (cve, bsi_advisory_id, affected_products, description, last_synced_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW(), NOW())
		ON CONFLICT (cve) DO UPDATE SET
			bsi_advisory_id = EXCLUDED.bsi_advisory_id,
			affected_products = EXCLUDED.affected_products,
			description = COALESCE(compliance.vulnerability_feeds.description, EXCLUDED.description, ''),
			last_synced_at = NOW(),
			updated_at = NOW()
	`)
	if err != nil {
		t.Fatalf("failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	var synced, errors int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(storageDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			errors++
			continue
		}

		var envelope struct {
			Identifier string                 `json:"identifier"`
			Item       map[string]interface{} `json:"item"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			errors++
			continue
		}

		cveID := extractBSICVE(envelope.Identifier, envelope.Item)
		advisoryID := extractBSIAdvisoryID(envelope.Item)
		affectedJSON := extractBSIAffected(envelope.Item)
		description := extractBSIDescription(envelope.Item)

		if _, err := stmt.Exec(cveID, advisoryID, affectedJSON, description); err != nil {
			errors++
			continue
		}
		synced++

		if synced%500 == 0 {
			t.Logf("seeded %d records...", synced)
		}
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("failed to commit seed data: %v", err)
	}

	t.Logf("Loaded %d BSI feed records (%d errors)", synced, errors)
}

func startAuthService(t *testing.T, pgURL string) *exec.Cmd {
	t.Helper()
	authRoot := AuthRoot()

	tmpDir, err := os.MkdirTemp("", "auth-service-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	binPath := filepath.Join(tmpDir, "auth-service")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/server")
	buildCmd.Dir = authRoot
	buildCmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build auth-service: %v\n%s", err, string(out))
	}

	envContent := fmt.Sprintf("DATABASE_URL=%s\nJWT_SECRET=%s\nPORT=%s\nMFA_ENABLED=false\nLISTEN=127.0.0.1\nGIN_MODE=release\n",
		pgURL, testJWTSecret, authServicePort)
	envPath := filepath.Join(authRoot, ".env")
	t.Cleanup(func() { os.Remove(envPath) })
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write auth-service .env: %v", err)
	}

	cmd := exec.Command(binPath)
	cmd.Env = os.Environ()
	cmd.Dir = authRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start auth-service: %v", err)
	}
	t.Logf("auth-service started (pid=%d) on port %s", cmd.Process.Pid, authServicePort)
	return cmd
}

func startTransparenzServer(t *testing.T, pgURL string, port int, extraEnv map[string]string) *exec.Cmd {
	t.Helper()
	serverRoot := ServerRoot()

	tmpDir, err := os.MkdirTemp("", "transparenz-server-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	binPath := filepath.Join(tmpDir, "transparenz-server")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/server")
	buildCmd.Dir = serverRoot
	buildCmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build transparenz-server: %v\n%s", err, string(out))
	}

	envContent := fmt.Sprintf(
		"DATABASE_URL=%s\nJWT_SECRET=%s\nENCRYPTION_KEY=%s\nPORT=%d\n"+
			"GRYPE_DISABLED=true\nRATE_LIMIT_DISABLED=true\nTELEMETRY_ENABLED=false\n"+
			"GREENBONE_ENABLED=false\nSBOM_WEBHOOK_ENABLED=false\nENRICHMENT_AUTO_INIT=false\n"+
			"LOG_LEVEL=warn\nGIN_MODE=release\n",
		pgURL, testJWTSecret, testEncryptionKey, port,
	)
	for k, v := range extraEnv {
		envContent += fmt.Sprintf("%s=%s\n", k, v)
	}

	envPath := filepath.Join(serverRoot, ".env")
	t.Cleanup(func() { os.Remove(envPath) })
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write transparenz-server .env: %v", err)
	}

	cmd := exec.Command(binPath)
	cmd.Env = os.Environ()
	cmd.Dir = serverRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start transparenz-server: %v", err)
	}
	t.Logf("transparenz-server started (pid=%d) on port %d", cmd.Process.Pid, port)
	return cmd
}

func waitForHealth(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Logf("health check passed: %s", url)
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("health check timed out after %v for %s", timeout, url)
}

func registerAndGetToken(t *testing.T, name, email, password, orgName string) string {
	t.Helper()

	registerBody := fmt.Sprintf(`{
		"name": %q,
		"email": %q,
		"password": %q,
		"org_name": %q
	}`, name, email, password, orgName)

	resp, err := http.Post(
		"http://127.0.0.1:"+authServicePort+"/api/auth/register",
		"application/json",
		strings.NewReader(registerBody),
	)
	if err != nil {
		t.Fatalf("register request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register returned status %d: %s", resp.StatusCode, string(body))
	}

	var regResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}

	if regResp.AccessToken == "" {
		t.Fatal("register response missing access_token")
	}

	t.Logf("registered user %s, got access token (len=%d)", email, len(regResp.AccessToken))
	return regResp.AccessToken
}

// RegisterSecondUser creates a second test user with a different org.
// Returns the access token.
func (env *TestEnvironment) RegisterSecondUser(name, email, password, orgName string) string {
	env.T.Helper()
	return registerAndGetToken(env.T, name, email, password, orgName)
}

// ---------------------------------------------------------------------------
// BSI data extraction helpers
// ---------------------------------------------------------------------------

func extractBSICVE(identifier string, item map[string]interface{}) string {
	if meta, ok := item["metadata"].(map[string]interface{}); ok {
		if v, ok := meta["cve_id"].(string); ok && v != "" {
			return v
		}
	}
	parts := strings.SplitN(identifier, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return identifier
}

func extractBSIAdvisoryID(item map[string]interface{}) string {
	if meta, ok := item["metadata"].(map[string]interface{}); ok {
		if v, ok := meta["advisory_id"].(string); ok && v != "" {
			return v
		}
	}
	if advisories, ok := item["advisories"].([]interface{}); ok && len(advisories) > 0 {
		if first, ok := advisories[0].(map[string]interface{}); ok {
			if v, ok := first["id"].(string); ok {
				return v
			}
		}
	}
	return ""
}

func extractBSIAffected(item map[string]interface{}) string {
	affected, ok := item["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return "[]"
	}
	data, err := json.Marshal(affected)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func extractBSIDescription(item map[string]interface{}) string {
	if desc, ok := item["description"].(string); ok && desc != "" {
		return desc
	}
	return ""
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// MustMarshalJSON marshals v to JSON or fatals the test.
func MustMarshalJSON(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal JSON: %v", err))
	}
	return string(data)
}

// maskDBURL masks the password in a database URL for evidence logs.
func maskDBURL(url string) string {
	// postgres://user:password@host:port/db → postgres://user:***@host:port/db
	parts := strings.SplitN(url, "://", 2)
	if len(parts) != 2 {
		return "***"
	}
	rest := parts[1]
	atIdx := strings.Index(rest, "@")
	if atIdx == -1 {
		return url
	}
	userInfo := rest[:atIdx]
	colonIdx := strings.LastIndex(userInfo, ":")
	if colonIdx == -1 {
		return url
	}
	return parts[0] + "://" + userInfo[:colonIdx+1] + "***@" + rest[atIdx+1:]
}

// ---------------------------------------------------------------------------
// Environment configuration
// ---------------------------------------------------------------------------

type envConfig struct {
	SetupTimeout time.Duration
	SeedBSIData  bool
	ExtraEnv     map[string]string
	UserName     string
	UserEmail    string
	UserPassword string
	OrgName      string
}

func defaultEnvConfig() *envConfig {
	return &envConfig{
		SetupTimeout: 10 * time.Minute,
		SeedBSIData:  BSIDataPath() != "",
		ExtraEnv:     map[string]string{},
		UserName:     "Test User",
		UserEmail:    "test-integration@example.com",
		UserPassword: "StrongPassword123!",
		OrgName:      "Test Integration Org",
	}
}

// EnvOption configures the test environment.
type EnvOption func(*envConfig)

// WithSetupTimeout sets the stack setup timeout.
func WithSetupTimeout(d time.Duration) EnvOption {
	return func(cfg *envConfig) { cfg.SetupTimeout = d }
}

// WithExtraEnv adds extra environment variables to the transparenz-server.
func WithExtraEnv(env map[string]string) EnvOption {
	return func(cfg *envConfig) {
		for k, v := range env {
			cfg.ExtraEnv[k] = v
		}
	}
}

// WithoutBSISeed disables BSI seed data loading.
func WithoutBSISeed() EnvOption {
	return func(cfg *envConfig) { cfg.SeedBSIData = false }
}

// WithUser configures the test user registration.
func WithUser(name, email, password, orgName string) EnvOption {
	return func(cfg *envConfig) {
		cfg.UserName = name
		cfg.UserEmail = email
		cfg.UserPassword = password
		cfg.OrgName = orgName
	}
}
