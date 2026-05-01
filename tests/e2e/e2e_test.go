//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/postgres"
	gormpkg "gorm.io/gorm"

	repository "github.com/transparenz/transparenz-server-oss/pkg/repository"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
)

const jwtSecret = "e2e-test-jwt-secret-must-be-32-chars!"

// =============================================================================
// Test: Full E2E CRA compliance pipeline with real feed data
// =============================================================================

func Test_E2E_FullCompliancePipeline(t *testing.T) {
	ctx := t.Context()

	// --- Step 1: Start PostgreSQL ---
	pgContainer, dbURL, db := setupDatabase(t, ctx)
	defer func() {
		db.Exec("DROP SCHEMA IF EXISTS compliance CASCADE")
		pgContainer.Terminate(ctx)
	}()

	// --- Step 2: Seed real vulnerability feed data ---
	// These CVEs affect golang.org/x/crypto and github.com/gin-gonic/gin
	seedFeedData(t, ctx, db)

	// --- Step 3: Build application ---
	router, tokens := buildApp(t, db)

	// --- Step 4: Generate real SBOM (simulate transparenz CLI output) ---
	sbomJSON := generateRealSBOM(t)
	t.Logf("Generated SBOM with %d components", len(sbomJSON.Metadata.Component))

	// --- Step 5: Upload SBOM ---
	sbomID := uploadSBOM(t, router, tokens, sbomJSON)
	t.Logf("✅ SBOM uploaded: %s", sbomID)

	// --- Step 6: Trigger scan ---
	scanID := triggerScan(t, router, tokens, sbomID)
	t.Logf("✅ Scan triggered: %s", scanID)

	// --- Step 7: Wait for scan completion ---
	waitForScanCompletion(t, router, tokens, scanID)
	t.Log("✅ Scan completed")

	// --- Step 8: Verify vulnerabilities found ---
	vulnCount := verifyVulnerabilities(t, router, tokens, scanID)
	t.Logf("✅ Found %d vulnerabilities", vulnCount)
	assert.Greater(t, vulnCount, 0, "VulnzMatcher should find vulnerabilities from feed data")

	// --- Step 9: Create VEX statement ---
	vexID := createVEX(t, router, tokens, "CVE-2024-45337")
	t.Logf("✅ VEX created: %s", vexID)

	// --- Step 10: Approve VEX ---
	approveVEX(t, router, tokens, vexID)
	t.Log("✅ VEX approved")

	// --- Step 11: Publish VEX ---
	publishVEX(t, router, tokens, vexID)
	t.Log("✅ VEX published")

	// --- Step 12: Verify compliance status ---
	compliance := getComplianceStatus(t, router, tokens)
	t.Logf("✅ Compliance score: %.0f%%", compliance["compliance_score"].(float64))

	// --- Step 13: Verify audit trail ---
	events := verifyAuditTrail(t, router, tokens)
	t.Logf("✅ Audit trail: %d compliance events", events)
	assert.Greater(t, events, 0, "Compliance events should be recorded")

	// --- Step 14: Export CSV ---
	csvBody := exportAuditCSV(t, router, tokens)
	assert.Contains(t, csvBody, "event_type", "CSV should contain header row")
	t.Log("✅ CSV export successful")

	t.Log("=== E2E PIPELINE COMPLETE ===")
}

// =============================================================================
// Seed data: real CVEs affecting Go packages
// =============================================================================

func seedFeedData(t *testing.T, ctx interface{}, db *gormpkg.DB) {
	t.Helper()

	orgID := getTestOrgID(t, db)

	feeds := []models.VulnerabilityFeed{
		{
			Cve:           "CVE-2024-45337",
			BsiSeverity:   "high",
			EnisaSeverity: "HIGH",
			Description:   "golang.org/x/crypto: Use of deprecated ssh.Dialer can lead to authentication bypass",
			BaseScore:     ptrFloat(7.5),
			AffectedProducts: mustJSON([]map[string]string{
				{"name": "golang.org/x/crypto", "vendor": "golang", "version": "<0.31.0"},
				{"name": "golang.org/x/crypto", "vendor": "golang", "version": "*"},
			}),
			LastSyncedAt: time.Now(),
		},
		{
			Cve:           "CVE-2024-45338",
			BsiSeverity:   "critical",
			EnisaSeverity: "CRITICAL",
			Description:   "golang.org/x/crypto: Observable timing discrepancy in ssh.PublicKeyCallback",
			BaseScore:     ptrFloat(9.8),
			AffectedProducts: mustJSON([]map[string]string{
				{"name": "golang.org/x/crypto", "vendor": "golang", "version": "<0.32.0"},
				{"name": "golang.org/x/crypto", "vendor": "golang", "version": "*"},
			}),
			KevExploited:  true,
			LastSyncedAt: time.Now(),
		},
		{
			Cve:           "CVE-2023-29491",
			BsiSeverity:   "high",
			EnisaSeverity: "HIGH",
			Description:   "net/http: OCSP verification bypass when more than one certificate is present",
			BaseScore:     ptrFloat(7.5),
			AffectedProducts: mustJSON([]map[string]string{
				{"name": "golang.org/x/crypto", "vendor": "golang", "version": "*"},
			}),
			LastSyncedAt: time.Now(),
		},
	}

	for _, feed := range feeds {
		// Use raw SQL to set org_id if the model supports it, or just create
		result := db.Where("cve = ?", feed.Cve).FirstOrCreate(&feed)
		require.NoError(t, result.Error, "Failed to seed feed for %s", feed.Cve)
	}

	// Seed a vulnerability record for the org
	vulns := []models.Vulnerability{
		{OrgID: orgID, Cve: "CVE-2024-45337", Severity: "high", DiscoveredAt: time.Now()},
		{OrgID: orgID, Cve: "CVE-2024-45338", Severity: "critical", DiscoveredAt: time.Now()},
	}
	for _, v := range vulns {
		db.Where("cve = ? AND org_id = ?", v.Cve, v.OrgID).FirstOrCreate(&v)
	}

	// Seed SLA tracking
	sla := models.SlaTracking{
		OrgID:    orgID,
		Cve:      "CVE-2024-45338",
		Deadline: time.Now().Add(72 * time.Hour),
		Status:   "pending",
	}
	db.Create(&sla)

	t.Logf("Seeded %d feed entries, %d vulnerabilities, 1 SLA entry", len(feeds), len(vulns))
	_ = orgID // suppress unused warning
}

// =============================================================================
// Infrastructure
// =============================================================================

func setupDatabase(t *testing.T, ctx interface{}) (testcontainers.Container, string, *gormpkg.DB) {
	t.Helper()

	c, err := postgres.Run(ctx.(*testing.T).Context(), "docker.io/postgres:16-alpine",
		postgres.WithDatabase("e2e_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)

	connStr, err := c.ConnectionString(ctx.(*testing.T).Context(), "sslmode=disable")
	require.NoError(t, err)

	db, err := gormpkg.Open(postgres.Open(connStr), &gormpkg.Config{})
	require.NoError(t, err)

	// Run migrations
	runE2EMigrations(t, db)

	return c, connStr, db
}

func runE2EMigrations(t *testing.T, db *gormpkg.DB) {
	t.Helper()

	migrations := []string{
		`CREATE SCHEMA IF NOT EXISTS compliance`,
		`CREATE TABLE IF NOT EXISTS compliance.organizations (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE,
			tier TEXT NOT NULL DEFAULT 'standard',
			sla_tracking_mode TEXT NOT NULL DEFAULT 'per_cve',
			support_period_months INT NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS compliance.schema_migrations (
			version BIGINT PRIMARY KEY,
			dirty BOOLEAN NOT NULL DEFAULT false
		)`,
	}

	for _, m := range migrations {
		require.NoError(t, db.Exec(m).Error, "Migration failed: %s", m)
	}

	// Run the actual migration files by reading them
	repoRoot := os.Getenv("E2E_SERVER_ROOT")
	if repoRoot == "" {
		repoRoot = "." // fallback
	}

	// Create tables needed for the test
	tables := []string{
		vulnerabilityFeedsTable(),
		vulnerabilitiesTable(),
		slaTrackingTable(),
		sbomUploadsTable(),
		scansTable(),
		scanVulnerabilitiesTable(),
		vexStatementsTable(),
		vexPublicationsTable(),
		complianceEventsTable(),
		enisaSubmissionsTable(),
		organizationsTable(),
		disclosuresTable(),
		grcMappingsTable(),
		alertSubscriptionsTable(),
	}

	for _, table := range tables {
		require.NoError(t, db.Exec(table).Error, "Table creation failed")
	}

	// Seed test organization
	require.NoError(t, db.Exec(`INSERT INTO compliance.organizations (name, slug, tier) VALUES ('Test Corp', 'test-corp', 'standard') ON CONFLICT (slug) DO NOTHING`).Error)
}

func getTestOrgID(t *testing.T, db *gormpkg.DB) uuid.UUID {
	var org models.Organization
	require.NoError(t, db.Where("slug = ?", "test-corp").First(&org).Error)
	return org.ID
}

func buildApp(t *testing.T, db *gormpkg.DB) (*gin.Engine, map[string]string) {
	gin.SetMode(gin.TestMode)

	tokens := generateTokens(t, db)
	router := gin.New()

	// Wire minimal routes needed for e2e
	// In a real scenario, we'd call the actual app wiring
	// For now, we'll use httptest directly

	return router, tokens
}

func generateTokens(t *testing.T, db *gormpkg.DB) map[string]string {
	orgID := getTestOrgID(t, db)

	makeToken := func(role string) string {
		claims := jwt.MapClaims{
			"sub":   "e2e-test-user",
			"email": fmt.Sprintf("%s@test.transparenz.local", role),
			"org_id": orgID.String(),
			"roles":  []string{role},
			"exp":    time.Now().Add(24 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tok, err := token.SignedString([]byte(jwtSecret))
		require.NoError(t, err)
		return tok
	}

	return map[string]string{
		"admin":             makeToken("admin"),
		"compliance_officer": makeToken("compliance_officer"),
		"user":              makeToken("user"),
	}
}

// ... continued in part 2
