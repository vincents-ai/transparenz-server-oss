package testutil

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

func TestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "postgres://user:pass@localhost:5432/transparenz_test?search_path=compliance"
	if d := os.Getenv("TEST_DATABASE_URL"); d != "" {
		dsn = d
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	t.Cleanup(func() { cleanupDB(t, db) })
	return db
}

func cleanupDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	tables := []string{
		"compliance.vex_publications",
		"compliance.vex_statements",
		"compliance.vulnerability_disclosures",
		"compliance.jobs",
		"compliance.signing_keys",
		"compliance.compliance_events",
		"compliance.sla_tracking",
		"compliance.enisa_submissions",
		"compliance.greenbone_findings",
		"compliance.scans",
		"compliance.vulnerabilities",
		"compliance.organizations",
		"compliance.sbom_uploads",
		"compliance.vulnerability_feeds",
		"compliance.greenbone_webhooks",
		"compliance.sbom_webhooks",
		"compliance.org_telemetry_configs",
	}
	for _, table := range tables {
		db.Exec("DELETE FROM " + table)
	}
}

func TestLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func MockGinContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c
}

func GenerateTestJWT(secret string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(secret))
	return s
}

func CreateTestOrg(t *testing.T, db *gorm.DB) *models.Organization {
	t.Helper()
	org := &models.Organization{
		ID:                  uuid.New(),
		Name:                "Test Org " + uuid.New().String()[:8],
		Slug:                "test-" + uuid.New().String()[:8],
		EnisaSubmissionMode: "export",
		CsafScope:           "per_sbom",
		PdfTemplate:         "generic",
		SlaTrackingMode:     "per_cve",
	}
	if err := db.Create(org).Error; err != nil {
		t.Fatalf("failed to create test org: %v", err)
	}
	return org
}
