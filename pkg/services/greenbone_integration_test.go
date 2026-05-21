//go:build integration

package services

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func skipIfNoDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "postgres://user:pass@localhost:5432/transparenz_test?search_path=compliance"
	if d := os.Getenv("TEST_DATABASE_URL"); d != "" {
		dsn = d
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("requires database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Skipf("requires database: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		t.Skipf("requires database: %v", err)
	}
	sqlDB.Close()
	return testutil.TestDB(t)
}

func setupGreenboneIntegrationService(t *testing.T, db *gorm.DB) *GreenboneService {
	t.Helper()
	greenboneRepo := repository.NewGreenboneRepository(db)
	scanRepo := repository.NewScanRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	alertHub := NewAlertHub(testutil.TestLogger())
	logger := zap.NewNop()
	return NewGreenboneService(greenboneRepo, scanRepo, vulnRepo, alertHub, nil, db, logger)
}

// TestFullWebhookFlow exercises the full greenbone pipeline from report XML
// processing through to scan, finding, and vulnerability creation in the database.
func TestFullWebhookFlow_Integration(t *testing.T) {
	db := skipIfNoDB(t)
	svc := setupGreenboneIntegrationService(t, db)
	org := testutil.CreateTestOrg(t, db)

	const testReportID = "rpt-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	sbomID := uuid.NewSHA1(greenboneSbomNamespace, []byte(org.ID.String()+":greenbone:"+testReportID))
	placeholder := &models.SbomUpload{
		ID:        sbomID,
		OrgID:     org.ID,
		Filename:  "greenbone-placeholder",
		Format:    "spdx-json",
		SizeBytes: 0,
		SHA256:    "greenbone-placeholder",
		Document:  []byte("{}"),
	}
	require.NoError(t, db.Create(placeholder).Error)

	body, err := os.ReadFile("../../testdata/greenbone/valid_report.xml")
	require.NoError(t, err)

	actions := models.GreenboneWebhookActions{StoreFindings: true}
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	err = svc.ProcessReport(ctx, org.ID, actions, body)
	require.NoError(t, err)

	var scan models.Scan
	err = db.Where("org_id = ? AND scanner_source = ?", org.ID, "greenbone").First(&scan).Error
	require.NoError(t, err)
	assert.Equal(t, "greenbone", scan.ScannerSource)
	assert.Equal(t, "rpt-a1b2c3d4-e5f6-7890-abcd-ef1234567890", scan.GvmReportID)
	assert.Equal(t, "completed", scan.Status)

	var findings []models.GreenboneFinding
	err = db.Where("org_id = ? AND scan_id = ?", org.ID, scan.ID).Find(&findings).Error
	require.NoError(t, err)
	assert.Len(t, findings, 3)

	for _, f := range findings {
		assert.Equal(t, org.ID, f.OrgID)
		assert.Equal(t, scan.ID, f.ScanID)
		assert.Equal(t, "rpt-a1b2c3d4-e5f6-7890-abcd-ef1234567890", f.GvmReportID)
		assert.NotEmpty(t, f.Host)
	}

	finding001 := findFindingByResultID(findings, "res-001")
	require.NotNil(t, finding001)
	assert.Equal(t, "CVE-2024-12345", finding001.CVE)
	assert.Equal(t, 9.8, finding001.Severity)
	assert.Equal(t, "192.168.1.10", finding001.Host)
	assert.Equal(t, "443/tcp", finding001.Port)
	assert.NotNil(t, finding001.VulnerabilityID)

	finding002 := findFindingByResultID(findings, "res-002")
	require.NotNil(t, finding002)
	assert.Equal(t, "CVE-2024-67890", finding002.CVE)
	assert.Equal(t, 5.3, finding002.Severity)
	assert.NotNil(t, finding002.VulnerabilityID)

	finding003 := findFindingByResultID(findings, "res-003")
	require.NotNil(t, finding003)
	assert.Equal(t, "", finding003.CVE)
	assert.Equal(t, 0.0, finding003.Severity)
	assert.Nil(t, finding003.VulnerabilityID)

	var vulnCount int64
	db.Model(&models.Vulnerability{}).Where("org_id = ?", org.ID).Count(&vulnCount)
	assert.Equal(t, int64(2), vulnCount)

	var vuln1 models.Vulnerability
	err = db.Where("org_id = ? AND cve = ?", org.ID, "CVE-2024-12345").First(&vuln1).Error
	require.NoError(t, err)
	assert.Equal(t, "critical", vuln1.Severity)
	require.NotNil(t, vuln1.CvssScore)
	assert.Equal(t, 9.8, *vuln1.CvssScore)

	var vuln2 models.Vulnerability
	err = db.Where("org_id = ? AND cve = ?", org.ID, "CVE-2024-67890").First(&vuln2).Error
	require.NoError(t, err)
	assert.Equal(t, "medium", vuln2.Severity)
	require.NotNil(t, vuln2.CvssScore)
	assert.Equal(t, 5.3, *vuln2.CvssScore)
}

// TestIdempotencyFull verifies that processing the same report twice
// produces no duplicate scans or findings.
func TestIdempotencyFull_Integration(t *testing.T) {
	db := skipIfNoDB(t)
	svc := setupGreenboneIntegrationService(t, db)
	org := testutil.CreateTestOrg(t, db)

	sbomID := uuid.NewSHA1(greenboneSbomNamespace, []byte(org.ID.String()+":greenbone:rpt-a1b2c3d4-e5f6-7890-abcd-ef1234567890"))
	placeholder := &models.SbomUpload{
		ID:        sbomID,
		OrgID:     org.ID,
		Filename:  "greenbone-placeholder",
		Format:    "spdx-json",
		SizeBytes: 0,
		SHA256:    "greenbone-placeholder",
		Document:  []byte("{}"),
	}
	require.NoError(t, db.Create(placeholder).Error)

	body, err := os.ReadFile("../../testdata/greenbone/valid_report.xml")
	require.NoError(t, err)

	actions := models.GreenboneWebhookActions{StoreFindings: true}
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	err = svc.ProcessReport(ctx, org.ID, actions, body)
	require.NoError(t, err)

	err = svc.ProcessReport(ctx, org.ID, actions, body)
	require.NoError(t, err)

	var scanCount int64
	db.Model(&models.Scan{}).Where("org_id = ?", org.ID).Count(&scanCount)
	assert.Equal(t, int64(1), scanCount)

	var findingsCount int64
	db.Model(&models.GreenboneFinding{}).Where("org_id = ?", org.ID).Count(&findingsCount)
	assert.Equal(t, int64(3), findingsCount)

	var vulnCount int64
	db.Model(&models.Vulnerability{}).Where("org_id = ?", org.ID).Count(&vulnCount)
	assert.Equal(t, int64(2), vulnCount)
}

// TestTransactionRollback verifies that when a mid-transaction failure occurs,
// no partial data is committed to the database.
func TestTransactionRollback_Integration(t *testing.T) {
	db := skipIfNoDB(t)
	svc := setupGreenboneIntegrationService(t, db)
	org := testutil.CreateTestOrg(t, db)

	sbomID := uuid.NewSHA1(greenboneSbomNamespace, []byte(org.ID.String()+":greenbone:rpt-a1b2c3d4-e5f6-7890-abcd-ef1234567890"))
	placeholder := &models.SbomUpload{
		ID:        sbomID,
		OrgID:     org.ID,
		Filename:  "greenbone-placeholder",
		Format:    "spdx-json",
		SizeBytes: 0,
		SHA256:    "greenbone-placeholder",
		Document:  []byte("{}"),
	}
	require.NoError(t, db.Create(placeholder).Error)

	triggerFn := `CREATE OR REPLACE FUNCTION compliance.test_force_rollback() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'forced rollback for test';
END; $$ LANGUAGE plpgsql`
	triggerCreate := fmt.Sprintf(
		`CREATE TRIGGER test_rollback_trigger BEFORE INSERT ON compliance.greenbone_findings FOR EACH ROW WHEN (NEW.org_id = '%s') EXECUTE FUNCTION compliance.test_force_rollback()`,
		org.ID.String(),
	)
	require.NoError(t, db.Exec(triggerFn).Error)
	require.NoError(t, db.Exec(triggerCreate).Error)
	t.Cleanup(func() {
		db.Exec("DROP TRIGGER IF EXISTS test_rollback_trigger ON compliance.greenbone_findings")
		db.Exec("DROP FUNCTION IF EXISTS compliance.test_force_rollback()")
	})

	body, err := os.ReadFile("../../testdata/greenbone/valid_report.xml")
	require.NoError(t, err)

	actions := models.GreenboneWebhookActions{StoreFindings: true}
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)

	err = svc.ProcessReport(ctx, org.ID, actions, body)
	assert.Error(t, err)

	var scanCount int64
	db.Model(&models.Scan{}).Where("org_id = ?", org.ID).Count(&scanCount)
	assert.Equal(t, int64(0), scanCount)

	var findingsCount int64
	db.Model(&models.GreenboneFinding{}).Where("org_id = ?", org.ID).Count(&findingsCount)
	assert.Equal(t, int64(0), findingsCount)

	var vulnCount int64
	db.Model(&models.Vulnerability{}).Where("org_id = ?", org.ID).Count(&vulnCount)
	assert.Equal(t, int64(0), vulnCount)
}

func findFindingByResultID(findings []models.GreenboneFinding, resultID string) *models.GreenboneFinding {
	for i := range findings {
		if findings[i].GvmResultID == resultID {
			return &findings[i]
		}
	}
	return nil
}
