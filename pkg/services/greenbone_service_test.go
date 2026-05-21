package services

import (
	"context"
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
	"gorm.io/gorm"
)

func setupGreenboneService(t *testing.T) (*GreenboneService, *gorm.DB) {
	t.Helper()
	db := testutil.SetupTestDB(t, "organizations", "scans", "greenbone_findings", "vulnerabilities", "sbom_uploads")
	greenboneRepo := repository.NewGreenboneRepository(db)
	scanRepo := repository.NewScanRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	logger := zap.NewNop()
	return NewGreenboneService(greenboneRepo, scanRepo, vulnRepo, nil, nil, db, logger), db
}

func loadTestXML(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func testCtxWithOrgID(orgID uuid.UUID) context.Context {
	return middleware.ContextWithOrgID(context.Background(), orgID)
}

func TestProcessReport_ValidReport(t *testing.T) {
	svc, db := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/valid_report.xml")
	actions := models.GreenboneWebhookActions{StoreFindings: true}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	var scanCount int64
	db.Model(&models.Scan{}).Where("org_id = ?", orgID).Count(&scanCount)
	assert.GreaterOrEqual(t, scanCount, int64(1))

	var findings []models.GreenboneFinding
	db.Where("org_id = ?", orgID).Find(&findings)
	assert.Len(t, findings, 3)

	var vulnCount int64
	db.Model(&models.Vulnerability{}).Where("org_id = ?", orgID).Count(&vulnCount)
	assert.Equal(t, int64(2), vulnCount)

	var cveVuln models.Vulnerability
	db.Where("org_id = ? AND cve = ?", orgID, "CVE-2024-12345").First(&cveVuln)
	assert.Equal(t, "critical", cveVuln.Severity)
}

func TestProcessReport_SingleCVE(t *testing.T) {
	svc, db := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/single_cve.xml")
	actions := models.GreenboneWebhookActions{StoreFindings: true}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	var findings []models.GreenboneFinding
	db.Where("org_id = ?", orgID).Find(&findings)
	require.Len(t, findings, 1)
	assert.Equal(t, "CVE-2024-99999", findings[0].CVE)
	assert.NotNil(t, findings[0].VulnerabilityID)

	var vuln models.Vulnerability
	db.Where("org_id = ? AND cve = ?", orgID, "CVE-2024-99999").First(&vuln)
	assert.Equal(t, "high", vuln.Severity)
	assert.NotNil(t, vuln.CvssScore)
	assert.Equal(t, 7.5, *vuln.CvssScore)
}

func TestProcessReport_NoCVE(t *testing.T) {
	svc, db := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/no_cve.xml")
	actions := models.GreenboneWebhookActions{StoreFindings: true}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	var findings []models.GreenboneFinding
	db.Where("org_id = ?", orgID).Find(&findings)
	assert.Len(t, findings, 2)
}

func TestProcessReport_MalformedXML(t *testing.T) {
	svc, _ := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/malformed.xml")
	actions := models.GreenboneWebhookActions{StoreFindings: true}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

func TestProcessReport_Idempotency(t *testing.T) {
	svc, db := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/valid_report.xml")
	actions := models.GreenboneWebhookActions{StoreFindings: true}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	err = svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	var scanCount int64
	db.Model(&models.Scan{}).Where("org_id = ?", orgID).Count(&scanCount)
	assert.GreaterOrEqual(t, scanCount, int64(1))

	var findingsCount int64
	db.Model(&models.GreenboneFinding{}).Where("org_id = ?", orgID).Count(&findingsCount)
	assert.Equal(t, int64(3), findingsCount)
}

func TestProcessReport_SeverityThreshold(t *testing.T) {
	svc, db := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/valid_report.xml")
	actions := models.GreenboneWebhookActions{StoreFindings: true,
		SeverityThreshold: "high",
	}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	var findings []models.GreenboneFinding
	db.Where("org_id = ?", orgID).Find(&findings)
	assert.Len(t, findings, 1)
	assert.Equal(t, "res-001", findings[0].GvmResultID)
	assert.True(t, findings[0].Severity >= 7.0)
}

func TestProcessReport_EmptyResults(t *testing.T) {
	svc, db := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/empty_results.xml")
	actions := models.GreenboneWebhookActions{StoreFindings: true}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	var findingsCount int64
	db.Model(&models.GreenboneFinding{}).Where("org_id = ?", orgID).Count(&findingsCount)
	assert.Equal(t, int64(0), findingsCount)
}

func TestProcessReport_StoreFindingsDisabled(t *testing.T) {
	svc, db := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/valid_report.xml")
	actions := models.GreenboneWebhookActions{
		StoreFindings: false,
	}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	var scanCount int64
	db.Model(&models.Scan{}).Where("org_id = ?", orgID).Count(&scanCount)
	assert.Equal(t, int64(1), scanCount)

	var findingsCount int64
	db.Model(&models.GreenboneFinding{}).Where("org_id = ?", orgID).Count(&findingsCount)
	assert.Equal(t, int64(0), findingsCount)

	var vulnCount int64
	db.Model(&models.Vulnerability{}).Where("org_id = ?", orgID).Count(&vulnCount)
	assert.Equal(t, int64(0), vulnCount)

	var scan models.Scan
	db.Where("org_id = ?", orgID).First(&scan)
	assert.Equal(t, 3, scan.VulnerabilitiesFound)
}

func TestProcessReport_EmptySeverityThreshold(t *testing.T) {
	svc, db := setupGreenboneService(t)
	orgID := uuid.New()

	body := loadTestXML(t, "../../testdata/greenbone/valid_report.xml")
	actions := models.GreenboneWebhookActions{StoreFindings: true, SeverityThreshold: ""}

	err := svc.ProcessReport(testCtxWithOrgID(orgID), orgID, actions, body)
	require.NoError(t, err)

	var findings []models.GreenboneFinding
	db.Where("org_id = ?", orgID).Find(&findings)
	assert.Len(t, findings, 3)

	var zeroSevFound bool
	for _, f := range findings {
		if f.Severity == 0.0 && f.GvmResultID == "res-003" {
			zeroSevFound = true
		}
	}
	assert.True(t, zeroSevFound, "empty threshold should include severity 0.0 results")
}
