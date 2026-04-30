// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
	"github.com/transparenz/transparenz-server-oss/internal/testutil"
	"go.uber.org/zap"
)

func setupComplianceTestRouter(t *testing.T) (*gin.Engine, uuid.UUID) {
	t.Helper()
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	// Add sla_tracking and compliance_events tables
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."sla_tracking" (
		id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
		sbom_id text, deadline datetime NOT NULL, status text DEFAULT 'pending',
		created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
		id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
		severity text, cve text, previous_event_hash text, event_hash text,
		signature text, reported_to_authority integer DEFAULT 0,
		metadata text DEFAULT '{}',
		timestamp datetime DEFAULT CURRENT_TIMESTAMP,
		created_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)

	org := testutil.CreateTestOrg(t, db)

	gin.SetMode(gin.TestMode)

	slaRepo := repository.NewSlaTrackingRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	eventRepo := repository.NewComplianceEventRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)

	handler := NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, grcRepo, zap.NewNop())

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})
	router.GET("/api/compliance/status", handler.GetComplianceStatus)
	router.POST("/api/compliance/exploited", handler.ReportExploitedVulnerability)

	return router, org.ID
}

func TestGetComplianceStatus_NoOrgContext(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities")
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."sla_tracking" (
		id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
		sbom_id text, deadline datetime NOT NULL, status text DEFAULT 'pending',
		created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
		id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
		severity text, cve text, previous_event_hash text, event_hash text,
		signature text, reported_to_authority integer DEFAULT 0,
		metadata text DEFAULT '{}',
		timestamp datetime DEFAULT CURRENT_TIMESTAMP,
		created_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)

	gin.SetMode(gin.TestMode)
	slaRepo := repository.NewSlaTrackingRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	eventRepo := repository.NewComplianceEventRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)

	handler := NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, nil, zap.NewNop())

	router := gin.New()
	router.GET("/api/compliance/status", handler.GetComplianceStatus)

	req := httptest.NewRequest(http.MethodGet, "/api/compliance/status", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetComplianceStatus_Success(t *testing.T) {
	router, _ := setupComplianceTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/compliance/status", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "compliance_score")
	assert.Contains(t, body, "sla_violations")
}

func TestReportExploited_BadJSON(t *testing.T) {
	router, _ := setupComplianceTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/compliance/exploited", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReportExploited_InvalidCVEFormat(t *testing.T) {
	router, _ := setupComplianceTestRouter(t)

	body := `{"cve":"NOT-A-CVE"}`
	req := httptest.NewRequest(http.MethodPost, "/api/compliance/exploited", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestReportExploited_CVENotFound(t *testing.T) {
	router, _ := setupComplianceTestRouter(t)

	// Valid CVE format but CVE does not exist in DB
	body := `{"cve":"CVE-2024-9999"}`
	req := httptest.NewRequest(http.MethodPost, "/api/compliance/exploited", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestReportExploited_NoOrgContext(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities")
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."sla_tracking" (
		id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
		sbom_id text, deadline datetime NOT NULL, status text DEFAULT 'pending',
		created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
		id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
		severity text, cve text, previous_event_hash text, event_hash text,
		signature text, reported_to_authority integer DEFAULT 0,
		metadata text DEFAULT '{}',
		timestamp datetime DEFAULT CURRENT_TIMESTAMP,
		created_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)

	gin.SetMode(gin.TestMode)
	slaRepo := repository.NewSlaTrackingRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	eventRepo := repository.NewComplianceEventRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)

	handler := NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, nil, zap.NewNop())

	router := gin.New()
	router.POST("/api/compliance/exploited", handler.ReportExploitedVulnerability)

	body := `{"cve":"CVE-2024-1234"}`
	req := httptest.NewRequest(http.MethodPost, "/api/compliance/exploited", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetComplianceStatus_GRCFields(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."sla_tracking" (
		id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
		sbom_id text, deadline datetime NOT NULL, status text DEFAULT 'pending',
		created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
		id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
		severity text, cve text, previous_event_hash text, event_hash text,
		signature text, reported_to_authority integer DEFAULT 0,
		metadata text DEFAULT '{}',
		timestamp datetime DEFAULT CURRENT_TIMESTAMP,
		created_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)

	org := testutil.CreateTestOrg(t, db)

	vuln := &models.Vulnerability{OrgID: org.ID, Cve: "CVE-2024-GRC-TEST", Severity: "high"}
	require.NoError(t, db.Create(vuln).Error)

	mapping := models.GRCMapping{
		OrgID:           org.ID,
		VulnerabilityID: &vuln.ID,
		ControlID:       "NIST_CSF_2_0/RS.MI-01",
		Framework:       "NIST_CSF_2_0",
		MappingType:     "cwe",
		Confidence:      0.85,
	}
	require.NoError(t, db.Create(&mapping).Error)

	slaRepo := repository.NewSlaTrackingRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	eventRepo := repository.NewComplianceEventRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)

	handler := NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, grcRepo, zap.NewNop())

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})
	router.GET("/api/compliance/status", handler.GetComplianceStatus)

	req := httptest.NewRequest(http.MethodGet, "/api/compliance/status", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ComplianceStatusResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Contains(t, resp.GRCFrameworks, "NIST_CSF_2_0")
	assert.Equal(t, int64(1), resp.GRCFrameworks["NIST_CSF_2_0"])
	assert.GreaterOrEqual(t, resp.GRCTotalMappings, int64(1))
	assert.GreaterOrEqual(t, resp.GRCVulnsWithMappings, int64(1))
	assert.Contains(t, resp.GRCAffectedFrameworks, "NIST_CSF_2_0")
}

func TestGetComplianceStatus_GRCFields_Empty(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."sla_tracking" (
		id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
		sbom_id text, deadline datetime NOT NULL, status text DEFAULT 'pending',
		created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
		id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
		severity text, cve text, previous_event_hash text, event_hash text,
		signature text, reported_to_authority integer DEFAULT 0,
		metadata text DEFAULT '{}',
		timestamp datetime DEFAULT CURRENT_TIMESTAMP,
		created_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)

	org := testutil.CreateTestOrg(t, db)

	slaRepo := repository.NewSlaTrackingRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	eventRepo := repository.NewComplianceEventRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)

	handler := NewComplianceHandler(slaRepo, vulnRepo, eventRepo, orgRepo, grcRepo, zap.NewNop())

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})
	router.GET("/api/compliance/status", handler.GetComplianceStatus)

	req := httptest.NewRequest(http.MethodGet, "/api/compliance/status", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ComplianceStatusResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.NotNil(t, resp.GRCFrameworks)
	assert.Empty(t, resp.GRCFrameworks)
	assert.Equal(t, int64(0), resp.GRCTotalMappings)
}
