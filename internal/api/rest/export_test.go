// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package rest

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/transparenz/transparenz-server-oss/internal/interfaces"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
	"github.com/transparenz/transparenz-server-oss/internal/testutil"
)

// mockPDFGenerator satisfies the PDFGenerator interface.
type mockPDFGenerator struct {
	data []byte
	err  error
}

func (m *mockPDFGenerator) GeneratePDF(_ models.PDFReportData) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.data != nil {
		return m.data, nil
	}
	return []byte("%PDF-1.4 test"), nil
}

func setupExportTestDB(t *testing.T) (*repository.ComplianceEventRepository, *repository.OrganizationRepository, uuid.UUID) {
	t.Helper()
	db := testutil.SetupTestDB(t, "organizations")
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
		id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
		severity text DEFAULT '', cve text DEFAULT '', previous_event_hash text DEFAULT '',
		event_hash text DEFAULT '', signature text DEFAULT '',
		reported_to_authority integer DEFAULT 0,
		metadata text DEFAULT '{}',
		timestamp datetime DEFAULT CURRENT_TIMESTAMP,
		created_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)

	org := testutil.CreateTestOrg(t, db)
	eventRepo := repository.NewComplianceEventRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	return eventRepo, orgRepo, org.ID
}

func setupExportRouter(t *testing.T, gen interfaces.PDFGenerator, orgID uuid.UUID, eventRepo *repository.ComplianceEventRepository, orgRepo *repository.OrganizationRepository) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	handler := NewExportHandler(eventRepo, orgRepo, nil, nil, gen)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", orgID.String())
		c.Set("org_uuid", orgID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgID))
		c.Next()
	})
	router.GET("/api/export/audit", handler.ExportAudit)
	return router
}

func TestExportAuditCSV_Success(t *testing.T) {
	eventRepo, orgRepo, orgID := setupExportTestDB(t)
	router := setupExportRouter(t, &mockPDFGenerator{}, orgID, eventRepo, orgRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=csv", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
	// Verify CSV header row is present
	assert.Contains(t, w.Body.String(), "Timestamp")
}

func TestExportAuditCSV_InvalidStartDate(t *testing.T) {
	eventRepo, orgRepo, orgID := setupExportTestDB(t)
	router := setupExportRouter(t, &mockPDFGenerator{}, orgID, eventRepo, orgRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=csv&start=not-a-date", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExportAuditCSV_InvalidEndDate(t *testing.T) {
	eventRepo, orgRepo, orgID := setupExportTestDB(t)
	router := setupExportRouter(t, &mockPDFGenerator{}, orgID, eventRepo, orgRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=csv&end=not-a-date", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExportAuditCSV_NoOrgContext(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations")
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."compliance_events" (
		id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
		severity text DEFAULT '', cve text DEFAULT '', metadata text DEFAULT '{}',
		timestamp datetime DEFAULT CURRENT_TIMESTAMP, created_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)
	eventRepo := repository.NewComplianceEventRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)

	gin.SetMode(gin.TestMode)
	handler := NewExportHandler(eventRepo, orgRepo, nil, nil, &mockPDFGenerator{})
	router := gin.New()
	router.GET("/api/export/audit", handler.ExportAudit)

	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=csv", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestExportAuditPDF_Success(t *testing.T) {
	eventRepo, orgRepo, orgID := setupExportTestDB(t)
	pdfGen := &mockPDFGenerator{data: []byte("%PDF-1.4 fake-pdf-content")}
	router := setupExportRouter(t, pdfGen, orgID, eventRepo, orgRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=pdf", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/pdf")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
}

func TestExportAuditPDF_GeneratorError(t *testing.T) {
	eventRepo, orgRepo, orgID := setupExportTestDB(t)
	pdfGen := &mockPDFGenerator{err: errors.New("pdf generation failed")}
	router := setupExportRouter(t, pdfGen, orgID, eventRepo, orgRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=pdf", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestExportAuditPDF_NilGenerator(t *testing.T) {
	eventRepo, orgRepo, orgID := setupExportTestDB(t)
	// Pass nil PDF generator to trigger "not configured" error
	router := setupExportRouter(t, nil, orgID, eventRepo, orgRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=pdf", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestExportAudit_UnsupportedFormat(t *testing.T) {
	eventRepo, orgRepo, orgID := setupExportTestDB(t)
	router := setupExportRouter(t, &mockPDFGenerator{}, orgID, eventRepo, orgRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/export/audit?format=xml", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
