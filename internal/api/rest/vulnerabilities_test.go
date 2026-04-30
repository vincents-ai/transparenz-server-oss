// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"github.com/transparenz/transparenz-server-oss/internal/testutil"
	"gorm.io/gorm"
)

func newVulnTestDB(t *testing.T) (*gorm.DB, uuid.UUID, *repository.VulnerabilityRepository, *repository.GRCMappingRepository) {
	t.Helper()
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	org := testutil.CreateTestOrg(t, db)
	repo := repository.NewVulnerabilityRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)
	return db, org.ID, repo, grcRepo
}

func newVulnTestContext(t *testing.T, method, url string) (*gin.Context, *httptest.ResponseRecorder, *repository.VulnerabilityRepository, *repository.GRCMappingRepository, uuid.UUID) {
	t.Helper()
	db, orgID, repo, grcRepo := newVulnTestDB(t)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(method, url, nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)
	c.Set("_test_db", db)
	return c, w, repo, grcRepo, orgID
}

func createVulnInDB(t *testing.T, db *gorm.DB, orgID uuid.UUID, cve, severity string) {
	t.Helper()
	vuln := &models.Vulnerability{
		OrgID:    orgID,
		Cve:      cve,
		Severity: severity,
	}
	require.NoError(t, db.Create(vuln).Error)
}

func TestListVulnerabilities_Empty(t *testing.T) {
	db, orgID, repo, grcRepo := newVulnTestDB(t)
	_ = orgID
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)
	_ = db

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.ListVulnerabilities(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), resp["count"])
	data, ok := resp["data"].([]interface{})
	assert.True(t, ok)
	assert.Empty(t, data)
}

func TestListVulnerabilities_WithResults(t *testing.T) {
	db, orgID, repo, grcRepo := newVulnTestDB(t)

	createVulnInDB(t, db, orgID, "CVE-2024-1001", "critical")
	createVulnInDB(t, db, orgID, "CVE-2024-1002", "high")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.ListVulnerabilities(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(2), resp["count"])
	data, ok := resp["data"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, data, 2)
}

func TestListVulnerabilities_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)

	repo := repository.NewVulnerabilityRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)

	vulnA := &models.Vulnerability{OrgID: orgA.ID, Cve: "CVE-2024-ORG-A", Severity: "critical"}
	require.NoError(t, db.Create(vulnA).Error)
	vulnB := &models.Vulnerability{OrgID: orgB.ID, Cve: "CVE-2024-ORG-B", Severity: "high"}
	require.NoError(t, db.Create(vulnB).Error)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgA.ID))
	c.Set("org_uuid", orgA.ID)

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.ListVulnerabilities(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(1), resp["count"])
}

func TestListVulnerabilities_FilterBySeverity(t *testing.T) {
	db, orgID, repo, grcRepo := newVulnTestDB(t)

	createVulnInDB(t, db, orgID, "CVE-2024-CRIT1", "critical")
	createVulnInDB(t, db, orgID, "CVE-2024-HIGH", "high")
	createVulnInDB(t, db, orgID, "CVE-2024-CRIT2", "critical")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities?severity=critical", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.ListVulnerabilities(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(2), resp["count"])
}

func TestListVulnerabilities_Pagination(t *testing.T) {
	db, orgID, repo, grcRepo := newVulnTestDB(t)

	for i := 0; i < 5; i++ {
		createVulnInDB(t, db, orgID, "CVE-2024-PAGE-"+string(rune('A'+i)), "high")
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities?limit=2&offset=0", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.ListVulnerabilities(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(2), resp["count"])
	assert.Equal(t, float64(5), resp["total"])
	assert.Equal(t, float64(2), resp["limit"])
	data, ok := resp["data"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, data, 2)
}

func TestGetVulnerability_Found(t *testing.T) {
	db, orgID, repo, grcRepo := newVulnTestDB(t)
	createVulnInDB(t, db, orgID, "CVE-2024-0001", "critical")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities/CVE-2024-0001", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)
	c.Params = gin.Params{{Key: "cve", Value: "CVE-2024-0001"}}

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.GetVulnerability(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp vulnerabilityResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "CVE-2024-0001", resp.Cve)
	assert.Equal(t, "critical", resp.Severity)
	assert.Empty(t, resp.GRCMappings)
}

func TestGetVulnerability_WithGRCMappings(t *testing.T) {
	db, orgID, repo, grcRepo := newVulnTestDB(t)
	vuln := &models.Vulnerability{OrgID: orgID, Cve: "CVE-2024-0001", Severity: "critical"}
	require.NoError(t, db.Create(vuln).Error)

	mapping := &models.GRCMapping{
		OrgID:           orgID,
		VulnerabilityID: &vuln.ID,
		Framework:       "PCI_DSS_v4",
		ControlID:       "PCI_DSS_v4/6.5",
		MappingType:     "cwe",
		Confidence:      0.8,
		Evidence:        "CWE-502 direct match",
	}
	require.NoError(t, db.Create(mapping).Error)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities/CVE-2024-0001", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)
	c.Params = gin.Params{{Key: "cve", Value: "CVE-2024-0001"}}

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.GetVulnerability(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp vulnerabilityResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "CVE-2024-0001", resp.Cve)
	require.Len(t, resp.GRCMappings, 1)
	assert.Equal(t, "PCI_DSS_v4", resp.GRCMappings[0].Framework)
	assert.Equal(t, "PCI_DSS_v4/6.5", resp.GRCMappings[0].ControlID)
	assert.Equal(t, "cwe", resp.GRCMappings[0].MappingType)
	assert.Equal(t, 0.8, resp.GRCMappings[0].Confidence)
	assert.Equal(t, "CWE-502 direct match", resp.GRCMappings[0].Evidence)
}

func TestListVulnerabilities_WithGRC(t *testing.T) {
	db, orgID, repo, grcRepo := newVulnTestDB(t)
	vuln1 := &models.Vulnerability{OrgID: orgID, Cve: "CVE-2024-2001", Severity: "high"}
	require.NoError(t, db.Create(vuln1).Error)
	vuln2 := &models.Vulnerability{OrgID: orgID, Cve: "CVE-2024-2002", Severity: "medium"}
	require.NoError(t, db.Create(vuln2).Error)

	mapping := &models.GRCMapping{
		OrgID:           orgID,
		VulnerabilityID: &vuln1.ID,
		Framework:       "ISO_27001",
		ControlID:       "A.12.6",
		MappingType:     "cve",
		Confidence:      0.9,
		Evidence:        "direct match",
	}
	require.NoError(t, db.Create(mapping).Error)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities?include_grc=true", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.ListVulnerabilities(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(2), resp["count"])

	data, ok := resp["data"].([]interface{})
	assert.True(t, ok)
	require.Len(t, data, 2)

	for _, item := range data {
		m, ok := item.(map[string]interface{})
		require.True(t, ok)
		_, hasGRC := m["grc_mappings"]
		assert.True(t, hasGRC)
	}
}

func TestListVulnerabilities_IncludeGRC_EmptyList(t *testing.T) {
	_, orgID, repo, grcRepo := newVulnTestDB(t)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities?include_grc=true", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.ListVulnerabilities(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), resp["count"])
	data, ok := resp["data"].([]interface{})
	assert.True(t, ok)
	assert.Empty(t, data)
}

func TestGetVulnerability_NotFound(t *testing.T) {
	_, orgID, repo, grcRepo := newVulnTestDB(t)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities/CVE-2024-99999", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgID))
	c.Set("org_uuid", orgID)
	c.Params = gin.Params{{Key: "cve", Value: "CVE-2024-99999"}}

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.GetVulnerability(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetVulnerability_CrossTenantNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)

	vuln := &models.Vulnerability{OrgID: orgA.ID, Cve: "CVE-2024-1111", Severity: "critical"}
	require.NoError(t, db.Create(vuln).Error)

	repo := repository.NewVulnerabilityRepository(db)
	grcRepo := repository.NewGRCMappingRepository(db)
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/vulnerabilities/CVE-2024-1111", nil)
	c.Request = req.WithContext(middleware.ContextWithOrgID(req.Context(), orgB.ID))
	c.Set("org_uuid", orgB.ID)
	c.Params = gin.Params{{Key: "cve", Value: "CVE-2024-1111"}}

	handler := NewVulnerabilityHandler(repo, grcRepo)
	handler.GetVulnerability(c)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListVulnerabilities_NoOrgUUID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/vulnerabilities", nil)

	repo := repository.NewVulnerabilityRepository(nil)
	handler := NewVulnerabilityHandler(repo, nil)

	handler.ListVulnerabilities(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetVulnerability_NoOrgUUID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/vulnerabilities/CVE-2024-1234", nil)
	c.Params = gin.Params{{Key: "cve", Value: "CVE-2024-1234"}}

	repo := repository.NewVulnerabilityRepository(nil)
	handler := NewVulnerabilityHandler(repo, nil)

	handler.GetVulnerability(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
