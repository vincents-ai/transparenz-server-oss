// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"go.uber.org/zap"
)

type mockDisclosureRepo struct {
	disclosures map[uuid.UUID]*models.VulnerabilityDisclosure
}

func newMockDisclosureRepo() *mockDisclosureRepo {
	return &mockDisclosureRepo{disclosures: make(map[uuid.UUID]*models.VulnerabilityDisclosure)}
}

func (m *mockDisclosureRepo) Create(_ context.Context, _ uuid.UUID, d *models.VulnerabilityDisclosure) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.ReceivedAt.IsZero() {
		d.ReceivedAt = time.Now()
	}
	if d.Status == "" {
		d.Status = "received"
	}
	m.disclosures[d.ID] = d
	return nil
}

func (m *mockDisclosureRepo) GetByID(_ context.Context, id uuid.UUID) (*models.VulnerabilityDisclosure, error) {
	d, ok := m.disclosures[id]
	if !ok {
		return nil, services.ErrDisclosureNotFound
	}
	return d, nil
}

func (m *mockDisclosureRepo) List(_ context.Context, limit, offset int) ([]models.VulnerabilityDisclosure, error) {
	var result []models.VulnerabilityDisclosure
	for _, d := range m.disclosures {
		result = append(result, *d)
	}
	if offset > len(result) {
		return nil, nil
	}
	if offset > 0 {
		result = result[offset:]
	}
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

func (m *mockDisclosureRepo) ListByStatus(_ context.Context, status string, _, _ int) ([]models.VulnerabilityDisclosure, error) {
	var result []models.VulnerabilityDisclosure
	for _, d := range m.disclosures {
		if d.Status == status {
			result = append(result, *d)
		}
	}
	return result, nil
}

func (m *mockDisclosureRepo) ListByCVE(_ context.Context, _ string) ([]models.VulnerabilityDisclosure, error) {
	return nil, nil
}

func (m *mockDisclosureRepo) UpdateStatus(_ context.Context, id uuid.UUID, status string) error {
	d, ok := m.disclosures[id]
	if !ok {
		return services.ErrDisclosureNotFound
	}
	d.Status = status
	return nil
}

func (m *mockDisclosureRepo) Update(_ context.Context, d *models.VulnerabilityDisclosure) error {
	m.disclosures[d.ID] = d
	return nil
}

func (m *mockDisclosureRepo) Count(_ context.Context) (int64, error) {
	return int64(len(m.disclosures)), nil
}

func newDisclosureTestRouter(t *testing.T) (*gin.Engine, *mockDisclosureRepo, uuid.UUID) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	repo := newMockDisclosureRepo()
	svc := services.NewDisclosureService(repo)
	handler := NewDisclosureHandler(svc, zap.NewNop())

	orgID := uuid.New()

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", orgID.String())
		c.Set("org_uuid", orgID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgID))
		c.Next()
	})

	api := router.Group("/api/disclosures")
	api.POST("", handler.CreateDisclosure)
	api.GET("", handler.ListDisclosures)
	api.GET("/:id", handler.GetDisclosure)
	api.PUT("/:id/status", handler.UpdateStatus)

	return router, repo, orgID
}

func TestCreateDisclosure_Success(t *testing.T) {
	router, _, _ := newDisclosureTestRouter(t)

	body := `{"cve":"CVE-2024-1001","title":"Test Vulnerability","severity":"high"}`
	req := httptest.NewRequest(http.MethodPost, "/api/disclosures", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp models.VulnerabilityDisclosure
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "CVE-2024-1001", resp.Cve)
	assert.Equal(t, "Test Vulnerability", resp.Title)
	assert.Equal(t, "high", resp.Severity)
	assert.Equal(t, "received", resp.Status)
	assert.NotEmpty(t, resp.ID)
}

func TestCreateDisclosure_MissingCve(t *testing.T) {
	router, _, _ := newDisclosureTestRouter(t)

	body := `{"title":"Missing CVE"}`
	req := httptest.NewRequest(http.MethodPost, "/api/disclosures", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDisclosure_MissingTitle(t *testing.T) {
	router, _, _ := newDisclosureTestRouter(t)

	body := `{"cve":"CVE-2024-1001"}`
	req := httptest.NewRequest(http.MethodPost, "/api/disclosures", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDisclosure_InvalidJSON(t *testing.T) {
	router, _, _ := newDisclosureTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/disclosures", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateDisclosure_NoOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newMockDisclosureRepo()
	svc := services.NewDisclosureService(repo)
	handler := NewDisclosureHandler(svc, zap.NewNop())

	router := gin.New()
	router.POST("/api/disclosures", handler.CreateDisclosure)

	body := `{"cve":"CVE-2024-1001","title":"Test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/disclosures", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListDisclosures_Empty(t *testing.T) {
	router, _, _ := newDisclosureTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/disclosures", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), resp["count"])
}

func TestListDisclosures_WithData(t *testing.T) {
	router, repo, _ := newDisclosureTestRouter(t)

	repo.Create(context.Background(), uuid.New(), &models.VulnerabilityDisclosure{
		Cve: "CVE-2024-1001", Title: "First", Severity: "high",
	})
	repo.Create(context.Background(), uuid.New(), &models.VulnerabilityDisclosure{
		Cve: "CVE-2024-1002", Title: "Second", Severity: "low",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/disclosures", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(2), resp["count"])
	data, ok := resp["data"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, data, 2)
}

func TestGetDisclosure_Found(t *testing.T) {
	router, repo, _ := newDisclosureTestRouter(t)

	d := &models.VulnerabilityDisclosure{
		Cve: "CVE-2024-2001", Title: "Get Test", Severity: "critical",
	}
	repo.Create(context.Background(), uuid.New(), d)

	req := httptest.NewRequest(http.MethodGet, "/api/disclosures/"+d.ID.String(), nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp models.VulnerabilityDisclosure
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "CVE-2024-2001", resp.Cve)
}

func TestGetDisclosure_NotFound(t *testing.T) {
	router, _, _ := newDisclosureTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/disclosures/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetDisclosure_InvalidID(t *testing.T) {
	router, _, _ := newDisclosureTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/disclosures/not-a-uuid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateStatus_Triaging(t *testing.T) {
	router, repo, _ := newDisclosureTestRouter(t)

	d := &models.VulnerabilityDisclosure{
		Cve: "CVE-2024-3001", Title: "Status Test", Severity: "high",
	}
	repo.Create(context.Background(), uuid.New(), d)

	body := `{"status":"triaging"}`
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+d.ID.String()+"/status", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "triaging", resp["status"])
}

func TestUpdateStatus_InvalidStatus(t *testing.T) {
	router, repo, _ := newDisclosureTestRouter(t)

	d := &models.VulnerabilityDisclosure{
		Cve: "CVE-2024-3002", Title: "Bad Status", Severity: "low",
	}
	repo.Create(context.Background(), uuid.New(), d)

	body := `{"status":"nonexistent"}`
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+d.ID.String()+"/status", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateStatus_NotFound(t *testing.T) {
	router, _, _ := newDisclosureTestRouter(t)

	body := `{"status":"triaging"}`
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+uuid.New().String()+"/status", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateStatus_MissingStatusField(t *testing.T) {
	router, repo, _ := newDisclosureTestRouter(t)

	d := &models.VulnerabilityDisclosure{
		Cve: "CVE-2024-3003", Title: "No Status", Severity: "medium",
	}
	repo.Create(context.Background(), uuid.New(), d)

	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+d.ID.String()+"/status", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateStatus_Acknowledge(t *testing.T) {
	router, repo, _ := newDisclosureTestRouter(t)

	d := &models.VulnerabilityDisclosure{
		Cve: "CVE-2024-3004", Title: "Ack Test", Severity: "high",
	}
	repo.Create(context.Background(), uuid.New(), d)

	body := `{"status":"acknowledged","coordinator_name":"Alice","coordinator_email":"alice@example.com"}`
	req := httptest.NewRequest(http.MethodPut, "/api/disclosures/"+d.ID.String()+"/status", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "acknowledged", resp["status"])
}
