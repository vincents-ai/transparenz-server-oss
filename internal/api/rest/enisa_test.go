// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparenz/transparenz-server-oss/pkg/interfaces"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"github.com/transparenz/transparenz-server-oss/internal/testutil"
	"go.uber.org/zap"
)

type mockENISASubmitter struct {
	submission *models.EnisaSubmission
	err        error
}

func (m *mockENISASubmitter) Submit(_ context.Context, orgID uuid.UUID, cve string, _ models.JSONMap) (*models.EnisaSubmission, error) {
	if m.err != nil {
		return nil, m.err
	}
	sub := m.submission
	if sub == nil {
		sub = &models.EnisaSubmission{
			ID:     uuid.New(),
			OrgID:  orgID,
			Status: "pending",
		}
	}
	return sub, nil
}

func setupENISATestDB(t *testing.T) (*repository.EnisaSubmissionRepository, uuid.UUID) {
	t.Helper()
	db := testutil.SetupTestDB(t, "organizations")
	db.Exec(`CREATE TABLE IF NOT EXISTS "compliance"."enisa_submissions" (
		id text PRIMARY KEY, org_id text NOT NULL, submission_id text UNIQUE,
		csaf_document text DEFAULT '{}', status text DEFAULT 'pending',
		retry_count integer DEFAULT 0, submitted_at datetime,
		response text, created_at datetime DEFAULT CURRENT_TIMESTAMP,
		updated_at datetime DEFAULT CURRENT_TIMESTAMP
	)`)

	org := testutil.CreateTestOrg(t, db)
	repo := repository.NewEnisaSubmissionRepository(db)
	return repo, org.ID
}

func setupENISARouter(t *testing.T, submitter interfaces.ENISASubmitter, subRepo *repository.EnisaSubmissionRepository, orgID uuid.UUID) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	handler := NewENISAHandler(submitter, subRepo, zap.NewNop())

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", orgID.String())
		c.Set("org_uuid", orgID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgID))
		c.Next()
	})
	router.POST("/api/enisa/submit", handler.Submit)
	router.GET("/api/enisa/submissions", handler.ListSubmissions)
	router.GET("/api/enisa/submissions/:id", handler.GetSubmission)
	return router
}

func TestENISASubmit_Success(t *testing.T) {
	subRepo, orgID := setupENISATestDB(t)
	sub := &models.EnisaSubmission{ID: uuid.New(), OrgID: orgID, Status: "pending"}
	router := setupENISARouter(t, &mockENISASubmitter{submission: sub}, subRepo, orgID)

	body := `{"cve":"CVE-2024-1001"}`
	req := httptest.NewRequest(http.MethodPost, "/api/enisa/submit", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["submission_id"])
	assert.Equal(t, "CVE-2024-1001", resp["cve"])
}

func TestENISASubmit_ServiceError(t *testing.T) {
	subRepo, orgID := setupENISATestDB(t)
	router := setupENISARouter(t, &mockENISASubmitter{err: errors.New("submission failed")}, subRepo, orgID)

	body := `{"cve":"CVE-2024-1001"}`
	req := httptest.NewRequest(http.MethodPost, "/api/enisa/submit", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestENISASubmit_BadRequestBody(t *testing.T) {
	subRepo, orgID := setupENISATestDB(t)
	router := setupENISARouter(t, &mockENISASubmitter{}, subRepo, orgID)

	req := httptest.NewRequest(http.MethodPost, "/api/enisa/submit", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestENISASubmit_MissingCVE(t *testing.T) {
	subRepo, orgID := setupENISATestDB(t)
	router := setupENISARouter(t, &mockENISASubmitter{}, subRepo, orgID)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/enisa/submit", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestENISASubmit_NoOrgContext(t *testing.T) {
	subRepo, _ := setupENISATestDB(t)
	gin.SetMode(gin.TestMode)

	handler := NewENISAHandler(&mockENISASubmitter{}, subRepo, zap.NewNop())
	router := gin.New()
	router.POST("/api/enisa/submit", handler.Submit)

	body := `{"cve":"CVE-2024-1001"}`
	req := httptest.NewRequest(http.MethodPost, "/api/enisa/submit", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestENISAGetSubmission_NotFound(t *testing.T) {
	subRepo, orgID := setupENISATestDB(t)
	router := setupENISARouter(t, &mockENISASubmitter{}, subRepo, orgID)

	nonExistentID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions/"+nonExistentID.String(), nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestENISAGetSubmission_InvalidID(t *testing.T) {
	subRepo, orgID := setupENISATestDB(t)
	router := setupENISARouter(t, &mockENISASubmitter{}, subRepo, orgID)

	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions/not-a-uuid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestENISAGetSubmission_Success(t *testing.T) {
	subRepo, orgID := setupENISATestDB(t)
	router := setupENISARouter(t, &mockENISASubmitter{}, subRepo, orgID)

	// Create a submission directly in the repo
	ctx := middleware.ContextWithOrgID(context.Background(), orgID)
	sub := &models.EnisaSubmission{
		ID:           uuid.New(),
		OrgID:        orgID,
		CsafDocument: models.JSONMap{},
		Status:       "pending",
	}
	require.NoError(t, subRepo.Create(ctx, orgID, sub))

	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions/"+sub.ID.String(), nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.EnisaSubmission
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, sub.ID, resp.ID)
}

func TestENISAListSubmissions_Empty(t *testing.T) {
	subRepo, orgID := setupENISATestDB(t)
	router := setupENISARouter(t, &mockENISASubmitter{}, subRepo, orgID)

	req := httptest.NewRequest(http.MethodGet, "/api/enisa/submissions", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, float64(0), resp["count"])
}
