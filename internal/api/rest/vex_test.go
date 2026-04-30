// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package rest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"github.com/transparenz/transparenz-server-oss/internal/testutil"
	"go.uber.org/zap"
)

// newVEXTestRouter builds a router backed by an in-memory SQLite database so
// the test suite runs without a live Postgres connection.
func newVEXTestRouter(t *testing.T) (*gin.Engine, uuid.UUID) {
	t.Helper()
	db := testutil.SetupTestDB(t,
		"organizations",
		"vulnerabilities",
		"vulnerability_feeds",
		"vex_statements",
		"vex_publications",
	)
	org := testutil.CreateTestOrg(t, db)

	stmtRepo := repository.NewVexStatementRepository(db)
	pubRepo := repository.NewVexPublicationRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	feedRepo := repository.NewVulnerabilityFeedRepository(db)

	vexService := services.NewVEXService(stmtRepo, pubRepo, feedRepo, vulnRepo, db, zap.NewNop(), nil, nil)

	gin.SetMode(gin.TestMode)
	handler := NewVEXHandler(vexService, stmtRepo, zap.NewNop())

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})
	router.POST("/api/vex", handler.CreateVEX)
	router.GET("/api/vex", handler.ListVEX)
	router.POST("/api/vex/:id/approve", handler.ApproveVEX)
	router.POST("/api/vex/:id/publish", handler.PublishVEX)
	return router, org.ID
}

func TestVEXCreate_NoOrgContext(t *testing.T) {
	db := testutil.SetupTestDB(t,
		"organizations",
		"vulnerabilities",
		"vulnerability_feeds",
		"vex_statements",
		"vex_publications",
	)
	stmtRepo := repository.NewVexStatementRepository(db)
	pubRepo := repository.NewVexPublicationRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	feedRepo := repository.NewVulnerabilityFeedRepository(db)

	vexService := services.NewVEXService(stmtRepo, pubRepo, feedRepo, vulnRepo, db, zap.NewNop(), nil, nil)

	gin.SetMode(gin.TestMode)
	handler := NewVEXHandler(vexService, stmtRepo, zap.NewNop())
	router := gin.New()
	router.POST("/api/vex", handler.CreateVEX)

	body := `{"cve":"CVE-2024-1234","product_id":"product-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/vex", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestVEXCreate_BadJSON(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/vex", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVEXCreate_MissingFields(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	// Missing product_id
	body := `{"cve":"CVE-2024-1234"}`
	req := httptest.NewRequest(http.MethodPost, "/api/vex", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVEXCreate_Success(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	body := `{"cve":"CVE-2024-1234","product_id":"product-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/vex", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestVEXList_Success(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/vex", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "data")
}

func TestVEXApprove_InvalidID(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/vex/not-a-uuid/approve", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVEXApprove_NotFound(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	nonExistentID := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/api/vex/"+nonExistentID.String()+"/approve", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Service returns error when not found; handler returns 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVEXPublish_InvalidID(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	body := `{"channel":"file"}`
	req := httptest.NewRequest(http.MethodPost, "/api/vex/not-a-uuid/publish", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVEXPublish_BadChannel(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	vexID := uuid.New()
	body := `{"channel":"invalid-channel"}`
	req := httptest.NewRequest(http.MethodPost, "/api/vex/"+vexID.String()+"/publish", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVEXPublish_NotFound(t *testing.T) {
	router, _ := newVEXTestRouter(t)

	nonExistentID := uuid.New()
	body := `{"channel":"file"}`
	req := httptest.NewRequest(http.MethodPost, "/api/vex/"+nonExistentID.String()+"/publish", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Service returns error when not found; handler returns 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
