package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
	"github.com/transparenz/transparenz-server-oss/internal/testutil"
	"gorm.io/gorm"
)

func createSbomWebhookTestOrg(t *testing.T, db *gorm.DB, tier string) *models.Organization {
	t.Helper()
	org := &models.Organization{
		ID:   uuid.New(),
		Name: "SBOM Test Org",
		Slug: "sbom-test-" + uuid.New().String()[:8],
		Tier: tier,
	}
	require.NoError(t, db.Create(org).Error)
	return org
}

func TestSbomWebhookHandleUpload_Success(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks", "sbom_uploads", "organizations")
	sbomRepo := repository.NewSbomRepository(db)
	sbomWebhookRepo := repository.NewSbomWebhookRepository(db)
	handler := NewSbomWebhookHandler(sbomWebhookRepo, sbomRepo, nil, nil, nil, nil, nil, 10*1024*1024)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/upload", func(c *gin.Context) {
		orgID := uuid.New()
		c.Set("sbom_org_id", orgID)
		c.Set("sbom_actions", models.SbomWebhookActions{})
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgID))
		handler.HandleUpload(c)
	})

	body, ct := createMultipartUpload(t, "file", "test.spdx", "application/json", validSPDXJSON())
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["id"])
	assert.Equal(t, "spdx-json", resp["format"])
	assert.Equal(t, "test.spdx", resp["filename"])
}

func TestSbomWebhookHandleUpload_Duplicate(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks", "sbom_uploads", "organizations")
	sbomRepo := repository.NewSbomRepository(db)
	sbomWebhookRepo := repository.NewSbomWebhookRepository(db)
	handler := NewSbomWebhookHandler(sbomWebhookRepo, sbomRepo, nil, nil, nil, nil, nil, 10*1024*1024)

	gin.SetMode(gin.TestMode)
	orgID := uuid.New()

	router := gin.New()
	router.POST("/upload", func(c *gin.Context) {
		c.Set("sbom_org_id", orgID)
		c.Set("sbom_actions", models.SbomWebhookActions{})
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgID))
		handler.HandleUpload(c)
	})

	data := validSPDXJSON()

	body1, ct1 := createMultipartUpload(t, "file", "first.spdx", "application/json", data)
	req1 := httptest.NewRequest(http.MethodPost, "/upload", body1)
	req1.Header.Set("Content-Type", ct1)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusCreated, w1.Code)

	body2, ct2 := createMultipartUpload(t, "file", "second.spdx", "application/json", data)
	req2 := httptest.NewRequest(http.MethodPost, "/upload", body2)
	req2.Header.Set("Content-Type", ct2)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

func TestSbomWebhookHandleUpload_InvalidFormat(t *testing.T) {
	db := testutil.SetupTestDB(t)
	sbomRepo := repository.NewSbomRepository(db)
	sbomWebhookRepo := repository.NewSbomWebhookRepository(db)
	handler := NewSbomWebhookHandler(sbomWebhookRepo, sbomRepo, nil, nil, nil, nil, nil, 10*1024*1024)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/upload", func(c *gin.Context) {
		orgID := uuid.New()
		c.Set("sbom_org_id", orgID)
		c.Set("sbom_actions", models.SbomWebhookActions{})
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgID))
		handler.HandleUpload(c)
	})

	body, ct := createMultipartUpload(t, "file", "document.txt", "text/plain", []byte("not a valid sbom"))
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSbomCreateWebhook_Success(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks", "organizations")
	org := createSbomWebhookTestOrg(t, db, "professional")
	sbomWebhookRepo := repository.NewSbomWebhookRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	tierSvc := newTierServiceForTest(db)
	handler := NewSbomWebhookHandler(sbomWebhookRepo, nil, nil, nil, nil, orgRepo, tierSvc, 0)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(`{"name":"sbom-hook","actions":{}}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("org_uuid", org.ID)

	handler.CreateSbomWebhook(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp CreateSbomWebhookResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Secret)
	assert.Equal(t, "sbom-hook", resp.Name)
	assert.True(t, resp.Active)
}

func TestSbomCreateWebhook_TierLimit(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks", "organizations")
	org := createSbomWebhookTestOrg(t, db, "free")
	sbomWebhookRepo := repository.NewSbomWebhookRepository(db)
	orgRepo := repository.NewOrganizationRepository(db)
	tierSvc := newTierServiceForTest(db)
	handler := NewSbomWebhookHandler(sbomWebhookRepo, nil, nil, nil, nil, orgRepo, tierSvc, 0)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(`{"name":"sbom-hook","actions":{}}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("org_uuid", org.ID)

	handler.CreateSbomWebhook(c)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSbomListWebhooks(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks", "organizations")
	org := createSbomWebhookTestOrg(t, db, "professional")
	sbomWebhookRepo := repository.NewSbomWebhookRepository(db)

	webhookID := uuid.New()
	require.NoError(t, db.Exec(
		`INSERT INTO "compliance"."sbom_webhooks" (id, org_id, name, secret_hash, actions, active) VALUES (?, ?, ?, '', '{}', true)`,
		webhookID, org.ID, "SBOM Hook",
	).Error)

	handler := NewSbomWebhookHandler(sbomWebhookRepo, nil, nil, nil, nil, nil, nil, 0)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/webhooks", nil)
	c.Set("org_uuid", org.ID)

	handler.ListSbomWebhooks(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	data := resp["data"].([]interface{})
	assert.Len(t, data, 1)
	assert.Equal(t, float64(50), resp["limit"])
	assert.Equal(t, float64(0), resp["offset"])
	assert.Equal(t, float64(1), resp["count"])
	assert.Equal(t, float64(1), resp["total"])
}

func TestSbomDeleteWebhook(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks", "organizations")
	org := createSbomWebhookTestOrg(t, db, "professional")
	sbomWebhookRepo := repository.NewSbomWebhookRepository(db)

	webhookID := uuid.New()
	require.NoError(t, db.Exec(
		`INSERT INTO "compliance"."sbom_webhooks" (id, org_id, name, secret_hash, actions, active) VALUES (?, ?, ?, '', '{}', true)`,
		webhookID, org.ID, "ToDelete",
	).Error)

	handler := NewSbomWebhookHandler(sbomWebhookRepo, nil, nil, nil, nil, nil, nil, 0)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodDelete, "/webhooks/"+webhookID.String(), nil)
	c.Set("org_uuid", org.ID)

	handler.DeleteSbomWebhook(c)

	assert.Equal(t, http.StatusOK, w.Code)

	_, err := sbomWebhookRepo.GetWebhookByID(context.Background(), webhookID)
	assert.ErrorIs(t, err, repository.ErrSbomWebhookNotFound)
}
