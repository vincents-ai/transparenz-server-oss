package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func insertSbomWebhook(t *testing.T, db *gorm.DB, active bool, secret string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	require.NoError(t, err)
	webhookID := uuid.New()
	orgID := uuid.New()
	require.NoError(t, db.Exec(
		`INSERT INTO "compliance"."sbom_webhooks" (id, org_id, name, secret_hash, actions, active) VALUES (?, ?, ?, ?, '{}', ?)`,
		webhookID, orgID, "Test SBOM Webhook", string(hash), active,
	).Error)
	return webhookID, orgID
}

func TestSbomWebhookAuth_ValidToken(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks")
	secret := "sbom-secret-token-12345"
	webhookID, _ := insertSbomWebhook(t, db, true, secret)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.Header.Set("X-SBOM-Token", secret)

	mw := SbomWebhookAuthMiddleware(db, nil)
	mw(c)

	assert.False(t, c.IsAborted())
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSbomWebhookAuth_InvalidToken(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks")
	webhookID, _ := insertSbomWebhook(t, db, true, "correct-secret")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.Header.Set("X-SBOM-Token", "wrong-token")

	mw := SbomWebhookAuthMiddleware(db, nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSbomWebhookAuth_MissingHeader(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks")
	webhookID, _ := insertSbomWebhook(t, db, true, "some-secret")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	mw := SbomWebhookAuthMiddleware(db, nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSbomWebhookAuth_InactiveWebhook(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks")
	secret := "test-secret"
	webhookID, _ := insertSbomWebhook(t, db, false, secret)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.Header.Set("X-SBOM-Token", secret)

	mw := SbomWebhookAuthMiddleware(db, nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSbomWebhookAuth_NonExistentWebhook(t *testing.T) {
	db := testutil.SetupTestDB(t, "sbom_webhooks")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: uuid.New().String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.Header.Set("X-SBOM-Token", "some-token")

	mw := SbomWebhookAuthMiddleware(db, nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
