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

func insertGreenboneWebhook(t *testing.T, db *gorm.DB, active bool, secret string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	require.NoError(t, err)
	webhookID := uuid.New()
	orgID := uuid.New()
	require.NoError(t, db.Exec(
		`INSERT INTO "compliance"."greenbone_webhooks" (id, org_id, name, secret_hash, actions, active) VALUES (?, ?, ?, ?, '{}', ?)`,
		webhookID, orgID, "Test Webhook", string(hash), active,
	).Error)
	return webhookID, orgID
}

func TestGreenboneAuth_ValidToken(t *testing.T) {
	db := testutil.SetupTestDB(t, "greenbone_webhooks")
	secret := "test-secret-token-12345"
	webhookID, _ := insertGreenboneWebhook(t, db, true, secret)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.Header.Set("X-Greenbone-Token", secret)

	mw := GreenboneAuthMiddleware(db, nil)
	mw(c)

	assert.False(t, c.IsAborted())
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGreenboneAuth_InvalidToken(t *testing.T) {
	db := testutil.SetupTestDB(t, "greenbone_webhooks")
	webhookID, _ := insertGreenboneWebhook(t, db, true, "correct-secret")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.Header.Set("X-Greenbone-Token", "wrong-token")

	mw := GreenboneAuthMiddleware(db, nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGreenboneAuth_MissingHeader(t *testing.T) {
	db := testutil.SetupTestDB(t, "greenbone_webhooks")
	webhookID, _ := insertGreenboneWebhook(t, db, true, "some-secret")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	mw := GreenboneAuthMiddleware(db, nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGreenboneAuth_InactiveWebhook(t *testing.T) {
	db := testutil.SetupTestDB(t, "greenbone_webhooks")
	secret := "test-secret"
	webhookID, _ := insertGreenboneWebhook(t, db, false, secret)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: webhookID.String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.Header.Set("X-Greenbone-Token", secret)

	mw := GreenboneAuthMiddleware(db, nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGreenboneAuth_NonExistentWebhook(t *testing.T) {
	db := testutil.SetupTestDB(t, "greenbone_webhooks")

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: uuid.New().String()}}
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Request.Header.Set("X-Greenbone-Token", "some-token")

	mw := GreenboneAuthMiddleware(db, nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
