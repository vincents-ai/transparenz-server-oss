// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/services"
	"go.uber.org/zap"
)

const testAlertJWTSecret = "test-secret-key-for-alerts-tests-min32"

func mustParseUUID(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		panic("invalid UUID: " + s)
	}
	return id
}

func makeAlertToken(t *testing.T, orgID string, secret string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"org_id": orgID,
		"exp":    time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed to sign test JWT: %v", err)
	}
	return signed
}

func newAlertTestRouter(orgID string) (*gin.Engine, *services.AlertHub) {
	gin.SetMode(gin.TestMode)
	hub := services.NewAlertHub(zap.NewNop())
	handler := NewAlertHandler(hub, testAlertJWTSecret)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", orgID)
		c.Set("org_uuid", mustParseUUID(orgID))
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), mustParseUUID(orgID)))
		c.Next()
	})
	router.GET("/api/alerts/stream", handler.StreamAlerts)
	return router, hub
}

func TestStreamAlerts_NoOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hub := services.NewAlertHub(zap.NewNop())
	handler := NewAlertHandler(hub, testAlertJWTSecret)

	router := gin.New()
	// No org middleware — no org context set
	router.GET("/api/alerts/stream", handler.StreamAlerts)

	req := httptest.NewRequest(http.MethodGet, "/api/alerts/stream?token=anything", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestStreamAlerts_MissingToken(t *testing.T) {
	orgID := "550e8400-e29b-41d4-a716-446655440001"
	router, _ := newAlertTestRouter(orgID)

	req := httptest.NewRequest(http.MethodGet, "/api/alerts/stream", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestStreamAlerts_InvalidToken(t *testing.T) {
	orgID := "550e8400-e29b-41d4-a716-446655440002"
	router, _ := newAlertTestRouter(orgID)

	req := httptest.NewRequest(http.MethodGet, "/api/alerts/stream?token=not-a-valid-jwt", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestStreamAlerts_TokenForWrongOrg(t *testing.T) {
	orgID := "550e8400-e29b-41d4-a716-446655440003"
	router, _ := newAlertTestRouter(orgID)

	// Token claims a different org_id
	token := makeAlertToken(t, "550e8400-e29b-41d4-a716-000000000000", testAlertJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/alerts/stream?token="+token, nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
