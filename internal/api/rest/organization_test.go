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
	"github.com/transparenz/transparenz-server-oss/internal/repository"
	"github.com/transparenz/transparenz-server-oss/internal/testutil"
	"go.uber.org/zap"
)

func setupOrgTestRouter(t *testing.T) (*gin.Engine, uuid.UUID) {
	t.Helper()
	db := testutil.SetupTestDB(t, "organizations")
	org := testutil.CreateTestOrg(t, db)

	gin.SetMode(gin.TestMode)
	orgRepo := repository.NewOrganizationRepository(db)
	handler := NewOrganizationHandler(orgRepo, zap.NewNop())

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})

	api := router.Group("/api/organization")
	api.GET("/support-period", handler.GetSupportPeriod)
	api.PUT("/support-period", handler.UpdateSupportPeriod)

	return router, org.ID
}

func TestGetSupportPeriod_NoPeriodSet(t *testing.T) {
	router, _ := setupOrgTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/organization/support-period", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(60), resp["support_period_months"])
}

func TestGetSupportPeriod_AfterUpdate(t *testing.T) {
	router, _ := setupOrgTestRouter(t)

	body := `{"months":24}`
	req := httptest.NewRequest(http.MethodPut, "/api/organization/support-period", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var putResp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &putResp)
	require.NoError(t, err)
	assert.Equal(t, float64(24), putResp["support_period_months"])
	assert.NotNil(t, putResp["support_start_date"])
	assert.NotNil(t, putResp["support_end_date"])

	getReq := httptest.NewRequest(http.MethodGet, "/api/organization/support-period", nil)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)
	assert.Equal(t, http.StatusOK, getW.Code)

	var getResp map[string]interface{}
	err = json.Unmarshal(getW.Body.Bytes(), &getResp)
	require.NoError(t, err)
	assert.Equal(t, float64(24), getResp["support_period_months"])
}

func TestUpdateSupportPeriod_Success(t *testing.T) {
	router, _ := setupOrgTestRouter(t)

	body := `{"months":36}`
	req := httptest.NewRequest(http.MethodPut, "/api/organization/support-period", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(36), resp["support_period_months"])
	assert.NotNil(t, resp["support_start_date"])
	assert.NotNil(t, resp["support_end_date"])
	assert.NotNil(t, resp["days_remaining"])
	assert.NotNil(t, resp["months_remaining"])
	assert.NotNil(t, resp["percentage_elapsed"])
	assert.NotNil(t, resp["is_expired"])
}

func TestUpdateSupportPeriod_TooShort(t *testing.T) {
	router, _ := setupOrgTestRouter(t)

	body := `{"months":6}`
	req := httptest.NewRequest(http.MethodPut, "/api/organization/support-period", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateSupportPeriod_InvalidJSON(t *testing.T) {
	router, _ := setupOrgTestRouter(t)

	req := httptest.NewRequest(http.MethodPut, "/api/organization/support-period", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateSupportPeriod_MissingMonths(t *testing.T) {
	router, _ := setupOrgTestRouter(t)

	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/api/organization/support-period", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSupportPeriod_NoOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testutil.SetupTestDB(t, "organizations")
	orgRepo := repository.NewOrganizationRepository(db)
	handler := NewOrganizationHandler(orgRepo, zap.NewNop())

	router := gin.New()
	router.GET("/api/organization/support-period", handler.GetSupportPeriod)

	req := httptest.NewRequest(http.MethodGet, "/api/organization/support-period", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateSupportPeriod_NoOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testutil.SetupTestDB(t, "organizations")
	orgRepo := repository.NewOrganizationRepository(db)
	handler := NewOrganizationHandler(orgRepo, zap.NewNop())

	router := gin.New()
	router.PUT("/api/organization/support-period", handler.UpdateSupportPeriod)

	body := `{"months":24}`
	req := httptest.NewRequest(http.MethodPut, "/api/organization/support-period", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
