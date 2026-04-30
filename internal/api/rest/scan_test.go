// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"github.com/transparenz/transparenz-server-oss/internal/testutil"
)

func setupScanTestDB(t *testing.T) (*gin.Engine, uuid.UUID, *repository.ScanRepository) {
	t.Helper()
	db := testutil.SetupTestDB(t, "organizations", "scans")
	org := testutil.CreateTestOrg(t, db)

	gin.SetMode(gin.TestMode)
	scanRepo := repository.NewScanRepository(db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})

	return router, org.ID, scanRepo
}

func TestCreateScan_InvalidJSON(t *testing.T) {
	router, _, _ := setupScanTestDB(t)
	router.POST("/api/scans", func(c *gin.Context) {
		orgID, err := middleware.GetOrgUUIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}
		_ = orgID
		var req CreateScanRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			api.BadRequest(c, "invalid request format")
			return
		}
		c.JSON(http.StatusAccepted, gin.H{})
	})

	req := httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateScan_MissingSbomID(t *testing.T) {
	router, _, _ := setupScanTestDB(t)
	router.POST("/api/scans", func(c *gin.Context) {
		orgID, err := middleware.GetOrgUUIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}
		_ = orgID
		var req CreateScanRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			api.BadRequest(c, "invalid request format")
			return
		}
		c.JSON(http.StatusAccepted, gin.H{})
	})

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateScan_InvalidSbomID(t *testing.T) {
	router, _, _ := setupScanTestDB(t)
	router.POST("/api/scans", func(c *gin.Context) {
		orgID, err := middleware.GetOrgUUIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}
		_ = orgID
		var req CreateScanRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			api.BadRequest(c, "invalid request format")
			return
		}
		sbomID, err := uuid.Parse(req.SbomID)
		if err != nil {
			api.BadRequest(c, "invalid sbom_id format")
			return
		}
		_ = sbomID
		c.JSON(http.StatusAccepted, gin.H{})
	})

	body := `{"sbom_id":"not-a-uuid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateScan_NoOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/api/scans", func(c *gin.Context) {
		orgID, err := middleware.GetOrgUUIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}
		_ = orgID
		c.JSON(http.StatusAccepted, gin.H{})
	})

	body := `{"sbom_id":"` + uuid.New().String() + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateScan_ValidSbomID(t *testing.T) {
	router, _, _ := setupScanTestDB(t)
	router.POST("/api/scans", func(c *gin.Context) {
		orgID, err := middleware.GetOrgUUIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}
		var req CreateScanRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			api.BadRequest(c, "invalid request format")
			return
		}
		sbomID, err := uuid.Parse(req.SbomID)
		if err != nil {
			api.BadRequest(c, "invalid sbom_id format")
			return
		}
		c.JSON(http.StatusAccepted, CreateScanResponse{
			ScanID: uuid.New(),
			OrgID:  orgID,
			Status: "in_progress",
			SbomID: sbomID,
		})
	})

	sbomID := uuid.New()
	body := `{"sbom_id":"` + sbomID.String() + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/scans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)

	var resp CreateScanResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, sbomID, resp.SbomID)
	assert.Equal(t, "in_progress", resp.Status)
}

func TestListScans_NoOrgContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/api/scans", func(c *gin.Context) {
		_, err := middleware.GetOrgUUIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListScans_WithData(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "scans")
	org := testutil.CreateTestOrg(t, db)
	scanRepo := repository.NewScanRepository(db)

	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	scan := &models.Scan{
		ID:     uuid.New(),
		OrgID:  org.ID,
		SbomID: uuid.New(),
		Status: "completed",
	}
	require.NoError(t, scanRepo.Create(ctx, org.ID, scan))

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})

	router.GET("/api/scans", func(c *gin.Context) {
		orgUUID, err := middleware.GetOrgUUIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}
		ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)
		scans, err := scanRepo.List(ctx, 50, 0)
		if err != nil {
			api.InternalError(c, "failed to list scans")
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": scans, "limit": 50, "offset": 0, "count": len(scans)})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(1), resp["count"])
	data, ok := resp["data"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, data, 1)
}

func TestListScans_Pagination(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "scans")
	org := testutil.CreateTestOrg(t, db)
	scanRepo := repository.NewScanRepository(db)

	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	for i := 0; i < 3; i++ {
		scan := &models.Scan{
			ID:     uuid.New(),
			OrgID:  org.ID,
			SbomID: uuid.New(),
			Status: "completed",
		}
		require.NoError(t, scanRepo.Create(ctx, org.ID, scan))
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", org.ID.String())
		c.Set("org_uuid", org.ID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), org.ID))
		c.Next()
	})

	router.GET("/api/scans", func(c *gin.Context) {
		orgUUID, err := middleware.GetOrgUUIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}
		limit := 50
		offset := 0
		if l := c.Query("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				if parsed > 100 {
					limit = 100
				} else {
					limit = parsed
				}
			}
		}
		if o := c.Query("offset"); o != "" {
			if parsed, err := strconv.Atoi(o); err == nil {
				offset = parsed
			}
		}
		ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)
		scans, err := scanRepo.List(ctx, limit, offset)
		if err != nil {
			api.InternalError(c, "failed to list scans")
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": scans, "limit": limit, "offset": offset, "count": len(scans)})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/scans?limit=2&offset=0", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(2), resp["limit"])
	data, ok := resp["data"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, data, 2)
}
