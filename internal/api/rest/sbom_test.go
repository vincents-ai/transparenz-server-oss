// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupSbomTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	_, err = sqlDB.Exec("ATTACH DATABASE ':memory:' AS compliance")
	require.NoError(t, err)
	_, err = sqlDB.Exec("ATTACH DATABASE ':memory:' AS public")
	require.NoError(t, err)
	_, err = sqlDB.Exec(
		`CREATE TABLE IF NOT EXISTS compliance.sbom_uploads (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			filename TEXT NOT NULL,
			format TEXT NOT NULL,
			size_bytes INTEGER NOT NULL,
			sha256 TEXT NOT NULL,
			document BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	)
	require.NoError(t, err)
	_, err = sqlDB.Exec(
		`CREATE TABLE IF NOT EXISTS public.sboms (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			filename TEXT NOT NULL,
			format TEXT NOT NULL,
			document BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	)
	require.NoError(t, err)
	return db
}

func sbomTestRouter(t *testing.T, db *gorm.DB, maxSize int64) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	repo := repository.NewSbomRepository(db)
	handler := NewSbomHandler(repo, maxSize, nil, nil)

	router := gin.New()
	orgID := uuid.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", orgID.String())
		c.Set("org_uuid", orgID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgID))
		c.Next()
	})

	api := router.Group("/api/sboms")
	api.POST("/upload", handler.Upload)
	api.GET("", handler.List)
	api.GET("/:id", handler.GetByID)
	api.GET("/:id/download", handler.Download)
	api.DELETE("/:id", handler.Delete)
	return router
}

func createMultipartUpload(t *testing.T, fieldName, filename, contentType string, content []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(fieldName, filename)
	require.NoError(t, err)
	_, err = part.Write(content)
	require.NoError(t, err)
	err = writer.Close()
	require.NoError(t, err)
	return &buf, writer.FormDataContentType()
}

func validSPDXJSON() []byte {
	doc := map[string]interface{}{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID":      "SPDXRef-DOCUMENT",
		"name":        "test-package",
		"packages": []map[string]interface{}{
			{
				"SPDXID":      "SPDXRef-Package",
				"name":        "test",
				"versionInfo": "1.0.0",
			},
		},
	}
	data, _ := json.Marshal(doc)
	return data
}

func validCycloneDXJSON() []byte {
	doc := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]interface{}{
			"component": map[string]interface{}{
				"name":    "test",
				"version": "1.0.0",
			},
		},
	}
	data, _ := json.Marshal(doc)
	return data
}

func TestUpload_ValidSPDX(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	body, ct := createMultipartUpload(t, "file", "sbom.spdx", "application/json", validSPDXJSON())
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp UploadResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "spdx-json", resp.Format)
	assert.Equal(t, "sbom.spdx", resp.Filename)
	assert.NotEmpty(t, resp.SHA256)
	assert.Greater(t, resp.SizeBytes, int64(0))
}

func TestUpload_ValidCycloneDX(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	body, ct := createMultipartUpload(t, "file", "bom.cdx", "application/vnd.cyclonedx+json", validCycloneDXJSON())
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp UploadResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "cyclonedx-json", resp.Format)
}

func TestUpload_FormatValidation_UnsupportedExtension(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	body, ct := createMultipartUpload(t, "file", "document.txt", "text/plain", []byte("hello"))
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpload_FormatValidation_XMLExtension(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	xmlContent := []byte(`<?xml version="1.0"?><spdxDocument><spdxVersion>SPDX-2.3</spdxVersion></spdxDocument>`)
	body, ct := createMultipartUpload(t, "file", "sbom.xml", "application/xml", xmlContent)
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestUpload_SHA256Deduplication(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	data := validSPDXJSON()
	body, ct := createMultipartUpload(t, "file", "first.spdx", "application/json", data)
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	body2, ct2 := createMultipartUpload(t, "file", "second.spdx", "application/json", data)
	req2 := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body2)
	req2.Header.Set("Content-Type", ct2)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

func TestUpload_SizeLimitEnforcement(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 1024)

	data := validSPDXJSON()
	body, ct := createMultipartUpload(t, "file", "large.spdx", "application/json", data)
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	huge := make([]byte, 2048)
	copy(huge, `{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"`)
	for i := len(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"`); i < len(huge)-2; i++ {
		huge[i] = 'x'
	}
	huge[len(huge)-2] = '"'
	huge[len(huge)-1] = '}'

	body2, ct2 := createMultipartUpload(t, "file", "huge.spdx", "application/json", huge)
	req2 := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body2)
	req2.Header.Set("Content-Type", ct2)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusBadRequest, w2.Code)
}

func TestUpload_InvalidJSON(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	body, ct := createMultipartUpload(t, "file", "bad.spdx", "application/json", []byte("not json at all"))
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpload_InvalidSPDXStructure(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	doc := map[string]interface{}{
		"dataLicense": "CC0-1.0",
		"name":        "missing-spxVersion",
	}
	data, _ := json.Marshal(doc)
	body, ct := createMultipartUpload(t, "file", "invalid.spdx", "application/json", data)
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpload_InvalidCycloneDXStructure(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	doc := map[string]interface{}{
		"specVersion": "1.5",
		"version":     1,
	}
	data, _ := json.Marshal(doc)
	body, ct := createMultipartUpload(t, "file", "invalid.cdx", "application/json", data)
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpload_MissingFile(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestList_Empty(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	req := httptest.NewRequest(http.MethodGet, "/api/sboms", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data  []models.SbomUpload `json:"data"`
		Count int                 `json:"count"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp.Data)
}

func TestList_AfterUpload(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	body, ct := createMultipartUpload(t, "file", "test.spdx", "application/json", validSPDXJSON())
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	req2 := httptest.NewRequest(http.MethodGet, "/api/sboms", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	var resp struct {
		Data  []models.SbomUpload `json:"data"`
		Count int                 `json:"count"`
	}
	err := json.Unmarshal(w2.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Data, 1)
	assert.Equal(t, "test.spdx", resp.Data[0].Filename)
}

func TestGetByID_NotFound(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	req := httptest.NewRequest(http.MethodGet, "/api/sboms/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetByID_InvalidID(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	req := httptest.NewRequest(http.MethodGet, "/api/sboms/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetByID_Found(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	body, ct := createMultipartUpload(t, "file", "test.spdx", "application/json", validSPDXJSON())
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created UploadResponse
	err := json.Unmarshal(w.Body.Bytes(), &created)
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodGet, "/api/sboms/"+created.ID.String(), nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestDownload_NotFound(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	req := httptest.NewRequest(http.MethodGet, "/api/sboms/"+uuid.New().String()+"/download", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDownload_Success(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	originalData := validSPDXJSON()
	body, ct := createMultipartUpload(t, "file", "test.spdx", "application/json", originalData)
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created UploadResponse
	err := json.Unmarshal(w.Body.Bytes(), &created)
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodGet, "/api/sboms/"+created.ID.String()+"/download", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "application/json", w2.Header().Get("Content-Type"))
	assert.Equal(t, originalData, w2.Body.Bytes())
}

func TestDelete_NotFound(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	req := httptest.NewRequest(http.MethodDelete, "/api/sboms/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDelete_Success(t *testing.T) {
	db := setupSbomTestDB(t)
	router := sbomTestRouter(t, db, 10*1024*1024)

	body, ct := createMultipartUpload(t, "file", "test.spdx", "application/json", validSPDXJSON())
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var created UploadResponse
	err := json.Unmarshal(w.Body.Bytes(), &created)
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodDelete, "/api/sboms/"+created.ID.String(), nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusNoContent, w2.Code)

	req3 := httptest.NewRequest(http.MethodGet, "/api/sboms/"+created.ID.String(), nil)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusNotFound, w3.Code)
}

func TestUpload_InsertsIntoPublicSBOMs(t *testing.T) {
	db := setupSbomTestDB(t)
	gin.SetMode(gin.TestMode)

	var capturedUpload *models.SbomUpload
	repo := repository.NewSbomRepository(db)
	handler := NewSbomHandler(repo, 10*1024*1024, nil, nil)
	handler.insertIntoPublicSBOMs = func(ctx context.Context, upload *models.SbomUpload) error {
		capturedUpload = upload
		return nil
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		orgID := uuid.New()
		c.Set("org_id", orgID.String())
		c.Set("org_uuid", orgID)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgID))
		c.Next()
	})
	router.POST("/api/sboms/upload", handler.Upload)

	data := validSPDXJSON()
	body, ct := createMultipartUpload(t, "file", "compat.spdx", "application/json", data)
	req := httptest.NewRequest(http.MethodPost, "/api/sboms/upload", body)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	require.NotNil(t, capturedUpload)
	assert.Equal(t, "compat.spdx", capturedUpload.Filename)
	assert.Equal(t, "spdx-json", capturedUpload.Format)
	assert.NotEmpty(t, capturedUpload.ID)
}

func TestExtensionToFormat(t *testing.T) {
	tests := []struct {
		ext    string
		ct     string
		want   string
		wantOK bool
	}{
		{".json", "application/json", "spdx-json", true},
		{".json", "application/vnd.cyclonedx+json", "cyclonedx-json", true},
		{".xml", "application/xml", "spdx+xml", true},
		{".xml", "application/vnd.cyclonedx+xml", "cyclonedx-xml", true},
		{".spdx", "", "spdx-json", true},
		{".cdx", "", "cyclonedx-json", true},
		{".txt", "text/plain", "", false},
	}

	for _, tt := range tests {
		got, ok := extensionToFormat(tt.ext, tt.ct)
		assert.Equal(t, tt.want, got, "ext=%s ct=%s", tt.ext, tt.ct)
		assert.Equal(t, tt.wantOK, ok, "ext=%s ct=%s", tt.ext, tt.ct)
	}
}

func TestValidateSBOMStructure(t *testing.T) {
	t.Run("valid spdx", func(t *testing.T) {
		data := validSPDXJSON()
		err := validateSBOMStructure(data, "spdx-json")
		assert.NoError(t, err)
	})

	t.Run("missing spdxVersion", func(t *testing.T) {
		doc := map[string]interface{}{"name": "test"}
		data, _ := json.Marshal(doc)
		err := validateSBOMStructure(data, "spdx-json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "spdxVersion")
	})

	t.Run("valid cyclonedx", func(t *testing.T) {
		data := validCycloneDXJSON()
		err := validateSBOMStructure(data, "cyclonedx-json")
		assert.NoError(t, err)
	})

	t.Run("missing bomFormat", func(t *testing.T) {
		doc := map[string]interface{}{"version": 1}
		data, _ := json.Marshal(doc)
		err := validateSBOMStructure(data, "cyclonedx-json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bomFormat")
	})

	t.Run("invalid json", func(t *testing.T) {
		err := validateSBOMStructure([]byte("not json"), "spdx-json")
		assert.Error(t, err)
	})
}

func TestTenantIsolation(t *testing.T) {
	db := setupSbomTestDB(t)
	gin.SetMode(gin.TestMode)

	orgA := uuid.New()
	orgB := uuid.New()

	repoA := repository.NewSbomRepository(db)
	handlerA := NewSbomHandler(repoA, 10*1024*1024, nil, nil)
	repoB := repository.NewSbomRepository(db)
	NewSbomHandler(repoB, 10*1024*1024, nil, nil)

	ctxA := middleware.ContextWithOrgID(context.Background(), orgA)
	uploadA := &models.SbomUpload{
		Filename:  "org-a.spdx",
		Format:    "spdx-json",
		SizeBytes: 100,
		SHA256:    "aaa",
		Document:  json.RawMessage(validSPDXJSON()),
	}
	err := repoA.CreateUpload(ctxA, orgA, uploadA)
	require.NoError(t, err)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("org_id", orgB.String())
		c.Set("org_uuid", orgB)
		c.Request = c.Request.WithContext(middleware.ContextWithOrgID(c.Request.Context(), orgB))
		c.Next()
	})
	router.GET("/api/sboms/:id", handlerA.GetByID)

	req := httptest.NewRequest(http.MethodGet, "/api/sboms/"+uploadA.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
