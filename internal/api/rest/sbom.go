// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"go.uber.org/zap"
)

// SbomHandler handles SBOM upload, listing, and retrieval requests.
type SbomHandler struct {
	sbomRepo              *repository.SbomRepository
	maxSize               int64
	alertHub              *services.AlertHub
	insertIntoPublicSBOMs func(ctx context.Context, upload *models.SbomUpload) error
}

// NewSbomHandler creates a handler for SBOM upload operations.
func NewSbomHandler(sbomRepo *repository.SbomRepository, maxSize int64, alertHub *services.AlertHub) *SbomHandler {
	return &SbomHandler{
		sbomRepo: sbomRepo,
		maxSize:  maxSize,
		alertHub: alertHub,
		insertIntoPublicSBOMs: func(ctx context.Context, upload *models.SbomUpload) error {
			return sbomRepo.InsertIntoPublic(ctx, upload)
		},
	}
}

// UploadResponse contains the metadata of a successfully uploaded SBOM.
type UploadResponse struct {
	ID        uuid.UUID `json:"id"`
	Filename  string    `json:"filename"`
	Format    string    `json:"format"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
}

func (h *SbomHandler) Upload(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	if h.maxSize > 0 {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, h.maxSize)
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		api.BadRequest(c, "file is required")
		return
	}
	defer file.Close() //nolint:errcheck

	if h.maxSize > 0 && header.Size > h.maxSize {
		api.BadRequest(c, "file exceeds maximum allowed size")
		return
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	// Check for .cdx.json compound extension first
	fullExt := strings.ToLower(header.Filename)
	if strings.HasSuffix(fullExt, ".cdx.json") || strings.HasSuffix(fullExt, ".cdx.xml") {
		ext = ".cdx"
	}
	format, ok := extensionToFormat(ext, header.Header.Get("Content-Type"))
	if !ok {
		api.BadRequest(c, "unsupported file format: must be SPDX or CycloneDX (JSON or XML)")
		return
	}

	tmpFile, err := os.CreateTemp("", "sbom-upload-*")
	if err != nil {
		api.InternalError(c, "failed to create temp file")
		return
	}
	defer os.Remove(tmpFile.Name())

	limited := io.LimitReader(file, h.maxSize+1)
	written, err := io.Copy(tmpFile, limited)
	if err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			zap.L().Warn("failed to close temp file", zap.Error(closeErr))
		}
		api.InternalError(c, "failed to read uploaded file")
		return
	}
	if written > h.maxSize {
		if closeErr := tmpFile.Close(); closeErr != nil {
			zap.L().Warn("failed to close temp file", zap.Error(closeErr))
		}
		api.BadRequest(c, "file exceeds maximum allowed size")
		return
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			zap.L().Warn("failed to close temp file", zap.Error(closeErr))
		}
		api.InternalError(c, "failed to process uploaded file")
		return
	}

	data, err := io.ReadAll(tmpFile)
	if closeErr := tmpFile.Close(); closeErr != nil {
		zap.L().Warn("failed to close temp file", zap.Error(closeErr))
	}
	if err != nil {
		api.InternalError(c, "failed to read temp file")
		return
	}

	if !strings.Contains(format, "xml") && !json.Valid(data) {
		api.BadRequest(c, "file content is not valid JSON")
		return
	}

	if err := validateSBOMStructure(data, format); err != nil {
		api.BadRequest(c, err.Error())
		return
	}

	hash := sha256.Sum256(data)
	sha256Str := hex.EncodeToString(hash[:])

	exists, err := h.sbomRepo.ExistsBySHA256(ctx, sha256Str)
	if err != nil {
		api.InternalError(c, "failed to check for duplicate SBOM")
		return
	}
	if exists {
		c.Header("Content-Type", "application/problem+json")
		c.AbortWithStatusJSON(http.StatusConflict, api.ProblemDetail{
			Type:   api.ErrBadRequest,
			Title:  "Conflict",
			Status: http.StatusConflict,
			Detail: "SBOM with identical content already exists",
		})
		return
	}

	upload := &models.SbomUpload{
		ID:        uuid.New(),
		Filename:  header.Filename,
		Format:    format,
		SizeBytes: int64(len(data)),
		SHA256:    sha256Str,
		Document:  json.RawMessage(data),
	}

	if err := h.sbomRepo.CreateUpload(ctx, orgUUID, upload); err != nil {
		api.InternalError(c, "failed to store SBOM upload")
		return
	}

	go func() {
		if h.alertHub != nil {
			h.alertHub.Broadcast(orgUUID.String(), &services.Alert{
				Type:      "sbom_uploaded",
				Severity:  "info",
				Message:   "New SBOM uploaded: " + upload.Filename,
				Timestamp: time.Now(),
			})
		}
	}()

	if h.insertIntoPublicSBOMs != nil {
		if err := h.insertIntoPublicSBOMs(ctx, upload); err != nil {
			api.InternalError(c, "failed to store SBOM for scan compatibility")
			return
		}
	}

	c.JSON(http.StatusCreated, UploadResponse{
		ID:        upload.ID,
		Filename:  upload.Filename,
		Format:    upload.Format,
		SizeBytes: upload.SizeBytes,
		SHA256:    upload.SHA256,
	})
}

func (h *SbomHandler) List(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

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
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	uploads, err := h.sbomRepo.List(ctx, limit, offset)
	if err != nil {
		api.InternalError(c, "failed to list SBOM uploads")
		return
	}

	if uploads == nil {
		uploads = []models.SbomUpload{}
	}

	total, err := h.sbomRepo.Count(ctx)
	if err != nil {
		api.InternalError(c, "failed to count SBOM uploads")
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": uploads, "limit": limit, "offset": offset, "count": len(uploads), "total": total})
}

func (h *SbomHandler) GetByID(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid id format")
		return
	}

	upload, err := h.sbomRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrSbomUploadNotFound) {
			api.NotFound(c, "SBOM upload not found")
			return
		}
		api.InternalError(c, "failed to retrieve SBOM upload")
		return
	}

	c.JSON(http.StatusOK, upload)
}

func (h *SbomHandler) Download(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid id format")
		return
	}

	doc, err := h.sbomRepo.GetDocument(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrSbomUploadNotFound) {
			api.NotFound(c, "SBOM upload not found")
			return
		}
		api.InternalError(c, "failed to retrieve SBOM document")
		return
	}

	upload, err := h.sbomRepo.GetByID(ctx, id)
	if err != nil {
		api.InternalError(c, "failed to retrieve SBOM metadata")
		return
	}

	contentType := "application/json"
	if strings.HasSuffix(upload.Format, "+xml") || strings.HasSuffix(upload.Format, "-xml") {
		contentType = "application/xml"
	}

	safeName := filepath.Base(upload.Filename)
	safeName = strings.Map(func(r rune) rune {
		if r < 32 || r == '"' || r == '\\' || r == '\n' || r == '\r' {
			return '_'
		}
		return r
	}, safeName)

	c.Header("Content-Disposition", "attachment; filename=\""+safeName+"\"")
	c.Data(http.StatusOK, contentType, doc)
}

func (h *SbomHandler) Delete(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid id format")
		return
	}

	if err := h.sbomRepo.Delete(ctx, id); err != nil {
		if errors.Is(err, repository.ErrSbomUploadNotFound) {
			api.NotFound(c, "SBOM upload not found")
			return
		}
		api.InternalError(c, "failed to delete SBOM upload")
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

func extensionToFormat(ext, contentType string) (string, bool) {
	switch ext {
	case ".json":
		ct := strings.ToLower(contentType)
		if strings.Contains(ct, "cyclonedx") {
			return "cyclonedx-json", true
		}
		return "spdx-json", true
	case ".xml":
		ct := strings.ToLower(contentType)
		if strings.Contains(ct, "cyclonedx") {
			return "cyclonedx-xml", true
		}
		return "spdx+xml", true
	case ".spdx":
		return "spdx-json", true
	case ".cdx":
		return "cyclonedx-json", true
	}
	return "", false
}

func validateSBOMStructure(data []byte, format string) error {
	switch format {
	case "spdx-json", "cyclonedx-json":
		var js json.RawMessage
		if err := json.Unmarshal(data, &js); err != nil {
			return fmt.Errorf("invalid JSON structure: %w", err)
		}
	case "spdx+xml", "cyclonedx-xml":
		if err := xml.Unmarshal(data, &struct{ XMLName xml.Name }{}); err != nil {
			return fmt.Errorf("invalid XML structure: %w", err)
		}
	}

	// Additional field validation for JSON formats
	switch {
	case format == "spdx-json":
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			return err
		}
		if _, ok := doc["spdxVersion"]; !ok {
			return &sbomValidationError{"invalid SPDX document: missing spdxVersion field"}
		}
	case format == "cyclonedx-json":
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			return err
		}
		if _, ok := doc["bomFormat"]; !ok {
			return &sbomValidationError{"invalid CycloneDX document: missing bomFormat field"}
		}
	}

	return nil
}

type sbomValidationError struct {
	msg string
}

func (e *sbomValidationError) Error() string {
	return e.msg
}
