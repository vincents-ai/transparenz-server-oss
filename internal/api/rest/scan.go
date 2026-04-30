// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"go.uber.org/zap"
)

// ScanHandler handles scan creation and listing requests.
type ScanHandler struct {
	scanService  *services.ScanService
	scanVulnRepo *repository.ScanVulnerabilityRepository
	logger       *zap.Logger
}

// NewScanHandler creates a handler for scan operations.
func NewScanHandler(scanService *services.ScanService, logger *zap.Logger) *ScanHandler {
	return &ScanHandler{
		scanService: scanService,
		logger:      logger,
	}
}

// NewScanHandlerWithVulns creates a handler with access to the scan_vulnerabilities repository.
func NewScanHandlerWithVulns(scanService *services.ScanService, scanVulnRepo *repository.ScanVulnerabilityRepository, logger *zap.Logger) *ScanHandler {
	return &ScanHandler{
		scanService:  scanService,
		scanVulnRepo: scanVulnRepo,
		logger:       logger,
	}
}

// CreateScanRequest holds the SBOM ID for initiating a new scan.
type CreateScanRequest struct {
	SbomID string `json:"sbom_id" binding:"required"`
}

// CreateScanResponse contains the created scan's identifiers and status.
type CreateScanResponse struct {
	ScanID uuid.UUID `json:"scan_id"`
	OrgID  uuid.UUID `json:"org_id"`
	Status string    `json:"status"`
	SbomID uuid.UUID `json:"sbom_id"`
}

func (h *ScanHandler) CreateScan(c *gin.Context) {
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

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgID)
	scan, err := h.scanService.CreateScan(ctx, orgID, sbomID)
	if err != nil {
		if errors.Is(err, services.ErrSbomNotFound) {
			api.NotFound(c, "SBOM not found")
			return
		}
		h.logger.Error("failed to create scan", zap.Error(err))
		api.InternalError(c, "failed to create scan")
		return
	}

	c.JSON(http.StatusAccepted, CreateScanResponse{
		ScanID: scan.ID,
		OrgID:  orgID,
		Status: "in_progress",
		SbomID: sbomID,
	})
}

func (h *ScanHandler) ListScans(c *gin.Context) {
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
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
		}
	}

	scans, err := h.scanService.ListScans(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list scans", zap.Error(err))
		api.InternalError(c, "failed to list scans")
		return
	}

	total, err := h.scanService.CountScans(ctx)
	if err != nil {
		h.logger.Error("failed to count scans", zap.Error(err))
		api.InternalError(c, "failed to count scans")
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": scans, "limit": limit, "offset": offset, "count": len(scans), "total": total})
}

// GetScanVulnerabilities returns the vulnerability matches for a specific scan,
// enriched with CVE identifiers and severity from the vulnerability feed.
// Only scans belonging to the caller's organisation are accessible.
func (h *ScanHandler) GetScanVulnerabilities(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	scanIDStr := c.Param("id")
	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		api.BadRequest(c, "invalid scan ID format")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	// Verify the scan belongs to this organisation.
	scan, err := h.scanService.GetScan(ctx, scanID)
	if err != nil {
		if errors.Is(err, services.ErrScanNotFound) {
			api.NotFound(c, "scan not found")
			return
		}
		h.logger.Error("failed to get scan", zap.String("scan_id", scanIDStr), zap.Error(err))
		api.InternalError(c, "failed to get scan")
		return
	}
	if scan.OrgID != orgUUID {
		api.NotFound(c, "scan not found")
		return
	}

	if h.scanVulnRepo == nil {
		c.JSON(http.StatusOK, gin.H{"data": []struct{}{}, "count": 0})
		return
	}

	vulns, err := h.scanVulnRepo.ListByScanIDEnriched(ctx, scanID)
	if err != nil {
		h.logger.Error("failed to list scan vulnerabilities", zap.String("scan_id", scanIDStr), zap.Error(err))
		api.InternalError(c, "failed to list scan vulnerabilities")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  vulns,
		"count": len(vulns),
	})
}
