// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
	"github.com/transparenz/transparenz-server-oss/internal/services"
	"go.uber.org/zap"
)

// VEXHandler handles VEX statement creation, approval, and publishing.
type VEXHandler struct {
	vexService *services.VEXService
	stmtRepo   *repository.VexStatementRepository
	logger     *zap.Logger
}

// NewVEXHandler creates a handler for VEX statement operations.
func NewVEXHandler(vexService *services.VEXService, stmtRepo *repository.VexStatementRepository, logger *zap.Logger) *VEXHandler {
	return &VEXHandler{vexService: vexService, stmtRepo: stmtRepo, logger: logger}
}

func (h *VEXHandler) CreateVEX(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	var req struct {
		CVE       string `json:"cve" binding:"required,max=32"`
		ProductID string `json:"product_id" binding:"required,max=256"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request body: cve and product_id are required")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)
	stmt, err := h.vexService.AutoDraftVEX(ctx, orgUUID, req.CVE, req.ProductID)
	if err != nil {
		h.logger.Error("failed to create VEX statement", zap.Error(err))
		api.InternalError(c, "failed to create VEX statement")
		return
	}

	c.JSON(http.StatusCreated, stmt)
}

func (h *VEXHandler) ListVEX(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
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
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	stmts, err := h.stmtRepo.ListByOrg(c.Request.Context(), orgUUID, limit, offset)
	if err != nil {
		h.logger.Error("failed to list VEX statements", zap.Error(err))
		api.InternalError(c, "failed to list VEX statements")
		return
	}

	if stmts == nil {
		stmts = []models.VexStatement{}
	}

	total, err := h.stmtRepo.CountByOrg(c.Request.Context(), orgUUID)
	if err != nil {
		h.logger.Error("failed to count VEX statements", zap.Error(err))
		api.InternalError(c, "failed to count VEX statements")
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": stmts, "limit": limit, "offset": offset, "count": len(stmts), "total": total})
}

func (h *VEXHandler) ApproveVEX(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	vexID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid vex id")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)
	stmt, err := h.vexService.ApproveVEX(ctx, vexID)
	if err != nil {
		api.BadRequest(c, "failed to approve VEX statement")
		return
	}

	c.JSON(http.StatusOK, stmt)
}

func (h *VEXHandler) PublishVEX(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	vexID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid vex id")
		return
	}

	var req struct {
		Channel string `json:"channel" binding:"required,oneof=file csaf enisa"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request body: channel is required and must be one of file, csaf, enisa")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)
	pub, err := h.vexService.PublishVEX(ctx, vexID, req.Channel)
	if err != nil {
		api.BadRequest(c, "failed to publish VEX statement")
		return
	}

	c.JSON(http.StatusOK, pub)
}
