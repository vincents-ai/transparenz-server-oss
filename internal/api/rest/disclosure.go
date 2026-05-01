// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"net/http"
	"regexp"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/services"
	"go.uber.org/zap"
)

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// DisclosureHandler handles vulnerability disclosure lifecycle requests.
type DisclosureHandler struct {
	svc    *services.DisclosureService
	logger *zap.Logger
}

// NewDisclosureHandler creates a handler for vulnerability disclosure operations.
func NewDisclosureHandler(svc *services.DisclosureService, logger *zap.Logger) *DisclosureHandler {
	return &DisclosureHandler{svc: svc, logger: logger}
}

// CreateDisclosureRequest holds the fields for creating a new vulnerability disclosure.
type CreateDisclosureRequest struct {
	Cve            string `json:"cve" binding:"required"`
	Title          string `json:"title" binding:"required,max=512"`
	Description    string `json:"description" binding:"omitempty,max=8192"`
	Severity       string `json:"severity"`
	ReporterName   string `json:"reporter_name" binding:"omitempty,max=256"`
	ReporterEmail  string `json:"reporter_email" binding:"omitempty,max=256,email"`
	ReporterPublic bool   `json:"reporter_public"`
}

func (h *DisclosureHandler) CreateDisclosure(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	orgUUID, err := getOrgUUID(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	var req CreateDisclosureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request body: cve and title are required")
		return
	}

	if !cveRegex.MatchString(req.Cve) {
		api.BadRequest(c, "invalid CVE format: must match CVE-YYYY-NNNNN")
		return
	}

	disclosure := &models.VulnerabilityDisclosure{
		Cve:            req.Cve,
		Title:          req.Title,
		Description:    req.Description,
		Severity:       req.Severity,
		ReporterName:   req.ReporterName,
		ReporterEmail:  req.ReporterEmail,
		ReporterPublic: req.ReporterPublic,
	}

	created, err := h.svc.ReceiveDisclosure(ctx, orgUUID, disclosure)
	if err != nil {
		api.BadRequest(c, "failed to create disclosure")
		return
	}

	c.JSON(http.StatusCreated, created)
}

func (h *DisclosureHandler) ListDisclosures(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	limit, offset := parseLimitOffset(c)
	disclosures, err := h.svc.ListByOrg(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list disclosures", zap.Error(err))
		api.InternalError(c, "failed to list disclosures")
		return
	}

	total, err := h.svc.CountByOrg(ctx)
	if err != nil {
		h.logger.Error("failed to count disclosures", zap.Error(err))
		api.InternalError(c, "failed to count disclosures")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   disclosures,
		"limit":  limit,
		"offset": offset,
		"count":  len(disclosures),
		"total":  total,
	})
}

func (h *DisclosureHandler) GetDisclosure(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid disclosure id")
		return
	}

	disclosure, err := h.svc.GetByID(ctx, id)
	if err != nil {
		if err == services.ErrDisclosureNotFound {
			api.NotFound(c, "disclosure not found")
			return
		}
		h.logger.Error("failed to get disclosure", zap.Error(err))
		api.InternalError(c, "failed to get disclosure")
		return
	}

	c.JSON(http.StatusOK, disclosure)
}

// UpdateStatusRequest holds the fields for updating a disclosure's status.
type UpdateStatusRequest struct {
	Status           string `json:"status" binding:"required"`
	CoordinatorName  string `json:"coordinator_name"`
	CoordinatorEmail string `json:"coordinator_email"`
	FixCommit        string `json:"fix_commit" binding:"omitempty,max=512"`
	FixVersion       string `json:"fix_version" binding:"omitempty,max=128"`
	InternalNotes    string `json:"internal_notes" binding:"omitempty,max=8192"`
}

func (h *DisclosureHandler) UpdateStatus(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid disclosure id")
		return
	}

	var req UpdateStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request body: status is required")
		return
	}

	switch req.Status {
	case "triaging":
		err = h.svc.StartTriaging(ctx, id)
	case "acknowledged":
		err = h.svc.AcknowledgeDisclosure(ctx, id, req.CoordinatorName, req.CoordinatorEmail)
	case "fixing":
		err = h.svc.StartFixing(ctx, id)
	case "fixed":
		err = h.svc.MarkFixed(ctx, id, req.FixCommit, req.FixVersion)
	case "disclosed":
		err = h.svc.Disclose(ctx, id)
	case "rejected":
		err = h.svc.RejectDisclosure(ctx, id, req.InternalNotes)
	case "withdrawn":
		err = h.svc.WithdrawDisclosure(ctx, id)
	default:
		api.BadRequest(c, "invalid status: must be one of triaging, acknowledged, fixing, fixed, disclosed, rejected, withdrawn")
		return
	}

	if err != nil {
		if err == services.ErrDisclosureNotFound {
			api.NotFound(c, "disclosure not found")
			return
		}
		h.logger.Error("failed to update disclosure status", zap.Error(err))
		api.InternalError(c, "failed to update disclosure status")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "status updated", "status": req.Status})
}

func (h *DisclosureHandler) CheckSLACompliance(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	violations, err := h.svc.CheckSLACompliance(ctx)
	if err != nil {
		h.logger.Error("failed to check SLA compliance", zap.Error(err))
		api.InternalError(c, "failed to check SLA compliance")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  violations,
		"count": len(violations),
	})
}

func getOrgUUID(c *gin.Context) (uuid.UUID, error) {
	return middleware.GetOrgUUIDFromContext(c)
}

func parseLimitOffset(c *gin.Context) (limit, offset int) {
	limit, _ = strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ = strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return
}
