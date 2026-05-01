// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
	"github.com/vincents-ai/transparenz-server-oss/pkg/interfaces"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
)

// ENISAHandler handles ENISA submission and listing requests.
type ENISAHandler struct {
	submitter interfaces.ENISASubmitter
	subRepo   *repository.EnisaSubmissionRepository
	logger    *zap.Logger
}

// NewENISAHandler creates a handler for ENISA submission operations.
func NewENISAHandler(submitter interfaces.ENISASubmitter, subRepo *repository.EnisaSubmissionRepository, logger *zap.Logger) *ENISAHandler {
	return &ENISAHandler{
		submitter: submitter,
		subRepo:   subRepo,
		logger:    logger,
	}
}

// SubmitRequest holds the CVE identifier for ENISA submission.
type SubmitRequest struct {
	CVE string `json:"cve" binding:"required,max=32"`
}

func (h *ENISAHandler) Submit(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	var req SubmitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request format")
		return
	}

	submission, err := h.submitter.Submit(middleware.ContextWithOrgID(c.Request.Context(), orgUUID), orgUUID, req.CVE, nil)
	if err != nil {
		h.logger.Error("failed to submit CVE to ENISA", zap.Error(err))
		api.InternalError(c, "failed to submit CVE")
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"submission_id": submission.ID,
		"status":        submission.Status,
		"cve":           req.CVE,
	})
}

func (h *ENISAHandler) ListSubmissions(c *gin.Context) {
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
			limit = parsed
		}
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	submissions, err := h.subRepo.List(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list ENISA submissions", zap.Error(err))
		api.InternalError(c, "failed to list submissions")
		return
	}

	total, err := h.subRepo.Count(ctx)
	if err != nil {
		h.logger.Error("failed to count ENISA submissions", zap.Error(err))
		api.InternalError(c, "failed to count submissions")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   submissions,
		"limit":  limit,
		"offset": offset,
		"count":  len(submissions),
		"total":  total,
	})
}

func (h *ENISAHandler) GetSubmission(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid submission ID")
		return
	}

	submission, err := h.subRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrEnisaSubmissionNotFound) {
			api.NotFound(c, "submission not found")
			return
		}
		h.logger.Error("failed to get ENISA submission", zap.Error(err))
		api.InternalError(c, "failed to get submission")
		return
	}

	c.JSON(http.StatusOK, submission)
}

func (h *ENISAHandler) DownloadSubmission(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		api.BadRequest(c, "invalid submission ID")
		return
	}

	submission, err := h.subRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrEnisaSubmissionNotFound) {
			api.NotFound(c, "submission not found")
			return
		}
		h.logger.Error("failed to get ENISA submission for download", zap.Error(err))
		api.InternalError(c, "failed to get submission")
		return
	}

	jsonData, err := json.Marshal(submission.CsafDocument)
	if err != nil {
		h.logger.Error("failed to marshal CSAF document", zap.Error(err))
		api.InternalError(c, "failed to marshal CSAF")
		return
	}

	filename := fmt.Sprintf("csaf-submission-%s.json", submission.ID.String())
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", strings.Map(sanitizeFilename, filename)))
	c.Header("Content-Type", "application/json")

	c.Data(http.StatusOK, "application/json", jsonData)
}

// sanitizeFilename strips characters that are unsafe in Content-Disposition filenames.
func sanitizeFilename(r rune) rune {
	if r < 32 || r == '"' || r == '\\' || r == '\n' || r == '\r' {
		return '_'
	}
	return r
}
