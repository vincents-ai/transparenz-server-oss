// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/services"
)

// AuditHandler handles audit chain verification requests.
type AuditHandler struct {
	signingService *services.SigningService
}

// NewAuditHandler creates a handler for audit chain operations.
func NewAuditHandler(signingService *services.SigningService) *AuditHandler {
	return &AuditHandler{signingService: signingService}
}

// VerifyAuditRequest holds the date range parameters for audit chain verification.
type VerifyAuditRequest struct {
	Start string `form:"start" binding:"required"`
	End   string `form:"end" binding:"required"`
}

func (h *AuditHandler) VerifyAuditChain(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	var req VerifyAuditRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		api.BadRequest(c, "start and end query parameters are required (format: 2006-01-02)")
		return
	}

	start, err := time.Parse("2006-01-02", req.Start)
	if err != nil {
		api.BadRequest(c, "invalid start date format, use YYYY-MM-DD")
		return
	}

	end, err := time.Parse("2006-01-02", req.End)
	if err != nil {
		api.BadRequest(c, "invalid end date format, use YYYY-MM-DD")
		return
	}

	end = end.Add(23*time.Hour + 59*time.Minute + 59*time.Second)

	results, err := h.signingService.VerifyEventChain(orgUUID, start, end)
	if err != nil {
		api.InternalError(c, "failed to verify audit chain")
		return
	}

	if results == nil {
		results = []services.EventVerification{}
	}

	allVerified := true
	for _, r := range results {
		if !r.Verified {
			allVerified = false
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"verified":        allVerified,
		"total_events":    len(results),
		"verified_events": results,
	})
}
