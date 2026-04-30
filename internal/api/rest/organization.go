// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
	"go.uber.org/zap"
)

// OrganizationHandler handles organization-level management requests.
type OrganizationHandler struct {
	orgRepo *repository.OrganizationRepository
	logger  *zap.Logger
}

// NewOrganizationHandler creates a handler for organization operations.
func NewOrganizationHandler(orgRepo *repository.OrganizationRepository, logger *zap.Logger) *OrganizationHandler {
	return &OrganizationHandler{orgRepo: orgRepo, logger: logger}
}

// UpdateSupportPeriodRequest holds the number of months for support period updates.
type UpdateSupportPeriodRequest struct {
	Months int `json:"months" binding:"required"`
}

func (h *OrganizationHandler) UpdateSupportPeriod(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	var req UpdateSupportPeriodRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request body: months is required")
		return
	}

	org := &models.Organization{SupportPeriodMonths: req.Months}
	if err := org.ValidateSupportPeriod(); err != nil {
		api.BadRequest(c, err.Error())
		return
	}

	if err := h.orgRepo.UpdateSupportPeriod(ctx, orgUUID, req.Months); err != nil {
		h.logger.Error("failed to update support period", zap.Error(err))
		api.InternalError(c, "failed to update support period")
		return
	}

	status, err := h.orgRepo.GetSupportPeriodStatus(ctx, orgUUID)
	if err != nil {
		h.logger.Error("failed to retrieve support period status", zap.Error(err))
		api.InternalError(c, "failed to retrieve support period status")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"support_period_months": status.SupportPeriodMonths,
		"support_start_date":    status.SupportStartDate,
		"support_end_date":      status.SupportEndDate,
		"months_remaining":      status.MonthsRemaining,
		"days_remaining":        status.DaysRemaining,
		"is_expired":            status.IsExpired,
		"percentage_elapsed":    status.PercentageElapsed,
	})
}

func (h *OrganizationHandler) GetSupportPeriod(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	status, err := h.orgRepo.GetSupportPeriodStatus(ctx, orgUUID)
	if err != nil {
		if errors.Is(err, repository.ErrOrganizationNotFound) {
			api.NotFound(c, "organization not found")
			return
		}
		h.logger.Error("failed to retrieve support period status", zap.Error(err))
		api.InternalError(c, "failed to retrieve support period status")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"support_period_months": status.SupportPeriodMonths,
		"support_start_date":    status.SupportStartDate,
		"support_end_date":      status.SupportEndDate,
		"months_remaining":      status.MonthsRemaining,
		"days_remaining":        status.DaysRemaining,
		"is_expired":            status.IsExpired,
		"percentage_elapsed":    status.PercentageElapsed,
	})
}
