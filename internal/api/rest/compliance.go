// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
)

var vulnerabilitiesExploitedTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "vulnerabilities_exploited_total",
	Help: "Total number of exploited vulnerabilities reported",
})

func init() {
	prometheus.MustRegister(vulnerabilitiesExploitedTotal)
}

// ComplianceHandler handles compliance status and SLA tracking requests.
type ComplianceHandler struct {
	slaRepo   *repository.SlaTrackingRepository
	vulnRepo  *repository.VulnerabilityRepository
	eventRepo *repository.ComplianceEventRepository
	orgRepo   *repository.OrganizationRepository
	grcRepo   *repository.GRCMappingRepository
	logger    *zap.Logger
}

// NewComplianceHandler creates a handler for compliance operations.
func NewComplianceHandler(
	slaRepo *repository.SlaTrackingRepository,
	vulnRepo *repository.VulnerabilityRepository,
	eventRepo *repository.ComplianceEventRepository,
	orgRepo *repository.OrganizationRepository,
	grcRepo *repository.GRCMappingRepository,
	logger *zap.Logger,
) *ComplianceHandler {
	return &ComplianceHandler{
		slaRepo:   slaRepo,
		vulnRepo:  vulnRepo,
		eventRepo: eventRepo,
		orgRepo:   orgRepo,
		grcRepo:   grcRepo,
		logger:    logger,
	}
}

// ComplianceStatusResponse contains the organization's compliance metrics.
type ComplianceStatusResponse struct {
	ComplianceScore              float64          `json:"compliance_score"`
	SlaViolations                int64            `json:"sla_violations"`
	ApproachingDeadlines         int64            `json:"approaching_deadlines"`
	SovereignCoverage            float64          `json:"sovereign_coverage"`
	TotalSlas                    int64            `json:"total_slas"`
	ReportedSlas                 int64            `json:"reported_slas"`
	TotalVulnerabilities         int64            `json:"total_vulnerabilities"`
	VulnerabilitiesWithSource    int64            `json:"vulnerabilities_with_source"`
	SupportPeriodMonthsRemaining int64            `json:"support_period_months_remaining"`
	SupportPeriodExpired         bool             `json:"support_period_expired"`
	GRCFrameworks                map[string]int64 `json:"grc_frameworks"`
	GRCTotalMappings             int64            `json:"grc_total_mappings"`
	GRCVulnsWithMappings         int64            `json:"grc_vulns_with_mappings"`
	GRCVulnsWithoutMappings      int64            `json:"grc_vulns_without_mappings"`
	GRCAffectedFrameworks        []string         `json:"grc_affected_frameworks"`
}

func (h *ComplianceHandler) GetComplianceStatus(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	complianceScore, totalSlas, reportedSlas, err := h.calculateComplianceScore(ctx)
	if err != nil {
		api.InternalError(c, "failed to calculate compliance score")
		return
	}

	slaViolations, err := h.slaRepo.CountByStatus(ctx, "violated")
	if err != nil {
		api.InternalError(c, "failed to count SLA violations")
		return
	}

	approachingDeadlines, err := h.slaRepo.CountApproaching(ctx, 6*time.Hour)
	if err != nil {
		api.InternalError(c, "failed to count approaching deadlines")
		return
	}

	vulnWithSource, totalVulns, err := h.vulnRepo.CountBySovereignCoverage(ctx)
	if err != nil {
		api.InternalError(c, "failed to calculate sovereign coverage")
		return
	}

	sovereignCoverage := 0.0
	if totalVulns > 0 {
		sovereignCoverage = float64(vulnWithSource) / float64(totalVulns) * 100
	}

	supportMonthsRemaining := int64(0)
	supportExpired := true
	orgUUID, orgErr := middleware.GetOrgUUIDFromContext(c)
	if orgErr == nil {
		supportStatus, supportErr := h.orgRepo.GetSupportPeriodStatus(ctx, orgUUID)
		if supportErr == nil {
			supportMonthsRemaining = supportStatus.MonthsRemaining
			supportExpired = supportStatus.IsExpired
		}
	}

	grcFrameworks := map[string]int64{}
	var grcTotalMappings int64
	var grcVulnsWithMappings int64
	var grcAffectedFrameworks []string

	if orgErr == nil && h.grcRepo != nil {
		frameworkCounts, grcErr := h.grcRepo.CountByFramework(ctx, orgUUID)
		if grcErr == nil {
			grcFrameworks = frameworkCounts
			for _, count := range frameworkCounts {
				grcTotalMappings += count
			}
			for fw := range frameworkCounts {
				grcAffectedFrameworks = append(grcAffectedFrameworks, fw)
			}
			vulnsMapped, vulnsErr := h.grcRepo.CountDistinctVulnsWithMappings(ctx, orgUUID)
			if vulnsErr == nil {
				grcVulnsWithMappings = vulnsMapped
			}
		}
	}
	grcVulnsWithoutMappings := totalVulns - grcVulnsWithMappings
	if grcVulnsWithoutMappings < 0 {
		grcVulnsWithoutMappings = 0
	}

	c.JSON(http.StatusOK, ComplianceStatusResponse{
		ComplianceScore:              complianceScore,
		SlaViolations:                slaViolations,
		ApproachingDeadlines:         approachingDeadlines,
		SovereignCoverage:            sovereignCoverage,
		TotalSlas:                    totalSlas,
		ReportedSlas:                 reportedSlas,
		TotalVulnerabilities:         totalVulns,
		VulnerabilitiesWithSource:    vulnWithSource,
		SupportPeriodMonthsRemaining: supportMonthsRemaining,
		SupportPeriodExpired:         supportExpired,
		GRCFrameworks:                grcFrameworks,
		GRCTotalMappings:             grcTotalMappings,
		GRCVulnsWithMappings:         grcVulnsWithMappings,
		GRCVulnsWithoutMappings:      grcVulnsWithoutMappings,
		GRCAffectedFrameworks:        grcAffectedFrameworks,
	})
}

func (h *ComplianceHandler) calculateComplianceScore(ctx context.Context) (float64, int64, int64, error) {
	totalSlas, err := h.slaRepo.CountAll(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	reportedSlas, err := h.slaRepo.CountByStatus(ctx, "reported")
	if err != nil {
		return 0, 0, 0, err
	}

	if totalSlas == 0 {
		return 100.0, totalSlas, reportedSlas, nil
	}

	complianceScore := float64(reportedSlas) / float64(totalSlas) * 100
	return complianceScore, totalSlas, reportedSlas, nil
}

// SlaListQuery holds optional filtering parameters for SLA listing.
type SlaListQuery struct {
	Status      string `form:"status"`
	Approaching string `form:"approaching"`
	Limit       int    `form:"limit,default=50"`
	Offset      int    `form:"offset,default=0"`
}

// SlaTrackingResponse represents an SLA tracking entry in API responses.
type SlaTrackingResponse struct {
	ID             uuid.UUID  `json:"id"`
	Cve            string     `json:"cve"`
	SbomID         *uuid.UUID `json:"sbom_id,omitempty"`
	Deadline       time.Time  `json:"deadline"`
	HoursRemaining float64    `json:"hours_remaining"`
	Status         string     `json:"status"`
}

func (h *ComplianceHandler) ListSlaTracking(c *gin.Context) {
	ctx, err := orgContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}

	var query SlaListQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		api.BadRequest(c, "invalid query parameters")
		return
	}

	if query.Limit <= 0 || query.Limit > 100 {
		query.Limit = 50
	}

	var slas []models.SlaTracking
	var total int64

	switch {
	case query.Approaching == "true":
		slas, err = h.slaRepo.ListApproaching(ctx, 6*time.Hour)
		if err != nil {
			api.InternalError(c, "failed to list approaching SLAs")
			return
		}
		if query.Status != "" {
			var filtered []models.SlaTracking
			for _, sla := range slas {
				if sla.Status == query.Status {
					filtered = append(filtered, sla)
				}
			}
			slas = filtered
		}
		total = int64(len(slas))
	case query.Status != "":
		slas, err = h.slaRepo.ListByStatus(ctx, query.Status, query.Limit, query.Offset)
		if err != nil {
			api.InternalError(c, "failed to list SLAs by status")
			return
		}
		total, err = h.slaRepo.CountByStatus(ctx, query.Status)
		if err != nil {
			api.InternalError(c, "failed to count SLAs by status")
			return
		}
	default:
		slas, err = h.slaRepo.List(ctx, query.Limit, query.Offset)
		if err != nil {
			api.InternalError(c, "failed to list SLAs")
			return
		}
		total, err = h.slaRepo.CountAll(ctx)
		if err != nil {
			api.InternalError(c, "failed to count SLAs")
			return
		}
	}

	var response []SlaTrackingResponse
	now := time.Now()
	for _, sla := range slas {
		hoursRemaining := sla.Deadline.Sub(now).Hours()
		response = append(response, SlaTrackingResponse{
			ID:             sla.ID,
			Cve:            sla.Cve,
			SbomID:         sla.SbomID,
			Deadline:       sla.Deadline,
			HoursRemaining: hoursRemaining,
			Status:         sla.Status,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   response,
		"limit":  query.Limit,
		"offset": query.Offset,
		"count":  len(response),
		"total":  total,
	})
}

// ExploitedVulnerabilityRequest holds the CVE and optional SBOM IDs for reporting exploitation.
type ExploitedVulnerabilityRequest struct {
	Cve     string      `json:"cve" binding:"required,max=32"`
	SbomIDs []uuid.UUID `json:"sbom_ids"`
}

func (h *ComplianceHandler) ReportExploitedVulnerability(c *gin.Context) {
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

	var req ExploitedVulnerabilityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request body: CVE is required")
		return
	}

	if !regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`).MatchString(req.Cve) {
		api.BadRequest(c, "invalid CVE identifier format")
		return
	}

	vuln, err := h.vulnRepo.GetByCVE(ctx, req.Cve)
	if err != nil {
		if errors.Is(err, repository.ErrVulnerabilityNotFound) {
			api.NotFound(c, "CVE not found for this organization")
			return
		}
		api.InternalError(c, "failed to validate CVE")
		return
	}

	org, err := h.orgRepo.GetByID(ctx, orgUUID)
	if err != nil {
		api.InternalError(c, "failed to get organization")
		return
	}

	slaMode := org.SlaTrackingMode
	if slaMode == "" {
		slaMode = "per_cve"
	}

	if slaMode == "per_cve" {
		slas, err := h.slaRepo.ListPending(ctx)
		if err != nil {
			api.InternalError(c, "failed to fetch SLAs")
			return
		}

		var found bool
		for _, sla := range slas {
			if sla.Cve == req.Cve && sla.SbomID == nil {
				if err := h.slaRepo.UpdateStatus(ctx, sla.ID, "reported"); err != nil {
					api.InternalError(c, "failed to update SLA status")
					return
				}
				found = true
				break
			}
		}
		if !found {
			api.NotFound(c, "no pending SLA found for this CVE")
			return
		}
	} else if slaMode == "per_sbom" {
		if len(req.SbomIDs) == 0 {
			api.BadRequest(c, "sbom_ids required for per_sbom mode")
			return
		}

		slas, err := h.slaRepo.ListPending(ctx)
		if err != nil {
			api.InternalError(c, "failed to fetch SLAs")
			return
		}

		var updated int
		for _, sla := range slas {
			if sla.Cve == req.Cve {
				for _, sbomID := range req.SbomIDs {
					if sla.SbomID != nil && *sla.SbomID == sbomID {
						if err := h.slaRepo.UpdateStatus(ctx, sla.ID, "reported"); err != nil {
							api.InternalError(c, "failed to update SLA status")
							return
						}
						updated++
					}
				}
			}
		}
		if updated == 0 {
			api.NotFound(c, "no matching SLA found for CVE-SBOM combinations")
			return
		}
	}

	previousHash, err := h.eventRepo.GetLatestEventHash(ctx, orgUUID)
	if err != nil {
		h.logger.Warn("failed to get latest event hash, defaulting to empty",
			zap.String("org_id", orgUUID.String()),
			zap.Error(err),
		)
	}

	event := &models.ComplianceEvent{
		EventType:         "exploited_reported",
		Severity:          "high",
		Cve:               req.Cve,
		Metadata:          models.JSONMap{},
		PreviousEventHash: previousHash,
	}

	if err := h.eventRepo.Create(ctx, orgUUID, event); err != nil {
		api.InternalError(c, "failed to create audit log")
		return
	}

	vuln.ExploitedInWild = true
	if err := h.vulnRepo.Update(ctx, vuln); err != nil {
		api.InternalError(c, "failed to update vulnerability")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "exploited vulnerability reported successfully",
		"cve":     req.Cve,
	})
	vulnerabilitiesExploitedTotal.Inc()
}
