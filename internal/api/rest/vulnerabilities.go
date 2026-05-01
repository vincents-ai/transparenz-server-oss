// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
)

type VulnerabilityHandler struct {
	vulnRepo *repository.VulnerabilityRepository
	grcRepo  *repository.GRCMappingRepository
}

func NewVulnerabilityHandler(vulnRepo *repository.VulnerabilityRepository, grcRepo *repository.GRCMappingRepository) *VulnerabilityHandler {
	return &VulnerabilityHandler{
		vulnRepo: vulnRepo,
		grcRepo:  grcRepo,
	}
}

type VulnerabilityFilters struct {
	Exploited       bool    `form:"exploited"`
	SovereignSource string  `form:"sovereign_source"`
	Severity        string  `form:"severity"`
	CvssMin         float64 `form:"cvss_min"`
	Limit           int     `form:"limit,default=50"`
	Offset          int     `form:"offset,default=0"`
	IncludeGRC      bool    `form:"include_grc"`
}

type vulnerabilityResponse struct {
	models.Vulnerability
	GRCMappings []models.GRCMapping `json:"grc_mappings"`
}

func (h *VulnerabilityHandler) ListVulnerabilities(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	var filters VulnerabilityFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		api.BadRequest(c, "invalid query parameters")
		return
	}

	if filters.Limit <= 0 || filters.Limit > 100 {
		filters.Limit = 50
	}

	repoFilters := repository.VulnFilterParams{
		Exploited:       filters.Exploited,
		SovereignSource: filters.SovereignSource,
		Severity:        filters.Severity,
		CvssMin:         filters.CvssMin,
		Limit:           filters.Limit,
		Offset:          filters.Offset,
	}

	vulns, total, err := h.vulnRepo.ListWithFilters(ctx, repoFilters)
	if err != nil {
		api.InternalError(c, "failed to list vulnerabilities")
		return
	}

	if !filters.IncludeGRC {
		c.JSON(http.StatusOK, gin.H{
			"data":   vulns,
			"limit":  filters.Limit,
			"offset": filters.Offset,
			"count":  len(vulns),
			"total":  total,
		})
		return
	}

	vulnIDs := make([]uuid.UUID, 0, len(vulns))
	for _, v := range vulns {
		vulnIDs = append(vulnIDs, v.ID)
	}

	allMappings, err := h.grcRepo.ListByVulnerabilityIDs(ctx, vulnIDs)
	if err != nil {
		api.InternalError(c, "failed to fetch GRC mappings")
		return
	}

	mappingByVulnID := make(map[uuid.UUID][]models.GRCMapping, len(vulns))
	for _, m := range allMappings {
		if m.VulnerabilityID != nil {
			mappingByVulnID[*m.VulnerabilityID] = append(mappingByVulnID[*m.VulnerabilityID], m)
		}
	}

	data := make([]vulnerabilityResponse, 0, len(vulns))
	for _, v := range vulns {
		data = append(data, vulnerabilityResponse{
			Vulnerability: v,
			GRCMappings:   mappingByVulnID[v.ID],
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   data,
		"limit":  filters.Limit,
		"offset": filters.Offset,
		"count":  len(data),
		"total":  total,
	})
}

func (h *VulnerabilityHandler) GetVulnerability(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found in context")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	cve := c.Param("cve")
	if cve == "" {
		api.BadRequest(c, "CVE is required")
		return
	}

	if !regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`).MatchString(cve) {
		api.BadRequest(c, "invalid CVE identifier format")
		return
	}

	vuln, err := h.vulnRepo.GetByCVE(ctx, cve)
	if err != nil {
		if errors.Is(err, repository.ErrVulnerabilityNotFound) {
			api.NotFound(c, "vulnerability not found")
			return
		}
		api.InternalError(c, "failed to get vulnerability")
		return
	}

	grcMappings, _ := h.grcRepo.ListByVulnerabilityID(ctx, vuln.ID)

	c.JSON(http.StatusOK, vulnerabilityResponse{
		Vulnerability: *vuln,
		GRCMappings:   grcMappings,
	})
}
