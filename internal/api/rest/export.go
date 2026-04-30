// Copyright (c) 2026 Vincent Palmer. All rights reserved.

package rest

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/internal/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
)

// ExportHandler handles audit export in CSV format.
// PDF export is available in the commercial edition.
type ExportHandler struct {
	eventRepo *repository.ComplianceEventRepository
	orgRepo   *repository.OrganizationRepository
	sbomRepo  *repository.SbomRepository
	grcRepo   *repository.GRCMappingRepository
}

// NewExportHandler creates a handler for audit export operations.
func NewExportHandler(
	eventRepo *repository.ComplianceEventRepository,
	orgRepo *repository.OrganizationRepository,
	sbomRepo *repository.SbomRepository,
	grcRepo *repository.GRCMappingRepository,
) *ExportHandler {
	return &ExportHandler{
		eventRepo: eventRepo,
		orgRepo:   orgRepo,
		sbomRepo:  sbomRepo,
		grcRepo:   grcRepo,
	}
}

func (h *ExportHandler) ExportAudit(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found")
		return
	}

	_ = orgUUID
	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	format := c.DefaultQuery("format", "csv")
	_ = c.DefaultQuery("template", "bsi_tr03116")
	startStr := c.Query("start")
	endStr := c.Query("end")

	var start, end time.Time
	if startStr != "" {
		start, err = time.Parse("2006-01-02", startStr)
		if err != nil {
			api.BadRequest(c, "invalid start date format")
			return
		}
	} else {
		start = time.Now().AddDate(0, -1, 0)
	}

	if endStr != "" {
		end, err = time.Parse("2006-01-02", endStr)
		if err != nil {
			api.BadRequest(c, "invalid end date format")
			return
		}
	} else {
		end = time.Now()
	}

	events, err := h.eventRepo.ListByDateRange(ctx, start, end)
	if err != nil {
		api.InternalError(c, "failed to fetch events")
		return
	}

	switch format {
	case "csv":
		h.exportCSV(c, events)
	default:
		api.BadRequest(c, "unsupported format: use csv (pdf requires commercial edition)")
	}
}

func (h *ExportHandler) exportCSV(c *gin.Context, events []models.ComplianceEvent) {
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=audit-export-%s.csv", time.Now().Format("2006-01-02")))

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	if err := writer.Write([]string{"Timestamp", "Event Type", "Severity", "CVE", "Details"}); err != nil {
		zap.L().Error("failed to write CSV header", zap.Error(err))
		return
	}

	for _, event := range events {
		if err := writer.Write([]string{
			event.Timestamp.Format("2006-01-02 15:04:05"),
			event.EventType,
			event.Severity,
			event.Cve,
			event.Metadata.String(),
		}); err != nil {
			zap.L().Error("failed to write CSV row", zap.String("event_type", event.EventType), zap.Error(err))
		}
	}
}

func (h *ExportHandler) ExportEnrichedSBOM(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization ID not found")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgUUID)

	sbomID, err := uuid.Parse(c.Param("sbom_id"))
	if err != nil {
		api.BadRequest(c, "invalid sbom_id format")
		return
	}

	doc, err := h.sbomRepo.GetDocument(ctx, sbomID)
	if err != nil {
		if err == repository.ErrSbomUploadNotFound {
			api.NotFound(c, "SBOM not found")
			return
		}
		zap.L().Error("failed to fetch SBOM document", zap.Error(err))
		api.InternalError(c, "failed to fetch SBOM document")
		return
	}

	mappings, err := h.grcRepo.ListByOrg(ctx, orgUUID)
	if err != nil {
		zap.L().Error("failed to fetch GRC mappings", zap.Error(err))
		api.InternalError(c, "failed to fetch GRC mappings")
		return
	}

	grcByCVE := make(map[string][]models.GRCMapping)
	for _, m := range mappings {
		if m.Vulnerability != nil {
			grcByCVE[m.Vulnerability.Cve] = append(grcByCVE[m.Vulnerability.Cve], m)
		}
	}

	var sbom map[string]interface{}
	if err := json.Unmarshal(doc, &sbom); err != nil {
		api.InternalError(c, "failed to parse SBOM document")
		return
	}

	vulns, ok := sbom["vulnerabilities"].([]interface{})
	if !ok {
		c.Header("Content-Type", "application/json")
		c.Data(http.StatusOK, "application/json", doc)
		return
	}

	for i, v := range vulns {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		cveID := ""
		if id, ok := vuln["id"].(string); ok {
			cveID = id
		}

		mappings := grcByCVE[cveID]
		if len(mappings) == 0 {
			continue
		}

		var props []interface{}
		if existing, ok := vuln["properties"].([]interface{}); ok {
			props = existing
		}

		for _, m := range mappings {
			props = append(props, map[string]interface{}{
				"name": fmt.Sprintf("transparenz:grc:%s:%s", m.Framework, m.ControlID),
				"value": map[string]interface{}{
					"mapping_type": m.MappingType,
					"confidence":   m.Confidence,
					"evidence":     m.Evidence,
					"framework":    m.Framework,
					"control_id":   m.ControlID,
				},
			})
		}

		vuln["properties"] = props
		vulns[i] = vuln
	}

	sbom["vulnerabilities"] = vulns

	out, err := json.Marshal(sbom)
	if err != nil {
		api.InternalError(c, "failed to serialize enriched SBOM")
		return
	}

	c.Header("Content-Type", "application/vnd.cyclonedx+json")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="enriched-sbom-%s.json"`, sbomID))
	c.Data(http.StatusOK, "application/vnd.cyclonedx+json", out)
}
