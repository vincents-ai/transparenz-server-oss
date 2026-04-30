// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var greenboneSbomNamespace = uuid.MustParse("a441b15f-9762-4307-b8dd-6646e4bb7085")

var severityThresholds = map[string]float64{
	"low":      0.1,
	"medium":   4.0,
	"high":     7.0,
	"critical": 9.0,
}

// GreenboneService processes GVM/OpenVAS reports and creates vulnerability findings.
type GreenboneService struct {
	greenboneRepo    *repository.GreenboneRepository
	scanRepo         *repository.ScanRepository
	vulnRepo         *repository.VulnerabilityRepository
	alertHub         *AlertHub
	telemetryService *TelemetryService
	csafGenerator    *CSAFGenerator
	db               *gorm.DB
	logger           *zap.Logger
}

func (s *GreenboneService) SetCSAFGenerator(g *CSAFGenerator) {
	s.csafGenerator = g
}

// NewGreenboneService creates a GreenboneService with the given repository and infrastructure dependencies.
func NewGreenboneService(
	greenboneRepo *repository.GreenboneRepository,
	scanRepo *repository.ScanRepository,
	vulnRepo *repository.VulnerabilityRepository,
	alertHub *AlertHub,
	telemetryService *TelemetryService,
	db *gorm.DB,
	logger *zap.Logger,
) *GreenboneService {
	return &GreenboneService{
		greenboneRepo:    greenboneRepo,
		scanRepo:         scanRepo,
		vulnRepo:         vulnRepo,
		alertHub:         alertHub,
		telemetryService: telemetryService,
		db:               db,
		logger:           logger,
	}
}

func (s *GreenboneService) ProcessReport(ctx context.Context, orgID uuid.UUID, webhookActions models.GreenboneWebhookActions, body []byte) error {
	var report models.GMPReport
	if err := xml.Unmarshal(body, &report); err != nil {
		return fmt.Errorf("failed to unmarshal GMP XML report: %w", err)
	}

	if report.FormatID != "" && !isValidGmpFormatID(report.FormatID) {
		s.logger.Warn("unexpected GMP format_id",
			zap.String("format_id", report.FormatID),
			zap.String("report_id", report.ID),
		)
	}

	exists, err := s.greenboneRepo.ReportExists(ctx, orgID, report.ID)
	if err != nil {
		return fmt.Errorf("failed to check report existence: %w", err)
	}
	if exists {
		s.logger.Info("report already processed, skipping",
			zap.String("report_id", report.ID),
			zap.String("org_id", orgID.String()),
		)
		return nil
	}

	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	sbomID := uuid.NewSHA1(greenboneSbomNamespace, []byte(orgID.String()+":greenbone:"+report.ID))

	sbom := &models.SbomUpload{
		ID:        sbomID,
		OrgID:     orgID,
		Filename:  fmt.Sprintf("greenbone-%s.xml", report.ID),
		Format:    "cyclonedx-json",
		SizeBytes: 0,
		SHA256:    "",
		Document:  []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`),
	}
	if err := tx.Create(sbom).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create greenbone SBOM record: %w", err)
	}

	scan := &models.Scan{
		OrgID:         orgID,
		SbomID:        sbomID,
		Status:        "completed",
		ScannerSource: "greenbone",
		GvmReportID:   report.ID,
		ScanDate:      time.Now(),
	}

	if !webhookActions.StoreFindings {
		resultCount := len(report.Results.ResultList)
		scan.VulnerabilitiesFound = resultCount
		if err := tx.Create(scan).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to create scan: %w", err)
		}

		if err := tx.Commit().Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				s.logger.Info("report already processed by concurrent request, skipping",
					zap.String("report_id", report.ID),
					zap.String("org_id", orgID.String()),
				)
				return nil
			}
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		s.logger.Info("processed GVM report (findings storage disabled)",
			zap.String("report_id", report.ID),
			zap.String("org_id", orgID.String()),
			zap.Int("result_count", resultCount),
		)

		if webhookActions.EmitOTel {
			s.telemetryService.EmitEvent(ctx, orgID, "greenbone_report", map[string]string{
				"report_id":      report.ID,
				"findings_count": strconv.Itoa(resultCount),
			})
		}

		return nil
	}

	if err := tx.Create(scan).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to create scan: %w", err)
	}

	var threshold float64
	if webhookActions.SeverityThreshold == "" {
		threshold = -1
	} else {
		var ok bool
		threshold, ok = severityThresholds[strings.ToLower(webhookActions.SeverityThreshold)]
		if !ok {
			tx.Rollback()
			return fmt.Errorf("invalid severity threshold: %q, must be one of: low, medium, high, critical", webhookActions.SeverityThreshold)
		}
	}

	var worstSeverity string
	var findingsCount int

	for _, result := range report.Results.ResultList {
		severity, parseErr := strconv.ParseFloat(result.Severity, 64)
		if parseErr != nil {
			s.logger.Warn("failed to parse severity, defaulting to 0",
				zap.String("severity", result.Severity),
				zap.Error(parseErr),
			)
			severity = 0
		}

		if severity < threshold {
			continue
		}

		var vulnerabilityID *uuid.UUID

		if result.NVT.CVE != "" {
			var existingVuln models.Vulnerability
			err := tx.Where("org_id = ? AND cve = ?", orgID, result.NVT.CVE).First(&existingVuln).Error
			if err != nil {
				if err == gorm.ErrRecordNotFound {
					newVuln := &models.Vulnerability{
						OrgID:        orgID,
						Cve:          result.NVT.CVE,
						Severity:     severityToString(severity),
						DiscoveredAt: time.Now(),
					}
					if severity > 0 {
						score := severity
						newVuln.CvssScore = &score
					}
					if err := tx.Create(newVuln).Error; err != nil {
						tx.Rollback()
						return fmt.Errorf("failed to create vulnerability: %w", err)
					}
					vulnerabilityID = &newVuln.ID
				} else {
					tx.Rollback()
					return fmt.Errorf("failed to query vulnerability: %w", err)
				}
			} else {
				if existingVuln.CvssScore == nil || *existingVuln.CvssScore < severity {
					score := severity
					existingVuln.CvssScore = &score
					existingVuln.Severity = severityToString(severity)
					if err := tx.Save(&existingVuln).Error; err != nil {
						tx.Rollback()
						return fmt.Errorf("failed to update vulnerability: %w", err)
					}
				}
				vulnerabilityID = &existingVuln.ID
			}
		}

		qod, _ := strconv.Atoi(result.QoD)

		finding := models.GreenboneFinding{
			OrgID:           orgID,
			ScanID:          scan.ID,
			GvmReportID:     report.ID,
			GvmResultID:     result.ID,
			GvmNvtOid:       result.NVT.OID,
			CVE:             result.NVT.CVE,
			Host:            result.Host,
			Port:            result.Port,
			Severity:        severity,
			Threat:          result.Threat,
			Name:            result.Name,
			Description:     result.Description,
			QoD:             qod,
			VulnerabilityID: vulnerabilityID,
		}

		if err := tx.Create(&finding).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to create finding: %w", err)
		}

		findingsCount++

		if result.Threat != "" {
			if compareThreat(result.Threat, worstSeverity) > 0 {
				worstSeverity = result.Threat
			}
		}
	}

	if err := tx.Commit().Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			s.logger.Info("report already processed by concurrent request, skipping",
				zap.String("report_id", report.ID),
				zap.String("org_id", orgID.String()),
			)
			return nil
		}
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	scan.VulnerabilitiesFound = findingsCount
	if err := s.scanRepo.Update(ctx, scan); err != nil {
		s.logger.Error("failed to update scan vulnerability count",
			zap.String("scan_id", scan.ID.String()),
			zap.Error(err),
		)
	}

	s.logger.Info("processed GVM report",
		zap.String("report_id", report.ID),
		zap.String("org_id", orgID.String()),
		zap.Int("findings_count", findingsCount),
		zap.String("worst_severity", worstSeverity),
	)

	if webhookActions.BroadcastAlerts {
		s.alertHub.Broadcast(orgID.String(), &Alert{
			Type:      "greenbone_report",
			Severity:  worstSeverity,
			Message:   fmt.Sprintf("GVM report %s: %d findings", report.ID, findingsCount),
			Timestamp: time.Now(),
		})
	}

	if webhookActions.TriggerSLA {
		s.logger.Info("SLA trigger requested for greenbone report",
			zap.String("report_id", report.ID),
			zap.String("org_id", orgID.String()),
		)
	}

	if webhookActions.GenerateCSAF && s.csafGenerator != nil {
		_, err := s.csafGenerator.GeneratePerCVE(ctx, orgID, sbomID.String())
		if err != nil {
			s.logger.Error("failed to generate CSAF for greenbone report",
				zap.String("report_id", report.ID),
				zap.String("org_id", orgID.String()),
				zap.Error(err),
			)
		}
	} else if webhookActions.GenerateCSAF {
		s.logger.Warn("CSAF generation requested but generator not configured")
	}

	if webhookActions.EmitOTel {
		s.telemetryService.EmitEvent(ctx, orgID, "greenbone_report", map[string]string{
			"report_id":      report.ID,
			"findings_count": strconv.Itoa(findingsCount),
			"worst_severity": worstSeverity,
		})
	}

	return nil
}

func isValidGmpFormatID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}

func severityToString(severity float64) string {
	switch {
	case severity >= 9.0:
		return "critical"
	case severity >= 7.0:
		return "high"
	case severity >= 4.0:
		return "medium"
	case severity > 0:
		return "low"
	default:
		return "unknown"
	}
}

func compareThreat(a, b string) int {
	ranks := map[string]int{
		"Log":      0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	return ranks[a] - ranks[b]
}
