// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/jobs"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"go.uber.org/zap"
)

type scanJobPayload struct {
	ScanID uuid.UUID `json:"scan_id"`
	OrgID  uuid.UUID `json:"org_id"`
	SbomID uuid.UUID `json:"sbom_id"`
}

type ScanWorker struct {
	scanRepo     workerScanRepository
	vulnRepo     workerVulnerabilityRepository
	feedRepo     workerVulnerabilityFeedRepository
	sbomRepo     workerSbomRepository
	grcRepo      workerGRCMappingRepository
	scanVulnRepo workerScanVulnerabilityRepository
	vulnzMatcher *VulnzMatcher
	queue        *jobs.JobQueue
	logger       *zap.Logger
	enrichment   *EnrichmentService
	mu           sync.RWMutex
}

func NewScanWorker(
	scanRepo workerScanRepository,
	vulnRepo workerVulnerabilityRepository,
	feedRepo workerVulnerabilityFeedRepository,
	sbomRepo workerSbomRepository,
	queue *jobs.JobQueue,
	logger *zap.Logger,
	enrichment *EnrichmentService,
	scanVulnRepo workerScanVulnerabilityRepository,
) *ScanWorker {
	return &ScanWorker{
		scanRepo:     scanRepo,
		vulnRepo:     vulnRepo,
		feedRepo:     feedRepo,
		sbomRepo:     sbomRepo,
		queue:        queue,
		logger:       logger,
		enrichment:   enrichment,
		scanVulnRepo: scanVulnRepo,
	}
}

func (w *ScanWorker) SetGRCMappingRepository(repo workerGRCMappingRepository) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.grcRepo = repo
}

func (w *ScanWorker) SetEnrichmentService(svc *EnrichmentService) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enrichment = svc
}

func (w *ScanWorker) SetVulnzMatcher(vm *VulnzMatcher) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.vulnzMatcher = vm
}

func (w *ScanWorker) EnqueueScan(ctx context.Context, scanID, orgID, sbomID uuid.UUID) error {
	_, err := w.queue.Enqueue(ctx, "scan", scanJobPayload{
		ScanID: scanID,
		OrgID:  orgID,
		SbomID: sbomID,
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue scan job: %w", err)
	}
	return nil
}

func (w *ScanWorker) Start(ctx context.Context) {
	w.queue.StartWorker(ctx, "scan", w.handleJob)
}

func (w *ScanWorker) handleJob(ctx context.Context, job *jobs.Job) error {
	var payload scanJobPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		w.logger.Error("failed to unmarshal scan job payload",
			zap.String("job_id", job.ID.String()),
			zap.Error(err),
		)
		return err
	}

	scanCtx := middleware.ContextWithOrgID(ctx, payload.OrgID)

	scan, err := w.scanRepo.GetByID(scanCtx, payload.ScanID)
	if err != nil {
		return fmt.Errorf("failed to load scan %s: %w", payload.ScanID, err)
	}

	if err := w.processScan(scanCtx, scan); err != nil {
		_ = w.scanRepo.UpdateStatus(scanCtx, scan.ID, "failed")
		return err
	}

	return nil
}

func (w *ScanWorker) processScan(ctx context.Context, scan *models.Scan) error {
	w.logger.Info("processing scan",
		zap.String("scan_id", scan.ID.String()),
		zap.String("sbom_id", scan.SbomID.String()),
	)

	sbomResult, err := w.sbomRepo.GetDocumentAndFormatFromPublic(ctx, scan.SbomID)
	if err != nil {
		return fmt.Errorf("failed to load SBOM: %w", err)
	}
	sbomDoc := sbomResult.Document

	return w.processScanWithVulnzMatcher(ctx, scan, sbomDoc)
}

func buildVulnRecord(match VulnerabilityMatch) map[string]interface{} {
	record := map[string]interface{}{
		"id": match.CVE,
		"cve": map[string]interface{}{
			"id": match.CVE,
			"descriptions": []map[string]string{
				{"lang": "en", "value": ""},
			},
		},
	}

	if match.Severity != "" {
		record["severity"] = match.Severity
	}
	if match.CVSSScore != nil {
		record["cvss_score"] = *match.CVSSScore
	}
	if match.PackageName != "" {
		record["affected_package"] = match.PackageName + "@" + match.PackageVersion
	}

	return record
}

func (w *ScanWorker) processScanWithVulnzMatcher(ctx context.Context, scan *models.Scan, sbomDoc []byte) error {
	w.mu.RLock()
	matcher := w.vulnzMatcher
	w.mu.RUnlock()

	if matcher == nil {
		w.logger.Warn("vulnz matcher not configured, skipping scan")
		scan.Status = "completed"
		scan.ScannerVersion = "none"
		if err := w.scanRepo.Update(ctx, scan); err != nil {
			w.logger.Error("failed to update scan", zap.Error(err))
		}
		return nil
	}

	components := parseSBOMComponents(sbomDoc)
	if len(components) == 0 {
		w.logger.Warn("no components parsed from SBOM, skipping vulnz match")
		scan.Status = "completed"
		scan.ScannerVersion = "vulnz-matcher"
		if err := w.scanRepo.Update(ctx, scan); err != nil {
			w.logger.Error("failed to update scan", zap.Error(err))
		}
		return nil
	}

	componentsByName := make(map[string]SBOMComponent, len(components))
	for _, comp := range components {
		componentsByName[comp.Name] = comp
	}

	matches, err := matcher.MatchComponents(ctx, components)
	if err != nil {
		return fmt.Errorf("vulnz matcher failed: %w", err)
	}

	var vulnCount int
	for _, match := range matches {
		vuln := &models.Vulnerability{
			OrgID:        scan.OrgID,
			Cve:          match.CVE,
			CvssScore:    match.CVSSScore,
			Severity:     match.Severity,
			DiscoveredAt: time.Now(),
		}

		if feed, err := w.feedRepo.GetByCVE(ctx, match.CVE); err == nil {
			vuln.ExploitedInWild = feed.KevExploited
			vuln.KevDateAdded = feed.KevDateAdded
			vuln.EuvdID = feed.EnisaEuvdID
			vuln.BsiTr03116Compliant = feed.BsiTr03116Compliant
		}

		if err := w.vulnRepo.Create(ctx, scan.OrgID, vuln); err != nil {
			w.logger.Error("failed to create vulnerability",
				zap.String("cve", match.CVE),
				zap.Error(err),
			)
			continue
		}
		vulnCount++

		if w.scanVulnRepo != nil {
			comp, ok := componentsByName[match.PackageName]
			if !ok {
				comp = SBOMComponent{Name: match.PackageName, Version: match.PackageVersion, Type: match.PackageType}
			}
			sv := []models.ScanVulnerability{{
				ScanID:               scan.ID,
				VulnerabilityID:      vuln.ID,
				SbomComponentName:    comp.Name,
				SbomComponentVersion: comp.Version,
				SbomComponentType:    comp.Type,
				SbomComponentPURL:    comp.PURL,
				MatchConfidence:      "matched",
				FeedSource:           match.Source,
				MatchedAt:            time.Now(),
			}}
			if err := w.scanVulnRepo.CreateBatch(ctx, sv); err != nil {
				w.logger.Error("failed to create scan vulnerability record", zap.Error(err))
			}
		}

		w.mu.RLock()
		enrichSvc := w.enrichment
		grcRepo := w.grcRepo
		w.mu.RUnlock()

		if enrichSvc != nil && enrichSvc.IsReady() && grcRepo != nil {
			vulnRecord := buildVulnRecord(match)
			mappings, err := enrichSvc.EnrichVulnerability(ctx, match.CVE, vulnRecord)
			if err != nil {
				w.logger.Warn("enrichment failed for CVE", zap.String("cve", match.CVE), zap.Error(err))
			} else if len(mappings) > 0 {
				if err := grcRepo.DeleteByVulnerability(ctx, scan.OrgID, match.CVE); err != nil {
					w.logger.Warn("failed to delete old GRC mappings", zap.String("cve", match.CVE), zap.Error(err))
				}
				grcMappings := make([]models.GRCMapping, 0, len(mappings))
				for _, m := range mappings {
					grcMappings = append(grcMappings, models.GRCMapping{
						OrgID:           scan.OrgID,
						VulnerabilityID: &vuln.ID,
						Framework:       m.Framework,
						ControlID:       m.Framework + "/" + m.ControlID,
						MappingType:     m.MappingType,
						Confidence:      m.Confidence,
						Evidence:        m.Evidence,
					})
				}
				if err := grcRepo.CreateBatch(ctx, grcMappings); err != nil {
					w.logger.Warn("failed to store GRC mappings", zap.String("cve", match.CVE), zap.Error(err))
				}
			}
		}
	}

	scan.VulnerabilitiesFound = vulnCount
	scan.ScannerVersion = "vulnz-matcher"
	scan.Status = "completed"
	if err := w.scanRepo.Update(ctx, scan); err != nil {
		w.logger.Error("failed to update scan", zap.Error(err))
	}

	w.logger.Info("vulnz matcher scan completed",
		zap.String("scan_id", scan.ID.String()),
		zap.Int("vulnerabilities_found", vulnCount),
	)

	return nil
}
