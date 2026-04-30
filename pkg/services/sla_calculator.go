// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	// SlaModePerCve tracks one SLA deadline per CVE across all SBOMs.
	SlaModePerCve = "per_cve"
	// SlaModePerSbom tracks one SLA deadline per CVE per SBOM.
	SlaModePerSbom = "per_sbom"

	// SlaDeadlineKEV is the CRA-mandated reporting deadline for KEV (exploited) vulnerabilities.
	SlaDeadlineKEV = 24 * time.Hour
	// SlaDeadlineCritical is the CRA-mandated reporting deadline for critical vulnerabilities.
	SlaDeadlineCritical = 72 * time.Hour

	// SlaAutomationAlertsOnly means SLA breaches only trigger UI alerts; no automated submissions.
	SlaAutomationAlertsOnly = "alerts_only"
	// SlaAutomationApprovalGate means CSAF is auto-generated but requires human approval before submission.
	SlaAutomationApprovalGate = "approval_gate"
	// SlaAutomationFullyAutomatic means CSAF is auto-generated and submitted without human intervention.
	SlaAutomationFullyAutomatic = "fully_automatic"
)

// SlaCalculator computes and tracks CRA-mandated SLA deadlines for vulnerabilities.
type SlaCalculator struct {
	vulnRepo     *repository.VulnerabilityRepository
	slaRepo      *repository.SlaTrackingRepository
	orgRepo      *repository.OrganizationRepository
	enisaService *ENISAService
	db           *gorm.DB
	logger       *zap.Logger
	tickInterval time.Duration
	stopCh       chan struct{}
	serverCtx    context.Context
}

func NewSlaCalculator(
	vulnRepo *repository.VulnerabilityRepository,
	slaRepo *repository.SlaTrackingRepository,
	orgRepo *repository.OrganizationRepository,
	enisaService *ENISAService,
	db *gorm.DB,
	logger *zap.Logger,
	tickInterval time.Duration,
) *SlaCalculator {
	if tickInterval == 0 {
		tickInterval = 1 * time.Minute
	}
	return &SlaCalculator{
		vulnRepo:     vulnRepo,
		slaRepo:      slaRepo,
		orgRepo:      orgRepo,
		enisaService: enisaService,
		db:           db,
		logger:       logger,
		tickInterval: tickInterval,
		stopCh:       make(chan struct{}),
	}
}

func (c *SlaCalculator) Start(ctx context.Context) {
	c.serverCtx = ctx
	c.logger.Info("starting SLA calculator")

	ticker := time.NewTicker(c.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.CalculateDeadlines(ctx)
		case <-c.stopCh:
			c.logger.Info("SLA calculator stopped")
			return
		case <-ctx.Done():
			c.logger.Info("SLA calculator context cancelled")
			return
		}
	}
}

func (c *SlaCalculator) Stop() {
	close(c.stopCh)
}

func (c *SlaCalculator) CalculateDeadlines(ctx context.Context) {
	orgs, err := c.orgRepo.ListAll(ctx)
	if err != nil {
		c.logger.Error("failed to list organizations", zap.Error(err))
		return
	}

	var totalCreated, totalSkipped, totalErrors int

	for _, org := range orgs {
		created, skipped, errors := c.processOrganization(ctx, org)
		totalCreated += created
		totalSkipped += skipped
		totalErrors += errors
	}

	c.logger.Info("SLA deadline calculation completed",
		zap.Int("slas_created", totalCreated),
		zap.Int("slas_skipped", totalSkipped),
		zap.Int("errors", totalErrors),
	)

	c.detectAndHandleBreaches(ctx)
}

func (c *SlaCalculator) processOrganization(ctx context.Context, org models.Organization) (created, skipped, errors int) {
	ctx = middleware.ContextWithOrgID(ctx, org.ID)
	slaMode := org.SlaTrackingMode
	if slaMode == "" {
		slaMode = SlaModePerCve
	}

	kevVulns, err := c.vulnRepo.ListKEVWithoutSla(ctx)
	if err != nil {
		c.logger.Error("failed to list KEV vulnerabilities",
			zap.String("org_id", org.ID.String()),
			zap.Error(err),
		)
		return 0, 0, 1
	}

	criticalVulns, err := c.vulnRepo.ListCriticalWithoutSla(ctx)
	if err != nil {
		c.logger.Error("failed to list critical vulnerabilities",
			zap.String("org_id", org.ID.String()),
			zap.Error(err),
		)
		return 0, 0, 1
	}

	vulnsToProcess := make(map[string]struct{})
	for _, v := range kevVulns {
		vulnsToProcess[v.Cve] = struct{}{}
	}
	for _, v := range criticalVulns {
		vulnsToProcess[v.Cve] = struct{}{}
	}

	if slaMode == SlaModePerSbom {
		created += c.processPerSbomMode(ctx, org.ID, org.SlaMode, kevVulns, criticalVulns, &skipped, &errors)
	} else {
		created += c.processPerCveMode(ctx, org.ID, org.SlaMode, kevVulns, criticalVulns, &skipped, &errors)
	}

	return created, skipped, errors
}

func (c *SlaCalculator) processPerCveMode(
	ctx context.Context,
	orgID uuid.UUID,
	slaMode string,
	kevVulns []repository.VulnerabilityWithSbom,
	criticalVulns []repository.VulnerabilityWithSbom,
	skipped *int,
	errors *int,
) int {
	var created int

	vulnMap := make(map[string]bool)
	for _, v := range kevVulns {
		vulnMap[v.Cve] = true
	}
	for _, v := range criticalVulns {
		vulnMap[v.Cve] = true
	}

	for cve := range vulnMap {
		exists, err := c.slaRepo.ExistsByCveAndSbom(ctx, cve, nil)
		if err != nil {
			c.logger.Error("failed to check SLA existence",
				zap.String("org_id", orgID.String()),
				zap.String("cve", cve),
				zap.Error(err),
			)
			*errors++
			continue
		}

		if exists {
			*skipped++
			continue
		}

		isKEV := false
		for _, v := range kevVulns {
			if v.Cve == cve {
				isKEV = true
				break
			}
		}

		deadline := time.Now().Add(SlaDeadlineCritical)
		if isKEV {
			deadline = time.Now().Add(SlaDeadlineKEV)
		}

		sla := &models.SlaTracking{
			OrgID:    orgID,
			Cve:      cve,
			SbomID:   nil,
			Deadline: deadline,
			Status:   "pending",
		}

		if err := c.slaRepo.Create(ctx, orgID, sla); err != nil {
			c.logger.Error("failed to create SLA entry",
				zap.String("org_id", orgID.String()),
				zap.String("cve", cve),
				zap.Error(err),
			)
			*errors++
			continue
		}

		c.applySlaAutomation(ctx, sla, slaMode)

		created++
		c.logger.Info("created SLA entry",
			zap.String("org_id", orgID.String()),
			zap.String("cve", cve),
			zap.Time("deadline", deadline),
		)
	}

	return created
}

func (c *SlaCalculator) processPerSbomMode(
	ctx context.Context,
	orgID uuid.UUID,
	slaMode string,
	kevVulns []repository.VulnerabilityWithSbom,
	criticalVulns []repository.VulnerabilityWithSbom,
	skipped *int,
	errors *int,
) int {
	var created int

	var scans []models.Scan
	err := c.db.WithContext(ctx).
		Where("org_id = ?", orgID).
		Find(&scans).Error
	if err != nil {
		c.logger.Error("failed to list scans",
			zap.String("org_id", orgID.String()),
			zap.Error(err),
		)
		*errors++
		return 0
	}

	sbomVulnMap := make(map[uuid.UUID]map[string]bool)
	for _, scan := range scans {
		if sbomVulnMap[scan.SbomID] == nil {
			sbomVulnMap[scan.SbomID] = make(map[string]bool)
		}
	}

	for _, v := range kevVulns {
		if v.SbomID != nil {
			sbomVulnMap[*v.SbomID][v.Cve] = true
		}
	}
	for _, v := range criticalVulns {
		if v.SbomID != nil {
			sbomVulnMap[*v.SbomID][v.Cve] = true
		}
	}

	for sbomID, vulns := range sbomVulnMap {
		for cve := range vulns {
			exists, err := c.slaRepo.ExistsByCveAndSbom(ctx, cve, &sbomID)
			if err != nil {
				c.logger.Error("failed to check SLA existence",
					zap.String("org_id", orgID.String()),
					zap.String("cve", cve),
					zap.String("sbom_id", sbomID.String()),
					zap.Error(err),
				)
				*errors++
				continue
			}

			if exists {
				*skipped++
				continue
			}

			isKEV := false
			for _, v := range kevVulns {
				if v.Cve == cve && v.SbomID != nil && *v.SbomID == sbomID {
					isKEV = true
					break
				}
			}

			deadline := time.Now().Add(SlaDeadlineCritical)
			if isKEV {
				deadline = time.Now().Add(SlaDeadlineKEV)
			}

			sla := &models.SlaTracking{
				OrgID:    orgID,
				Cve:      cve,
				SbomID:   &sbomID,
				Deadline: deadline,
				Status:   "pending",
			}

			if err := c.slaRepo.Create(ctx, orgID, sla); err != nil {
				c.logger.Error("failed to create SLA entry",
					zap.String("org_id", orgID.String()),
					zap.String("cve", cve),
					zap.String("sbom_id", sbomID.String()),
					zap.Error(err),
				)
				*errors++
				continue
			}

			c.applySlaAutomation(ctx, sla, slaMode)

			created++
			c.logger.Info("created SLA entry",
				zap.String("org_id", orgID.String()),
				zap.String("cve", cve),
				zap.String("sbom_id", sbomID.String()),
				zap.Time("deadline", deadline),
			)
		}
	}

	return created
}

func (c *SlaCalculator) detectAndHandleBreaches(ctx context.Context) {
	orgs, err := c.orgRepo.ListAll(ctx)
	if err != nil {
		c.logger.Error("failed to list organizations for breach detection", zap.Error(err))
		return
	}

	var totalBreached int

	for _, org := range orgs {
		orgCtx := middleware.ContextWithOrgID(ctx, org.ID)
		breached, err := c.slaRepo.ListViolated(orgCtx)
		if err != nil {
			c.logger.Error("failed to list breached SLAs",
				zap.String("org_id", org.ID.String()),
				zap.Error(err),
			)
			continue
		}

		for _, sla := range breached {
			c.logger.Warn("SLA breached",
				zap.String("cve", sla.Cve),
				zap.String("org_id", sla.OrgID.String()),
				zap.Time("deadline", sla.Deadline),
			)
			c.applySlaAutomation(orgCtx, &sla, org.SlaMode)
			totalBreached++
		}
	}

	if totalBreached > 0 {
		c.logger.Info("SLA breach detection completed",
			zap.Int("breached_slas", totalBreached),
		)
	}
}

func (c *SlaCalculator) applySlaAutomation(ctx context.Context, sla *models.SlaTracking, slaMode string) {
	switch slaMode {
	case SlaAutomationApprovalGate:
		if err := c.db.WithContext(ctx).Model(sla).Update("status", "pending_approval").Error; err != nil {
			c.logger.Error("failed to set SLA to pending_approval",
				zap.String("id", sla.ID.String()),
				zap.Error(err),
			)
		}
	case SlaAutomationFullyAutomatic:
		if err := c.db.WithContext(ctx).Model(sla).Update("status", "auto_submitted").Error; err != nil {
			c.logger.Error("failed to set SLA to auto_submitted",
				zap.String("id", sla.ID.String()),
				zap.Error(err),
			)
			return
		}
		if c.enisaService != nil {
			slaID := sla.ID
			orgID := sla.OrgID
			cve := sla.Cve
			baseCtx := c.serverCtx
			if baseCtx == nil {
				baseCtx = context.Background()
			}
			go func() {
				submitCtx, cancel := context.WithTimeout(baseCtx, 30*time.Second)
				defer cancel()
				_, err := c.enisaService.Submit(submitCtx, orgID, cve, nil)
				if err != nil {
					c.logger.Error("ENISA auto-submission failed",
						zap.String("sla_id", slaID.String()),
						zap.String("org_id", orgID.String()),
						zap.String("cve", cve),
						zap.Error(err),
					)
				} else {
					c.logger.Info("ENISA auto-submission succeeded",
						zap.String("sla_id", slaID.String()),
						zap.String("org_id", orgID.String()),
						zap.String("cve", cve),
					)
				}
			}()
		}
	}
}
