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
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
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
	enisaService autoSubmitter
	enisaSubRepo *repository.EnisaSubmissionRepository
	db           *gorm.DB
	logger       *zap.Logger
	tickInterval time.Duration
	stopCh       chan struct{}
	serverCtx    context.Context
	tick         *TickWorker
}

// autoSubmitter is the subset of ENISAService the SLA calculator depends on.
// It exists so the autosubmit path can be tested with a fake and so the
// calculator depends on an abstraction rather than a concrete service.
type autoSubmitter interface {
	Submit(ctx context.Context, orgID uuid.UUID, cve string, meta models.JSONMap) (*models.EnisaSubmission, error)
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
	calc := &SlaCalculator{
		vulnRepo:     vulnRepo,
		slaRepo:      slaRepo,
		orgRepo:      orgRepo,
		enisaService: enisaService,
		db:           db,
		logger:       logger,
		tickInterval: tickInterval,
		stopCh:       make(chan struct{}),
	}
	calc.tick = NewTickWorker("sla_calculator", tickInterval)
	return calc
}

// WithEnisaSubmissionRepository wires the ENISA submission repository used by
// the reconciler to reflect later-successful retries onto SLA status. Optional:
// when unset, reconciliation is skipped (SLAs stay pending/violated if a retry
// later succeeds — the EnisaSubmission row remains the authoritative record).
// Separate setter to keep the constructor signature stable across releases.
func (c *SlaCalculator) WithEnisaSubmissionRepository(repo *repository.EnisaSubmissionRepository) *SlaCalculator {
	c.enisaSubRepo = repo
	return c
}

// TickWorker returns the embedded health reporter for this calculator.
func (c *SlaCalculator) TickWorker() *TickWorker { return c.tick }

func (c *SlaCalculator) Start(ctx context.Context) {
	c.serverCtx = ctx
	c.logger.Info("starting SLA calculator")

	ticker := time.NewTicker(c.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.tick.RecordTick(0)
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

	// Reflect later-successful ENISA retries onto SLA status: if a submission
	// that initially failed (leaving the SLA pending/violated) later succeeded
	// via the retry worker, flip the SLA to auto_submitted. No-op when the
	// submission repo isn't wired.
	c.reconcileAutoSubmitted(ctx)
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

	// Build a lookup map for CVE → DiscoveredAt so deadlines are
	// calculated from the CVE publication date, not from when the
	// SLA calculator happens to run. This prevents SLA erosion.
	vulnDiscoveredAt := make(map[string]time.Time)
	for _, v := range kevVulns {
		if !v.DiscoveredAt.IsZero() {
			vulnDiscoveredAt[v.Cve] = v.DiscoveredAt
		}
	}
	for _, v := range criticalVulns {
		if !v.DiscoveredAt.IsZero() {
			vulnDiscoveredAt[v.Cve] = v.DiscoveredAt
		}
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
		var matched repository.VulnerabilityWithSbom
		for _, v := range kevVulns {
			if v.Cve == cve {
				isKEV = true
				matched = v
				break
			}
		}
		if !isKEV {
			for _, v := range criticalVulns {
				if v.Cve == cve {
					matched = v
					break
				}
			}
		}

		deadline := computeDeadline(matched.Vulnerability, isKEV)

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

	// Build CVE → DiscoveredAt lookup for correct SLA deadlines.
	vulnDiscoveredAtSbom := make(map[string]time.Time)
	for _, v := range kevVulns {
		if !v.DiscoveredAt.IsZero() {
			vulnDiscoveredAtSbom[v.Cve] = v.DiscoveredAt
		}
	}
	for _, v := range criticalVulns {
		if !v.DiscoveredAt.IsZero() {
			vulnDiscoveredAtSbom[v.Cve] = v.DiscoveredAt
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
			var matched repository.VulnerabilityWithSbom
			for _, v := range kevVulns {
				if v.Cve == cve && v.SbomID != nil && *v.SbomID == sbomID {
					isKEV = true
					matched = v
					break
				}
			}
			if !isKEV {
				for _, v := range criticalVulns {
					if v.Cve == cve && v.SbomID != nil && *v.SbomID == sbomID {
						matched = v
						break
					}
				}
			}

			deadline := computeDeadline(matched.Vulnerability, isKEV)

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

// computeDeadline returns the CRA Art. 10 SLA deadline for a vulnerability,
// anchored to when the vuln became known to the vendor rather than to the
// moment the calculator happened to run. CRA Art. 10(1) (exploited) clocks run
// from exploitation; Art. 10(2) (critical) clocks run from when the vuln was
// known to the manufacturer.
//
// Anchor selection:
//   - KEV/exploited (24h): KevDateAdded (the exploitation date) if present,
//     otherwise DiscoveredAt.
//   - critical (72h): DiscoveredAt (the known-to-vendor date).
//
// Guards:
//   - A zero or future anchor (missing feed data / clock skew) falls back to
//     time.Now() so we never persist a 1970-based or future deadline.
//   - A deadline already in the past is returned as-is: the SLA is genuinely
//     already breached and the breach detector (alert_service) will flip it to
//     'violated' and sign the event. Surfacing real breaches is the point of
//     this function — masking them was the original bug.
func computeDeadline(vuln models.Vulnerability, isKEV bool) time.Time {
	var anchor time.Time
	if isKEV && vuln.KevDateAdded != nil {
		anchor = *vuln.KevDateAdded
	} else {
		anchor = vuln.DiscoveredAt
	}

	now := time.Now()
	window := SlaDeadlineCritical
	if isKEV {
		window = SlaDeadlineKEV
	}

	if anchor.IsZero() || anchor.After(now) {
		// Missing/stale feed data: cannot reconstruct the regulatory clock
		// start, so start from now rather than persist a nonsensical deadline.
		return now.Add(window)
	}
	return anchor.Add(window)
}

// reconcileAutoSubmitted flips SLAs to "auto_submitted" when their ENISA
// submission has since succeeded via the retry worker. Fix #5 made the initial
// autosubmit flip integrity-correct (only on confirmed success in-flight), but
// a submission that initially FAILED and later succeeded on retry leaves the
// SLA stuck in pending/violated. This pass closes that reporting gap.
//
// No-op when enisaSubRepo is unset. Idempotent: once an SLA is auto_submitted
// it's no longer pending/violated so it won't be revisited. The EnisaSubmission
// row remains the authoritative record regardless.
func (c *SlaCalculator) reconcileAutoSubmitted(ctx context.Context) {
	if c.enisaSubRepo == nil {
		return
	}
	orgs, err := c.orgRepo.ListAll(ctx)
	if err != nil {
		c.logger.Error("failed to list organizations for SLA reconciliation", zap.Error(err))
		return
	}
	var totalReconciled int
	for _, org := range orgs {
		// Only fully_automatic orgs autosubmit, so only they can be reconciled.
		if org.SlaMode != SlaAutomationFullyAutomatic {
			continue
		}
		orgCtx := middleware.ContextWithOrgID(ctx, org.ID)

		submitted, err := c.enisaSubRepo.ListSubmittedByOrg(orgCtx)
		if err != nil {
			c.logger.Error("failed to list submitted ENISA submissions for reconciliation",
				zap.String("org_id", org.ID.String()),
				zap.Error(err))
			continue
		}
		if len(submitted) == 0 {
			continue
		}
		submittedCVEs := make(map[string]bool, len(submitted))
		for _, sub := range submitted {
			if cve := cveFromCsafDoc(sub.CsafDocument); cve != "" {
				submittedCVEs[cve] = true
			}
		}
		if len(submittedCVEs) == 0 {
			continue
		}

		for _, status := range []string{"pending", "violated"} {
			slas, err := c.slaRepo.ListByStatus(orgCtx, status, 1000, 0)
			if err != nil {
				c.logger.Error("failed to list SLAs for reconciliation",
					zap.String("org_id", org.ID.String()),
					zap.String("status", status),
					zap.Error(err))
				continue
			}
			for _, sla := range slas {
				if !submittedCVEs[sla.Cve] {
					continue
				}
				if err := c.slaRepo.UpdateStatus(orgCtx, sla.ID, "auto_submitted"); err != nil {
					c.logger.Warn("failed to reconcile SLA to auto_submitted",
						zap.String("sla_id", sla.ID.String()),
						zap.String("cve", sla.Cve),
						zap.Error(err))
					continue
				}
				totalReconciled++
			}
		}
	}
	if totalReconciled > 0 {
		c.logger.Info("SLA reconciliation completed", zap.Int("reconciled", totalReconciled))
	}
}

// cveFromCsafDoc extracts the CVE from a stored CSAF document. Submit() is
// per-CVE and the generator places it at vulnerabilities[].cve, so each
// submission maps to exactly one CVE. Returns "" on any miss/parse failure
// (defensive: a miss just means that submission won't drive reconciliation).
func cveFromCsafDoc(doc models.JSONMap) string {
	if doc == nil {
		return ""
	}
	vulns, ok := doc["vulnerabilities"].([]interface{})
	if !ok || len(vulns) == 0 {
		return ""
	}
	first, ok := vulns[0].(map[string]interface{})
	if !ok {
		return ""
	}
	cve, _ := first["cve"].(string)
	return cve
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
		overdue, err := c.slaRepo.ListOverdue(orgCtx)
		if err != nil {
			c.logger.Error("failed to list overdue SLAs",
				zap.String("org_id", org.ID.String()),
				zap.Error(err),
			)
			continue
		}

		for _, sla := range overdue {
			// The calculator owns the pending -> violated state transition. The
			// AlertService previously did this flip, splitting the SLA state
			// machine across two services; now it lives here so the calculator
			// is the single owner of SLA status.
			if err := c.slaRepo.UpdateStatus(orgCtx, sla.ID, "violated"); err != nil {
				c.logger.Error("failed to mark SLA violated",
					zap.String("org_id", sla.OrgID.String()),
					zap.String("sla_id", sla.ID.String()),
					zap.Error(err),
				)
				continue
			}
			sla.Status = "violated"
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
		if c.enisaService == nil {
			return
		}
		// Regulatory integrity: do NOT flip the SLA to "auto_submitted" before
		// the submission is confirmed. The previous code flipped synchronously
		// and then submitted in a detached goroutine, so a crash left the SLA
		// falsely showing compliant. The EnisaSubmission row created by Submit
		// (plus the ENISA retry worker) carries the durable intent; this status
		// is flipped ONLY once Submit actually succeeds. On failure the SLA
		// keeps its prior status so it is never a false positive.
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
			sub, err := c.enisaService.Submit(submitCtx, orgID, cve, nil)
			if err != nil {
				c.logger.Error("ENISA auto-submission failed; SLA left un-flipped (retry worker will retry the submission)",
					zap.String("sla_id", slaID.String()),
					zap.String("org_id", orgID.String()),
					zap.String("cve", cve),
					zap.Error(err),
				)
				return
			}
			// Submission confirmed — now record it on the SLA. A failure here is
			// non-fatal: the EnisaSubmission row is the authoritative record.
			if err := c.db.WithContext(context.Background()).Model(&models.SlaTracking{}).
				Where("id = ?", slaID).
				Update("status", "auto_submitted").Error; err != nil {
				c.logger.Warn("ENISA submission succeeded but failed to flip SLA status",
					zap.String("sla_id", slaID.String()),
					zap.String("enisa_submission_id", submissionIDOr(sub)),
					zap.Error(err),
				)
				return
			}
			c.logger.Info("ENISA auto-submission succeeded",
				zap.String("sla_id", slaID.String()),
				zap.String("org_id", orgID.String()),
				zap.String("cve", cve),
			)
		}()
	}
}

func submissionIDOr(sub *models.EnisaSubmission) string {
	if sub == nil {
		return ""
	}
	return sub.SubmissionID
}
