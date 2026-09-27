// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
)

// Compliance event types recorded by the Article 14 sweeper.
const (
	// EventCRADeadlineMissed records a reporting stage whose deadline passed
	// with no submission recorded. This is a missed regulatory obligation and
	// is the most serious thing this sweeper can report.
	EventCRADeadlineMissed = "cra_deadline_missed"

	// EventCRASubmissionLate records a stage that WAS submitted, but after
	// its deadline. It is kept distinct from EventCRADeadlineMissed because
	// the two mean different things to an authority: one obligation was
	// discharged late, the other was not discharged at all.
	EventCRASubmissionLate = "cra_submission_late"
)

// CRADeadlineSweeper watches CRA Article 14 reporting deadlines.
//
// Without it, nothing detects a missed 24-hour Early Warning. The deadlines
// are computed correctly and the API can report them, but both only happen when
// somebody asks. A compliance system whose clock is noticed on demand is not
// watching the clock, and the whole purpose of Article 14 is that the window is
// short.
//
// # What this deliberately does not do
//
// It does not submit anything. The SLA calculator can auto-submit in its
// fully_automatic mode; this sweeper has no equivalent, for two independent
// reasons. The ENISA Single Reporting Platform publishes no API, so there is
// nowhere to submit to. And even given a receiver, filing is a legal
// determination about what an authority must be told — a machine making that
// call and recording a case reference against it would be fabricating the
// evidence of a regulatory act.
//
// It also does not invent a deadline. A stage whose anchor has not occurred has
// no deadline: an AEV final report before a mitigating measure exists is not
// breached, it is not yet due to be computable. Reporting it as breached would
// be a false positive on the single most consequential alert this system emits.
//
// # Alerting once
//
// A breached window stays breached, so each condition is recorded once, keyed on
// the report and the stage. A duplicate in a signed hash chain is a second
// signed assertion that the same thing happened twice, not a harmless repeat.
type CRADeadlineSweeper struct {
	reports        *repository.CRARepository
	orgRepo        *repository.OrganizationRepository
	eventRepo      *repository.ComplianceEventRepository
	signingService *SigningService
	alertHub       *AlertHub
	logger         *zap.Logger

	tickInterval time.Duration
	// now is injectable so a sweep can be tested at a chosen instant — near a
	// deadline, past it, across a month boundary — without waiting for a
	// ticker or moving the system clock.
	now      func() time.Time
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewCRADeadlineSweeper constructs a sweeper. A zero tick interval defaults to
// one minute.
func NewCRADeadlineSweeper(
	reports *repository.CRARepository,
	orgRepo *repository.OrganizationRepository,
	eventRepo *repository.ComplianceEventRepository,
	signingService *SigningService,
	alertHub *AlertHub,
	logger *zap.Logger,
	tickInterval time.Duration,
) *CRADeadlineSweeper {
	if tickInterval == 0 {
		tickInterval = time.Minute
	}
	return &CRADeadlineSweeper{
		reports:        reports,
		orgRepo:        orgRepo,
		eventRepo:      eventRepo,
		signingService: signingService,
		alertHub:       alertHub,
		logger:         logger,
		tickInterval:   tickInterval,
		now:            time.Now,
		stopCh:         make(chan struct{}),
	}
}

// Start runs the sweeper until ctx is cancelled or Stop is called.
func (s *CRADeadlineSweeper) Start(ctx context.Context) {
	s.logger.Info("CRA Article 14 deadline sweeper started",
		zap.Duration("interval", s.tickInterval))
	ticker := time.NewTicker(s.tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Sweep(ctx)
		case <-s.stopCh:
			s.logger.Info("CRA Article 14 deadline sweeper stopped")
			return
		case <-ctx.Done():
			s.logger.Info("CRA Article 14 deadline sweeper context cancelled")
			return
		}
	}
}

// Stop terminates the sweeper. It is safe to call more than once.
func (s *CRADeadlineSweeper) Stop() { s.stopOnce.Do(func() { close(s.stopCh) }) }

// SweepResult summarises one pass, so a caller (or a test) can assert on what
// happened rather than inferring it from logs.
type SweepResult struct {
	ReportsScanned int
	BreachesFound  int
	BreachesLogged int
	LateLogged     int
	Errors         int
}

// Sweep performs one pass across every organisation.
func (s *CRADeadlineSweeper) Sweep(ctx context.Context) SweepResult {
	return s.sweepAt(ctx, s.now())
}

// SweepAtForTest runs a pass at an explicit instant.
//
// It exists so the sweeper can be tested at a chosen moment — near a deadline,
// past it, across a month boundary — without moving the system clock or
// waiting for a ticker. Behaviour is identical to Sweep.
func (s *CRADeadlineSweeper) SweepAtForTest(ctx context.Context, now time.Time) SweepResult {
	return s.sweepAt(ctx, now)
}

func (s *CRADeadlineSweeper) sweepAt(ctx context.Context, now time.Time) SweepResult {
	result := SweepResult{}

	// The report list is cross-tenant by design: a regulatory clock does not
	// run only for the organisation someone happens to be looking at.
	rows, err := s.reports.ListOpenReports(ctx, 0)
	if err != nil {
		s.logger.Error("failed to list open CRA reports for deadline sweep", zap.Error(err))
		result.Errors++
		return result
	}
	result.ReportsScanned = len(rows)

	for i := range rows {
		row := rows[i]
		orgCtx := middleware.ContextWithOrgID(ctx, row.OrgID)

		domain, err := repository.ToDomain(&row)
		if err != nil {
			s.logger.Warn("failed to project CRA report to domain",
				zap.String("report_id", row.ID.String()), zap.Error(err))
			result.Errors++
			continue
		}
		// An undetermined report has no event class, so no reporting duty
		// exists yet and there is nothing to be late for. Assessment is the
		// human's job and the assessment is not this sweeper's concern.
		if !domain.EventType.Valid() {
			continue
		}

		deadlines, err := domain.Deadlines()
		if err != nil {
			s.logger.Warn("failed to compute CRA deadlines",
				zap.String("report_id", row.ID.String()), zap.Error(err))
			result.Errors++
			continue
		}

		for _, d := range deadlines {
			var submittedAt time.Time
			if sub, ok := domain.SubmissionFor(d.Stage); ok {
				submittedAt = sub.SubmittedAt
			}
			switch d.Evaluate(now, submittedAt) {
			case cra.StatusMissed:
				result.BreachesFound++
				if s.recordOnce(orgCtx, row, d, EventCRADeadlineMissed, "critical", now, &result) {
					result.BreachesLogged++
				}
			case cra.StatusLate:
				if s.recordOnce(orgCtx, row, d, EventCRASubmissionLate, "high", now, &result) {
					result.LateLogged++
				}
			case cra.StatusPending, cra.StatusDue, cra.StatusSubmitted,
				cra.StatusNotApplicable:
				// Nothing to do. A pending deadline is the normal case, and a
				// submitted one has been discharged.
			}
		}
	}

	if result.BreachesFound > 0 || result.BreachesLogged > 0 || result.LateLogged > 0 {
		s.logger.Warn("CRA Article 14 deadline sweep completed",
			zap.Int("reports_scanned", result.ReportsScanned),
			zap.Int("breaches_found", result.BreachesFound),
			zap.Int("breaches_logged", result.BreachesLogged),
			zap.Int("late_logged", result.LateLogged),
			zap.Int("errors", result.Errors))
	}
	return result
}

// recordOnce writes a signed compliance event and broadcasts an alert, but only
// if this condition has not been recorded for this report before.
//
// Returns true if it wrote.
func (s *CRADeadlineSweeper) recordOnce(
	ctx context.Context,
	row models.CRAReport,
	d cra.Deadline,
	eventType, severity string,
	now time.Time,
	result *SweepResult,
) bool {
	stage := string(d.Stage)

	seen, err := s.eventRepo.HasEventForReport(ctx, row.OrgID, eventType, row.ID.String(), stage)
	if err != nil {
		s.logger.Warn("failed to check for an existing CRA deadline event",
			zap.String("report_id", row.ID.String()),
			zap.String("stage", stage),
			zap.Error(err))
		result.Errors++
		return false
	}
	if seen {
		// Already recorded. Staying silent is the point: the window is still
		// breached, and re-announcing it every tick would train people to
		// ignore the alert that matters.
		return false
	}

	previousHash, err := s.eventRepo.GetLatestEventHash(ctx, row.OrgID)
	if err != nil {
		s.logger.Warn("failed to get latest event hash, defaulting to empty",
			zap.String("org_id", row.OrgID.String()), zap.Error(err))
	}

	event := &models.ComplianceEvent{
		EventType: eventType,
		Severity:  severity,
		Cve:       row.Cve,
		Metadata: models.JSONMap{
			"report_id":   row.ID.String(),
			"stage":       stage,
			"event_type":  string(d.EventType),
			"due":         d.Due.Format(time.RFC3339),
			"anchor":      d.Anchor.Format(time.RFC3339),
			"anchor_name": d.AnchorName,
			"rule":        d.Rule,
			"overdue_by":  d.Overdue(now).String(),
			"product_id":  row.ProductID,
		},
		PreviousEventHash: previousHash,
	}
	if s.signingService != nil {
		if err := s.signingService.SignEvent(event); err != nil {
			// Do NOT store an unsigned event. A missing event is auditable; a
			// broken hash chain is suspicious. The next tick retries.
			s.logger.Error("failed to sign CRA deadline event — not storing, to preserve hash chain integrity",
				zap.String("report_id", row.ID.String()),
				zap.String("stage", stage),
				zap.Error(err))
			result.Errors++
			return false
		}
	}
	if err := s.eventRepo.Create(ctx, row.OrgID, event); err != nil {
		s.logger.Error("failed to record CRA deadline event",
			zap.String("report_id", row.ID.String()),
			zap.String("stage", stage),
			zap.Error(err))
		result.Errors++
		return false
	}

	if s.alertHub != nil {
		s.alertHub.Broadcast(row.OrgID.String(), &Alert{
			Type:      eventType,
			Severity:  severity,
			CVE:       row.Cve,
			Message:   describeBreach(d, row, now),
			Timestamp: now,
		})
	}

	s.logger.Warn("CRA Article 14 reporting deadline recorded",
		zap.String("report_id", row.ID.String()),
		zap.String("stage", stage),
		zap.String("event_type", eventType),
		zap.Time("due", d.Due),
		zap.Duration("overdue_by", d.Overdue(now)),
		zap.String("anchor_name", d.AnchorName))
	return true
}

// describeBreach writes the alert message.
//
// The rule and the anchor are included because "you missed a deadline" is
// close to useless to an operator at 03:00: what they need is which window, on
// what basis, and since when.
func describeBreach(d cra.Deadline, row models.CRAReport, now time.Time) string {
	overdue := d.Overdue(now).Truncate(time.Minute)
	product := row.ProductName
	if product == "" {
		product = row.ProductID
	}
	return fmt.Sprintf(
		"CRA Article 14 %s for %s (product %s) was due %s, anchored on %s at %s — %s overdue. Rule: %s. No submission has been recorded through the SRP; file it now.",
		d.Stage, row.Cve, product,
		d.Due.Format(time.RFC3339), d.AnchorName, d.Anchor.Format(time.RFC3339),
		overdue, d.Rule)
}
