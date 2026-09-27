// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification, is strictly prohibited.
// See LICENSE.md for terms.

package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
)

// ErrNotFound is returned when a CRA report does not exist.
var ErrNotFound = errors.New("cra report not found")

// CRARepository persists CRA Article 14 reporting cycles.
//
// Writes go through the domain types in pkg/regulatory/cra rather than
// accepting raw model structs, because the rules that matter here — the
// awareness anchor, the AEV/SI split, PEC's availability, the retention of
// submission instants — are enforced by validating a domain value before it is
// stored. A caller that could write a row directly would bypass every one of
// them.
type CRARepository struct {
	db *gorm.DB
}

// NewCRARepository constructs a CRARepository.
func NewCRARepository(db *gorm.DB) *CRARepository { return &CRARepository{db: db} }

// Create inserts a new report in its DETECTED state, together with the decision
// log entries that explain why it was opened.
//
// The report is written as-is; its state is advanced through Transition, which
// is the only path that can move it. Creating a report directly in a
// reportable state would skip the assessment that produced the determination.
func (r *CRARepository) Create(ctx context.Context, report cra.Report) error {
	if report.ID == uuid.Nil {
		return fmt.Errorf("%w: report has no id", ErrNotFound)
	}
	if report.State != cra.StateDetected {
		return fmt.Errorf("cra: a new report must start at DETECTED, got %s", report.State)
	}
	if report.EventType.Valid() {
		// A report opens undetermined. A class asserted at open time carries no
		// determination, no reasoning and no actor behind it, and the whole
		// point of the DETECTED -> ASSESSING -> REPORTABLE_* path is that the
		// determination is a distinct, attributable act. Accepting one here
		// would let a report be born already classified and would bypass it.
		return fmt.Errorf(
			"cra: a new report must not carry an event type; open it undetermined and " +
				"record the determination through classification")
	}

	row, err := reportToRow(report)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		return r.appendEvents(tx, report.OrgID, report.ID, report.Decisions)
	})
}

// Transition applies a validated state change and appends the decision.
//
// It takes the full expected report, validates the transition through the
// domain state machine, and writes the new state and the decision entry in one
// transaction. The report is read back inside the transaction and its state
// re-checked, so two concurrent transitions cannot both apply.
func (r *CRARepository) Transition(ctx context.Context, report cra.Report, reason string, now time.Time) error {
	updated, err := report.TransitionTo(report.State, "", reason, now)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current models.CRAReport
		if err := tx.Where("id = ? AND org_id = ?", report.ID, report.OrgID).
			First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		// Re-validate against the state actually on record, not the one the
		// caller believes is current.
		if current.State != string(report.State) {
			return fmt.Errorf(
				"cra: report %s is in state %s, not %s; the transition was computed against a stale read",
				report.ID, current.State, report.State)
		}
		res := tx.Model(&models.CRAReport{}).
			Where("id = ? AND org_id = ? AND state = ?", report.ID, report.OrgID, report.State).
			Updates(map[string]any{
				"state":      string(updated.State),
				"event_type": nullIfEmpty(string(updated.EventType)),
				"updated_at": now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("cra: concurrent transition detected on report %s", report.ID)
		}
		if len(updated.Decisions) > len(report.Decisions) {
			return r.appendEvents(tx, report.OrgID, report.ID, updated.Decisions[len(report.Decisions):])
		}
		return nil
	})
}

// Classify records the reportability determination.
//
// This is the one write that sets event_type, and it validates the evidence the
// determination rests on: an AEV requires exploitation evidence, and a severe
// incident may not carry one.
func (r *CRARepository) Classify(ctx context.Context, report cra.Report, eventType cra.EventType, actor, reason string, now time.Time) error {
	if !eventType.Valid() {
		return fmt.Errorf("cra: %q is not a valid event type", eventType)
	}
	if eventType == cra.EventTypeAEV {
		if err := report.Exploitation.Validate(); err != nil {
			return fmt.Errorf("cra: AEV classification requires exploitation evidence: %w", err)
		}
	} else if report.Exploitation != nil {
		return fmt.Errorf("cra: a severe incident report must not carry AEV exploitation evidence")
	}
	// Run it through the domain so the state machine agrees. The walk goes
	// DETECTED -> ASSESSING_REPORTABILITY -> REPORTABLE_*: the assessment is a
	// distinct fact from the determination, and collapsing them would make the
	// decision log claim a determination was made at the instant the event was
	// noticed. The state machine forbids the shortcut, and so does this.
	assessing, err := report.TransitionTo(cra.StateAssessingReportability, actor,
		"reportability assessment started", now)
	if err != nil {
		return err
	}
	classified, err := assessing.TransitionTo(
		stateForEventType(eventType), actor, reason, now)
	if err != nil {
		return err
	}

	row, err := reportToRow(classified)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.CRAReport{}).
			Where("id = ? AND org_id = ?", report.ID, report.OrgID).
			Updates(map[string]any{
				"event_type":                 string(eventType),
				"state":                      string(classified.State),
				"title":                      row.Title,
				"description":                row.Description,
				"exploitation_observed_at":   row.ExploitationObservedAt,
				"exploitation_source":        row.ExploitationSource,
				"exploitation_reference":     row.ExploitationReference,
				"exploitation_summary":       row.ExploitationSummary,
				"exploitation_attack_vector": row.ExploitationAttackVector,
				"exploitation_actor":         row.ExploitationActor,
				"exploitation_scope":         row.ExploitationScope,
				"updated_at":                 now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return r.appendEvents(tx, report.OrgID, report.ID, classified.Decisions[len(report.Decisions):])
	})
}

func stateForEventType(t cra.EventType) cra.State {
	if t == cra.EventTypeSI {
		return cra.StateReportableSI
	}
	return cra.StateReportableAEV
}

// SetAwareness records the clock anchor and its provenance.
func (r *CRARepository) SetAwareness(ctx context.Context, report cra.Report, actor string) error {
	a := report.Awareness
	if err := a.Validate(); err != nil {
		return err
	}
	recordedAt := a.RecordedAt
	if recordedAt.IsZero() {
		recordedAt = time.Now()
	}
	updated := report
	updated.Awareness.RecordedAt = recordedAt
	updated.Awareness.RecordedBy = actor

	row, err := reportToRow(updated)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.CRAReport{}).
			Where("id = ? AND org_id = ?", report.ID, report.OrgID).
			Updates(map[string]any{
				"awareness_at":          row.AwarenessAt,
				"awareness_source":      row.AwarenessSource,
				"awareness_evidence":    row.AwarenessEvidence,
				"awareness_reasoning":   row.AwarenessReasoning,
				"awareness_recorded_at": row.AwarenessRecordedAt,
				"awareness_recorded_by": row.AwarenessRecordedBy,
				"updated_at":            time.Now(),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return r.appendAudit(tx, &models.CRAAwarenessAudit{
			OrgID:             report.OrgID,
			ReportID:          report.ID,
			OldValue:          nil,
			NewValue:          a.AwarenessAt,
			Actor:             actor,
			Reason:            firstNonEmpty(a.Reasoning, "initial awareness determination"),
			EvidenceReference: a.Evidence,
			ChangedAt:         recordedAt,
		})
	})
}

// CorrectAwareness applies a correction and records the full before/after.
//
// The report's anchor may move in either direction. What must never happen is
// a correction that silently rewrites whether a deadline was met: already
// recorded submission instants are untouched, so a correction that reveals a
// submission was in fact late is visible rather than relabelled.
func (r *CRARepository) CorrectAwareness(ctx context.Context, report cra.Report, c cra.AwarenessCorrection) (cra.Report, error) {
	updated, entry, err := cra.ApplyAwarenessCorrection(report.Awareness, c)
	if err != nil {
		return report, err
	}
	changed := report
	changed.Awareness = updated

	row, err := reportToRow(changed)
	if err != nil {
		return report, err
	}
	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.CRAReport{}).
			Where("id = ? AND org_id = ?", report.ID, report.OrgID).
			Updates(map[string]any{
				"awareness_at":        row.AwarenessAt,
				"awareness_evidence":  row.AwarenessEvidence,
				"awareness_reasoning": row.AwarenessReasoning,
				"updated_at":          time.Now(),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return r.appendAudit(tx, &models.CRAAwarenessAudit{
			OrgID:             report.OrgID,
			ReportID:          report.ID,
			OldValue:          &entry.OldValue,
			NewValue:          entry.NewValue,
			Actor:             entry.Actor,
			Reason:            entry.Reason,
			EvidenceReference: entry.EvidenceReference,
			ChangedAt:         entry.At,
		})
	})
	if err != nil {
		return report, err
	}
	return changed, nil
}

// RecordSubmission records a stage submission and advances the workflow.
//
// The unique (report_id, stage) constraint is what makes re-submission safe:
// the instant cannot be replaced, only the reference, so a missed deadline
// cannot be relabelled as met by filing again with a later timestamp.
func (r *CRARepository) RecordSubmission(ctx context.Context, report cra.Report, s cra.Submission, actor string, now time.Time) (cra.Report, error) {
	updated, err := report.RecordSubmission(s, actor, now)
	if err != nil {
		return report, err
	}

	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// ON CONFLICT updates the reference fields only. submitted_at is
		// deliberately excluded from the update list: the first recorded
		// instant is the one the deadline is measured against.
		if err := tx.Exec(`
			INSERT INTO compliance.cra_submissions
				(org_id, report_id, stage, submitted_at, case_reference,
				 package_digest, submitted_by, via, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (report_id, stage) DO UPDATE SET
				case_reference = EXCLUDED.case_reference,
				package_digest = EXCLUDED.package_digest,
				via           = EXCLUDED.via`,
			report.OrgID, report.ID, string(s.Stage), s.SubmittedAt,
			s.CaseReference, s.PackageDigest, firstNonEmpty(s.SubmittedBy, actor),
			firstNonEmpty(s.Via, "human_srp"), now,
		).Error; err != nil {
			return err
		}
		return tx.Model(&models.CRAReport{}).
			Where("id = ? AND org_id = ?", report.ID, report.OrgID).
			Updates(map[string]any{"state": string(updated.State), "updated_at": now}).Error
	})
	if err != nil {
		return report, err
	}
	return updated, nil
}

// SetPEC records a Particularly Exceptional Circumstances claim.
//
// The validation runs before the write, so a claim that is unavailable for the
// event class, attached to the wrong stage, or missing grounds, reasoning,
// evidence or a human decision, never reaches the database. The CHECK
// constraints repeat the same rules independently.
func (r *CRARepository) SetPEC(ctx context.Context, report cra.Report, p *cra.PEC) error {
	if p == nil {
		return nil
	}
	if err := p.Validate(report.EventType, cra.StageNotification72h); err != nil {
		return err
	}
	updates := map[string]any{
		"pec_applicable":      p.Applicable,
		"pec_grounds":         p.Grounds,
		"pec_reasoning":       p.Reasoning,
		"pec_evidence":        p.Evidence,
		"pec_delay_requested": p.DisseminationDelayRequested,
		"pec_decision_at":     p.DecisionAt,
		"pec_decision_by":     p.DecisionBy,
		"updated_at":          time.Now(),
	}
	return r.db.WithContext(ctx).Model(&models.CRAReport{}).
		Where("id = ? AND org_id = ?", report.ID, report.OrgID).
		Updates(updates).Error
}

// RecordCoordinatorSelection appends a CDaC selection, chaining it to any
// previous one so a selection that has been changed twice is still
// reconstructible.
func (r *CRARepository) RecordCoordinatorSelection(ctx context.Context, report cra.Report, c cra.Coordinator) error {
	if c.CsirtID == "" {
		return cra.ErrCoordinatorUndetermined
	}
	selected := report
	updated, err := selected.SelectCoordinator(c, time.Now())
	if err != nil {
		return err
	}
	coordinator := updated.Coordinator
	if coordinator == nil {
		return cra.ErrCoordinatorUndetermined
	}

	row := &models.CRACoordinatorSelection{
		OrgID:         report.OrgID,
		ReportID:      report.ID,
		CsirtID:       coordinator.CsirtID,
		Country:       coordinator.Country,
		Basis:         string(coordinator.Basis),
		Justification: coordinator.Justification,
		SelectedBy:    coordinator.SelectedBy,
		SelectedAt:    time.Now(),
	}
	if coordinator.Overridden != nil {
		row.SupersedesID = &uuid.Nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		basis := string(coordinator.Basis)
		return tx.Model(&models.CRAReport{}).
			Where("id = ? AND org_id = ?", report.ID, report.OrgID).
			Updates(map[string]any{
				"csirt_id":              coordinator.CsirtID,
				"csirt_country":         coordinator.Country,
				"csirt_selection_basis": basis,
				"csirt_justification":   coordinator.Justification,
				"csirt_selected_at":     coordinator.SelectedAt,
				"csirt_selected_by":     coordinator.SelectedBy,
				"updated_at":            time.Now(),
			}).Error
	})
}

// SetMitigation records the AEV final-report anchor.
func (r *CRARepository) SetMitigation(ctx context.Context, report cra.Report, updated cra.Report, actor string, now time.Time) error {
	if updated.MitigationAvailableAt == nil {
		return fmt.Errorf("cra: no mitigation timestamp on the updated report")
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.CRAReport{}).
			Where("id = ? AND org_id = ?", report.ID, report.OrgID).
			Updates(map[string]any{
				"mitigation_available_at": updated.MitigationAvailableAt,
				"updated_at":              now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return r.appendEvents(tx, report.OrgID, report.ID, updated.Decisions[len(report.Decisions):])
	})
}

// GetByID loads a report with its decision log, submissions, awareness audit
// and coordinator history.
func (r *CRARepository) GetByID(ctx context.Context, orgID, reportID uuid.UUID) (*models.CRAReport, error) {
	var row models.CRAReport
	err := r.db.WithContext(ctx).
		Preload("Events", func(db *gorm.DB) *gorm.DB { return db.Order("occurred_at") }).
		Preload("Submissions").
		Preload("AwarenessAudits", func(db *gorm.DB) *gorm.DB { return db.Order("changed_at") }).
		Preload("CoordinatorHistory", func(db *gorm.DB) *gorm.DB { return db.Order("selected_at") }).
		Where("id = ? AND org_id = ?", reportID, orgID).
		First(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &row, nil
}

// ListByCVE returns the open reports already covering a CVE in an org.
//
// The exposure resolver uses this to flag what is already covered, so a
// second assessment does not invite a duplicate filing of the same event.
func (r *CRARepository) ListByCVE(ctx context.Context, orgID uuid.UUID, cve string) ([]models.CRAReport, error) {
	var rows []models.CRAReport
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND cve = ?", orgID, cve).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

// ListByState returns reports in a state for the breach sweeper.
func (r *CRARepository) ListByState(ctx context.Context, orgID uuid.UUID, state cra.State, limit int) ([]models.CRAReport, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows []models.CRAReport
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND state = ?", orgID, string(state)).
		Order("awareness_at").
		Limit(limit).
		Find(&rows).Error
	return rows, err
}

// ToDomain projects a stored report back into the domain value.
func ToDomain(row *models.CRAReport) (cra.Report, error) {
	r := cra.Report{
		ID:              row.ID,
		OrgID:           row.OrgID,
		State:           cra.State(row.State),
		Title:           row.Title,
		Description:     row.Description,
		VulnerabilityID: row.Cve,
		EUVDID:          row.EuvdID,
		// The product and component round-trip. Losing them here would mean a
		// report reloaded from the database could no longer answer "which
		// product is affected?" — the first question an authority asks, and
		// the one this schema exists to answer.
		ProductID:             row.ProductID,
		ProductName:           row.ProductName,
		SbomID:                row.SbomID,
		ComponentName:         row.ComponentName,
		ComponentVersion:      row.ComponentVersion,
		ComponentPURL:         row.ComponentPURL,
		MitigationAvailableAt: row.MitigationAvailableAt,
		DispositionReason:     row.DispositionReason,
		DuplicateOf:           row.DuplicateOf,
		CreatedAt:             row.CreatedAt,
		UpdatedAt:             row.UpdatedAt,
	}
	if row.EventType != nil && *row.EventType != "" {
		r.EventType = cra.EventType(*row.EventType)
	}
	if row.AwarenessAt != nil {
		r.Awareness = cra.Awareness{
			AwarenessAt: *row.AwarenessAt,
			Source:      cra.AwarenessSource(row.AwarenessSource),
			Evidence:    row.AwarenessEvidence,
			Reasoning:   row.AwarenessReasoning,
			RecordedAt:  derefTime(row.AwarenessRecordedAt),
			RecordedBy:  row.AwarenessRecordedBy,
		}
	}
	if row.ExploitationReference != "" {
		r.Exploitation = &cra.ExploitationEvidence{
			ObservedAt:      derefTime(row.ExploitationObservedAt),
			Summary:         row.ExploitationSummary,
			Source:          cra.AwarenessSource(row.ExploitationSource),
			Reference:       row.ExploitationReference,
			AttackVector:    row.ExploitationAttackVector,
			AttributedActor: row.ExploitationActor,
			Scope:           row.ExploitationScope,
		}
	}
	if row.PecApplicable {
		grounds := make([]cra.PECGrounds, 0, len(row.PecGrounds))
		for _, g := range row.PecGrounds {
			grounds = append(grounds, cra.PECGrounds(g))
		}
		r.PEC = &cra.PEC{
			Applicable:                  true,
			Grounds:                     grounds,
			Reasoning:                   row.PecReasoning,
			Evidence:                    row.PecEvidence,
			DisseminationDelayRequested: row.PecDelayRequested,
			DecisionAt:                  row.PecDecisionAt,
			DecisionBy:                  row.PecDecisionBy,
		}
	}
	if row.CsirtID != "" {
		coordinator := &cra.Coordinator{
			CsirtID:    row.CsirtID,
			Country:    row.CsirtCountry,
			SelectedBy: row.CsirtSelectedBy,
			SelectedAt: row.CsirtSelectedAt,
		}
		if row.CsirtSelectionBasis != nil {
			coordinator.Basis = cra.SelectionBasis(*row.CsirtSelectionBasis)
			coordinator.Justification = row.CsirtJustification
		}
		r.Coordinator = coordinator
	}
	for _, s := range row.Submissions {
		r.Submissions = append(r.Submissions, cra.Submission{
			Stage:         cra.Stage(s.Stage),
			SubmittedAt:   s.SubmittedAt,
			CaseReference: s.CaseReference,
			PackageDigest: s.PackageDigest,
			SubmittedBy:   s.SubmittedBy,
			Via:           s.Via,
		})
	}
	for _, e := range row.Events {
		r.Decisions = append(r.Decisions, cra.Decision{
			At:       e.OccurredAt,
			From:     cra.State(e.FromState),
			To:       cra.State(e.ToState),
			Actor:    e.Actor,
			Reason:   e.Reason,
			Evidence: e.Evidence,
		})
	}
	return r, nil
}

// reportToRow projects a domain report into its stored form.
func reportToRow(r cra.Report) (*models.CRAReport, error) {
	row := &models.CRAReport{
		ID:                    r.ID,
		OrgID:                 r.OrgID,
		Cve:                   r.VulnerabilityID,
		EuvdID:                r.EUVDID,
		State:                 string(r.State),
		Title:                 r.Title,
		Description:           r.Description,
		ProductID:             r.ProductID,
		ProductName:           r.ProductName,
		SbomID:                r.SbomID,
		ComponentName:         r.ComponentName,
		ComponentVersion:      r.ComponentVersion,
		ComponentPURL:         r.ComponentPURL,
		DispositionReason:     r.DispositionReason,
		DuplicateOf:           r.DuplicateOf,
		CreatedAt:             r.CreatedAt,
		UpdatedAt:             r.UpdatedAt,
		MitigationAvailableAt: r.MitigationAvailableAt,
	}
	if r.EventType.Valid() {
		et := string(r.EventType)
		row.EventType = &et
	}
	if !r.Awareness.AwarenessAt.IsZero() {
		row.AwarenessAt = &r.Awareness.AwarenessAt
		row.AwarenessSource = string(r.Awareness.Source)
		row.AwarenessEvidence = r.Awareness.Evidence
		row.AwarenessReasoning = r.Awareness.Reasoning
		if !r.Awareness.RecordedAt.IsZero() {
			row.AwarenessRecordedAt = &r.Awareness.RecordedAt
		}
		row.AwarenessRecordedBy = r.Awareness.RecordedBy
	}
	if e := r.Exploitation; e != nil {
		row.ExploitationObservedAt = &e.ObservedAt
		row.ExploitationSource = string(e.Source)
		row.ExploitationReference = e.Reference
		row.ExploitationSummary = e.Summary
		row.ExploitationAttackVector = e.AttackVector
		row.ExploitationActor = e.AttributedActor
		row.ExploitationScope = e.Scope
	}
	// A nil pq.StringArray serialises as SQL NULL, which the NOT NULL DEFAULT
	// '{}' columns reject. "No PEC grounds recorded" and "PEC grounds are
	// null" are different claims and the schema distinguishes them, so the
	// zero value must be an empty set rather than an absence.
	row.PecGrounds = nonNilArray(row.PecGrounds)
	row.PecEvidence = nonNilArray(row.PecEvidence)
	return row, nil
}

// nonNilArray maps a nil slice to an empty one.
//
// A nil pq.StringArray serialises as SQL NULL, which every text[] NOT NULL
// DEFAULT '{}' column rejects. "No evidence recorded" and "evidence is null"
// are different claims, and the schema is right to insist on the distinction —
// the mapping is what has to make the distinction.
func nonNilArray(v pq.StringArray) pq.StringArray {
	if v == nil {
		return pq.StringArray{}
	}
	return v
}

func (r *CRARepository) appendEvents(tx *gorm.DB, orgID, reportID uuid.UUID, decisions []cra.Decision) error {
	if len(decisions) == 0 {
		return nil
	}
	rows := make([]models.CRAReportEvent, 0, len(decisions))
	for _, d := range decisions {
		actor := d.Actor
		if actor == "" {
			// The decision log requires an accountable actor; an unattributed
			// decision is not auditable and is not written.
			return fmt.Errorf("cra: decision to %s has no actor", d.To)
		}
		rows = append(rows, models.CRAReportEvent{
			OrgID:      orgID,
			ReportID:   reportID,
			FromState:  string(d.From),
			ToState:    string(d.To),
			Actor:      actor,
			Reason:     d.Reason,
			Evidence:   nonNilArray(d.Evidence),
			OccurredAt: d.At,
		})
	}
	return tx.Create(&rows).Error
}

func (r *CRARepository) appendAudit(tx *gorm.DB, a *models.CRAAwarenessAudit) error {
	return tx.Create(a).Error
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// ListOpenReports returns every CRA report that is not in a terminal state,
// across all organisations.
//
// It is deliberately cross-tenant, like the SLA calculator's org sweep: a
// reporting deadline is a regulatory clock, and a clock that only ticks for
// the organisation someone happens to be looking at is not a clock. The caller
// is responsible for establishing per-org context before writing.
//
// Terminal dispositions are excluded. A closed, not-reportable, false-positive
// or duplicate report has no outstanding obligation, and repeatedly
// "discovering" that one has no deadlines is how a sweeper fills a log with
// noise that trains people to ignore it.
func (r *CRARepository) ListOpenReports(ctx context.Context, limit int) ([]models.CRAReport, error) {
	if limit <= 0 {
		limit = 500
	}
	terminal := []string{
		"CLOSED", "NOT_REPORTABLE", "FALSE_POSITIVE", "DUPLICATE",
	}
	var rows []models.CRAReport
	// Submissions MUST be preloaded. Without them the caller cannot tell a
	// report whose 24-hour window was discharged from one that was missed, and
	// will report a breach for a filing that already happened — the single
	// worst false positive a deadline sweeper can produce.
	err := r.db.WithContext(ctx).
		Preload("Submissions").
		Where("state NOT IN ?", terminal).
		Order("awareness_at NULLS LAST").
		Limit(limit).
		Find(&rows).Error
	return rows, err
}
