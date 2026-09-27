// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
)

var sweepNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// craSweepDB creates a SQLite database with just the columns the sweeper's
// decision logic reads.
//
// The shipping Article 14 schema uses PostgreSQL features SQLite cannot
// express — text[] columns, CHECK constraints over cardinality(), and PL/pgSQL
// append-only triggers — so those are exercised against a real PostgreSQL in
// tests/integration/cra_report_test.go. What is verified here is the sweeper's
// judgement: which deadlines exist, which have passed, and what that means.
// Duplicating the full schema here to test arithmetic that is already covered
// would add a second place for it to drift.
func craSweepDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`ATTACH DATABASE ':memory:' AS compliance`).Error)

	ddl := []string{
		`CREATE TABLE IF NOT EXISTS compliance.organizations (
			id text PRIMARY KEY, name text NOT NULL, slug text NOT NULL,
			enisa_submission_mode text DEFAULT 'export', csaf_scope text DEFAULT 'per_sbom',
			pdf_template text DEFAULT 'generic', sla_tracking_mode text DEFAULT 'per_cve',
			tier text DEFAULT 'standard', sla_mode text DEFAULT 'alerts_only',
			multi_tenant_mode text DEFAULT 'shared', enisa_api_endpoint text,
			enisa_api_key_encrypted text, csirt_endpoint text,
			nis2_member_state text, nis2_sector text, nis2_entity_class text,
			support_period_months integer DEFAULT 60,
			support_start_date datetime, support_end_date datetime,
			created_at datetime, updated_at datetime
		)`,
		`CREATE TABLE IF NOT EXISTS compliance.compliance_events (
			id text PRIMARY KEY, org_id text NOT NULL, event_type text NOT NULL,
			severity text NOT NULL, cve text, reported_to_authority text,
			timestamp datetime, metadata text DEFAULT '{}',
			signature text, signing_key_id text,
			previous_event_hash text, event_hash text,
			created_at datetime
		)`,
		`CREATE TABLE IF NOT EXISTS compliance.cra_reports (
			id text PRIMARY KEY, org_id text NOT NULL, cve text DEFAULT '', euvd_id text DEFAULT '',
			event_type text, state text NOT NULL DEFAULT 'DETECTED',
			title text DEFAULT '', description text DEFAULT '',
			product_id text DEFAULT '', product_name text DEFAULT '', sbom_id text,
			component_name text DEFAULT '', component_version text DEFAULT '', component_purl text DEFAULT '',
			awareness_at datetime, awareness_source text, awareness_evidence text DEFAULT '',
			awareness_reasoning text DEFAULT '', awareness_recorded_at datetime, awareness_recorded_by text DEFAULT '',
			exploitation_observed_at datetime, exploitation_source text,
			exploitation_reference text DEFAULT '', exploitation_summary text DEFAULT '',
			exploitation_attack_vector text DEFAULT '', exploitation_actor text DEFAULT '',
			exploitation_scope text DEFAULT '',
			mitigation_available_at datetime,
			pec_applicable integer DEFAULT 0, pec_grounds text, pec_reasoning text DEFAULT '',
			pec_evidence text, pec_delay_requested integer, pec_decision_at datetime,
			pec_decision_by text DEFAULT '',
			csirt_id text DEFAULT '', csirt_country text DEFAULT '', csirt_selection_basis text,
			csirt_justification text DEFAULT '', csirt_selected_at datetime, csirt_selected_by text DEFAULT '',
			disposition_reason text DEFAULT '', duplicate_of text,
			closed_at datetime, created_at datetime, updated_at datetime
		)`,
		`CREATE TABLE IF NOT EXISTS compliance.cra_submissions (
			id text PRIMARY KEY, org_id text NOT NULL, report_id text NOT NULL,
			stage text NOT NULL, submitted_at datetime NOT NULL,
			case_reference text DEFAULT '', package_digest text DEFAULT '',
			submitted_by text DEFAULT '', via text DEFAULT 'human_srp', created_at datetime
		)`,
	}
	for _, d := range ddl {
		require.NoError(t, db.Exec(d).Error)
	}
	return db
}

type sweeperFixture struct {
	sweeper *CRADeadlineSweeper
	db      *gorm.DB
	reports *repository.CRARepository
	events  *repository.ComplianceEventRepository
	orgID   uuid.UUID
}

func newSweeperFixture(t *testing.T) *sweeperFixture {
	t.Helper()
	db := craSweepDB(t)
	orgID := uuid.New()
	require.NoError(t, db.Exec(
		`INSERT INTO compliance.organizations (id, name, slug) VALUES (?, ?, ?)`,
		orgID.String(), "Acme", "acme").Error)

	f := &sweeperFixture{
		db:      db,
		reports: repository.NewCRARepository(db),
		events:  repository.NewComplianceEventRepository(db),
		orgID:   orgID,
	}
	f.sweeper = NewCRADeadlineSweeper(
		f.reports, repository.NewOrganizationRepository(db), f.events,
		nil, // no signing service; the signed path is covered in the PostgreSQL integration tests
		nil, // no alert hub
		zap.NewNop(), time.Minute,
	)
	f.sweeper.now = func() time.Time { return sweepNow }
	return f
}

// seedReport inserts a report whose awareness instant is the given number of
// hours before the sweeper's clock.
func (f *sweeperFixture) seedReport(t *testing.T, eventType, state string, awarenessHoursAgo int) uuid.UUID {
	t.Helper()
	return f.seedReportIn(t, f.orgID, eventType, state, awarenessHoursAgo)
}

func (f *sweeperFixture) seedReportIn(t *testing.T, orgID uuid.UUID, eventType, state string, awarenessHoursAgo int) uuid.UUID {
	t.Helper()
	awareness := sweepNow.Add(-time.Duration(awarenessHoursAgo) * time.Hour)
	id := uuid.New()
	rec := &models.CRAReport{
		ID: id, OrgID: orgID, Cve: "CVE-2026-31337",
		State:       state,
		AwarenessAt: &awareness, AwarenessSource: "cert",
		AwarenessEvidence: "cert mail", AwarenessRecordedBy: "user:sec@example.eu",
		ExploitationReference: "pcap-1",
		ProductID:             "sbom:abc", ProductName: "gateway.json",
		CreatedAt: awareness, UpdatedAt: awareness,
	}
	if eventType != "" {
		et := eventType
		rec.EventType = &et
	}
	require.NoError(t, f.db.Create(rec).Error)
	return id
}

// seedSubmission records a stage filing. It uses the fixture's org, which is
// every org these tests file against; the cross-tenant case does not file.
func (f *sweeperFixture) seedSubmission(t *testing.T, reportID uuid.UUID, stage string, at time.Time) {
	t.Helper()
	require.NoError(t, f.db.Create(&models.CRASubmission{
		ID: uuid.New(), OrgID: f.orgID, ReportID: reportID,
		Stage: stage, SubmittedAt: at, Via: "human_srp",
	}).Error)
}

func (f *sweeperFixture) countEvents(t *testing.T, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&models.ComplianceEvent{}).
		Where("org_id = ? AND event_type = ?", f.orgID, eventType).Count(&n).Error)
	return n
}

const (
	stAEV = "ACTIVELY_EXPLOITED_VULNERABILITY"
	stSI  = "SEVERE_INCIDENT"
)

// --- the core case -------------------------------------------------------

// Awareness 30 hours ago means the 24-hour Early Warning fell due six hours
// ago and nothing was filed.
func TestSweeperDetectsAMissedEarlyWarning(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, stAEV, "REPORTABLE_AEV", 30)

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 1, result.ReportsScanned)
	assert.Equal(t, 1, result.BreachesFound)
	assert.Equal(t, 1, result.BreachesLogged)
	assert.Equal(t, int64(1), f.countEvents(t, EventCRADeadlineMissed))
}

// Severity is critical in both the breached and the not-yet-due case. The only
// difference is the clock, which is the point.
func TestSweeperDoesNotBreachADeadlineThatHasNotPassed(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, stAEV, "REPORTABLE_AEV", 5) // due in 19h

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 0, result.BreachesFound)
	assert.Equal(t, int64(0), f.countEvents(t, EventCRADeadlineMissed))
}

func TestSweeperDoesNotBreachAStageThatWasSubmitted(t *testing.T) {
	f := newSweeperFixture(t)
	id := f.seedReport(t, stAEV, "REPORTABLE_AEV", 30)
	f.seedSubmission(t, id, "EARLY_WARNING", sweepNow.Add(-20*time.Hour))

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 0, result.BreachesFound, "a discharged obligation is not a missed one")
}

// Submitted on time, submitted late, and never submitted are three different
// facts. Collapsing late into missed would tell an authority the duty was
// discharged when it was not; collapsing late into submitted would hide a
// breach.
func TestSweeperDistinguishesLateFromMissed(t *testing.T) {
	t.Run("filed after the deadline is late", func(t *testing.T) {
		f := newSweeperFixture(t)
		id := f.seedReport(t, stAEV, "REPORTABLE_AEV", 30) // awareness 30h ago, so due 6h ago
		// Filed 5h ago, i.e. 25 hours after awareness: one hour past the window.
		f.seedSubmission(t, id, "EARLY_WARNING", sweepNow.Add(-5*time.Hour))

		result := f.sweeper.Sweep(context.Background())

		assert.Equal(t, 0, result.BreachesFound)
		assert.Equal(t, 1, result.LateLogged)
		assert.Equal(t, int64(0), f.countEvents(t, EventCRADeadlineMissed))
		assert.Equal(t, int64(1), f.countEvents(t, EventCRASubmissionLate))
	})

	t.Run("filed on time is neither", func(t *testing.T) {
		f := newSweeperFixture(t)
		id := f.seedReport(t, stAEV, "REPORTABLE_AEV", 30)
		f.seedSubmission(t, id, "EARLY_WARNING", sweepNow.Add(-20*time.Hour))

		result := f.sweeper.Sweep(context.Background())

		assert.Equal(t, 0, result.BreachesFound)
		assert.Equal(t, 0, result.LateLogged)
	})
}

// --- alerting once -------------------------------------------------------

// A breached window stays breached. Without dedup a one-minute ticker would
// write a duplicate on every pass, and a duplicate in a signed hash chain is a
// second signed assertion that the same thing happened twice.
func TestSweeperRecordsABreachExactlyOnce(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, stAEV, "REPORTABLE_AEV", 30)

	first := f.sweeper.Sweep(context.Background())
	second := f.sweeper.Sweep(context.Background())
	third := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 1, first.BreachesLogged)
	assert.Equal(t, 1, second.BreachesFound, "the condition is still true")
	assert.Equal(t, 0, second.BreachesLogged, "but it is not reported again")
	assert.Equal(t, 0, third.BreachesLogged)
	assert.Equal(t, int64(1), f.countEvents(t, EventCRADeadlineMissed))
}

// A single report can miss BOTH its 24-hour and its 72-hour window. Those are
// two separate failures, and an authority would want to see both. Deduplication
// keyed on report and type alone would let the first suppress the second, and
// the 72-hour miss would never be recorded at all.
func TestSweeperRecordsEveryBreachedStageOfOneReport(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, stAEV, "REPORTABLE_AEV", 200) // both windows long past

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 2, result.BreachesFound)
	assert.Equal(t, 2, result.BreachesLogged,
		"both the 24h and 72h misses must be recorded, not just the first")
	assert.Equal(t, int64(2), f.countEvents(t, EventCRADeadlineMissed))
}

// --- the false positive this sweeper is most able to produce -------------

// An AEV final report has no deadline until a mitigating measure becomes
// available. Reporting it as breached would be a false alarm on the most
// consequential alert the system emits, which is exactly the kind of noise that
// teaches an operator to ignore it.
func TestSweeperNeverBreachesAnUncomputableDeadline(t *testing.T) {
	f := newSweeperFixture(t)
	// 400 days of awareness: both awareness-anchored windows are long breached
	// and discharged, and the AEV final report still has no anchor at all.
	id := f.seedReport(t, stAEV, "REPORTABLE_AEV", 24*400)
	f.seedSubmission(t, id, "EARLY_WARNING", sweepNow.Add(-24*399*time.Hour))
	f.seedSubmission(t, id, "NOTIFICATION_72H", sweepNow.Add(-72*398*time.Hour))

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 0, result.BreachesFound,
		"a final report with no mitigation anchor is not due, not breached")
	assert.Equal(t, 0, result.BreachesLogged)
}

// A severe incident's final report is anchored on the 72-hour notification.
// With no notification there is no deadline, and that is the correct state.
func TestSweeperIgnoresSIReportsWithoutANotification(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, stSI, "REPORTABLE_SI", 10)

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 0, result.BreachesFound)
}

// Once a mitigation exists, the AEV final report becomes computable and can be
// breached like any other — this is the flip side of the test above.
func TestSweeperBreachesAnAEVFinalReportOnceAMitigationExists(t *testing.T) {
	f := newSweeperFixture(t)
	id := f.seedReport(t, stAEV, "REPORTABLE_AEV", 24*100)
	f.seedSubmission(t, id, "EARLY_WARNING", sweepNow.Add(-24*99*time.Hour))
	f.seedSubmission(t, id, "NOTIFICATION_72H", sweepNow.Add(-72*99*time.Hour))
	// Mitigation 20 days ago, so the 14-day final report fell due 6 days ago.
	mitigation := sweepNow.AddDate(0, 0, -20)
	require.NoError(t, f.db.Model(&models.CRAReport{}).Where("id = ?", id).
		Update("mitigation_available_at", mitigation).Error)

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 1, result.BreachesFound)
	assert.Equal(t, int64(1), f.countEvents(t, EventCRADeadlineMissed))
}

// --- boundaries ----------------------------------------------------------

// Assessment is a human act. A report that has not been classified carries no
// duty, so there is nothing to be late for.
func TestSweeperIgnoresUndeterminedReports(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, "", "ASSESSING_REPORTABILITY", 30)

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 1, result.ReportsScanned)
	assert.Equal(t, 0, result.BreachesFound, "an unclassified report has no obligation yet")
}

// A closed or not-reportable report has nothing outstanding. Re-discovering that
// every tick is how a sweeper fills a log with noise.
func TestSweeperIgnoresTerminalReports(t *testing.T) {
	f := newSweeperFixture(t)
	for _, state := range []string{"CLOSED", "NOT_REPORTABLE", "FALSE_POSITIVE", "DUPLICATE"} {
		f.seedReport(t, stAEV, state, 30)
	}

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 0, result.ReportsScanned, "terminal reports are not swept at all")
	assert.Equal(t, 0, result.BreachesFound)
}

// The breach boundary is the deadline instant itself, not the instant after.
//
// This is the domain's existing rule (Deadline.Evaluate uses now.Before(due) to
// decide pending, so an exact hit with nothing filed is a miss) and the sweeper
// follows it rather than inventing its own. The choice is defensible: "within
// 24 hours" that is met at the 24-hour mark, and a filing at the boundary is
// already no longer within the window. The test pins the behaviour so a future
// change is deliberate rather than accidental.
func TestSweeperBreachBoundaryIsTheDeadlineInstant(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, stAEV, "REPORTABLE_AEV", 24) // due exactly at sweepNow

	// One second before the deadline: still pending.
	f.sweeper.now = func() time.Time { return sweepNow.Add(-time.Second) }
	before := f.sweeper.Sweep(context.Background())
	assert.Equal(t, 0, before.BreachesFound, "one second early is not breached")

	// Exactly at the deadline, nothing filed: breached.
	f.sweeper.now = func() time.Time { return sweepNow }
	at := f.sweeper.Sweep(context.Background())
	assert.Equal(t, 1, at.BreachesFound, "the deadline instant itself with nothing filed is a miss")
}

// --- cross-tenant -------------------------------------------------------

// A regulatory clock that only ticks for the tenant someone happens to be
// looking at is not a clock.
func TestSweeperIsCrossTenant(t *testing.T) {
	f := newSweeperFixture(t)
	other := uuid.New()
	require.NoError(t, f.db.Exec(
		`INSERT INTO compliance.organizations (id, name, slug) VALUES (?, ?, ?)`,
		other.String(), "Beta", "beta").Error)

	f.seedReport(t, stAEV, "REPORTABLE_AEV", 30)
	f.seedReportIn(t, other, stAEV, "REPORTABLE_AEV", 30)

	result := f.sweeper.Sweep(context.Background())

	assert.Equal(t, 2, result.ReportsScanned)
	assert.Equal(t, 2, result.BreachesFound, "both tenants' clocks are watched")

	var n int64
	require.NoError(t, f.db.Model(&models.ComplianceEvent{}).Count(&n).Error)
	assert.Equal(t, int64(2), n)
}

// --- what the sweeper must never do -------------------------------------

// There is no ENISA API to submit to, and filing is a legal determination.
// The sweeper detects and records; it never files, and it never records a case
// reference it was not given.
func TestSweeperNeverRecordsASubmission(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, stAEV, "REPORTABLE_AEV", 30)

	f.sweeper.Sweep(context.Background())

	var n int64
	require.NoError(t, f.db.Model(&models.CRASubmission{}).Count(&n).Error)
	assert.Zero(t, n, "a sweeper must never create a submission record")
}

// The recorded event has to carry enough for an operator woken at 03:00 to act:
// which window, on what basis, since when, and for which product.
func TestSweeperRecordsAnActionableEvent(t *testing.T) {
	f := newSweeperFixture(t)
	f.seedReport(t, stAEV, "REPORTABLE_AEV", 30)

	f.sweeper.Sweep(context.Background())

	var ev models.ComplianceEvent
	require.NoError(t, f.db.Where("event_type = ?", EventCRADeadlineMissed).First(&ev).Error)
	assert.Equal(t, "critical", ev.Severity)
	assert.Equal(t, "CVE-2026-31337", ev.Cve)
	assert.Equal(t, "EARLY_WARNING", ev.Metadata["stage"])
	assert.Equal(t, "awareness_at", ev.Metadata["anchor_name"])
	assert.Equal(t, "sbom:abc", ev.Metadata["product_id"])
	assert.NotEmpty(t, ev.Metadata["rule"], "the rule applied must be on the event")
	assert.NotEmpty(t, ev.Metadata["overdue_by"])
}
