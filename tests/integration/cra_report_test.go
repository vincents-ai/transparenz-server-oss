// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

// The CRA reporting tables use PostgreSQL features the SQLite test schema
// cannot express: text[] columns, CHECK constraints over cardinality(), PL/pgSQL
// trigger functions enforcing append-only logs, and an ON CONFLICT upsert on a
// partial unique index. Testing them against SQLite would test a different
// schema than the one that ships, which is worse than not testing them at all
// — the append-only guarantees in particular would silently not exist.
//
//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"github.com/vincents-ai/transparenz-server-oss/pkg/services"
)

// craTestDB connects to a PostgreSQL instance whose compliance schema already
// has the CRA reporting tables (migrations/000045). It deliberately does not use
// the testcontainers harness in this package, which builds and boots the whole
// server binary: these tests exercise the repository against the schema alone,
// and coupling them to a full server boot would make a schema test fail for
// reasons that have nothing to do with the schema.
func craTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; skipping the PostgreSQL CRA reporting tests")
	}
	// TimeZone=UTC is requested so timestamps render in UTC rather than the
	// driver's local zone. It is a request, not a guarantee: pgx honours it
	// when the server accepts it as a runtime parameter. The assertions below
	// therefore compare INSTANTS rather than wall-clock structs, because a
	// regulatory deadline is an instant and comparing struct fields would make
	// the test fail on the local zone rather than on the value.
	if !strings.Contains(dsn, "TimeZone") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "TimeZone=UTC"
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	return db
}

func craTestOrg(t *testing.T, db *gorm.DB) uuid.UUID {
	t.Helper()
	// Only the primary key is inserted. A real deployment's organizations
	// table has name/slug and more, but this test needs nothing beyond a row
	// that satisfies the foreign key, and hard-coding the full column list
	// would break against any schema variation.
	id := uuid.New()
	require.NoError(t, db.Exec(
		`INSERT INTO compliance.organizations (id) VALUES (?) ON CONFLICT (id) DO NOTHING`, id).Error)
	return id
}

var craNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func newCRAReport(orgID uuid.UUID) cra.Report {
	awareness := craNow.Add(-6 * time.Hour)
	return cra.Report{
		ID:               uuid.New(),
		OrgID:            orgID,
		State:            cra.StateDetected,
		VulnerabilityID:  "CVE-2026-31337",
		ProductID:        "sbom:abc",
		ProductName:      "gateway.json",
		ComponentName:    "libfoo",
		ComponentVersion: "2.2.0",
		Title:            "Actively exploited vulnerability CVE-2026-31337",
		Awareness: cra.Awareness{
			AwarenessAt: awareness,
			Source:      cra.AwarenessSourceExploitEvidence,
			Evidence:    "pcap-2026-09-20",
		},
		Exploitation: &cra.ExploitationEvidence{
			ObservedAt:   awareness,
			Summary:      "observed mass exploitation",
			Source:       cra.AwarenessSourceExploitEvidence,
			Reference:    "pcap-2026-09-20",
			AttackVector: "network",
		},
		Decisions: []cra.Decision{{
			At:     craNow,
			To:     cra.StateDetected,
			Actor:  "user:sec@example.eu",
			Reason: "report opened from an exposure assessment",
		}},
		CreatedAt: craNow,
		UpdatedAt: craNow,
	}
}

func TestCRARepository_CreatePersistsAnchorAndDecisionLog(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	require.NoError(t, repo.Create(ctx, report))

	got, err := repo.GetByID(ctx, orgID, report.ID)
	require.NoError(t, err)
	assert.Equal(t, "CVE-2026-31337", got.Cve)
	assert.Equal(t, "sbom:abc", got.ProductID, "the report names the product the duty is owed for")
	assert.Equal(t, "libfoo", got.ComponentName)
	require.NotNil(t, got.AwarenessAt)
	assert.True(t, report.Awareness.AwarenessAt.Equal(*got.AwarenessAt),
		"the anchor must survive the round trip as the same instant")
	assert.Equal(t, "pcap-2026-09-20", got.AwarenessEvidence)
	require.Len(t, got.Events, 1, "the decision log is written with the report")
	assert.Equal(t, "user:sec@example.eu", got.Events[0].Actor)
}

func TestCRARepository_CreateRefusesAReportThatSkipsAssessment(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)

	report := newCRAReport(orgID)
	report.State = cra.StateReportableAEV
	report.EventType = cra.EventTypeAEV
	err := repo.Create(context.Background(), report)
	require.Error(t, err, "a report must not be created already classified")
}

func TestCRARepository_CreateRefusesAnUnattributedDecision(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)

	report := newCRAReport(orgID)
	report.Decisions[0].Actor = ""
	err := repo.Create(context.Background(), report)
	require.Error(t, err, "an unattributed decision is not auditable")
}

func TestCRARepository_ClassifyRequiresExploitationEvidence(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	report.Exploitation = nil
	require.NoError(t, repo.Create(ctx, report))

	err := repo.Classify(ctx, report, cra.EventTypeAEV, "user:sec@example.eu", "critical severity", craNow)
	require.Error(t, err, "a CVSS score is not exploitation evidence")
}

func TestCRARepository_ClassifyStoresTheDetermination(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	require.NoError(t, repo.Create(ctx, report))
	require.NoError(t, repo.Classify(ctx, report, cra.EventTypeAEV, "user:sec@example.eu", "exploitation evidence accepted", craNow))

	got, err := repo.GetByID(ctx, orgID, report.ID)
	require.NoError(t, err)
	require.NotNil(t, got.EventType)
	assert.Equal(t, "ACTIVELY_EXPLOITED_VULNERABILITY", *got.EventType)
	assert.Equal(t, "REPORTABLE_AEV", got.State)
	assert.Equal(t, "pcap-2026-09-20", got.ExploitationReference)
}

func TestCRARepository_ResubmissionKeepsTheFirstInstant(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	require.NoError(t, repo.Create(ctx, report))
	require.NoError(t, repo.Classify(ctx, report, cra.EventTypeAEV, "u", "assessed", craNow))

	current, err := repo.GetByID(ctx, orgID, report.ID)
	require.NoError(t, err)
	domain, err := repository.ToDomain(current)
	require.NoError(t, err)

	// File the early warning on time.
	_, err = repo.RecordSubmission(ctx, domain, cra.Submission{
		Stage:         cra.StageEarlyWarning,
		SubmittedAt:   craNow.Add(time.Hour),
		CaseReference: "SRP-2026-000123",
		Via:           "human_srp",
	}, "u", craNow)
	require.NoError(t, err)

	// File again, later, with a different reference.
	_, err = repo.RecordSubmission(ctx, domain, cra.Submission{
		Stage:         cra.StageEarlyWarning,
		SubmittedAt:   craNow.Add(20 * time.Hour),
		CaseReference: "SRP-2026-000123",
		Via:           "human_srp",
	}, "u", craNow)
	require.NoError(t, err)

	got, err := repo.GetByID(ctx, orgID, report.ID)
	require.NoError(t, err)
	require.Len(t, got.Submissions, 1, "one stage has one recorded submission")
	assert.True(t, craNow.Add(time.Hour).Equal(got.Submissions[0].SubmittedAt),
		"a later 'corrected' timestamp must never replace the recorded instant")
}

func TestCRARepository_AwarenessCorrectionRetainsTheAuditTrail(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	require.NoError(t, repo.Create(ctx, report))

	_, err := repo.CorrectAwareness(ctx, report, cra.AwarenessCorrection{
		NewValue: craNow.Add(-10 * time.Hour),
		Reason:   "advisory timestamp was the sender's clock; gateway logged receipt earlier",
		Evidence: "gateway log gl-2026-09-26",
		Actor:    "user:sec@example.eu",
		At:       craNow,
	})
	require.NoError(t, err)

	got, err := repo.GetByID(ctx, orgID, report.ID)
	require.NoError(t, err)
	require.Len(t, got.AwarenessAudits, 1)
	assert.True(t, report.Awareness.AwarenessAt.Equal(*got.AwarenessAudits[0].OldValue))
	assert.True(t, craNow.Add(-10*time.Hour).Equal(got.AwarenessAudits[0].NewValue))
	assert.Contains(t, got.AwarenessAudits[0].Reason, "sender's clock")
}

func TestCRARepository_DecisionLogIsAppendOnly(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	require.NoError(t, repo.Create(ctx, report))

	got, err := repo.GetByID(ctx, orgID, report.ID)
	require.NoError(t, err)
	require.NotEmpty(t, got.Events)

	err = db.Exec(`UPDATE compliance.cra_report_events SET reason = 'rewritten' WHERE id = ?`,
		got.Events[0].ID).Error
	require.Error(t, err, "the decision log must not be rewritable, even by direct SQL")

	err = db.Exec(`DELETE FROM compliance.cra_report_events WHERE id = ?`, got.Events[0].ID).Error
	require.Error(t, err, "the decision log must not be deletable, even by direct SQL")
}

func TestCRARepository_DatabaseRefusesAHandBuiltAEVWithoutEvidence(t *testing.T) {
	// The Go layer is not the only line of defence. A migration mistake or a
	// direct INSERT must not be able to record an AEV determination with no
	// evidence behind it.
	db := craTestDB(t)
	orgID := craTestOrg(t, db)

	err := db.Exec(`
		INSERT INTO compliance.cra_reports
			(id, org_id, cve, event_type, state, awareness_at, awareness_evidence)
		VALUES (?, ?, 'CVE-X', 'ACTIVELY_EXPLOITED_VULNERABILITY', 'REPORTABLE_AEV', ?, 'ref')`,
		uuid.New(), orgID, craNow).Error
	require.Error(t, err, "the database must reject an AEV with no exploitation evidence")
}

func TestCRARepository_DatabaseRefusesHandBuiltPecOnASevereIncident(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)

	err := db.Exec(`
		INSERT INTO compliance.cra_reports
			(id, org_id, cve, event_type, state, awareness_at, awareness_evidence,
			 pec_applicable, pec_grounds, pec_reasoning, pec_evidence, pec_decision_at, pec_decision_by)
		VALUES (?, ?, 'CVE-Y', 'SEVERE_INCIDENT', 'REPORTABLE_SI', ?, 'ref',
			TRUE, ARRAY['active_remediation'], 'because', ARRAY['rp-9'], ?, 'legal')`,
		uuid.New(), orgID, craNow, craNow).Error
	require.Error(t, err, "the database must reject PEC on a severe incident")
}

func TestCRARepository_TenantIsolation(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	other := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	require.NoError(t, repo.Create(ctx, report))

	_, err := repo.GetByID(ctx, other, report.ID)
	require.ErrorIs(t, err, repository.ErrNotFound, "another tenant must not read the report")

	rows, err := repo.ListByCVE(ctx, other, report.VulnerabilityID)
	require.NoError(t, err)
	assert.Empty(t, rows, "another tenant must not see the CVE either")
}

func TestCRARepository_ToDomainRoundTrip(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	require.NoError(t, repo.Create(ctx, report))
	report.EventType = cra.EventTypeAEV

	require.NoError(t, repo.Classify(ctx, report, cra.EventTypeAEV, "u", "assessed", craNow))

	stored, err := repo.GetByID(ctx, orgID, report.ID)
	require.NoError(t, err)
	domain, err := repository.ToDomain(stored)
	require.NoError(t, err)

	assert.Equal(t, cra.EventTypeAEV, domain.EventType)
	assert.Equal(t, cra.StateReportableAEV, domain.State)
	assert.Equal(t, report.ProductID, domain.ProductID)
	assert.Equal(t, "libfoo", domain.ComponentName)
	require.NotNil(t, domain.Exploitation)
	assert.Equal(t, "pcap-2026-09-20", domain.Exploitation.Reference)

	// The round trip must produce a report whose clock agrees with the
	// original, or the persisted record is not the regulatory record.
	deadlines, err := domain.Deadlines()
	require.NoError(t, err)
	require.NotEmpty(t, deadlines)
	assert.True(t, report.Awareness.AwarenessAt.Add(24*time.Hour).Equal(deadlines[0].Due),
		"a reloaded report must compute the same deadline as the one that was written")
}

func TestCRARepository_CoordinatorSelectionIsRecordedAndJustified(t *testing.T) {
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	repo := repository.NewCRARepository(db)
	ctx := context.Background()

	report := newCRAReport(orgID)
	require.NoError(t, repo.Create(ctx, report))

	err := repo.RecordCoordinatorSelection(ctx, report, cra.Coordinator{
		CsirtID: "DE-CSIRT", Country: "DE",
		Basis: cra.SelectionBasisManualOverride, SelectedBy: "u",
	})
	require.Error(t, err, "a manual override needs a written justification")

	require.NoError(t, repo.RecordCoordinatorSelection(ctx, report, cra.Coordinator{
		CsirtID: "DE-CSIRT", Country: "DE",
		Basis: cra.SelectionBasisEstablishmentCountry, SelectedBy: "u",
	}))

	got, err := repo.GetByID(ctx, orgID, report.ID)
	require.NoError(t, err)
	assert.Equal(t, "DE-CSIRT", got.CsirtID)
	require.NotNil(t, got.CsirtSelectionBasis)
	assert.Equal(t, "establishment_country", *got.CsirtSelectionBasis)
	require.Len(t, got.CoordinatorHistory, 1)
}

// --- Article 14 deadline sweeper -------------------------------------------
// The sweeper's decision logic is unit-tested against SQLite, but two things
// only exist on PostgreSQL: the JSON metadata operator the alert-once check
// uses, and the signed audit chain. Both are verified here.

func craSweepPostgres(t *testing.T) (*gorm.DB, *repository.CRARepository, *repository.ComplianceEventRepository, uuid.UUID) {
	t.Helper()
	db := craTestDB(t)
	orgID := craTestOrg(t, db)
	return db, repository.NewCRARepository(db), repository.NewComplianceEventRepository(db), orgID
}

func seedSweptReport(t *testing.T, db *gorm.DB, orgID uuid.UUID, eventType, state string, awareness time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	et := eventType
	row := &models.CRAReport{
		ID: id, OrgID: orgID, Cve: "CVE-2026-31337",
		EventType: &et, State: state,
		ProductID: "sbom:abc", ProductName: "gateway.json",
		AwarenessAt: &awareness, AwarenessSource: "cert",
		AwarenessEvidence: "cert mail", AwarenessRecordedBy: "user:sec@example.eu",
		ExploitationReference: "pcap-1",
		CreatedAt:             awareness, UpdatedAt: awareness,
		// A nil pq.StringArray serialises as SQL NULL, which the NOT NULL
		// DEFAULT '{}' columns reject. The repository's mapping sets these; a
		// test that builds the row directly has to do it itself.
		PecGrounds:  pq.StringArray{},
		PecEvidence: pq.StringArray{},
	}
	require.NoError(t, db.Create(row).Error)
	return id
}

// A breach is recorded into the signed audit chain, and recorded once. The
// once-ness matters more than usual here: the chain is a sequence of signed
// assertions, so a duplicate is a second signed statement that the same event
// happened twice.
func TestCRASweeperRecordsABreachOnceInTheSignedChain(t *testing.T) {
	db, reports, events, orgID := craSweepPostgres(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	seedSweptReport(t, db, orgID, "ACTIVELY_EXPLOITED_VULNERABILITY", "REPORTABLE_AEV", now.Add(-30*time.Hour))

	keyDir := t.TempDir()
	sweeper := services.NewCRADeadlineSweeper(
		reports, repository.NewOrganizationRepository(db), events,
		services.NewSigningService(db, zap.NewNop(), keyDir),
		nil, zap.NewNop(), time.Minute,
	)
	sweeper.SweepAtForTest(context.Background(), now)
	sweeper.SweepAtForTest(context.Background(), now)
	sweeper.SweepAtForTest(context.Background(), now)

	var breaches []models.ComplianceEvent
	require.NoError(t, db.Where("org_id = ? AND event_type = ?", orgID, services.EventCRADeadlineMissed).
		Find(&breaches).Error)
	require.Len(t, breaches, 1, "three sweeps must produce one audit event, not three")

	ev := breaches[0]
	assert.NotEmpty(t, ev.Signature, "the breach must be signed")
	assert.NotEmpty(t, ev.EventHash)
	assert.Equal(t, "critical", ev.Severity)
	assert.Equal(t, "EARLY_WARNING", ev.Metadata["stage"])
	assert.Equal(t, "awareness_at", ev.Metadata["anchor_name"])
	assert.Equal(t, "sbom:abc", ev.Metadata["product_id"])
	assert.NotEmpty(t, ev.Metadata["rule"], "the rule applied belongs on the event")
}

// The once-ness check relies on a JSON metadata lookup, which is a PostgreSQL
// operator. This asserts it directly so a future change to the dedup strategy
// cannot quietly break alerting and start emitting a duplicate every tick.
func TestHasEventForReportUsesReportScopedMetadata(t *testing.T) {
	db, _, events, orgID := craSweepPostgres(t)
	reportID := "11111111-1111-4111-8111-111111111111"
	otherID := "22222222-2222-4222-8222-222222222222"

	seen, err := events.HasEventForReport(context.Background(), orgID, "cra_deadline_missed", reportID, "EARLY_WARNING")
	require.NoError(t, err)
	assert.False(t, seen)

	require.NoError(t, db.Create(&models.ComplianceEvent{
		OrgID: orgID, EventType: "cra_deadline_missed", Severity: "critical",
		Metadata: models.JSONMap{"report_id": reportID, "stage": "EARLY_WARNING"},
	}).Error)

	seen, err = events.HasEventForReport(context.Background(), orgID, "cra_deadline_missed", reportID, "EARLY_WARNING")
	require.NoError(t, err)
	assert.True(t, seen)

	// A different STAGE of the same report is a separate failure and must not
	// be suppressed by the first one recorded. A report can miss both its 24h
	// and its 72h window, and an authority would want to see both.
	seen, err = events.HasEventForReport(context.Background(), orgID, "cra_deadline_missed", reportID, "NOTIFICATION_72H")
	require.NoError(t, err)
	assert.False(t, seen, "a second breached stage of the same report must be recordable")

	// A different stage of the same report type, and a different report, must
	// not be conflated: both are separately recordable conditions.
	seen, err = events.HasEventForReport(context.Background(), orgID, "cra_deadline_missed", otherID, "EARLY_WARNING")
	require.NoError(t, err)
	assert.False(t, seen)

	seen, err = events.HasEventForReport(context.Background(), orgID, "cra_submission_late", reportID, "EARLY_WARNING")
	require.NoError(t, err)
	assert.False(t, seen, "a different event type is a different condition")
}

// A deadline that cannot be computed must never be reported as breached. On
// PostgreSQL the full schema applies, so this exercises the real constraints
// alongside the sweeper's judgement.
func TestCRASweeperIgnoresUncomputableFinalReport(t *testing.T) {
	db, reports, events, orgID := craSweepPostgres(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	reportID := seedSweptReport(t, db, orgID, "ACTIVELY_EXPLOITED_VULNERABILITY", "REPORTABLE_AEV", now.Add(-400*24*time.Hour))

	sweeper := services.NewCRADeadlineSweeper(
		reports, repository.NewOrganizationRepository(db), events, nil, nil, zap.NewNop(), time.Minute)
	sweeper.SweepAtForTest(context.Background(), now)

	// The assertion is scoped to this report, because the sweeper is
	// deliberately cross-tenant and the test database holds other reports.
	var stages []string
	require.NoError(t, db.Model(&models.ComplianceEvent{}).
		Where("org_id = ? AND event_type = ? AND metadata->>'report_id' = ?",
			orgID, services.EventCRADeadlineMissed, reportID.String()).
		Pluck("metadata->>'stage'", &stages).Error)

	// The 24h and 72h windows are long breached, so two misses are expected.
	// What must not appear is a third for the final report, which has no
	// mitigation anchor and therefore no deadline to miss.
	assert.ElementsMatch(t, []string{"EARLY_WARNING", "NOTIFICATION_72H"}, stages,
		"two awareness-anchored windows breach; the unanchored final report must not")
}

// The sweeper detects and records. It must never create a submission: there is
// no ENISA API, and a filing is a legal determination, not a scheduled action.
func TestCRASweeperNeverCreatesASubmission(t *testing.T) {
	db, reports, events, orgID := craSweepPostgres(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	reportID := seedSweptReport(t, db, orgID, "ACTIVELY_EXPLOITED_VULNERABILITY", "REPORTABLE_AEV", now.Add(-30*time.Hour))

	sweeper := services.NewCRADeadlineSweeper(
		reports, repository.NewOrganizationRepository(db), events, nil, nil, zap.NewNop(), time.Minute)
	sweeper.SweepAtForTest(context.Background(), now)

	// Scoped to this report, since the sweeper is cross-tenant and the test
	// database holds submissions from other cases.
	var n int64
	require.NoError(t, db.Model(&models.CRASubmission{}).
		Where("report_id = ?", reportID).Count(&n).Error)
	assert.Zero(t, n)
}
