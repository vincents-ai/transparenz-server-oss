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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
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
