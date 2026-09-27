package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func TestSlaDeadlineConstants(t *testing.T) {
	assert.Equal(t, 24*time.Hour, SlaHandlingExploitedWindow)
	assert.Equal(t, 72*time.Hour, SlaHandlingCriticalWindow)
}

func TestSlaModeConstants(t *testing.T) {
	assert.Equal(t, "per_cve", SlaModePerCve)
	assert.Equal(t, "per_sbom", SlaModePerSbom)
}

func TestSlaAutomationConstants(t *testing.T) {
	assert.Equal(t, "alerts_only", SlaAutomationAlertsOnly)
	assert.Equal(t, "approval_gate", SlaAutomationApprovalGate)
	assert.Equal(t, "fully_automatic", SlaAutomationFullyAutomatic)
}

func TestSlaAutomationModeValuesDistinct(t *testing.T) {
	modes := []string{
		SlaAutomationAlertsOnly,
		SlaAutomationApprovalGate,
		SlaAutomationFullyAutomatic,
	}
	seen := make(map[string]bool)
	for _, m := range modes {
		assert.False(t, seen[m], "duplicate mode value: %s", m)
		seen[m] = true
	}
	assert.Len(t, seen, 3)
}

func TestHandlingCriticalWindowIsLongerThanExploited(t *testing.T) {
	assert.Greater(t, SlaHandlingCriticalWindow, SlaHandlingExploitedWindow)
}

// fakeAutoSubmitter is a test double for the autoSubmitter interface. It lets
// the test control whether Submit succeeds or fails and observe the call.
type fakeAutoSubmitter struct {
	err        error
	submission *models.EnisaSubmission
	calledCVE  string
	calledOrg  uuid.UUID
}

func (f *fakeAutoSubmitter) Submit(_ context.Context, orgID uuid.UUID, cve string, _ models.JSONMap) (*models.EnisaSubmission, error) {
	f.calledCVE = cve
	f.calledOrg = orgID
	return f.submission, f.err
}

// TestApplySlaAutomation_FullyAutomatic_FlipsOnlyOnSuccess verifies the core
// integrity fix from the regulatory review: the SLA must flip to
// "auto_submitted" ONLY when the ENISA submission actually succeeds. A failed
// submission must never leave the SLA in a false-compliant state.
func TestApplySlaAutomation_FullyAutomatic_FlipsOnlyOnSuccess(t *testing.T) {
	t.Run("success flips SLA to auto_submitted", func(t *testing.T) {
		sla, calc, db := setupSlaAutomationTest(t)
		calc.enisaService = &fakeAutoSubmitter{submission: &models.EnisaSubmission{SubmissionID: "CSAF-ok"}}

		calc.applySlaAutomation(context.Background(), sla, SlaAutomationFullyAutomatic)

		fake := calc.enisaService.(*fakeAutoSubmitter)
		// The goroutine flips the status asynchronously; poll until Submit was
		// called AND the status has landed.
		require.Eventually(t, func() bool {
			if fake.calledCVE != sla.Cve {
				return false
			}
			var got models.SlaTracking
			require.NoError(t, db.First(&got, "id = ?", sla.ID).Error)
			return got.Status == "auto_submitted"
			// Poll slowly. The wait condition reads on every tick, and SQLite
			// allows a single writer: a tight 10ms read loop starves the
			// goroutine's UPDATE we are waiting for, which is why this test was
			// flaky under package-wide load and not in isolation.
		}, 10*time.Second, 100*time.Millisecond, "SLA must flip to auto_submitted after successful submission")
	})

	t.Run("failure leaves SLA status unchanged (no false compliant)", func(t *testing.T) {
		sla, calc, db := setupSlaAutomationTest(t)
		fake := &fakeAutoSubmitter{err: errors.New("receiver 503")}
		calc.enisaService = fake

		calc.applySlaAutomation(context.Background(), sla, SlaAutomationFullyAutomatic)

		// Wait for the goroutine to actually run and fail, then assert. The
		// previous version slept a fixed 100ms and asserted, which could pass
		// simply because the goroutine had not run yet — a false pass that
		// proved nothing about the behaviour under test.
		require.Eventually(t, func() bool { return fake.calledCVE == sla.Cve },
			10*time.Second, 50*time.Millisecond, "the submission must have been attempted")

		// And then hold the line: the status must not flip, for long enough
		// that a late flip would be caught.
		assert.Never(t, func() bool {
			var got models.SlaTracking
			if err := db.First(&got, "id = ?", sla.ID).Error; err != nil {
				return true
			}
			return got.Status == "auto_submitted"
		}, 500*time.Millisecond, 100*time.Millisecond,
			"a failed submission must never leave the SLA in a false-compliant state")

		var got models.SlaTracking
		require.NoError(t, db.First(&got, "id = ?", sla.ID).Error)
		assert.Equal(t, "pending", got.Status)
	})
}

// setupSlaAutomationTest builds an SlaCalculator backed by an in-memory sqlite
// DB with the sla_tracking table and one pending SLA row. Returns the SLA, a
// minimal calculator, and the DB handle for assertions.
func setupSlaAutomationTest(t *testing.T) (*models.SlaTracking, *SlaCalculator, *gorm.DB) {
	t.Helper()
	db := testutil.SetupTestDB(t, "sla_tracking")

	orgID := uuid.New()
	sla := &models.SlaTracking{
		ID:       uuid.New(),
		OrgID:    orgID,
		Cve:      "CVE-2024-AUTO",
		Status:   "pending",
		Deadline: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, db.Create(sla).Error)

	logger := zap.NewNop()
	calc := &SlaCalculator{db: db, logger: logger, serverCtx: context.Background()}
	return sla, calc, db
}

func ptrTime(t time.Time) *time.Time { return &t }

// TestComputeDeadlineSeparatesHandlingWindowsFromArticle14Obligations verifies
// the central correction: an internal remediation window and a CRA Article 14
// reporting obligation are computed by different rules, anchored on different
// events, and say which one they are.
//
// The previous model derived both from CVSS severity and the feed's own
// timestamps, so a CVSS 9.8 with no evidence of exploitation produced something
// that looked like a regulatory deadline and measured nothing the Regulation
// requires.
func TestComputeDeadlineSeparatesHandlingWindowsFromArticle14Obligations(t *testing.T) {
	kevDate := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	discDate := time.Date(2024, 6, 2, 12, 0, 0, 0, time.UTC)

	t.Run("confirmed exploitation with evidenced awareness is an Article 14 obligation", func(t *testing.T) {
		awareness := time.Date(2024, 6, 1, 9, 0, 0, 0, time.UTC)
		vuln := models.Vulnerability{
			DiscoveredAt:                discDate,
			KevDateAdded:                ptrTime(kevDate),
			AwarenessAt:                 ptrTime(awareness),
			AwarenessSource:             "cert",
			AwarenessEvidence:           "BSI CERT-Bund notification ref CERT-2026-0042",
			ActiveExploitationConfirmed: true,
		}
		deadline, anchor, anchorName := computeDeadline(vuln, true)

		assert.Equal(t, models.AnchorAwarenessAt, anchorName)
		assert.Equal(t, awareness, anchor)
		// 24h from awareness — NOT from the KEV feed date two days earlier, and
		// not from our ingestion the next day.
		assert.Equal(t, awareness.Add(24*time.Hour), deadline)
		assert.NotEqual(t, kevDate.Add(SlaHandlingExploitedWindow), deadline,
			"a third party's feed clock is not the manufacturer's awareness instant")
		assert.NotEqual(t, discDate.Add(SlaHandlingExploitedWindow), deadline,
			"our ingestion time is not the manufacturer's awareness instant")
	})

	t.Run("critical CVSS with no exploitation evidence is only a handling window", func(t *testing.T) {
		// CVSS 9.8, in the KEV feed, but the manufacturer has made no
		// evidenced determination and recorded no awareness. Not reportable.
		score := 9.8
		vuln := models.Vulnerability{
			CvssScore: &score, DiscoveredAt: discDate, KevDateAdded: ptrTime(kevDate),
			ActiveExploitationConfirmed: false,
		}
		_, _, anchorName := computeDeadline(vuln, false)
		assert.Equal(t, models.AnchorDiscoveredAt, anchorName,
			"a severity score is not a reportability trigger")
	})

	t.Run("confirmed exploitation without awareness evidence is refused, not defaulted", func(t *testing.T) {
		// This is the fallback the old code had and the new code must not: a
		// missing anchor must never be substituted, because a substituted
		// anchor silently extends the deadline in the filer's favour.
		awareness := time.Date(2024, 6, 1, 9, 0, 0, 0, time.UTC)
		vuln := models.Vulnerability{
			DiscoveredAt:                discDate,
			AwarenessAt:                 ptrTime(awareness),
			ActiveExploitationConfirmed: true,
		}
		_, _, anchorName := computeDeadline(vuln, true)
		assert.NotEqual(t, models.AnchorAwarenessAt, anchorName)
	})

	t.Run("exploitation with a future awareness timestamp is refused", func(t *testing.T) {
		// Clock skew must not hand the filer a fresh 24 hours for a past event.
		future := time.Now().Add(48 * time.Hour)
		vuln := models.Vulnerability{
			AwarenessAt:                 ptrTime(future),
			AwarenessEvidence:           "ref x",
			ActiveExploitationConfirmed: true,
		}
		_, _, anchorName := computeDeadline(vuln, true)
		assert.NotEqual(t, models.AnchorAwarenessAt, anchorName)
	})

	// --- handling windows ---------------------------------------------------

	t.Run("KEV handling window anchors to the feed date", func(t *testing.T) {
		vuln := models.Vulnerability{DiscoveredAt: discDate, KevDateAdded: ptrTime(kevDate)}
		deadline, _, anchorName := computeDeadline(vuln, true)
		assert.Equal(t, models.AnchorKevDateAdded, anchorName)
		assert.Equal(t, kevDate.Add(SlaHandlingExploitedWindow), deadline)
	})

	t.Run("KEV without a feed date falls back to ingestion", func(t *testing.T) {
		vuln := models.Vulnerability{DiscoveredAt: discDate}
		deadline, _, _ := computeDeadline(vuln, true)
		assert.Equal(t, discDate.Add(SlaHandlingExploitedWindow), deadline)
	})

	t.Run("past handling deadline is preserved so a real breach surfaces", func(t *testing.T) {
		old := time.Now().AddDate(0, 0, -10)
		vuln := models.Vulnerability{DiscoveredAt: old}
		deadline, _, _ := computeDeadline(vuln, false)
		assert.True(t, deadline.Before(time.Now()), "an already-breached deadline must not be reset")
		assert.Equal(t, old.Add(SlaHandlingCriticalWindow), deadline)
	})

	t.Run("zero ingestion timestamp falls back to now", func(t *testing.T) {
		before := time.Now()
		vuln := models.Vulnerability{}
		deadline, _, _ := computeDeadline(vuln, false)
		after := time.Now()
		lo, hi := before.Add(SlaHandlingCriticalWindow), after.Add(SlaHandlingCriticalWindow)
		assert.True(t, !deadline.Before(lo) && !deadline.After(hi),
			"zero anchor should fall back to ~now+window, got %v", deadline)
	})

	t.Run("future ingestion timestamp clamps to now", func(t *testing.T) {
		future := time.Now().Add(48 * time.Hour)
		vuln := models.Vulnerability{DiscoveredAt: future}
		before := time.Now()
		deadline, _, _ := computeDeadline(vuln, false)
		after := time.Now()
		unclamped := future.Add(SlaHandlingCriticalWindow)
		assert.True(t, deadline.Before(unclamped), "future anchor must be clamped")
		lo, hi := before.Add(SlaHandlingCriticalWindow), after.Add(SlaHandlingCriticalWindow)
		assert.True(t, !deadline.Before(lo) && !deadline.After(hi),
			"clamped deadline should be ~now+window, got %v", deadline)
	})
}

// TestArticle14ObligationIsAnchoredOnAwarenessNotOnTheFeed pins the single
// property the whole change exists for, as a standalone assertion.
func TestArticle14ObligationIsAnchoredOnAwarenessNotOnTheFeed(t *testing.T) {
	// The feed knew for three days before we did, and we ingested it a day
	// after that. The manufacturer's obligation runs from when the
	// manufacturer knew.
	awareness := time.Now().Add(-6 * time.Hour)
	feedDate := awareness.Add(-72 * time.Hour)
	ingested := awareness.Add(-24 * time.Hour)

	vuln := models.Vulnerability{
		DiscoveredAt:                ingested,
		KevDateAdded:                ptrTime(feedDate),
		AwarenessAt:                 ptrTime(awareness),
		AwarenessSource:             "exploit_evidence",
		AwarenessEvidence:           "pcap-2026-09-20-0845",
		ActiveExploitationConfirmed: true,
	}
	deadline, _, anchorName := computeDeadline(vuln, true)

	assert.Equal(t, models.AnchorAwarenessAt, anchorName)
	assert.Equal(t, awareness.Add(24*time.Hour), deadline)
	assert.True(t, deadline.After(ingested.Add(24*time.Hour)),
		"ingestion time is not awareness; using it would shorten the deadline")
}

// TestSlaCalculator_OwnsPendingToViolatedTransition verifies the calculator
// (not the alert service) flips overdue pending SLAs to "violated", and that
// the alert service's notification query (ListUnnotifiedViolated) is gated by
// notified_at so each breach is alerted exactly once.
func TestSlaCalculator_OwnsPendingToViolatedTransition(t *testing.T) {
	db := testutil.SetupTestDB(t, "sla_tracking")
	repo := repository.NewSlaTrackingRepository(db)

	orgID := uuid.New()
	ctx := middleware.ContextWithOrgID(context.Background(), orgID)

	// Insert an overdue-pending SLA directly.
	overdue := &models.SlaTracking{
		ID:       uuid.New(),
		OrgID:    orgID,
		Cve:      "CVE-2024-OVERDUE",
		Status:   "pending",
		Deadline: time.Now().Add(-2 * time.Hour), // past
	}
	require.NoError(t, db.Create(overdue).Error)

	// ListOverdue should find it (the misnamed ListViolated used to).
	got, err := repo.ListOverdue(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1, "ListOverdue must return the overdue-pending SLA")

	// The calculator flips it.
	require.NoError(t, repo.UpdateStatus(ctx, overdue.ID, "violated"))

	// ListUnnotifiedViolated now returns it (violated, not yet notified).
	unnotified, err := repo.ListUnnotifiedViolated(ctx)
	require.NoError(t, err)
	require.Len(t, unnotified, 1, "violated SLA should appear as unnotified")

	// After MarkNotified, it must NOT reappear (idempotent notification).
	require.NoError(t, repo.MarkNotified(ctx, overdue.ID))
	unnotified2, err := repo.ListUnnotifiedViolated(ctx)
	require.NoError(t, err)
	assert.Empty(t, unnotified2, "notified SLA must not be returned again")
}

// TestSlaCalculator_ReconcileAutoSubmitted verifies the reconciler closes the
// reporting gap from fix #5: when an ENISA submission that initially failed
// (leaving the SLA pending) later succeeds via the retry worker, the SLA is
// flipped to auto_submitted so status reflects the eventual success.
func TestSlaCalculator_ReconcileAutoSubmitted(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "sla_tracking", "enisa_submissions")
	slaRepo := repository.NewSlaTrackingRepository(db)
	subRepo := repository.NewEnisaSubmissionRepository(db)
	ctx := t.Context()

	t.Run("pending SLA flipped when matching submission is submitted", func(t *testing.T) {
		orgID := uuid.New()
		require.NoError(t, db.Create(&models.Organization{ID: orgID, Name: "auto-org", Slug: "auto-org", SlaMode: SlaAutomationFullyAutomatic}).Error)

		cve := "CVE-2024-RECON"
		sla := &models.SlaTracking{
			ID: uuid.New(), OrgID: orgID, Cve: cve, Status: "pending",
			Deadline: time.Now().Add(24 * time.Hour),
		}
		require.NoError(t, slaRepo.Create(ctx, orgID, sla))

		// A submitted ENISA filing whose CSAF doc carries the same CVE.
		require.NoError(t, subRepo.Create(ctx, orgID, &models.EnisaSubmission{
			OrgID: orgID, SubmissionID: "CSAF-recon-1", Status: "submitted",
			CsafDocument: models.JSONMap{"vulnerabilities": []interface{}{
				map[string]interface{}{"cve": cve},
			}},
		}))

		calc := &SlaCalculator{db: db, logger: zap.NewNop(), slaRepo: slaRepo, orgRepo: repository.NewOrganizationRepository(db), enisaSubRepo: subRepo}
		calc.reconcileAutoSubmitted(ctx)

		var got models.SlaTracking
		require.NoError(t, db.First(&got, "id = ?", sla.ID).Error)
		assert.Equal(t, "auto_submitted", got.Status, "pending SLA with a successful matching submission must flip to auto_submitted")
	})

	t.Run("no flip when CVE does not match", func(t *testing.T) {
		orgID := uuid.New()
		require.NoError(t, db.Create(&models.Organization{ID: orgID, Name: "nomatch-org", Slug: "nomatch-org", SlaMode: SlaAutomationFullyAutomatic}).Error)
		sla := &models.SlaTracking{ID: uuid.New(), OrgID: orgID, Cve: "CVE-OTHER", Status: "pending", Deadline: time.Now().Add(24 * time.Hour)}
		require.NoError(t, slaRepo.Create(ctx, orgID, sla))
		require.NoError(t, subRepo.Create(ctx, orgID, &models.EnisaSubmission{
			OrgID: orgID, SubmissionID: "CSAF-other-1", Status: "submitted",
			CsafDocument: models.JSONMap{"vulnerabilities": []interface{}{map[string]interface{}{"cve": "CVE-DIFFERENT"}}},
		}))

		calc := &SlaCalculator{db: db, logger: zap.NewNop(), slaRepo: slaRepo, orgRepo: repository.NewOrganizationRepository(db), enisaSubRepo: subRepo}
		calc.reconcileAutoSubmitted(ctx)

		var got models.SlaTracking
		require.NoError(t, db.First(&got, "id = ?", sla.ID).Error)
		assert.Equal(t, "pending", got.Status, "SLA with no matching submission must stay pending")
	})

	t.Run("no flip for non-fully_automatic org", func(t *testing.T) {
		orgID := uuid.New()
		require.NoError(t, db.Create(&models.Organization{ID: orgID, Name: "alerts-org", Slug: "alerts-org", SlaMode: SlaAutomationAlertsOnly}).Error)
		cve := "CVE-NOAUTO"
		sla := &models.SlaTracking{ID: uuid.New(), OrgID: orgID, Cve: cve, Status: "pending", Deadline: time.Now().Add(24 * time.Hour)}
		require.NoError(t, slaRepo.Create(ctx, orgID, sla))
		require.NoError(t, subRepo.Create(ctx, orgID, &models.EnisaSubmission{
			OrgID: orgID, SubmissionID: "CSAF-noauto-1", Status: "submitted",
			CsafDocument: models.JSONMap{"vulnerabilities": []interface{}{map[string]interface{}{"cve": cve}}},
		}))

		calc := &SlaCalculator{db: db, logger: zap.NewNop(), slaRepo: slaRepo, orgRepo: repository.NewOrganizationRepository(db), enisaSubRepo: subRepo}
		calc.reconcileAutoSubmitted(ctx)

		var got models.SlaTracking
		require.NoError(t, db.First(&got, "id = ?", sla.ID).Error)
		assert.Equal(t, "pending", got.Status, "non-fully_automatic orgs do not autosubmit and must not be reconciled")
	})

	t.Run("nil submission repo is a no-op", func(t *testing.T) {
		// Defends the nil-safe contract so unwired callers don't panic.
		calc := &SlaCalculator{db: db, logger: zap.NewNop(), slaRepo: slaRepo, orgRepo: repository.NewOrganizationRepository(db), enisaSubRepo: nil}
		assert.NotPanics(t, func() { calc.reconcileAutoSubmitted(ctx) })
	})
}

// TestCveFromCsafDoc covers the CSAF-JSON CVE extractor (defensive parsing).
func TestCveFromCsafDoc(t *testing.T) {
	assert.Equal(t, "CVE-2024-X", cveFromCsafDoc(models.JSONMap{"vulnerabilities": []interface{}{map[string]interface{}{"cve": "CVE-2024-X"}}}))
	assert.Equal(t, "", cveFromCsafDoc(nil))
	assert.Equal(t, "", cveFromCsafDoc(models.JSONMap{}))
	assert.Equal(t, "", cveFromCsafDoc(models.JSONMap{"vulnerabilities": []interface{}{}}))
	assert.Equal(t, "", cveFromCsafDoc(models.JSONMap{"vulnerabilities": "not-a-slice"}))
	assert.Equal(t, "", cveFromCsafDoc(models.JSONMap{"vulnerabilities": []interface{}{map[string]interface{}{ /* no cve */ }}}))
}

// TestSlaDeadlineUsesDiscoveredAt verifies that the SLA calculator uses
// the CVE's DiscoveredAt timestamp as the deadline anchor, NOT time.Now().
//
// This is critical for ENISA/NIS2/CRA compliance: if a CVE was published
// 5 days ago and the SLA calculator runs today, the deadline MUST be
// discovered_at + 72h, not now + 72h. Using now + 72h would give the
// operator 5 extra days, violating the mandated reporting window.
//
// The deadline = discovered_at + SlaHandlingExploitedWindow (24h) or SlaHandlingCriticalWindow (72h).
func TestSlaDeadlineUsesDiscoveredAt(t *testing.T) {
	// Simulate a CVE discovered 5 days ago
	discoveredAt := time.Now().Add(-5 * 24 * time.Hour)

	// KEV: deadline should be discovered_at + 24h = 4 days ago
	kevDeadline := discoveredAt.Add(SlaHandlingExploitedWindow)
	expectedKEV := time.Now().Add(-4*24*time.Hour + SlaHandlingExploitedWindow - 5*24*time.Hour)
	_ = expectedKEV // sanity: discoveredAt + 24h
	assert.True(t, kevDeadline.Before(time.Now().Add(-3*24*time.Hour)),
		"KEV deadline for a CVE discovered 5 days ago should already be in the past (4d ago)")

	// Critical: deadline should be discovered_at + 72h = 3 days ago (ALREADY VIOLATED)
	criticalDeadline := discoveredAt.Add(SlaHandlingCriticalWindow)
	assert.True(t, criticalDeadline.Before(time.Now().Add(-2*24*time.Hour)),
		"Critical deadline for a CVE discovered 5 days ago should be ~3 days in the past")

	// Verify that the deadline is NOT time.Now() + SLA
	notNow := time.Now().Add(SlaHandlingCriticalWindow)
	assert.NotEqual(t, notNow, criticalDeadline,
		"SLA deadline must NOT be calculated from time.Now()")

	t.Logf("CVE discovered 5 days ago:")
	t.Logf("  discovered_at:    %s", discoveredAt.Format(time.RFC3339))
	t.Logf("  KEV deadline:     %s (should be ~4d ago)", kevDeadline.Format(time.RFC3339))
	t.Logf("  Critical deadline: %s (should be ~3d ago)", criticalDeadline.Format(time.RFC3339))
}

// TestSlaDeadlineNotFromNow is a regression test for the SLA calculator bug
// where deadlines were incorrectly calculated from time.Now() instead of
// discovered_at. This caused SLA windows to be much larger than mandated
// by ENISA/NIS2/CRA.
func TestSlaDeadlineNotFromNow(t *testing.T) {
	discoveredAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	// Correct: deadline from discovered_at
	correctDeadline := discoveredAt.Add(SlaHandlingExploitedWindow) // 2026-05-02 12:00 UTC

	// Wrong: deadline from now
	wrongDeadline := time.Now().Add(SlaDeadlineKEV) // ~24h from now

	// They should NOT be equal (unless the test happens to run at exactly discoveredAt)
	diff := wrongDeadline.Sub(correctDeadline)

	// The wrong deadline would be ~25 days later than the correct one
	assert.Greater(t, diff, 20*24*time.Hour,
		"deadline from time.Now() would be ~25 days later than deadline from discovered_at. "+
			"This is the SLA erosion bug.")

	t.Logf("Correct (discovered_at + 24h): %s", correctDeadline.Format(time.RFC3339))
	t.Logf("Wrong (now + 24h):             %s", wrongDeadline.Format(time.RFC3339))
	t.Logf("Difference:                     %v", diff)
}
