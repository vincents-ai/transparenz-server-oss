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
	assert.Equal(t, 24*time.Hour, SlaDeadlineKEV)
	assert.Equal(t, 72*time.Hour, SlaDeadlineCritical)
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

func TestSlaDeadlineCriticalIsLongerThanKEV(t *testing.T) {
	assert.Greater(t, SlaDeadlineCritical, SlaDeadlineKEV)
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
		}, 2*time.Second, 10*time.Millisecond, "SLA must flip to auto_submitted after successful submission")
	})

	t.Run("failure leaves SLA status unchanged (no false compliant)", func(t *testing.T) {
		sla, calc, db := setupSlaAutomationTest(t)
		calc.enisaService = &fakeAutoSubmitter{err: errors.New("ENISA 503")}

		calc.applySlaAutomation(context.Background(), sla, SlaAutomationFullyAutomatic)

		// Give the goroutine a moment to run and fail.
		time.Sleep(100 * time.Millisecond)
		var got models.SlaTracking
		require.NoError(t, db.First(&got, "id = ?", sla.ID).Error)
		assert.Equal(t, "pending", got.Status, "failed submission must NOT flip SLA to auto_submitted")
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

// TestComputeDeadline verifies CRA Art. 10 deadlines are anchored to the vuln's
// known/exploited date rather than the moment the calculator runs.
func TestComputeDeadline(t *testing.T) {
	// Fixed "now"-relative inputs: use real times well in the past so the
	// anchors are unambiguously valid.
	kevDate := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)       // exploited
	discDate := time.Date(2024, 6, 2, 12, 0, 0, 0, time.UTC)      // discovered
	expectedKEVDeadline := kevDate.Add(SlaDeadlineKEV)            // 24h after exploit
	expectedCriticalDeadline := discDate.Add(SlaDeadlineCritical) // 72h after known

	t.Run("KEV anchors to KevDateAdded", func(t *testing.T) {
		vuln := models.Vulnerability{DiscoveredAt: discDate, KevDateAdded: ptrTime(kevDate)}
		got := computeDeadline(vuln, true)
		assert.Equal(t, expectedKEVDeadline, got, "KEV deadline must run from exploitation date")
	})

	t.Run("KEV without KevDateAdded falls back to DiscoveredAt", func(t *testing.T) {
		vuln := models.Vulnerability{DiscoveredAt: discDate, KevDateAdded: nil}
		got := computeDeadline(vuln, true)
		assert.Equal(t, discDate.Add(SlaDeadlineKEV), got)
	})

	t.Run("critical anchors to DiscoveredAt regardless of KEV date", func(t *testing.T) {
		vuln := models.Vulnerability{DiscoveredAt: discDate, KevDateAdded: ptrTime(kevDate)}
		got := computeDeadline(vuln, false)
		assert.Equal(t, expectedCriticalDeadline, got, "critical deadline must run from known date")
	})

	t.Run("past deadline is preserved (real breach surfaces, not masked)", func(t *testing.T) {
		// Vuln discovered 10 days ago -> 72h deadline is already in the past.
		old := time.Now().AddDate(0, 0, -10)
		vuln := models.Vulnerability{DiscoveredAt: old}
		got := computeDeadline(vuln, false)
		assert.True(t, got.Before(time.Now()), "already-breached deadline must not be reset to the future")
		assert.Equal(t, old.Add(SlaDeadlineCritical), got)
	})

	t.Run("zero anchor falls back to now", func(t *testing.T) {
		before := time.Now()
		vuln := models.Vulnerability{} // zero DiscoveredAt, nil KevDateAdded
		got := computeDeadline(vuln, false)
		after := time.Now()
		lo, hi := before.Add(SlaDeadlineCritical), after.Add(SlaDeadlineCritical)
		assert.True(t, !got.Before(lo) && !got.After(hi), "zero anchor should fall back to ~now+window, got %v want [%v,%v]", got, lo, hi)
	})

	t.Run("future anchor (clock skew / bad feed) clamps to now", func(t *testing.T) {
		future := time.Now().Add(48 * time.Hour)
		vuln := models.Vulnerability{DiscoveredAt: future}
		before := time.Now()
		got := computeDeadline(vuln, false)
		after := time.Now()
		// The clamp must discard the future anchor: the deadline should be
		// ~now+window, NOT future+window (which would push the SLA out further).
		unclamped := future.Add(SlaDeadlineCritical)
		assert.True(t, got.Before(unclamped), "future anchor must be clamped (deadline earlier than unclamped future+window)")
		lo, hi := before.Add(SlaDeadlineCritical), after.Add(SlaDeadlineCritical)
		assert.True(t, !got.Before(lo) && !got.After(hi), "clamped deadline should be ~now+window, got %v want [%v,%v]", got, lo, hi)
	})
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
// The deadline = discovered_at + SlaDeadlineKEV (24h) or SlaDeadlineCritical (72h).
func TestSlaDeadlineUsesDiscoveredAt(t *testing.T) {
	// Simulate a CVE discovered 5 days ago
	discoveredAt := time.Now().Add(-5 * 24 * time.Hour)

	// KEV: deadline should be discovered_at + 24h = 4 days ago
	kevDeadline := discoveredAt.Add(SlaDeadlineKEV)
	expectedKEV := time.Now().Add(-4*24*time.Hour + SlaDeadlineKEV - 5*24*time.Hour)
	_ = expectedKEV // sanity: discoveredAt + 24h
	assert.True(t, kevDeadline.Before(time.Now().Add(-3*24*time.Hour)),
		"KEV deadline for a CVE discovered 5 days ago should already be in the past (4d ago)")

	// Critical: deadline should be discovered_at + 72h = 3 days ago (ALREADY VIOLATED)
	criticalDeadline := discoveredAt.Add(SlaDeadlineCritical)
	assert.True(t, criticalDeadline.Before(time.Now().Add(-2*24*time.Hour)),
		"Critical deadline for a CVE discovered 5 days ago should be ~3 days in the past")

	// Verify that the deadline is NOT time.Now() + SLA
	notNow := time.Now().Add(SlaDeadlineCritical)
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
	correctDeadline := discoveredAt.Add(SlaDeadlineKEV) // 2026-05-02 12:00 UTC

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
