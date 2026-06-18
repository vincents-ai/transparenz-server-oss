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
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
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
	kevDate := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)         // exploited
	discDate := time.Date(2024, 6, 2, 12, 0, 0, 0, time.UTC)       // discovered
	expectedKEVDeadline := kevDate.Add(SlaDeadlineKEV)              // 24h after exploit
	expectedCriticalDeadline := discDate.Add(SlaDeadlineCritical)   // 72h after known

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
