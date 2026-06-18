package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
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
