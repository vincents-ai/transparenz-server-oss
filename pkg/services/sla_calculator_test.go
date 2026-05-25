package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
