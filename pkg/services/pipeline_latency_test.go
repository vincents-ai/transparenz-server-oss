package services

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// PipelineLatency tracks timing through the vulnerability disclosure pipeline.
// The pipeline stages are:
//
//   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
//   │  1. Feed     │────▶│  2. Match    │────▶│  3. SLA      │────▶│  4. Alert    │────▶│  5. Disclose │
//   │  Ingest      │     │  (Scan)      │     │  Calculate   │     │  (AlertSvc)  │     │  (ENISA)     │
//   └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
//        T0                  T1                  T2                   T3                   T4
//
// Key metrics:
//
//	Feed→Report: T4 - T0  (end-to-end: CVE published → visible in dashboard)
//	Feed→Match:  T1 - T0  (feed synced → vulnerability linked to SBOM component)
//	Match→SLA:   T2 - T1  (vulnerability known → SLA deadline set)
//	SLA→Alert:   T3 - T2  (deadline set → operator notified)
//	Alert→Report: T4 - T3  (notification → disclosure/ENISA report filed)
//
// The SLA clock starts at T0 (CVE published date), NOT at T2 (when we calculate it).
// This is critical: if Feed→SLA takes 6h and the SLA is 72h, the operator only has
// 66h remaining. This is the "hidden latency" we're measuring.
type PipelineLatency struct {
	FeedIngestedAt   time.Time `json:"feed_ingested_at"`
	VulnMatchedAt    time.Time `json:"vuln_matched_at"`
	SLACalculatedAt  time.Time `json:"sla_calculated_at"`
	AlertSentAt      time.Time `json:"alert_sent_at"`
	DisclosedAt      time.Time `json:"disclosed_at"`
	CVEPublishedDate time.Time `json:"cve_published_date"`
}

// FeedToReport returns end-to-end latency.
func (p PipelineLatency) FeedToReport() time.Duration {
	if p.DisclosedAt.IsZero() {
		return 0
	}
	return p.DisclosedAt.Sub(p.FeedIngestedAt)
}

// FeedToMatch returns the time from feed ingestion to vulnerability matching.
func (p PipelineLatency) FeedToMatch() time.Duration {
	if p.VulnMatchedAt.IsZero() {
		return 0
	}
	return p.VulnMatchedAt.Sub(p.FeedIngestedAt)
}

// MatchToSLA returns the time from matching to SLA calculation.
func (p PipelineLatency) MatchToSLA() time.Duration {
	if p.SLACalculatedAt.IsZero() {
		return 0
	}
	return p.SLACalculatedAt.Sub(p.VulnMatchedAt)
}

// SLAToAlert returns the time from SLA calculation to alert sent.
func (p PipelineLatency) SLAToAlert() time.Duration {
	if p.AlertSentAt.IsZero() {
		return 0
	}
	return p.AlertSentAt.Sub(p.SLACalculatedAt)
}

// HiddenSLAErosion returns how much SLA time is consumed by pipeline latency.
// This is the difference between the nominal SLA and what the operator actually gets.
func (p PipelineLatency) HiddenSLAErosion() time.Duration {
	if p.SLACalculatedAt.IsZero() || p.CVEPublishedDate.IsZero() {
		return 0
	}
	return p.SLACalculatedAt.Sub(p.CVEPublishedDate)
}

// PipelineLatencyCollector collects latency measurements from multiple pipeline runs.
type PipelineLatencyCollector struct {
	Measurements []PipelineLatency `json:"measurements"`
}

func NewPipelineLatencyCollector() *PipelineLatencyCollector {
	return &PipelineLatencyCollector{}
}

func (c *PipelineLatencyCollector) Record(p PipelineLatency) {
	c.Measurements = append(c.Measurements, p)
}

// Summary returns aggregate statistics for the collected measurements.
func (c *PipelineLatencyCollector) Summary() PipelineSummary {
	if len(c.Measurements) == 0 {
		return PipelineSummary{}
	}

	var totalFeedMatch, totalMatchSLA, totalSLAAlert, totalFeedReport, totalHiddenErosion time.Duration
	var maxFeedMatch, maxMatchSLA, maxSLAAlert, maxFeedReport, maxHiddenErosion time.Duration

	for _, m := range c.Measurements {
		fm := m.FeedToMatch()
		ms := m.MatchToSLA()
		sa := m.SLAToAlert()
		fr := m.FeedToReport()
		he := m.HiddenSLAErosion()

		totalFeedMatch += fm
		totalMatchSLA += ms
		totalSLAAlert += sa
		totalFeedReport += fr
		totalHiddenErosion += he

		if fm > maxFeedMatch {
			maxFeedMatch = fm
		}
		if ms > maxMatchSLA {
			maxMatchSLA = ms
		}
		if sa > maxSLAAlert {
			maxSLAAlert = sa
		}
		if fr > maxFeedReport {
			maxFeedReport = fr
		}
		if he > maxHiddenErosion {
			maxHiddenErosion = he
		}
	}

	n := time.Duration(len(c.Measurements))
	return PipelineSummary{
		SampleCount:      len(c.Measurements),
		AvgFeedToMatch:   totalFeedMatch / n,
		MaxFeedToMatch:   maxFeedMatch,
		AvgMatchToSLA:    totalMatchSLA / n,
		MaxMatchToSLA:    maxMatchSLA,
		AvgSLAToAlert:    totalSLAAlert / n,
		MaxSLAToAlert:    maxSLAAlert,
		AvgFeedToReport:  totalFeedReport / n,
		MaxFeedToReport:  maxFeedReport,
		AvgHiddenErosion: totalHiddenErosion / n,
		MaxHiddenErosion: maxHiddenErosion,
	}
}

// PipelineSummary contains aggregate pipeline latency statistics.
type PipelineSummary struct {
	SampleCount      int           `json:"sample_count"`
	AvgFeedToMatch   time.Duration `json:"avg_feed_to_match"`
	MaxFeedToMatch   time.Duration `json:"max_feed_to_match"`
	AvgMatchToSLA    time.Duration `json:"avg_match_to_sla"`
	MaxMatchToSLA    time.Duration `json:"max_match_to_sla"`
	AvgSLAToAlert    time.Duration `json:"avg_sla_to_alert"`
	MaxSLAToAlert    time.Duration `json:"max_sla_to_alert"`
	AvgFeedToReport  time.Duration `json:"avg_feed_to_report"`
	MaxFeedToReport  time.Duration `json:"max_feed_to_report"`
	AvgHiddenErosion time.Duration `json:"avg_hidden_erosion"`
	MaxHiddenErosion time.Duration `json:"max_hidden_erosion"`
}

func (s PipelineSummary) String() string {
	return fmt.Sprintf(
		"Pipeline Summary (n=%d):\n"+
			"  Feed→Match:   avg=%s  max=%s\n"+
			"  Match→SLA:    avg=%s  max=%s\n"+
			"  SLA→Alert:    avg=%s  max=%s\n"+
			"  Feed→Report:  avg=%s  max=%s\n"+
			"  Hidden SLA erosion:  avg=%s  max=%s",
		s.SampleCount,
		s.AvgFeedToMatch, s.MaxFeedToMatch,
		s.AvgMatchToSLA, s.MaxMatchToSLA,
		s.AvgSLAToAlert, s.MaxSLAToAlert,
		s.AvgFeedToReport, s.MaxFeedToReport,
		s.AvgHiddenErosion, s.MaxHiddenErosion,
	)
}

// =============================================================================
// Tests
// =============================================================================

// TestPipelineLatencyCollection verifies that the latency measurement
// infrastructure correctly records and summarizes pipeline stages.
func TestPipelineLatencyCollection(t *testing.T) {
	collector := NewPipelineLatencyCollector()
	now := time.Now()

	// Record 3 pipeline runs with different latencies
	collector.Record(PipelineLatency{
		FeedIngestedAt:   now,
		VulnMatchedAt:    now.Add(2 * time.Second),
		SLACalculatedAt:  now.Add(5 * time.Second),
		AlertSentAt:      now.Add(6 * time.Second),
		DisclosedAt:      now.Add(10 * time.Second),
		CVEPublishedDate: now.Add(-24 * time.Hour),
	})

	collector.Record(PipelineLatency{
		FeedIngestedAt:   now,
		VulnMatchedAt:    now.Add(4 * time.Second),
		SLACalculatedAt:  now.Add(8 * time.Second),
		AlertSentAt:      now.Add(9 * time.Second),
		DisclosedAt:      now.Add(15 * time.Second),
		CVEPublishedDate: now.Add(-48 * time.Hour),
	})

	collector.Record(PipelineLatency{
		FeedIngestedAt:   now,
		VulnMatchedAt:    now.Add(1 * time.Second),
		SLACalculatedAt:  now.Add(3 * time.Second),
		AlertSentAt:      now.Add(4 * time.Second),
		DisclosedAt:      now.Add(7 * time.Second),
		CVEPublishedDate: now.Add(-12 * time.Hour),
	})

	summary := collector.Summary()

	assert.Equal(t, 3, summary.SampleCount)

	// Feed→Match: avg=(2+4+1)/3=2.33s, max=4s
	assert.Equal(t, 2333*time.Millisecond, summary.AvgFeedToMatch.Round(time.Millisecond))
	assert.Equal(t, 4*time.Second, summary.MaxFeedToMatch)

	// Match→SLA: avg=(3+4+2)/3=3s, max=4s
	assert.Equal(t, 3*time.Second, summary.AvgMatchToSLA)
	assert.Equal(t, 4*time.Second, summary.MaxMatchToSLA)

	// Feed→Report: avg=(10+15+7)/3=10.667s, max=15s
	assert.Equal(t, 10667*time.Millisecond, summary.AvgFeedToReport.Round(time.Millisecond))
	assert.Equal(t, 15*time.Second, summary.MaxFeedToReport)

	t.Log(summary.String())
}

// TestPipelineLatencyZeros verifies that zero timestamps don't cause panics.
func TestPipelineLatencyZeros(t *testing.T) {
	p := PipelineLatency{}
	assert.Equal(t, time.Duration(0), p.FeedToReport())
	assert.Equal(t, time.Duration(0), p.FeedToMatch())
	assert.Equal(t, time.Duration(0), p.MatchToSLA())
	assert.Equal(t, time.Duration(0), p.SLAToAlert())
	assert.Equal(t, time.Duration(0), p.HiddenSLAErosion())
}

// TestHiddenSLAErosion verifies the "hidden latency" calculation.
// This is the critical metric: how much SLA time does the pipeline consume
// before the operator even sees the vulnerability.
//
// Example:
//
//	CVE published:    T0 (Monday 09:00)
//	Feed ingested:    T0+1h (Monday 10:00)
//	Vuln matched:     T0+2h (Monday 11:00)
//	SLA calculated:   T0+3h (Monday 12:00)  ← HiddenSLAErosion = 3h
//	SLA deadline:     T0+72h (Thursday 09:00)
//	Operator sees:    T0+3h with 69h remaining (not 72h)
func TestHiddenSLAErosion(t *testing.T) {
	cvePublished := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)

	p := PipelineLatency{
		CVEPublishedDate: cvePublished,
		FeedIngestedAt:   cvePublished.Add(1 * time.Hour),
		VulnMatchedAt:    cvePublished.Add(2 * time.Hour),
		SLACalculatedAt:  cvePublished.Add(3 * time.Hour),
		AlertSentAt:      cvePublished.Add(3*time.Hour + 30*time.Minute),
	}

	erosion := p.HiddenSLAErosion()
	assert.Equal(t, 3*time.Hour, erosion)
	t.Logf("Hidden SLA erosion: %v (operator loses this much of the SLA window)", erosion)
}

// TestSLADeadlineWithErosion simulates the full deadline calculation.
func TestSLADeadlineWithErosion(t *testing.T) {
	cvePublished := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	slaNominal := 72 * time.Hour

	pipelineErosion := PipelineLatency{
		CVEPublishedDate: cvePublished,
		FeedIngestedAt:   cvePublished.Add(30 * time.Minute),
		VulnMatchedAt:    cvePublished.Add(45 * time.Minute),
		SLACalculatedAt:  cvePublished.Add(1 * time.Hour),
		AlertSentAt:      cvePublished.Add(1*time.Hour + 5*time.Minute),
	}

	erosion := pipelineErosion.HiddenSLAErosion()
	remainingForOperator := slaNominal - erosion

	assert.Equal(t, 1*time.Hour, erosion)
	assert.Equal(t, 71*time.Hour, remainingForOperator)

	t.Logf("Nominal SLA:      %v", slaNominal)
	t.Logf("Pipeline erosion: %v", erosion)
	t.Logf("Operator gets:    %v remaining", remainingForOperator)
}

// TestENISAExhaustion verifies SLA exhaustion scenarios from ENISA recommendations.
// ENISA coordinated vulnerability disclosure guidelines specify:
//   - 72h for critical severity (CISA BOD 22-01 / EU NIS2)
//   - 7 days for high severity
//   - 30 days for medium severity
//   - 90 days for low severity
//
// The pipeline MUST NOT consume more than 10% of the SLA window.
// If it does, operators cannot meet their regulatory obligations.
func TestENISAExhaustion(t *testing.T) {
	scenarios := []struct {
		name          string
		severity      string
		slaWindow     time.Duration
		maxErosionPct float64 // max % of SLA the pipeline may consume
	}{
		{"Critical (72h SLA)", "critical", 72 * time.Hour, 0.10},
		{"High (7d SLA)", "high", 7 * 24 * time.Hour, 0.10},
		{"Medium (30d SLA)", "medium", 30 * 24 * time.Hour, 0.10},
		{"Low (90d SLA)", "low", 90 * 24 * time.Hour, 0.10},
	}

	// Simulate pipeline stages with realistic timings.
	// Commercial (15m sync + auto-rescan):
	commericalStages := PipelineLatency{
		FeedIngestedAt:  time.Now(),
		VulnMatchedAt:   time.Now().Add(15 * time.Minute),   // commercial: 15m sync + auto-rescan
		SLACalculatedAt: time.Now().Add(15*time.Minute + 1*time.Minute),
		AlertSentAt:     time.Now().Add(15*time.Minute + 90*time.Second),
	}

	// OSS (6h sync, manual scan):
	ossStages := PipelineLatency{
		FeedIngestedAt:  time.Now(),
		VulnMatchedAt:   time.Now().Add(6 * time.Hour),
		SLACalculatedAt: time.Now().Add(6*time.Hour + 5*time.Minute),
		AlertSentAt:     time.Now().Add(6*time.Hour + 10*time.Minute),
	}

	configs := []struct {
		name    string
		stages  PipelineLatency
	}{
		{"Commercial (15m)", commericalStages},
		{"OSS (6h)", ossStages},
	}

	for _, tc := range scenarios {
		for _, cfg := range configs {
			t.Run(tc.name+"/"+cfg.name, func(t *testing.T) {
				stages := cfg.stages
				stages.CVEPublishedDate = stages.FeedIngestedAt.Add(-1 * time.Second)

				erosion := stages.HiddenSLAErosion()
				erosionPct := float64(erosion) / float64(tc.slaWindow)

				maxAllowed := time.Duration(float64(tc.slaWindow) * tc.maxErosionPct)

				t.Logf("%s %s: erosion=%v (%.1f%% of %v SLA)",
					tc.name, cfg.name, erosion, erosionPct*100, tc.slaWindow)

				assert.LessOrEqualf(t, erosion, maxAllowed,
					"Pipeline erosion (%v) exceeds %.0f%% of %s SLA (%v). "+
						"Operators cannot meet ENISA/NIS2 deadlines.",
					erosion, tc.maxErosionPct*100, tc.name, maxAllowed)
			})
		}
	}
}

// TestFeedSyncIntervals documents the expected sync intervals
// and their impact on pipeline latency.
//
// FINDING: For critical (72h) SLA compliance under ENISA/NIS2:
//   - 15m sync (commercial): 0.4% erosion ✓ (recommended)
//   - 1h sync: 1.6% erosion ✓
//   - 6h sync (OSS): 8.6% erosion ✓ (near the 10% limit)
//   - 12h sync: 16.9% erosion ✗ (EXCEEDS 10% threshold)
//   - 24h sync: 33.6% erosion ✗ (VIOLATES critical SLA)
//
// Commercial default: 15m with auto-rescan enabled.
// OSS default: 6h (manual scan trigger).
func TestFeedSyncIntervals(t *testing.T) {
	intervals := []struct {
		name           string
		interval       time.Duration
		shouldPass10pc bool // whether it should pass the 10% threshold
	}{
		{"15m sync (commercial)", 15 * time.Minute, true},
		{"1h sync", 1 * time.Hour, true},
		{"6h sync (OSS)", 6 * time.Hour, true},
		{"12h sync", 12 * time.Hour, false}, // exceeds 10% — documented limit
		{"24h sync", 24 * time.Hour, false}, // exceeds 10% — documented limit
	}

	criticalSLA := 72 * time.Hour

	for _, tc := range intervals {
		t.Run(tc.name, func(t *testing.T) {
			// Worst case: CVE arrives right after a sync
			worstCaseErosion := tc.interval + 10*time.Minute // sync + scan + SLA calc
			pct := float64(worstCaseErosion) / float64(criticalSLA) * 100

			t.Logf("Interval=%v  worst-case erosion=%v (%.1f%% of 72h SLA)",
				tc.interval, worstCaseErosion, pct)

			// For critical (72h) SLA, the pipeline must not consume >10%
			if tc.shouldPass10pc {
				assert.Lessf(t, pct, 10.0,
					"Sync interval %v consumes %.1f%% of 72h SLA. "+
						"Reduce sync interval or optimize pipeline stages.",
					tc.interval, pct)
			} else {
				// Document that this interval exceeds the threshold
				t.Logf("WARNING: %s consumes %.1f%% of 72h SLA (exceeds 10%% threshold). "+
					"Not recommended for critical severity.", tc.name, pct)
			}
		})
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

// BenchmarkPipelineLatencySummary benchmarks the summary calculation.
func BenchmarkPipelineLatencySummary(b *testing.B) {
	collector := NewPipelineLatencyCollector()
	now := time.Now()
	for i := 0; i < 1000; i++ {
		collector.Record(PipelineLatency{
			FeedIngestedAt:   now,
			VulnMatchedAt:    now.Add(time.Duration(i) * time.Millisecond),
			SLACalculatedAt:  now.Add(time.Duration(i*2) * time.Millisecond),
			AlertSentAt:      now.Add(time.Duration(i*3) * time.Millisecond),
			DisclosedAt:      now.Add(time.Duration(i*4) * time.Millisecond),
			CVEPublishedDate: now.Add(-time.Hour),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.Summary()
	}
}

// Ensure unused imports don't fail compilation
var _ = json.Marshal
var _ = zap.NewNop
