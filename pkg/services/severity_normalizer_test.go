// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"math"
	"testing"
)

func ptr(f float64) *float64 { return &f }

// ---------------------------------------------------------------------------
// scoreToSeverity
// ---------------------------------------------------------------------------

func TestScoreToSeverity(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		expected string
	}{
		{"zero", 0.0, "unknown"},
		{"low boundary 0.1", 0.1, "low"},
		{"low midpoint", 1.5, "low"},
		{"low top 3.9", 3.9, "low"},
		{"medium boundary 4.0", 4.0, "medium"},
		{"medium midpoint", 6.0, "medium"},
		{"medium top 6.9", 6.9, "medium"},
		{"high boundary 7.0", 7.0, "high"},
		{"high midpoint", 8.0, "high"},
		{"high top 8.9", 8.9, "high"},
		{"critical boundary 9.0", 9.0, "critical"},
		{"critical 9.5", 9.5, "critical"},
		{"critical max 10.0", 10.0, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreToSeverity(tt.score)
			if got != tt.expected {
				t.Errorf("scoreToSeverity(%v) = %q, want %q", tt.score, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// severityToScore
// ---------------------------------------------------------------------------

func TestSeverityToScore(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"critical", 10.0},
		{"Critical", 10.0}, // case-insensitive
		{"High", 8.0},
		{"high", 8.0},
		{"Medium", 5.0},
		{"medium", 5.0},
		{"Low", 2.0},
		{"low", 2.0},
		{"unknown", 0.0},
		{"", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := severityToScore(tt.severity)
			if math.Abs(got-tt.expected) > 1e-9 {
				t.Errorf("severityToScore(%q) = %v, want %v", tt.severity, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// mapBSISeverity
// ---------------------------------------------------------------------------

func TestMapBSISeverity(t *testing.T) {
	tests := []struct {
		de       string
		expected string
	}{
		{"kritisch", "critical"},
		{"hoch", "high"},
		{"mittel", "medium"},
		{"niedrig", "low"},
		{"unbekannt", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.de, func(t *testing.T) {
			got := mapBSISeverity(tt.de)
			if got != tt.expected {
				t.Errorf("mapBSISeverity(%q) = %q, want %q", tt.de, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SeverityNormalizer.Normalize
// ---------------------------------------------------------------------------

func TestSeverityNormalizer_Normalize_BaseScore(t *testing.T) {
	sn := NewSeverityNormalizer()

	tests := []struct {
		name          string
		score         *float64
		enisa         string
		bsi           string
		expectedScore float64
		expectedSev   string
	}{
		{"nil score uses enisa", nil, "High", "", 8.0, "high"},
		{"nil score uses bsi when enisa empty", nil, "", "hoch", 8.0, "high"},
		{"nil score falls through to unknown", nil, "", "", 0.0, "unknown"},
		{"zero score uses enisa", ptr(0.0), "Medium", "", 5.0, "medium"},
		{"positive score overrides everything", ptr(9.5), "Low", "niedrig", 9.5, "critical"},
		{"score 7.5 → high", ptr(7.5), "", "", 7.5, "high"},
		{"score 4.0 → medium", ptr(4.0), "", "", 4.0, "medium"},
		{"score 0.1 → low", ptr(0.1), "", "", 0.1, "low"},
		{"score 10.0 → critical", ptr(10.0), "", "", 10.0, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScore, gotSev := sn.Normalize(tt.score, tt.enisa, tt.bsi)
			if math.Abs(gotScore-tt.expectedScore) > 1e-9 {
				t.Errorf("score: got %v, want %v", gotScore, tt.expectedScore)
			}
			if gotSev != tt.expectedSev {
				t.Errorf("severity: got %q, want %q", gotSev, tt.expectedSev)
			}
		})
	}
}

// TestSeverityNormalizer_Monotonic verifies that for any pair of scores
// s1 < s2, the resulting severity label is either equal to or "higher" than
// the one produced by s1 (i.e. the function is non-decreasing).
func TestSeverityNormalizer_Monotonic(t *testing.T) {
	sn := NewSeverityNormalizer()

	// Define an ordinal rank for the severity labels.
	rank := map[string]int{
		"unknown":  0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	scores := []float64{0.0, 0.1, 1.0, 2.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 9.5, 10.0}

	for i := 0; i < len(scores)-1; i++ {
		s1 := scores[i]
		s2 := scores[i+1]

		_, sev1 := sn.Normalize(ptr(s1), "", "")
		_, sev2 := sn.Normalize(ptr(s2), "", "")

		r1, ok1 := rank[sev1]
		r2, ok2 := rank[sev2]
		if !ok1 || !ok2 {
			t.Errorf("unknown severity label at scores %.1f→%q / %.1f→%q", s1, sev1, s2, sev2)
			continue
		}
		if r2 < r1 {
			t.Errorf("non-monotonic: score %.1f→%q (rank %d) > score %.1f→%q (rank %d)",
				s2, sev2, r2, s1, sev1, r1)
		}
	}
}

func TestSeverityNormalizer_BSITakesPrecedenceOverEmpty(t *testing.T) {
	sn := NewSeverityNormalizer()

	// When both enisa and bsi are set but baseScore is nil/zero,
	// enisa takes precedence over bsi.
	gotScore, gotSev := sn.Normalize(nil, "Critical", "niedrig")
	if gotSev != "critical" {
		t.Errorf("expected enisa to take precedence, got %q", gotSev)
	}
	if math.Abs(gotScore-10.0) > 1e-9 {
		t.Errorf("expected score 10.0, got %v", gotScore)
	}
}
