package services

import (
	"math"
	"testing"
)

func TestNormalizeMetadata(t *testing.T) {
	n := NewSeverityNormalizer()
	for _, tc := range []struct{ enisa, bsi, want string }{
		{"", "", "unknown"}, {"High", "", "high"}, {"", "hoch", "high"},
		{"unknown", " KRITISCH ", "critical"},
	} {
		score, severity := n.NormalizeMetadata(nil, tc.enisa, tc.bsi)
		if score != nil || severity != tc.want {
			t.Fatalf("missing score fabricated or severity lost: %v %s", score, severity)
		}
	}
	for _, v := range []float64{0, 4.2, 9.8, 10} {
		score, _ := n.NormalizeMetadata(&v, "", "")
		if score == nil || *score != v {
			t.Fatal("valid numeric score lost")
		}
	}
	for _, v := range []float64{-1, 11, math.NaN(), math.Inf(1)} {
		score, _ := n.NormalizeMetadata(&v, "", "")
		if score != nil {
			t.Fatal("invalid score retained")
		}
	}
}
