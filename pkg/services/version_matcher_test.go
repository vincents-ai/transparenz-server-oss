package services

import "testing"

func TestNormalizeVersion(t *testing.T) {
	vm := NewVersionMatcher()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"strip v prefix", "v1.2.3", "1.2.3"},
		{"strip build suffix", "1.2.3+build", "1.2.3"},
		{"no change", "1.2.3", "1.2.3"},
		{"non-semver preserved", "R30 P2", "R30 P2"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vm.normalizeVersion(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeVersion(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMatchVersion_ExactMatch(t *testing.T) {
	vm := NewVersionMatcher()

	tests := []struct {
		comp, feed string
	}{
		{"1.2.3", "1.2.3"},
		{"1.0.0", "1.0.0"},
	}

	for _, tt := range tests {
		got := vm.MatchVersion(tt.comp, tt.feed)
		if got != ExactMatch {
			t.Errorf("MatchVersion(%q, %q) = %v, want ExactMatch", tt.comp, tt.feed, got)
		}
	}
}

func TestMatchVersion_Wildcard(t *testing.T) {
	vm := NewVersionMatcher()

	tests := []struct {
		name       string
		comp, feed string
	}{
		{"star", "1.2.3", "*"},
		{"empty feed version", "1.2.3", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vm.MatchVersion(tt.comp, tt.feed)
			if got != WildcardMatch {
				t.Errorf("MatchVersion(%q, %q) = %v, want WildcardMatch", tt.comp, tt.feed, got)
			}
		})
	}
}

func TestMatchVersion_SemverRange(t *testing.T) {
	vm := NewVersionMatcher()

	tests := []struct {
		name       string
		comp, feed string
		want       VersionMatchResult
	}{
		{"within range", "1.5.0", "1.0.0 <2.0.0", RangeMatch},
		{"at lower bound", "1.0.0", "1.0.0 <2.0.0", RangeMatch},
		{"at exclusive upper", "2.0.0", "1.0.0 <2.0.0", NoMatch},
		{"below range", "0.9.0", "1.0.0 <2.0.0", NoMatch},
		{"less-than-equal within", "1.5.0", "<=2.0.0", RangeMatch},
		{"less-than-equal at bound", "2.0.0", "<=2.0.0", ExactMatch},
		{"less-than-equal above", "2.0.1", "<=2.0.0", NoMatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vm.MatchVersion(tt.comp, tt.feed)
			if got != tt.want {
				t.Errorf("MatchVersion(%q, %q) = %v, want %v", tt.comp, tt.feed, got, tt.want)
			}
		})
	}
}

func TestMatchVersion_CaseInsensitive(t *testing.T) {
	vm := NewVersionMatcher()

	got := vm.MatchVersion("V1.2.3", "v1.2.3")
	if got != ExactMatch {
		t.Errorf("MatchVersion(%q, %q) = %v, want ExactMatch", "V1.2.3", "v1.2.3", got)
	}
}

func TestMatchVersion_NoMatch(t *testing.T) {
	vm := NewVersionMatcher()

	got := vm.MatchVersion("3.0.0", "1.0.0 <2.0.0")
	if got != NoMatch {
		t.Errorf("MatchVersion(%q, %q) = %v, want NoMatch", "3.0.0", "1.0.0 <2.0.0", got)
	}
}

// TestMatchVersion_UnicodeOperators verifies that EUVD unicode comparison
// operators (≤, ≥) are normalised before version matching.
func TestMatchVersion_UnicodeOperators(t *testing.T) {
	vm := NewVersionMatcher()

	tests := []struct {
		name       string
		comp, feed string
		want       VersionMatchResult
	}{
		// "7.4.5 ≤7.4.6" → version is within the inclusive upper bound
		{"unicode ≤ within range", "7.4.5", "7.4.5 ≤7.4.6", RangeMatch},
		// At the inclusive upper bound: comp == high → ExactMatch (correctly flagged as vulnerable)
		{"unicode ≤ at upper bound", "7.4.6", "7.4.5 ≤7.4.6", ExactMatch},
		{"unicode ≤ above bound", "7.4.7", "7.4.5 ≤7.4.6", NoMatch},
		// standalone "≤1.9.0" → component at or below bound
		{"unicode standalone ≤ within", "1.8.0", "≤1.9.0", RangeMatch},
		{"unicode standalone ≤ at bound", "1.9.0", "≤1.9.0", ExactMatch},
		{"unicode standalone ≤ above", "2.0.0", "≤1.9.0", NoMatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vm.MatchVersion(tt.comp, tt.feed)
			if got != tt.want {
				t.Errorf("MatchVersion(%q, %q) = %v, want %v", tt.comp, tt.feed, got, tt.want)
			}
		})
	}
}
