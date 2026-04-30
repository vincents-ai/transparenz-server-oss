package services

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

type VersionMatchResult int

const (
	NoMatch VersionMatchResult = iota
	ExactMatch
	RangeMatch
	WildcardMatch
)

type VersionMatcher struct{}

func NewVersionMatcher() *VersionMatcher {
	return &VersionMatcher{}
}

func (vm *VersionMatcher) MatchVersion(compVersion, feedVersion string) VersionMatchResult {
	feedVersion = strings.TrimSpace(feedVersion)
	if feedVersion == "*" || feedVersion == "" {
		return WildcardMatch
	}

	compNorm := vm.normalizeVersion(compVersion)
	feedNorm := vm.normalizeVersion(feedVersion)

	if compNorm == feedNorm {
		return ExactMatch
	}

	compSemver, compErr := semver.NewVersion(compNorm)
	feedSemver, feedErr := semver.NewVersion(feedNorm)
	if compErr == nil && feedErr == nil {
		if compSemver.Equal(feedSemver) {
			return ExactMatch
		}
	}

	low, high, highInclusive, rangeErr := vm.parseSemverRange(feedVersion)
	if rangeErr == nil && compSemver != nil {
		if low != nil && compSemver.LessThan(low) {
			return NoMatch
		}
		if high != nil {
			if highInclusive {
				// inclusive: comp > high is a no-match; comp == high is ExactMatch
				if compSemver.GreaterThan(high) {
					return NoMatch
				}
				if compSemver.Equal(high) {
					return ExactMatch
				}
			} else {
				// exclusive: comp >= high is a no-match
				if !compSemver.LessThan(high) {
					return NoMatch
				}
			}
		}
		if low != nil || high != nil {
			return RangeMatch
		}
	}

	return NoMatch
}

// parseSemverRange parses a version range string and returns (low, high, highInclusive, err).
// highInclusive is true when the upper bound operator is <= (or ≤).
func (vm *VersionMatcher) parseSemverRange(rangeStr string) (low, high *semver.Version, highInclusive bool, err error) {
	rangeStr = strings.TrimSpace(rangeStr)
	if rangeStr == "" || rangeStr == "*" {
		return nil, nil, false, nil
	}

	// Normalise unicode comparison operators used by EUVD (e.g. "7.4.5 ≤7.4.6")
	rangeStr = strings.ReplaceAll(rangeStr, "≤", "<=")
	rangeStr = strings.ReplaceAll(rangeStr, "≥", ">=")
	rangeStr = strings.ReplaceAll(rangeStr, "≠", "!=")

	// Two-part range: "low <high" or "low <=high"
	if strings.Contains(rangeStr, "<") {
		parts := strings.Fields(rangeStr)
		if len(parts) == 2 {
			lowStr := vm.normalizeVersion(parts[0])
			inclusive := strings.HasPrefix(parts[1], "<=")
			highStr := vm.normalizeVersion(parts[1])
			low, err = semver.NewVersion(lowStr)
			if err != nil {
				return nil, nil, false, err
			}
			high, err = semver.NewVersion(highStr)
			if err != nil {
				return nil, nil, false, err
			}
			return low, high, inclusive, nil
		}
	}

	if strings.HasPrefix(rangeStr, "<=") {
		v, e := semver.NewVersion(vm.normalizeVersion(rangeStr[2:]))
		if e != nil {
			return nil, nil, false, e
		}
		return nil, v, true, nil
	}

	if strings.HasPrefix(rangeStr, ">=") {
		v, e := semver.NewVersion(vm.normalizeVersion(rangeStr[2:]))
		if e != nil {
			return nil, nil, false, e
		}
		return v, nil, false, nil
	}

	if strings.HasPrefix(rangeStr, "<") {
		v, e := semver.NewVersion(vm.normalizeVersion(rangeStr[1:]))
		if e != nil {
			return nil, nil, false, e
		}
		return nil, v, false, nil
	}

	if strings.HasPrefix(rangeStr, ">") {
		v, e := semver.NewVersion(vm.normalizeVersion(rangeStr[1:]))
		if e != nil {
			return nil, nil, false, e
		}
		return v, nil, false, nil
	}

	return nil, nil, false, nil
}

func (vm *VersionMatcher) normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V") {
		if idx := strings.IndexAny(v, ".0123456789"); idx > 0 && idx <= 1 {
			v = v[idx:]
		}
	}
	if idx := strings.Index(v, "+"); idx != -1 {
		v = v[:idx]
	}
	for _, prefix := range []string{"=", ">=", "<=", ">", "<"} {
		if strings.HasPrefix(v, prefix) {
			v = strings.TrimSpace(v[len(prefix):])
			break
		}
	}
	return strings.TrimSpace(v)
}
