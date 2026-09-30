package services

import "testing"

// Two components affected by the same CVE are two separate exposures. The
// matcher used to deduplicate on the CVE alone, so the second component
// disappeared from the result entirely — the single worst outcome for exposure
// tracking, because the report then reads as though that component is clean.
//
// These tests pin the key that fixes it. The loop-level behaviour needs a live
// database and is exercised by the integration and BDD suites; what is
// verified here is the property the loop relies on.
func TestExposureKeyDistinguishesComponentsSharingACVE(t *testing.T) {
	const cve = "CVE-2026-1234"

	a := SBOMComponent{Name: "libfoo", Version: "1.0", Type: "library"}
	b := SBOMComponent{Name: "libbar", Version: "2.0", Type: "library"}

	if exposureKey(cve, a) == exposureKey(cve, b) {
		t.Fatal("two different components affected by the same CVE must not share " +
			"an exposure key, or one of them is silently dropped from the result")
	}
}

func TestExposureKeyDistinguishesSameNameDifferentVersion(t *testing.T) {
	const cve = "CVE-2026-1234"
	old := SBOMComponent{Name: "openssl", Version: "1.0.0", Type: "library"}
	fixed := SBOMComponent{Name: "openssl", Version: "3.0.0", Type: "library"}

	if exposureKey(cve, old) == exposureKey(cve, fixed) {
		t.Error("a fix shipped for one version is not a fix for another; " +
			"components differing only in version are distinct exposures")
	}
}

func TestExposureKeyDistinguishesSameNameDifferentEcosystem(t *testing.T) {
	const cve = "CVE-2026-1234"
	npm := SBOMComponent{Name: "glob", Version: "7.0.0", Type: "npm"}
	maven := SBOMComponent{Name: "glob", Version: "7.0.0", Type: "maven"}

	if exposureKey(cve, npm) == exposureKey(cve, maven) {
		t.Error("components sharing a name and version but in different ecosystems " +
			"are different products and must not be merged")
	}
}

func TestExposureKeyIsStableForTheSameComponent(t *testing.T) {
	// A component is reached through several lookup names — its own name and
	// names derived from its PURL — so the same CVE can be found more than once
	// for one component. Those duplicate observations must collapse, or the
	// result gains phantom rows.
	cve := "CVE-2026-1234"
	comp := SBOMComponent{Name: "openssl", Version: "3.0.0", Type: "library"}

	first := exposureKey(cve, comp)
	second := exposureKey(cve, comp)
	if first != second {
		t.Error("the same component and CVE must produce the same key so repeated " +
			"observations of one relationship merge rather than duplicating")
	}
}

func TestExposureKeyCannotCollideAcrossFieldBoundaries(t *testing.T) {
	// Without a separator, ("a", "bc") and ("ab", "c") would produce the same
	// string. A NUL separator is used precisely to prevent that.
	a := SBOMComponent{Name: "a", Version: "bc", Type: "library"}
	b := SBOMComponent{Name: "ab", Version: "c", Type: "library"}
	if exposureKey("CVE-2026-1234", a) == exposureKey("CVE-2026-1234", b) {
		t.Error("field boundaries are not preserved; two distinct components " +
			"concatenated to the same key")
	}
}
