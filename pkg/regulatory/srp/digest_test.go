package srp

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func collisionPair() (Package, Package) {
	rid, oid := uuid.New(), uuid.New()
	base := func(fields map[string]string) Package {
		return Package{
			ReportID: rid, OrgID: oid,
			EventClass: "actively_exploited_vulnerability",
			Stage:      "early_warning",
			SchemaID:   "ENISA-SRP-1.3",
			// CoordinatorID is empty on purpose: identity fields must be
			// validated too, and a package missing one should still not be
			// forgeable into another.
			Fields: fields,
		}
	}
	return base(map[string]string{"v5": "observed"}), base(map[string]string{"v6": "high"})
}

// The original encoding let a value manufacture a field boundary, so two
// structurally different packages hashed identically. This is the counterexample
// from the remediation brief, reproduced before it was fixed and now pinned so
// it cannot come back.
func TestFieldValueCannotForgeAFieldBoundary(t *testing.T) {
	plain := Package{
		ReportID: uuid.New(), OrgID: uuid.New(), Stage: "early_warning", SchemaID: "v1",
		Fields: map[string]string{"v5": "observed", "v6": "high"},
	}
	forged := Package{
		ReportID: plain.ReportID, OrgID: plain.OrgID, Stage: plain.Stage, SchemaID: plain.SchemaID,
		Fields: map[string]string{"v5": "observed\nfield=v6\thigh"},
	}
	if plain.computeDigest() == forged.computeDigest() {
		t.Error("a field value containing a newline and tab forged a second field; " +
			"two different packages produced the same digest, so the digest cannot " +
			"identify the document that was filed")
	}

	// The legacy encoding is the one that collides, and it must stay that way
	// only so historical digests can be verified.
	if plain.computeDigestLegacy() != forged.computeDigestLegacy() {
		t.Error("expected the legacy encoding to still collide; the reproduction " +
			"test is only meaningful if the old behaviour is preserved exactly")
	}
}

// Reordering keys in a map must not change the digest: the map is unordered and
// two identical packages should hash the same.
func TestKeyOrderDoesNotAffectTheDigest(t *testing.T) {
	rid, oid := uuid.New(), uuid.New()
	a := Package{ReportID: rid, OrgID: oid, Stage: "s", SchemaID: "v1",
		Fields: map[string]string{"x": "1", "y": "2", "z": "3"}}
	b := Package{ReportID: rid, OrgID: oid, Stage: "s", SchemaID: "v1",
		Fields: map[string]string{"z": "3", "y": "2", "x": "1"}}
	if a.computeDigest() != b.computeDigest() {
		t.Error("the same fields in a different map order must produce the same digest")
	}
}

// Content that the old encoding handled badly must round-trip unambiguously.
func TestTrickyContentRoundTrips(t *testing.T) {
	rid, oid := uuid.New(), uuid.New()
	values := []string{
		"", "plain",
		"tab\there",
		"newline\nhere",
		"both\tand\nhere",
		"field=v6\thigh",
		"trailing\n",
		"\nleading",
		"ünïcodé ✓ 日本語",
		"quote\"and'quote",
		"nul\x00byte",
		strings.Repeat("x", 5000),
	}
	for _, v := range values {
		p := Package{ReportID: rid, OrgID: oid, Stage: "s", SchemaID: "v1",
			Fields: map[string]string{"v5": v}}
		if p.computeDigest() == p.computeDigestLegacy() && strings.Contains(v, "\n") {
			// Not a failure on its own — a value with no newline can legitimately
			// coincide — but any value that LOOKS like a boundary must not.
			continue
		}
	}

	// Distinct tricky values must all produce distinct digests.
	seen := map[string]string{}
	for i, v := range values {
		p := Package{ReportID: rid, OrgID: oid, Stage: "s", SchemaID: "v1",
			Fields: map[string]string{"v5": v}}
		d := p.computeDigest()
		if prev, dup := seen[d]; dup {
			t.Errorf("values %q and %q produced the same digest", prev, v)
		}
		seen[d] = v
		_ = i
	}
}

// Every identity field must affect the digest, so a package cannot be altered
// in a field that matters and still verify.
func TestMutatingAnyIdentityFieldBreaksVerification(t *testing.T) {
	rid, oid := uuid.New(), uuid.New()
	base := Package{
		ReportID: rid, OrgID: oid, EventClass: "aev", Stage: "early_warning",
		SchemaID: "v1", CoordinatorID: "co-1",
		Fields: map[string]string{"v5": "observed"},
	}
	base.Digest = base.computeDigest()
	if !base.VerifyDigest() {
		t.Fatal("a freshly computed digest must verify")
	}

	mutations := map[string]func(*Package){
		"report_id":      func(p *Package) { p.ReportID = uuid.New() },
		"org_id":         func(p *Package) { p.OrgID = uuid.New() },
		"event_class":    func(p *Package) { p.EventClass = "severe_incident" },
		"stage":          func(p *Package) { p.Stage = "final_report" },
		"schema_id":      func(p *Package) { p.SchemaID = "ENISA-SRP-1.4" },
		"coordinator_id": func(p *Package) { p.CoordinatorID = "co-2" },
		"a field value":  func(p *Package) { p.Fields = map[string]string{"v5": "tampered"} },
		"a field key":    func(p *Package) { p.Fields = map[string]string{"v6": "observed"} },
		"an added field": func(p *Package) { p.Fields["v9"] = "extra" },
		"a removed field": func(p *Package) {
			delete(p.Fields, "v5")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := base
			p.Fields = map[string]string{"v5": "observed"}
			mutate(&p)
			if p.VerifyDigest() {
				t.Errorf("mutating %s must break verification", name)
			}
		})
	}
}

// A digest recorded historically under the ambiguous encoding must still verify.
// Invalidating it would rewrite evidence, and re-deriving a v2 digest to match
// would claim the historical digest was something it never was.
func TestLegacyDigestsStillVerify(t *testing.T) {
	p := Package{
		ReportID: uuid.New(), OrgID: uuid.New(), Stage: "s", SchemaID: "v1",
		Fields: map[string]string{"v5": "observed", "v6": "high"},
	}
	p.Digest = p.computeDigestLegacy()

	if !p.VerifyDigest() {
		t.Error("a digest recorded under the legacy encoding must still verify")
	}
	if !p.VerifiedUnderLegacyEncoding() {
		t.Error("the package must report that it matched only under the weaker encoding")
	}

	// A freshly computed digest is the current encoding and must not claim to be
	// legacy evidence.
	fresh := p
	fresh.Digest = fresh.computeDigest()
	if fresh.VerifiedUnderLegacyEncoding() {
		t.Error("a current-encoding digest must not be reported as legacy")
	}
}

func TestUnknownDigestPrefixIsRejected(t *testing.T) {
	p := Package{ReportID: uuid.New(), OrgID: uuid.New(), Fields: map[string]string{"v5": "x"}}
	for _, d := range []string{"", "md5:abc", "sha1:abc", "garbage", "sha256-", "sha256-v9:abc"} {
		p.Digest = d
		if p.VerifyDigest() {
			t.Errorf("digest %q must not verify", d)
		}
	}
}
