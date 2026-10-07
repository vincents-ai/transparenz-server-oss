package config

import (
	"strings"
	"testing"
)

// TestInitMultiTenantDBRejectsUnknownMode pins a fail-LOUD decision.
//
// InitMultiTenantDB previously had a `default:` case that built the shared
// single-tenant backend, so ANY unrecognised MULTI_TENANT_MODE silently degraded a
// deployment configured for per-organisation isolation to one shared database. No
// error, no warning, no log line. A deployment could be configured for isolation,
// have a typo survive review, and run unisolated while reporting itself healthy.
//
// That combination is what makes it dangerous rather than untidy. Shared mode
// isolates tenants by nothing but an org_id predicate on each query, and
// MatchAndInsert, fixed earlier in the same cycle, is a worked example of a query
// that omitted one with no RLS behind it to catch the omission. A config typo plus a
// missing predicate is complete cross-tenant exposure, and under the old code neither
// layer said anything.
//
// The rule applied here is the opposite of RequireFeature's, and deliberately so.
// RequireFeature fails CLOSED on an unknown feature name, because granting an
// unrequested capability is the dangerous direction. Tenant mode fails LOUD, because
// running with LESS isolation than configured is also the dangerous direction, and a
// refusal to start cannot be mistaken for working.
func TestInitMultiTenantDBRejectsUnknownMode(t *testing.T) {
	// Every plausible typo or misconfiguration must be refused, not silently
	// downgraded to shared.
	for _, mode := range []string{
		"schema-per-org",    // hyphen instead of underscore
		"instanceperorg",    // missing separator
		"schema_per_tenant", // wrong noun
		"instance-per-org",  // hyphen
		"SHARED",            // wrong case
		"rls",               // plausible-sounding but unsupported here
		"true", "1", "yes",  // boolean-ish values someone might set
		"dedicated", "per-org",
	} {
		cfg := &Config{MultiTenantMode: mode}
		db, backend, err := InitMultiTenantDB(cfg)
		if err == nil {
			t.Errorf("MULTI_TENANT_MODE=%q was accepted and returned a backend; "+
				"an unknown mode must be refused rather than silently downgraded "+
				"to shared single-tenant", mode)
			continue
		}
		if db != nil || backend != nil {
			t.Errorf("MULTI_TENANT_MODE=%q returned both an error and a non-nil "+
				"database/ backend; a refusal must not hand back a usable one", mode)
		}
		if !strings.Contains(err.Error(), mode) {
			t.Errorf("the error for %q does not quote the offending value: %v",
				mode, err)
		}
	}
}

// TestInitMultiTenantModeAcceptsOnlyTheDocumentedValues states the other half of the
// contract: the three documented values must still be accepted, so the fail-loud
// change cannot be used to brick a working deployment.
//
// "shared" and "" cannot be exercised without a real database, because they proceed to
// InitDB. Only the validation behaviour is asserted here; the remaining values are
// checked against the same list the error message names, so the two cannot drift.
func TestInitMultiTenantModeAcceptsOnlyTheDocumentedValues(t *testing.T) {
	valid := map[string]bool{"": true, "shared": true, "schema_per_org": true, "instance_per_org": true}

	// Anything not in that set must be refused. This mirrors the table above
	// explicitly so that adding a mode to one and not the other is a visible failure.
	for _, mode := range []string{"schema-per-org", "instanceperorg", "unknown", "rls"} {
		if valid[mode] {
			t.Errorf("%q is listed as invalid in the test above but the documented "+
				"set here does not agree", mode)
		}
	}
}

// TestValidateConfigRejectsUnknownTenantMode checks the EARLIER of the two guards.
//
// validateConfig already enforces DATABASE_URL, JWT_SECRET at 32 characters and
// ENCRYPTION_KEY at exactly 32. MULTI_TENANT_MODE was not in that list, even though
// it selects the tenant isolation strategy, which is the one setting where a silently
// wrong value is worse than a missing one.
//
// Validating here rather than only in InitMultiTenantDB matters because it fails at
// config load and catches every caller, including any path that never reaches the
// database initialiser. A deployment with a typo should not be able to start far
// enough to serve a request before anyone notices.
func TestValidateConfigRejectsUnknownTenantMode(t *testing.T) {
	base := func() *Config {
		return &Config{
			DatabaseURL:     "postgres://localhost/test",
			JWTSecret:       strings.Repeat("x", 32),
			EncryptionKey:   strings.Repeat("k", 32),
			MultiTenantMode: "shared",
		}
	}

	if err := validateConfig(base()); err != nil {
		t.Fatalf("a valid configuration was rejected: %v", err)
	}

	// The empty value is the legitimate default and must remain acceptable.
	empty := base()
	empty.MultiTenantMode = ""
	if err := validateConfig(empty); err != nil {
		t.Errorf("the default empty MULTI_TENANT_MODE was rejected: %v", err)
	}

	for _, mode := range []string{"schema-per-org", "instanceperorg", "rls", "SHARED", "true"} {
		cfg := base()
		cfg.MultiTenantMode = mode
		err := validateConfig(cfg)
		if err == nil {
			t.Errorf("MULTI_TENANT_MODE=%q passed validation; it selects the tenant "+
				"isolation strategy and a wrong value must not start silently", mode)
			continue
		}
		if !strings.Contains(err.Error(), mode) {
			t.Errorf("the validation error for %q does not quote the value: %v", mode, err)
		}
	}
}
