// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package services

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
)

var resolverNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

type fixture struct {
	resolver *ExposureResolver
	db       *gorm.DB
	orgID    uuid.UUID
	vulnID   uuid.UUID
	cve      string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := testutil.SetupTestDB(t,
		"organizations", "vulnerabilities", "scans", "scan_vulnerabilities",
		"sbom_uploads", "vex_statements")

	orgID := uuid.New()
	vulnID := uuid.New()
	require.NoError(t, db.Create(&models.Organization{ID: orgID, Name: "Acme", Slug: "acme"}).Error)
	require.NoError(t, db.Create(&models.Vulnerability{
		ID:        vulnID,
		OrgID:     orgID,
		Cve:       "CVE-2026-31337",
		Severity:  "critical",
		UpdatedAt: resolverNow,
	}).Error)

	return &fixture{
		resolver: &ExposureResolver{
			db:     db,
			logger: zap.NewNop(),
			clock:  func() time.Time { return resolverNow },
		},
		db: db, orgID: orgID, vulnID: vulnID, cve: "CVE-2026-31337",
	}
}

// ship inserts an SBOM, a scan of it, and a component match — the evidence
// that a product contained a third-party component at a point in time.
func (f *fixture) ship(t *testing.T, filename, sha, component, version string, scanDate time.Time) uuid.UUID {
	t.Helper()
	t.Helper()
	sbomID := uuid.New()
	scanID := uuid.New()
	require.NoError(t, f.db.Create(&models.SbomUpload{
		ID: sbomID, OrgID: f.orgID, Filename: filename,
		Format: "cyclonedx", SizeBytes: 1, SHA256: sha,
		Document: []byte(`{}`), CreatedAt: scanDate,
	}).Error)
	require.NoError(t, f.db.Create(&models.Scan{
		ID: scanID, OrgID: f.orgID, SbomID: sbomID,
		Status: "completed", ScanDate: scanDate, CreatedAt: scanDate,
	}).Error)
	require.NoError(t, f.db.Create(&models.ScanVulnerability{
		ID: uuid.New(), ScanID: scanID, VulnerabilityID: f.vulnID, OrgID: f.orgID,
		SbomComponentName: component, SbomComponentVersion: version,
		SbomComponentType: "library",
		MatchConfidence:   "high", FeedSource: "grype", MatchedAt: scanDate,
	}).Error)
	return sbomID
}

func (f *fixture) resolve(t *testing.T) cra.Assessment {
	t.Helper()
	a, err := f.resolver.Resolve(context.Background(), f.orgID, f.vulnID)
	require.NoError(t, err)
	return a
}

func (f *fixture) confirmExploitation(t *testing.T, awareness time.Time, evidence string) {
	t.Helper()
	require.NoError(t, f.db.Model(&models.Vulnerability{}).
		Where("id = ?", f.vulnID).
		Updates(map[string]any{
			"active_exploitation_confirmed": true,
			"awareness_at":                  awareness,
			"awareness_source":              "exploit_evidence",
			"awareness_evidence":            evidence,
			"awareness_recorded_at":         awareness,
			"awareness_recorded_by":         "user:sec@example.eu",
		}).Error)
}

// --- the graph walk -------------------------------------------------------

func TestResolverReportsNoExposureWhenNothingWasShipped(t *testing.T) {
	f := newFixture(t)

	a := f.resolve(t)
	require.NotNil(t, a.NotExposed)
	assert.Equal(t, "no_product_exposure", a.NotExposed.Reason)
	assert.Empty(t, a.Prioritised)
}

func TestResolverFindsShippedComponent(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway-3.1.2.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	f.confirmExploitation(t, resolverNow.Add(-6*time.Hour), "pcap-2026-09-20")

	a := f.resolve(t)
	require.Len(t, a.Prioritised, 1, "a shipped third-party component is one exposure")
	e := a.Prioritised[0]
	assert.Equal(t, "libfoo", e.ComponentName)
	assert.Equal(t, "2.2.0", e.ComponentVersion)
	assert.Equal(t, "library", e.ComponentType)
	assert.Equal(t, "gateway-3.1.2.json", e.ProductName)
	assert.Equal(t, "sbom:aaa", e.ProductID)
	assert.Equal(t, cra.ReachabilityUnknown, e.Reachability,
		"nothing in the schema evidences reachability, so it must be unknown")
}

func TestRepeatedScansOfTheSameCompositionCollapseToOneExposure(t *testing.T) {
	f := newFixture(t)
	// The same SBOM scanned weekly for a month: four observations, one question.
	for i := 0; i < 4; i++ {
		f.ship(t, "gateway-3.1.2.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -7*i))
	}
	a := f.resolve(t)
	assert.Len(t, a.Prioritised, 1, "one product shipping one component is one exposure, not four")
}

func TestDistinctComponentsAndProductsAreDistinctExposures(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	f.ship(t, "gateway.json", "aaa", "openssl", "3.0.1", resolverNow.AddDate(0, 0, -30))
	f.ship(t, "analytics.json", "bbb", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))

	a := f.resolve(t)
	require.Len(t, a.Prioritised, 3)

	products := map[string]int{}
	for _, e := range a.Prioritised {
		products[e.ProductID]++
	}
	assert.Equal(t, 2, products["sbom:aaa"], "two components in one product")
	assert.Equal(t, 1, products["sbom:bbb"], "one component in another product")
}

func TestAnUnrelatedVulnerabilityYieldsNoExposure(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))

	other := uuid.New()
	require.NoError(t, f.db.Create(&models.Vulnerability{
		ID: other, OrgID: f.orgID, Cve: "CVE-2026-99999", UpdatedAt: resolverNow,
	}).Error)

	a, err := f.resolver.Resolve(context.Background(), f.orgID, other)
	require.NoError(t, err)
	require.NotNil(t, a.NotExposed)
	assert.Empty(t, a.Prioritised)
}

func TestResolverIsTenantScoped(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))

	// A different org resolving the same vulnerability id must see nothing.
	// Without the org predicate on the join this leaks another tenant's
	// composition.
	a, err := f.resolver.Resolve(context.Background(), uuid.New(), f.vulnID)
	require.Error(t, err, "another tenant's vulnerability is not visible")
	assert.Empty(t, a.Prioritised)
}

func TestUnknownVulnerabilityReturnsAnErrorNotAnEmptyAssessment(t *testing.T) {
	f := newFixture(t)
	_, err := f.resolver.Resolve(context.Background(), f.orgID, uuid.New())
	require.Error(t, err, "a missing vulnerability is an error, not 'no exposure'")
}

// --- evidence and reportability separation --------------------------------

func TestConfirmedExploitationProducesEvidenceNotAVerdict(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	f.confirmExploitation(t, resolverNow.Add(-6*time.Hour), "pcap-2026-09-20")

	a := f.resolve(t)
	require.Len(t, a.Prioritised, 1)
	assert.Equal(t, cra.SignalStrengthDirect, a.Prioritised[0].StrongestSignal)
	// The assessment carries no reportability verdict. The type has no such
	// field, so there is nothing for a caller to read off and act on.
	assert.Empty(t, a.BlockingGaps, "an evidenced, aware exposure has no blocking gaps")
}

func TestSeverityAloneProducesNoEvidenceSignal(t *testing.T) {
	// severity = "critical" and no confirmation: the resolver must not
	// manufacture exploitation evidence out of a triage score.
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	require.NoError(t, f.db.Model(&models.Vulnerability{}).
		Where("id = ?", f.vulnID).
		Update("severity", "critical").Error)

	a := f.resolve(t)
	require.Len(t, a.Prioritised, 1)
	assert.Empty(t, a.Prioritised[0].Signals, "a critical score is not exploitation evidence")
	assert.Contains(t, gapCodesOf(a.Prioritised[0].Gaps), cra.GapNoExploitationEvidence)
}

func TestAwarenessIsRequiredToStartTheClock(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	// Confirmed exploitation but no awareness instant recorded.
	require.NoError(t, f.db.Model(&models.Vulnerability{}).
		Where("id = ?", f.vulnID).
		Update("active_exploitation_confirmed", true).Error)

	a := f.resolve(t)
	require.NotEmpty(t, a.BlockingGaps)
	assert.Equal(t, cra.GapNoAwarenessRecorded, a.BlockingGaps[0].Code)
}

func TestASingleFeedIsUncorroboratedEvidenceNotAbsence(t *testing.T) {
	// One feed asserting exploitation is weak evidence, and it is evidence.
	// Marking a single KEV entry as corroborated would inflate every KEV hit to
	// the top of the queue; reporting it as absent would understate the
	// position entirely. It is reported as present and uncorroborated.
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	kev := resolverNow.AddDate(0, 0, -10)
	require.NoError(t, f.db.Model(&models.Vulnerability{}).
		Where("id = ?", f.vulnID).
		Updates(map[string]any{"exploited_in_wild": true, "kev_date_added": kev}).Error)

	a := f.resolve(t)
	require.Len(t, a.Prioritised, 1)
	require.NotEmpty(t, a.Prioritised[0].Signals)
	assert.Equal(t, cra.SignalStrengthUncorroborated, a.Prioritised[0].StrongestSignal,
		"one feed is evidence, but not corroboration")
	assert.NotContains(t, gapCodesOf(a.Prioritised[0].Gaps), cra.GapNoExploitationEvidence,
		"a reported signal is not the same as no signal at all")
}

// --- VEX ------------------------------------------------------------------

func TestActiveNotAffectedVexIsAttachedToTheExposure(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	f.confirmExploitation(t, resolverNow.Add(-6*time.Hour), "pcap")

	require.NoError(t, f.db.Create(&models.VexStatement{
		ID: uuid.New(), OrgID: f.orgID, CVE: f.cve, ProductID: "sbom:aaa",
		Justification:   "vulnerable_code_not_in_execute_path",
		ImpactStatement: "the affected function is only reachable from the CLI",
		Confidence:      "high", Status: "active",
	}).Error)

	a := f.resolve(t)
	require.Len(t, a.Prioritised, 1)
	assert.True(t, a.Prioritised[0].VexAssertsNotAffected,
		"a not_affected claim demotes the exposure; it does not remove it")
}

func TestExpiredVexIsNotAttachedAsAStandingClaim(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	f.confirmExploitation(t, resolverNow.Add(-6*time.Hour), "pcap")

	expired := resolverNow.AddDate(0, 0, -30)
	require.NoError(t, f.db.Create(&models.VexStatement{
		ID: uuid.New(), OrgID: f.orgID, CVE: f.cve, ProductID: "sbom:aaa",
		Justification: "component_not_present", Confidence: "high",
		Status: "active", ValidUntil: &expired,
	}).Error)

	a := f.resolve(t)
	require.Len(t, a.Prioritised, 1)
	assert.False(t, a.Prioritised[0].VexAssertsNotAffected,
		"a claim that expired last month is not a claim about today")
}

func TestVexForAnotherProductIsNotAttached(t *testing.T) {
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	f.confirmExploitation(t, resolverNow.Add(-6*time.Hour), "pcap")

	require.NoError(t, f.db.Create(&models.VexStatement{
		ID: uuid.New(), OrgID: f.orgID, CVE: f.cve, ProductID: "sbom:some-other-product",
		Justification: "component_not_present", Confidence: "high", Status: "active",
	}).Error)

	a := f.resolve(t)
	require.Len(t, a.Prioritised, 1)
	assert.False(t, a.Prioritised[0].VexAssertsNotAffected,
		"a claim about a different product says nothing about this one")
}

// --- dependency-free degradation ------------------------------------------

func TestResolverWorksBeforeTheReportingTableExists(t *testing.T) {
	// The CRA reporting table arrives with a later migration; a deployment
	// that has not run it yet must still resolve exposures.
	f := newFixture(t)
	f.ship(t, "gateway.json", "aaa", "libfoo", "2.2.0", resolverNow.AddDate(0, 0, -30))
	f.confirmExploitation(t, resolverNow.Add(-6*time.Hour), "pcap")

	a := f.resolve(t)
	assert.Empty(t, a.AlreadyCovered)
	assert.Len(t, a.Prioritised, 1)
}

func gapCodesOf(gaps []cra.Gap) []string {
	out := make([]string, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, g.Code)
	}
	return out
}
