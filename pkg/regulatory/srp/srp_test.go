// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package srp

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingExporter struct {
	exported []Package
	err      error
}

func (e *recordingExporter) Export(_ context.Context, p Package) error {
	if e.err != nil {
		return e.err
	}
	e.exported = append(e.exported, p)
	return nil
}

func validPackage(t *testing.T) Package {
	t.Helper()
	p, err := NewPackage(
		uuid.New(), uuid.New(), "AEV", "early_warning", "ENISA-SRP-1.3", "DE-CSIRT",
		map[string]string{
			"v1":  "CVE-2026-31337",
			"v5":  "observed mass exploitation",
			"v7":  "network",
			"v12": "Example Gateway 3.x",
		},
		time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC),
	)
	require.NoError(t, err)
	return p
}

func TestPackageRequiresAValidatedSchemaVersion(t *testing.T) {
	_, err := NewPackage(uuid.New(), uuid.New(), "AEV", "early_warning", "", "DE-CSIRT", nil, time.Now())
	require.Error(t, err, "a package that does not say which glossary version it was validated against is not auditable")
}

func TestPackageRequiresACoordinator(t *testing.T) {
	_, err := NewPackage(uuid.New(), uuid.New(), "AEV", "early_warning", "ENISA-SRP-1.3", "", nil, time.Now())
	require.ErrorIs(t, err, err)
	assert.Contains(t, err.Error(), "coordinator")
}

func TestDigestIsStableAcrossMapIterationOrder(t *testing.T) {
	// Go randomises map iteration order. An unstable digest would make every
	// retry look like changed content and defeat deduplication.
	id, org := uuid.New(), uuid.New()
	fields := map[string]string{"v1": "CVE-2026-31337", "v5": "x", "v7": "network", "v12": "y", "v6": "z"}
	first, err := NewPackage(id, org, "AEV", "early_warning", "ENISA-SRP-1.3", "DE-CSIRT", fields, time.Now())
	require.NoError(t, err)
	for i := 0; i < 20; i++ {
		again, err := NewPackage(id, org, "AEV", "early_warning", "ENISA-SRP-1.3", "DE-CSIRT", fields, time.Now())
		require.NoError(t, err)
		assert.Equal(t, first.Digest, again.Digest)
	}
}

func TestDigestChangesWhenAnySubmittedValueChanges(t *testing.T) {
	base := validPackage(t)
	changed, err := NewPackage(base.ReportID, base.OrgID, base.EventClass, base.Stage, base.SchemaID,
		base.CoordinatorID, map[string]string{
			"v1":  "CVE-2026-31337",
			"v5":  "observed mass exploitation (updated)", // one value differs
			"v7":  "network",
			"v12": "Example Gateway 3.x",
		}, time.Now())
	require.NoError(t, err)
	assert.NotEqual(t, base.Digest, changed.Digest)
}

func TestDigestDoesNotChangeWithGenerationTime(t *testing.T) {
	id, org := uuid.New(), uuid.New()
	fields := map[string]string{"v1": "CVE-2026-31337"}
	a, err := NewPackage(id, org, "AEV", "early_warning", "ENISA-SRP-1.3", "DE-CSIRT", fields, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	b, err := NewPackage(id, org, "AEV", "early_warning", "ENISA-SRP-1.3", "DE-CSIRT", fields, time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, a.Digest, b.Digest, "generation time is transport metadata, not content")
}

func TestTamperedPackageIsDetectedAndRefused(t *testing.T) {
	exp := &recordingExporter{}
	tr := &ManualTransport{Exporter: exp}

	p := validPackage(t)
	p.Fields["v5"] = "rewritten after validation"

	_, err := tr.Deliver(context.Background(), p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match its digest")
	assert.Empty(t, exp.exported, "nothing is handed to a filer if the content drifted")
}

func TestManualTransportReportsPendingRatherThanSubmitted(t *testing.T) {
	// The load-bearing honesty property: a manual delivery is not a filing.
	exp := &recordingExporter{}
	tr := &ManualTransport{Exporter: exp}

	receipt, err := tr.Deliver(context.Background(), validPackage(t))
	require.NoError(t, err)
	assert.True(t, receipt.Pending)
	assert.Empty(t, receipt.CaseReference, "no case reference exists until a person files it and the authority issues one")
	assert.NotEmpty(t, receipt.Digest)
	require.Len(t, exp.exported, 1)
	assert.Equal(t, ViaHumanSRP, tr.Name())
}

func TestManualTransportRequiresAnExporter(t *testing.T) {
	tr := &ManualTransport{}
	_, err := tr.Deliver(context.Background(), validPackage(t))
	require.Error(t, err)
}

func TestExporterFailurePropagates(t *testing.T) {
	tr := &ManualTransport{Exporter: &recordingExporter{err: assert.AnError}}
	receipt, err := tr.Deliver(context.Background(), validPackage(t))
	require.Error(t, err)
	assert.False(t, receipt.Pending)
}

func TestManualTransportHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr := &ManualTransport{Exporter: &recordingExporter{}}
	_, err := tr.Deliver(ctx, validPackage(t))
	require.ErrorIs(t, err, context.Canceled)
}

// The transport is an interface so the domain never names a concrete adapter.
// This is a compile-time assertion that a future ENISA API adapter is a
// drop-in replacement requiring no change to the reporting domain.
var _ Transport = (*ManualTransport)(nil)
