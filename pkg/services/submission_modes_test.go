// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package services

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

// The mode normaliser is the single point where a stored configuration value is
// turned into behaviour, so these tests are about the mapping rather than about
// delivery.

func TestNormalizeSubmissionMode(t *testing.T) {
	cases := []struct {
		raw      string
		wantMode string
		wantOK   bool
		explain  string
	}{
		// The default. A person files.
		{"", SubmissionModeManual, true, "an unset mode must default to a human filing"},
		{"export", SubmissionModeManual, true, "the legacy export value is the manual mode"},
		{SubmissionModeManual, SubmissionModeManual, true, "manual maps to itself"},

		// The push. A configured receiver, in practice a national CSIRT.
		{SubmissionModeReceiver, SubmissionModeReceiver, true, "receiver maps to itself"},
		{"csirt", SubmissionModeReceiver, true, "the legacy csirt value was always a receiver push"},
		{"enisa", SubmissionModeReceiver, true,
			"the legacy 'enisa' value was never ENISA: it posted to a user-configured URL"},

		// Refused. There is no ENISA API to talk to.
		{"api", SubmissionModeENISAAPI, false, "the legacy api value claimed an ENISA integration that never existed"},
		{SubmissionModeENISAAPI, SubmissionModeENISAAPI, false, "named explicitly, still refused"},

		{"nonsense", "", false, "an unrecognised mode is not honoured"},
	}
	for _, tc := range cases {
		t.Run(tc.explain, func(t *testing.T) {
			mode, ok := NormalizeSubmissionMode(tc.raw)
			assert.Equal(t, tc.wantMode, mode)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

func TestModeNormalisationIsCaseAndWhitespaceInsensitive(t *testing.T) {
	// Case and surrounding whitespace must not change behaviour, or a
	// configuration edited by hand could silently change what a filing does.
	mode, ok := NormalizeSubmissionMode("  RECEIVER ")
	assert.True(t, ok)
	assert.Equal(t, SubmissionModeReceiver, mode)

	mode, ok = NormalizeSubmissionMode("  csirt\n")
	assert.True(t, ok)
	assert.Equal(t, SubmissionModeReceiver, mode)

	_, ok = NormalizeSubmissionMode("  Api  ")
	assert.False(t, ok, "the ENISA mode stays refused however it is capitalised")
}

func TestENISAAPIErrorExplainsItselfAndNamesTheAlternatives(t *testing.T) {
	err := enisaAPINotAvailableError("api")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrENISAAPINotAvailable)
	// An operator reading this must learn WHY and WHAT TO DO, not just that
	// something failed. "Not available" and "your config is wrong" call for
	// completely different responses.
	assert.Contains(t, err.Error(), "publishes no API")
	assert.Contains(t, err.Error(), SubmissionModeReceiver)
	assert.Contains(t, err.Error(), SubmissionModeManual)
	assert.Contains(t, err.Error(), "api", "the offending configured value is named back")
}

func TestSubmissionEndpointPrefersTheCSIRTField(t *testing.T) {
	// The legacy column is named for ENISA but has always held whatever URL the
	// operator configured. New installations set the CSIRT field; both resolve.
	onlyLegacy := &models.Organization{EnisaAPIEndpoint: "https://legacy.example.invalid/x"}
	assert.Equal(t, "https://legacy.example.invalid/x", submissionEndpoint(onlyLegacy))

	both := &models.Organization{
		EnisaAPIEndpoint: "https://legacy.example.invalid/x",
		CsirtEndpoint:    "https://csirt.example.eu/submit",
	}
	assert.Equal(t, "https://csirt.example.eu/submit", submissionEndpoint(both))

	neither := &models.Organization{}
	assert.Empty(t, submissionEndpoint(neither))

	whitespace := &models.Organization{EnisaAPIEndpoint: "   ", CsirtEndpoint: " "}
	assert.Empty(t, submissionEndpoint(whitespace), "whitespace is not an endpoint")
}

// The point of the whole change: selecting the ENISA mode must never result in
// a document being sent anywhere.
func TestENISAModeCannotReachTheNetwork(t *testing.T) {
	f := newENISATestService(t)

	org := &models.Organization{
		ID:                  uuid.New(),
		Name:                "Enisa Mode Org",
		Slug:                "enisa-mode-org",
		EnisaSubmissionMode: legacyModeAPI,
		// An endpoint that would succeed if it were ever contacted.
		EnisaAPIEndpoint: "https://example.invalid/somewhere",
		CsafScope:        "per_sbom",
		SlaTrackingMode:  "per_cve",
	}
	require.NoError(t, f.orgRepo.Create(t.Context(), org))
	require.NoError(t, f.db.Create(&models.Vulnerability{
		ID: uuid.New(), OrgID: org.ID, Cve: "CVE-2024-8888", Severity: "critical",
	}).Error)

	ctx := middleware.ContextWithOrgID(t.Context(), org.ID)
	_, err := f.svc.Submit(ctx, org.ID, "CVE-2024-8888", nil)
	require.ErrorIs(t, err, ErrENISAAPINotAvailable)

	// Nothing was recorded as submitted. A refused mode must not leave a
	// submission row that a later reader could mistake for a completed filing.
	var count int64
	require.NoError(t, f.db.Model(&models.EnisaSubmission{}).
		Where("org_id = ?", org.ID).Count(&count).Error)
	assert.Zero(t, count, "a refused ENISA mode must not create a submission record")
}
