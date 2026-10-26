// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package regulatory

import (
	"html"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/cra"
)

// regulationText returns the retained Regulation with tags removed and
// whitespace normalised, so assertions can be made about the words of an article
// rather than about markup.
func regulationText(t *testing.T) string {
	t.Helper()
	raw := string(CRARegulationText())
	require.NotEmpty(t, raw, "the Regulation must be retained for this test to mean anything")

	tags := regexp.MustCompile(`(?s)<[^>]+>`)
	text := tags.ReplaceAllString(raw, " ")
	text = html.UnescapeString(text)
	// The published XHTML uses non-breaking spaces inside "Article 14"; normalise
	// them or every phrase built with a plain space silently fails to match.
	text = strings.ReplaceAll(text, "\u00a0", " ")
	return strings.Join(strings.Fields(text), " ")
}

// The statutory periods this product computes from are checked against the words
// that set them.
//
// This is the difference between "the constant is documented as 24 hours" and
// "the article says 24 hours". Before the Regulation was retained, the citation
// was a hash over a label and no test could tell the two apart.
func TestStatutoryPeriodsAreTheOnesInTheRegulation(t *testing.T) {
	text := regulationText(t)

	cases := []struct {
		name     string
		phrase   string
		ours     time.Duration
		ourClaim string
	}{
		{
			name:   "AEV early warning",
			phrase: "within 24 hours of the manufacturer becoming aware",
			ours:   cra.EarlyWarningWindow,
		},
		{
			name:   "AEV vulnerability notification",
			phrase: "within 72 hours of the manufacturer becoming aware",
			ours:   cra.NotificationWindow,
		},
		{
			name:   "AEV final report",
			phrase: "no later than 14 days after a corrective or mitigating measure is available",
			ours:   cra.AEVFinalReportWindow,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Contains(t, text, tc.phrase,
				"the phrase this product's period is based on is not in the retained Regulation")
		})
	}

	assert.Equal(t, 24*time.Hour, cra.EarlyWarningWindow)
	assert.Equal(t, 72*time.Hour, cra.NotificationWindow)
	assert.Equal(t, 14*24*time.Hour, cra.AEVFinalReportWindow)

	// The severe-incident final report is anchored to the submission of the 72-hour
	// notification and runs for one calendar month — not from awareness, and not 30
	// days. Both halves are asserted against the article.
	assert.Contains(t, text,
		"a final report, within one month after the submission of the incident notification",
		"the SI final-report anchor is the notification submission, and the period is a calendar month")
	assert.Equal(t, 1, cra.SIFinalReportMonths,
		"one calendar month, because the article says 'within one month' and February is not 30 days")
}

// Article 14(4)(a) requires the early warning of a severe incident to state
// whether the incident is suspected of unlawful or malicious acts. That is field
// i31, which the earlier schemas did not model at all — so this test also records
// why it is required at the first stage rather than later.
func TestSevereIncidentEarlyWarningRequiresTheSuspicionOfMalice(t *testing.T) {
	text := regulationText(t)
	assert.Contains(t, text,
		"an early warning notification of a severe incident having an impact on the security of the "+
			"product with digital elements, without undue delay and in any event within 24 hours of the "+
			"manufacturer becoming aware of it, including at least whether the incident is suspected of "+
			"being caused by unlawful or malicious acts",
		"the statutory basis for field i31 at the early-warning stage")
}

// The Regulation's "particularly exceptional circumstances" are three specific
// grounds. The domain models a different vocabulary, which is recorded here so the
// mismatch cannot be mistaken for agreement.
func TestParticularlyExceptionalCircumstancesAreThreeSpecificGrounds(t *testing.T) {
	text := regulationText(t)

	assert.Contains(t, text,
		"it has been exploited in no other Member State than the one of the CSIRT designated as "+
			"coordinator to which the manufacturer has notified the vulnerability",
		"ground (a)")
	assert.Contains(t, text,
		"any immediate further dissemination of the notified vulnerability would likely result in "+
			"the supply of information the disclosure of which would be contrary to the essential "+
			"interests of that Member State",
		"ground (b)")
	assert.Contains(t, text,
		"the notified vulnerability poses an imminent high cybersecurity risk stemming from the "+
			"further dissemination",
		"ground (c)")
}

// The Regulation is retained, and the hash reproduces from the bytes that ship.
func TestRegulationProvenanceIsVerifiable(t *testing.T) {
	artifact := CRARegulationArtifact()
	require.True(t, artifact.Verify(), "the retained Regulation must reproduce its own hash")

	reg, _, err := BuildDefaultRegistry(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	src, ok := reg.Source(AuthorityLaw, InstrumentCRA, craRegulationVersion)
	require.True(t, ok, "the Regulation must be registered under the retained version")
	require.True(t, src.IsVerifiable(),
		"the legal basis of the Article 14 duty must be verifiable, not a label hash")
	require.True(t, src.VerifyHash(CRARegulationText()),
		"the registered hash must reproduce from the embedded text")
}
