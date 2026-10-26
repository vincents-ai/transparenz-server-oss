// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package regulatory

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every source the Article 14 obligation cites is retained and reproducible.
//
// This is the end state of R02: a source either ships as text whose hash a reader
// can recompute, or says plainly that its hash identifies a title and nothing
// more. What is no longer acceptable is a source whose provenance cannot be
// stated either way.
func TestEveryObligationSourceIsRetainedOrSaysItIsNot(t *testing.T) {
	reg, _, err := BuildDefaultRegistry(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	o, ok := reg.Obligation(ObligationCRAArticle14Report)
	require.True(t, ok)

	cited := append([]string{o.SourceKey}, o.Guidance...)
	require.NotEmpty(t, cited)

	for _, key := range cited {
		src, ok := reg.SourceByKey(key)
		require.True(t, ok, "obligation cites unregistered source %s", key)
		switch src.ArtifactDerived {
		case ArtifactRetained:
			assert.True(t, src.IsVerifiable(),
				"%s claims retained provenance but its hash is not a content hash", key)
		case ArtifactLabelDerived:
			assert.False(t, src.IsVerifiable(),
				"%s is label-derived and must not claim otherwise", key)
		default:
			t.Errorf("%s has ArtifactDerived=%q", key, src.ArtifactDerived)
		}
	}

	// The one source that is still label-derived must be the historical glossary
	// version, kept so reports filed against the old schemas stay explainable.
	// Anything else slipping back to a label hash is a regression.
	for _, key := range cited {
		src, _ := reg.SourceByKey(key)
		if src.ArtifactDerived != ArtifactLabelDerived {
			continue
		}
		assert.Equal(t, "1.3", src.Version,
			"%s is label-derived; only the superseded glossary 1.3 may be, and only "+
				"because it cannot be re-fetched in a form it originally had", key)
	}
}

// The guidance the registry cites must be the document that exists.
//
// The previous entry named "Commission Guidance on CRA Article 14 reporting",
// dated 2026-07-01. C(2026) 5252 final is dated 27 July 2026, is a Communication
// to the Commission approving draft guidance on the CRA as a whole, and covers
// Article 14 reporting in subsection 5.3 of its annex. A product that misnames
// the document it rests on invites a customer to cite something that does not
// exist.
func TestCommissionGuidanceIsNamedAndDatedAsPublished(t *testing.T) {
	reg, _, err := BuildDefaultRegistry(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	src, ok := reg.Source(AuthorityCommissionGuidance, commissionGuidanceDocument, commissionGuidanceVersion)
	require.True(t, ok, "the guidance must be registered under the title the Commission publishes")

	assert.Equal(t, "2026-07-27T00:00:00Z", src.PublicationDate.Format(time.RFC3339),
		"the document's own date is on its first page")
	assert.False(t, src.Authority.Binding(),
		"guidance informs the implementation; the Regulation creates the duty")
	require.True(t, src.VerifyHash(CRAGuidanceText()))

	// The retained bytes are a PDF, and the guidance text is in it. Asserting the
	// file signature rather than parsing it keeps the dependency surface at zero;
	// what a reader checks is the hash, not this test.
	assert.True(t, strings.HasPrefix(string(CRAGuidanceText()), "%PDF"),
		"the retained guidance must be the published PDF")
	assert.NotContains(t, src.Document, "Article 14 reporting",
		"the guidance is not Article 14 specific, and naming it so was wrong")
}

// The FAQ's version is the date the page itself states.
func TestSRPFAQIsDatedFromThePageItself(t *testing.T) {
	reg, _, err := BuildDefaultRegistry(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	src, ok := reg.Source(AuthorityENISAOperationalGuidance, srpFAQDocument, "2026-10-15")
	require.True(t, ok, "the FAQ must be registered under the date the page states")

	page := string(SRPFAQText())
	assert.Contains(t, page, "Updated: 15 October 2026",
		"the registered version must be the page's own updated date, not a guess")
	require.True(t, src.VerifyHash(SRPFAQText()))

	// The obligation's start date is corroborated by the same page rather than
	// resting only on the Regulation's entry into force: the FAQ states the Article
	// 14 reporting obligations apply from 11 September 2026.
	assert.Contains(t, page, "11 September 2026",
		"the retained FAQ states the date the Article 14 obligations start, which is "+
			"what Obligation.AppliesFrom carries")
}
