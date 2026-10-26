// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package regulatory

import (
	_ "embed"
	"time"
)

// The remaining regulatory sources, retained.
//
// Every source the Article 14 obligation cites is now either retained text that
// ships with the binary or an explicitly labelled label-derived hash. The
// distinction mattered: a label hash identifies a title and a version and
// nothing more, so an assertion resting on it cannot be checked by anyone.
//
// Two of the three headings below were also WRONG about the documents they named,
// which only became visible when the documents were fetched:
//
//   - The Commission source called itself "Commission Guidance on CRA Article 14
//     reporting", dated 2026-07-01. There is no such document. C(2026) 5252 final
//     of 27 July 2026 is a Communication to the Commission approving draft
//     Commission guidance on the application of the CRA as a whole; Article 14
//     reporting is subsection 5.3 of its annex. A product that misnames its own
//     guidance invites a customer to cite a document that does not exist.
//   - The SRP FAQ was dated 2026-09-17. The published page says "Updated: 15
//     October 2026".

// Commission guidance, retained as published.
//
//go:embed COMMISSION_GUIDANCE_C2026_5252_ANNEX.pdf
var commissionGuidanceRetained []byte

// ENISA SRP FAQ, retained as served.
//
//go:embed ENISA_SRP_FAQ_2026-10-15.html
var srpFAQRetained []byte

const (
	// commissionGuidanceDocument is the title the Commission publishes. It is a
	// guidance document on the CRA as a whole; the Article 14 reporting material
	// this product implements is subsection 5.3 of the annex.
	commissionGuidanceDocument = "Commission guidance on the application of Regulation (EU) 2024/2847 (CRA)"

	// commissionGuidanceVersion is the act number, with the annex named because
	// the guidance IS the annex. The covering Communication C(2026) 5252 final is
	// the Commission's internal approval of it and carries almost no text of its
	// own, which is why retaining the annex rather than the Communication is the
	// right artifact.
	commissionGuidanceVersion = "C(2026) 5252 final, Annex"

	// commissionGuidanceURL is the download the Commission's own library page
	// offers for the annex.
	commissionGuidanceURL = "https://ec.europa.eu/newsroom/dae/redirection/document/131456"

	// srpFAQDocument and version identify the ENISA FAQ page. Its own "Updated:"
	// line is the version, because ENISA does not version the page.
	srpFAQDocument = "ENISA SRP FAQ"
	srpFAQURL      = "https://www.enisa.europa.eu/topics/product-security/vulnerability-services/eu-incident-response-and-cyber-crisis-management/single-reporting-platform-srp/frequently-asked-questions"
)

var (
	// commissionGuidancePublished is the document's own date, from its first page.
	commissionGuidancePublished = time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)
	// commissionGuidanceRetrieved is when these bytes were fetched.
	commissionGuidanceRetrieved = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)

	// srpFAQUpdated is the page's own "Updated:" date.
	srpFAQUpdated = time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	// srpFAQRetrieved is when these bytes were fetched.
	srpFAQRetrieved = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
)

// CommissionGuidanceArtifact returns the retained guidance as evidence.
func CommissionGuidanceArtifact() SourceArtifact {
	return NewSourceArtifact(
		commissionGuidanceDocument, commissionGuidanceVersion, commissionGuidanceURL,
		commissionGuidanceRetrieved, commissionGuidanceRetained, "",
	)
}

// SRPFAQArtifact returns the retained FAQ page as evidence.
func SRPFAQArtifact() SourceArtifact {
	return NewSourceArtifact(
		srpFAQDocument, srpFAQUpdated.Format("2006-01-02"), srpFAQURL,
		srpFAQRetrieved, srpFAQRetained, "",
	)
}

// CRAGuidanceText and SRPFAQText expose the retained bytes so a test can check
// what the product says about them.
func CRAGuidanceText() []byte { return commissionGuidanceRetained }
func SRPFAQText() []byte      { return srpFAQRetained }
