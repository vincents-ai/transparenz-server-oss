// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package regulatory

import (
	_ "embed"
	"time"
)

// The Regulation itself, retained.
//
// Why this exists. The registry cited Regulation (EU) 2024/2847 with a hash
// computed from the STRING "Regulation (EU) 2024/2847|consolidated-2026-09-11" —
// a label, not a document. Anything the product asserts about the statutory
// periods therefore rested on a citation nobody could check, which is the exact
// defect ADR-002 exists to prevent.
//
// The text is now retained as the authority published it, so the periods the code
// computes from can be compared with the words of the article that sets them, and
// a reader can re-hash the file and reach the same conclusion.
//
// Provenance note worth keeping: eur-lex.europa.eu answers automated requests
// with an empty 202 from a bot-protection layer, so the copy is the Publications
// Office CELLAR manifestation of the same OJ act
// (publications.europa.eu/resource/oj/L_202402847.ENG.xhtml), fetched with an
// explicit language parameter. Same document, different host, hash recorded over
// these bytes.

//go:embed CRA_REGULATION_2024-2847_EN.xhtml
var craRegulationRetained []byte

const (
	// craRegulationVersion names the act as it was retained. It is not a
	// consolidated version: the product has never claimed to track amendments,
	// and saying "corrigenda applied" when they have not been read would be a
	// misstatement in an audit.
	craRegulationVersion = "2024/2847 as published in OJ L, 2024/2847, 20.11.2024"

	// craRegulationURL is the manifest URL the bytes came from.
	craRegulationURL = "https://publications.europa.eu/resource/oj/L_202402847.ENG.xhtml?language=eng"

	// craRegulationCanonicalURL is where a human reads the same act.
	craRegulationCanonicalURL = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
)

var (
	// craRegulationPublished is the OJ publication date.
	craRegulationPublished = time.Date(2024, 11, 20, 0, 0, 0, 0, time.UTC)
	// craRegulationRetrieved is when these bytes were fetched.
	craRegulationRetrieved = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
)

// CRARegulationArtifact returns the retained Regulation as provenance evidence.
func CRARegulationArtifact() SourceArtifact {
	a := NewSourceArtifact(
		InstrumentCRA, craRegulationVersion, craRegulationURL,
		craRegulationRetrieved, craRegulationRetained, "",
	)
	// The artifact records where the bytes came from; the canonical URL is what a
	// human should be given when they want to read the act.
	a.CanonicalURL = craRegulationURL
	return a
}

// CRARegulationText returns the retained Regulation text, for tests that check
// what the product asserts about it.
func CRARegulationText() []byte { return craRegulationRetained }
