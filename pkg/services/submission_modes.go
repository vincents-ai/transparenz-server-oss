// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package services

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

// Submission modes.
//
// These are named for what actually happens rather than for an authority the
// system cannot reach. The previous set was "api" | "csirt" | "export", and
// "api" was not an ENISA integration at all: it POSTed the document to
// org.EnisaAPIEndpoint, a URL the operator configured. The ENISA Single
// Reporting Platform publishes no API, so there is no endpoint for that mode to
// mean. The old names are retained as accepted aliases so existing
// configurations do not break, but they are mapped to honest behaviour and the
// ENISA one is refused outright.
const (
	// SubmissionModeReceiver pushes the document to an operator-configured
	// receiver, in practice a national CSIRT's own submission endpoint.
	SubmissionModeReceiver = "receiver"

	// SubmissionModeManual hands the document to a person, who files it
	// themselves. This is the default and the correct default.
	SubmissionModeManual = "manual"

	// SubmissionModeENISAAPI addresses an ENISA API that does not exist. It is
	// accepted as a configuration value only so the system can explain why it
	// cannot be honoured, rather than failing with a bare "unknown mode".
	SubmissionModeENISAAPI = "enisa_api"
)

// Legacy mode values, kept so existing rows and configurations keep working.
const (
	legacyModeAPI         = "api"
	legacyModeCSIRT       = "csirt"
	legacyModeCSIRTLegacy = "enisa"
	legacyModeExport      = "export"
)

// ErrENISAAPINotAvailable is returned when a submission is attempted in the
// ENISA API mode.
//
// The error names the reason rather than reporting a generic failure,
// because "this is not available" and "your configuration is wrong" call for
// completely different responses from an operator, and a manufacturer reading
// the failure needs to know which one this is.
var ErrENISAAPINotAvailable = errors.New(
	"the ENISA Single Reporting Platform publishes no API; notifications are submitted " +
		"through the SRP interface by a person, and ENISA states API functionality may be " +
		"considered at a later stage")

// submissionEndpoint returns the receiver URL to push a document to.
//
// It prefers a CSIRT-specific endpoint over the legacy column. The legacy
// column is named for ENISA but has always held whatever URL the operator
// configured, which in practice is a CSIRT. Reading it here — rather than
// treating it as an ENISA endpoint — is what keeps the record honest without
// forcing a migration on existing installations.
//
// It is a function rather than a method because the fallback rule is a
// submission-routing decision, not a property of an organisation.
func submissionEndpoint(o *models.Organization) string {
	if v := strings.TrimSpace(o.CsirtEndpoint); v != "" {
		return v
	}
	return strings.TrimSpace(o.EnisaAPIEndpoint)
}

// enisaAPINotAvailableError builds the single message used whenever the ENISA
// API mode is encountered.
//
// One formatting point, so the normaliser and the switch cannot drift into
// saying different things about the same condition. The guidance names the
// alternatives: an operator reading this needs to know what to do next, not
// merely that something is unavailable.
func enisaAPINotAvailableError(configured string) error {
	return fmt.Errorf(
		"%w: submission mode %q addresses an ENISA API that does not exist. "+
			"ENISA's Single Reporting Platform publishes no API, so there is nothing to post to. "+
			"Use %q to push to a national CSIRT endpoint, or %q for a document a person files.",
		ErrENISAAPINotAvailable, configured, SubmissionModeReceiver, SubmissionModeManual)
}

// NormalizeSubmissionMode maps a stored configuration value onto a current
// mode, reporting whether the value is honoured.
//
// The ENISA API mode is returned with ok=false and the reason, so the caller
// can refuse with an explanation instead of silently doing something else.
func NormalizeSubmissionMode(raw string) (mode string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", legacyModeExport, SubmissionModeManual:
		return SubmissionModeManual, true
	case SubmissionModeReceiver, legacyModeCSIRT, legacyModeCSIRTLegacy:
		return SubmissionModeReceiver, true
	case legacyModeAPI, SubmissionModeENISAAPI:
		return SubmissionModeENISAAPI, false
	default:
		return "", false
	}
}
