// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package srp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
)

// Receiver is an authority that accepts a submission over HTTP.
//
// The name matters. This is deliberately NOT called an ENISA transport,
// because the ENISA Single Reporting Platform publishes no API and there is
// therefore nothing to point one at. What this actually talks to is an
// operator-configured receiver — in practice a national CSIRT's own
// submission endpoint, which does exist and does accept filings.
type Receiver struct {
	// Endpoint is the receiver's HTTPS submission URL.
	Endpoint string

	// BearerToken is an optional credential. Many CSIRT endpoints are
	// unauthenticated; some require a token.
	BearerToken string

	// Authority names the receiver for logs and receipts, e.g. "DE-CSIRT".
	Authority string
}

// ErrNoEndpoint is returned when a receiver is not configured.
var ErrNoEndpoint = errors.New("srp: no submission endpoint is configured")

// ErrNotHTTPS is returned when a configured endpoint is not a public HTTPS URL.
var ErrNotHTTPS = errors.New("srp: submission endpoint must be HTTPS and must not be a private address")

// ReceiverTransport delivers a package to an operator-configured receiver.
//
// It is the implementation for CSIRT submission. It is honest about what it
// does — an authenticated push to a configured endpoint, with retry
// information preserved for a human to act on — and it is not a substitute for
// the ENISA SRP, which has no API to substitute for.
type ReceiverTransport struct {
	// Client is the HTTP client. A nil Client uses a 30-second default.
	Client *http.Client

	// Logger receives delivery outcomes. Optional.
	Logger interface {
		Warn(msg string, fields ...any)
		Info(msg string, fields ...any)
	}

	receiver Receiver
}

// NewReceiverTransport constructs a ReceiverTransport.
func NewReceiverTransport(receiver Receiver, client *http.Client) *ReceiverTransport {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &ReceiverTransport{Client: client, receiver: receiver}
}

// Name implements Transport.
//
// The name is recorded on the submission and is what an auditor reads. It
// deliberately describes the mechanism rather than naming a destination the
// system cannot actually reach.
func (t *ReceiverTransport) Name() string { return ViaReceiverPush }

// ViaReceiverPush is the transport name recorded for a configured-receiver
// push. It is distinct from ViaHumanSRP so an audit trail never conflates an
// automated push to a CSIRT with a person filing in the ENISA interface.
const ViaReceiverPush = "receiver_push"

// Validate checks the configured endpoint before any delivery is attempted.
//
// The SSRF checks are not incidental. The endpoint is operator-supplied, and a
// compliance tool that will POST a document to any configured URL is a tool
// that will happily POST to an internal metadata service if the configuration
// is wrong or hostile.
func (t *ReceiverTransport) Validate() error {
	if strings.TrimSpace(t.receiver.Endpoint) == "" {
		return ErrNoEndpoint
	}
	u, err := url.Parse(t.receiver.Endpoint)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotHTTPS, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme is %q, not https", ErrNotHTTPS, u.Scheme)
	}
	if middleware.IsPrivateIP(u.Hostname()) {
		return fmt.Errorf("%w: %s is a private address", ErrNotHTTPS, u.Hostname())
	}
	return nil
}

// Deliver posts a package to the configured receiver.
//
// Idempotency is keyed on the package digest, so a retried delivery of an
// unchanged package is recognisable as the same filing rather than a second
// one. A receiver that creates a second case for the same event is itself a
// reporting defect.
func (t *ReceiverTransport) Deliver(ctx context.Context, p Package) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err := t.Validate(); err != nil {
		return Receipt{}, err
	}
	if !p.VerifyDigest() {
		return Receipt{}, errors.New("srp: package content does not match its digest; refusing to deliver altered content")
	}

	payload, err := json.Marshal(map[string]any{
		"report_id":      p.ReportID,
		"org_id":         p.OrgID,
		"event_class":    p.EventClass,
		"stage":          p.Stage,
		"schema_version": p.SchemaID,
		"coordinator":    p.CoordinatorID,
		"digest":         p.Digest,
		"fields":         p.Fields,
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("srp: encode package: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.receiver.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return Receipt{}, fmt.Errorf("srp: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", p.Digest)
	if t.receiver.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.receiver.BearerToken)
	}

	resp, err := t.Client.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("srp: deliver to receiver: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		if secs, err := strconv.Atoi(retryAfter); err == nil {
			return Receipt{}, &RateLimitedError{RetryAfter: time.Duration(secs) * time.Second, Body: string(body)}
		}
		return Receipt{}, &RateLimitedError{RetryAfter: 0, Body: string(body)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Receipt{}, fmt.Errorf("srp: receiver returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	receipt := Receipt{
		Digest:     p.Digest,
		ReceivedAt: time.Now().UTC(),
	}
	var parsed struct {
		CaseReference string `json:"case_reference"`
		Reference     string `json:"reference"`
		ID            string `json:"id"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		// Receivers disagree on the field name, so all three are accepted.
		// A missing case reference is recorded as empty rather than invented:
		// the authority's reference is a fact about what they returned.
		receipt.CaseReference = firstNonEmptyString(parsed.CaseReference, parsed.Reference, parsed.ID)
	}
	return receipt, nil
}

// RateLimitedError reports that the receiver asked the caller to back off.
//
// It is a distinct type so a retry worker can honour Retry-After instead of
// treating a backpressure signal as a failure and burning its whole retry
// budget immediately.
type RateLimitedError struct {
	RetryAfter time.Duration
	Body       string
}

func (e *RateLimitedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("srp: receiver rate limited, retry after %s", e.RetryAfter)
	}
	return "srp: receiver rate limited"
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
