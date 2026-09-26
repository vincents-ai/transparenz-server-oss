// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package srp

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func receiverPackage(t *testing.T) Package {
	t.Helper()
	p, err := NewPackage(
		uuid.New(), uuid.New(), "AEV", "early_warning", "ENISA-SRP-1.3", "DE-CSIRT",
		map[string]string{"v1": "CVE-2026-31337", "v5": "observed"},
		time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC),
	)
	require.NoError(t, err)
	return p
}

// The transport is named for its mechanism, not for an authority. An auditor
// reading a submission record must be able to tell a push to a CSIRT from a
// person filing in the ENISA interface, and the two are not the same act.
func TestReceiverTransportIsNamedForItsMechanismNotAnAuthority(t *testing.T) {
	tr := NewReceiverTransport(Receiver{Endpoint: "https://csirt.example.eu/submit"}, nil)
	assert.Equal(t, ViaReceiverPush, tr.Name())
	assert.NotEqual(t, ViaHumanSRP, tr.Name())
	assert.NotContains(t, strings.ToLower(tr.Name()), "enisa")
}

// The endpoint is operator-supplied, so the SSRF guard is load-bearing: a
// compliance tool that will POST to any configured URL will happily POST to an
// internal metadata service.
func TestReceiverTransportRefusesUnsafeEndpoints(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		wantErr  error
	}{
		{"unset", "", ErrNoEndpoint},
		{"plaintext http", "http://csirt.example.eu/submit", ErrNotHTTPS},
		{"loopback literal", "https://127.0.0.1/submit", ErrNotHTTPS},
		{"private range", "https://10.0.0.5/submit", ErrNotHTTPS},
		{"link local metadata service", "https://169.254.169.254/latest/meta-data/", ErrNotHTTPS},
		{"not a url", "://nope", ErrNotHTTPS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewReceiverTransport(Receiver{Endpoint: tc.endpoint}, nil)
			err := tr.Validate()
			require.ErrorIs(t, err, tc.wantErr)
			// Delivery must refuse before any request is attempted.
			_, err = tr.Deliver(context.Background(), receiverPackage(t))
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestReceiverTransportDeliversWithAStableIdempotencyKey(t *testing.T) {
	var gotKey, gotAuth, gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Idempotency-Key")
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"case_reference":"SRP-2026-000123"}`))
	}))
	defer srv.Close()

	tr := NewReceiverTransport(Receiver{
		Endpoint:    localURL(srv.URL),
		BearerToken: "tok-abc",
	}, testClient())

	p := receiverPackage(t)
	receipt, err := tr.Deliver(context.Background(), p)
	require.NoError(t, err)

	assert.Equal(t, p.Digest, gotKey,
		"a retry of an unchanged package must be recognisable as the same filing")
	assert.Equal(t, "Bearer tok-abc", gotAuth)
	assert.Equal(t, "/", gotPath)
	assert.Equal(t, "SRP-2026-000123", receipt.CaseReference)
	assert.Equal(t, p.Digest, receipt.Digest)
	assert.False(t, receipt.Pending, "a push that succeeded is not pending")
}

func TestReceiverTransportAcceptsTheReferenceFieldNamesReceiversDisagreeOn(t *testing.T) {
	// Receivers are not consistent about what they call the case reference, and
	// a missing one is recorded as empty rather than invented: the reference is
	// a fact about what the authority returned.
	for _, body := range []string{
		`{"case_reference":"CSIRT-1"}`,
		`{"reference":"CSIRT-2"}`,
		`{"id":"CSIRT-3"}`,
	} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		}))
		tr := NewReceiverTransport(Receiver{Endpoint: localURL(srv.URL)}, testClient())
		receipt, err := tr.Deliver(context.Background(), receiverPackage(t))
		require.NoError(t, err, body)
		assert.True(t, strings.HasPrefix(receipt.CaseReference, "CSIRT-"), body)
		srv.Close()
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer srv.Close()
	tr := NewReceiverTransport(Receiver{Endpoint: localURL(srv.URL)}, testClient())
	receipt, err := tr.Deliver(context.Background(), receiverPackage(t))
	require.NoError(t, err, "an unparseable body is not a delivery failure")
	assert.Empty(t, receipt.CaseReference, "no reference is invented")
}

func TestReceiverTransportRefusesTamperedPackages(t *testing.T) {
	called := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewReceiverTransport(Receiver{Endpoint: localURL(srv.URL)}, testClient())
	p := receiverPackage(t)
	p.Fields["v5"] = "rewritten after validation"

	_, err := tr.Deliver(context.Background(), p)
	require.Error(t, err)
	assert.False(t, called, "altered content is never sent to a receiver")
}

func TestRateLimitingIsADistinctFailure(t *testing.T) {
	// Backpressure is not a delivery failure. A retry worker that cannot tell
	// them apart burns its whole retry budget immediately and then gives up.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	tr := NewReceiverTransport(Receiver{Endpoint: localURL(srv.URL)}, testClient())
	_, err := tr.Deliver(context.Background(), receiverPackage(t))
	require.Error(t, err)

	var rate *RateLimitedError
	require.ErrorAs(t, err, &rate)
	assert.Equal(t, 120*time.Second, rate.RetryAfter)
}

func TestRateLimitedWithoutRetryAfterStillIsTyped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	tr := NewReceiverTransport(Receiver{Endpoint: localURL(srv.URL)}, testClient())
	_, err := tr.Deliver(context.Background(), receiverPackage(t))
	var rate *RateLimitedError
	require.ErrorAs(t, err, &rate)
	assert.Zero(t, rate.RetryAfter)
}

func TestNonSuccessStatusIsAFailure(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("rejected"))
		}))
		tr := NewReceiverTransport(Receiver{Endpoint: localURL(srv.URL)}, testClient())
		_, err := tr.Deliver(context.Background(), receiverPackage(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rejected")
		srv.Close()
	}
}

func TestReceiverTransportHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr := NewReceiverTransport(Receiver{Endpoint: localURL(srv.URL)}, testClient())
	_, err := tr.Deliver(ctx, receiverPackage(t))
	require.ErrorIs(t, err, context.Canceled)
}

// Both transports satisfy the interface, so swapping in an official ENISA API
// adapter when one exists is a drop-in change.
var (
	_ Transport = (*ReceiverTransport)(nil)
	_ Transport = (*ManualTransport)(nil)
)

// testClient trusts the httptest certificate.
//
// The test server's certificate is issued for example.com, not localhost, so a
// correctly-verifying client rejects it on hostname alone. InsecureSkipVerify
// is a TEST-ONLY concession; the transport itself never disables verification,
// and there is a test below asserting that a private-address endpoint is
// refused regardless.
func testClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   10 * time.Second,
	}
}

// localURL rewrites a loopback test server's address to the hostname
// "localhost". The SSRF guard blocks IP literals, which is correct — a
// compliance tool must not POST to a private address — and the guard checks
// hostnames, so a test that genuinely wants to reach a local server addresses
// it by name.
func localURL(u string) string { return strings.Replace(u, "127.0.0.1", "localhost", 1) }

var _ = tls.Config{}
