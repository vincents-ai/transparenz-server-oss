// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package middleware

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestComputeWebhookSignature_Consistent(t *testing.T) {
	body := []byte(`{"test":"data"}`)
	secret := "my-secret-key"

	sig1 := ComputeWebhookSignature(body, secret)
	sig2 := ComputeWebhookSignature(body, secret)

	assert.Equal(t, sig1, sig2)
	assert.Len(t, sig1, 64)
}

func TestComputeWebhookSignature_DifferentBodies(t *testing.T) {
	secret := "my-secret-key"

	sig1 := ComputeWebhookSignature([]byte(`{"a":1}`), secret)
	sig2 := ComputeWebhookSignature([]byte(`{"b":2}`), secret)

	assert.NotEqual(t, sig1, sig2)
}

func TestComputeWebhookSignature_DifferentSecrets(t *testing.T) {
	body := []byte(`{"test":"data"}`)

	sig1 := ComputeWebhookSignature(body, "secret-a")
	sig2 := ComputeWebhookSignature(body, "secret-b")

	assert.NotEqual(t, sig1, sig2)
}

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	secret := "test-secret"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := ComputeWebhookSignature(body, secret)

	err := VerifyWebhookSignature(body, secret, signature, timestamp)
	assert.NoError(t, err)
}

func TestVerifyWebhookSignature_InvalidSignature(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	secret := "test-secret"
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	err := VerifyWebhookSignature(body, secret, "invalid-signature", timestamp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")
}

func TestVerifyWebhookSignature_EmptySecret(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	err := VerifyWebhookSignature(body, "", "anything", timestamp)
	assert.NoError(t, err)
}

func TestVerifyWebhookSignature_InvalidTimestamp(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	secret := "test-secret"
	signature := ComputeWebhookSignature(body, secret)

	err := VerifyWebhookSignature(body, secret, signature, "not-a-number")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid timestamp format")
}

func TestVerifyWebhookSignature_ExpiredTimestamp(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	secret := "test-secret"
	oldTimestamp := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	signature := ComputeWebhookSignature(body, secret)

	err := VerifyWebhookSignature(body, secret, signature, oldTimestamp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside tolerance window")
}

func TestVerifyWebhookSignature_FutureTimestamp(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	secret := "test-secret"
	futureTimestamp := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)
	signature := ComputeWebhookSignature(body, secret)

	err := VerifyWebhookSignature(body, secret, signature, futureTimestamp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outside tolerance window")
}

func TestVerifyWebhookSignature_JustWithinTolerance(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	secret := "test-secret"
	withinTolerance := strconv.FormatInt(time.Now().Add(-4*time.Minute).Unix(), 10)
	signature := ComputeWebhookSignature(body, secret)

	err := VerifyWebhookSignature(body, secret, signature, withinTolerance)
	assert.NoError(t, err)
}
