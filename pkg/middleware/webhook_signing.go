// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// WebhookTimestampTolerance is the maximum allowed clock skew for webhook timestamps.
const WebhookTimestampTolerance = 5 * time.Minute

// ComputeWebhookSignature computes an HMAC-SHA256 signature for the given body.
func ComputeWebhookSignature(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature verifies the HMAC-SHA256 signature and timestamp of a webhook request.
func VerifyWebhookSignature(body []byte, secret, signature, timestamp string) error {
	if secret == "" {
		return nil
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp format")
	}

	reqTime := time.Unix(ts, 0)
	now := time.Now()
	if now.Sub(reqTime) > WebhookTimestampTolerance || reqTime.Sub(now) > WebhookTimestampTolerance {
		return fmt.Errorf("request timestamp outside tolerance window")
	}

	expected := ComputeWebhookSignature(body, secret)
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}
