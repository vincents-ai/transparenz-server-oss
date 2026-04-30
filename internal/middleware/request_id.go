// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package middleware

import (
	"fmt"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// requestIDPattern allows alphanumeric chars, dashes, underscores, dots.
// Rejects control characters, newlines, and excessively long values.
var requestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// RequestIDMiddleware returns a Gin middleware that assigns a unique request ID.
// If the client supplies X-Request-ID, it is validated against a safe character set.
// Invalid values are rejected and a server-generated ID is used instead.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" || !requestIDPattern.MatchString(requestID) {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// FormatRequestID is exported for use in tests.
func FormatRequestID(s string) string {
	if requestIDPattern.MatchString(s) {
		return s
	}
	return fmt.Sprintf("<invalid-request-id: len=%d>", len(s))
}
