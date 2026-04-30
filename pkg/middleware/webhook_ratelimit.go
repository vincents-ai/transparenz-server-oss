// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type keyVisitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// KeyRateLimiter manages per-key rate limiting using token buckets.
// Keys can be webhook IDs, org IDs, or any other identifier.
type KeyRateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*keyVisitor
	rate     rate.Limit
	burst    int
	stopCh   chan struct{}
}

// NewKeyRateLimiter creates a rate limiter with the given rate and burst capacity.
func NewKeyRateLimiter(r rate.Limit, burst int) *KeyRateLimiter {
	return &KeyRateLimiter{
		visitors: make(map[string]*keyVisitor),
		rate:     r,
		burst:    burst,
		stopCh:   make(chan struct{}),
	}
}

// Allow checks whether the given key is within rate limits.
func (rl *KeyRateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if v, exists := rl.visitors[key]; exists {
		v.lastSeen = time.Now()
		return v.limiter.Allow()
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.visitors[key] = &keyVisitor{limiter: limiter, lastSeen: time.Now()}
	return limiter.Allow()
}

// Cleanup removes entries not seen within the given duration.
func (rl *KeyRateLimiter) Cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for key, v := range rl.visitors {
		if time.Since(v.lastSeen) > maxAge {
			delete(rl.visitors, key)
		}
	}
}

// Stop terminates the background cleanup goroutine started by WebhookRateLimitMiddleware.
func (rl *KeyRateLimiter) Stop() {
	close(rl.stopCh)
}

// WebhookRateLimitMiddleware returns a Gin middleware that enforces per-webhook rate limits.
// The key is extracted from the context value set by webhook auth middleware (e.g., "greenbone_org_id" or "sbom_org_id").
// This protects against token compromise: even with a valid token, requests are capped per org.
func WebhookRateLimitMiddleware(limiter *KeyRateLimiter, contextKey string) gin.HandlerFunc {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				limiter.Cleanup(5 * time.Minute)
			case <-limiter.stopCh:
				return
			}
		}
	}()

	return func(c *gin.Context) {
		key := ""
		if val, exists := c.Get(contextKey); exists {
			switch v := val.(type) {
			case string:
				key = v
			case fmt.Stringer: // handles uuid.UUID
				key = v.String()
			}
		}
		if key == "" {
			// Fallback to client IP if no org key available
			key = c.ClientIP()
		}

		if !limiter.Allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"type":   "about:blank",
				"title":  "Too Many Requests",
				"status": 429,
				"detail": "webhook rate limit exceeded for this organization",
			})
			return
		}
		c.Next()
	}
}
