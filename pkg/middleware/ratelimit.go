// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter manages per-IP rate limiting using token buckets.
type IPRateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*visitor
	rate     rate.Limit
	burst    int
	stopCh   chan struct{}
}

// NewIPRateLimiter creates a rate limiter with the given rate and burst capacity.
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		visitors: make(map[string]*visitor),
		rate:     r,
		burst:    b,
		stopCh:   make(chan struct{}),
	}
}

func (rl *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if v, exists := rl.visitors[ip]; exists {
		v.lastSeen = time.Now()
		return v.limiter
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.visitors[ip] = &visitor{limiter: limiter, lastSeen: time.Now()}
	return limiter
}

func (rl *IPRateLimiter) cleanupStaleVisitors() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, v := range rl.visitors {
		if time.Since(v.lastSeen) > 3*time.Minute {
			delete(rl.visitors, ip)
		}
	}
}

func (rl *IPRateLimiter) Stop() {
	close(rl.stopCh)
}

// RateLimitMiddleware returns a Gin middleware that enforces per-IP rate limits.
func RateLimitMiddleware(limiter *IPRateLimiter) gin.HandlerFunc {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				limiter.cleanupStaleVisitors()
			case <-limiter.stopCh:
				return
			}
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()
		lim := limiter.getLimiter(ip)

		allowed := lim.Allow()

		remaining := int(lim.Tokens())
		if remaining < 0 {
			remaining = 0
		}

		r := lim.ReserveN(time.Now(), 1)
		resetAt := time.Now().Add(r.Delay()).Unix()
		r.Cancel()

		c.Header("X-RateLimit-Limit", strconv.Itoa(limiter.burst))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(resetAt, 10))

		if !allowed {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"type":   "about:blank",
				"title":  "Too Many Requests",
				"status": 429,
				"detail": "rate limit exceeded",
			})
			return
		}
		c.Next()
	}
}
