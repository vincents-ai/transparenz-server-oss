// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
// Package config provides configuration utilities for the transparenz-server.
// This includes structured logging setup using zap and HTTP middleware for request logging.
package config

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// InitLogger initializes and returns a configured zap.Logger with the specified log level.
// The logger outputs structured JSON logs suitable for production environments.
//
// Parameters:
//   - logLevel: desired log level (debug, info, warn, error)
//
// Returns:
//   - *zap.Logger: configured logger instance
//   - error: if the log level is invalid or logger creation fails
func InitLogger(logLevel string) (*zap.Logger, error) {
	// Parse log level string to zapcore.Level
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", logLevel, err)
	}

	// Create production config with custom level
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(level)

	// Build the logger
	logger, err := config.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return logger, nil
}

// LoggingMiddleware returns a Gin middleware handler that logs HTTP requests with structured logging.
// It captures request details including method, path, status code, duration, and organization ID.
//
// Log levels are assigned based on response status codes:
//   - 2xx responses: Info level
//   - 4xx responses: Warn level
//   - 5xx responses: Error level
//
// Parameters:
//   - logger: zap.Logger instance to use for logging
//
// Returns:
//   - gin.HandlerFunc: middleware handler function
func LoggingMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Record start time
		start := time.Now()

		// Process request
		c.Next()

		// Calculate request duration
		duration := time.Since(start).Milliseconds()

		// Extract request details
		method := c.Request.Method
		path := c.Request.URL.Path
		status := c.Writer.Status()

		// Extract org_id from context (empty string if not present)
		orgID, exists := c.Get("org_id")
		orgIDStr := ""
		if exists {
			if id, ok := orgID.(string); ok {
				orgIDStr = id
			}
		}

		// Create structured log fields
		requestID := c.GetString("request_id")

		fields := []zap.Field{
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", status),
			zap.Int64("duration", duration),
			zap.String("org_id", orgIDStr),
			zap.String("request_id", requestID),
		}

		// Log with appropriate level based on status code
		switch {
		case status >= 500:
			logger.Error("HTTP request", fields...)
		case status >= 400:
			logger.Warn("HTTP request", fields...)
		default:
			logger.Info("HTTP request", fields...)
		}
	}
}
