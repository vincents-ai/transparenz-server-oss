// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
// Package middleware provides HTTP middleware functions for the Transparenz server.
package middleware

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
)

type contextKey string

const orgIDContextKey contextKey = "org_id"

// ContextWithOrgID returns a new context with the org_id set for use by
// repository TenantScope outside of Gin request handlers (e.g. background workers).
func ContextWithOrgID(ctx context.Context, orgID uuid.UUID) context.Context {
	return context.WithValue(ctx, orgIDContextKey, orgID.String())
}

// GetOrgIDFromContext retrieves the organization ID from either a Gin context
// or a context.Context enriched via ContextWithOrgID.
func GetOrgIDFromContext(c any) (string, error) {
	switch ctx := c.(type) {
	case *gin.Context:
		orgIDInterface, exists := ctx.Get("org_id")
		if !exists {
			return "", errors.New("org_id not found in context")
		}
		orgID, ok := orgIDInterface.(string)
		if !ok {
			return "", errors.New("invalid org_id type in context")
		}
		if orgID == "" {
			return "", errors.New("org_id is empty")
		}
		return orgID, nil
	case context.Context:
		orgID, ok := ctx.Value(orgIDContextKey).(string)
		if !ok || orgID == "" {
			return "", errors.New("org_id not found in context")
		}
		return orgID, nil
	default:
		return "", errors.New("unsupported context type")
	}
}

// TenantMiddleware returns a Gin middleware handler that extracts and validates tenant context.
// This middleware MUST be placed after JWTMiddleware in the middleware chain, as it depends on
// JWT claims being present in the context.
//
// The middleware performs the following operations:
//   - Retrieves JWT claims from the context (set by JWTMiddleware)
//   - Extracts org_id (tenant UUID) from claims
//   - Validates that org_id is not empty
//   - Sets both org_id and org_slug in the Gin context for downstream handlers
//
// Returns:
//   - gin.HandlerFunc: The middleware function
//
// The middleware will abort the request with 401 Unauthorized if:
//   - JWT claims are missing from context (indicates JWT middleware was not run first)
//   - org_id is empty in the claims (user not associated with an organization)
//
// Example middleware chain order:
//
//	router.Use(LoggingMiddleware())
//	router.Use(JWTMiddleware(secret))
//	router.Use(TenantMiddleware())  // Must come AFTER JWT middleware
func TenantMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Retrieve JWT claims from context (set by JWTMiddleware)
		claims, err := GetClaimsFromContext(c)
		if err != nil {
			api.Unauthorized(c, "Authentication required: JWT claims not found")
			return
		}

		if claims.OrgID == "" {
			api.Unauthorized(c, "User is not associated with an organization")
			return
		}

		// Set tenant context in Gin context for downstream handlers
		c.Set("org_id", claims.OrgID)
		c.Set("org_slug", claims.OrgSlug)

		// Continue to the next handler
		c.Next()
	}
}

// ParseOrgIDMiddleware returns a Gin middleware handler that parses the org_id string
// from the context (set by TenantMiddleware) into a uuid.UUID and stores it under "org_uuid".
//
// This middleware MUST be placed after TenantMiddleware in the middleware chain.
//
// The middleware will abort the request with 401 Unauthorized if:
//   - org_id is not found in the context
//   - org_id cannot be parsed as a valid UUID
func ParseOrgIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgIDStr, err := GetOrgIDFromContext(c)
		if err != nil {
			api.Unauthorized(c, "organization ID not found in context")
			return
		}

		orgID, err := uuid.Parse(orgIDStr)
		if err != nil {
			api.Unauthorized(c, "invalid organization ID in context")
			return
		}

		c.Set("org_uuid", orgID)
		c.Next()
	}
}

// GetOrgUUIDFromContext retrieves the parsed organization UUID from the Gin context.
// This helper function should be called in handlers that have ParseOrgIDMiddleware
// in their middleware chain.
//
// Parameters:
//   - c: The Gin context
//
// Returns:
//   - uuid.UUID: The parsed organization UUID if found
//   - error: An error if org_uuid is not found or is of the wrong type
func GetOrgUUIDFromContext(c *gin.Context) (uuid.UUID, error) {
	orgUUIDInterface, exists := c.Get("org_uuid")
	if !exists {
		return uuid.Nil, errors.New("org_uuid not found in context")
	}

	orgUUID, ok := orgUUIDInterface.(uuid.UUID)
	if !ok {
		return uuid.Nil, errors.New("invalid org_uuid type in context")
	}

	return orgUUID, nil
}
