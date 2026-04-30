// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
// Package middleware provides HTTP middleware functions for the Transparenz server.
package middleware

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/transparenz/transparenz-server-oss/internal/api"
)

// TokenIssuer is the expected issuer claim for JWT tokens.
const TokenIssuer = "auth-service"

// TokenAudience is the expected audience claim for JWT tokens.
const TokenAudience = "transparenz-server"

// Claims represents the JWT claims structure for authenticated users.
// It includes user identity, organization/tenant information, and role-based permissions.
type Claims struct {
	Sub     string   `json:"sub"`      // User UUID
	Email   string   `json:"email"`    // User email
	OrgID   string   `json:"org_id"`   // Tenant/Organization UUID
	OrgSlug string   `json:"org_slug"` // Human-readable tenant identifier
	Roles   []string `json:"roles"`    // User roles (admin, compliance_officer, etc.)
	jwt.RegisteredClaims
}

// JWTMiddleware returns a Gin middleware handler that validates JWT tokens.
// It extracts the token from the Authorization header, validates it using the provided secret,
// and sets the parsed claims in the Gin context for downstream handlers.
//
// Parameters:
//   - jwtSecret: The secret key used to validate JWT signatures
//
// Returns:
//   - gin.HandlerFunc: The middleware function
//
// The middleware will abort the request with 401 Unauthorized if:
//   - The Authorization header is missing or malformed
//   - The token is invalid or expired
//   - The token cannot be parsed
func JWTMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			api.Unauthorized(c, "Authorization header is required")
			return
		}

		// Check for Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			api.Unauthorized(c, "Authorization header must be in format: Bearer <token>")
			return
		}

		tokenString := parts[1]

		// Parse and validate the token
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil {
			// Check if the error is due to token expiration
			if errors.Is(err, jwt.ErrTokenExpired) {
				api.Unauthorized(c, "Token has expired")
				return
			}

			api.Unauthorized(c, "Invalid token")
			return
		}

		// Extract claims from the validated token
		claims, ok := token.Claims.(*Claims)
		if !ok || !token.Valid {
			api.Unauthorized(c, "Invalid token claims")
			return
		}

		// Validate issuer and audience when present in the token.
		// This ensures forward compatibility with tokens that include iss/aud
		// while accepting legacy tokens that don't.
		if claims.Issuer != "" && claims.Issuer != TokenIssuer {
			api.Unauthorized(c, "Invalid token issuer")
			return
		}
		if len(claims.Audience) > 0 {
			audMatch := false
			for _, aud := range claims.Audience {
				if aud == TokenAudience {
					audMatch = true
					break
				}
			}
			if !audMatch {
				api.Unauthorized(c, "Invalid token audience")
				return
			}
		}

		// Set claims in context for downstream handlers
		c.Set("claims", claims)

		// Continue to the next handler
		c.Next()
	}
}

// GetClaimsFromContext retrieves the JWT claims from the Gin context.
// This helper function should be called in handlers that require access to the authenticated user's information.
//
// Parameters:
//   - c: The Gin context
//
// Returns:
//   - *Claims: The JWT claims if found
//   - error: An error if claims are not found or are of the wrong type
//
// Example usage:
//
//	func MyHandler(c *gin.Context) {
//	    claims, err := GetClaimsFromContext(c)
//	    if err != nil {
//	        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user claims"})
//	        return
//	    }
//	    // Use claims.Sub, claims.OrgID, etc.
//	}
func GetClaimsFromContext(c *gin.Context) (*Claims, error) {
	claimsInterface, exists := c.Get("claims")
	if !exists {
		return nil, errors.New("claims not found in context")
	}

	claims, ok := claimsInterface.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims type in context")
	}

	return claims, nil
}
