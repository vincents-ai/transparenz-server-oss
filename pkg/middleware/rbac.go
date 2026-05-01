// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
)

// RequireRole returns a Gin middleware that enforces role-based access control.
func RequireRole(roles ...string) gin.HandlerFunc {
	roleSet := make(map[string]bool, len(roles))
	for _, r := range roles {
		roleSet[r] = true
	}
	return func(c *gin.Context) {
		claims, err := GetClaimsFromContext(c)
		if err != nil {
			api.Unauthorized(c, "authentication required")
			c.Abort()
			return
		}
		for _, userRole := range claims.Roles {
			if roleSet[userRole] {
				c.Next()
				return
			}
		}
		api.Forbidden(c, "insufficient permissions")
		c.Abort()
	}
}
