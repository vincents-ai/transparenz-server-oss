// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.
package rest

import (
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
	"go.uber.org/zap"
)

func ErrorRecoveryMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				logger.Error("panic recovered",
					zap.Any("error", r),
					zap.String("stack", string(stack)),
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
				)
				api.RespondWithProblem(c, http.StatusInternalServerError, api.ProblemDetail{
					Type:   api.ErrInternal,
					Title:  "Internal Server Error",
					Status: http.StatusInternalServerError,
					Detail: "An unexpected error occurred. Please try again later.",
				})
			}
		}()
		c.Next()
	}
}
