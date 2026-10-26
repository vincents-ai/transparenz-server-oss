// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const defaultMaxBodyBytes int64 = 4 * 1024 * 1024 // 4 MiB

// MaxBodySize returns a Gin middleware that limits request body size to maxBytes.
// Requests exceeding the limit receive a 413 Request Entity Too Large response.
func MaxBodySize(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// DefaultBodyLimit returns MaxBodySize with the default 4 MiB limit.
func DefaultBodyLimit() gin.HandlerFunc {
	return MaxBodySize(defaultMaxBodyBytes)
}
