// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.
package rest

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
)

func orgContext(c *gin.Context) (context.Context, error) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		return nil, err
	}
	return middleware.ContextWithOrgID(c.Request.Context(), orgUUID), nil
}
