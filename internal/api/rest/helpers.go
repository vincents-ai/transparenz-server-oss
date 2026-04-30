// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package rest

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
)

func orgContext(c *gin.Context) (context.Context, error) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		return nil, err
	}
	return middleware.ContextWithOrgID(c.Request.Context(), orgUUID), nil
}
