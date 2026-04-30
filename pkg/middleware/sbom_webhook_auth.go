// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package middleware

import (
	"bytes"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/api"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SbomWebhookAuthMiddleware returns a Gin middleware that authenticates SBOM webhook requests.
func SbomWebhookAuthMiddleware(db *gorm.DB, updater *LastUsedAtUpdater) gin.HandlerFunc {
	return func(c *gin.Context) {
		idParam := c.Param("id")
		webhookID, err := uuid.Parse(idParam)
		if err != nil {
			api.Unauthorized(c, "invalid webhook ID")
			return
		}

		var webhook models.SbomWebhook
		if err := db.Where("id = ?", webhookID).First(&webhook).Error; err != nil {
			api.Unauthorized(c, "webhook not found")
			return
		}

		if !webhook.Active {
			api.Forbidden(c, "webhook is deactivated")
			return
		}

		token := c.GetHeader("X-SBOM-Token")
		if token == "" {
			api.Unauthorized(c, "X-SBOM-Token header is required")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(webhook.SecretHash), []byte(token)); err != nil {
			api.Unauthorized(c, "invalid webhook token")
			return
		}

		if webhook.SigningSecret != "" {
			signature := c.GetHeader("X-Webhook-Signature")
			timestamp := c.GetHeader("X-Webhook-Timestamp")
			body, _ := io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
			if err := VerifyWebhookSignature(body, webhook.SigningSecret, signature, timestamp); err != nil {
				api.Unauthorized(c, "webhook signature verification failed: "+err.Error())
				return
			}
		}

		c.Set("sbom_org_id", webhook.OrgID)
		c.Set("sbom_actions", webhook.Actions)

		if updater != nil {
			updater.Schedule(webhook.ID)
		}

		c.Next()
	}
}
