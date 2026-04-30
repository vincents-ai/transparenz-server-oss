// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/internal/models"
)

// signingKeyID holds the active signing key ID discovered during a scenario.
var signingKeyID string

// RegisterSigningSteps registers all step definitions for signing_key_management.feature.
func RegisterSigningSteps(s *godog.ScenarioContext) {
	s.Step(`^the organisation has an active signing key$`, signingEnsureActiveKey)
	s.Step(`^I send DELETE to "([^"]*)"$`, signingDelete)
}

// signingEnsureActiveKey looks up or creates an active signing key for the test org and stores its ID.
func signingEnsureActiveKey() error {
	ctx := tc()
	orgID := uuid.MustParse(ctx.OrgID)

	var key models.SigningKey
	err := ctx.DB.Where("org_id = ? AND revoked_at IS NULL", orgID).
		Order("created_at DESC").
		First(&key).Error
	if err != nil {
		// No active key yet — create one directly in the DB so the scenario has something to revoke.
		key = models.SigningKey{
			ID:           uuid.New(),
			OrgID:        orgID,
			PublicKey:    "00000000000000000000000000000000000000000000000000000000000000000000",
			KeyAlgorithm: "ed25519",
		}
		if dbErr := ctx.DB.Create(&key).Error; dbErr != nil {
			return fmt.Errorf("failed to create signing key for scenario: %w", dbErr)
		}
	}

	signingKeyID = key.ID.String()
	return nil
}

// signingDelete performs a DELETE request, substituting {org_id} and {key_id} placeholders.
func signingDelete(path string) error {
	ctx := tc()

	path = strings.ReplaceAll(path, "{org_id}", ctx.OrgID)
	path = strings.ReplaceAll(path, "{key_id}", signingKeyID)

	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req.Header.Set("Authorization", "Bearer "+ctx.Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	ctx.Router.ServeHTTP(lastResponse, req)
	return nil
}
