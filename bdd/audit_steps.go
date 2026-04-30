// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
)

const auditTestJWTSecret = "bdd-test-secret-key-must-be-at-least-32-bytes!!"

func RegisterAuditSteps(s *godog.ScenarioContext) {
	s.Step(`^I send a GET request to "([^"]*)" without authentication$`, auditGetNoAuth)
	s.Step(`^I send a GET request to "([^"]*)" with an expired JWT$`, auditGetExpired)
	s.Step(`^I send a PUT request to "([^"]*)" as a non-admin user$`, auditPutNonAdmin)
	s.Step(`^I verify the audit chain from "([^"]*)" to "([^"]*)"$`, auditVerifyChain)
	// Unhappy-path steps
	s.Step(`^I send a GET request to "([^"]*)" as a user-role JWT$`, auditGetAsUserRole)
	s.Step(`^I send a GET request to "([^"]*)" with a tampered JWT$`, auditGetTamperedJWT)
}

func auditGetNoAuth(path string) error {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func auditGetExpired(path string) error {
	token, err := generateExpiredToken(tc().OrgID)
	if err != nil {
		return fmt.Errorf("failed to generate expired token: %w", err)
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func auditPutNonAdmin(path string) error {
	body := strings.NewReader(`{"months":12}`)
	req := httptest.NewRequest(http.MethodPut, path, body)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.UserToken)
	req.Header.Set("Content-Type", "application/json")
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func auditVerifyChain(start, end string) error {
	url := fmt.Sprintf("/api/audit/verify?start=%s&end=%s", start, end)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.AdminToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

func generateExpiredToken(orgID string) (string, error) {
	now := time.Now()
	claims := middleware.Claims{
		Sub:     uuid.New().String(),
		Email:   "expired@test.transparenz.local",
		OrgID:   orgID,
		OrgSlug: "test-corp",
		Roles:   []string{"user"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(auditTestJWTSecret))
}

// auditGetAsUserRole sends a GET request using the UserToken (role: "user").
// Endpoints restricted to admin/compliance_officer should return 403.
func auditGetAsUserRole(path string) error {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+tc().Tokens.UserToken)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}

// auditGetTamperedJWT sends a GET request with a JWT whose signature has been corrupted.
// The server should reject it with 401.
func auditGetTamperedJWT(path string) error {
	validToken := tc().Tokens.AdminToken
	// Tamper by appending garbage to the signature segment
	tampered := validToken + "TAMPERED"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	lastResponse = httptest.NewRecorder()
	tc().Router.ServeHTTP(lastResponse, req)
	return nil
}
