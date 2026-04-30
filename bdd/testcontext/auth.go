// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package testcontext

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
)

const testJWTSecret = "bdd-test-secret-key-must-be-at-least-32-bytes!!"

func GenerateToken(role string, orgID string) (string, error) {
	userID := uuid.New().String()
	now := time.Now()

	claims := middleware.Claims{
		Sub:     userID,
		Email:   fmt.Sprintf("%s@test.transparenz.local", role),
		OrgID:   orgID,
		OrgSlug: "test-corp",
		Roles:   []string{role},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(testJWTSecret))
}

func GenerateTokens(orgID string) (*TestTokens, error) {
	adminToken, err := GenerateToken("admin", orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate admin token: %w", err)
	}

	complianceToken, err := GenerateToken("compliance_officer", orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate compliance officer token: %w", err)
	}

	userToken, err := GenerateToken("user", orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user token: %w", err)
	}

	return &TestTokens{
		AdminToken:             adminToken,
		ComplianceOfficerToken: complianceToken,
		UserToken:              userToken,
	}, nil
}
