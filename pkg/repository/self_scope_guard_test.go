package repository

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/stretchr/testify/assert"
)

// ginCtxWithOrg creates a *gin.Context with the given orgID set.
func ginCtxWithOrg(t *testing.T, orgID string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	c.Set("org_id", orgID)
	return c
}

// TestSelfScopeGuard_AllowsOwner verifies that SelfScopeGuard allows access
// when the context org matches the record's org.
func TestSelfScopeGuard_AllowsOwner(t *testing.T) {
	orgID := uuid.New()
	ctx := ginCtxWithOrg(t, orgID.String())

	err := SelfScopeGuard(ctx, orgID)
	assert.NoError(t, err)
}

// TestSelfScopeGuard_BlocksCrossTenant verifies that SelfScopeGuard blocks
// cross-tenant access when context org differs from record's org.
func TestSelfScopeGuard_BlocksCrossTenant(t *testing.T) {
	orgA := uuid.New()
	orgB := uuid.New()
	ctx := ginCtxWithOrg(t, orgA.String())

	err := SelfScopeGuard(ctx, orgB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "self-scope violation")
	assert.Contains(t, err.Error(), orgB.String())
	assert.Contains(t, err.Error(), orgA.String())
}

// TestSelfScopeGuard_AdminBypass verifies that admin-level access (no org context)
// bypasses the guard.
func TestSelfScopeGuard_AdminBypass(t *testing.T) {
	orgID := uuid.New()
	ctx := context.Background()

	err := SelfScopeGuard(ctx, orgID)
	assert.NoError(t, err)
}

// TestSelfScopeGuard_EmptyOrgContext verifies empty org_id bypasses the guard.
func TestSelfScopeGuard_EmptyOrgContext(t *testing.T) {
	orgID := uuid.New()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	c.Set("org_id", "")

	err := SelfScopeGuard(c, orgID)
	assert.NoError(t, err)
}

// TestSelfScopeGuard_Regression_CRIT1 is the deterministic regression test
// for CRITICAL-1: tenant isolation via SelfScopeGuard.
// Org A and Org B share the same name but have different UUIDs.
// A record owned by org A must not pass the guard under org B's context.
func TestSelfScopeGuard_Regression_CRIT1(t *testing.T) {
	orgAID := uuid.New()
	orgBID := uuid.New()
	sameName := "Acme Corp"

	_ = models.Organization{ID: orgAID, Name: sameName}
	_ = models.Organization{ID: orgBID, Name: sameName}

	recordOrgID := orgAID

	// Attempt SelfScopeGuard under org B's context — must fail
	ctxB := ginCtxWithOrg(t, orgBID.String())
	err := SelfScopeGuard(ctxB, recordOrgID)
	assert.Error(t, err, "SelfScopeGuard must block cross-tenant access even when orgs share the same name")
	assert.Contains(t, err.Error(), "self-scope violation")

	// Attempt SelfScopeGuard under org A's context — must succeed
	ctxA := ginCtxWithOrg(t, orgAID.String())
	err = SelfScopeGuard(ctxA, recordOrgID)
	assert.NoError(t, err, "SelfScopeGuard must allow access when org IDs match")

	// Admin-level bypass (no org context)
	ctxAdmin := context.Background()
	err = SelfScopeGuard(ctxAdmin, recordOrgID)
	assert.NoError(t, err, "SelfScopeGuard must allow admin-level access with no org context")
}
