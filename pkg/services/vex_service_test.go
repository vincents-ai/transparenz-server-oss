// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
	"go.uber.org/zap"
)

func TestAutoDraftVEX_Basic(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "vex_statements", "vex_publications")
	stmtRepo := repository.NewVexStatementRepository(db)
	org := testutil.CreateTestOrg(t, db)
	svc := &VEXService{
		stmtRepo: stmtRepo,
		db:       db,
		logger:   zap.NewNop(),
	}
	stmt, err := svc.AutoDraftVEX(context.Background(), org.ID, "CVE-2024-1234", "product-1")
	if err != nil {
		t.Fatal(err)
	}
	if stmt.CVE != "CVE-2024-1234" {
		t.Errorf("expected CVE CVE-2024-1234, got %s", stmt.CVE)
	}
	if stmt.Status != "draft" {
		t.Errorf("expected status draft, got %s", stmt.Status)
	}
	if stmt.ProductID != "product-1" {
		t.Errorf("expected product_id product-1, got %s", stmt.ProductID)
	}
}

func TestAutoDraftVEX_ExploitedInWild(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "vex_statements", "vex_publications")
	stmtRepo := repository.NewVexStatementRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	org := testutil.CreateTestOrg(t, db)

	vuln := &models.Vulnerability{
		OrgID:           org.ID,
		Cve:             "CVE-2024-5678",
		Severity:        "high",
		ExploitedInWild: true,
	}
	require.NoError(t, db.Create(vuln).Error)

	svc := &VEXService{
		stmtRepo: stmtRepo,
		vulnRepo: vulnRepo,
		db:       db,
		logger:   zap.NewNop(),
	}
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	stmt, err := svc.AutoDraftVEX(ctx, org.ID, "CVE-2024-5678", "product-2")
	if err != nil {
		t.Fatal(err)
	}
	if stmt.Justification != "vulnerable_code_cannot_be_controlled_by_adversary" {
		t.Errorf("expected justification for exploited vuln, got %s", stmt.Justification)
	}
	if stmt.Confidence != "high" {
		t.Errorf("expected high confidence for exploited vuln, got %s", stmt.Confidence)
	}
}

func TestAutoDraftVEX_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "vex_statements", "vex_publications")
	stmtRepo := repository.NewVexStatementRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	org := testutil.CreateTestOrg(t, db)
	svc := &VEXService{
		stmtRepo: stmtRepo,
		vulnRepo: vulnRepo,
		db:       db,
		logger:   zap.NewNop(),
	}
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	stmt, err := svc.AutoDraftVEX(ctx, org.ID, "CVE-2024-9999", "product-1")
	if err != nil {
		t.Fatal(err)
	}
	if stmt.Justification != "component_not_present" {
		t.Errorf("expected component_not_present for unknown vuln, got %s", stmt.Justification)
	}
	if stmt.Confidence != "unknown" {
		t.Errorf("expected unknown confidence for unknown vuln, got %s", stmt.Confidence)
	}
}
