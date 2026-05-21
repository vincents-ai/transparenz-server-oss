// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/internal/testutil"
)

func TestGRCMappingRepository_CreateAndGet(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	org := testutil.CreateTestOrg(t, db)

	vuln := &models.Vulnerability{OrgID: org.ID, Cve: "CVE-2024-TEST1", Severity: "high"}
	require.NoError(t, db.Create(vuln).Error)

	mappings := []models.GRCMapping{
		{
			OrgID:           org.ID,
			VulnerabilityID: &vuln.ID,
			ControlID:       "PCI_DSS_v4/6.5",
			Framework:       "PCI_DSS_v4",
			MappingType:     "cwe",
			Confidence:      0.8,
			Evidence:        "CWE-502 direct match",
		},
	}

	repo := NewGRCMappingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	require.NoError(t, repo.CreateBatch(ctx, mappings))

	results, err := repo.ListByVulnerabilityID(ctx, vuln.ID)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "PCI_DSS_v4", results[0].Framework)
}

func TestGRCMappingRepository_CreateBatch(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	org := testutil.CreateTestOrg(t, db)

	mappings := []models.GRCMapping{
		{OrgID: org.ID, ControlID: "ISO_27001_2022/A.8.25", Framework: "ISO_27001_2022", MappingType: "cwe", Confidence: 0.8},
		{OrgID: org.ID, ControlID: "NIST_CSF_2_0/PR.IR-05", Framework: "NIST_CSF_2_0", MappingType: "cpe", Confidence: 0.6},
	}

	repo := NewGRCMappingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	require.NoError(t, repo.CreateBatch(ctx, mappings))

	results, err := repo.CountByFramework(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), results["ISO_27001_2022"])
	require.Equal(t, int64(1), results["NIST_CSF_2_0"])
}

func TestGRCMappingRepository_DeleteByVulnerability(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	org := testutil.CreateTestOrg(t, db)

	vuln := &models.Vulnerability{OrgID: org.ID, Cve: "CVE-2024-DELETE", Severity: "critical"}
	require.NoError(t, db.Create(vuln).Error)

	mappings := []models.GRCMapping{
		{
			OrgID:           org.ID,
			VulnerabilityID: &vuln.ID,
			ControlID:       "HIPAA_SECURITY_RULE_2013/164.308(a)(5)(ii)(B)",
			Framework:       "HIPAA_SECURITY_RULE_2013",
			MappingType:     "cwe",
			Confidence:      0.8,
		},
	}

	repo := NewGRCMappingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	require.NoError(t, repo.CreateBatch(ctx, mappings))

	allMappings, err := repo.ListByOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, allMappings, 1)

	require.NoError(t, repo.DeleteByVulnerability(ctx, org.ID, vuln.Cve))

	allMappingsAfter, err := repo.ListByOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, allMappingsAfter, 0)
}

func TestGRCMappingRepository_ListByVulnerabilityIDs(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	org := testutil.CreateTestOrg(t, db)

	vuln1 := &models.Vulnerability{OrgID: org.ID, Cve: "CVE-2024-BULK-1", Severity: "high"}
	vuln2 := &models.Vulnerability{OrgID: org.ID, Cve: "CVE-2024-BULK-2", Severity: "medium"}
	require.NoError(t, db.Create(vuln1).Error)
	require.NoError(t, db.Create(vuln2).Error)

	mappings := []models.GRCMapping{
		{OrgID: org.ID, VulnerabilityID: &vuln1.ID, ControlID: "NIST_CSF_2_0/DE.CM-01", Framework: "NIST_CSF_2_0", MappingType: "cwe", Confidence: 0.9},
		{OrgID: org.ID, VulnerabilityID: &vuln1.ID, ControlID: "NIST_CSF_2_0/DE.CM-02", Framework: "NIST_CSF_2_0", MappingType: "cpe", Confidence: 0.7},
		{OrgID: org.ID, VulnerabilityID: &vuln2.ID, ControlID: "NIST_CSF_2_0/PR.PS-01", Framework: "NIST_CSF_2_0", MappingType: "cve", Confidence: 0.5},
	}

	repo := NewGRCMappingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	require.NoError(t, repo.CreateBatch(ctx, mappings))

	results, err := repo.ListByVulnerabilityIDs(ctx, []uuid.UUID{vuln1.ID, vuln2.ID})
	require.NoError(t, err)
	require.Len(t, results, 3)
}

func TestGRCMappingRepository_CountDistinctVulnsWithMappings(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	org := testutil.CreateTestOrg(t, db)

	vuln1 := &models.Vulnerability{OrgID: org.ID, Cve: "CVE-2024-COUNT-1", Severity: "high"}
	vuln2 := &models.Vulnerability{OrgID: org.ID, Cve: "CVE-2024-COUNT-2", Severity: "medium"}
	require.NoError(t, db.Create(vuln1).Error)
	require.NoError(t, db.Create(vuln2).Error)

	mappings := []models.GRCMapping{
		{OrgID: org.ID, VulnerabilityID: &vuln1.ID, ControlID: "ISO_27001/A.8.1", Framework: "ISO_27001", MappingType: "cwe", Confidence: 0.9},
		{OrgID: org.ID, VulnerabilityID: &vuln2.ID, ControlID: "ISO_27001/A.8.2", Framework: "ISO_27001", MappingType: "cpe", Confidence: 0.7},
		{OrgID: org.ID, VulnerabilityID: &vuln2.ID, ControlID: "ISO_27001/A.8.3", Framework: "ISO_27001", MappingType: "cve", Confidence: 0.5},
	}

	repo := NewGRCMappingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	require.NoError(t, repo.CreateBatch(ctx, mappings))

	count, err := repo.CountDistinctVulnsWithMappings(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), count)
}

func TestGRCMappingRepository_ListByOrg(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	org := testutil.CreateTestOrg(t, db)

	vuln := &models.Vulnerability{OrgID: org.ID, Cve: "CVE-2024-ORG", Severity: "high"}
	require.NoError(t, db.Create(vuln).Error)

	mappings := []models.GRCMapping{
		{OrgID: org.ID, VulnerabilityID: &vuln.ID, ControlID: "PCI_DSS_v4/6.5", Framework: "PCI_DSS_v4", MappingType: "cwe", Confidence: 0.9},
		{OrgID: org.ID, VulnerabilityID: &vuln.ID, ControlID: "ISO_27001/A.8.1", Framework: "ISO_27001", MappingType: "cwe", Confidence: 0.8},
	}

	repo := NewGRCMappingRepository(db)
	ctx := middleware.ContextWithOrgID(context.Background(), org.ID)
	require.NoError(t, repo.CreateBatch(ctx, mappings))

	results, err := repo.ListByOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, results, 2)
}

func TestGRCMappingRepository_TenantIsolation(t *testing.T) {
	db := testutil.SetupTestDB(t, "organizations", "vulnerabilities", "grc_mappings")
	orgA := testutil.CreateTestOrg(t, db)
	orgB := testutil.CreateTestOrg(t, db)

	vulnA := &models.Vulnerability{OrgID: orgA.ID, Cve: "CVE-2024-ORG-A", Severity: "high"}
	vulnB := &models.Vulnerability{OrgID: orgB.ID, Cve: "CVE-2024-ORG-B", Severity: "medium"}
	require.NoError(t, db.Create(vulnA).Error)
	require.NoError(t, db.Create(vulnB).Error)

	mappingsA := []models.GRCMapping{{OrgID: orgA.ID, VulnerabilityID: &vulnA.ID, ControlID: "ISO/A.1", Framework: "ISO", MappingType: "cwe", Confidence: 0.9}}
	mappingsB := []models.GRCMapping{{OrgID: orgB.ID, VulnerabilityID: &vulnB.ID, ControlID: "PCI/1.1", Framework: "PCI", MappingType: "cve", Confidence: 0.8}}

	repo := NewGRCMappingRepository(db)
	ctxA := middleware.ContextWithOrgID(context.Background(), orgA.ID)
	ctxB := middleware.ContextWithOrgID(context.Background(), orgB.ID)
	require.NoError(t, repo.CreateBatch(ctxA, mappingsA))
	require.NoError(t, repo.CreateBatch(ctxB, mappingsB))

	resultsA, err := repo.ListByOrg(ctxA, orgA.ID)
	require.NoError(t, err)
	require.Len(t, resultsA, 1)
	require.Equal(t, "ISO", resultsA[0].Framework)

	resultsB, err := repo.ListByOrg(ctxB, orgB.ID)
	require.NoError(t, err)
	require.Len(t, resultsB, 1)
	require.Equal(t, "PCI", resultsB[0].Framework)
}
