// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
)

// workerScanRepository defines the scan data-access operations required by ScanWorker.
type workerScanRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Scan, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	Update(ctx context.Context, scan *models.Scan) error
}

// workerVulnerabilityRepository defines the vulnerability data-access operations required by ScanWorker.
type workerVulnerabilityRepository interface {
	Create(ctx context.Context, orgID uuid.UUID, vuln *models.Vulnerability) error
}

// workerVulnerabilityFeedRepository defines the feed data-access operations required by ScanWorker.
type workerVulnerabilityFeedRepository interface {
	GetByCVE(ctx context.Context, cve string) (*models.VulnerabilityFeed, error)
}

// workerSbomRepository defines the SBOM data-access operations required by ScanWorker.
type workerSbomRepository interface {
	GetDocumentAndFormatFromPublic(ctx context.Context, id uuid.UUID) (*repository.SbomDocumentResult, error)
}

// workerGRCMappingRepository defines the GRC mapping data-access operations required by ScanWorker.
type workerGRCMappingRepository interface {
	DeleteByVulnerability(ctx context.Context, orgID uuid.UUID, vulnID string) error
	CreateBatch(ctx context.Context, mappings []models.GRCMapping) error
}

// workerScanVulnerabilityRepository defines the scan-vulnerability data-access operations required by ScanWorker.
type workerScanVulnerabilityRepository interface {
	CreateBatch(ctx context.Context, records []models.ScanVulnerability) error
}
