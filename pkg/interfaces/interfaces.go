// Package interfaces defines common interfaces for transparenz-server.
// These interfaces are extracted from services and API layers for better organization and testability.
// All interfaces and methods include proper GoDoc documentation.
package interfaces

import (
	"context"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

// ScanWorker defines the interface for scan worker operations.
// It provides methods to enqueue scans for asynchronous processing.
type ScanWorker interface {
	// EnqueueScan queues a scan for background processing.
	EnqueueScan(ctx context.Context, scanID, orgID, sbomID uuid.UUID) error
}

// ScanRepository defines the interface for scan data operations.
// It provides methods to create, retrieve, and list vulnerability scans.
type ScanRepository interface {
	// Create stores a new scan for the given organization.
	Create(ctx context.Context, orgID uuid.UUID, scan *models.Scan) error

	// GetByID retrieves a scan by its UUID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.Scan, error)

	// Count returns the total number of scans in the system.
	Count(ctx context.Context) (int64, error)

	// List returns a paginated list of scans.
	List(ctx context.Context, limit, offset int) ([]models.Scan, error)
}

// SbomRepository defines the interface for SBOM data operations.
// It provides methods to check existence of SBOM records.
type SbomRepository interface {
	// ExistsByID checks if an SBOM with the given ID exists.
	ExistsByID(ctx context.Context, id uuid.UUID) (bool, error)
}

// DisclosureRepository defines the interface for vulnerability disclosure operations.
// It provides methods to create, retrieve, and list vulnerability disclosures.
type DisclosureRepository interface {
	// Create stores a new vulnerability disclosure for the given organization.
	Create(ctx context.Context, orgID uuid.UUID, disclosure *models.VulnerabilityDisclosure) error

	// GetByID retrieves a vulnerability disclosure by its UUID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.VulnerabilityDisclosure, error)

	// List returns a paginated list of vulnerability disclosures.
	List(ctx context.Context, limit, offset int) ([]models.VulnerabilityDisclosure, error)

	// Count returns the total number of vulnerability disclosures.
	Count(ctx context.Context) (int64, error)

	// Update modifies an existing vulnerability disclosure.
	Update(ctx context.Context, disclosure *models.VulnerabilityDisclosure) error

	// UpdateStatus changes the status of a vulnerability disclosure.
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error

	// ListByStatus returns vulnerability disclosures filtered by status.
	ListByStatus(ctx context.Context, status string, limit, offset int) ([]models.VulnerabilityDisclosure, error)
}

// ENISASubmitter defines the interface for ENISA submission operations.
// It provides methods to submit vulnerability data to the European cybersecurity agency.
type ENISASubmitter interface {
	// Submit sends a CVE to ENISA for processing and returns the submission record.
	Submit(ctx context.Context, orgID uuid.UUID, cve string, metadata models.JSONMap) (*models.EnisaSubmission, error)
}

// PDFGenerator defines the interface for PDF generation operations.
// It provides methods to generate PDF reports from structured data.
type PDFGenerator interface {
	// GeneratePDF creates a PDF document from the given report data.
	GeneratePDF(data models.PDFReportData) ([]byte, error)
}

// SigningService defines the interface for signing key management.
type SigningService interface {
	// RevokeKey revokes a signing key for an organization.
	RevokeKey(ctx context.Context, orgID string, keyID string) error
}

// GreenboneService defines the interface for Greenbone integration.
type GreenboneService interface {
	// ProcessReport handles an incoming Greenbone webhook report.
	ProcessReport(ctx context.Context, orgID uuid.UUID, webhookActions models.GreenboneWebhookActions, body []byte) error
}

// TelemetryRepository defines the interface for telemetry data operations.
// It provides methods to store and retrieve organization telemetry configurations.
type TelemetryRepository interface {
	// Create stores a new telemetry configuration for an organization.
	Create(ctx context.Context, orgID uuid.UUID, telemetry *models.OrgTelemetryConfig) error

	// GetByOrgID retrieves a telemetry configuration by organization ID.
	GetByOrgID(ctx context.Context, orgID uuid.UUID) (*models.OrgTelemetryConfig, error)

	// GetByMetricsTokenPrefix retrieves telemetry configs by metrics token prefix.
	GetByMetricsTokenPrefix(ctx context.Context, prefix string) ([]*models.OrgTelemetryConfig, error)

	// Update modifies an existing telemetry configuration.
	Update(ctx context.Context, config *models.OrgTelemetryConfig) error
}
