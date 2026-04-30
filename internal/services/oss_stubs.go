// Package services provides stub types for proprietary features
// that are only available in the commercial transparenz-server.
package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
)

// ENISAService is a stub that provides read-only ENISA operations.
// In the OSS version, Submit is a no-op that returns an error.
// The full ENISA submission pipeline is available in the proprietary repo.
type ENISAService struct{}

// NewENISAService creates a no-op ENISA service for OSS.
func NewENISAService() *ENISAService {
	return &ENISAService{}
}

// Submit returns an error in the OSS version — ENISA submission requires the commercial edition.
func (s *ENISAService) Submit(_ context.Context, _ uuid.UUID, _ string, _ models.JSONMap) (*models.EnisaSubmission, error) {
	return nil, fmt.Errorf("ENISA submission requires the commercial edition of transparenz-server")
}

// SigningService provides audit trail signing for the OSS version.
// The full key management (generate, revoke) is in the proprietary repo.
// The OSS version only supports SignEvent for audit trail integrity.
type SigningService struct{}

// NewSigningService creates a no-op signing service for OSS.
// Audit events are stored but not cryptographically signed in the OSS version.
func NewSigningService() *SigningService {
	return &SigningService{}
}

// SignEvent is a no-op in the OSS version.
// Cryptographic signing requires the commercial edition.
func (s *SigningService) SignEvent(_ *models.ComplianceEvent) error {
	return nil // no-op: signing not available in OSS
}

// EventVerification represents a verification result for a single event.
type EventVerification struct {
	EventID   uuid.UUID `json:"event_id"`
	Valid     bool      `json:"valid"`
	Error     string    `json:"error,omitempty"`
}

// VerifyEventChain returns empty results in the OSS version.
// Cryptographic chain verification requires the commercial edition.
func (s *SigningService) VerifyEventChain(_ uuid.UUID, _, _ time.Time) ([]EventVerification, error) {
	return []EventVerification{}, nil
}
