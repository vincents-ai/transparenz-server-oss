// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package models

import (
	"time"

	"github.com/google/uuid"
)

// CRASRPSubmissionPackage is a built, validated, sealed submission package
// retained as an immutable revision.
//
// The Fields column is the reason this table exists. A digest on its own can
// only be believed; with the field set retained beside it, the digest can be
// recomputed and the claim "this is the document that was filed" becomes a
// comparison rather than an assertion.
//
// Nothing here is mutable: the table is append-only by trigger (migration
// 000050). Rebuilding a package for the same report and stage writes revision
// N+1 and leaves revision N readable, because what a filing record needs to
// answer later is what existed at that instant, not what would be built today.
type CRASRPSubmissionPackage struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID    uuid.UUID `gorm:"type:uuid;not null" json:"org_id"`
	ReportID uuid.UUID `gorm:"type:uuid;not null" json:"report_id"`

	// Stage is the glossary stage, not the workflow state.
	Stage string `gorm:"type:text;not null" json:"stage"`

	// Revision is monotonic per (report_id, stage).
	Revision int `gorm:"not null" json:"revision"`

	// SchemaID is the reporting schema the package was validated against, so the
	// field list that produced it stays identifiable after ENISA revises the
	// glossary.
	SchemaID string `gorm:"column:schema_id;type:text;not null" json:"schema_id"`

	EventClass    string `gorm:"column:event_class;type:text;not null" json:"event_class"`
	CoordinatorID string `gorm:"column:coordinator_id;type:text;not null" json:"coordinator_id"`

	// Fields are the glossary field values keyed by published position, exactly
	// as sealed.
	Fields JSONMap `gorm:"column:fields;type:jsonb;not null" json:"fields"`

	// Digest is the SHA-256 over the canonical serialisation, carrying its
	// encoding version as a prefix.
	Digest string `gorm:"type:text;not null" json:"digest"`

	GeneratedAt time.Time `gorm:"not null" json:"generated_at"`
	CreatedAt   time.Time `gorm:"not null" json:"created_at"`

	// CreatedBy is the principal that built the package. A package is a
	// determination about a legal artefact, so it is attributable like every
	// other step in the workflow.
	CreatedBy string `gorm:"column:created_by;type:text;not null" json:"created_by"`
}

// TableName is schema-qualified, as every compliance table is.
func (CRASRPSubmissionPackage) TableName() string { return "compliance.cra_srp_packages" }
