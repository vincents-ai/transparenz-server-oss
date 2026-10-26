// SPDX-FileCopyrightText: 2026 Vincent Palmer
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Transparenz, an open-source CRA compliance server.
// It is licensed under the GNU Affero General Public License v3.0; see LICENSE.

package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/srp"
)

// ErrNoBuiltPackage is returned when a filing names a digest this service never
// produced for that report and stage.
var ErrNoBuiltPackage = errors.New("repository: no built package matches that digest for this report and stage")

// SRPPackageRepository stores built submission packages as immutable revisions.
//
// It is the other half of srp.Build. Build produces a validated, sealed package;
// this keeps it, so a filing record's digest can later be re-derived and
// compared instead of taken on trust.
type SRPPackageRepository struct {
	db *gorm.DB
}

// NewSRPPackageRepository returns a repository over the supplied connection.
func NewSRPPackageRepository(db *gorm.DB) *SRPPackageRepository {
	return &SRPPackageRepository{db: db}
}

// Store retains a built package and returns the stored row.
//
// Storing is idempotent per digest: rebuilding an unchanged field set yields the
// same digest, and the digest is what identifies a document. Without that, every
// rebuild would append a revision that differs only in when it was created,
// which would read as a history of revisions to the document.
func (r *SRPPackageRepository) Store(ctx context.Context, pkg srp.Package, actor string) (*models.CRASRPSubmissionPackage, error) {
	if pkg.ReportID == uuid.Nil {
		return nil, errors.New("repository: a package must belong to a report")
	}
	if pkg.Digest == "" {
		return nil, errors.New("repository: refusing to store a package with no digest; " +
			"an unsealed package cannot evidence anything")
	}
	if actor == "" {
		return nil, errors.New("repository: a package must be attributable to an actor; " +
			"an anonymous determination about a legal artefact is not usable as evidence")
	}

	// Same document, already stored: return it rather than minting a revision.
	if existing, err := r.ByDigest(ctx, pkg.OrgID, pkg.ReportID, pkg.Stage, pkg.Digest); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNoBuiltPackage) {
		return nil, err
	}

	fields := make(models.JSONMap, len(pkg.Fields))
	for id, v := range pkg.Fields {
		fields[id] = v
	}

	var stored models.CRASRPSubmissionPackage
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var next int
		if err := tx.Raw(`
			SELECT COALESCE(MAX(revision), 0) + 1
			FROM compliance.cra_srp_packages
			WHERE report_id = ? AND stage = ?`,
			pkg.ReportID, pkg.Stage,
		).Scan(&next).Error; err != nil {
			return err
		}

		stored = models.CRASRPSubmissionPackage{
			OrgID:         pkg.OrgID,
			ReportID:      pkg.ReportID,
			Stage:         pkg.Stage,
			Revision:      next,
			SchemaID:      pkg.SchemaID,
			EventClass:    pkg.EventClass,
			CoordinatorID: pkg.CoordinatorID,
			Fields:        fields,
			Digest:        pkg.Digest,
			GeneratedAt:   pkg.GeneratedAt,
			CreatedBy:     actor,
		}
		return tx.Create(&stored).Error
	})
	if err != nil {
		// A concurrent build may have inserted the same digest between the
		// existence check and this insert. The unique constraint is the arbiter,
		// and re-reading is the correct answer rather than surfacing a conflict
		// for a document that is identical.
		if existing, again := r.ByDigest(ctx, pkg.OrgID, pkg.ReportID, pkg.Stage, pkg.Digest); again == nil {
			return existing, nil
		}
		return nil, err
	}
	return &stored, nil
}

// ByDigest returns the stored package with this digest, scoped to the
// organisation, report and stage.
//
// The stage is part of the key on purpose: the same field values filed at the
// 72-hour stage and at the final report are different documents, and a digest
// that matched across stages would let a final report be evidenced by a
// notification.
func (r *SRPPackageRepository) ByDigest(ctx context.Context, orgID, reportID uuid.UUID, stage, digest string) (*models.CRASRPSubmissionPackage, error) {
	if digest == "" {
		return nil, errors.New("repository: a digest is required to look up a package")
	}
	var row models.CRASRPSubmissionPackage
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND report_id = ? AND stage = ? AND digest = ?", orgID, reportID, stage, digest).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: %s/%s/%s", ErrNoBuiltPackage, reportID, stage, digest)
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// Latest returns the most recent revision for a report and stage.
func (r *SRPPackageRepository) Latest(ctx context.Context, orgID, reportID uuid.UUID, stage string) (*models.CRASRPSubmissionPackage, error) {
	var row models.CRASRPSubmissionPackage
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND report_id = ? AND stage = ?", orgID, reportID, stage).
		Order("revision DESC").
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: %s/%s (no revision yet)", ErrNoBuiltPackage, reportID, stage)
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// History returns every stored revision for a report and stage, oldest first.
func (r *SRPPackageRepository) History(ctx context.Context, orgID, reportID uuid.UUID, stage string) ([]models.CRASRPSubmissionPackage, error) {
	var rows []models.CRASRPSubmissionPackage
	err := r.db.WithContext(ctx).
		Where("org_id = ? AND report_id = ? AND stage = ?", orgID, reportID, stage).
		Order("revision ASC").
		Find(&rows).Error
	return rows, err
}

// ToPackage reconstructs the sealed package from its stored row.
//
// The reconstruction deliberately keeps the STORED digest rather than computing
// a fresh one: the question being answered is whether the row still describes
// the document its digest claims, and computing a new digest would answer a
// different question — what would this field set hash to now — and always agree
// with itself.
func ToPackage(row *models.CRASRPSubmissionPackage) srp.Package {
	fields := make(map[string]string, len(row.Fields))
	for id, v := range row.Fields {
		if s, ok := v.(string); ok {
			fields[id] = s
		}
	}
	return srp.Package{
		ReportID:      row.ReportID,
		OrgID:         row.OrgID,
		EventClass:    row.EventClass,
		Stage:         row.Stage,
		SchemaID:      row.SchemaID,
		CoordinatorID: row.CoordinatorID,
		Fields:        fields,
		GeneratedAt:   row.GeneratedAt,
		Digest:        row.Digest,
	}
}
