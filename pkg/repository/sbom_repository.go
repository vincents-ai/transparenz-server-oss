// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"gorm.io/gorm"
)

var ErrSbomUploadNotFound = errors.New("sbom upload not found")

// SbomRepository provides data access for SBOM uploads and documents.
type SbomRepository struct {
	db *gorm.DB
}

// NewSbomRepository creates a new SbomRepository backed by the given DB.
func NewSbomRepository(db *gorm.DB) *SbomRepository {
	return &SbomRepository{db: db}
}

func (r *SbomRepository) CreateUpload(ctx context.Context, orgID uuid.UUID, upload *models.SbomUpload) error {
	upload.OrgID = orgID
	return r.db.WithContext(ctx).Create(upload).Error
}

func (r *SbomRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SbomUpload, error) {
	var upload models.SbomUpload
	err := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Where("id = ?", id).First(&upload).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSbomUploadNotFound
		}
		return nil, err
	}
	return &upload, nil
}

func (r *SbomRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.SbomUpload{}).
		Scopes(TenantScope(ctx)).
		Count(&count).Error
	return count, err
}

func (r *SbomRepository) List(ctx context.Context, limit, offset int) ([]models.SbomUpload, error) {
	var uploads []models.SbomUpload
	query := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Order("created_at DESC")
	if limit > 0 {
		query = query.Limit(limit).Offset(offset)
	}
	err := query.Find(&uploads).Error
	return uploads, err
}

func (r *SbomRepository) ExistsBySHA256(ctx context.Context, sha256 string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.SbomUpload{}).
		Scopes(TenantScope(ctx)).
		Where("sha256 = ?", sha256).
		Count(&count).Error
	return count > 0, err
}

func (r *SbomRepository) GetDocument(ctx context.Context, id uuid.UUID) ([]byte, error) {
	var upload models.SbomUpload
	err := r.db.WithContext(ctx).Scopes(TenantScope(ctx)).Select("document").Where("id = ?", id).First(&upload).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSbomUploadNotFound
		}
		return nil, err
	}
	return []byte(upload.Document), nil
}

// SbomDocumentResult holds an SBOM document and its format.
type SbomDocumentResult struct {
	Document []byte
	Format   string
}

func (r *SbomRepository) GetDocumentAndFormatFromPublic(ctx context.Context, id uuid.UUID) (*SbomDocumentResult, error) {
	orgID, err := middleware.GetOrgIDFromContext(ctx)
	if err != nil {
		return nil, ErrSbomUploadNotFound
	}
	parsed, err := uuid.Parse(orgID)
	if err != nil {
		return nil, ErrSbomUploadNotFound
	}
	var result SbomDocumentResult
	err = r.db.WithContext(ctx).
		Raw("SELECT document, format FROM compliance.sbom_uploads WHERE id = ? AND org_id = ?", id, parsed).
		Scan(&result).Error
	if err != nil {
		return nil, err
	}
	if result.Document == nil {
		return nil, ErrSbomUploadNotFound
	}
	return &result, nil
}

func (r *SbomRepository) ExistsByID(ctx context.Context, id uuid.UUID) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.SbomUpload{}).
		Scopes(TenantScope(ctx)).
		Where("id = ?", id).
		Count(&count).Error
	return count > 0, err
}

func (r *SbomRepository) InsertIntoPublic(ctx context.Context, upload *models.SbomUpload) error {
	// CreateUpload already inserts into compliance.sbom_uploads.
	// This method is kept for interface compatibility.
	return nil
}

func (r *SbomRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).
		Scopes(TenantScope(ctx)).
		Where("id = ?", id).
		Delete(&models.SbomUpload{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrSbomUploadNotFound
	}
	return nil
}
