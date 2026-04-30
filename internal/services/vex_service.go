// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/transparenz/transparenz-server-oss/internal/models"
	"github.com/transparenz/transparenz-server-oss/internal/repository"
)

// VEXService manages VEX statement lifecycle including drafting, approval, and publication.
type VEXService struct {
	stmtRepo      *repository.VexStatementRepository
	pubRepo       *repository.VexPublicationRepository
	feedRepo      *repository.VulnerabilityFeedRepository
	vulnRepo      *repository.VulnerabilityRepository
	csafGenerator *CSAFGenerator
	enisaService  *ENISAService
	db            *gorm.DB
	logger        *zap.Logger
}

// NewVEXService creates a VEXService with the provided repository and generator dependencies.
func NewVEXService(stmtRepo *repository.VexStatementRepository, pubRepo *repository.VexPublicationRepository, feedRepo *repository.VulnerabilityFeedRepository, vulnRepo *repository.VulnerabilityRepository, db *gorm.DB, logger *zap.Logger, csafGenerator *CSAFGenerator, enisaService *ENISAService) *VEXService {
	return &VEXService{
		stmtRepo:      stmtRepo,
		pubRepo:       pubRepo,
		feedRepo:      feedRepo,
		vulnRepo:      vulnRepo,
		csafGenerator: csafGenerator,
		enisaService:  enisaService,
		db:            db,
		logger:        logger,
	}
}

func (s *VEXService) AutoDraftVEX(ctx context.Context, orgID uuid.UUID, cve string, productID string) (*models.VexStatement, error) {
	stmt := &models.VexStatement{
		ID:            uuid.New(),
		OrgID:         orgID,
		CVE:           cve,
		ProductID:     productID,
		Justification: "component_not_present",
		Confidence:    "unknown",
		Status:        "draft",
	}

	if s.vulnRepo != nil {
		vuln, err := s.vulnRepo.GetByCVE(ctx, cve)
		if err != nil {
			s.logger.Warn("vulnerability not found, creating draft VEX anyway", zap.String("cve", cve), zap.Error(err))
		} else if vuln != nil {
			if vuln.CvssScore != nil {
				stmt.ImpactStatement = fmt.Sprintf("Vulnerability %s affects product %s. CVSS: %.1f", cve, productID, *vuln.CvssScore)
			} else {
				stmt.ImpactStatement = fmt.Sprintf("Vulnerability %s affects product %s", cve, productID)
			}
			if vuln.ExploitedInWild {
				stmt.Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
				stmt.Confidence = "high"
			} else {
				stmt.Justification = "vulnerable_code_not_present"
				stmt.Confidence = "reasonable"
			}
		}
	}

	if err := s.stmtRepo.Create(ctx, orgID, stmt); err != nil {
		return nil, fmt.Errorf("create VEX statement: %w", err)
	}

	return stmt, nil
}

func (s *VEXService) ApproveVEX(ctx context.Context, vexID uuid.UUID) (*models.VexStatement, error) {
	stmt, err := s.stmtRepo.GetByID(ctx, vexID)
	if err != nil {
		return nil, fmt.Errorf("get VEX statement: %w", err)
	}
	if stmt.Status != "draft" && stmt.Status != "pending_approval" {
		return nil, fmt.Errorf("VEX %s is not approvable (status: %s)", vexID, stmt.Status)
	}
	stmt.Status = "active"
	if err := s.stmtRepo.Update(ctx, stmt); err != nil {
		return nil, fmt.Errorf("approve VEX: %w", err)
	}
	return stmt, nil
}

func (s *VEXService) PublishVEX(ctx context.Context, vexID uuid.UUID, channel string) (*models.VexPublication, error) {
	stmt, err := s.stmtRepo.GetByID(ctx, vexID)
	if err != nil {
		return nil, fmt.Errorf("get VEX statement: %w", err)
	}
	if stmt.Status != "active" {
		return nil, fmt.Errorf("VEX %s is not active (status: %s)", vexID, stmt.Status)
	}

	validChannels := map[string]bool{"file": true, "csaf": true, "enisa": true}
	if !validChannels[channel] {
		return nil, fmt.Errorf("invalid channel: %s", channel)
	}

	pub := &models.VexPublication{
		ID:          uuid.New(),
		VexID:       vexID,
		PublishedAt: time.Now(),
		Channel:     channel,
		Status:      "published",
	}

	switch channel {
	case "csaf":
		if s.csafGenerator == nil {
			s.logger.Warn("CSAFGenerator is nil, falling back to file publication", zap.String("vex_id", vexID.String()))
			pub.Channel = "file"
			break
		}
		csafDoc, err := s.csafGenerator.GeneratePerCVE(ctx, stmt.OrgID, stmt.CVE)
		if err != nil {
			s.logger.Warn("CSAF generation failed, falling back to file publication", zap.String("vex_id", vexID.String()), zap.Error(err))
			pub.Channel = "file"
		} else {
			data, _ := json.Marshal(csafDoc)
			var resp models.JSONMap
			if err := json.Unmarshal(data, &resp); err == nil {
				pub.Response = resp
			}
		}
	case "enisa":
		if s.enisaService == nil {
			s.logger.Warn("ENISAService is nil, falling back to file publication", zap.String("vex_id", vexID.String()))
			pub.Channel = "file"
			break
		}
		submission, err := s.enisaService.Submit(ctx, stmt.OrgID, stmt.CVE, nil)
		if err != nil {
			s.logger.Warn("ENISA submission failed, falling back to file publication", zap.String("vex_id", vexID.String()), zap.Error(err))
			pub.Channel = "file"
		} else {
			data, _ := json.Marshal(submission)
			var resp models.JSONMap
			if err := json.Unmarshal(data, &resp); err == nil {
				pub.Response = resp
			}
		}
	}

	if err := s.pubRepo.Create(ctx, pub); err != nil {
		return nil, fmt.Errorf("create VEX publication: %w", err)
	}

	stmt.Status = "active"
	if err := s.stmtRepo.Update(ctx, stmt); err != nil {
		return nil, fmt.Errorf("update VEX status: %w", err)
	}

	return pub, nil
}

func (s *VEXService) RotateVEX(ctx context.Context, vexID uuid.UUID) (*models.VexStatement, error) {
	stmt, err := s.stmtRepo.GetByID(ctx, vexID)
	if err != nil {
		return nil, fmt.Errorf("get VEX for rotation: %w", err)
	}

	stmt.Status = "superseded"
	if err := s.stmtRepo.Update(ctx, stmt); err != nil {
		return nil, fmt.Errorf("failed to supersede VEX: %w", err)
	}

	newStmt, err := s.AutoDraftVEX(ctx, stmt.OrgID, stmt.CVE, stmt.ProductID)
	if err != nil {
		return nil, fmt.Errorf("create replacement VEX: %w", err)
	}

	return newStmt, nil
}
