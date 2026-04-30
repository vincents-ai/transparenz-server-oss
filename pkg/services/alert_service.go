// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/transparenz/transparenz-server-oss/pkg/middleware"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
)

var slaViolationsTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "sla_violations_total",
	Help: "Total number of SLA violations",
})

func init() {
	prometheus.MustRegister(slaViolationsTotal)
}

// AlertService monitors SLA deadlines and broadcasts compliance alerts to connected clients.
type AlertService struct {
	hub            *AlertHub
	slaRepo        *repository.SlaTrackingRepository
	vulnRepo       *repository.VulnerabilityRepository
	eventRepo      *repository.ComplianceEventRepository
	orgRepo        *repository.OrganizationRepository
	signingService *SigningService
	logger         *zap.Logger
	tickInterval   time.Duration
	stopCh         chan struct{}
}

func NewAlertService(
	hub *AlertHub,
	slaRepo *repository.SlaTrackingRepository,
	vulnRepo *repository.VulnerabilityRepository,
	eventRepo *repository.ComplianceEventRepository,
	orgRepo *repository.OrganizationRepository,
	signingService *SigningService,
	logger *zap.Logger,
	tickInterval time.Duration,
) *AlertService {
	if tickInterval == 0 {
		tickInterval = 30 * time.Second
	}
	return &AlertService{
		hub:            hub,
		slaRepo:        slaRepo,
		vulnRepo:       vulnRepo,
		eventRepo:      eventRepo,
		orgRepo:        orgRepo,
		signingService: signingService,
		logger:         logger,
		tickInterval:   tickInterval,
		stopCh:         make(chan struct{}),
	}
}

func (s *AlertService) Start(ctx context.Context) {
	s.logger.Info("starting alert service")

	ticker := time.NewTicker(s.tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.CheckAndAlert(ctx)
		case <-s.stopCh:
			s.logger.Info("alert service stopped")
			return
		case <-ctx.Done():
			s.logger.Info("alert service context cancelled")
			return
		}
	}
}

func (s *AlertService) Stop() {
	close(s.stopCh)
}

func (s *AlertService) CheckAndAlert(ctx context.Context) {
	orgs, err := s.orgRepo.ListAll(ctx)
	if err != nil {
		s.logger.Error("failed to list organizations", zap.Error(err))
		return
	}

	var approachingCount, violatedCount, kevCount int

	for _, org := range orgs {
		s.checkApproachingDeadlines(ctx, org, &approachingCount)
		s.checkViolations(ctx, org, &violatedCount)
		s.checkNewKEV(ctx, org, &kevCount)
	}

	s.logger.Info("alert check completed",
		zap.Int("approaching_slas", approachingCount),
		zap.Int("violated_slas", violatedCount),
		zap.Int("new_kev_entries", kevCount),
	)
}

func (s *AlertService) checkApproachingDeadlines(ctx context.Context, org models.Organization, count *int) {
	ctx = middleware.ContextWithOrgID(ctx, org.ID)
	approaching, err := s.slaRepo.ListApproaching(ctx, 6*time.Hour)
	if err != nil {
		s.logger.Error("failed to list approaching SLAs",
			zap.String("org_id", org.ID.String()),
			zap.Error(err),
		)
		return
	}

	now := time.Now()
	for _, sla := range approaching {
		hoursRemaining := sla.Deadline.Sub(now).Hours()
		s.hub.Broadcast(sla.OrgID.String(), &Alert{
			Type:      "sla_warning",
			Severity:  "warning",
			Message:   fmt.Sprintf("SLA deadline in %.1f hours", hoursRemaining),
			CVE:       sla.Cve,
			Timestamp: time.Now(),
		})
		*count++
	}
}

func (s *AlertService) checkViolations(ctx context.Context, org models.Organization, count *int) {
	ctx = middleware.ContextWithOrgID(ctx, org.ID)
	violated, err := s.slaRepo.ListViolated(ctx)
	if err != nil {
		s.logger.Error("failed to list violated SLAs",
			zap.String("org_id", org.ID.String()),
			zap.Error(err),
		)
		return
	}

	for _, sla := range violated {
		if err := s.slaRepo.UpdateStatus(ctx, sla.ID, "violated"); err != nil {
			s.logger.Error("failed to update SLA status",
				zap.String("org_id", sla.OrgID.String()),
				zap.String("sla_id", sla.ID.String()),
				zap.Error(err),
			)
			continue
		}

		previousHash, err := s.eventRepo.GetLatestEventHash(ctx, sla.OrgID)
		if err != nil {
			s.logger.Warn("failed to get latest event hash, defaulting to empty",
				zap.String("org_id", sla.OrgID.String()),
				zap.Error(err),
			)
		}

		event := &models.ComplianceEvent{
			EventType:         "sla_breach",
			Severity:          "critical",
			Cve:               sla.Cve,
			Metadata:          models.JSONMap{},
			PreviousEventHash: previousHash,
		}
		if err := s.signingService.SignEvent(event); err != nil {
			s.logger.Error("failed to sign compliance event",
				zap.String("org_id", sla.OrgID.String()),
				zap.Error(err),
			)
		}
		if err := s.eventRepo.Create(ctx, sla.OrgID, event); err != nil {
			s.logger.Error("failed to create audit log",
				zap.String("org_id", sla.OrgID.String()),
				zap.Error(err),
			)
		}

		s.hub.Broadcast(sla.OrgID.String(), &Alert{
			Type:      "sla_violation",
			Severity:  "critical",
			Message:   "SLA deadline violated",
			CVE:       sla.Cve,
			Timestamp: time.Now(),
		})
		slaViolationsTotal.Inc()
		*count++
	}
}

func (s *AlertService) checkNewKEV(ctx context.Context, org models.Organization, count *int) {
	ctx = middleware.ContextWithOrgID(ctx, org.ID)
	newKev, err := s.vulnRepo.ListNewKEV(ctx, 24*time.Hour)
	if err != nil {
		s.logger.Error("failed to list new KEV entries",
			zap.String("org_id", org.ID.String()),
			zap.Error(err),
		)
		return
	}

	for _, vuln := range newKev {
		s.hub.Broadcast(vuln.OrgID.String(), &Alert{
			Type:      "exploited",
			Severity:  "critical",
			Message:   fmt.Sprintf("New KEV entry detected: %s", vuln.Cve),
			CVE:       vuln.Cve,
			Timestamp: time.Now(),
		})
		*count++
	}
}
