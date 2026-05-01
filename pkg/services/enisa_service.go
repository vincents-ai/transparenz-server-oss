// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
)

// ENISAService manages CSAF document submission to ENISA and national CSIRTs.
type ENISAService struct {
	orgRepo       *repository.OrganizationRepository
	subRepo       *repository.EnisaSubmissionRepository
	generator     *CSAFGenerator
	cryptoService *CryptoService
	httpClient    *http.Client
	logger        *zap.Logger
	retryInterval time.Duration
	maxRetries    int
}

func NewENISAService(orgRepo *repository.OrganizationRepository, subRepo *repository.EnisaSubmissionRepository, generator *CSAFGenerator, cryptoService *CryptoService, logger *zap.Logger, timeout time.Duration, retryInterval time.Duration, maxRetries int) *ENISAService {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if retryInterval == 0 {
		retryInterval = 15 * time.Minute
	}
	if maxRetries == 0 {
		maxRetries = 5
	}
	return &ENISAService{
		orgRepo:       orgRepo,
		subRepo:       subRepo,
		generator:     generator,
		cryptoService: cryptoService,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger:        logger,
		retryInterval: retryInterval,
		maxRetries:    maxRetries,
	}
}

func (s *ENISAService) Submit(ctx context.Context, orgID uuid.UUID, cve string, _ models.JSONMap) (*models.EnisaSubmission, error) {
	org, err := s.orgRepo.GetByID(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to load organization: %w", err)
	}

	csafDoc, err := s.generator.GeneratePerCVE(ctx, orgID, cve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSAF: %w", err)
	}

	submission := &models.EnisaSubmission{
		OrgID:        orgID,
		CsafDocument: toJSONMap(csafDoc),
		Status:       "pending",
	}

	switch org.EnisaSubmissionMode {
	case "api":
		err = s.submitToENISAAPI(org, csafDoc)
		if err != nil {
			submission.Status = "failed"
			s.logger.Error("ENISA API submission failed", zap.Error(err))
		} else {
			submission.Status = "submitted"
		}
	case "csirt":
		err = s.submitToCSIRT(org, csafDoc)
		if err != nil {
			submission.Status = "failed"
			s.logger.Error("CSIRT submission failed", zap.Error(err))
		} else {
			submission.Status = "submitted"
		}
	case "export":
		submission.Status = "pending"
	default:
		return nil, fmt.Errorf("unknown submission mode: %s", org.EnisaSubmissionMode)
	}

	if err := s.subRepo.Create(ctx, orgID, submission); err != nil {
		return nil, fmt.Errorf("failed to save submission: %w", err)
	}

	return submission, nil
}

func (s *ENISAService) submitToENISAAPI(org *models.Organization, csaf *CSAFDocument) error {
	if org.EnisaAPIEndpoint == "" {
		return fmt.Errorf("ENISA API endpoint not configured")
	}

	u, err := url.Parse(org.EnisaAPIEndpoint)
	if err != nil || u.Scheme != "https" || middleware.IsPrivateIP(u.Hostname()) {
		return fmt.Errorf("invalid ENISA API endpoint: must be HTTPS and not a private IP")
	}

	payload, err := json.Marshal(csaf)
	if err != nil {
		return fmt.Errorf("failed to marshal CSAF: %w", err)
	}

	req, err := http.NewRequest("POST", org.EnisaAPIEndpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	apiKey, err := s.cryptoService.Decrypt(org.EnisaAPIKeyEncrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt API key: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			s.logger.Warn("ENISA API rate limited",
				zap.Int("status_code", resp.StatusCode),
				zap.String("retry_after", retryAfter),
				zap.String("body", string(body)),
			)
			return fmt.Errorf("ENISA API error %d: rate limited, retry-after: %s, body: %s", resp.StatusCode, retryAfter, string(body))
		}
		return fmt.Errorf("ENISA API error %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		s.logger.Warn("failed to parse ENISA response", zap.Error(err))
	}

	s.logger.Info("ENISA submission successful",
		zap.String("org_id", org.ID.String()),
		zap.Int("status_code", resp.StatusCode),
	)

	return nil
}

func (s *ENISAService) submitToCSIRT(org *models.Organization, csaf *CSAFDocument) error {
	if org.EnisaAPIEndpoint == "" {
		return fmt.Errorf("CSIRT endpoint not configured")
	}

	u, err := url.Parse(org.EnisaAPIEndpoint)
	if err != nil || u.Scheme != "https" || middleware.IsPrivateIP(u.Hostname()) {
		return fmt.Errorf("invalid CSIRT endpoint: must be HTTPS and not a private IP")
	}

	payload, err := json.Marshal(csaf)
	if err != nil {
		return fmt.Errorf("failed to marshal CSAF: %w", err)
	}

	req, err := http.NewRequest("POST", org.EnisaAPIEndpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if org.EnisaAPIKeyEncrypted != "" {
		apiKey, err := s.cryptoService.Decrypt(org.EnisaAPIKeyEncrypted)
		if err != nil {
			return fmt.Errorf("failed to decrypt API key: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			s.logger.Warn("CSIRT rate limited",
				zap.Int("status_code", resp.StatusCode),
				zap.String("retry_after", retryAfter),
				zap.String("body", string(body)),
			)
			return fmt.Errorf("CSIRT error %d: rate limited, retry-after: %s, body: %s", resp.StatusCode, retryAfter, string(body))
		}
		return fmt.Errorf("CSIRT error %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Info("CSIRT submission successful",
		zap.String("org_id", org.ID.String()),
		zap.Int("status_code", resp.StatusCode),
	)

	return nil
}

func (s *ENISAService) StartRetryWorker(ctx context.Context) {
	ticker := time.NewTicker(s.retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.retryFailed(ctx); err != nil {
				s.logger.Error("retry failed submissions error", zap.Error(err))
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *ENISAService) retryFailed(ctx context.Context) error {
	submissions, err := s.subRepo.ListFailedForRetry(ctx, s.maxRetries)
	if err != nil {
		return err
	}

	for _, sub := range submissions {
		backoff := time.Duration(math.Pow(2, float64(sub.RetryCount))) * time.Minute
		var jitterBuf [8]byte
		_, _ = rand.Read(jitterBuf[:])
		jitterFrac := 0.5 + 0.5*float64(binary.LittleEndian.Uint64(jitterBuf[:]))/float64(^uint64(0))
		jitter := time.Duration(float64(backoff) * jitterFrac)
		if time.Since(sub.UpdatedAt) < jitter {
			continue
		}

		org, err := s.orgRepo.GetByID(ctx, sub.OrgID)
		if err != nil {
			continue
		}

		var csafDoc *CSAFDocument
		if sub.CsafDocument != nil {
			csafDoc = &CSAFDocument{}
			if data, err := json.Marshal(sub.CsafDocument); err == nil {
				if uerr := json.Unmarshal(data, csafDoc); uerr != nil {
					s.logger.Warn("failed to unmarshal CSAF document", zap.Error(uerr))
				}
			}
		}

		var submitErr error
		switch org.EnisaSubmissionMode {
		case "api":
			submitErr = s.submitToENISAAPI(org, csafDoc)
		case "csirt":
			submitErr = s.submitToCSIRT(org, csafDoc)
		default:
			continue
		}

		if submitErr != nil {
			_ = s.subRepo.IncrementRetry(ctx, sub.ID)
			s.logger.Warn("retry failed",
				zap.String("submission_id", sub.ID.String()),
				zap.Error(submitErr),
			)
			continue
		}

		_ = s.subRepo.UpdateStatus(ctx, sub.ID, "submitted")
		s.logger.Info("retry successful",
			zap.String("submission_id", sub.ID.String()),
		)
	}

	return nil
}

func toJSONMap(doc *CSAFDocument) models.JSONMap {
	if doc == nil {
		return nil
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	var result models.JSONMap
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

// isPrivateIP is deprecated: use middleware.IsPrivateIP instead.
// Removed local implementation in favor of the shared one.
