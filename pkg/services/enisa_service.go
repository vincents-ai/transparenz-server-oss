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
		SubmissionID: fmt.Sprintf("CSAF-%s", uuid.New().String()[:8]),
		CsafDocument: toJSONMap(csafDoc),
		Status:       "pending",
	}

	switch org.EnisaSubmissionMode {
	case "api":
		receipt, submitErr := s.submitToENISAAPI(org, csafDoc, submission.SubmissionID)
		if submitErr != nil {
			submission.Status = "failed"
			s.logger.Error("ENISA API submission failed", zap.Error(submitErr))
		} else {
			submission.Status = "submitted"
			submission.Response = receipt
			now := time.Now().UTC()
			submission.SubmittedAt = &now
		}
	case "csirt":
		receipt, submitErr := s.submitToCSIRT(org, csafDoc, submission.SubmissionID)
		if submitErr != nil {
			submission.Status = "failed"
			s.logger.Error("CSIRT submission failed", zap.Error(submitErr))
		} else {
			submission.Status = "submitted"
			submission.Response = receipt
			now := time.Now().UTC()
			submission.SubmittedAt = &now
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

func (s *ENISAService) submitToENISAAPI(org *models.Organization, csaf *CSAFDocument, idempotencyKey string) (models.JSONMap, error) {
	if org.EnisaAPIEndpoint == "" {
		return nil, fmt.Errorf("ENISA API endpoint not configured")
	}

	u, err := url.Parse(org.EnisaAPIEndpoint)
	if err != nil || u.Scheme != "https" || middleware.IsPrivateIP(u.Hostname()) {
		return nil, fmt.Errorf("invalid ENISA API endpoint: must be HTTPS and not a private IP")
	}

	payload, err := json.Marshal(csaf)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSAF: %w", err)
	}

	req, err := http.NewRequest("POST", org.EnisaAPIEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		// Idempotency-Key lets ENISA dedupe retries of the same filing (e.g. when
		// the first attempt reached the server but the response was lost). The
		// key is the persisted SubmissionID, stable across the initial Submit and
		// all background retries.
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	apiKey, err := s.cryptoService.Decrypt(org.EnisaAPIKeyEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt API key: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
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
			return nil, fmt.Errorf("enisa API error %d: rate limited, retry-after: %s, body: %s", resp.StatusCode, retryAfter, string(body))
		}
		return nil, fmt.Errorf("enisa API error %d: %s", resp.StatusCode, string(body))
	}

	var result models.JSONMap
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		s.logger.Warn("failed to parse ENISA response", zap.Error(err))
		result = nil
	}

	s.logger.Info("ENISA submission successful",
		zap.String("org_id", org.ID.String()),
		zap.Int("status_code", resp.StatusCode),
	)

	return result, nil
}

func (s *ENISAService) submitToCSIRT(org *models.Organization, csaf *CSAFDocument, idempotencyKey string) (models.JSONMap, error) {
	if org.EnisaAPIEndpoint == "" {
		return nil, fmt.Errorf("csirt endpoint not configured")
	}

	u, err := url.Parse(org.EnisaAPIEndpoint)
	if err != nil || u.Scheme != "https" || middleware.IsPrivateIP(u.Hostname()) {
		return nil, fmt.Errorf("invalid CSIRT endpoint: must be HTTPS and not a private IP")
	}

	payload, err := json.Marshal(csaf)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CSAF: %w", err)
	}

	req, err := http.NewRequest("POST", org.EnisaAPIEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if org.EnisaAPIKeyEncrypted != "" {
		apiKey, err := s.cryptoService.Decrypt(org.EnisaAPIKeyEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt API key: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
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
			return nil, fmt.Errorf("csirt error %d: rate limited, retry-after: %s, body: %s", resp.StatusCode, retryAfter, string(body))
		}
		return nil, fmt.Errorf("csirt error %d: %s", resp.StatusCode, string(body))
	}

	var result models.JSONMap
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		s.logger.Warn("failed to parse CSIRT response", zap.Error(err))
		result = nil
	}

	s.logger.Info("CSIRT submission successful",
		zap.String("org_id", org.ID.String()),
		zap.Int("status_code", resp.StatusCode),
	)

	return result, nil
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

		var receipt models.JSONMap
		var submitErr error
		switch org.EnisaSubmissionMode {
		case "api":
			receipt, submitErr = s.submitToENISAAPI(org, csafDoc, sub.SubmissionID)
		case "csirt":
			receipt, submitErr = s.submitToCSIRT(org, csafDoc, sub.SubmissionID)
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

		// Persist the receipt (submission acknowledgement) so there is auditable
		// evidence the authority accepted the filing — not just a status flip.
		if err := s.subRepo.MarkSubmitted(ctx, sub.ID, receipt); err != nil {
			s.logger.Warn("retry succeeded but failed to persist receipt",
				zap.String("submission_id", sub.ID.String()),
				zap.Error(err),
			)
		}
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
