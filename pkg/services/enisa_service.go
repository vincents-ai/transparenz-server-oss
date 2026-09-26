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
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
	"github.com/vincents-ai/transparenz-server-oss/pkg/regulatory/srp"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
)

// submissionFailuresTotal counts deliveries that exhausted their retries.
//
// It is NOT an ENISA counter. The ENISA Single Reporting Platform publishes no
// API, so nothing is ever submitted to ENISA by this service; the destination
// is an operator-configured receiver, in practice a national CSIRT.
var submissionFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "transparenz_submission_failures_total",
	Help: "Total number of submissions to a configured receiver that exhausted all retries",
})

// enisaSubmissionFailuresTotal is the deprecated name of the same count.
//
// It is kept and incremented alongside the correctly-named counter because
// dashboards and alerts query it by name, and silently removing a metric is a
// worse outage than keeping a misnomer. The Help text states plainly what it
// actually measures so anyone reading the metric is not misled into thinking the
// system files with ENISA. Remove it once the dashboards have been migrated.
var enisaSubmissionFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "enisa_submission_failures_total",
	Help: "DEPRECATED: misnomer. Counts failures pushing to an operator-configured " +
		"receiver (typically a national CSIRT). The ENISA Single Reporting Platform " +
		"publishes no API and this service never files with ENISA. " +
		"Use transparenz_submission_failures_total instead.",
})

func init() {
	prometheus.MustRegister(submissionFailuresTotal, enisaSubmissionFailuresTotal)
}

// ENISAService manages CSAF document submission to ENISA and national CSIRTs.
type ENISAService struct {
	orgRepo       *repository.OrganizationRepository
	subRepo       *repository.EnisaSubmissionRepository
	eventRepo     *repository.ComplianceEventRepository
	generator     *CSAFGenerator
	cryptoService *CryptoService
	httpClient    *http.Client
	alertHub      *AlertHub
	logger        *zap.Logger
	retryInterval time.Duration
	maxRetries    int
}

func NewENISAService(orgRepo *repository.OrganizationRepository, subRepo *repository.EnisaSubmissionRepository, eventRepo *repository.ComplianceEventRepository, generator *CSAFGenerator, cryptoService *CryptoService, alertHub *AlertHub, logger *zap.Logger, timeout time.Duration, retryInterval time.Duration, maxRetries int) *ENISAService {
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
		eventRepo:     eventRepo,
		generator:     generator,
		cryptoService: cryptoService,
		alertHub:      alertHub,
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

	mode, honoured := NormalizeSubmissionMode(org.EnisaSubmissionMode)
	if !honoured {
		if mode == SubmissionModeENISAAPI {
			return nil, enisaAPINotAvailableError(org.EnisaSubmissionMode)
		}
		return nil, fmt.Errorf("unknown submission mode: %s", org.EnisaSubmissionMode)
	}

	switch mode {
	case SubmissionModeReceiver:
		// A push to an operator-configured receiver — in practice a national
		// CSIRT's own endpoint, which does exist and does accept filings.
		receipt, submitErr := s.deliverToReceiver(ctx, org, csafDoc, submission.SubmissionID)
		if submitErr != nil {
			submission.Status = "failed"
			s.logger.Error("receiver submission failed", zap.Error(submitErr))
		} else {
			submission.Status = "submitted"
			submission.Response = receipt
			now := time.Now().UTC()
			submission.SubmittedAt = &now
		}
	case SubmissionModeManual:
		// A person files the document themselves. Nothing is sent.
		submission.Status = "pending"
	case SubmissionModeENISAAPI:
		// Refused rather than silently redirected.
		//
		// This mode used to POST the document to org.EnisaAPIEndpoint — a URL
		// the operator configured themselves. It was not an ENISA integration,
		// because there is no ENISA API to integrate with: the Single Reporting
		// Platform publishes none, and ENISA states API functionality may be
		// considered later. Silently sending a CSIRT's document to a
		// user-supplied URL under the name "ENISA" is how a manufacturer comes
		// to believe a filing duty has been discharged when it has not.
		//
		// Existing configurations are pointed at the receiver mode, which is
		// what they were actually doing.
		return nil, enisaAPINotAvailableError(org.EnisaSubmissionMode)
	default:
		return nil, fmt.Errorf("unknown submission mode: %s", org.EnisaSubmissionMode)
	}

	if err := s.subRepo.Create(ctx, orgID, submission); err != nil {
		return nil, fmt.Errorf("failed to save submission: %w", err)
	}

	return submission, nil
}

// deliverToReceiver pushes a CSAF document to an operator-configured receiver.
//
// It replaces two near-identical functions, submitToENISAAPI and submitToCSIRT,
// which differed only in log wording and in whether an API key was mandatory.
// Both posted to org.EnisaAPIEndpoint, so selecting "ENISA API" sent the
// document to a user-supplied URL under ENISA's name. Collapsing them into one
// honestly-named function makes it obvious that there is no ENISA integration
// here and never was.
func (s *ENISAService) deliverToReceiver(ctx context.Context, org *models.Organization, csaf *CSAFDocument, idempotencyKey string) (models.JSONMap, error) {
	endpoint := submissionEndpoint(org)
	if endpoint == "" {
		return nil, fmt.Errorf("no submission endpoint configured: set the CSIRT endpoint, or use %q for a document a person files", SubmissionModeManual)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || middleware.IsPrivateIP(u.Hostname()) {
		return nil, fmt.Errorf("%w: %s", srp.ErrNotHTTPS, endpoint)
	}

	payload, err := json.Marshal(csaf)
	if err != nil {
		return nil, fmt.Errorf("failed to encode CSAF: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The persisted SubmissionID is stable across the initial Submit and every
	// background retry, so a receiver can recognise a retry of the same filing
	// rather than opening a second case for one event.
	req.Header.Set("Idempotency-Key", idempotencyKey)
	if org.EnisaAPIKeyEncrypted != "" {
		apiKey, derr := s.cryptoService.Decrypt(org.EnisaAPIKeyEncrypted)
		if derr != nil {
			return nil, fmt.Errorf("failed to decrypt submission credential: %w", derr)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submission to receiver failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusTooManyRequests {
		s.logger.Warn("receiver rate limited",
			zap.String("endpoint", endpoint),
			zap.String("retry_after", resp.Header.Get("Retry-After")),
			zap.String("body", string(body)))
		return nil, fmt.Errorf("receiver rate limited, retry-after: %s", resp.Header.Get("Retry-After"))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("receiver returned %d: %s", resp.StatusCode, string(body))
	}

	s.logger.Info("submission delivered to configured receiver",
		zap.String("endpoint", endpoint),
		zap.String("submission_id", idempotencyKey),
		zap.String("note", "delivered to an operator-configured receiver; this is not the ENISA Single Reporting Platform, which publishes no API"))

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		parsed = map[string]any{"body": string(body)}
	}
	return models.JSONMap(parsed), nil
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
			if err := s.checkExhausted(ctx); err != nil {
				s.logger.Error("check exhausted submissions error", zap.Error(err))
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

		mode, honoured := NormalizeSubmissionMode(org.EnisaSubmissionMode)
		if !honoured {
			// An un-honourable mode is a configuration problem, not a transient
			// delivery failure, so retrying it would burn the whole retry budget
			// against something that can never succeed. It is logged once and
			// the submission is left pending for an operator to resolve.
			if mode == SubmissionModeENISAAPI {
				s.logger.Warn("cannot retry: submission mode addresses an ENISA API that does not exist",
					zap.String("submission_id", sub.ID.String()),
					zap.Error(ErrENISAAPINotAvailable))
			} else {
				s.logger.Warn("cannot retry: unknown submission mode",
					zap.String("submission_id", sub.ID.String()),
					zap.String("mode", org.EnisaSubmissionMode))
			}
			continue
		}
		if mode != SubmissionModeReceiver {
			// Manual mode is not a failed delivery; it was never a delivery.
			continue
		}

		receipt, submitErr := s.deliverToReceiver(ctx, org, csafDoc, sub.SubmissionID)

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

// checkExhausted finds submissions that have exhausted all retries, marks them
// as 'exhausted', broadcasts a CRITICAL alert, and creates a compliance event.
// This closes the CRA Article 10 gap where failed submissions went unnoticed.
func (s *ENISAService) checkExhausted(ctx context.Context) error {
	submissions, err := s.subRepo.ListExhausted(ctx, s.maxRetries)
	if err != nil {
		return fmt.Errorf("list exhausted: %w", err)
	}

	for _, sub := range submissions {
		// Extract CVE from CSAF document metadata
		cve := extractCVEFromCSAF(sub.CsafDocument)

		// Mark as exhausted so we don't process again
		if err := s.subRepo.UpdateStatus(ctx, sub.ID, "exhausted"); err != nil {
			s.logger.Error("failed to mark submission as exhausted",
				zap.String("submission_id", sub.ID.String()),
				zap.Error(err))
			continue
		}

		// Broadcast CRITICAL alert via AlertHub
		if s.alertHub != nil {
			s.alertHub.Broadcast(sub.OrgID.String(), &Alert{
				Type:      "enisa_submission_exhausted",
				Severity:  "critical",
				Message:   fmt.Sprintf("ENISA submission for %s exhausted all %d retries — CRA Article 10 non-compliance risk", cve, s.maxRetries),
				CVE:       cve,
				Timestamp: time.Now(),
			})
		}

		// Create compliance event for audit trail
		if s.eventRepo != nil {
			event := &models.ComplianceEvent{
				EventType: "enisa_submission_failed",
				Severity:  "critical",
				Cve:       cve,
				Metadata: models.JSONMap{
					"submission_id":   sub.ID.String(),
					"retry_count":     sub.RetryCount,
					"max_retries":     s.maxRetries,
					"last_attempt_at": sub.UpdatedAt.Format(time.RFC3339),
					"action_required": "Manual submission required to maintain CRA Article 10 compliance",
				},
			}
			if err := s.eventRepo.Create(ctx, sub.OrgID, event); err != nil {
				s.logger.Error("failed to create compliance event for exhausted submission",
					zap.String("submission_id", sub.ID.String()),
					zap.Error(err))
			}
		}

		// Increment Prometheus counter
		submissionFailuresTotal.Inc()
		enisaSubmissionFailuresTotal.Inc()

		s.logger.Error("ENISA submission exhausted all retries",
			zap.String("submission_id", sub.ID.String()),
			zap.String("org_id", sub.OrgID.String()),
			zap.String("cve", cve),
			zap.Int("retry_count", sub.RetryCount),
			zap.String("recommendation", "manual submission required for CRA Article 10 compliance"),
		)
	}

	return nil
}

// extractCVEFromCSAF extracts the CVE identifier from a CSAF document JSON map.
func extractCVEFromCSAF(doc models.JSONMap) string {
	if doc == nil {
		return "unknown"
	}
	// CSAF /vulnerabilities[]/cve field
	if vulns, ok := doc["vulnerabilities"].([]interface{}); ok && len(vulns) > 0 {
		if first, ok := vulns[0].(map[string]interface{}); ok {
			if cve, ok := first["cve"].(string); ok {
				return cve
			}
		}
	}
	// Fallback: check top-level CVE field
	if cve, ok := doc["cve"].(string); ok {
		return cve
	}
	return "unknown"
}
