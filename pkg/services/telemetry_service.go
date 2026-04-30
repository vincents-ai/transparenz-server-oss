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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/transparenz/transparenz-server-oss/pkg/interfaces"
	"github.com/transparenz/transparenz-server-oss/pkg/models"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const maxConsecutiveFailures = 5

var orgMetricsCollectors = struct {
	sbomUploads       *prometheus.CounterVec
	greenboneReports  *prometheus.CounterVec
	greenboneFindings *prometheus.CounterVec
	slaViolations     *prometheus.CounterVec
}{
	sbomUploads: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbom_uploads_total",
		Help: "Total number of SBOM uploads per organization",
	}, []string{"org_id"}),
	greenboneReports: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "greenbone_reports_total",
		Help: "Total number of Greenbone reports per organization",
	}, []string{"org_id"}),
	greenboneFindings: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "greenbone_findings_total",
		Help: "Total number of Greenbone findings per organization",
	}, []string{"org_id"}),
	slaViolations: prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sla_violations_total",
		Help: "Total number of SLA violations per organization",
	}, []string{"org_id"}),
}

type circuitBreakerState struct {
	failures int
	lastFail time.Time
	mu       sync.Mutex
}

// TelemetryService collects and forwards per-organization metrics to configured OTel endpoints.
type TelemetryService struct {
	telemetryRepo interfaces.TelemetryRepository
	hub           *AlertHub
	logger        *zap.Logger
	httpClient    *http.Client
	breakers      map[string]*circuitBreakerState
	breakersMu    sync.Mutex
}

func NewTelemetryService(
	telemetryRepo *repository.TelemetryRepository,
	hub *AlertHub,
	logger *zap.Logger,
) *TelemetryService {
	return &TelemetryService{
		telemetryRepo: telemetryRepo,
		hub:           hub,
		logger:        logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		breakers: make(map[string]*circuitBreakerState),
	}
}

func (s *TelemetryService) RegisterPrometheusMetrics() {
	prometheus.MustRegister(
		orgMetricsCollectors.sbomUploads,
		orgMetricsCollectors.greenboneReports,
		orgMetricsCollectors.greenboneFindings,
		orgMetricsCollectors.slaViolations,
	)
}

func (s *TelemetryService) EmitEvent(ctx context.Context, orgID uuid.UUID, eventType string, attributes map[string]string) {
	orgIDStr := orgID.String()

	switch eventType {
	case "sbom_upload":
		orgMetricsCollectors.sbomUploads.WithLabelValues(orgIDStr).Inc()
	case "greenbone_report":
		orgMetricsCollectors.greenboneReports.WithLabelValues(orgIDStr).Inc()
	case "greenbone_finding":
		orgMetricsCollectors.greenboneFindings.WithLabelValues(orgIDStr).Inc()
	case "sla_violation":
		orgMetricsCollectors.slaViolations.WithLabelValues(orgIDStr).Inc()
	default:
		s.logger.Warn("unknown telemetry event type",
			zap.String("org_id", orgIDStr),
			zap.String("event_type", eventType),
		)
		return
	}

	config, err := s.telemetryRepo.GetByOrgID(ctx, orgID)
	if err != nil {
		return
	}

	if !config.Active {
		return
	}

	if config.Provider == "otel" || config.Provider == "both" {
		if config.OtelEndpoint != "" {
			s.pushToOtel(ctx, config, eventType, attributes)
		}
	}
}

func (s *TelemetryService) pushToOtel(ctx context.Context, config *models.OrgTelemetryConfig, eventType string, attributes map[string]string) {
	orgIDStr := config.OrgID.String()

	if s.isOpen(orgIDStr) {
		s.logger.Debug("OTel push skipped, circuit breaker open",
			zap.String("org_id", orgIDStr),
		)
		return
	}

	payloadMap := map[string]string{
		"type":   eventType,
		"org_id": orgIDStr,
	}
	for k, v := range attributes {
		payloadMap[k] = v
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		s.logger.Error("failed to marshal OTel payload",
			zap.String("org_id", orgIDStr),
			zap.Error(err),
		)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.OtelEndpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		s.logger.Error("failed to create OTel request",
			zap.String("org_id", orgIDStr),
			zap.Error(err),
		)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range config.OtelHeaders {
		req.Header.Set(k, fmt.Sprintf("%v", v))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.recordFailure(orgIDStr)
		s.logger.Warn("failed to push event to OTel collector",
			zap.String("org_id", orgIDStr),
			zap.String("endpoint", config.OtelEndpoint),
			zap.Error(err),
		)
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		s.recordFailure(orgIDStr)
		s.logger.Warn("OTel collector returned error status",
			zap.String("org_id", orgIDStr),
			zap.Int("status_code", resp.StatusCode),
		)
		return
	}

	s.recordSuccess(orgIDStr)
}

func (s *TelemetryService) isOpen(orgID string) bool {
	s.breakersMu.Lock()
	breaker, ok := s.breakers[orgID]
	s.breakersMu.Unlock()

	if !ok {
		return false
	}

	breaker.mu.Lock()
	defer breaker.mu.Unlock()

	if breaker.failures >= maxConsecutiveFailures {
		if time.Since(breaker.lastFail) > 5*time.Minute {
			breaker.failures = 0
			return false
		}
		return true
	}
	return false
}

func (s *TelemetryService) recordFailure(orgID string) {
	s.breakersMu.Lock()
	breaker, ok := s.breakers[orgID]
	if !ok {
		breaker = &circuitBreakerState{}
		s.breakers[orgID] = breaker
	}
	s.breakersMu.Unlock()

	breaker.mu.Lock()
	breaker.failures++
	breaker.lastFail = time.Now()
	breaker.mu.Unlock()
}

func (s *TelemetryService) recordSuccess(orgID string) {
	s.breakersMu.Lock()
	breaker, ok := s.breakers[orgID]
	s.breakersMu.Unlock()

	if ok {
		breaker.mu.Lock()
		breaker.failures = 0
		breaker.mu.Unlock()
	}
}

func (s *TelemetryService) GetMetricsForOrg(ctx context.Context, token string) (string, error) {
	// Fast O(1) routing: compute SHA-256 prefix of token, look up candidates by prefix,
	// then verify with bcrypt. This avoids scanning ALL configs with expensive bcrypt.
	sha := sha256.Sum256([]byte(token))
	prefix := hex.EncodeToString(sha[:])[:16]

	configs, err := s.telemetryRepo.GetByMetricsTokenPrefix(ctx, prefix)
	if err != nil {
		return "", err
	}

	var config *models.OrgTelemetryConfig
	for _, c := range configs {
		if err := bcrypt.CompareHashAndPassword([]byte(c.MetricsTokenHash), []byte(token)); err == nil {
			config = c
			break
		}
	}
	if config == nil {
		return "", repository.ErrTelemetryConfigNotFound
	}

	orgIDStr := config.OrgID.String()

	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return "", fmt.Errorf("failed to gather metrics: %w", err)
	}

	var buf bytes.Buffer
	for _, mf := range metricFamilies {
		name := mf.GetName()
		if !isOrgMetric(name) {
			continue
		}

		filtered := filterMetricFamily(mf, orgIDStr)
		if filtered == nil {
			continue
		}

		encoder := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
		if err := encoder.Encode(filtered); err != nil {
			s.logger.Warn("failed to encode metric family",
				zap.String("metric", name),
				zap.Error(err),
			)
			continue
		}
	}

	return buf.String(), nil
}

func isOrgMetric(name string) bool {
	orgMetricNames := []string{
		"sbom_uploads_total",
		"greenbone_reports_total",
		"greenbone_findings_total",
		"sla_violations_total",
	}
	for _, n := range orgMetricNames {
		if strings.HasPrefix(name, n) {
			return true
		}
	}
	return false
}

func filterMetricFamily(mf *dto.MetricFamily, orgID string) *dto.MetricFamily {
	var filteredMetrics []*dto.Metric

	for _, m := range mf.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "org_id" && lp.GetValue() == orgID {
				filteredMetrics = append(filteredMetrics, m)
				break
			}
		}
	}

	if len(filteredMetrics) == 0 {
		return nil
	}

	name := mf.GetName()
	help := mf.GetHelp()
	mtype := mf.GetType()

	return &dto.MetricFamily{
		Name:   &name,
		Help:   &help,
		Type:   &mtype,
		Metric: filteredMetrics,
	}
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *TelemetryService) RotateToken(ctx context.Context, orgID uuid.UUID) (string, error) {
	config, err := s.telemetryRepo.GetByOrgID(ctx, orgID)
	if err != nil {
		return "", err
	}
	newToken, err := generateSecureToken()
	if err != nil {
		return "", err
	}
	tokenHash, tokenPrefix, err := HashMetricsToken(newToken)
	if err != nil {
		return "", err
	}
	config.MetricsTokenHash = tokenHash
	config.MetricsTokenPrefix = tokenPrefix
	if err := s.telemetryRepo.Update(ctx, config); err != nil {
		return "", err
	}
	return newToken, nil
}

// HashMetricsToken returns a bcrypt hash of the given metrics token and a fast-lookup prefix.
// The prefix is the first 16 hex characters of SHA-256(token), used for O(1) routing
// to avoid bcrypt-scanning all configs.
func HashMetricsToken(token string) (hash string, prefix string, err error) {
	h, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	sha := sha256.Sum256([]byte(token))
	prefix = hex.EncodeToString(sha[:])[:16]
	return string(h), prefix, nil
}
