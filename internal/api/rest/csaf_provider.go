// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// CSAF v2.0 Provider endpoints per OASIS standard:
// https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html
//
// A CSAF Provider serves:
//   - /.well-known/csaf/{org-slug}/provider-metadata.json  (provider discovery, PUBLIC)
//   - /.well-known/csaf/{org-slug}/changes.csv             (change tracking, PUBLIC)
//   - /.well-known/csaf/{org-slug}/{advisory-id}.json      (per-advisory documents, PUBLIC)
//
// Transparenz Server acts as a multi-tenant CSAF Provider: each organization
// is a separate provider namespace identified by its slug.
//
// Authenticated variants also exist under /api/csaf/ for internal consumers.
package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/repository"
	"github.com/vincents-ai/transparenz-server-oss/pkg/services"
	"go.uber.org/zap"
)

// CSAFProviderHandler serves CSAF v2.0 provider metadata and advisory documents.
type CSAFProviderHandler struct {
	subRepo   *repository.EnisaSubmissionRepository
	orgRepo   *repository.OrganizationRepository
	generator *services.CSAFGenerator
	logger    *zap.Logger
	baseURL   string // e.g. "https://transparenz.example.com"
}

// NewCSAFProviderHandler creates a handler for CSAF v2.0 provider endpoints.
func NewCSAFProviderHandler(
	subRepo *repository.EnisaSubmissionRepository,
	orgRepo *repository.OrganizationRepository,
	generator *services.CSAFGenerator,
	logger *zap.Logger,
	baseURL string,
) *CSAFProviderHandler {
	return &CSAFProviderHandler{
		subRepo:   subRepo,
		orgRepo:   orgRepo,
		generator: generator,
		logger:    logger,
		baseURL:   strings.TrimRight(baseURL, "/"),
	}
}

// CSAFProviderMetadata is the provider-metadata.json document per CSAF v2.0 §7.1.
type CSAFProviderMetadata struct {
	CanonicalURL          string             `json:"canonical_url"`
	Distributor           CSAFDistributor    `json:"distributor"`
	LastUpdated           string             `json:"last_updated"`
	ListOnCSAFAggregators bool               `json:"list_on_CSAF_aggregators"`
	MetadataVersion       string             `json:"metadata_version"`
	Mirrors               []string           `json:"mirrors,omitempty"`
	Publisher             CSAFPublisherMeta  `json:"publisher"`
	Role                  string             `json:"role"`
	RollingWindow         CSAFRollingWindow  `json:"rolling_window"`
}

type CSAFDistributor struct {
	Name string `json:"name"`
}

type CSAFPublisherMeta struct {
	Category         string `json:"category"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	ContactDetails   string `json:"contact_details,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
}

type CSAFRollingWindow struct {
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date,omitempty"`
}

// resolveOrgSlug resolves an org slug (from the URL path) to an organization ID.
// Returns 404 if the org is not found.
func (h *CSAFProviderHandler) resolveOrgSlug(c *gin.Context) (uuid.UUID, bool) {
	slug := c.Param("org_slug")
	if slug == "" {
		api.BadRequest(c, "org_slug is required")
		return uuid.Nil, false
	}

	org, err := h.orgRepo.GetBySlug(c.Request.Context(), slug)
	if err != nil {
		api.NotFound(c, "organization not found")
		return uuid.Nil, false
	}
	return org.ID, true
}

// resolveOrgFromContext resolves org ID from JWT context (authenticated endpoints).
func (h *CSAFProviderHandler) resolveOrgFromContext(c *gin.Context) (uuid.UUID, bool) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return uuid.Nil, false
	}
	return orgUUID, true
}

// =============================================================================
// Public .well-known endpoints (NO AUTH — for CSAF aggregators)
// =============================================================================

// WellKnownProviderMetadata returns provider-metadata.json for a given org slug.
// GET /.well-known/csaf/:org_slug/provider-metadata.json
func (h *CSAFProviderHandler) WellKnownProviderMetadata(c *gin.Context) {
	orgID, ok := h.resolveOrgSlug(c)
	if !ok {
		return
	}
	h.serveProviderMetadata(c, orgID)
}

// WellKnownAdvisory returns a specific advisory JSON file.
// GET /.well-known/csaf/:org_slug/:advisory_id.json
func (h *CSAFProviderHandler) WellKnownAdvisory(c *gin.Context) {
	orgID, ok := h.resolveOrgSlug(c)
	if !ok {
		return
	}
	advisoryID := strings.TrimSuffix(c.Param("advisory_id.json"), ".json")
	h.serveAdvisory(c, orgID, advisoryID)
}

// WellKnownChanges returns changes.csv for a given org slug.
// GET /.well-known/csaf/:org_slug/changes.csv
func (h *CSAFProviderHandler) WellKnownChanges(c *gin.Context) {
	orgID, ok := h.resolveOrgSlug(c)
	if !ok {
		return
	}
	h.serveChanges(c, orgID)
}

// =============================================================================
// Authenticated /api/csaf/ endpoints (JWT required)
// =============================================================================

// GetProviderMetadata returns provider-metadata.json for the authenticated org.
// GET /api/csaf/provider-metadata.json
func (h *CSAFProviderHandler) GetProviderMetadata(c *gin.Context) {
	orgID, ok := h.resolveOrgFromContext(c)
	if !ok {
		return
	}
	h.serveProviderMetadata(c, orgID)
}

// ListAdvisories returns a list of CSAF advisory documents.
// GET /api/csaf/advisories
func (h *CSAFProviderHandler) ListAdvisories(c *gin.Context) {
	orgID, ok := h.resolveOrgFromContext(c)
	if !ok {
		return
	}
	h.serveAdvisoryList(c, orgID)
}

// GetAdvisory returns a specific CSAF advisory document.
// GET /api/csaf/advisories/:id
func (h *CSAFProviderHandler) GetAdvisory(c *gin.Context) {
	orgID, ok := h.resolveOrgFromContext(c)
	if !ok {
		return
	}
	h.serveAdvisory(c, orgID, c.Param("id"))
}

// GetChanges returns changes.csv for the authenticated org.
// GET /api/csaf/changes.csv
func (h *CSAFProviderHandler) GetChanges(c *gin.Context) {
	orgID, ok := h.resolveOrgFromContext(c)
	if !ok {
		return
	}
	h.serveChanges(c, orgID)
}

// =============================================================================
// Shared implementation methods
// =============================================================================

func (h *CSAFProviderHandler) serveProviderMetadata(c *gin.Context, orgID uuid.UUID) {
	org, err := h.orgRepo.GetByID(c.Request.Context(), orgID)
	if err != nil {
		api.InternalError(c, "failed to load organization")
		return
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	wellKnownBase := fmt.Sprintf("%s/.well-known/csaf/%s", h.baseURL, org.Slug)

	meta := CSAFProviderMetadata{
		CanonicalURL:          wellKnownBase + "/provider-metadata.json",
		Distributor:            CSAFDistributor{Name: org.Name},
		LastUpdated:            now,
		ListOnCSAFAggregators:  false,
		MetadataVersion:        "2.0",
		Publisher: CSAFPublisherMeta{
			Category:       "vendor",
			Name:           org.Name,
			Namespace:      fmt.Sprintf("https://transparenz.io/org/%s", org.Slug),
			ContactDetails: fmt.Sprintf("security@%s", org.Slug),
		},
		Role: "csaf_provider",
		RollingWindow: CSAFRollingWindow{
			StartDate: now,
		},
	}

	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, meta)
}

func (h *CSAFProviderHandler) serveAdvisory(c *gin.Context, orgID uuid.UUID, idStr string) {
	id, err := uuid.Parse(idStr)
	if err != nil {
		api.BadRequest(c, "invalid advisory ID")
		return
	}

	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgID)

	submission, err := h.subRepo.GetByID(ctx, id)
	if err != nil {
		api.NotFound(c, "advisory not found")
		return
	}

	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, submission.ID.String()))
	c.JSON(http.StatusOK, submission.CsafDocument)
}

func (h *CSAFProviderHandler) serveAdvisoryList(c *gin.Context, orgID uuid.UUID) {
	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgID)

	limit := 50
	offset := 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	submissions, err := h.subRepo.List(ctx, limit, offset)
	if err != nil {
		h.logger.Error("failed to list CSAF advisories", zap.Error(err))
		api.InternalError(c, "failed to list advisories")
		return
	}

	total, err := h.subRepo.Count(ctx)
	if err != nil {
		api.InternalError(c, "failed to count advisories")
		return
	}

	type advisorySummary struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		URL       string `json:"url"`
		CreatedAt string `json:"created_at"`
	}

	org, _ := h.orgRepo.GetByID(c.Request.Context(), orgID)
	var orgSlug string
	if org != nil {
		orgSlug = org.Slug
	}

	var summaries []advisorySummary
	for _, sub := range submissions {
		summaries = append(summaries, advisorySummary{
			ID:        sub.ID.String(),
			Status:    sub.Status,
			URL:       fmt.Sprintf("%s/.well-known/csaf/%s/%s.json", h.baseURL, orgSlug, sub.ID.String()),
			CreatedAt: sub.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   summaries,
		"limit":  limit,
		"offset": offset,
		"count":  len(summaries),
		"total":  total,
	})
}

func (h *CSAFProviderHandler) serveChanges(c *gin.Context, orgID uuid.UUID) {
	ctx := middleware.ContextWithOrgID(c.Request.Context(), orgID)

	submissions, err := h.subRepo.List(ctx, 100, 0)
	if err != nil {
		api.InternalError(c, "failed to list submissions")
		return
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=changes.csv")

	// CSAF changes.csv format: advisory_id,current_release_date
	var b strings.Builder
	b.WriteString("advisory_id,current_release_date\n")
	for _, sub := range submissions {
		fmt.Fprintf(&b, "%s.json,%s\n",
			sub.ID.String(),
			sub.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		)
	}
	c.String(http.StatusOK, b.String())
}

// =============================================================================
// CSAF Feed Ingestion (admin only)
// =============================================================================

// CSAFFeedIngestionHandler ingests external CSAF feeds from third-party providers
// (BSI-CERT-BUND, Nozomi, etc.) and upserts them into the vulnerability_feed table.
type CSAFFeedIngestionHandler struct {
	feedRepo *repository.VulnerabilityFeedRepository
	logger   *zap.Logger
}

// NewCSAFFeedIngestionHandler creates a handler for external CSAF feed ingestion.
func NewCSAFFeedIngestionHandler(
	feedRepo *repository.VulnerabilityFeedRepository,
	logger *zap.Logger,
) *CSAFFeedIngestionHandler {
	return &CSAFFeedIngestionHandler{
		feedRepo: feedRepo,
		logger:   logger,
	}
}

// IngestFeedRequest holds the URL and provider name for feed ingestion.
type IngestFeedRequest struct {
	URL      string `json:"url" binding:"required"`
	Provider string `json:"provider" binding:"required,oneof=bsi-cert-bund nozomi enisa-euvd cisa-kev other"`
}

// IngestFeed triggers ingestion of an external CSAF feed.
// Endpoint: POST /api/csaf/feeds/ingest (admin only)
func (h *CSAFFeedIngestionHandler) IngestFeed(c *gin.Context) {
	var req IngestFeedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.BadRequest(c, "invalid request: url and provider are required")
		return
	}

	resp, err := http.Get(req.URL)
	if err != nil {
		api.BadRequest(c, fmt.Sprintf("failed to fetch CSAF feed: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		api.BadRequest(c, fmt.Sprintf("CSAF feed returned status %d", resp.StatusCode))
		return
	}

	var feedDocs []csafFeedDocument
	contentType := resp.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		var single csafFeedDocument
		if err := json.NewDecoder(resp.Body).Decode(&single); err != nil {
			api.BadRequest(c, fmt.Sprintf("failed to parse CSAF feed: %v", err))
			return
		}
		if len(single.Vulnerabilities) > 0 || single.Document.Tracking.ID != "" {
			feedDocs = append(feedDocs, single)
		}
	}

	var totalIngested int
	for _, doc := range feedDocs {
		n, err := h.ingestCSAFDocument(c.Request.Context(), doc, req.Provider)
		if err != nil {
			h.logger.Error("failed to ingest CSAF document",
				zap.String("tracking_id", doc.Document.Tracking.ID),
				zap.Error(err),
			)
			continue
		}
		totalIngested += n
	}

	c.JSON(http.StatusOK, gin.H{
		"provider":       req.Provider,
		"total_ingested": totalIngested,
		"documents":      len(feedDocs),
	})
}

type csafFeedDocument struct {
	Document struct {
		Tracking struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		} `json:"tracking"`
	} `json:"document"`
	Vulnerabilities []struct {
		CVE string `json:"cve"`
	} `json:"vulnerabilities"`
}

func (h *CSAFFeedIngestionHandler) ingestCSAFDocument(_ context.Context, _ csafFeedDocument, _ string) (int, error) {
	// Stub: parse vulnerability entries from the external CSAF document
	// and upsert into vulnerability_feeds, similar to VulnzSyncService.upsertRecords.
	// Full implementation deferred — the handler scaffolding is in place.
	return 0, nil
}
