package rest

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/transparenz/transparenz-server-oss/pkg/repository"
)

type FeedStatusHandler struct {
	feedRepo *repository.VulnerabilityFeedRepository
}

func NewFeedStatusHandler(feedRepo *repository.VulnerabilityFeedRepository) *FeedStatusHandler {
	return &FeedStatusHandler{feedRepo: feedRepo}
}

type FeedStatusResponse struct {
	TotalFeeds          int            `json:"total_feeds"`
	BSIEntries          int            `json:"bsi_entries"`
	EUVDEntries         int            `json:"euvd_entries"`
	KEVEntries          int            `json:"kev_entries"`
	EntriesWithSeverity map[string]int `json:"entries_with_severity"`
	LastSyncedAt        *time.Time     `json:"last_synced_at,omitempty"`
	Sources             []string       `json:"sources"`
}

// GetStatus returns aggregated vulnerability feed data.
// Feed data is global (shared across all orgs) as it represents public vulnerability databases
// (BSI-CERT-BUND, ENISA EUVD, CISA KEV). Tenant isolation is not applicable here.
func (h *FeedStatusHandler) GetStatus(c *gin.Context) {
	ctx := c.Request.Context()

	feeds, err := h.feedRepo.List(ctx, 0, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := FeedStatusResponse{
		TotalFeeds:          len(feeds),
		EntriesWithSeverity: make(map[string]int),
		Sources:             []string{},
	}

	var latestSync *time.Time
	for _, feed := range feeds {
		if feed.BsiAdvisoryID != "" {
			resp.BSIEntries++
		}
		if feed.EnisaEuvdID != "" {
			resp.EUVDEntries++
		}
		if feed.KevExploited {
			resp.KEVEntries++
		}
		if feed.EnisaSeverity != "" {
			resp.EntriesWithSeverity[feed.EnisaSeverity]++
		}
		if feed.BsiSeverity != "" {
			resp.EntriesWithSeverity[feed.BsiSeverity]++
		}
		if latestSync == nil || feed.LastSyncedAt.After(*latestSync) {
			latestSync = &feed.LastSyncedAt
		}
	}

	if latestSync != nil {
		resp.LastSyncedAt = latestSync
	}

	seen := make(map[string]bool)
	for _, feed := range feeds {
		if feed.BsiAdvisoryID != "" && !seen["bsi"] {
			seen["bsi"] = true
			resp.Sources = append(resp.Sources, "bsi-cert-bund")
		}
		if feed.EnisaEuvdID != "" && !seen["euvd"] {
			seen["euvd"] = true
			resp.Sources = append(resp.Sources, "enisa-euvd")
		}
		if feed.KevExploited && !seen["kev"] {
			seen["kev"] = true
			resp.Sources = append(resp.Sources, "cisa-kev")
		}
	}

	c.JSON(http.StatusOK, resp)
}
