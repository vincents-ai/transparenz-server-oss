package services

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

type Alert struct {
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	CVE       string    `json:"cve,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// AlertFilter is called before broadcasting an alert. Return false to suppress.
// Commercial uses this for gossip-based cross-node deduplication.
type AlertFilter func(orgID string, alert *Alert) bool

type AlertHub struct {
	clients map[string]map[chan *Alert]struct{}
	mu      sync.RWMutex
	logger  *zap.Logger
	filter  AlertFilter
}

func NewAlertHub(logger *zap.Logger) *AlertHub {
	return &AlertHub{
		clients: make(map[string]map[chan *Alert]struct{}),
		logger:  logger,
	}
}

// SetFilter installs an alert filter. Called by commercial server to
// inject gossip-based dedup. If filter returns false, the alert is suppressed.
func (h *AlertHub) SetFilter(f AlertFilter) {
	h.filter = f
}

func (h *AlertHub) Broadcast(orgID string, alert *Alert) {
	// Check filter (dedup, rate limiting, etc.)
	if h.filter != nil && !h.filter(orgID, alert) {
		return
	}

	h.mu.RLock()
	clients := h.clients[orgID]
	// Snapshot the channels while holding the read lock to avoid
	// racing with Subscribe/Unsubscribe which modify the map.
	snapshot := make([]chan *Alert, 0, len(clients))
	for ch := range clients {
		snapshot = append(snapshot, ch)
	}
	h.mu.RUnlock()

	for _, clientChan := range snapshot {
		func() {
			defer func() {
				//nolint:errcheck
				recover()
			}()
			select {
			case clientChan <- alert:
			default:
			}
		}()
	}
}

func (h *AlertHub) Subscribe(orgID string) (<-chan *Alert, func()) {
	alertChan := make(chan *Alert, 100)

	h.mu.Lock()
	if h.clients[orgID] == nil {
		h.clients[orgID] = make(map[chan *Alert]struct{})
	}
	h.clients[orgID][alertChan] = struct{}{}
	h.mu.Unlock()

	unsubscribe := func() {
		h.mu.Lock()
		if h.clients[orgID] != nil {
			delete(h.clients[orgID], alertChan)
		}
		h.mu.Unlock()
	}

	return alertChan, unsubscribe
}
