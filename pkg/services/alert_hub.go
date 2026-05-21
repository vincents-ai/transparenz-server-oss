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

type AlertHub struct {
	clients map[string]map[chan *Alert]struct{}
	mu      sync.RWMutex
	logger  *zap.Logger
}

func NewAlertHub(logger *zap.Logger) *AlertHub {
	return &AlertHub{
		clients: make(map[string]map[chan *Alert]struct{}),
		logger:  logger,
	}
}

func (h *AlertHub) Broadcast(orgID string, alert *Alert) {
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
