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
	h.mu.RUnlock()

	for clientChan := range clients {
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
			close(alertChan)
		}
		h.mu.Unlock()
	}

	return alertChan, unsubscribe
}
