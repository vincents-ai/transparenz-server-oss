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

// subscriber owns one alert channel.
//
// The channel and the flag that says whether it is still open are guarded by the
// same mutex, so a broadcast and an unsubscribe cannot touch the channel at the
// same time. Without that, unsubscribe closed the channel while a broadcast was
// sending on it: the send used to be wrapped in recover(), which swallowed the
// panic but left the race, and `go test -race` reported it whenever a subscriber
// left while an alert was in flight.
type subscriber struct {
	mu     sync.Mutex
	ch     chan *Alert
	closed bool
}

// send delivers an alert if the channel has room and is still open.
func (s *subscriber) send(alert *Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	// Non-blocking: a subscriber that cannot keep up loses the alert rather than
	// stalling the broadcaster. The buffer is generous (see Subscribe), and
	// dropping is preferable to back-pressuring an incident workflow.
	select {
	case s.ch <- alert:
	default:
	}
}

// close marks the channel closed and closes it exactly once.
func (s *subscriber) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	// Close so receivers blocked on <-ch, and the standard "range over channel"
	// consume loop, unblock and observe end-of-stream. Without this, unsubscribe
	// only stopped NEW broadcasts from reaching this subscriber and left existing
	// receivers blocked forever, which hung the suite.
	close(s.ch)
}

type AlertHub struct {
	clients map[string]map[*subscriber]struct{}
	mu      sync.RWMutex
	logger  *zap.Logger
	filter  AlertFilter
}

func NewAlertHub(logger *zap.Logger) *AlertHub {
	return &AlertHub{
		clients: make(map[string]map[*subscriber]struct{}),
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
	// Snapshot the subscribers while holding the read lock to avoid racing with
	// Subscribe/Unsubscribe which modify the map.
	snapshot := make([]*subscriber, 0, len(clients))
	for s := range clients {
		snapshot = append(snapshot, s)
	}
	h.mu.RUnlock()

	for _, s := range snapshot {
		s.send(alert)
	}
}

func (h *AlertHub) Subscribe(orgID string) (<-chan *Alert, func()) {
	sub := &subscriber{ch: make(chan *Alert, 100)}

	h.mu.Lock()
	if h.clients[orgID] == nil {
		h.clients[orgID] = make(map[*subscriber]struct{})
	}
	h.clients[orgID][sub] = struct{}{}
	h.mu.Unlock()

	unsubscribe := func() {
		h.mu.Lock()
		if h.clients[orgID] != nil {
			delete(h.clients[orgID], sub)
		}
		h.mu.Unlock()
		sub.close()
	}

	return sub.ch, unsubscribe
}
