package services

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// WorkerStatus represents the health of a single background worker.
type WorkerStatus struct {
	Name         string    `json:"name"`
	LastTick     time.Time `json:"last_tick"`
	JobsHandled  int64     `json:"jobs_handled"`
	ErrorsLast5m int       `json:"errors_last_5m"`
	Healthy      bool      `json:"healthy"`
	Message      string    `json:"message,omitempty"`
}

// HealthReporter is implemented by background workers that can report their health.
type HealthReporter interface {
	// WorkerName returns a unique identifier for this worker.
	WorkerName() string
	// HealthStatus returns the current health of the worker.
	HealthStatus() WorkerStatus
}

// HealthRegistry collects health from all registered background workers.
type HealthRegistry struct {
	mu      sync.RWMutex
	workers map[string]HealthReporter
	logger  *zap.Logger
}

var workerLastTick = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "worker_last_tick_seconds",
	Help: "Unix timestamp of the last tick for each background worker",
}, []string{"worker"})

func init() {
	prometheus.MustRegister(workerLastTick)
}

// NewHealthRegistry creates a new HealthRegistry.
func NewHealthRegistry(logger *zap.Logger) *HealthRegistry {
	return &HealthRegistry{
		workers: make(map[string]HealthReporter),
		logger:  logger,
	}
}

// Register adds a worker to the health registry.
func (r *HealthRegistry) Register(w HealthReporter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.workers[w.WorkerName()] = w
	r.logger.Info("registered worker for health monitoring", zap.String("worker", w.WorkerName()))
}

// Status returns the health status of all registered workers.
func (r *HealthRegistry) Status() map[string]WorkerStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]WorkerStatus, len(r.workers))
	for name, w := range r.workers {
		status := w.HealthStatus()
		// Update Prometheus gauge
		if !status.LastTick.IsZero() {
			workerLastTick.WithLabelValues(name).Set(float64(status.LastTick.Unix()))
		}
		result[name] = status
	}
	return result
}

// IsHealthy returns true if all registered workers are healthy.
// A worker is unhealthy if it hasn't ticked in more than 2x its expected interval.
func (r *HealthRegistry) IsHealthy() bool {
	for _, s := range r.Status() {
		if !s.Healthy {
			return false
		}
	}
	return true
}

// Summary returns a human-readable summary for /readyz.
func (r *HealthRegistry) Summary() map[string]interface{} {
	statuses := r.Status()
	allHealthy := true
	for _, s := range statuses {
		if !s.Healthy {
			allHealthy = false
			break
		}
	}
	return map[string]interface{}{
		"healthy": allHealthy,
		"workers": statuses,
	}
}

// TickWorker is a helper for workers to report their health.
// Embed this in your worker struct and call RecordTick() on each iteration.
type TickWorker struct {
	name        string
	interval    time.Duration
	lastTick    time.Time
	jobsHandled int64
	mu          sync.Mutex
}

// NewTickWorker creates a TickWorker helper with the given name and expected interval.
func NewTickWorker(name string, interval time.Duration) *TickWorker {
	return &TickWorker{
		name:     name,
		interval: interval,
	}
}

// RecordTick should be called at the start of each worker iteration.
func (t *TickWorker) RecordTick(jobsHandled int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastTick = time.Now()
	t.jobsHandled += int64(jobsHandled)
}

// WorkerName implements HealthReporter.
func (t *TickWorker) WorkerName() string {
	return t.name
}

// HealthStatus implements HealthReporter.
func (t *TickWorker) HealthStatus() WorkerStatus {
	t.mu.Lock()
	defer t.mu.Unlock()

	healthy := true
	msg := ""
	if t.lastTick.IsZero() {
		healthy = false
		msg = "worker has not ticked yet"
	} else if t.interval > 0 {
		staleThreshold := 2 * t.interval
		if time.Since(t.lastTick) > staleThreshold {
			healthy = false
			msg = fmt.Sprintf("worker hasn't ticked in %v (threshold: %v)", time.Since(t.lastTick).Round(time.Second), staleThreshold)
		}
	}

	return WorkerStatus{
		Name:        t.name,
		LastTick:    t.lastTick,
		JobsHandled: t.jobsHandled,
		Healthy:     healthy,
		Message:     msg,
	}
}
