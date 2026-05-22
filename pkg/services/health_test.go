package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHealthRegistry_RegisterAndStatus(t *testing.T) {
	registry := NewHealthRegistry(zap.NewNop())

	tw := NewTickWorker("test-worker", 10*time.Second)
	registry.Register(tw)

	statuses := registry.Status()
	require.Contains(t, statuses, "test-worker")
	assert.False(t, statuses["test-worker"].Healthy, "unticked worker should be unhealthy")
	assert.Equal(t, "worker has not ticked yet", statuses["test-worker"].Message)
}

func TestHealthRegistry_HealthyAfterTick(t *testing.T) {
	registry := NewHealthRegistry(zap.NewNop())

	tw := NewTickWorker("scan-worker", 10*time.Second)
	registry.Register(tw)

	tw.RecordTick(5)

	statuses := registry.Status()
	assert.True(t, statuses["scan-worker"].Healthy)
	assert.Equal(t, int64(5), statuses["scan-worker"].JobsHandled)
	assert.True(t, registry.IsHealthy())
}

func TestHealthRegistry_UnhealthyWhenStale(t *testing.T) {
	registry := NewHealthRegistry(zap.NewNop())

	tw := NewTickWorker("stale-worker", 1*time.Millisecond)
	registry.Register(tw)

	tw.RecordTick(1)
	time.Sleep(5 * time.Millisecond) // let it go stale

	statuses := registry.Status()
	assert.False(t, statuses["stale-worker"].Healthy)
	assert.Contains(t, statuses["stale-worker"].Message, "hasn't ticked")
	assert.False(t, registry.IsHealthy())
}

func TestHealthRegistry_MultipleWorkers(t *testing.T) {
	registry := NewHealthRegistry(zap.NewNop())

	w1 := NewTickWorker("scan", 10*time.Second)
	w2 := NewTickWorker("sla", 10*time.Second)
	registry.Register(w1)
	registry.Register(w2)

	w1.RecordTick(10)
	// w2 not ticked

	assert.False(t, registry.IsHealthy(), "one unhealthy worker makes registry unhealthy")

	summary := registry.Summary()
	require.Contains(t, summary, "workers")
	assert.False(t, summary["healthy"].(bool))
}

func TestHealthRegistry_ZeroInterval(t *testing.T) {
	registry := NewHealthRegistry(zap.NewNop())

	tw := NewTickWorker("oneshot", 0) // no interval check
	registry.Register(tw)
	tw.RecordTick(1)

	statuses := registry.Status()
	assert.True(t, statuses["oneshot"].Healthy, "zero-interval worker should always be healthy after first tick")
}

func TestTickWorker_JobCountAccumulates(t *testing.T) {
	tw := NewTickWorker("counter", time.Minute)
	tw.RecordTick(3)
	tw.RecordTick(7)

	status := tw.HealthStatus()
	assert.Equal(t, int64(10), status.JobsHandled)
}
