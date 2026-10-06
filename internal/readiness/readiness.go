// Package readiness determines whether this instance should receive traffic.
//
// It exists because the /readyz logic was duplicated: once in cmd/server/main.go,
// which is package main and unreachable from a test, and once in the BDD harness
// bdd/testcontext/app.go, which was a stub returning 200 unconditionally. The two
// copies drifted, and in the harness the drift meant readiness scenarios could not
// fail.
//
// Server and harness now call this one function, so the endpoint they exercise is
// the endpoint that ships.
package readiness

import (
	"context"
	"database/sql"
	"fmt"
)

// HealthChecker reports whether registered subsystems are healthy. It is an
// interface so this package does not force the server and the harness to share a
// registry implementation.
type HealthChecker interface {
	IsHealthy() bool
}

// Checker holds the dependencies a readiness evaluation needs.
type Checker struct {
	// DB is the raw handle. It is taken as *sql.DB rather than *gorm.DB so the
	// harness and the server can both supply one without agreeing on an ORM.
	DB *sql.DB
	// Health is optional; a nil Health means no subsystem registry is configured.
	Health HealthChecker
}

// Result is the outcome of a readiness evaluation.
type Result struct {
	Ready  bool
	Detail string
}

// Evaluate reports whether the instance should receive traffic.
func Evaluate(ctx context.Context, c *Checker) Result {
	if c == nil || c.DB == nil {
		return Result{Detail: "no database handle configured"}
	}
	if err := c.DB.PingContext(ctx); err != nil {
		return Result{Detail: fmt.Sprintf("database unreachable: %v", err)}
	}
	if c.Health != nil && !c.Health.IsHealthy() {
		return Result{Detail: "one or more registered subsystems are unhealthy"}
	}
	return Result{Ready: true}
}

// HTTPStatus maps a result onto the status code callers should return, so the
// server and the harness cannot disagree about what ready means.
func (r Result) HTTPStatus() int {
	if r.Ready {
		return 200
	}
	return 503
}
