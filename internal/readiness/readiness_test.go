package readiness

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
)

type fakeHealth struct{ healthy bool }

func (f fakeHealth) IsHealthy() bool { return f.healthy }

// stubDriver lets the ping path be driven without a real database and without
// pulling a mocking dependency into a repository whose dependency set was just
// audited down to zero reachable vulnerabilities.
//
// The commercial sibling of this package cannot be tested this way because its
// Checker takes a *gorm.DB and faking one needs a dialector wrapper plus a new
// dependency. Here a *sql.DB is enough, and adding a dependency to avoid a
// thirty-line stub would have been the worse trade.
type stubDriver struct{ err error }

func (d stubDriver) Open(string) (driver.Conn, error) { return stubConn{d.err}, nil }

type stubConn struct{ err error }

func (c stubConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unsupported") }
func (c stubConn) Close() error                        { return nil }
func (c stubConn) Begin() (driver.Tx, error)           { return nil, errors.New("unsupported") }

func (c stubConn) Ping(context.Context) error { return c.err }

func stubDB(t *testing.T, pingErr error) *sql.DB {
	t.Helper()
	name := "stub"
	// A unique name per database keeps the driver registry global state from
	// leaking between parallel tests.
	name = name + t.Name()
	sql.Register(name, stubDriver{err: pingErr})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("open stub database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// A readiness check that reports ready with no database handle is worse than one
// reporting not ready, because it takes the instance into rotation with nothing
// behind it. This is the case most likely to be introduced by a careless edit.
func TestEvaluateNotReadyWithoutHandle(t *testing.T) {
	if got := Evaluate(context.Background(), nil); got.Ready {
		t.Error("a nil checker reported ready")
	} else if got.Detail == "" {
		t.Error("a not-ready result must explain why")
	}
	if got := Evaluate(context.Background(), &Checker{}); got.Ready {
		t.Error("a checker with no database handle reported ready")
	}
}

func TestEvaluateReadyWhenDatabaseAnswers(t *testing.T) {
	got := Evaluate(context.Background(), &Checker{DB: stubDB(t, nil)})
	if !got.Ready {
		t.Errorf("reported not ready with a healthy database: %s", got.Detail)
	}
	if got.Detail != "" {
		t.Errorf("a ready result carries detail %q", got.Detail)
	}
}

func TestEvaluateNotReadyWhenDatabaseUnreachable(t *testing.T) {
	got := Evaluate(context.Background(), &Checker{DB: stubDB(t, errors.New("connection refused"))})
	if got.Ready {
		t.Error("reported ready with an unreachable database")
	}
	if got.HTTPStatus() != 503 {
		t.Errorf("status %d, want 503", got.HTTPStatus())
	}
	if got.Detail == "" {
		t.Error("a not-ready result must explain why")
	}
}

// The instance-per-org rule: an unhealthy registered subsystem means not ready
// even when the database answers. Reporting ready in that state sends traffic to
// an instance that cannot serve it, which is worse than a blanket outage because
// the failure is partial and intermittent.
func TestEvaluateNotReadyWhenSubsystemUnhealthy(t *testing.T) {
	got := Evaluate(context.Background(), &Checker{
		DB: stubDB(t, nil), Health: fakeHealth{healthy: false},
	})
	if got.Ready {
		t.Error("reported ready with an unhealthy subsystem")
	}
}

func TestEvaluateReadyWithHealthySubsystem(t *testing.T) {
	got := Evaluate(context.Background(), &Checker{
		DB: stubDB(t, nil), Health: fakeHealth{healthy: true},
	})
	if !got.Ready {
		t.Errorf("reported not ready with a healthy database and subsystem: %s", got.Detail)
	}
}

// HTTPStatus lives with the decision so the server and the harness cannot
// disagree about what ready means. Both directions are checked because a
// one-sided check would pass with the mapping inverted in production code.
func TestHTTPStatus(t *testing.T) {
	if got := (Result{Ready: true}).HTTPStatus(); got != 200 {
		t.Errorf("ready maps to %d, want 200", got)
	}
	if got := (Result{}).HTTPStatus(); got != 503 {
		t.Errorf("not-ready maps to %d, want 503", got)
	}
}
