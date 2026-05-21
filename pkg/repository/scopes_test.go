package repository

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestTenantScope(t *testing.T) {
	dsn := "postgres://user:pass@localhost:5432/transparenz_test?search_path=compliance"
	if d := os.Getenv("TEST_DATABASE_URL"); d != "" {
		dsn = d
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("test database not available: %v", err)
	}
	t.Cleanup(func() {
		tables := []string{
			"compliance.compliance_events",
			"compliance.sla_tracking",
			"compliance.enisa_submissions",
			"compliance.scans",
			"compliance.vulnerabilities",
			"compliance.organizations",
		}
		for _, table := range tables {
			db.Exec("DELETE FROM " + table)
		}
	})

	orgID := uuid.New()

	tests := []struct {
		name      string
		ctx       context.Context
		wantWhere string
		dontWant  string
	}{
		{
			name:      "valid org id",
			ctx:       middleware.ContextWithOrgID(context.Background(), orgID),
			wantWhere: orgID.String(),
		},
		{
			name:      "no org id",
			ctx:       context.Background(),
			wantWhere: "1 = 0",
		},
		{
			name:     "invalid uuid",
			ctx:      middleware.ContextWithOrgID(context.Background(), uuid.Nil),
			dontWant: orgID.String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := db.Session(&gorm.Session{DryRun: true}).
				Table("compliance.vulnerabilities").
				Scopes(TenantScope(tt.ctx)).
				Select("id").
				Find(&map[string]interface{}{})

			sql := stmt.Statement.SQL.String()

			if tt.wantWhere != "" {
				if !strings.Contains(sql, "WHERE") {
					t.Errorf("SQL = %s, want to contain WHERE clause", sql)
				}
				if tt.wantWhere != "1 = 0" && !strings.Contains(sql, "org_id") {
					t.Errorf("SQL = %s, want to contain org_id clause", sql)
				}
			}
			if tt.dontWant != "" && strings.Contains(sql, tt.dontWant) {
				t.Errorf("SQL = %s, should NOT contain %q", sql, tt.dontWant)
			}
		})
	}
}
