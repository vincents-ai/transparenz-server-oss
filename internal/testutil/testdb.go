package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// SetupTestDB creates an in-memory SQLite database with the compliance schema
// attached and all required tables created with SQLite-compatible DDL.
func SetupTestDB(t *testing.T, tables ...string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec("ATTACH DATABASE ':memory:' AS compliance").Error)

	allDDL := map[string]string{
		"organizations": `CREATE TABLE IF NOT EXISTS "compliance"."organizations" (
			id text PRIMARY KEY, name text NOT NULL, slug text NOT NULL,
			enisa_submission_mode text DEFAULT 'export', csaf_scope text DEFAULT 'per_sbom',
			pdf_template text DEFAULT 'generic', sla_tracking_mode text DEFAULT 'per_cve',
			tier text NOT NULL DEFAULT 'standard', sla_mode text NOT NULL DEFAULT 'alerts_only',
			multi_tenant_mode text DEFAULT 'shared', enisa_api_endpoint text,
			enisa_api_key_encrypted text, support_period_months integer DEFAULT 60,
			support_start_date datetime, support_end_date datetime,
			created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"greenbone_webhooks": `CREATE TABLE IF NOT EXISTS "compliance"."greenbone_webhooks" (
			id text PRIMARY KEY, org_id text NOT NULL, name text NOT NULL,
			secret_hash text NOT NULL, actions text DEFAULT '{}',
			signing_secret text DEFAULT '',
			active integer DEFAULT 1, created_at datetime DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP, last_used_at datetime
		)`,
		"sbom_webhooks": `CREATE TABLE IF NOT EXISTS "compliance"."sbom_webhooks" (
			id text PRIMARY KEY, org_id text NOT NULL, name text NOT NULL,
			secret_hash text NOT NULL, actions text DEFAULT '{}',
			signing_secret text DEFAULT '',
			active integer DEFAULT 1, created_at datetime DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP, last_used_at datetime
		)`,
		"scans": `CREATE TABLE IF NOT EXISTS "compliance"."scans" (
			id text PRIMARY KEY, org_id text NOT NULL, sbom_id text NOT NULL,
			status text DEFAULT 'pending', scan_date datetime DEFAULT CURRENT_TIMESTAMP,
			scanner_version text, scanner_source text DEFAULT 'grype',
			gvm_report_id text, vulnerabilities_found integer DEFAULT 0,
			created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"greenbone_findings": `CREATE TABLE IF NOT EXISTS "compliance"."greenbone_findings" (
			id text PRIMARY KEY, org_id text NOT NULL, scan_id text NOT NULL,
			gvm_report_id text NOT NULL, gvm_result_id text NOT NULL,
			gvm_nvt_oid text NOT NULL, cve text, host text NOT NULL,
			port text, severity real, threat text, name text NOT NULL,
			description text, qod integer, vulnerability_id text,
			created_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"vulnerabilities": `CREATE TABLE IF NOT EXISTS "compliance"."vulnerabilities" (
			id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
			cvss_score real, severity text, exploited_in_wild integer DEFAULT 0,
			kev_date_added datetime, euvd_id text DEFAULT '',
			"bsi_tr_03116_compliant" integer,
			sovereign_feed_source text DEFAULT '',
			discovered_at datetime DEFAULT CURRENT_TIMESTAMP,
			created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"sbom_uploads": `CREATE TABLE IF NOT EXISTS "compliance"."sbom_uploads" (
			id text PRIMARY KEY, org_id text NOT NULL, filename text NOT NULL,
			format text NOT NULL, size_bytes integer NOT NULL,
			sha256 text NOT NULL, document blob NOT NULL,
			created_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"vulnerability_feeds": `CREATE TABLE IF NOT EXISTS "compliance"."vulnerability_feeds" (
			id text PRIMARY KEY, cve text NOT NULL UNIQUE,
			kev_exploited integer DEFAULT 0, kev_date_added datetime,
			enisa_euvd_id text DEFAULT '', enisa_severity text DEFAULT '',
			bsi_advisory_id text DEFAULT '', bsi_tr_03116_compliant integer,
			affected_products text DEFAULT '[]',
			description text DEFAULT NULL,
			base_score real DEFAULT NULL, base_score_vector text DEFAULT '',
			epss_score real DEFAULT NULL, exploited_since datetime DEFAULT NULL,
			bsi_severity text DEFAULT '', kev_sources text DEFAULT NULL,
			last_synced_at datetime DEFAULT CURRENT_TIMESTAMP,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"vex_statements": `CREATE TABLE IF NOT EXISTS "compliance"."vex_statements" (
			id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
			product_id text NOT NULL DEFAULT '', justification text NOT NULL DEFAULT 'component_not_present',
			impact_statement text DEFAULT '', confidence text NOT NULL DEFAULT 'unknown',
			valid_until datetime, status text NOT NULL DEFAULT 'draft',
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"vex_publications": `CREATE TABLE IF NOT EXISTS "compliance"."vex_publications" (
			id text PRIMARY KEY, vex_id text NOT NULL,
			published_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			channel text NOT NULL DEFAULT 'file',
			response text DEFAULT '{}',
			status text NOT NULL DEFAULT 'pending',
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"signing_keys": `CREATE TABLE IF NOT EXISTS "compliance"."signing_keys" (
			id text PRIMARY KEY, org_id text NOT NULL,
			public_key text NOT NULL, key_algorithm text NOT NULL DEFAULT 'ed25519',
			revoked_at datetime,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"enisa_submissions": `CREATE TABLE IF NOT EXISTS "compliance"."enisa_submissions" (
			id text PRIMARY KEY, org_id text NOT NULL, submission_id text UNIQUE,
			csaf_document text DEFAULT '{}', status text DEFAULT 'pending',
			retry_count integer DEFAULT 0, submitted_at datetime,
			response text, created_at datetime DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"grc_mappings": `CREATE TABLE IF NOT EXISTS "compliance"."grc_mappings" (
			id text PRIMARY KEY, org_id text NOT NULL, vulnerability_id text,
			control_id text NOT NULL, framework text NOT NULL,
			mapping_type text NOT NULL, confidence real DEFAULT 0,
			evidence text DEFAULT '',
			created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"vulnerability_disclosures": `CREATE TABLE IF NOT EXISTS "compliance"."vulnerability_disclosures" (
			id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
			title text NOT NULL, description text DEFAULT '',
			severity text NOT NULL DEFAULT 'medium', status text NOT NULL DEFAULT 'received',
			reporter_name text DEFAULT '', reporter_email text DEFAULT '',
			reporter_public integer DEFAULT 0, coordinator_name text DEFAULT '',
			coordinator_email text DEFAULT '', internal_notes text DEFAULT '',
			fix_commit text DEFAULT '', fix_version text DEFAULT '',
			disclosure_date datetime, cve_assigned integer DEFAULT 0,
			created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP,
			received_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP, acknowledged_at datetime,
			fixing_started_at datetime, fixed_at datetime,
			disclosed_at datetime, rejected_at datetime, withdrawn_at datetime
		)`,
		"sla_tracking": `CREATE TABLE IF NOT EXISTS "compliance"."sla_tracking" (
			id text PRIMARY KEY, org_id text NOT NULL, cve text NOT NULL,
			sbom_id text, deadline datetime NOT NULL, status text DEFAULT 'pending',
			notified_at datetime,
			created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"org_telemetry_configs": `CREATE TABLE IF NOT EXISTS "compliance"."org_telemetry_configs" (
			id text PRIMARY KEY, org_id text NOT NULL UNIQUE,
			provider text NOT NULL DEFAULT 'prometheus', otel_endpoint text DEFAULT '',
			otel_headers text DEFAULT '{}', metrics_token_hash text NOT NULL UNIQUE,
			metrics_token_prefix text DEFAULT '',
			active integer NOT NULL DEFAULT 1,
			created_at datetime DEFAULT CURRENT_TIMESTAMP, updated_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
		"scan_vulnerabilities": `CREATE TABLE IF NOT EXISTS "compliance"."scan_vulnerabilities" (
			id text PRIMARY KEY, scan_id text NOT NULL, vulnerability_id text NOT NULL,
			sbom_component_name text DEFAULT '', sbom_component_version text DEFAULT '',
			sbom_component_type text DEFAULT '', sbom_component_p_url text DEFAULT '',
			match_confidence text DEFAULT '', feed_source text DEFAULT '',
			matched_at datetime DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	if len(tables) == 0 {
		for _, ddl := range allDDL {
			require.NoError(t, db.Exec(ddl).Error)
		}
	} else {
		for _, table := range tables {
			ddl, ok := allDDL[table]
			if !ok {
				t.Fatalf("unknown table: %s", table)
			}
			require.NoError(t, db.Exec(ddl).Error)
		}
	}
	return db
}
