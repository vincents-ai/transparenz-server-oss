-- Columns are dropped rather than nulled: once a reporting obligation is
-- removed, leaving a stale anchor behind would let a later report be
-- reconstructed against a deadline that no longer exists.
ALTER TABLE compliance.sla_tracking
    DROP CONSTRAINT IF EXISTS sla_tracking_article14_requires_anchor,
    DROP CONSTRAINT IF EXISTS sla_tracking_obligation_type_check;

ALTER TABLE compliance.sla_tracking
    DROP COLUMN IF EXISTS anchor_name,
    DROP COLUMN IF EXISTS anchor_at,
    DROP COLUMN IF EXISTS obligation_type;

DROP INDEX IF EXISTS compliance.idx_vulnerabilities_confirmed_exploitation;
DROP INDEX IF EXISTS compliance.idx_vulnerabilities_awareness_at;

ALTER TABLE compliance.vulnerabilities
    DROP CONSTRAINT IF EXISTS vulnerabilities_awareness_evidence_required,
    DROP CONSTRAINT IF EXISTS vulnerabilities_awareness_source_check;

ALTER TABLE compliance.vulnerabilities
    DROP COLUMN IF EXISTS active_exploitation_confirmed,
    DROP COLUMN IF EXISTS awareness_recorded_by,
    DROP COLUMN IF EXISTS awareness_recorded_at,
    DROP COLUMN IF EXISTS awareness_evidence,
    DROP COLUMN IF EXISTS awareness_source,
    DROP COLUMN IF EXISTS awareness_at;
