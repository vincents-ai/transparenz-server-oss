-- 000036_scans_created_at_index.up.sql
CREATE INDEX IF NOT EXISTS idx_scans_org_created_at
    ON compliance.scans(org_id, created_at);
