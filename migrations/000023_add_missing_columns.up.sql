ALTER TABLE compliance.scans ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed'));
CREATE INDEX IF NOT EXISTS idx_scans_status ON compliance.scans(status);
ALTER TABLE compliance.enisa_submissions ADD COLUMN IF NOT EXISTS retry_count INT NOT NULL DEFAULT 0;
