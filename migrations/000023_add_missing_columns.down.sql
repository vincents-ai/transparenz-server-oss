ALTER TABLE compliance.scans DROP COLUMN IF EXISTS status;
ALTER TABLE compliance.enisa_submissions DROP COLUMN IF EXISTS retry_count;
