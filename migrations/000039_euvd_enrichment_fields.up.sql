ALTER TABLE compliance.vulnerability_feeds ADD COLUMN IF NOT EXISTS base_score DOUBLE PRECISION;
ALTER TABLE compliance.vulnerability_feeds ADD COLUMN IF NOT EXISTS base_score_vector TEXT;
ALTER TABLE compliance.vulnerability_feeds ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION;
ALTER TABLE compliance.vulnerability_feeds ADD COLUMN IF NOT EXISTS exploited_since TIMESTAMPTZ;
ALTER TABLE compliance.vulnerability_feeds ADD COLUMN IF NOT EXISTS bsi_severity TEXT;
ALTER TABLE compliance.vulnerability_feeds ADD COLUMN IF NOT EXISTS kev_sources TEXT[];
