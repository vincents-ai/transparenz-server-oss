ALTER TABLE compliance.vulnerability_feeds DROP COLUMN IF EXISTS base_score;
ALTER TABLE compliance.vulnerability_feeds DROP COLUMN IF EXISTS base_score_vector;
ALTER TABLE compliance.vulnerability_feeds DROP COLUMN IF EXISTS epss_score;
ALTER TABLE compliance.vulnerability_feeds DROP COLUMN IF EXISTS exploited_since;
ALTER TABLE compliance.vulnerability_feeds DROP COLUMN IF EXISTS bsi_severity;
ALTER TABLE compliance.vulnerability_feeds DROP COLUMN IF EXISTS kev_sources;
