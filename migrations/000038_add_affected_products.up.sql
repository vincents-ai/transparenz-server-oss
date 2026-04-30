ALTER TABLE compliance.vulnerability_feeds ADD COLUMN IF NOT EXISTS affected_products JSONB DEFAULT '[]';
