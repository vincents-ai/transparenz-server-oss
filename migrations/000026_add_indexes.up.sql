CREATE INDEX IF NOT EXISTS idx_disclosures_org_status ON compliance.vulnerability_disclosures(org_id, status);
CREATE INDEX IF NOT EXISTS idx_disclosures_received_at ON compliance.vulnerability_disclosures(received_at);
CREATE INDEX IF NOT EXISTS idx_sbom_uploads_created_at ON compliance.sbom_uploads(created_at);
