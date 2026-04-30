ALTER TABLE compliance.compliance_events ADD COLUMN IF NOT EXISTS signature TEXT;
ALTER TABLE compliance.compliance_events ADD COLUMN IF NOT EXISTS signing_key_id UUID REFERENCES compliance.signing_keys(id);
ALTER TABLE compliance.compliance_events ADD COLUMN IF NOT EXISTS previous_event_hash TEXT;
ALTER TABLE compliance.compliance_events ADD COLUMN IF NOT EXISTS event_hash TEXT;
