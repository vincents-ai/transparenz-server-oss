ALTER TABLE compliance.compliance_events DROP COLUMN IF EXISTS event_hash;
ALTER TABLE compliance.compliance_events DROP COLUMN IF EXISTS previous_event_hash;
ALTER TABLE compliance.compliance_events DROP COLUMN IF EXISTS signing_key_id;
ALTER TABLE compliance.compliance_events DROP COLUMN IF EXISTS signature;
