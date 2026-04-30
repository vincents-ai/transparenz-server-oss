DROP TRIGGER IF EXISTS prevent_compliance_events_update ON compliance.compliance_events;
DROP TRIGGER IF EXISTS prevent_compliance_events_delete ON compliance.compliance_events;
DROP FUNCTION IF EXISTS compliance.prevent_compliance_events_mutation();
