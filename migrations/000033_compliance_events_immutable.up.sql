CREATE OR REPLACE FUNCTION compliance.prevent_compliance_events_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'compliance_events table is immutable: % operation not permitted', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS prevent_compliance_events_update ON compliance.compliance_events;
DROP TRIGGER IF EXISTS prevent_compliance_events_delete ON compliance.compliance_events;

CREATE TRIGGER prevent_compliance_events_update
    BEFORE UPDATE ON compliance.compliance_events
    FOR EACH ROW
    EXECUTE FUNCTION compliance.prevent_compliance_events_mutation();

CREATE TRIGGER prevent_compliance_events_delete
    BEFORE DELETE ON compliance.compliance_events
    FOR EACH ROW
    EXECUTE FUNCTION compliance.prevent_compliance_events_mutation();
