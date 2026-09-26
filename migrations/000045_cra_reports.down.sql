-- Drop in dependency order. The append-only triggers are dropped with their
-- tables; the functions are dropped explicitly because a trigger function
-- outlives its table otherwise.
DROP TRIGGER IF EXISTS cra_coordinator_selections_manual ON compliance.cra_coordinator_selections;
DROP TABLE IF EXISTS compliance.cra_coordinator_selections;

DROP TRIGGER IF EXISTS cra_awareness_audit_no_update ON compliance.cra_awareness_audit;
DROP TABLE IF EXISTS compliance.cra_awareness_audit;
DROP FUNCTION IF EXISTS compliance.cra_awareness_audit_append_only();

DROP TABLE IF EXISTS compliance.cra_submissions;

DROP TRIGGER IF EXISTS cra_report_events_no_update ON compliance.cra_report_events;
DROP TABLE IF EXISTS compliance.cra_report_events;
DROP FUNCTION IF EXISTS compliance.cra_report_events_append_only();

-- Reports reference themselves for duplicate_of, so the self-reference is
-- dropped with the table.
DROP TABLE IF EXISTS compliance.cra_reports;
