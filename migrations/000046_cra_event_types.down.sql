-- Removes the two Article 14 event types from the allow-list.
--
-- Rows using them must be removed first: the constraint cannot be narrowed
-- while they exist. That is deliberate. These are signed audit events, and
-- silently deleting them to satisfy a rollback would destroy the record of a
-- missed regulatory obligation — which is the one thing this table exists to
-- hold.
DELETE FROM compliance.compliance_events
    WHERE event_type IN ('cra_deadline_missed', 'cra_submission_late');

ALTER TABLE compliance.compliance_events
    DROP CONSTRAINT IF EXISTS compliance_events_event_type_check;

ALTER TABLE compliance.compliance_events
    ADD CONSTRAINT compliance_events_event_type_check
    CHECK (event_type IN (
        'exploited_reported',
        'sla_breach',
        'enisa_submission',
        'notification_sent'
    ));
