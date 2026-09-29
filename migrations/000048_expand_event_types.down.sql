-- Reverts to this set's original six-value list. This is a narrowing, not a
-- restoration: it removes the fifteen event types added by 000048.
ALTER TABLE compliance.compliance_events
    DROP CONSTRAINT IF EXISTS compliance_events_event_type_check;

ALTER TABLE compliance.compliance_events
    ADD CONSTRAINT compliance_events_event_type_check
    CHECK (event_type IN (
        'exploited_reported',
        'sla_breach',
        'enisa_submission',
        'notification_sent',
        'cra_deadline_missed',
        'cra_submission_late'
    ));
