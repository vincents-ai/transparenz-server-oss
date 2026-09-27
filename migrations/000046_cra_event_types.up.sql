-- CRA Article 14 audit event types.
--
-- compliance.compliance_events.event_type is a closed allow-list, and it did
-- not contain the Article 14 event types. The deadline sweeper would have
-- failed to record every breach it detected, with a constraint violation
-- rather than a clear error — so a missed 24-hour window would have gone
-- unrecorded in the signed audit chain while the sweeper reported success in
-- its own logs.
--
-- This was found by the PostgreSQL integration tests, not the SQLite unit
-- tests: the SQLite test schema for compliance_events carries no CHECK
-- constraints, so the sweeper's unit tests passed against a schema that does
-- not ship.
--
-- Extending an allow-list is a schema change and is done explicitly here rather
-- than by loosening the constraint, because the list is what stops a typo
-- becoming a permanent, signed, unverifiable assertion in the audit chain.

ALTER TABLE compliance.compliance_events
    DROP CONSTRAINT IF EXISTS compliance_events_event_type_check;

-- The original four are preserved; the two Article 14 types are added.
--
--   cra_deadline_missed   a reporting stage passed its deadline with nothing
--                         filed — a missed regulatory obligation
--   cra_submission_late   a stage WAS filed, but after its deadline. Kept
--                         distinct from the above because they are different
--                         facts: one duty was discharged late, the other was
--                         not discharged at all.
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
