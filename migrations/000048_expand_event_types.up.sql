-- Bring this migration set's event-type allow-list up to the same vocabulary
-- the commercial repository uses, and add the failure event both sets were
-- missing.
--
-- WHY THIS WAS NEEDED. The commercial set expanded compliance_events
-- .event_type in 000043 and then collapsed it again in 000052, which was
-- repaired in that repository as 000054. This migration set never had the
-- expansion, so its constraint still permitted only the original four plus
-- the two Article 14 types. That is thirteen event types short of the
-- commercial set, and it included vulnerability_discovered — the core
-- lifecycle event, written by the product's own code in this repository. An
-- OSS deployment could not record a vulnerability being found.
--
-- The unit and integration tests did not catch it, because the SQLite test
-- schema carries no CHECK constraints at all, and the BDD suite runs against
-- this repository's own migrations only when pointed at the commercial ones.
--
-- enisa_submission_failed is added in both sets. The product writes it from
-- enisa_service.go when a regulatory submission does not succeed, and neither
-- set permitted it: a failed Article 14 filing could not be recorded in the
-- signed audit chain, which is precisely the record an auditor asks about.
ALTER TABLE compliance.compliance_events
    DROP CONSTRAINT IF EXISTS compliance_events_event_type_check;

ALTER TABLE compliance.compliance_events
    ADD CONSTRAINT compliance_events_event_type_check
    CHECK (event_type IN (
        'exploited_reported',
        'sla_breach',
        'sla_tracked',
        'sla_violation',
        'enisa_submission',
        'enisa_submitted',
        'enisa_submission_failed',
        'notification_sent',
        'vulnerability_discovered',
        'vulnerability_matched',
        'vulnerability_enriched',
        'vulnerability_scanned',
        'disclosure_received',
        'disclosure_acknowledged',
        'disclosure_fixed',
        'disclosure_published',
        'csaf_published',
        'csaf_updated',
        'cra_deadline_missed',
        'cra_submission_late'
    ));
