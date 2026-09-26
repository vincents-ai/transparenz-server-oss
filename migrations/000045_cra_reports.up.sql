-- CRA Article 14 reporting records.
--
-- This is the storage for the regulatory objects modelled in
-- pkg/regulatory/cra. It is deliberately NOT a general "findings" table: a
-- report is a legal artefact with a clock, a state machine, a retained
-- decision log and a submission history, and flattening any of those into
-- columns on a vulnerability would destroy the evidence the record exists to
-- preserve.
--
-- Design rules encoded below, each of which the Go domain enforces too. The
-- database is the last line of defence: these constraints hold even for a
-- process that bypasses the service layer, and a migration mistake is silent
-- in a way a failed INSERT is not.

-- ---------------------------------------------------------------------------
-- Reports
-- ---------------------------------------------------------------------------
-- event_type is pinned by state: REPORTABLE_AEV implies an AEV report and
-- REPORTABLE_SI a severe incident. An AEV has a CVE; a severe incident does
-- not necessarily have one, but may if a tracked vulnerability is the cause.
CREATE TABLE compliance.cra_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,

    cve TEXT NOT NULL DEFAULT '',
    euvd_id TEXT NOT NULL DEFAULT '',

    -- NULL until the human determination is made. Never inferred from
    -- severity, from KEV membership, or from the presence of a scan match.
    event_type TEXT,

    -- Mirrors the state machine in pkg/regulatory/cra/event.go. Terminal
    -- states are absorbing in the domain; here they are simply enumerated so
    -- an unexpected value is rejected at write time.
    state TEXT NOT NULL DEFAULT 'DETECTED' CHECK (state IN (
        'DETECTED',
        'ASSESSING_REPORTABILITY',
        'REPORTABLE_AEV',
        'REPORTABLE_SI',
        'EARLY_WARNING_DRAFT',
        'EARLY_WARNING_SUBMITTED',
        'NOTIFICATION_72H_DRAFT',
        'NOTIFICATION_72H_SUBMITTED',
        'FINAL_REPORT_DRAFT',
        'FINAL_REPORT_SUBMITTED',
        'CLOSED',
        'NOT_REPORTABLE',
        'FALSE_POSITIVE',
        'DUPLICATE',
        'UNDER_INVESTIGATION'
    )),

    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',

    -- The product and component the obligation actually attaches to. The
    -- duty is owed in respect of the product, not the upstream library.
    product_id TEXT NOT NULL DEFAULT '',
    product_name TEXT NOT NULL DEFAULT '',
    sbom_id UUID,
    component_name TEXT NOT NULL DEFAULT '',
    component_version TEXT NOT NULL DEFAULT '',
    component_purl TEXT NOT NULL DEFAULT '',

    -- Article 14 clock anchor. Nullable, and nullable on purpose: a detected
    -- vulnerability is not yet an awareness event. NULL means the clock has
    -- not started; it must never be backfilled from kev_date_added or
    -- discovered_at.
    awareness_at TIMESTAMPTZ,
    awareness_source TEXT CHECK (awareness_source IS NULL OR awareness_source IN (
        'internal_telemetry', 'cert', 'vendor_advisory', 'intelligence', 'exploit_evidence'
    )),
    -- How the manufacturer came to know is mandatory whenever the instant is
    -- recorded. A bare timestamp is not defensible in a post-market audit.
    awareness_evidence TEXT NOT NULL DEFAULT '',
    awareness_reasoning TEXT NOT NULL DEFAULT '',
    awareness_recorded_at TIMESTAMPTZ,
    awareness_recorded_by TEXT NOT NULL DEFAULT '',

    -- Exploitation evidence supporting an AEV determination.
    exploitation_observed_at TIMESTAMPTZ,
    exploitation_source TEXT,
    exploitation_reference TEXT NOT NULL DEFAULT '',
    exploitation_summary TEXT NOT NULL DEFAULT '',
    exploitation_attack_vector TEXT NOT NULL DEFAULT '',
    exploitation_actor TEXT NOT NULL DEFAULT '',
    exploitation_scope TEXT NOT NULL DEFAULT '',

    -- AEV final-report anchor: when a corrective or mitigating measure became
    -- available. The 14-day window starts here, not at awareness, because the
    -- manufacturer is not required to report a remediation that does not exist.
    -- NULL for severe incidents, which anchor on the 72h submission instead.
    mitigation_available_at TIMESTAMPTZ,

    -- Particular Exceptional Circumstances. AEV's 72-hour notification only.
    pec_applicable BOOLEAN NOT NULL DEFAULT FALSE,
    pec_grounds TEXT[] NOT NULL DEFAULT '{}',
    pec_reasoning TEXT NOT NULL DEFAULT '',
    pec_evidence TEXT[] NOT NULL DEFAULT '{}',
    pec_delay_requested INTERVAL,
    pec_decision_at TIMESTAMPTZ,
    pec_decision_by TEXT NOT NULL DEFAULT '',

    -- CSIRT designated as coordinator. Recorded even while NULL, because an
    -- undetermined coordinator is a blocking gap that must be visible.
    csirt_id TEXT NOT NULL DEFAULT '',
    csirt_country TEXT NOT NULL DEFAULT '',
    csirt_selection_basis TEXT CHECK (csirt_selection_basis IS NULL OR csirt_selection_basis IN (
        'establishment_country', 'eu_representative', 'marketed_in',
        'affected_users', 'manual_override'
    )),
    csirt_justification TEXT NOT NULL DEFAULT '',
    csirt_selected_at TIMESTAMPTZ,
    csirt_selected_by TEXT NOT NULL DEFAULT '',

    -- A non-reportable exit must say why. "Not reportable" with no reasoning
    -- is indistinguishable from "we never looked", and that distinction is
    -- exactly what an authority asks about.
    disposition_reason TEXT NOT NULL DEFAULT '',
    duplicate_of UUID REFERENCES compliance.cra_reports(id) ON DELETE SET NULL,

    closed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT cra_reports_awareness_evidence_required
        CHECK (awareness_at IS NULL OR btrim(awareness_evidence) <> ''),

    -- An AEV determination requires exploitation evidence. A CVSS score is
    -- not exploitation evidence and cannot satisfy this.
    CONSTRAINT cra_reports_aev_requires_exploitation_evidence
        CHECK (event_type IS DISTINCT FROM 'ACTIVELY_EXPLOITED_VULNERABILITY'
               OR btrim(exploitation_reference) <> ''),

    -- PEC is available only for an actively exploited vulnerability's
    -- 72-hour notification. Encoding it here means a severe incident cannot
    -- carry a PEC claim even via a process that bypasses the domain.
    CONSTRAINT cra_reports_pec_is_aev_only
        CHECK (NOT pec_applicable OR event_type = 'ACTIVELY_EXPLOITED_VULNERABILITY'),

    -- A PEC claim is a human or legal decision with evidence, never an
    -- automatic determination.
    CONSTRAINT cra_reports_pec_requires_human_decision
        CHECK (NOT pec_applicable
               OR (btrim(pec_reasoning) <> ''
                   AND cardinality(pec_grounds) > 0
                   AND cardinality(pec_evidence) > 0
                   AND pec_decision_at IS NOT NULL
                   AND btrim(pec_decision_by) <> '')),

    -- A manual coordinator override must be justified in writing.
    CONSTRAINT cra_reports_manual_csirt_requires_justification
        CHECK (csirt_selection_basis IS DISTINCT FROM 'manual_override'
               OR btrim(csirt_justification) <> ''),

    -- A severe incident's final report is due one calendar month after the
    -- 72-hour notification; an AEV's is due 14 days after a mitigation
    -- becomes available. The two rules have different anchors, so an SI report
    -- carrying a mitigation anchor is a category error rather than a harmless
    -- extra field: it would be computed under the wrong rule.
    CONSTRAINT cra_reports_si_must_not_carry_mitigation_anchor
        CHECK (event_type IS DISTINCT FROM 'SEVERE_INCIDENT'
               OR mitigation_available_at IS NULL)
);

CREATE INDEX idx_cra_reports_org_state ON compliance.cra_reports(org_id, state);
CREATE INDEX idx_cra_reports_org_cve ON compliance.cra_reports(org_id, cve);
-- Partial index: the reporting clock only queries rows that have an anchor.
CREATE INDEX idx_cra_reports_awareness ON compliance.cra_reports(awareness_at)
    WHERE awareness_at IS NOT NULL;
CREATE INDEX idx_cra_reports_product ON compliance.cra_reports(org_id, product_id)
    WHERE product_id <> '';

-- ---------------------------------------------------------------------------
-- Decision log (append-only)
-- ---------------------------------------------------------------------------
-- Every classification and transition, with its actor and reason. This is the
-- answer to "why is or isn't this reportable?" and it is retained rather than
-- recomputed, because a conclusion that cannot be traced to the facts it rested
-- on is not evidence of anything.
CREATE TABLE compliance.cra_report_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES compliance.cra_reports(id) ON DELETE CASCADE,
    from_state TEXT NOT NULL DEFAULT '',
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    evidence TEXT[] NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT cra_report_events_requires_actor CHECK (btrim(actor) <> ''),
    -- A corrective decision must say why; a routine stage submission may not.
    CONSTRAINT cra_report_events_disposition_requires_reason
        CHECK (to_state NOT IN ('NOT_REPORTABLE', 'FALSE_POSITIVE', 'DUPLICATE')
               OR btrim(reason) <> '')
);

CREATE INDEX idx_cra_report_events_report
    ON compliance.cra_report_events(report_id, occurred_at);

-- Append-only is enforced here rather than trusted to the service. An audit
-- trail that can be rewritten is not an audit trail.
CREATE OR REPLACE FUNCTION compliance.cra_report_events_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'compliance.cra_report_events is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER cra_report_events_no_update
    BEFORE UPDATE OR DELETE ON compliance.cra_report_events
    FOR EACH ROW EXECUTE FUNCTION compliance.cra_report_events_append_only();

-- ---------------------------------------------------------------------------
-- Submissions
-- ---------------------------------------------------------------------------
-- What was actually sent, when, and the digest of the exact package. The
-- submitted_at value is a fact: it anchors the severe-incident final-report
-- deadline and it is the proof a deadline was met. It is never overwritten on
-- re-submission, because a later "corrected" timestamp is precisely what would
-- let a missed deadline be relabelled as met.
CREATE TABLE compliance.cra_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES compliance.cra_reports(id) ON DELETE CASCADE,
    stage TEXT NOT NULL CHECK (stage IN ('EARLY_WARNING', 'NOTIFICATION_72H', 'FINAL_REPORT')),
    submitted_at TIMESTAMPTZ NOT NULL,
    case_reference TEXT NOT NULL DEFAULT '',
    package_digest TEXT NOT NULL DEFAULT '',
    submitted_by TEXT NOT NULL DEFAULT '',
    -- 'human_srp' is the expected value: the ENISA Single Reporting Platform
    -- publishes no API, so a submission is performed by a person and recorded
    -- here. A future official API adapter would use a different value.
    via TEXT NOT NULL DEFAULT 'human_srp',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One recorded submission per stage. Re-submission updates the reference,
    -- never the instant.
    CONSTRAINT uq_cra_submissions_report_stage UNIQUE (report_id, stage)
);

CREATE INDEX idx_cra_submissions_org ON compliance.cra_submissions(org_id, submitted_at);

-- ---------------------------------------------------------------------------
-- Awareness corrections
-- ---------------------------------------------------------------------------
-- A late-discovered awareness, a timezone mistake, bad feed data: all produce
-- corrections in practice. How the correction was handled is exactly what an
-- authority examines, so the full before/after with actor, reason and evidence
-- is retained. The report's current awareness_at may move; this history cannot
-- be rewritten.
CREATE TABLE compliance.cra_awareness_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES compliance.cra_reports(id) ON DELETE CASCADE,
    old_value TIMESTAMPTZ,
    new_value TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_reference TEXT NOT NULL DEFAULT '',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT cra_awareness_audit_requires_actor CHECK (btrim(actor) <> ''),
    -- A correction without a reason is not auditable and is not a correction.
    CONSTRAINT cra_awareness_audit_requires_reason CHECK (btrim(reason) <> ''),
    -- The initial determination has no old value; every subsequent correction
    -- has both. A "correction" that changes nothing is not accepted.
    CONSTRAINT cra_awareness_audit_must_change_something
        CHECK (old_value IS NULL OR old_value IS DISTINCT FROM new_value)
);

CREATE INDEX idx_cra_awareness_audit_report
    ON compliance.cra_awareness_audit(report_id, changed_at);

CREATE OR REPLACE FUNCTION compliance.cra_awareness_audit_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'compliance.cra_awareness_audit is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER cra_awareness_audit_no_update
    BEFORE UPDATE OR DELETE ON compliance.cra_awareness_audit
    FOR EACH ROW EXECUTE FUNCTION compliance.cra_awareness_audit_append_only();

-- ---------------------------------------------------------------------------
-- Coordinator selection history
-- ---------------------------------------------------------------------------
-- A changed CDaC selection is a decision somebody made and would be asked
-- about. Superseded selections are retained rather than overwritten.
CREATE TABLE compliance.cra_coordinator_selections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES compliance.cra_reports(id) ON DELETE CASCADE,
    csirt_id TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    basis TEXT NOT NULL CHECK (basis IN (
        'establishment_country', 'eu_representative', 'marketed_in',
        'affected_users', 'manual_override'
    )),
    justification TEXT NOT NULL DEFAULT '',
    selected_by TEXT NOT NULL,
    selected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    supersedes_id UUID REFERENCES compliance.cra_coordinator_selections(id) ON DELETE SET NULL,

    CONSTRAINT cra_coordinator_selections_requires_selector CHECK (btrim(selected_by) <> ''),
    CONSTRAINT cra_coordinator_selections_manual_requires_justification
        CHECK (basis <> 'manual_override' OR btrim(justification) <> '')
);

CREATE INDEX idx_cra_coordinator_selections_report
    ON compliance.cra_coordinator_selections(report_id, selected_at);
