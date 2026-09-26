-- CRA Article 14 awareness provenance and reporting-scope separation.
--
-- Rationale: every Article 14 deadline runs from the moment the MANUFACTURER
-- became aware, not from CVE publication, feed ingestion, scan time, ticket
-- creation, triage acknowledgement or submission time. awareness_at therefore
-- becomes a first-class, evidenced, auditable column rather than being inferred
-- from whichever feed timestamp happened to arrive first.
--
-- awareness_* is nullable: a vulnerability can be tracked long before anyone
-- asserts that it is being exploited, and NULL here means exactly that — no
-- reportable determination has been made. A NULL awareness_at must never be
-- silently substituted with a feed timestamp.
ALTER TABLE compliance.vulnerabilities
    ADD COLUMN IF NOT EXISTS awareness_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS awareness_source TEXT,
    ADD COLUMN IF NOT EXISTS awareness_evidence TEXT,
    ADD COLUMN IF NOT EXISTS awareness_recorded_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS awareness_recorded_by TEXT,
    -- True once evidence of active exploitation is asserted, which is the
    -- Article 14 reportability condition. Distinct from exploited_in_wild,
    -- which records a feed's assertion; this records the manufacturer's own
    -- evidenced determination.
    ADD COLUMN IF NOT EXISTS active_exploitation_confirmed BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE compliance.vulnerabilities
    ADD CONSTRAINT vulnerabilities_awareness_source_check
        CHECK (awareness_source IS NULL OR awareness_source IN (
            'internal_telemetry', 'cert', 'vendor_advisory', 'intelligence', 'exploit_evidence'
        )),
    -- Evidence of how the manufacturer came to know is mandatory whenever an
    -- awareness instant is recorded. A bare timestamp is not defensible in a
    -- post-market audit.
    ADD CONSTRAINT vulnerabilities_awareness_evidence_required
        CHECK (awareness_at IS NULL OR (awareness_evidence IS NOT NULL AND btrim(awareness_evidence) <> ''));

-- Partial index: the reporting clock only needs rows that have an anchor.
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_awareness_at
    ON compliance.vulnerabilities(awareness_at)
    WHERE awareness_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_confirmed_exploitation
    ON compliance.vulnerabilities(org_id, cve)
    WHERE active_exploitation_confirmed = TRUE;

-- sla_tracking.obligation_type separates the two duties that were previously
-- conflated into one deadline:
--
--   'handling'    — an internal vulnerability-handling window (remediate a
--                   critical finding). Driven by CVSS severity. NOT a CRA
--                   Article 14 reporting obligation.
--   'article_14'  — a CRA Article 14 reporting obligation. Anchored on
--                   awareness_at. NOT driven by CVSS severity.
--
-- Existing rows predate Article 14 enforcement and are handling windows by
-- construction, so they are backfilled as such rather than being silently
-- relabelled as regulatory reporting deadlines they never were.
ALTER TABLE compliance.sla_tracking
    ADD COLUMN IF NOT EXISTS obligation_type TEXT NOT NULL DEFAULT 'handling',
    ADD COLUMN IF NOT EXISTS anchor_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS anchor_name TEXT;

ALTER TABLE compliance.sla_tracking
    ADD CONSTRAINT sla_tracking_obligation_type_check
        CHECK (obligation_type IN ('handling', 'article_14'));

-- A reporting obligation is meaningless without its anchor.
ALTER TABLE compliance.sla_tracking
    ADD CONSTRAINT sla_tracking_article14_requires_anchor
        CHECK (obligation_type <> 'article_14' OR anchor_at IS NOT NULL);
