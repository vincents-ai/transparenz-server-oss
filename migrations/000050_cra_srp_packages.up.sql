-- Built SRP submission packages, retained as immutable revisions.
--
-- Why this table exists, stated as the defect it removes. Before it, a filing
-- record carried a package_digest that the operator typed. The digest forced
-- them to name a document, which is better than filing blind, but nothing tied
-- that value to anything this service had produced: a transposed character, a
-- digest from a different stage, or a value copied off an old draft all stored
-- identically, and the record then looked verified while asserting nothing.
--
-- A package is now built, validated against the reporting schema, sealed, and
-- stored here. The field set is retained with the digest so the digest can be
-- RECOMPUTED later: verification is a comparison, not a claim. That is the whole
-- point of keeping `fields` — a digest with no field set behind it can only be
-- believed.
--
-- Revisions, not overwrites. Rebuilding a package for the same report and stage
-- creates revision N+1; revision N stays readable, because the question asked
-- after a filing is "what exactly did you send?", and that answer is a document
-- that existed at an instant, not the latest thing we would build today.

CREATE TABLE compliance.cra_srp_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES compliance.organizations(id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES compliance.cra_reports(id) ON DELETE CASCADE,

    -- The glossary stage, not the workflow state. 'notification_72h' is the
    -- 72-hour notification whether the case is early in the workflow or late.
    stage TEXT NOT NULL CHECK (stage IN (
        'early_warning',
        'notification_72h',
        'final_report'
    )),

    -- Monotonic per (report_id, stage). Assigned in the writing transaction.
    revision INTEGER NOT NULL CHECK (revision >= 1),

    -- The reporting schema the package was validated against. A package is only
    -- interpretable alongside the field list that produced it, and that list is
    -- versioned because ENISA revises the glossary.
    schema_id TEXT NOT NULL,

    event_class TEXT NOT NULL CHECK (event_class IN ('AEV', 'SI')),

    -- The CSIRT designated as coordinator the package is addressed to. Filing to
    -- the wrong authority loses the report, so it is recorded, not inferred.
    coordinator_id TEXT NOT NULL,

    -- The glossary field values, keyed by published position, exactly as they
    -- were sealed. Retained so the digest can be recomputed rather than trusted.
    fields JSONB NOT NULL CHECK (jsonb_typeof(fields) = 'object'),

    -- SHA-256 over the canonical serialisation, prefixed with its encoding
    -- version so a digest recorded under the older, ambiguous encoding stays
    -- identifiable as weaker evidence rather than being silently equivalent.
    digest TEXT NOT NULL,

    generated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The principal that built the package. A package is a determination about
    -- a legal artefact, so it is personally attributable like every other step
    -- in the reporting workflow.
    created_by TEXT NOT NULL,

    -- One revision per stage, and one row per document. The digest constraint is
    -- what makes a rebuild of unchanged input idempotent instead of producing a
    -- second revision that differs only in its creation time.
    CONSTRAINT cra_srp_packages_revision_key UNIQUE (report_id, stage, revision),
    CONSTRAINT cra_srp_packages_digest_key UNIQUE (report_id, stage, digest)
);

CREATE INDEX idx_cra_srp_packages_report
    ON compliance.cra_srp_packages(report_id, stage, revision DESC);

CREATE INDEX idx_cra_srp_packages_org
    ON compliance.cra_srp_packages(org_id, created_at DESC);

-- Append-only, enforced here rather than trusted to the service. A package that
-- could be edited after a filing would permit the digest on a submission record
-- to be made true retroactively, which is precisely the claim the record exists
-- to support.
CREATE OR REPLACE FUNCTION compliance.cra_srp_packages_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'compliance.cra_srp_packages is append-only (attempted %)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER cra_srp_packages_no_update
    BEFORE UPDATE OR DELETE ON compliance.cra_srp_packages
    FOR EACH ROW EXECUTE FUNCTION compliance.cra_srp_packages_append_only();
