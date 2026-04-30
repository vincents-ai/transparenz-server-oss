INSERT INTO compliance.organizations (id, name, slug, tier, sla_mode, enisa_submission_mode, csaf_scope, pdf_template, sla_tracking_mode, created_at, updated_at)
VALUES (
    'a1b2c3d4-e5f6-7890-ab12-cd34e5678f90',
    'Transparenz Internal',
    'transparenz-internal',
    'standard',
    'alerts_only',
    'export',
    'per_sbom',
    'bsi_tr03116',
    'per_cve',
    NOW(), NOW()
);
