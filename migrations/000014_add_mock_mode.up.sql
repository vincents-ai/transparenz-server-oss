ALTER TABLE compliance.organizations DROP CONSTRAINT IF EXISTS organizations_enisa_submission_mode_check;
ALTER TABLE compliance.organizations ADD CONSTRAINT organizations_enisa_submission_mode_check CHECK (enisa_submission_mode IN ('api', 'csirt', 'export', 'mock'));
