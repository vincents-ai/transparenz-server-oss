ALTER TABLE compliance.cra_reports
    DROP CONSTRAINT IF EXISTS cra_reports_incident_suspected_len,
    DROP CONSTRAINT IF EXISTS cra_reports_root_cause_len,
    DROP CONSTRAINT IF EXISTS cra_reports_update_details_len,
    DROP CONSTRAINT IF EXISTS cra_reports_user_action_len,
    DROP CONSTRAINT IF EXISTS cra_reports_measures_for_users_len,
    DROP CONSTRAINT IF EXISTS cra_reports_measures_taken_len,
    DROP CONSTRAINT IF EXISTS cra_reports_initial_assessment_len,
    DROP CONSTRAINT IF EXISTS cra_reports_general_information_len,
    DROP CONSTRAINT IF EXISTS cra_reports_impact_description_len,
    DROP CONSTRAINT IF EXISTS cra_reports_severity_description_len;

ALTER TABLE compliance.cra_reports
    DROP COLUMN IF EXISTS incident_suspected,
    DROP COLUMN IF EXISTS root_cause,
    DROP COLUMN IF EXISTS update_details,
    DROP COLUMN IF EXISTS initial_assessment,
    DROP COLUMN IF EXISTS general_information,
    DROP COLUMN IF EXISTS user_action,
    DROP COLUMN IF EXISTS measures_for_users,
    DROP COLUMN IF EXISTS measures_taken,
    DROP COLUMN IF EXISTS impact_description,
    DROP COLUMN IF EXISTS severity_description;
