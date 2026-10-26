-- The written statements the SRP asks for, recorded once on the report.
--
-- The remaining gap after migration 000051 was the prose: severity and impact
-- descriptions, the corrective measures taken and the measures users can take,
-- user action, the general information for the 72-hour notification, the initial
-- assessment of a severe incident, and the details of the available security
-- update. A filer typed each of them again for every stage, with nothing to
-- compare the versions against — so the final report could describe a severity
-- the 72-hour notification had contradicted, and no part of the system would
-- notice.
--
-- They live on the report because they are statements about the case, not about
-- one notification. The package derives each one into whichever glossary position
-- the event class uses (v24/v25 for an AEV, i34/i35 for a severe incident), so
-- there is one text per fact and one place to correct it.
--
-- The length limits are the glossary's own, checked here as well as in the domain
-- so a process that bypasses the service cannot store a value the SRP form would
-- truncate.

ALTER TABLE compliance.cra_reports
    ADD COLUMN IF NOT EXISTS severity_description TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS impact_description   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS measures_taken       TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS measures_for_users   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_action          TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS general_information  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS initial_assessment   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS update_details       TEXT NOT NULL DEFAULT '',
    -- i36: the type of threat or root cause likely to have triggered the incident,
    -- required at a severe incident's final report. The investigation produces it
    -- once; typing it again per stage is how two versions of a root cause end up in
    -- one filing.
    ADD COLUMN IF NOT EXISTS root_cause TEXT NOT NULL DEFAULT '',
    -- i31: whether a severe incident is suspected of unlawful or malicious acts.
    -- Required at the early warning, and one of the few facts the first stage must
    -- state that the report did not hold.
    ADD COLUMN IF NOT EXISTS incident_suspected TEXT NOT NULL DEFAULT '';

ALTER TABLE compliance.cra_reports
    -- v24 / i34, v25 / i35, v21 / i32, i39: 4000 characters in the glossary.
    ADD CONSTRAINT cra_reports_severity_description_len CHECK (char_length(severity_description) <= 4000),
    ADD CONSTRAINT cra_reports_impact_description_len   CHECK (char_length(impact_description) <= 4000),
    ADD CONSTRAINT cra_reports_general_information_len  CHECK (char_length(general_information) <= 4000),
    ADD CONSTRAINT cra_reports_initial_assessment_len   CHECK (char_length(initial_assessment) <= 4000),
    -- 16: 2000 characters. 17 and 14: 4000.
    ADD CONSTRAINT cra_reports_measures_taken_len       CHECK (char_length(measures_taken) <= 2000),
    ADD CONSTRAINT cra_reports_measures_for_users_len   CHECK (char_length(measures_for_users) <= 4000),
    ADD CONSTRAINT cra_reports_user_action_len          CHECK (char_length(user_action) <= 4000),
    -- v23: 2000 characters.
    ADD CONSTRAINT cra_reports_update_details_len       CHECK (char_length(update_details) <= 2000),
    -- i36: 255 characters.
    ADD CONSTRAINT cra_reports_root_cause_len           CHECK (char_length(root_cause) <= 255),
    -- i31: 255 characters.
    ADD CONSTRAINT cra_reports_incident_suspected_len   CHECK (char_length(incident_suspected) <= 255);

COMMENT ON COLUMN compliance.cra_reports.severity_description IS
    'SRP v24 (AEV) / i34 (SI). One text per case; the package derives it into the position the event class uses.';
COMMENT ON COLUMN compliance.cra_reports.measures_taken IS
    'SRP 16 (both) and i33 for a severe incident.';
