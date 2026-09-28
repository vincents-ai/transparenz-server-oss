-- The Organization model has carried CsirtEndpoint since the CSIRT endpoint
-- became the preferred submission target, and the REST tests have always had
-- the column because internal/testutil/testdb.go keeps its own hand-written
-- copy of the schema. No migration ever created it, so a database built from
-- the real migrations diverged from both the model and the test schema, and
-- inserting an organisation failed with
--
--   ERROR: column "csirt_endpoint" of relation "organizations" does not exist
--
-- This is additive and nullable, so it is safe on existing installations.
ALTER TABLE compliance.organizations
    ADD COLUMN IF NOT EXISTS csirt_endpoint TEXT;

COMMENT ON COLUMN compliance.organizations.csirt_endpoint IS
    'National CSIRT submission endpoint. Preferred over enisa_api_endpoint, whose name is a misnomer: the ENISA Single Reporting Platform publishes no API. The legacy column is still read as a fallback.';
