-- Filing facts the report did not previously hold.
--
-- Why these belong on the report rather than being typed into each package. The
-- SRP asks every filing for the manufacturer, the Member States in which the
-- product is available, and the affected product version. None of those had a
-- column, so a filer re-typed them for the early warning, again for the 72-hour
-- notification and again for the final report — three chances per report to
-- transcribe a name or a country inconsistently, with nothing to compare the
-- result against.
--
-- They are case facts, not package decoration: which Member States a product is
-- available in decides which CSIRTs are concerned, and it changes as distribution
-- changes. Recording it on the report means the package is derived from one
-- record instead of from memory.
--
-- manufacturer_name is deliberately NOT defaulted from the organisation name.
-- The organisation is the account holder; the manufacturer is a legal person who
-- markets the product under its name or trademark, and for an importer,
-- rebrander or OEM arrangement those are different parties. Inferring one from
-- the other would put a named legal person in a regulatory filing on the
-- strength of an account record.

ALTER TABLE compliance.cra_reports
    ADD COLUMN IF NOT EXISTS manufacturer_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS product_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS member_states TEXT[] NOT NULL DEFAULT '{}';

-- Both are short, published values with a stated maximum in the glossary
-- (manufacturer and product version are max 255 characters each).
ALTER TABLE compliance.cra_reports
    ADD CONSTRAINT cra_reports_manufacturer_name_len
        CHECK (char_length(manufacturer_name) <= 255),
    ADD CONSTRAINT cra_reports_product_version_len
        CHECK (char_length(product_version) <= 255);

COMMENT ON COLUMN compliance.cra_reports.manufacturer_name IS
    'Legal person marketing the product; never inferred from the organisation.';
COMMENT ON COLUMN compliance.cra_reports.member_states IS
    'ISO 3166-1 alpha-2 codes of Member States where the product is available; '
    'drives which CSIRTs are concerned.';
