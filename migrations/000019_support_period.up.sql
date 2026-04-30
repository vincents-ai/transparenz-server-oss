ALTER TABLE compliance.organizations ADD COLUMN support_period_months INT DEFAULT 60;
ALTER TABLE compliance.organizations ADD CONSTRAINT support_period_min CHECK (support_period_months >= 12);
ALTER TABLE compliance.organizations ADD COLUMN support_start_date TIMESTAMPTZ;
ALTER TABLE compliance.organizations ADD COLUMN support_end_date TIMESTAMPTZ;
