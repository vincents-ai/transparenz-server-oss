ALTER TABLE compliance.organizations DROP CONSTRAINT IF EXISTS support_period_min;
ALTER TABLE compliance.organizations DROP COLUMN IF EXISTS support_period_months;
ALTER TABLE compliance.organizations DROP COLUMN IF EXISTS support_start_date;
ALTER TABLE compliance.organizations DROP COLUMN IF EXISTS support_end_date;
