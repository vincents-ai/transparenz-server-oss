package models

import "testing"

func TestOrganizationTierValidation(t *testing.T) {
	validTiers := []string{"standard", "enterprise", "sovereign"}
	for _, tier := range validTiers {
		org := Organization{Tier: tier}
		if org.Tier != tier {
			t.Errorf("expected tier %s, got %s", tier, org.Tier)
		}
	}
}

func TestOrganizationSlaModeValidation(t *testing.T) {
	validModes := []string{"alerts_only", "approval_gate", "fully_automatic"}
	for _, mode := range validModes {
		org := Organization{SlaMode: mode}
		if org.SlaMode != mode {
			t.Errorf("expected sla_mode %s, got %s", mode, org.SlaMode)
		}
	}
}

func TestOrganizationTableName(t *testing.T) {
	org := Organization{}
	if org.TableName() != "compliance.organizations" {
		t.Errorf("expected compliance.organizations, got %s", org.TableName())
	}
}

func TestValidateSupportPeriod(t *testing.T) {
	t.Run("minimum 12 months passes", func(t *testing.T) {
		org := &Organization{SupportPeriodMonths: 12}
		if err := org.ValidateSupportPeriod(); err != nil {
			t.Errorf("expected no error for 12 months, got %v", err)
		}
	})

	t.Run("zero months fails", func(t *testing.T) {
		org := &Organization{SupportPeriodMonths: 0}
		if err := org.ValidateSupportPeriod(); err == nil {
			t.Error("expected error for 0 months, got nil")
		}
	})

	t.Run("negative months fails", func(t *testing.T) {
		org := &Organization{SupportPeriodMonths: -1}
		if err := org.ValidateSupportPeriod(); err == nil {
			t.Error("expected error for -1 months, got nil")
		}
	})

	t.Run("60 months passes", func(t *testing.T) {
		org := &Organization{SupportPeriodMonths: 60}
		if err := org.ValidateSupportPeriod(); err != nil {
			t.Errorf("expected no error for 60 months, got %v", err)
		}
	})

	t.Run("11 months fails", func(t *testing.T) {
		org := &Organization{SupportPeriodMonths: 11}
		if err := org.ValidateSupportPeriod(); err == nil {
			t.Error("expected error for 11 months, got nil")
		}
	})
}
