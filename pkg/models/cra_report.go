// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.

package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// CRAReport is the persisted form of a CRA Article 14 reporting cycle.
//
// It is a regulatory record, not a finding. The difference shows in the fields:
// the clock anchor and its provenance, the retained submissions, the awareness
// audit trail and the coordinator selection history all exist to answer
// "what did we report, when, on what basis, and who decided" months later.
//
// The domain rules live in pkg/regulatory/cra. The database repeats the
// load-bearing ones as CHECK constraints (migration 000045) so they hold even
// for a process that bypasses this layer — a migration mistake is silent in a
// way a rejected INSERT is not.
type CRAReport struct {
	ID    uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID uuid.UUID `gorm:"type:uuid;not null;index:idx_cra_reports_org_state" json:"org_id"`

	Cve    string `gorm:"not null;default:'';index:idx_cra_reports_org_cve" json:"cve"`
	EuvdID string `gorm:"column:euvd_id;not null;default:''" json:"euvd_id,omitempty"`

	// EventType is NULL until a human determination is made. It is never
	// inferred from severity, from KEV membership, or from a scan match.
	EventType *string `gorm:"type:text" json:"event_type,omitempty"`

	State string `gorm:"not null;default:'DETECTED';index:idx_cra_reports_org_state" json:"state"`

	Title       string `gorm:"not null;default:''" json:"title"`
	Description string `gorm:"not null;default:''" json:"description,omitempty"`

	// The product and component the obligation attaches to. The duty is owed
	// in respect of the product, not the upstream library.
	ProductID        string     `json:"product_id,omitempty"`
	ProductName      string     `json:"product_name,omitempty"`
	SbomID           *uuid.UUID `json:"sbom_id,omitempty"`
	ComponentName    string     `gorm:"not null;default:''" json:"component_name,omitempty"`
	ComponentVersion string     `gorm:"not null;default:''" json:"component_version,omitempty"`
	ComponentPURL    string     `gorm:"column:component_purl;not null;default:''" json:"component_purl,omitempty"`

	// Article 14 clock anchor and its provenance. Nullable on purpose: a
	// detected vulnerability is not yet an awareness event. Never backfilled
	// from a feed timestamp or an ingestion time.
	AwarenessAt         *time.Time `gorm:"index" json:"awareness_at,omitempty"`
	AwarenessSource     string     `gorm:"type:text" json:"awareness_source,omitempty"`
	AwarenessEvidence   string     `gorm:"not null;default:''" json:"awareness_evidence,omitempty"`
	AwarenessReasoning  string     `gorm:"not null;default:''" json:"awareness_reasoning,omitempty"`
	AwarenessRecordedAt *time.Time `json:"awareness_recorded_at,omitempty"`
	AwarenessRecordedBy string     `gorm:"not null;default:''" json:"awareness_recorded_by,omitempty"`

	// Exploitation evidence. Required before an AEV determination; a CVSS
	// score cannot satisfy it.
	ExploitationObservedAt   *time.Time `json:"exploitation_observed_at,omitempty"`
	ExploitationSource       string     `gorm:"type:text" json:"exploitation_source,omitempty"`
	ExploitationReference    string     `gorm:"not null;default:''" json:"exploitation_reference,omitempty"`
	ExploitationSummary      string     `gorm:"not null;default:''" json:"exploitation_summary,omitempty"`
	ExploitationAttackVector string     `gorm:"not null;default:''" json:"exploitation_attack_vector,omitempty"`
	ExploitationActor        string     `gorm:"not null;default:''" json:"exploitation_actor,omitempty"`
	ExploitationScope        string     `gorm:"not null;default:''" json:"exploitation_scope,omitempty"`

	// AEV final-report anchor. NULL for severe incidents, which anchor on the
	// 72-hour submission instead.
	MitigationAvailableAt *time.Time `json:"mitigation_available_at,omitempty"`

	// Particularly Exceptional Circumstances. AEV's 72-hour notification only.
	PecApplicable     bool           `gorm:"column:pec_applicable;not null;default:false" json:"pec_applicable"`
	PecGrounds        pq.StringArray `gorm:"column:pec_grounds;type:text[]" json:"pec_grounds,omitempty"`
	PecReasoning      string         `gorm:"not null;default:''" json:"pec_reasoning,omitempty"`
	PecEvidence       pq.StringArray `gorm:"column:pec_evidence;type:text[]" json:"pec_evidence,omitempty"`
	PecDelayRequested *time.Duration `gorm:"column:pec_delay_requested" json:"pec_delay_requested,omitempty"`
	PecDecisionAt     *time.Time     `json:"pec_decision_at,omitempty"`
	PecDecisionBy     string         `gorm:"not null;default:''" json:"pec_decision_by,omitempty"`

	// CSIRT designated as coordinator. An undetermined coordinator is a
	// blocking gap, so it is a recorded state rather than an absent row.
	CsirtID             string     `gorm:"column:csirt_id;not null;default:''" json:"csirt_id,omitempty"`
	CsirtCountry        string     `gorm:"column:csirt_country;not null;default:''" json:"csirt_country,omitempty"`
	CsirtSelectionBasis *string    `gorm:"column:csirt_selection_basis;type:text" json:"csirt_selection_basis,omitempty"`
	CsirtJustification  string     `gorm:"not null;default:''" json:"csirt_justification,omitempty"`
	CsirtSelectedAt     *time.Time `json:"csirt_selected_at,omitempty"`
	CsirtSelectedBy     string     `gorm:"not null;default:''" json:"csirt_selected_by,omitempty"`

	// A non-reportable exit must say why. "Not reportable" with no reasoning
	// is indistinguishable from "we never looked".
	DispositionReason string     `gorm:"not null;default:''" json:"disposition_reason,omitempty"`
	DuplicateOf       *uuid.UUID `json:"duplicate_of,omitempty"`

	ClosedAt  *time.Time `json:"closed_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`

	Events             []CRAReportEvent          `gorm:"foreignKey:ReportID" json:"events,omitempty"`
	Submissions        []CRASubmission           `gorm:"foreignKey:ReportID" json:"submissions,omitempty"`
	AwarenessAudits    []CRAAwarenessAudit       `gorm:"foreignKey:ReportID" json:"awareness_audits,omitempty"`
	CoordinatorHistory []CRACoordinatorSelection `gorm:"foreignKey:ReportID" json:"coordinator_history,omitempty"`
}

func (CRAReport) TableName() string { return "compliance.cra_reports" }

// CRAReportEvent is one entry in the retained decision log.
//
// Append-only, enforced by a trigger in the database. Every classification
// and transition is recorded with its actor, reason and evidence, because a
// conclusion that cannot be traced to the facts it rested on is not evidence
// of anything.
type CRAReportEvent struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID    uuid.UUID `gorm:"type:uuid;not null" json:"org_id"`
	ReportID uuid.UUID `gorm:"type:uuid;not null;index:idx_cra_report_events_report" json:"report_id"`

	FromState  string         `gorm:"column:from_state;not null;default:''" json:"from_state,omitempty"`
	ToState    string         `gorm:"column:to_state;not null" json:"to_state"`
	Actor      string         `gorm:"not null" json:"actor"`
	Reason     string         `gorm:"not null;default:''" json:"reason,omitempty"`
	Evidence   pq.StringArray `gorm:"type:text[]" json:"evidence,omitempty"`
	OccurredAt time.Time      `gorm:"column:occurred_at;not null" json:"occurred_at"`
}

func (CRAReportEvent) TableName() string { return "compliance.cra_report_events" }

// CRASubmission records what was actually sent for one stage.
//
// SubmittedAt is a fact. It anchors the severe-incident final-report deadline
// and it is the proof a deadline was met, so a re-submission updates the
// reference and never the instant — a later "corrected" timestamp is precisely
// what would let a missed deadline be relabelled as met. The unique constraint
// on (report_id, stage) enforces that structurally.
type CRASubmission struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID    uuid.UUID `gorm:"type:uuid;not null;index:idx_cra_submissions_org" json:"org_id"`
	ReportID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:uq_cra_submissions_report_stage" json:"report_id"`
	// Stage is the glossary stage, not the workflow state.
	Stage         string    `gorm:"type:text;not null;uniqueIndex:uq_cra_submissions_report_stage" json:"stage"`
	SubmittedAt   time.Time `gorm:"not null" json:"submitted_at"`
	CaseReference string    `gorm:"not null;default:''" json:"case_reference,omitempty"`
	PackageDigest string    `gorm:"not null;default:''" json:"package_digest,omitempty"`
	SubmittedBy   string    `gorm:"not null;default:''" json:"submitted_by,omitempty"`
	// Via is "human_srp" today: the ENISA Single Reporting Platform publishes
	// no API, so a person files and this records the fact.
	Via       string    `gorm:"not null;default:'human_srp'" json:"via,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (CRASubmission) TableName() string { return "compliance.cra_submissions" }

// CRAAwarenessAudit records a correction to a recorded awareness instant.
//
// Late discovery, timezone misunderstandings and bad feed data all produce
// corrections in practice. How the correction was handled is exactly what an
// authority examines, so the full before/after with actor, reason and evidence
// is retained, and the table is append-only by trigger.
type CRAAwarenessAudit struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID    uuid.UUID `gorm:"type:uuid;not null" json:"org_id"`
	ReportID uuid.UUID `gorm:"type:uuid;not null;index:idx_cra_awareness_audit_report" json:"report_id"`
	// OldValue is NULL for the initial determination.
	OldValue          *time.Time `json:"old_value,omitempty"`
	NewValue          time.Time  `gorm:"column:new_value;not null" json:"new_value"`
	Actor             string     `gorm:"not null" json:"actor"`
	Reason            string     `gorm:"not null" json:"reason"`
	EvidenceReference string     `gorm:"not null;default:''" json:"evidence_reference,omitempty"`
	ChangedAt         time.Time  `gorm:"column:changed_at;not null" json:"changed_at"`
}

func (CRAAwarenessAudit) TableName() string { return "compliance.cra_awareness_audit" }

// CRACoordinatorSelection records one CSIRT designated-as-coordinator choice.
//
// Changed selections are retained rather than overwritten: a supersession
// chain is what makes the decision reconstructible.
type CRACoordinatorSelection struct {
	ID            uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	OrgID         uuid.UUID  `gorm:"type:uuid;not null" json:"org_id"`
	ReportID      uuid.UUID  `gorm:"type:uuid;not null;index:idx_cra_coordinator_selections_report" json:"report_id"`
	CsirtID       string     `gorm:"column:csirt_id;not null" json:"csirt_id"`
	Country       string     `gorm:"not null;default:''" json:"country,omitempty"`
	Basis         string     `gorm:"type:text;not null" json:"basis"`
	Justification string     `gorm:"not null;default:''" json:"justification,omitempty"`
	SelectedBy    string     `gorm:"not null" json:"selected_by"`
	SelectedAt    time.Time  `gorm:"not null" json:"selected_at"`
	SupersedesID  *uuid.UUID `json:"supersedes_id,omitempty"`
}

func (CRACoordinatorSelection) TableName() string { return "compliance.cra_coordinator_selections" }
