package models

import "github.com/google/uuid"

// PDFSection represents a single section in a generated PDF report.
type PDFSection struct {
	Title   string
	Content string
	Level   string
}

// PDFReportData contains all data needed to generate a PDF compliance report.
type PDFReportData struct {
	OrgName    string
	ReportDate string
	ReportID   string
	Sections   []PDFSection
	OrgID      uuid.UUID
}
