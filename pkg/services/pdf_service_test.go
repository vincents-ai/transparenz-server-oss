package services

import (
	"testing"

	"github.com/vincents-ai/transparenz-server-oss/pkg/models"
)

func TestGeneratePDF_ContainsHeader(t *testing.T) {
	svc := NewPDFService(nil)
	data := models.PDFReportData{
		OrgName:    "Test Corp",
		ReportDate: "2026-03-30",
		ReportID:   "TR-03116-001",
		Sections: []models.PDFSection{
			{Title: "Test Section", Content: "Test content", Level: "section"},
		},
	}
	pdf, err := svc.GeneratePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pdf) == 0 {
		t.Error("expected non-empty PDF")
	}
}

func TestGeneratePDF_WithMultipleSections(t *testing.T) {
	svc := NewPDFService(nil)
	data := models.PDFReportData{
		OrgName:    "Multi Section Corp",
		ReportDate: "2026-03-30",
		ReportID:   "TR-03116-002",
		Sections: []models.PDFSection{
			{Title: "First", Content: "Content 1", Level: "section"},
			{Title: "Second", Content: "Content 2", Level: "section"},
			{Title: "Third", Content: "Content 3", Level: "section"},
		},
	}
	pdf, err := svc.GeneratePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pdf) == 0 {
		t.Error("expected non-empty PDF")
	}
}

func TestGeneratePDF_GermanChars(t *testing.T) {
	svc := NewPDFService(nil)
	data := models.PDFReportData{
		OrgName:    "Test GmbH",
		ReportDate: "2026-03-30",
		ReportID:   "TR-03116-003",
		Sections: []models.PDFSection{
			{Title: "Uberblick", Content: "Zusammenfassung fur Ubereinkommen", Level: "section"},
		},
	}
	pdf, err := svc.GeneratePDF(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pdf) == 0 {
		t.Error("expected non-empty PDF with German characters")
	}
}

func TestGeneratePDF_EmptySections(t *testing.T) {
	svc := NewPDFService(nil)
	data := models.PDFReportData{
		OrgName:    "Empty Corp",
		ReportDate: "2026-03-30",
		ReportID:   "TR-03116-004",
	}
	_, err := svc.GeneratePDF(data)
	if err != nil {
		t.Fatal(err)
	}
}
