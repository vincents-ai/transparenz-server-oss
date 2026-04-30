package services

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/transparenz/transparenz-server-oss/pkg/models"
)

type MockSubmissionRecord struct {
	OrgID        uuid.UUID
	CVE          string
	CsafDocument models.JSONMap
	Status       string
}

type MockENISASubmitter struct {
	mu      sync.RWMutex
	records []MockSubmissionRecord
}

func NewMockENISASubmitter() *MockENISASubmitter {
	return &MockENISASubmitter{}
}

func (m *MockENISASubmitter) Submit(ctx context.Context, orgID uuid.UUID, cve string, csafDoc models.JSONMap) (*models.EnisaSubmission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	record := MockSubmissionRecord{
		OrgID:        orgID,
		CVE:          cve,
		CsafDocument: csafDoc,
		Status:       "submitted",
	}
	m.records = append(m.records, record)

	submission := &models.EnisaSubmission{
		ID:           uuid.New(),
		OrgID:        orgID,
		SubmissionID: fmt.Sprintf("MOCK-%s", uuid.New().String()[:8]),
		CsafDocument: csafDoc,
		Status:       "submitted",
	}

	return submission, nil
}

func (m *MockENISASubmitter) GetRecords() []MockSubmissionRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]MockSubmissionRecord, len(m.records))
	copy(result, m.records)
	return result
}

func (m *MockENISASubmitter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = nil
}
