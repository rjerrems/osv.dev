package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/models"

	pb "osv.dev/bindings/go/api"
)

type mockImportFindingsStore struct {
	findings          []*models.ImportFinding
	listFromSourceErr error
}

func (m *mockImportFindingsStore) Clear(_ context.Context, _ string) error {
	return nil
}

func (m *mockImportFindingsStore) ListIDs(_ context.Context) ([]string, error) {
	return nil, nil
}

func (m *mockImportFindingsStore) GetMulti(_ context.Context, _ []string) ([]*models.ImportFinding, error) {
	return nil, nil
}

func (m *mockImportFindingsStore) PutMulti(_ context.Context, _ []*models.ImportFinding) error {
	return nil
}

func (m *mockImportFindingsStore) DeleteMulti(_ context.Context, _ []string) error {
	return nil
}

func (m *mockImportFindingsStore) UploadResult(_ context.Context, _ string, _ []byte) error {
	return nil
}

func (m *mockImportFindingsStore) UploadSummary(_ context.Context, _ []byte) error {
	return nil
}

func (m *mockImportFindingsStore) ListResultSources(_ context.Context) ([]string, error) {
	return nil, nil
}

func (m *mockImportFindingsStore) DeleteResult(_ context.Context, _ string) error {
	return nil
}

func (m *mockImportFindingsStore) ListAllFromSource(_ context.Context, source string) ([]*models.ImportFinding, error) {
	if m.listFromSourceErr != nil {
		return nil, m.listFromSourceErr
	}
	var res []*models.ImportFinding
	for _, f := range m.findings {
		if f.Source == source {
			res = append(res, f)
		}
	}
	return res, nil
}

func TestServer_ImportFindings(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	mockStore := &mockImportFindingsStore{
		findings: []*models.ImportFinding{
			{
				BugID:       "GHSA-1111-2222",
				Source:      "ghsa",
				Findings:    []models.ImportFindings{models.ImportFindingsInvalidJSON},
				FirstSeen:   now,
				LastAttempt: now,
			},
			{
				BugID:       "PYSEC-1234-5678",
				Source:      "pypi",
				Findings:    []models.ImportFindings{models.ImportFindingsInvalidVersion},
				FirstSeen:   now,
				LastAttempt: now,
			},
		},
	}

	s := &server{importFindingsStore: mockStore}

	t.Run("with specific source", func(t *testing.T) {
		req := &pb.ImportFindingsParameters{Source: "ghsa"}
		resp, err := s.ImportFindings(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.GetInvalidRecords()) != 1 {
			t.Fatalf("expected 1 record, got %d", len(resp.GetInvalidRecords()))
		}
		if resp.GetInvalidRecords()[0].GetBugId() != "GHSA-1111-2222" {
			t.Errorf("expected bug ID GHSA-1111-2222, got %s", resp.GetInvalidRecords()[0].GetBugId())
		}
	})

	t.Run("with empty source returns error", func(t *testing.T) {
		req := &pb.ImportFindingsParameters{Source: ""}
		_, err := s.ImportFindings(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for empty source, got nil")
		}
	})

	t.Run("store error on ListAllFromSource", func(t *testing.T) {
		errStore := &mockImportFindingsStore{listFromSourceErr: errors.New("db error")}
		sErr := &server{importFindingsStore: errStore}
		_, err := sErr.ImportFindings(context.Background(), &pb.ImportFindingsParameters{Source: "ghsa"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
