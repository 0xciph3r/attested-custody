// Package policy implements monotonic policy state for rollback defense.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// ErrStateNotFound is returned when no persisted policy state exists yet.
var ErrStateNotFound = errors.New("policy: persisted state not found")

// StateStore persists the latest signed policy state.
//
// Storage is treated as untrusted: integrity comes from quorum signatures
// and monotonic version checks performed by the validator.
type StateStore interface {
	SavePolicyState(ctx context.Context, record *types.PolicyStateRecord) error
	LoadLatestPolicyState(ctx context.Context) (*types.PolicyStateRecord, error)
}

type persistedPolicyState struct {
	FormatVersion int                      `json:"format_version"`
	Record        *types.PolicyStateRecord `json:"record"`
}

// FileStateStore persists policy state to a single JSON file atomically.
type FileStateStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStateStore creates a file-backed state store.
func NewFileStateStore(path string) (*FileStateStore, error) {
	if path == "" {
		return nil, errors.New("policy: state store path is required")
	}
	return &FileStateStore{path: path}, nil
}

// SavePolicyState writes the latest policy state atomically.
func (s *FileStateStore) SavePolicyState(ctx context.Context, record *types.PolicyStateRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if record == nil {
		return errors.New("policy: record is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("policy: create state directory: %w", err)
	}

	payload := persistedPolicyState{
		FormatVersion: 1,
		Record:        record,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("policy: marshal record: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("policy: write temp state file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("policy: replace state file: %w", err)
	}

	return nil
}

// LoadLatestPolicyState reads the latest persisted policy state.
func (s *FileStateStore) LoadLatestPolicyState(ctx context.Context) (*types.PolicyStateRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrStateNotFound
		}
		return nil, fmt.Errorf("policy: read state file: %w", err)
	}

	var payload persistedPolicyState
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("policy: decode state file: %w", err)
	}
	if payload.FormatVersion != 1 {
		return nil, fmt.Errorf("policy: unsupported state format version %d", payload.FormatVersion)
	}
	if payload.Record == nil {
		return nil, errors.New("policy: state file missing record")
	}

	return payload.Record, nil
}
