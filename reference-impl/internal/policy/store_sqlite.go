// Package policy implements monotonic policy state for rollback defense.
package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// SQLiteStateStore persists latest policy state in SQLite.
type SQLiteStateStore struct {
	db *sql.DB
}

// NewSQLiteStateStore creates a SQLite-backed policy state store.
func NewSQLiteStateStore(dsn string) (*SQLiteStateStore, error) {
	if dsn == "" {
		return nil, errors.New("policy: sqlite dsn is required")
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("policy: open sqlite: %w", err)
	}

	store := &SQLiteStateStore{db: db}
	if err := store.initSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStateStore) initSchema(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS policy_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  format_version INTEGER NOT NULL,
  version INTEGER NOT NULL,
  record_json BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("policy: create sqlite schema: %w", err)
	}
	return nil
}

// SavePolicyState writes the latest policy state atomically as a singleton row.
func (s *SQLiteStateStore) SavePolicyState(ctx context.Context, record *types.PolicyStateRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if record == nil {
		return errors.New("policy: record is nil")
	}

	payload := persistedPolicyState{
		FormatVersion: 1,
		Record:        record,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("policy: marshal record: %w", err)
	}

	const upsert = `
INSERT INTO policy_state (singleton, format_version, version, record_json, updated_at)
VALUES (1, ?, ?, ?, ?)
ON CONFLICT(singleton) DO UPDATE SET
  format_version = excluded.format_version,
  version = excluded.version,
  record_json = excluded.record_json,
  updated_at = excluded.updated_at;
`
	if _, err := s.db.ExecContext(
		ctx,
		upsert,
		payload.FormatVersion,
		record.Version,
		data,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("policy: upsert sqlite state: %w", err)
	}

	return nil
}

// LoadLatestPolicyState reads the latest persisted policy state.
func (s *SQLiteStateStore) LoadLatestPolicyState(ctx context.Context) (*types.PolicyStateRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	const q = `SELECT record_json FROM policy_state WHERE singleton = 1`
	var raw []byte
	if err := s.db.QueryRowContext(ctx, q).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrStateNotFound
		}
		return nil, fmt.Errorf("policy: query sqlite state: %w", err)
	}

	var payload persistedPolicyState
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("policy: decode sqlite state: %w", err)
	}
	if payload.FormatVersion != 1 {
		return nil, fmt.Errorf("policy: unsupported state format version %d", payload.FormatVersion)
	}
	if payload.Record == nil {
		return nil, errors.New("policy: sqlite state missing record")
	}

	return payload.Record, nil
}

// Close closes the underlying SQLite connection.
func (s *SQLiteStateStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
