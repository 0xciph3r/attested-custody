package policy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

func TestSQLiteStateStore_SaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "policy-state.db")
	store, err := NewSQLiteStateStore(dsn)
	if err != nil {
		t.Fatalf("NewSQLiteStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	want := &types.PolicyStateRecord{
		Version:   42,
		StateRoot: [32]byte{9, 8, 7},
		Timestamp: time.Unix(1710001000, 0).UTC(),
		QuorumSignatures: []types.QuorumSignature{
			{SignerID: "guardian-a", Signature: []byte{0xaa}},
			{SignerID: "guardian-b", Signature: []byte{0xbb}},
		},
	}

	if err := store.SavePolicyState(context.Background(), want); err != nil {
		t.Fatalf("SavePolicyState: %v", err)
	}

	got, err := store.LoadLatestPolicyState(context.Background())
	if err != nil {
		t.Fatalf("LoadLatestPolicyState: %v", err)
	}
	if got.Version != want.Version {
		t.Fatalf("version mismatch: got %d want %d", got.Version, want.Version)
	}
	if got.StateRoot != want.StateRoot {
		t.Fatalf("state root mismatch")
	}
	if len(got.QuorumSignatures) != 2 {
		t.Fatalf("signature count mismatch: got %d", len(got.QuorumSignatures))
	}
}

func TestSQLiteStateStore_LoadNotFound(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "policy-state.db")
	store, err := NewSQLiteStateStore(dsn)
	if err != nil {
		t.Fatalf("NewSQLiteStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	_, err = store.LoadLatestPolicyState(context.Background())
	if !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("expected ErrStateNotFound, got %v", err)
	}
}

func TestSQLiteStateStore_OverwriteLatest(t *testing.T) {
	t.Parallel()

	dsn := filepath.Join(t.TempDir(), "policy-state.db")
	store, err := NewSQLiteStateStore(dsn)
	if err != nil {
		t.Fatalf("NewSQLiteStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.SavePolicyState(context.Background(), &types.PolicyStateRecord{
		Version:   1,
		Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	if err := store.SavePolicyState(context.Background(), &types.PolicyStateRecord{
		Version:   2,
		Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("save v2: %v", err)
	}

	got, err := store.LoadLatestPolicyState(context.Background())
	if err != nil {
		t.Fatalf("load latest: %v", err)
	}
	if got.Version != 2 {
		t.Fatalf("expected latest version 2, got %d", got.Version)
	}
}
