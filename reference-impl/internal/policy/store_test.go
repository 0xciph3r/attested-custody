package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

func TestFileStateStore_SaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy", "state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}

	want := &types.PolicyStateRecord{
		Version:   7,
		StateRoot: [32]byte{1, 2, 3},
		Timestamp: time.Unix(1710000000, 0).UTC(),
		QuorumSignatures: []types.QuorumSignature{
			{SignerID: "guardian-a", Signature: []byte{0x01, 0x02}},
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
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Fatalf("timestamp mismatch: got %v want %v", got.Timestamp, want.Timestamp)
	}
	if len(got.QuorumSignatures) != 1 || got.QuorumSignatures[0].SignerID != "guardian-a" {
		t.Fatalf("signature payload mismatch: %+v", got.QuorumSignatures)
	}
}

func TestFileStateStore_LoadNotFound(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}

	_, err = store.LoadLatestPolicyState(context.Background())
	if !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("expected ErrStateNotFound, got %v", err)
	}
}

func TestFileStateStore_OverwriteLatestState(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}

	v1 := &types.PolicyStateRecord{Version: 1, Timestamp: time.Now().UTC()}
	v2 := &types.PolicyStateRecord{Version: 2, Timestamp: time.Now().UTC()}

	if err := store.SavePolicyState(context.Background(), v1); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	if err := store.SavePolicyState(context.Background(), v2); err != nil {
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

func TestFileStateStore_CorruptFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}

	_, err = store.LoadLatestPolicyState(context.Background())
	if err == nil {
		t.Fatal("expected decode error")
	}
}
