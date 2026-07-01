package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

func testGuardiansAndKeys(t *testing.T, n int) ([]Guardian, []ed25519.PrivateKey) {
	t.Helper()

	guardians := make([]Guardian, 0, n)
	privateKeys := make([]ed25519.PrivateKey, 0, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		guardians = append(guardians, Guardian{
			ID:        string(rune('A' + i)),
			PublicKey: pub,
		})
		privateKeys = append(privateKeys, priv)
	}
	return guardians, privateKeys
}

func signPolicyRecord(record *types.PolicyStateRecord, guardians []Guardian, keys []ed25519.PrivateKey, count int) {
	hash := record.Hash()
	record.QuorumSignatures = make([]types.QuorumSignature, 0, count)
	for i := 0; i < count && i < len(guardians); i++ {
		record.QuorumSignatures = append(record.QuorumSignatures, types.QuorumSignature{
			SignerID:  guardians[i].ID,
			Signature: ed25519.Sign(keys[i], hash[:]),
		})
	}
}

func TestRecoverPolicyState_LoadsExistingState(t *testing.T) {
	t.Parallel()

	guardians, keys := testGuardiansAndKeys(t, 3)
	validator, err := NewValidator(ValidatorConfig{
		Guardians:      guardians,
		Threshold:      2,
		InitialVersion: 0,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	store, err := NewSQLiteStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	record := &types.PolicyStateRecord{
		Version:   1,
		StateRoot: [32]byte{1, 2, 3},
		Timestamp: time.Now().UTC(),
	}
	signPolicyRecord(record, guardians, keys, 2)
	if err := store.SavePolicyState(context.Background(), record); err != nil {
		t.Fatalf("SavePolicyState: %v", err)
	}

	got, err := RecoverPolicyState(context.Background(), RecoveryConfig{
		Store:     store,
		Validator: validator,
	})
	if err != nil {
		t.Fatalf("RecoverPolicyState: %v", err)
	}
	if got.Version != 1 {
		t.Fatalf("version mismatch: got %d want 1", got.Version)
	}
}

func TestRecoverPolicyState_BootstrapMode(t *testing.T) {
	t.Parallel()

	guardians, keys := testGuardiansAndKeys(t, 3)
	validator, err := NewValidator(ValidatorConfig{
		Guardians:      guardians,
		Threshold:      2,
		InitialVersion: 0,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	store, err := NewSQLiteStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	bootstrap := &types.PolicyStateRecord{
		Version:   1,
		StateRoot: [32]byte{0xaa},
		Timestamp: time.Now().UTC(),
	}
	signPolicyRecord(bootstrap, guardians, keys, 2)

	got, err := RecoverPolicyState(context.Background(), RecoveryConfig{
		Store:           store,
		Validator:       validator,
		AllowBootstrap:  true,
		BootstrapRecord: bootstrap,
	})
	if err != nil {
		t.Fatalf("RecoverPolicyState bootstrap: %v", err)
	}
	if got.Version != 1 {
		t.Fatalf("version mismatch: got %d want 1", got.Version)
	}

	loaded, err := store.LoadLatestPolicyState(context.Background())
	if err != nil {
		t.Fatalf("LoadLatestPolicyState: %v", err)
	}
	if loaded.Version != 1 {
		t.Fatalf("persisted version mismatch: got %d want 1", loaded.Version)
	}
}

func TestRecoverPolicyState_NoStateFailClosed(t *testing.T) {
	t.Parallel()

	guardians, _ := testGuardiansAndKeys(t, 3)
	validator, err := NewValidator(ValidatorConfig{
		Guardians:      guardians,
		Threshold:      2,
		InitialVersion: 0,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	store, err := NewSQLiteStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStateStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	_, err = RecoverPolicyState(context.Background(), RecoveryConfig{
		Store:     store,
		Validator: validator,
	})
	if !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("expected ErrStateNotFound, got %v", err)
	}
}
