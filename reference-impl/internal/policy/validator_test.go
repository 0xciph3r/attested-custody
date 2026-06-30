package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

func generateGuardians(t *testing.T, n int) []Guardian {
	t.Helper()
	guardians := make([]Guardian, n)
	for i := 0; i < n; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		guardians[i] = Guardian{
			ID:        string(rune('A' + i)),
			PublicKey: pub,
		}
	}
	return guardians
}

func signRecord(t *testing.T, record *types.PolicyStateRecord, guardians []Guardian, keys []ed25519.PrivateKey, count int) {
	t.Helper()
	hash := record.Hash()
	for i := 0; i < count && i < len(guardians); i++ {
		sig := ed25519.Sign(keys[i], hash[:])
		record.QuorumSignatures = append(record.QuorumSignatures, types.QuorumSignature{
			SignerID:  guardians[i].ID,
			Signature: sig,
		})
	}
}

func TestValidator_ValidTransition(t *testing.T) {
	// Generate 3 guardians with their keys
	var guardians []Guardian
	var privateKeys []ed25519.PrivateKey

	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		guardians = append(guardians, Guardian{
			ID:        string(rune('A' + i)),
			PublicKey: pub,
		})
		privateKeys = append(privateKeys, priv)
	}

	validator, err := NewValidator(ValidatorConfig{
		Guardians:      guardians,
		Threshold:      2, // 2-of-3
		InitialVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid state record at version 1
	record := &types.PolicyStateRecord{
		Version:   1,
		StateRoot: [32]byte{1, 2, 3},
		Timestamp: time.Now(),
	}

	// Sign with 2 guardians (meets threshold)
	signRecord(t, record, guardians, privateKeys, 2)

	// Validate
	if err := validator.ValidateTransition(record); err != nil {
		t.Errorf("ValidateTransition: %v", err)
	}

	// Accept the transition
	if err := validator.AcceptTransition(record); err != nil {
		t.Errorf("AcceptTransition: %v", err)
	}

	if validator.LastKnownVersion() != 1 {
		t.Errorf("expected version 1, got %d", validator.LastKnownVersion())
	}
}

func TestValidator_RollbackDetection(t *testing.T) {
	var guardians []Guardian
	var privateKeys []ed25519.PrivateKey

	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		guardians = append(guardians, Guardian{
			ID:        string(rune('A' + i)),
			PublicKey: pub,
		})
		privateKeys = append(privateKeys, priv)
	}

	validator, _ := NewValidator(ValidatorConfig{
		Guardians:      guardians,
		Threshold:      2,
		InitialVersion: 5, // Start at version 5
	})

	// Try to accept version 5 (not strictly greater)
	record := &types.PolicyStateRecord{
		Version:   5,
		StateRoot: [32]byte{1, 2, 3},
		Timestamp: time.Now(),
	}
	signRecord(t, record, guardians, privateKeys, 2)

	err := validator.ValidateTransition(record)
	if err == nil {
		t.Error("expected rollback detection error")
	}
	if !errors.Is(err, ErrRollbackDetected) {
		t.Errorf("expected ErrRollbackDetected, got %v", err)
	}

	// Try version 3 (rollback)
	record.Version = 3
	record.QuorumSignatures = nil
	signRecord(t, record, guardians, privateKeys, 2)

	err = validator.ValidateTransition(record)
	if err == nil {
		t.Error("expected rollback detection error")
	}
}

func TestValidator_InsufficientQuorum(t *testing.T) {
	var guardians []Guardian
	var privateKeys []ed25519.PrivateKey

	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		guardians = append(guardians, Guardian{
			ID:        string(rune('A' + i)),
			PublicKey: pub,
		})
		privateKeys = append(privateKeys, priv)
	}

	validator, _ := NewValidator(ValidatorConfig{
		Guardians:      guardians,
		Threshold:      2, // Need 2
		InitialVersion: 0,
	})

	record := &types.PolicyStateRecord{
		Version:   1,
		StateRoot: [32]byte{1, 2, 3},
		Timestamp: time.Now(),
	}

	// Sign with only 1 guardian (below threshold)
	signRecord(t, record, guardians, privateKeys, 1)

	err := validator.ValidateTransition(record)
	if err == nil {
		t.Error("expected insufficient quorum error")
	}
}

func TestValidator_InvalidSignature(t *testing.T) {
	var guardians []Guardian
	var privateKeys []ed25519.PrivateKey

	for i := 0; i < 3; i++ {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		guardians = append(guardians, Guardian{
			ID:        string(rune('A' + i)),
			PublicKey: pub,
		})
		privateKeys = append(privateKeys, priv)
	}

	validator, _ := NewValidator(ValidatorConfig{
		Guardians:      guardians,
		Threshold:      2,
		InitialVersion: 0,
	})

	record := &types.PolicyStateRecord{
		Version:   1,
		StateRoot: [32]byte{1, 2, 3},
		Timestamp: time.Now(),
	}

	// Add one valid signature
	hash := record.Hash()
	record.QuorumSignatures = append(record.QuorumSignatures, types.QuorumSignature{
		SignerID:  guardians[0].ID,
		Signature: ed25519.Sign(privateKeys[0], hash[:]),
	})

	// Add one invalid signature (wrong key)
	record.QuorumSignatures = append(record.QuorumSignatures, types.QuorumSignature{
		SignerID:  guardians[1].ID,
		Signature: ed25519.Sign(privateKeys[2], hash[:]), // Wrong key!
	})

	err := validator.ValidateTransition(record)
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestStateManager_EnrollAndRevoke(t *testing.T) {
	sm, err := NewStateManager(types.ThresholdConfig{Threshold: 2, Total: 3})
	if err != nil {
		t.Fatal(err)
	}

	// Enroll signer
	enrollment := &types.SignerEnrollment{
		SignerID:       "signer-1",
		PublicKeyShare: []byte("pubkey-share-1"),
	}

	version, err := sm.EnrollSigner(enrollment)
	if err != nil {
		t.Fatalf("EnrollSigner: %v", err)
	}
	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}

	// Verify enrolled
	signer, ok := sm.GetSigner("signer-1")
	if !ok {
		t.Error("signer not found after enrollment")
	}
	if signer.Status != types.SignerActive {
		t.Errorf("expected active status, got %s", signer.Status)
	}

	// Revoke
	version, err = sm.RevokeSigner("signer-1")
	if err != nil {
		t.Fatalf("RevokeSigner: %v", err)
	}
	if version != 2 {
		t.Errorf("expected version 2, got %d", version)
	}

	signer, _ = sm.GetSigner("signer-1")
	if signer.Status != types.SignerRevoked {
		t.Errorf("expected revoked status, got %s", signer.Status)
	}
}

func TestStateManager_StateRoot(t *testing.T) {
	sm, _ := NewStateManager(types.ThresholdConfig{Threshold: 2, Total: 3})

	// Empty state root
	root1 := sm.ComputeStateRoot()

	// Enroll a signer
	sm.EnrollSigner(&types.SignerEnrollment{
		SignerID:       "signer-1",
		PublicKeyShare: []byte("pubkey-1"),
	})

	root2 := sm.ComputeStateRoot()

	// Roots should differ
	if root1 == root2 {
		t.Error("state root should change after enrollment")
	}

	// Enroll another
	sm.EnrollSigner(&types.SignerEnrollment{
		SignerID:       "signer-2",
		PublicKeyShare: []byte("pubkey-2"),
	})

	root3 := sm.ComputeStateRoot()
	if root2 == root3 {
		t.Error("state root should change after second enrollment")
	}
}

func TestStateManager_CreateStateRecord(t *testing.T) {
	sm, _ := NewStateManager(types.ThresholdConfig{Threshold: 2, Total: 3})

	sm.EnrollSigner(&types.SignerEnrollment{
		SignerID:       "signer-1",
		PublicKeyShare: []byte("pubkey-1"),
	})

	record := sm.CreateStateRecord()

	if record.Version != 1 {
		t.Errorf("expected version 1, got %d", record.Version)
	}

	expectedRoot := sm.ComputeStateRoot()
	if record.StateRoot != expectedRoot {
		t.Error("state root mismatch in record")
	}
}
