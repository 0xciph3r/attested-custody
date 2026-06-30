package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/0xciph3r/attested-custody/internal/attestation"
	"github.com/0xciph3r/attested-custody/internal/policy"
	"github.com/0xciph3r/attested-custody/pkg/types"
)

// Test helpers
func setupTestEnvironment(t *testing.T) (*Manager, *attestation.NonceManager, types.PCRSet) {
	t.Helper()

	// Generate cert chain
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Enclave"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	expectedPCRs := types.PCRSet{
		types.PCR0: []byte("enclave-image-hash-here-48bytes!"),
	}

	// Create verifier
	verifier, err := attestation.NewVerifier(attestation.VerifierConfig{
		ExpectedPCRs: expectedPCRs,
		RootCerts:    rootPool,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create nonce manager
	nonceManager := attestation.NewNonceManager(types.DefaultNonceSpec())

	// Create policy state with some enrolled signers
	policyState, _ := policy.NewStateManager(types.ThresholdConfig{
		Threshold: 2,
		Total:     3,
	})
	policyState.EnrollSigner(&types.SignerEnrollment{
		SignerID:       "signer-1",
		PublicKeyShare: []byte("pubkey-1"),
	})
	policyState.EnrollSigner(&types.SignerEnrollment{
		SignerID:       "signer-2",
		PublicKeyShare: []byte("pubkey-2"),
	})
	policyState.EnrollSigner(&types.SignerEnrollment{
		SignerID:       "signer-3",
		PublicKeyShare: []byte("pubkey-3"),
	})

	// Create manager
	manager, err := NewManager(ManagerConfig{
		Verifier:     verifier,
		NonceManager: nonceManager,
		PolicyState:  policyState,
		Config:       types.DefaultSessionConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Store cert chain for creating attestations
	manager.testCertChain = []*x509.Certificate{leafCert, rootCert}

	return manager, nonceManager, expectedPCRs
}

// testCertChain is added for testing (not in production code)
// We'll add this field to help tests create valid attestations

func TestManager_CreateSession(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	req := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}

	session, err := manager.CreateSession(req)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if session.ID == "" {
		t.Error("session ID should not be empty")
	}
	if session.Status != types.SessionAttesting {
		t.Errorf("expected attesting status, got %s", session.Status)
	}
	if len(session.Participants) != 3 {
		t.Errorf("expected 3 participants, got %d", len(session.Participants))
	}
	if session.Threshold != 2 {
		t.Errorf("expected threshold 2, got %d", session.Threshold)
	}
}

func TestManager_CreateSession_Idempotent(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	req := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}

	session1, _ := manager.CreateSession(req)
	session2, _ := manager.CreateSession(req)

	if session1.ID != session2.ID {
		t.Error("duplicate request should return same session")
	}
}

func TestManager_CreateSession_SpecificSigners(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	req := types.SigningRequest{
		RequestID:       "req-001",
		PayloadHash:     [32]byte{1, 2, 3},
		RequiredSigners: []string{"signer-1", "signer-2"},
	}

	session, err := manager.CreateSession(req)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if len(session.Participants) != 2 {
		t.Errorf("expected 2 participants, got %d", len(session.Participants))
	}
}

func TestManager_CreateSession_UnknownSigner(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	req := types.SigningRequest{
		RequestID:       "req-001",
		PayloadHash:     [32]byte{1, 2, 3},
		RequiredSigners: []string{"unknown-signer"},
	}

	_, err := manager.CreateSession(req)
	if err == nil {
		t.Error("expected error for unknown signer")
	}
}

func TestManager_SessionExpiry(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	req := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}

	session, _ := manager.CreateSession(req)

	// Fast-forward past expiry
	manager.WithClock(func() time.Time {
		return time.Now().Add(15 * time.Minute)
	})

	_, err := manager.GetSession(session.ID)
	if err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestManager_IssueChallenge(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	req := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}

	session, _ := manager.CreateSession(req)

	nonce, err := manager.IssueChallenge(session.ID, "signer-1")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	if len(nonce) != 32 {
		t.Errorf("expected 32-byte nonce, got %d", len(nonce))
	}
}

func TestManager_IssueChallenge_NonParticipant(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	req := types.SigningRequest{
		RequestID:       "req-001",
		PayloadHash:     [32]byte{1, 2, 3},
		RequiredSigners: []string{"signer-1", "signer-2"},
	}

	session, _ := manager.CreateSession(req)

	// signer-3 is not in this session
	_, err := manager.IssueChallenge(session.ID, "signer-3")
	if err == nil {
		t.Error("expected error for non-participant")
	}
}

func TestManager_CleanupExpired(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Create some sessions
	for i := 0; i < 5; i++ {
		manager.CreateSession(types.SigningRequest{
			RequestID:   string(rune('a' + i)),
			PayloadHash: [32]byte{byte(i)},
		})
	}

	// Fast-forward past expiry
	manager.WithClock(func() time.Time {
		return time.Now().Add(15 * time.Minute)
	})

	removed := manager.CleanupExpired()
	if removed != 5 {
		t.Errorf("expected 5 removed, got %d", removed)
	}
}
