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

func TestManager_SessionDeduplication_SamePayloadSameSigner(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Two requests with the same payload and same (implicit) signers
	req1 := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}
	req2 := types.SigningRequest{
		RequestID:   "req-002", // Different request ID
		PayloadHash: [32]byte{1, 2, 3}, // Same payload
	}

	session1, _ := manager.CreateSession(req1)
	session2, _ := manager.CreateSession(req2)

	// Should get the same session ID due to payload + signer deduplication
	if session1.ID != session2.ID {
		t.Errorf("expected same session ID for identical payload + signer set, got %s and %s", session1.ID, session2.ID)
	}
}

func TestManager_SessionDeduplication_SamePayloadDifferentSigners(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Two requests with same payload but different signers
	req1 := types.SigningRequest{
		RequestID:       "req-001",
		PayloadHash:     [32]byte{1, 2, 3},
		RequiredSigners: []string{"signer-1", "signer-2"},
	}
	req2 := types.SigningRequest{
		RequestID:       "req-002",
		PayloadHash:     [32]byte{1, 2, 3}, // Same payload
		RequiredSigners: []string{"signer-1", "signer-3"}, // Different signers
	}

	session1, _ := manager.CreateSession(req1)
	session2, _ := manager.CreateSession(req2)

	// Should get different sessions because signer sets differ
	if session1.ID == session2.ID {
		t.Error("expected different session IDs for different signer sets")
	}
}

func TestManager_SessionDeduplication_DifferentPayloadSameSigner(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Two requests with different payloads but same signers
	req1 := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}
	req2 := types.SigningRequest{
		RequestID:   "req-002",
		PayloadHash: [32]byte{4, 5, 6}, // Different payload
	}

	session1, _ := manager.CreateSession(req1)
	session2, _ := manager.CreateSession(req2)

	// Should get different sessions because payloads differ
	if session1.ID == session2.ID {
		t.Error("expected different session IDs for different payloads")
	}
}

func TestManager_SessionDeduplication_SignerOrderIrrelevant(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Two requests with same payload and signers but in different order
	req1 := types.SigningRequest{
		RequestID:       "req-001",
		PayloadHash:     [32]byte{1, 2, 3},
		RequiredSigners: []string{"signer-1", "signer-2"},
	}
	req2 := types.SigningRequest{
		RequestID:       "req-002",
		PayloadHash:     [32]byte{1, 2, 3},
		RequiredSigners: []string{"signer-2", "signer-1"}, // Reversed order
	}

	session1, _ := manager.CreateSession(req1)
	session2, _ := manager.CreateSession(req2)

	// Should get the same session because the signer set is identical (order-independent)
	if session1.ID != session2.ID {
		t.Errorf("expected same session ID when signer order differs, got %s and %s", session1.ID, session2.ID)
	}
}

func TestManager_SessionDeduplication_CleanupPayloadIndex(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Create a session
	req := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}
	session1, _ := manager.CreateSession(req)

	// Verify payload index is populated
	manager.mu.RLock()
	indexSize := len(manager.sessionsByPayload)
	manager.mu.RUnlock()
	if indexSize != 1 {
		t.Errorf("expected 1 entry in payload index, got %d", indexSize)
	}

	// Fast-forward past expiry
	manager.WithClock(func() time.Time {
		return time.Now().Add(15 * time.Minute)
	})

	// Cleanup should remove both session and payload index entry
	removed := manager.CleanupExpired()
	if removed != 1 {
		t.Errorf("expected 1 session removed, got %d", removed)
	}

	// Verify payload index is cleaned up
	manager.mu.RLock()
	indexSize = len(manager.sessionsByPayload)
	manager.mu.RUnlock()
	if indexSize != 0 {
		t.Errorf("expected 0 entries in payload index after cleanup, got %d", indexSize)
	}

	// Verify session is gone
	_, err := manager.GetSession(session1.ID)
	if err == nil {
		t.Error("expected session to be removed")
	}
}

func TestManager_SessionDeduplication_ReusesInFlightSession(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Create first session
	req1 := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}
	session1, _ := manager.CreateSession(req1)

	// Transition to different status (simulate progress)
	session1.Status = types.SessionCommit

	// Create second request for same payload/signer
	req2 := types.SigningRequest{
		RequestID:   "req-002",
		PayloadHash: [32]byte{1, 2, 3},
	}
	session2, _ := manager.CreateSession(req2)

	// Should return the in-flight session (not expired, not failed)
	if session2.ID != session1.ID {
		t.Errorf("expected to reuse in-flight session, got different IDs")
	}
	if session2.Status != types.SessionCommit {
		t.Errorf("expected reused session to have original status, got %s", session2.Status)
	}
}

func TestManager_SessionDeduplication_ExpiredSessionNotReused(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Create first session
	req1 := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}
	session1, _ := manager.CreateSession(req1)
	sessionID1 := session1.ID

	// Mark session as expired
	manager.mu.Lock()
	manager.sessions[session1.ID].Status = types.SessionExpired
	manager.mu.Unlock()

	// Create second request for same payload/signer
	req2 := types.SigningRequest{
		RequestID:   "req-002",
		PayloadHash: [32]byte{1, 2, 3},
	}
	session2, _ := manager.CreateSession(req2)

	// Should create a new session instead of reusing expired one
	if session2.ID == sessionID1 {
		t.Error("expected new session to be created when previous one is expired")
	}
}

func TestManager_SessionDeduplication_FailedSessionNotReused(t *testing.T) {
	manager, _, _ := setupTestEnvironment(t)

	// Create first session
	req1 := types.SigningRequest{
		RequestID:   "req-001",
		PayloadHash: [32]byte{1, 2, 3},
	}
	session1, _ := manager.CreateSession(req1)
	sessionID1 := session1.ID

	// Mark session as failed
	manager.mu.Lock()
	manager.sessions[session1.ID].Status = types.SessionFailed
	manager.mu.Unlock()

	// Create second request for same payload/signer
	req2 := types.SigningRequest{
		RequestID:   "req-002",
		PayloadHash: [32]byte{1, 2, 3},
	}
	session2, _ := manager.CreateSession(req2)

	// Should create a new session instead of reusing failed one
	if session2.ID == sessionID1 {
		t.Error("expected new session to be created when previous one failed")
	}
}
