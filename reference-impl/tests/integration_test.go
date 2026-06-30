// Package integration_test demonstrates the full attested custody signing flow.
//
// This test simulates:
// 1. Coordinator creates session
// 2. Each signer requests a challenge
// 3. Each signer submits attestation
// 4. Signers submit FROST commitments
// 5. Signers submit signature shares
// 6. Session completes
package tests

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
	"github.com/0xciph3r/attested-custody/internal/session"
	"github.com/0xciph3r/attested-custody/pkg/types"
)

// TestFullSigningFlow simulates a complete 2-of-3 signing session.
func TestFullSigningFlow(t *testing.T) {
	// ========================================
	// SETUP: Create trusted infrastructure
	// ========================================

	// Generate root CA (represents AWS/Intel root of trust)
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Attested Custody Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	// Expected enclave measurements (PCR policy)
	expectedPCRs := types.PCRSet{
		types.PCR0: []byte("enclave-image-measurement-48byte"),
		types.PCR1: []byte("kernel-bootstrap-measurement-48b"),
	}

	// Create attestation verifier
	verifier, err := attestation.NewVerifier(attestation.VerifierConfig{
		ExpectedPCRs: expectedPCRs,
		RootCerts:    rootPool,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Create nonce manager
	nonceManager := attestation.NewNonceManager(types.DefaultNonceSpec())

	// Create policy state manager (2-of-3 threshold)
	policyState, _ := policy.NewStateManager(types.ThresholdConfig{
		Threshold: 2,
		Total:     3,
	})

	// ========================================
	// ENROLLMENT: Register signers
	// ========================================

	signerIDs := []string{"signer-alice", "signer-bob", "signer-carol"}
	for _, id := range signerIDs {
		_, err := policyState.EnrollSigner(&types.SignerEnrollment{
			SignerID:        id,
			PublicKeyShare:  []byte("frost-pubkey-share-" + id),
			EnclaveIdentity: expectedPCRs,
		})
		if err != nil {
			t.Fatalf("EnrollSigner %s: %v", id, err)
		}
	}

	t.Logf("Enrolled %d signers, policy version: %d", len(signerIDs), policyState.Version())

	// ========================================
	// SESSION: Create signing session
	// ========================================

	sessionMgr, err := session.NewManager(session.ManagerConfig{
		Verifier:     verifier,
		NonceManager: nonceManager,
		PolicyState:  policyState,
		Config:       types.DefaultSessionConfig(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Transaction to sign (just the hash)
	txHash := [32]byte{}
	copy(txHash[:], "bitcoin-transaction-hash-to-sign")

	signingSession, err := sessionMgr.CreateSession(types.SigningRequest{
		RequestID:   "tx-001",
		PayloadHash: txHash,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	t.Logf("Created session %s with %d participants", signingSession.ID, len(signingSession.Participants))

	// ========================================
	// ATTESTATION: Signers prove they're in TEE
	// ========================================

	// Helper to create mock attestation (in real system, enclave produces this)
	createMockAttestation := func(signerID string, nonce []byte) *types.AttestationDocument {
		// Generate enclave certificate
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(time.Now().UnixNano())),
			Subject:      pkix.Name{CommonName: "Enclave-" + signerID},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
		}
		leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
		leafCert, _ := x509.ParseCertificate(leafCertDER)

		return &types.AttestationDocument{
			ModuleID:  "enclave-" + signerID,
			PCRs:      expectedPCRs,
			Nonce:     nonce,
			Timestamp: time.Now(),
			CertChain: []*x509.Certificate{leafCert, rootCert},
			UserData:  []byte("frost-pubkey-share-" + signerID),
		}
	}

	// Only 2 signers attest (meets threshold)
	attestingSigners := []string{"signer-alice", "signer-bob"}

	for _, signerID := range attestingSigners {
		// Step 1: Request challenge
		nonce, err := sessionMgr.IssueChallenge(signingSession.ID, signerID)
		if err != nil {
			t.Fatalf("IssueChallenge for %s: %v", signerID, err)
		}
		t.Logf("%s received challenge (nonce length: %d)", signerID, len(nonce))

		// Step 2: Create attestation with nonce
		attestDoc := createMockAttestation(signerID, nonce)

		// Step 3: Submit attestation
		err = sessionMgr.SubmitAttestation(signingSession.ID, signerID, attestDoc, nonce)
		if err != nil {
			t.Fatalf("SubmitAttestation for %s: %v", signerID, err)
		}
		t.Logf("%s attestation verified ✓", signerID)
	}

	// Check session advanced to commit phase
	sess, _ := sessionMgr.GetSession(signingSession.ID)
	if sess.Status != types.SessionCommit {
		t.Errorf("expected session in commit phase, got %s", sess.Status)
	}
	t.Logf("Session advanced to: %s", sess.Status)

	// ========================================
	// FROST ROUND 1: Commitments
	// ========================================

	for _, signerID := range attestingSigners {
		err := sessionMgr.RecordCommitment(signingSession.ID, signerID)
		if err != nil {
			t.Fatalf("RecordCommitment for %s: %v", signerID, err)
		}
		t.Logf("%s submitted commitment ✓", signerID)
	}

	sess, _ = sessionMgr.GetSession(signingSession.ID)
	if sess.Status != types.SessionSign {
		t.Errorf("expected session in sign phase, got %s", sess.Status)
	}
	t.Logf("Session advanced to: %s", sess.Status)

	// ========================================
	// FROST ROUND 2: Signature shares
	// ========================================

	for _, signerID := range attestingSigners {
		err := sessionMgr.RecordShare(signingSession.ID, signerID)
		if err != nil {
			t.Fatalf("RecordShare for %s: %v", signerID, err)
		}
		t.Logf("%s submitted signature share ✓", signerID)
	}

	sess, _ = sessionMgr.GetSession(signingSession.ID)
	if sess.Status != types.SessionComplete {
		t.Errorf("expected session complete, got %s", sess.Status)
	}

	// ========================================
	// SUCCESS
	// ========================================

	t.Logf("")
	t.Logf("=== SIGNING SESSION COMPLETE ===")
	t.Logf("Session ID:    %s", sess.ID)
	t.Logf("Status:        %s", sess.Status)
	t.Logf("Participants:  %d attested, %d threshold", len(attestingSigners), sess.Threshold)
	t.Logf("Payload hash:  %x...", sess.PayloadHash[:8])
}

// TestAttestationRejection verifies that invalid attestations are rejected.
func TestAttestationRejection(t *testing.T) {
	// Setup (abbreviated)
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootCertDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootCertDER)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	expectedPCRs := types.PCRSet{
		types.PCR0: []byte("expected-measurement-here-48byte"),
	}

	verifier, _ := attestation.NewVerifier(attestation.VerifierConfig{
		ExpectedPCRs: expectedPCRs,
		RootCerts:    rootPool,
	})

	nonceManager := attestation.NewNonceManager(types.DefaultNonceSpec())
	policyState, _ := policy.NewStateManager(types.ThresholdConfig{Threshold: 1, Total: 1})
	policyState.EnrollSigner(&types.SignerEnrollment{
		SignerID:       "signer-1",
		PublicKeyShare: []byte("pubkey"),
	})

	sessionMgr, _ := session.NewManager(session.ManagerConfig{
		Verifier:     verifier,
		NonceManager: nonceManager,
		PolicyState:  policyState,
		Config:       types.DefaultSessionConfig(),
	})

	signingSession, _ := sessionMgr.CreateSession(types.SigningRequest{
		RequestID:   "tx-001",
		PayloadHash: [32]byte{1},
	})

	nonce, _ := sessionMgr.IssueChallenge(signingSession.ID, "signer-1")

	// Create attestation with WRONG PCR (simulates compromised enclave)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Evil Enclave"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	badAttestation := &types.AttestationDocument{
		ModuleID: "evil-enclave",
		PCRs: types.PCRSet{
			types.PCR0: []byte("WRONG-measurement-not-expected!!"), // WRONG!
		},
		Nonce:     nonce,
		Timestamp: time.Now(),
		CertChain: []*x509.Certificate{leafCert, rootCert},
	}

	err := sessionMgr.SubmitAttestation(signingSession.ID, "signer-1", badAttestation, nonce)
	if err == nil {
		t.Fatal("expected attestation to be rejected")
	}

	t.Logf("Malicious attestation correctly rejected: %v", err)
}
