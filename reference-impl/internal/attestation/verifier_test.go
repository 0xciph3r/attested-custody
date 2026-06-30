package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// Test helpers
func mustGenerateCertChain(t *testing.T) ([]*x509.Certificate, *x509.CertPool) {
	t.Helper()

	// Generate root CA
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

	// Generate leaf certificate
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Enclave"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCertDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafCertDER)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	return []*x509.Certificate{leafCert, rootCert}, rootPool
}

func TestVerifier_ValidAttestation(t *testing.T) {
	chain, rootPool := mustGenerateCertChain(t)
	now := time.Now()

	expectedPCRs := types.PCRSet{
		types.PCR0: []byte("enclave-image-hash-here-48bytes!"),
		types.PCR1: []byte("kernel-measurement-hash-48bytes!"),
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)

	doc := &types.AttestationDocument{
		ModuleID:  "test-enclave",
		PCRs:      expectedPCRs,
		Nonce:     nonce,
		Timestamp: now.Add(-time.Second), // 1 second ago
		CertChain: chain,
	}

	verifier, err := NewVerifier(VerifierConfig{
		ExpectedPCRs: expectedPCRs,
		RootCerts:    rootPool,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verifier.WithClock(func() time.Time { return now })

	result := verifier.Verify(doc, nonce)

	if !result.Valid {
		t.Errorf("expected valid, got reject: %s - %s", result.RejectCode, result.Details)
	}
	if len(result.PCRsChecked) != 2 {
		t.Errorf("expected 2 PCRs checked, got %d", len(result.PCRsChecked))
	}
}

func TestVerifier_PCRMismatch(t *testing.T) {
	chain, rootPool := mustGenerateCertChain(t)
	now := time.Now()

	expectedPCRs := types.PCRSet{
		types.PCR0: []byte("expected-measurement-hash-48byte"),
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)

	doc := &types.AttestationDocument{
		ModuleID: "test-enclave",
		PCRs: types.PCRSet{
			types.PCR0: []byte("different-measurement-48bytesss"), // MISMATCH
		},
		Nonce:     nonce,
		Timestamp: now.Add(-time.Second),
		CertChain: chain,
	}

	verifier, _ := NewVerifier(VerifierConfig{
		ExpectedPCRs: expectedPCRs,
		RootCerts:    rootPool,
	})
	verifier.WithClock(func() time.Time { return now })

	result := verifier.Verify(doc, nonce)

	if result.Valid {
		t.Error("expected rejection for PCR mismatch")
	}
	if result.RejectCode != types.RejectPCRMismatch {
		t.Errorf("expected PCR_MISMATCH, got %s", result.RejectCode)
	}
}

func TestVerifier_NonceMismatch(t *testing.T) {
	chain, rootPool := mustGenerateCertChain(t)
	now := time.Now()

	expectedPCRs := types.PCRSet{
		types.PCR0: []byte("enclave-image-hash-here-48bytes!"),
	}

	docNonce := make([]byte, 32)
	rand.Read(docNonce)

	expectedNonce := make([]byte, 32)
	rand.Read(expectedNonce) // Different nonce

	doc := &types.AttestationDocument{
		ModuleID:  "test-enclave",
		PCRs:      expectedPCRs,
		Nonce:     docNonce,
		Timestamp: now.Add(-time.Second),
		CertChain: chain,
	}

	verifier, _ := NewVerifier(VerifierConfig{
		ExpectedPCRs: expectedPCRs,
		RootCerts:    rootPool,
	})
	verifier.WithClock(func() time.Time { return now })

	result := verifier.Verify(doc, expectedNonce)

	if result.Valid {
		t.Error("expected rejection for nonce mismatch")
	}
	if result.RejectCode != types.RejectNonceInvalid {
		t.Errorf("expected NONCE_INVALID, got %s", result.RejectCode)
	}
}

func TestVerifier_ExpiredAttestation(t *testing.T) {
	chain, rootPool := mustGenerateCertChain(t)
	now := time.Now()

	expectedPCRs := types.PCRSet{
		types.PCR0: []byte("enclave-image-hash-here-48bytes!"),
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)

	doc := &types.AttestationDocument{
		ModuleID:  "test-enclave",
		PCRs:      expectedPCRs,
		Nonce:     nonce,
		Timestamp: now.Add(-10 * time.Minute), // 10 minutes ago (> 5 min default)
		CertChain: chain,
	}

	verifier, _ := NewVerifier(VerifierConfig{
		ExpectedPCRs: expectedPCRs,
		RootCerts:    rootPool,
	})
	verifier.WithClock(func() time.Time { return now })

	result := verifier.Verify(doc, nonce)

	if result.Valid {
		t.Error("expected rejection for expired attestation")
	}
	if result.RejectCode != types.RejectExpired {
		t.Errorf("expected EXPIRED, got %s", result.RejectCode)
	}
}

func TestNonceManager_IssueAndValidate(t *testing.T) {
	nm := NewNonceManager(types.DefaultNonceSpec())

	nonce, err := nm.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if len(nonce) != 32 {
		t.Errorf("expected 32-byte nonce, got %d", len(nonce))
	}

	// First validation should succeed
	if err := nm.Validate(nonce); err != nil {
		t.Errorf("first Validate: %v", err)
	}

	// Second validation should fail (replay)
	if err := nm.Validate(nonce); err == nil {
		t.Error("expected replay detection on second Validate")
	}
}

func TestNonceManager_UnknownNonce(t *testing.T) {
	nm := NewNonceManager(types.DefaultNonceSpec())

	unknownNonce := make([]byte, 32)
	rand.Read(unknownNonce)

	if err := nm.Validate(unknownNonce); err == nil {
		t.Error("expected error for unknown nonce")
	}
}

func TestNonceManager_ExpiredNonce(t *testing.T) {
	nm := NewNonceManager(types.DefaultNonceSpec())

	nonce, _ := nm.Issue()

	// Fast-forward time past max age
	nm.WithClock(func() time.Time {
		return time.Now().Add(10 * time.Minute)
	})

	if err := nm.Validate(nonce); err == nil {
		t.Error("expected error for expired nonce")
	}
}
