// Package attestation implements attestation verification for TEE custody.
//
// This is the security-critical gate: no operation proceeds without
// verified attestation. The verifier is intentionally strict — it rejects
// anything that doesn't match exactly.
package attestation

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// Verifier validates attestation documents against policy.
type Verifier struct {
	// expectedPCRs is the policy: what measurements we accept
	expectedPCRs types.PCRSet

	// rootCerts are the trusted root certificates (e.g., AWS Nitro root)
	rootCerts *x509.CertPool

	// nonceSpec defines nonce requirements
	nonceSpec types.NonceSpec

	// clock allows time mocking in tests
	clock func() time.Time
}

// VerifierConfig configures the attestation verifier.
type VerifierConfig struct {
	// ExpectedPCRs defines the accepted measurements
	ExpectedPCRs types.PCRSet

	// RootCerts are trusted CA certificates
	RootCerts *x509.CertPool

	// NonceSpec defines nonce requirements (optional, uses defaults)
	NonceSpec *types.NonceSpec
}

// NewVerifier creates a verifier with the given policy.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if len(cfg.ExpectedPCRs) == 0 {
		return nil, errors.New("attestation: expected PCRs required")
	}
	if cfg.RootCerts == nil {
		return nil, errors.New("attestation: root certificates required")
	}

	nonceSpec := types.DefaultNonceSpec()
	if cfg.NonceSpec != nil {
		nonceSpec = *cfg.NonceSpec
	}

	return &Verifier{
		expectedPCRs: cfg.ExpectedPCRs,
		rootCerts:    cfg.RootCerts,
		nonceSpec:    nonceSpec,
		clock:        time.Now,
	}, nil
}

// Verify checks an attestation document against policy.
// Returns a detailed result for audit logging.
func (v *Verifier) Verify(doc *types.AttestationDocument, expectedNonce []byte) types.VerificationResult {
	now := v.clock()

	result := types.VerificationResult{
		VerifiedAt:  now,
		PCRsChecked: make([]types.PCRIndex, 0, len(v.expectedPCRs)),
	}

	// Check 1: Document not nil/malformed
	if doc == nil {
		result.RejectCode = types.RejectMalformed
		result.Details = "attestation document is nil"
		return result
	}

	// Check 2: Nonce matches (freshness)
	if err := v.verifyNonce(doc.Nonce, expectedNonce, now); err != nil {
		result.RejectCode = types.RejectNonceInvalid
		result.Details = err.Error()
		return result
	}

	// Check 3: Attestation not too old
	if err := v.verifyTimestamp(doc.Timestamp, now); err != nil {
		result.RejectCode = types.RejectExpired
		result.Details = err.Error()
		return result
	}

	// Check 4: Certificate chain valid
	if err := v.verifyCertChain(doc.CertChain, now); err != nil {
		result.RejectCode = types.RejectChainInvalid
		result.Details = err.Error()
		return result
	}

	// Check 5: PCRs match policy (the core measurement check)
	if err := v.verifyPCRs(doc.PCRs, &result); err != nil {
		result.RejectCode = types.RejectPCRMismatch
		result.Details = err.Error()
		return result
	}

	// All checks passed
	result.Valid = true
	result.RejectCode = types.RejectNone
	result.Details = "attestation verified successfully"
	return result
}

// verifyNonce checks nonce correctness and freshness.
func (v *Verifier) verifyNonce(docNonce, expectedNonce []byte, now time.Time) error {
	// Length check
	if len(expectedNonce) != v.nonceSpec.Length {
		return fmt.Errorf("expected nonce length %d, got %d", v.nonceSpec.Length, len(expectedNonce))
	}

	// Exact match
	if !bytes.Equal(docNonce, expectedNonce) {
		return errors.New("nonce mismatch: attestation nonce does not match challenge")
	}

	return nil
}

// verifyTimestamp checks attestation freshness.
func (v *Verifier) verifyTimestamp(attestTime, now time.Time) error {
	age := now.Sub(attestTime)

	// Attestation from the future is suspicious
	if age < -time.Minute {
		return fmt.Errorf("attestation timestamp is in the future by %v", -age)
	}

	// Attestation too old
	if age > v.nonceSpec.MaxAge {
		return fmt.Errorf("attestation too old: %v > max %v", age, v.nonceSpec.MaxAge)
	}

	return nil
}

// verifyCertChain validates the certificate chain to a trusted root.
func (v *Verifier) verifyCertChain(chain []*x509.Certificate, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("certificate chain is empty")
	}

	// The first certificate is the enclave/leaf certificate
	leaf := chain[0]

	// Build intermediate pool from remaining certs
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	// Verify chain
	opts := x509.VerifyOptions{
		Roots:         v.rootCerts,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// verifyPCRs checks that all expected PCRs match.
func (v *Verifier) verifyPCRs(docPCRs types.PCRSet, result *types.VerificationResult) error {
	for idx, expected := range v.expectedPCRs {
		result.PCRsChecked = append(result.PCRsChecked, idx)

		actual, ok := docPCRs[idx]
		if !ok {
			return fmt.Errorf("PCR%d missing from attestation", idx)
		}

		if !bytes.Equal(actual, expected) {
			return fmt.Errorf("PCR%d mismatch: expected %x, got %x", idx, expected, actual)
		}
	}

	return nil
}

// WithClock sets a custom clock (for testing).
func (v *Verifier) WithClock(clock func() time.Time) {
	v.clock = clock
}
