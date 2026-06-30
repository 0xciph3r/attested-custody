// Package types defines core attestation primitives for attested custody.
//
// These types model the attestation document structure used by hardware TEEs
// (AWS Nitro, Intel SGX) and the verification results. The design is
// intentionally TEE-agnostic — the same verification logic applies regardless
// of which enclave technology produces the attestation.
package types

import (
	"crypto/x509"
	"time"
)

// PCRIndex identifies a Platform Configuration Register.
// PCR0 = enclave image, PCR1 = kernel, PCR2 = application.
type PCRIndex int

const (
	PCR0 PCRIndex = 0 // Enclave image measurement
	PCR1 PCRIndex = 1 // Kernel/bootstrap measurement
	PCR2 PCRIndex = 2 // Application-specific measurement
)

// PCRSet holds the expected measurements for attestation verification.
// Each PCR is a SHA-384 hash (48 bytes) in Nitro, SHA-256 (32 bytes) in SGX.
type PCRSet map[PCRIndex][]byte

// AttestationDocument represents a hardware-signed attestation from an enclave.
// This is the CBOR-encoded document from Nitro or the quote from SGX.
type AttestationDocument struct {
	// Raw is the original CBOR/binary attestation (for signature verification)
	Raw []byte

	// ModuleID identifies the enclave image (Nitro: enclave ID)
	ModuleID string

	// PCRs contains the platform configuration register values
	PCRs PCRSet

	// Nonce is the challenge value that proves freshness
	Nonce []byte

	// UserData is application-specific data signed into the attestation
	// (e.g., public key commitment, session ID)
	UserData []byte

	// Timestamp is when the attestation was generated
	Timestamp time.Time

	// CertChain is the certificate chain from enclave cert to AWS root
	CertChain []*x509.Certificate
}

// VerificationResult captures the outcome of attestation verification.
// It's designed to be auditable — every rejection has a reason code.
type VerificationResult struct {
	Valid     bool
	RejectCode RejectCode
	Details   string

	// Metadata for audit logging
	VerifiedAt time.Time
	PCRsChecked []PCRIndex
}

// RejectCode enumerates all possible attestation rejection reasons.
// These codes appear in audit logs and incident reports.
type RejectCode string

const (
	RejectNone         RejectCode = ""              // No rejection (valid)
	RejectPCRMismatch  RejectCode = "PCR_MISMATCH"  // Measurement doesn't match policy
	RejectNonceStale   RejectCode = "NONCE_STALE"   // Challenge-response failed
	RejectNonceInvalid RejectCode = "NONCE_INVALID" // Nonce format/length wrong
	RejectTCBRevoked   RejectCode = "TCB_REVOKED"   // TCB level revoked by vendor
	RejectChainInvalid RejectCode = "CHAIN_INVALID" // Certificate chain broken
	RejectExpired      RejectCode = "EXPIRED"       // Attestation too old
	RejectMalformed    RejectCode = "MALFORMED"     // Couldn't parse attestation
)

// NonceSpec defines nonce requirements for freshness verification.
type NonceSpec struct {
	// Length is the required nonce length in bytes (typically 32 or 64)
	Length int

	// MaxAge is how long a nonce remains valid after issuance
	MaxAge time.Duration
}

// DefaultNonceSpec returns conservative nonce requirements.
// 32 bytes = 256 bits of entropy, 5 minutes max age.
func DefaultNonceSpec() NonceSpec {
	return NonceSpec{
		Length: 32,
		MaxAge: 5 * time.Minute,
	}
}
