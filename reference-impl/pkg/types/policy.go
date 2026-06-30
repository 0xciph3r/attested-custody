// Package types defines core primitives for attested custody.
package types

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// PolicyStateRecord represents the monotonic state that prevents rollback.
// This is the critical structure that defends against an attacker replaying
// old sealed state after a reboot.
//
// Security invariant: policy_version must strictly increase across restarts.
// If an enclave sees a version <= its last known version, it must halt.
type PolicyStateRecord struct {
	// Version is a strictly monotonic counter (never decrements)
	Version uint64

	// StateRoot is the Merkle root of the current policy state
	// (enrolled signers, active sessions, etc.)
	StateRoot [32]byte

	// Timestamp is when this state was committed
	Timestamp time.Time

	// QuorumSignatures from threshold of policy guardians
	// Required: t-of-n signatures to accept a state transition
	QuorumSignatures []QuorumSignature
}

// QuorumSignature is a signature from a policy guardian.
type QuorumSignature struct {
	// SignerID identifies which guardian signed
	SignerID string

	// Signature is the Ed25519 or ECDSA signature over the state record
	Signature []byte
}

// Hash returns the canonical hash of this state record (excluding signatures).
// This is what guardians sign.
func (p *PolicyStateRecord) Hash() [32]byte {
	// Canonical encoding: version || state_root || timestamp_unix
	data := make([]byte, 8+32+8)
	
	// Little-endian version
	for i := 0; i < 8; i++ {
		data[i] = byte(p.Version >> (8 * i))
	}
	
	// State root
	copy(data[8:40], p.StateRoot[:])
	
	// Unix timestamp
	ts := uint64(p.Timestamp.Unix())
	for i := 0; i < 8; i++ {
		data[40+i] = byte(ts >> (8 * i))
	}
	
	return sha256.Sum256(data)
}

// StateRootHex returns the state root as a hex string for logging.
func (p *PolicyStateRecord) StateRootHex() string {
	return hex.EncodeToString(p.StateRoot[:])
}

// SignerEnrollment represents an enrolled signer in the custody system.
type SignerEnrollment struct {
	// SignerID is a unique identifier for this signer
	SignerID string

	// PublicKeyShare is the signer's FROST public key share
	// (committed during DKG, verified via attestation)
	PublicKeyShare []byte

	// EnclaveIdentity is the expected PCR set for this signer's enclave
	EnclaveIdentity PCRSet

	// EnrolledAt is when this signer was added to the policy
	EnrolledAt time.Time

	// Status tracks whether the signer is active, suspended, or revoked
	Status SignerStatus
}

// SignerStatus represents the lifecycle state of an enrolled signer.
type SignerStatus string

const (
	SignerActive    SignerStatus = "active"    // Can participate in signing
	SignerSuspended SignerStatus = "suspended" // Temporarily disabled
	SignerRevoked   SignerStatus = "revoked"   // Permanently removed
)

// ThresholdConfig defines the t-of-n parameters.
type ThresholdConfig struct {
	// Threshold is the minimum signers required (t)
	Threshold int

	// Total is the total number of signers (n)
	Total int
}

// Valid checks if the threshold config is sensible.
func (t ThresholdConfig) Valid() bool {
	return t.Threshold > 0 && t.Threshold <= t.Total && t.Total > 0
}
