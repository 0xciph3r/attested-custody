// Package types defines core primitives for attested custody.
package types

import (
	"time"
)

// SessionID uniquely identifies a signing session.
type SessionID string

// Session represents an active signing session.
// The coordinator manages sessions but never sees key material.
type Session struct {
	// ID uniquely identifies this session
	ID SessionID

	// Status tracks the session lifecycle
	Status SessionStatus

	// Participants are the enrolled signers participating in this session
	Participants []SessionParticipant

	// Threshold is how many participants must complete signing
	Threshold int

	// Payload is the transaction/message being signed
	// (hash only — coordinator doesn't need the full transaction)
	PayloadHash [32]byte

	// CreatedAt is when the session was initiated
	CreatedAt time.Time

	// ExpiresAt is the session deadline (prevents hanging sessions)
	ExpiresAt time.Time

	// Attestations received from participants
	Attestations map[string]*AttestationDocument
}

// SessionStatus represents the signing session lifecycle.
type SessionStatus string

const (
	SessionPending   SessionStatus = "pending"    // Waiting for participants
	SessionAttesting SessionStatus = "attesting"  // Collecting attestations
	SessionCommit    SessionStatus = "commit"     // FROST round 1: commitments
	SessionSign      SessionStatus = "sign"       // FROST round 2: signature shares
	SessionComplete  SessionStatus = "complete"   // Signature aggregated
	SessionFailed    SessionStatus = "failed"     // Session failed
	SessionExpired   SessionStatus = "expired"    // Deadline passed
)

// SessionParticipant tracks a signer's participation in a session.
type SessionParticipant struct {
	// SignerID references the enrolled signer
	SignerID string

	// Attested indicates whether we've verified their attestation
	Attested bool

	// AttestationTime is when attestation was verified
	AttestationTime time.Time

	// CommitmentReceived tracks FROST round 1 progress
	CommitmentReceived bool

	// ShareReceived tracks FROST round 2 progress
	ShareReceived bool
}

// SessionConfig defines parameters for session creation.
type SessionConfig struct {
	// Timeout is how long before session expires
	Timeout time.Duration

	// RequireAllAttestation requires all participants to attest
	// (even if only threshold needed for signing)
	RequireAllAttestation bool

	// StrictNonceLifetime enforces nonce max age during session
	StrictNonceLifetime bool
}

// DefaultSessionConfig returns conservative session parameters.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		Timeout:               10 * time.Minute,
		RequireAllAttestation: false, // Only threshold needed
		StrictNonceLifetime:   true,
	}
}

// SigningRequest is what initiates a signing session.
type SigningRequest struct {
	// RequestID for idempotency
	RequestID string

	// PayloadHash is what we're signing
	PayloadHash [32]byte

	// RequiredSigners specifies which signers to use (optional)
	// If empty, coordinator selects from available active signers
	RequiredSigners []string

	// Urgency affects timeout and retry behavior
	Urgency RequestUrgency
}

// RequestUrgency indicates how time-sensitive the signing is.
type RequestUrgency string

const (
	UrgencyNormal RequestUrgency = "normal" // Standard timeout
	UrgencyHigh   RequestUrgency = "high"   // Shorter timeout, more retries
)
