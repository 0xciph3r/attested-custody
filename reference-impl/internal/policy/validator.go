// Package policy implements monotonic policy state for rollback defense.
//
// The core security invariant: policy version must strictly increase.
// If an enclave ever sees a version <= its last known version, it halts.
// This prevents attackers from replaying old sealed state after reboot.
package policy

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// ErrRollbackDetected is returned when a state rollback is detected.
// This is a critical security event — the system should halt.
var ErrRollbackDetected = errors.New("policy: rollback detected - version not strictly increasing")

// ErrInsufficientQuorum is returned when not enough guardians signed.
var ErrInsufficientQuorum = errors.New("policy: insufficient quorum signatures")

// ErrInvalidSignature is returned when a guardian signature is invalid.
var ErrInvalidSignature = errors.New("policy: invalid guardian signature")

// Guardian represents a policy guardian who signs state transitions.
type Guardian struct {
	ID        string
	PublicKey ed25519.PublicKey
}

// Validator validates policy state transitions.
// It ensures monotonicity and quorum requirements.
type Validator struct {
	mu sync.RWMutex

	// guardians are the trusted signers for state transitions
	guardians map[string]Guardian

	// threshold is t in t-of-n
	threshold int

	// lastKnownVersion is the highest version we've seen
	// This is the critical state for rollback detection
	lastKnownVersion uint64

	// clock for testing
	clock func() time.Time
}

// ValidatorConfig configures the policy validator.
type ValidatorConfig struct {
	// Guardians are the trusted policy guardians
	Guardians []Guardian

	// Threshold is the minimum signatures required (t)
	Threshold int

	// InitialVersion is the starting version (usually 0)
	InitialVersion uint64
}

// NewValidator creates a policy validator.
func NewValidator(cfg ValidatorConfig) (*Validator, error) {
	if cfg.Threshold <= 0 {
		return nil, errors.New("policy: threshold must be positive")
	}
	if cfg.Threshold > len(cfg.Guardians) {
		return nil, errors.New("policy: threshold exceeds guardian count")
	}

	guardians := make(map[string]Guardian, len(cfg.Guardians))
	for _, g := range cfg.Guardians {
		if len(g.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("policy: guardian %s has invalid public key size", g.ID)
		}
		guardians[g.ID] = g
	}

	return &Validator{
		guardians:        guardians,
		threshold:        cfg.Threshold,
		lastKnownVersion: cfg.InitialVersion,
		clock:            time.Now,
	}, nil
}

// ValidateTransition checks if a state transition is valid.
// Returns nil if valid, error otherwise.
//
// Security checks:
// 1. Version is strictly greater than last known
// 2. At least threshold guardians signed
// 3. All signatures are valid
func (v *Validator) ValidateTransition(record *types.PolicyStateRecord) error {
	v.mu.RLock()
	lastVersion := v.lastKnownVersion
	v.mu.RUnlock()

	// Check 1: Monotonicity (the critical rollback defense)
	if record.Version <= lastVersion {
		return fmt.Errorf("%w: got version %d, last known %d",
			ErrRollbackDetected, record.Version, lastVersion)
	}

	// Check 2: Quorum count
	if len(record.QuorumSignatures) < v.threshold {
		return fmt.Errorf("%w: got %d signatures, need %d",
			ErrInsufficientQuorum, len(record.QuorumSignatures), v.threshold)
	}

	// Check 3: Validate each signature
	hash := record.Hash()
	validSigs := 0
	seenSigners := make(map[string]bool)

	for _, sig := range record.QuorumSignatures {
		// Prevent duplicate signer counting
		if seenSigners[sig.SignerID] {
			continue
		}

		guardian, ok := v.guardians[sig.SignerID]
		if !ok {
			// Unknown signer — ignore (not an error, just doesn't count)
			continue
		}

		if ed25519.Verify(guardian.PublicKey, hash[:], sig.Signature) {
			validSigs++
			seenSigners[sig.SignerID] = true
		}
	}

	if validSigs < v.threshold {
		return fmt.Errorf("%w: only %d valid signatures, need %d",
			ErrInsufficientQuorum, validSigs, v.threshold)
	}

	return nil
}

// AcceptTransition validates and accepts a state transition.
// If valid, updates lastKnownVersion.
//
// This is the commit point — after this, the validator will reject
// any version <= this one.
func (v *Validator) AcceptTransition(record *types.PolicyStateRecord) error {
	if err := v.ValidateTransition(record); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine might have advanced)
	if record.Version <= v.lastKnownVersion {
		return fmt.Errorf("%w: version %d already superseded by %d",
			ErrRollbackDetected, record.Version, v.lastKnownVersion)
	}

	v.lastKnownVersion = record.Version
	return nil
}

// LastKnownVersion returns the current version.
func (v *Validator) LastKnownVersion() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastKnownVersion
}

// WithClock sets a custom clock (for testing).
func (v *Validator) WithClock(clock func() time.Time) {
	v.clock = clock
}
