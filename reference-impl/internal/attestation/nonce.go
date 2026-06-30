// Package attestation implements attestation verification for TEE custody.
package attestation

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// NonceManager issues and validates nonces for attestation challenges.
// Each nonce can only be used once (replay protection).
type NonceManager struct {
	mu     sync.RWMutex
	spec   types.NonceSpec
	issued map[string]nonceEntry
	clock  func() time.Time
}

type nonceEntry struct {
	nonce    []byte
	issuedAt time.Time
	used     bool
}

// NewNonceManager creates a nonce manager with the given spec.
func NewNonceManager(spec types.NonceSpec) *NonceManager {
	return &NonceManager{
		spec:   spec,
		issued: make(map[string]nonceEntry),
		clock:  time.Now,
	}
}

// Issue generates a new nonce and returns it.
// The nonce is registered for later validation.
func (nm *NonceManager) Issue() ([]byte, error) {
	nonce := make([]byte, nm.spec.Length)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()

	key := string(nonce)
	nm.issued[key] = nonceEntry{
		nonce:    nonce,
		issuedAt: nm.clock(),
		used:     false,
	}

	return nonce, nil
}

// Validate checks if a nonce is valid and marks it as used.
// Returns error if nonce is unknown, expired, or already used.
func (nm *NonceManager) Validate(nonce []byte) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	key := string(nonce)
	entry, ok := nm.issued[key]
	if !ok {
		return errors.New("nonce: unknown nonce")
	}

	if entry.used {
		return errors.New("nonce: already used (replay detected)")
	}

	age := nm.clock().Sub(entry.issuedAt)
	if age > nm.spec.MaxAge {
		return errors.New("nonce: expired")
	}

	// Mark as used (one-time use)
	entry.used = true
	nm.issued[key] = entry

	return nil
}

// Cleanup removes expired nonces to prevent memory growth.
// Call periodically (e.g., every minute).
func (nm *NonceManager) Cleanup() int {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	now := nm.clock()
	cutoff := now.Add(-nm.spec.MaxAge * 2) // Keep some buffer

	removed := 0
	for key, entry := range nm.issued {
		if entry.issuedAt.Before(cutoff) {
			delete(nm.issued, key)
			removed++
		}
	}

	return removed
}

// WithClock sets a custom clock (for testing).
func (nm *NonceManager) WithClock(clock func() time.Time) {
	nm.clock = clock
}
