// Package policy implements monotonic policy state for rollback defense.
package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// StateManager manages the policy state (enrolled signers, config).
// It computes state roots for the policy record.
type StateManager struct {
	mu sync.RWMutex

	// enrolledSigners are the registered signers
	enrolledSigners map[string]*types.SignerEnrollment

	// thresholdConfig is the current t-of-n parameters
	thresholdConfig types.ThresholdConfig

	// version is the current policy version
	version uint64

	// clock for timestamps
	clock func() time.Time
}

// NewStateManager creates a new state manager.
func NewStateManager(threshold types.ThresholdConfig) (*StateManager, error) {
	if !threshold.Valid() {
		return nil, errors.New("policy: invalid threshold config")
	}

	return &StateManager{
		enrolledSigners: make(map[string]*types.SignerEnrollment),
		thresholdConfig: threshold,
		version:         0,
		clock:           time.Now,
	}, nil
}

// EnrollSigner adds a signer to the policy.
// Returns the new policy version.
func (sm *StateManager) EnrollSigner(enrollment *types.SignerEnrollment) (uint64, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if enrollment.SignerID == "" {
		return 0, errors.New("policy: signer ID required")
	}

	if _, exists := sm.enrolledSigners[enrollment.SignerID]; exists {
		return 0, fmt.Errorf("policy: signer %s already enrolled", enrollment.SignerID)
	}

	// Set enrollment timestamp and status
	enrollment.EnrolledAt = sm.clock()
	enrollment.Status = types.SignerActive

	sm.enrolledSigners[enrollment.SignerID] = enrollment
	sm.version++

	return sm.version, nil
}

// RevokeSigner marks a signer as revoked.
// Returns the new policy version.
func (sm *StateManager) RevokeSigner(signerID string) (uint64, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	signer, exists := sm.enrolledSigners[signerID]
	if !exists {
		return 0, fmt.Errorf("policy: signer %s not found", signerID)
	}

	if signer.Status == types.SignerRevoked {
		return 0, fmt.Errorf("policy: signer %s already revoked", signerID)
	}

	signer.Status = types.SignerRevoked
	sm.version++

	return sm.version, nil
}

// SuspendSigner temporarily disables a signer.
func (sm *StateManager) SuspendSigner(signerID string) (uint64, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	signer, exists := sm.enrolledSigners[signerID]
	if !exists {
		return 0, fmt.Errorf("policy: signer %s not found", signerID)
	}

	if signer.Status != types.SignerActive {
		return 0, fmt.Errorf("policy: signer %s not active (status: %s)", signerID, signer.Status)
	}

	signer.Status = types.SignerSuspended
	sm.version++

	return sm.version, nil
}

// ReactivateSigner reactivates a suspended signer.
func (sm *StateManager) ReactivateSigner(signerID string) (uint64, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	signer, exists := sm.enrolledSigners[signerID]
	if !exists {
		return 0, fmt.Errorf("policy: signer %s not found", signerID)
	}

	if signer.Status != types.SignerSuspended {
		return 0, fmt.Errorf("policy: signer %s not suspended (status: %s)", signerID, signer.Status)
	}

	signer.Status = types.SignerActive
	sm.version++

	return sm.version, nil
}

// GetActivesSigners returns all active signers.
func (sm *StateManager) GetActiveSigners() []*types.SignerEnrollment {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var active []*types.SignerEnrollment
	for _, s := range sm.enrolledSigners {
		if s.Status == types.SignerActive {
			active = append(active, s)
		}
	}
	return active
}

// GetSigner returns a specific signer's enrollment.
func (sm *StateManager) GetSigner(signerID string) (*types.SignerEnrollment, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.enrolledSigners[signerID]
	return s, ok
}

// ComputeStateRoot computes the Merkle root of current state.
// This is what gets signed into the PolicyStateRecord.
func (sm *StateManager) ComputeStateRoot() [32]byte {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Collect signer IDs and sort for deterministic ordering
	ids := make([]string, 0, len(sm.enrolledSigners))
	for id := range sm.enrolledSigners {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// Build leaf hashes
	leaves := make([][]byte, 0, len(ids)+1)

	// Add config leaf
	configLeaf := sm.hashThresholdConfig()
	leaves = append(leaves, configLeaf[:])

	// Add signer leaves
	for _, id := range ids {
		signer := sm.enrolledSigners[id]
		leaf := sm.hashSignerEnrollment(signer)
		leaves = append(leaves, leaf[:])
	}

	// Compute Merkle root (simplified: just hash all leaves together)
	// A production implementation would use a proper Merkle tree
	return sm.computeMerkleRoot(leaves)
}

// hashThresholdConfig hashes the threshold configuration.
func (sm *StateManager) hashThresholdConfig() [32]byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], uint32(sm.thresholdConfig.Threshold))
	binary.LittleEndian.PutUint32(data[4:8], uint32(sm.thresholdConfig.Total))
	return sha256.Sum256(data)
}

// hashSignerEnrollment hashes a signer enrollment.
func (sm *StateManager) hashSignerEnrollment(s *types.SignerEnrollment) [32]byte {
	// Hash: signerID || publicKeyShare || status
	h := sha256.New()
	h.Write([]byte(s.SignerID))
	h.Write(s.PublicKeyShare)
	h.Write([]byte(s.Status))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// computeMerkleRoot computes a simple Merkle root.
func (sm *StateManager) computeMerkleRoot(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256(nil)
	}
	if len(leaves) == 1 {
		var result [32]byte
		copy(result[:], leaves[0])
		return result
	}

	// Iteratively hash pairs
	for len(leaves) > 1 {
		var next [][]byte
		for i := 0; i < len(leaves); i += 2 {
			if i+1 < len(leaves) {
				h := sha256.New()
				h.Write(leaves[i])
				h.Write(leaves[i+1])
				next = append(next, h.Sum(nil))
			} else {
				// Odd number — carry forward
				next = append(next, leaves[i])
			}
		}
		leaves = next
	}

	var result [32]byte
	copy(result[:], leaves[0])
	return result
}

// CreateStateRecord creates a PolicyStateRecord for the current state.
// Note: QuorumSignatures must be added by the caller.
func (sm *StateManager) CreateStateRecord() *types.PolicyStateRecord {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return &types.PolicyStateRecord{
		Version:   sm.version,
		StateRoot: sm.ComputeStateRoot(),
		Timestamp: sm.clock(),
	}
}

// Version returns the current policy version.
func (sm *StateManager) Version() uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.version
}

// ThresholdConfig returns the threshold configuration.
func (sm *StateManager) ThresholdConfig() types.ThresholdConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.thresholdConfig
}

// WithClock sets a custom clock (for testing).
func (sm *StateManager) WithClock(clock func() time.Time) {
	sm.clock = clock
}
