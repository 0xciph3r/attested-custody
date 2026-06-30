// Package session manages signing session lifecycle.
//
// The session manager is the coordinator's core component. It:
// - Creates signing sessions
// - Collects attestations from participants
// - Tracks FROST round progress
// - Enforces timeouts
//
// Security principle: the coordinator is UNTRUSTED. It orchestrates
// but never sees key material. All security comes from attestation
// verification and threshold cryptography.
package session

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/0xciph3r/attested-custody/internal/attestation"
	"github.com/0xciph3r/attested-custody/internal/policy"
	"github.com/0xciph3r/attested-custody/pkg/types"
)

var (
	ErrSessionNotFound     = errors.New("session: not found")
	ErrSessionExpired      = errors.New("session: expired")
	ErrSignerNotEnrolled   = errors.New("session: signer not enrolled")
	ErrSignerNotActive     = errors.New("session: signer not active")
	ErrAttestationRequired = errors.New("session: attestation required before signing")
	ErrInsufficientSigners = errors.New("session: insufficient signers for threshold")
	ErrDuplicateSession    = errors.New("session: duplicate request ID")
)

// Manager manages signing sessions.
type Manager struct {
	mu sync.RWMutex

	// sessions tracks active sessions by ID
	sessions map[types.SessionID]*types.Session

	// requestIndex prevents duplicate requests (idempotency)
	requestIndex map[string]types.SessionID

	// dependencies
	verifier     *attestation.Verifier
	nonceManager *attestation.NonceManager
	policyState  *policy.StateManager

	// config
	config types.SessionConfig

	// clock for testing
	clock func() time.Time

	// testCertChain is only used in tests for creating mock attestations
	testCertChain []*x509.Certificate
}

// ManagerConfig configures the session manager.
type ManagerConfig struct {
	Verifier     *attestation.Verifier
	NonceManager *attestation.NonceManager
	PolicyState  *policy.StateManager
	Config       types.SessionConfig
}

// NewManager creates a session manager.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("session: verifier required")
	}
	if cfg.NonceManager == nil {
		return nil, errors.New("session: nonce manager required")
	}
	if cfg.PolicyState == nil {
		return nil, errors.New("session: policy state required")
	}

	return &Manager{
		sessions:     make(map[types.SessionID]*types.Session),
		requestIndex: make(map[string]types.SessionID),
		verifier:     cfg.Verifier,
		nonceManager: cfg.NonceManager,
		policyState:  cfg.PolicyState,
		config:       cfg.Config,
		clock:        time.Now,
	}, nil
}

// CreateSession initiates a new signing session.
func (m *Manager) CreateSession(req types.SigningRequest) (*types.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Idempotency check
	if existingID, ok := m.requestIndex[req.RequestID]; ok {
		if session, ok := m.sessions[existingID]; ok {
			return session, nil // Return existing session
		}
	}

	// Select participants
	participants, err := m.selectParticipants(req)
	if err != nil {
		return nil, err
	}

	threshold := m.policyState.ThresholdConfig().Threshold
	if len(participants) < threshold {
		return nil, fmt.Errorf("%w: got %d, need %d",
			ErrInsufficientSigners, len(participants), threshold)
	}

	// Generate session ID
	sessionID, err := m.generateSessionID()
	if err != nil {
		return nil, err
	}

	now := m.clock()
	session := &types.Session{
		ID:           sessionID,
		Status:       types.SessionAttesting,
		Participants: participants,
		Threshold:    threshold,
		PayloadHash:  req.PayloadHash,
		CreatedAt:    now,
		ExpiresAt:    now.Add(m.config.Timeout),
		Attestations: make(map[string]*types.AttestationDocument),
	}

	m.sessions[sessionID] = session
	m.requestIndex[req.RequestID] = sessionID

	return session, nil
}

// selectParticipants chooses signers for the session.
func (m *Manager) selectParticipants(req types.SigningRequest) ([]types.SessionParticipant, error) {
	var participants []types.SessionParticipant

	if len(req.RequiredSigners) > 0 {
		// Use specified signers
		for _, signerID := range req.RequiredSigners {
			signer, ok := m.policyState.GetSigner(signerID)
			if !ok {
				return nil, fmt.Errorf("%w: %s", ErrSignerNotEnrolled, signerID)
			}
			if signer.Status != types.SignerActive {
				return nil, fmt.Errorf("%w: %s (status: %s)",
					ErrSignerNotActive, signerID, signer.Status)
			}
			participants = append(participants, types.SessionParticipant{
				SignerID: signerID,
			})
		}
	} else {
		// Use all active signers
		for _, signer := range m.policyState.GetActiveSigners() {
			participants = append(participants, types.SessionParticipant{
				SignerID: signer.SignerID,
			})
		}
	}

	return participants, nil
}

// generateSessionID creates a unique session identifier.
func (m *Manager) generateSessionID() (types.SessionID, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return types.SessionID(hex.EncodeToString(b)), nil
}

// GetSession retrieves a session by ID.
func (m *Manager) GetSession(id types.SessionID) (*types.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}

	// Check expiry
	if m.clock().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// IssueChallenge generates a nonce for a signer to include in their attestation.
func (m *Manager) IssueChallenge(sessionID types.SessionID, signerID string) ([]byte, error) {
	session, err := m.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	// Verify signer is a participant
	found := false
	for _, p := range session.Participants {
		if p.SignerID == signerID {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: %s not in session", ErrSignerNotEnrolled, signerID)
	}

	return m.nonceManager.Issue()
}

// SubmitAttestation processes an attestation from a signer.
func (m *Manager) SubmitAttestation(
	sessionID types.SessionID,
	signerID string,
	doc *types.AttestationDocument,
	nonce []byte,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	if m.clock().After(session.ExpiresAt) {
		session.Status = types.SessionExpired
		return ErrSessionExpired
	}

	// Find participant
	var participant *types.SessionParticipant
	for i := range session.Participants {
		if session.Participants[i].SignerID == signerID {
			participant = &session.Participants[i]
			break
		}
	}
	if participant == nil {
		return fmt.Errorf("%w: %s", ErrSignerNotEnrolled, signerID)
	}

	// Validate nonce (one-time use)
	if err := m.nonceManager.Validate(nonce); err != nil {
		return fmt.Errorf("nonce validation failed: %w", err)
	}

	// Verify attestation
	result := m.verifier.Verify(doc, nonce)
	if !result.Valid {
		return fmt.Errorf("attestation rejected: %s - %s", result.RejectCode, result.Details)
	}

	// Record attestation
	session.Attestations[signerID] = doc
	participant.Attested = true
	participant.AttestationTime = m.clock()

	// Check if we can advance to signing
	m.maybeAdvanceSession(session)

	return nil
}

// maybeAdvanceSession checks if session can move to next phase.
func (m *Manager) maybeAdvanceSession(session *types.Session) {
	if session.Status != types.SessionAttesting {
		return
	}

	attestedCount := 0
	for _, p := range session.Participants {
		if p.Attested {
			attestedCount++
		}
	}

	// Need threshold attestations to proceed
	if attestedCount >= session.Threshold {
		session.Status = types.SessionCommit
	}
}

// RecordCommitment records a FROST round 1 commitment from a signer.
func (m *Manager) RecordCommitment(sessionID types.SessionID, signerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	if session.Status != types.SessionCommit {
		return fmt.Errorf("session not in commit phase (status: %s)", session.Status)
	}

	// Find participant and verify attested
	for i := range session.Participants {
		if session.Participants[i].SignerID == signerID {
			if !session.Participants[i].Attested {
				return ErrAttestationRequired
			}
			session.Participants[i].CommitmentReceived = true
			break
		}
	}

	// Check if ready for signing phase
	commitCount := 0
	for _, p := range session.Participants {
		if p.CommitmentReceived {
			commitCount++
		}
	}
	if commitCount >= session.Threshold {
		session.Status = types.SessionSign
	}

	return nil
}

// RecordShare records a FROST round 2 signature share from a signer.
func (m *Manager) RecordShare(sessionID types.SessionID, signerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	if session.Status != types.SessionSign {
		return fmt.Errorf("session not in sign phase (status: %s)", session.Status)
	}

	// Find participant
	for i := range session.Participants {
		if session.Participants[i].SignerID == signerID {
			if !session.Participants[i].Attested {
				return ErrAttestationRequired
			}
			session.Participants[i].ShareReceived = true
			break
		}
	}

	// Check if signing complete
	shareCount := 0
	for _, p := range session.Participants {
		if p.ShareReceived {
			shareCount++
		}
	}
	if shareCount >= session.Threshold {
		session.Status = types.SessionComplete
	}

	return nil
}

// CleanupExpired removes expired sessions.
func (m *Manager) CleanupExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	removed := 0

	for id, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, id)
			removed++
		}
	}

	return removed
}

// WithClock sets a custom clock (for testing).
func (m *Manager) WithClock(clock func() time.Time) {
	m.clock = clock
}
