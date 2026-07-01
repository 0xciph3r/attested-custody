package audit

import (
	"context"
	"time"
)

// Event is a structured audit event for security-relevant coordinator actions.
type Event struct {
	Timestamp  time.Time `json:"timestamp"`
	Category   string    `json:"category"`
	Action     string    `json:"action"`
	Result     string    `json:"result"`
	RejectCode string    `json:"reject_code,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	SignerID   string    `json:"signer_id,omitempty"`
	RequestID  string    `json:"request_id,omitempty"`
	Details    string    `json:"details,omitempty"`
}

// Emitter sends audit events to a sink (log pipeline, SIEM, DB).
type Emitter interface {
	Emit(ctx context.Context, event Event) error
}

// NopEmitter discards events.
type NopEmitter struct{}

func (NopEmitter) Emit(_ context.Context, _ Event) error { return nil }
