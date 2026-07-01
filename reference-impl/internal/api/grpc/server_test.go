package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/0xciph3r/attested-custody/internal/audit"
	coordinatorv1 "github.com/0xciph3r/attested-custody/proto/coordinator/v1"
	"github.com/0xciph3r/attested-custody/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type captureEmitter struct {
	events []audit.Event
}

func (c *captureEmitter) Emit(_ context.Context, event audit.Event) error {
	c.events = append(c.events, event)
	return nil
}

type fakeSessionService struct {
	createResp *types.Session
	createErr  error
}

func (f *fakeSessionService) CreateSession(req types.SigningRequest) (*types.Session, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.createResp != nil {
		return f.createResp, nil
	}
	now := time.Now().UTC()
	return &types.Session{
		ID:        "sess-1",
		Status:    types.SessionAttesting,
		Threshold: 2,
		Participants: []types.SessionParticipant{
			{SignerID: "s1"},
			{SignerID: "s2"},
		},
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}, nil
}

func (f *fakeSessionService) IssueChallenge(sessionID types.SessionID, signerID string) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}

func (f *fakeSessionService) SubmitAttestation(sessionID types.SessionID, signerID string, doc *types.AttestationDocument, nonce []byte) error {
	return nil
}

func (f *fakeSessionService) GetSession(id types.SessionID) (*types.Session, error) {
	now := time.Now().UTC()
	return &types.Session{
		ID:        id,
		Status:    types.SessionAttesting,
		Threshold: 2,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	}, nil
}

func TestCreateSessionRejectsBadHashLength(t *testing.T) {
	t.Parallel()

	srv, err := NewServer(&fakeSessionService{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	_, err = srv.CreateSession(context.Background(), &coordinatorv1.CreateSessionRequest{
		RequestId:   "req-1",
		PayloadHash: []byte{0x01},
	})
	if err == nil {
		t.Fatal("expected error")
	}

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestCreateSessionSuccess(t *testing.T) {
	t.Parallel()

	emitter := &captureEmitter{}
	srv, err := NewServerWithEmitter(&fakeSessionService{}, emitter)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	hash := make([]byte, 32)
	resp, err := srv.CreateSession(context.Background(), &coordinatorv1.CreateSessionRequest{
		RequestId:   "req-1",
		PayloadHash: hash,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if resp.SessionId == "" {
		t.Fatal("expected non-empty session_id")
	}
	if resp.Threshold != 2 {
		t.Fatalf("expected threshold 2, got %d", resp.Threshold)
	}
	if len(emitter.events) == 0 || emitter.events[0].Action != "create_session" || emitter.events[0].Result != "accepted" {
		t.Fatalf("expected accepted create_session audit event, got %+v", emitter.events)
	}
}

func TestExtractRejectCode(t *testing.T) {
	t.Parallel()

	got := extractRejectCode(errors.New("attestation rejected: PCR_MISMATCH - bad pcr"))
	if got != "PCR_MISMATCH" {
		t.Fatalf("expected PCR_MISMATCH, got %q", got)
	}
}
