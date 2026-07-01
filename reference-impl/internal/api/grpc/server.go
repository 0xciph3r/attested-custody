package grpcapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/0xciph3r/attested-custody/internal/audit"
	coordinatorv1 "github.com/0xciph3r/attested-custody/proto/coordinator/v1"
	"github.com/0xciph3r/attested-custody/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SessionService is the coordinator runtime dependency required by gRPC handlers.
type SessionService interface {
	CreateSession(req types.SigningRequest) (*types.Session, error)
	IssueChallenge(sessionID types.SessionID, signerID string) ([]byte, error)
	SubmitAttestation(sessionID types.SessionID, signerID string, doc *types.AttestationDocument, nonce []byte) error
	GetSession(id types.SessionID) (*types.Session, error)
}

// Server exposes coordinator operations over gRPC.
type Server struct {
	coordinatorv1.UnimplementedCoordinatorServiceServer
	sessions SessionService
	emitter  audit.Emitter
}

// NewServer creates a gRPC server for coordinator operations.
func NewServer(sessions SessionService) (*Server, error) {
	return NewServerWithEmitter(sessions, audit.NopEmitter{})
}

// NewServerWithEmitter creates a gRPC server and wires structured audit events.
func NewServerWithEmitter(sessions SessionService, emitter audit.Emitter) (*Server, error) {
	if sessions == nil {
		return nil, errors.New("grpcapi: session service is required")
	}
	if emitter == nil {
		emitter = audit.NopEmitter{}
	}
	return &Server{sessions: sessions, emitter: emitter}, nil
}

func (s *Server) CreateSession(ctx context.Context, req *coordinatorv1.CreateSessionRequest) (*coordinatorv1.CreateSessionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.RequestId == "" {
		return nil, status.Error(codes.InvalidArgument, "request_id is required")
	}
	if len(req.PayloadHash) != 32 {
		return nil, status.Error(codes.InvalidArgument, "payload_hash must be 32 bytes")
	}

	var payloadHash [32]byte
	copy(payloadHash[:], req.PayloadHash)

	session, err := s.sessions.CreateSession(types.SigningRequest{
		RequestID:       req.RequestId,
		PayloadHash:     payloadHash,
		RequiredSigners: req.RequiredSigners,
	})
	if err != nil {
		s.emit(ctx, audit.Event{
			Timestamp: time.Now().UTC(),
			Category:  "session",
			Action:    "create_session",
			Result:    "rejected",
			RequestID: req.RequestId,
			Details:   err.Error(),
		})
		return nil, status.Errorf(codes.FailedPrecondition, "create session: %v", err)
	}

	participants := make([]string, 0, len(session.Participants))
	for _, p := range session.Participants {
		participants = append(participants, p.SignerID)
	}

	resp := &coordinatorv1.CreateSessionResponse{
		SessionId:    string(session.ID),
		Status:       string(session.Status),
		Threshold:    uint32(session.Threshold),
		Participants: participants,
		CreatedUnix:  session.CreatedAt.Unix(),
		ExpiresUnix:  session.ExpiresAt.Unix(),
	}
	s.emit(ctx, audit.Event{
		Timestamp: time.Now().UTC(),
		Category:  "session",
		Action:    "create_session",
		Result:    "accepted",
		RequestID: req.RequestId,
		SessionID: resp.SessionId,
	})

	return resp, nil
}

func (s *Server) IssueChallenge(ctx context.Context, req *coordinatorv1.IssueChallengeRequest) (*coordinatorv1.IssueChallengeResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.SessionId == "" || req.SignerId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id and signer_id are required")
	}

	nonce, err := s.sessions.IssueChallenge(types.SessionID(req.SessionId), req.SignerId)
	if err != nil {
		s.emit(ctx, audit.Event{
			Timestamp: time.Now().UTC(),
			Category:  "attestation",
			Action:    "issue_challenge",
			Result:    "rejected",
			SessionID: req.SessionId,
			SignerID:  req.SignerId,
			Details:   err.Error(),
		})
		return nil, status.Errorf(codes.FailedPrecondition, "issue challenge: %v", err)
	}

	s.emit(ctx, audit.Event{
		Timestamp: time.Now().UTC(),
		Category:  "attestation",
		Action:    "issue_challenge",
		Result:    "accepted",
		SessionID: req.SessionId,
		SignerID:  req.SignerId,
	})

	return &coordinatorv1.IssueChallengeResponse{Nonce: nonce}, nil
}

func (s *Server) SubmitAttestation(ctx context.Context, req *coordinatorv1.SubmitAttestationRequest) (*coordinatorv1.SubmitAttestationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.SessionId == "" || req.SignerId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id and signer_id are required")
	}
	if len(req.Nonce) == 0 {
		return nil, status.Error(codes.InvalidArgument, "nonce is required")
	}

	pcrs := make(types.PCRSet, len(req.Pcrs))
	for idx, value := range req.Pcrs {
		if len(value) == 0 {
			return nil, status.Errorf(codes.InvalidArgument, "PCR%d value is empty", idx)
		}
		pcrs[types.PCRIndex(idx)] = value
	}

	timestamp := time.Unix(req.TimestampUnix, 0).UTC()
	if req.TimestampUnix == 0 {
		timestamp = time.Now().UTC()
	}

	doc := &types.AttestationDocument{
		ModuleID:  req.ModuleId,
		PCRs:      pcrs,
		Nonce:     req.Nonce,
		Timestamp: timestamp,
	}

	if err := s.sessions.SubmitAttestation(types.SessionID(req.SessionId), req.SignerId, doc, req.Nonce); err != nil {
		s.emit(ctx, audit.Event{
			Timestamp:  time.Now().UTC(),
			Category:   "attestation",
			Action:     "submit_attestation",
			Result:     "rejected",
			SessionID:  req.SessionId,
			SignerID:   req.SignerId,
			RejectCode: extractRejectCode(err),
			Details:    err.Error(),
		})
		return nil, status.Errorf(codes.FailedPrecondition, "submit attestation: %v", err)
	}

	s.emit(ctx, audit.Event{
		Timestamp: time.Now().UTC(),
		Category:  "attestation",
		Action:    "submit_attestation",
		Result:    "accepted",
		SessionID: req.SessionId,
		SignerID:  req.SignerId,
	})

	return &coordinatorv1.SubmitAttestationResponse{Status: "accepted"}, nil
}

func (s *Server) GetSession(ctx context.Context, req *coordinatorv1.GetSessionRequest) (*coordinatorv1.GetSessionResponse, error) {
	if req == nil || req.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}

	session, err := s.sessions.GetSession(types.SessionID(req.SessionId))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "get session: %v", err)
	}

	participants := make([]*coordinatorv1.SessionParticipant, 0, len(session.Participants))
	for _, p := range session.Participants {
		participants = append(participants, &coordinatorv1.SessionParticipant{
			SignerId:           p.SignerID,
			Attested:           p.Attested,
			CommitmentReceived: p.CommitmentReceived,
			ShareReceived:      p.ShareReceived,
		})
	}

	return &coordinatorv1.GetSessionResponse{
		SessionId:    string(session.ID),
		Status:       string(session.Status),
		Threshold:    uint32(session.Threshold),
		Participants: participants,
		CreatedUnix:  session.CreatedAt.Unix(),
		ExpiresUnix:  session.ExpiresAt.Unix(),
	}, nil
}

func (s *Server) emit(ctx context.Context, event audit.Event) {
	_ = s.emitter.Emit(ctx, event)
}

func extractRejectCode(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Expected shape from session layer:
	// "attestation rejected: PCR_MISMATCH - details"
	const prefix = "attestation rejected: "
	if !strings.HasPrefix(msg, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(msg, prefix)
	parts := strings.SplitN(rest, " - ", 2)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}
