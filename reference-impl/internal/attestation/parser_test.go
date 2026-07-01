package attestation

import (
	"errors"
	"testing"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

type stubParser struct {
	doc *types.AttestationDocument
	err error
}

func (s stubParser) Parse(raw []byte) (*types.AttestationDocument, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.doc, nil
}

func TestVerifier_VerifyRaw_ParserError(t *testing.T) {
	chain, rootPool := mustGenerateCertChain(t)
	now := time.Now()

	verifier, err := NewVerifier(VerifierConfig{
		ExpectedPCRs: types.PCRSet{types.PCR0: []byte("expected")},
		RootCerts:    rootPool,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verifier.WithClock(func() time.Time { return now })

	result := verifier.VerifyRaw(stubParser{err: errors.New("decode failed")}, []byte{0x01}, make([]byte, 32))
	if result.Valid {
		t.Fatal("expected invalid result")
	}
	if result.RejectCode != types.RejectMalformed {
		t.Fatalf("expected RejectMalformed, got %s", result.RejectCode)
	}

	_ = chain
}

func TestVerifier_VerifyRaw_SuccessPath(t *testing.T) {
	chain, rootPool := mustGenerateCertChain(t)
	now := time.Now()

	expectedPCRs := types.PCRSet{
		types.PCR0: []byte("expected-pcr0"),
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	doc := &types.AttestationDocument{
		ModuleID:  "test",
		PCRs:      expectedPCRs,
		Nonce:     nonce,
		Timestamp: now.Add(-time.Second),
		CertChain: chain,
	}

	verifier, err := NewVerifier(VerifierConfig{
		ExpectedPCRs: expectedPCRs,
		RootCerts:    rootPool,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verifier.WithClock(func() time.Time { return now })

	result := verifier.VerifyRaw(stubParser{doc: doc}, []byte{0xaa}, nonce)
	if !result.Valid {
		t.Fatalf("expected valid result, got reject %s (%s)", result.RejectCode, result.Details)
	}
}
