// Package attestation implements attestation verification for TEE custody.
package attestation

import (
	"errors"
	"fmt"
	"time"

	"github.com/0xciph3r/attested-custody/pkg/types"
)

// Parser converts raw attestation bytes into a structured document.
//
// Concrete parser implementations (Nitro, SGX, SEV) can plug into this
// interface without changing verifier logic.
type Parser interface {
	Parse(raw []byte) (*types.AttestationDocument, error)
}

// VerifyRaw parses and verifies a raw attestation payload.
func (v *Verifier) VerifyRaw(parser Parser, raw []byte, expectedNonce []byte) types.VerificationResult {
	now := v.clock()
	result := types.VerificationResult{
		VerifiedAt:  now,
		PCRsChecked: []types.PCRIndex{},
	}

	if parser == nil {
		result.RejectCode = types.RejectMalformed
		result.Details = "attestation parser is nil"
		return result
	}
	if len(raw) == 0 {
		result.RejectCode = types.RejectMalformed
		result.Details = "raw attestation is empty"
		return result
	}

	doc, err := parser.Parse(raw)
	if err != nil {
		result.RejectCode = types.RejectMalformed
		result.Details = fmt.Sprintf("failed to parse attestation: %v", err)
		return result
	}

	// Preserve parse timing context if parser leaves timestamp unset.
	if doc != nil && doc.Timestamp.IsZero() {
		doc.Timestamp = now.Add(-time.Second)
	}

	return v.Verify(doc, expectedNonce)
}

// ErrUnsupportedFormat is returned by parsers for unknown formats.
var ErrUnsupportedFormat = errors.New("attestation: unsupported format")
