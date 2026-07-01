# Attested Custody Reference Implementation

Reference implementation of the attested custody architecture described in the whitepaper.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Coordinator (Untrusted)                  │
│  - Orchestrates signing sessions                            │
│  - Routes messages between signers                          │
│  - NO access to key material                                │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  Signer Enclave │ │  Signer Enclave │ │  Signer Enclave │
│  (Attested)     │ │  (Attested)     │ │  (Attested)     │
│  - Key share    │ │  - Key share    │ │  - Key share    │
│  - FROST logic  │ │  - FROST logic  │ │  - FROST logic  │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

## Modules

| Package | Purpose |
|---------|---------|
| `pkg/types` | Core types: attestation documents, PCRs, certificates |
| `internal/attestation` | Attestation verification logic |
| `internal/policy` | Monotonic policy state management |
| `internal/session` | Signing session lifecycle |
| `internal/api/grpc` | gRPC coordinator API surface |
| `internal/audit` | Structured security/audit event model |
| `proto/coordinator/v1` | Coordinator gRPC protobuf contract |

## Production-hardening progress

1. Durable policy state stores added:
   - `FileStateStore` (atomic JSON file writes)
   - `SQLiteStateStore` (singleton latest-state row)
2. Startup recovery flow added:
   - fail-closed by default when no state exists
   - explicit bootstrap mode for genesis initialization only
   - persisted records are always re-validated with quorum + monotonic checks
3. gRPC API surface added:
   - `CreateSession`
   - `IssueChallenge`
   - `SubmitAttestation`
   - `GetSession`
4. Structured audit events emitted for session creation and attestation decisions.
5. Session collision detection added:
   - Prevents duplicate concurrent sessions for identical (payload_hash, signer_set)
   - Deterministic payload key computed from hash + sorted signer IDs
   - Reuses in-flight sessions (not expired/failed) for identical work
   - Payload index cleaned up on session expiry

## Build

```bash
cd reference-impl
go mod tidy
go build ./...
go test ./...
```

## Status

🚧 Under development — reference implementation with production-hardening scaffolding (not production-ready yet).
