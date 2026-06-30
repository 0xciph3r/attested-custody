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
| `cmd/coordinator` | Coordinator service |

## Build

```bash
cd reference-impl
go mod tidy
go build ./...
go test ./...
```

## Status

🚧 Under development — not production ready.
