# Attested Custody

Attested Custody is a security engineering project for institutional digital-asset custody: threshold signing coordinated by an untrusted service, with signer participation gated by hardware-backed attestation.

The goal is simple: make unauthorized signing extremely hard even when parts of the host infrastructure are compromised.

## Problem Statement

Institutional custody has to balance two hard requirements:

1. **Operational speed** for legitimate treasury movement.
2. **Strong compromise resistance** against insider abuse, host compromise, and rollback attacks.

Most approaches optimize only one side. This project focuses on combining them.

## Project Approach

This design composes four controls:

1. **Threshold signing (t-of-n)** so no single signer can authorize alone.
2. **TEE-backed signer runtime** so key-share operations remain in trusted execution.
3. **Hard-gated remote attestation** so only approved measured code can participate.
4. **Monotonic policy-state validation** so state rollback and downgrade attempts are rejected.

## Current Status

- Curriculum and architecture notes completed (`notes/`)
- Whitepaper drafted and packaged (`whitepaper/`)
- Reference implementation core completed (`reference-impl/`)
- Production hardening phase 1 completed:
  - durable state stores (file + SQLite)
  - startup recovery flow
  - gRPC API surface
  - structured audit events
- STRIDE threat model completed (`threat-model/`)

## Secure Engineer Roadmap (Project Track)

| Phase | Focus | Status |
|---|---|---|
| Day 1-3 | TEE fundamentals, attestation, threat model foundations | Done |
| Day 4-7 | Prior art, architecture, whitepaper, publication packaging | Done |
| Day 8-9 | Reference implementation + production hardening phase 1 | Done |
| Day 10+ | Production hardening phase 2 (real parsers, crypto integration, deploy controls) | Next |

## Repository Structure

```text
notes/           Day-by-day learning and design artifacts
research/        Prior-art and paper references
whitepaper/      Preprint source and build tooling
reference-impl/  Go reference implementation
threat-model/    STRIDE model and mitigation roadmap
```

## Security Model at a Glance

- **Coordinator is untrusted by default**
- **Key shares never leave signer enclaves**
- **Attestation verdict is a hard gate**
- **Replay is blocked through freshness checks**
- **Policy rollback is blocked via monotonic validation**

## Reference Implementation (Go)

See `reference-impl/README.md` for package-level details.

Quick start:

```bash
cd reference-impl
go mod tidy
go build ./...
go test ./...
```

## Whitepaper Artifacts

- Draft: `whitepaper/attested-custody-preprint.md`
- Build script: `whitepaper/build_pdf.py`
- Outline: `whitepaper/outline.md`

Build PDF locally:

```bash
python3 -m pip install reportlab
python3 whitepaper/build_pdf.py
```

## Recommended Reading Order

1. `notes/day-03-threat-model.md`
2. `notes/day-05-architecture-design.md`
3. `whitepaper/attested-custody-preprint.md`
4. `reference-impl/README.md`
5. `threat-model/STRIDE.md`

## Author

Chinonso Amadi (`0xciph3r`)
