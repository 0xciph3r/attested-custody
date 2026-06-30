# Attested Custody

FROST threshold signing with TEE-backed key protection and hard-gated remote attestation.

## What this project is

`attested-custody` is a security research + engineering project exploring how to build custody systems where:

1. key shares are generated/used inside trusted execution environments,
2. the coordinator remains untrusted orchestration,
3. signing is allowed only after strict attestation verification,
4. policy state is protected against rollback via monotonic external validation.

The objective is a publication-grade whitepaper and a practical reference implementation.

## Current status

- Whitepaper drafted and packaged for submission workflow
- Day 1-7 curriculum completed in `notes/`
- Reference implementation phase (Day 8+) is next

## Repository structure

```text
notes/           Day-by-day technical curriculum and design decisions
whitepaper/      Preprint draft, outline, and PDF build tooling
research/        Papers and prior-art research references
reference-impl/  Upcoming implementation work (Go + enclave integration path)
```

## Learning roadmap

| Day | Topic | Status |
|---|---|---|
| 1 | TEE Fundamentals | Done |
| 2 | Attestation Deep-dive | Done |
| 3 | TEE Threat Model | Done |
| 4 | Prior Art Survey | Done |
| 5 | Architecture Design | Done |
| 6 | Whitepaper Drafting | Done |
| 7 | Publication Packaging | Done |
| 8+ | Reference Implementation | Next |

## Core design principles

1. **Conservative trust model**  
   Host OS, hypervisor, and coordinator are untrusted by default.

2. **Attestation is a hard gate**  
   Sensitive operations require valid chain/signature/measurement/freshness checks.

3. **No plaintext key-share handling outside enclaves**  
   Signing and share handling remain in trusted execution boundary.

4. **Rollback resistance is mandatory**  
   Enclave sealing alone is insufficient; monotonic state validation is required.

## Whitepaper artifacts

- Draft: `whitepaper/attested-custody-preprint.md`
- PDF: `whitepaper/attested-custody-preprint.pdf` (generated, ignored by git)
- Build script: `whitepaper/build_pdf.py`
- Outline: `whitepaper/outline.md`

Build PDF locally:

```bash
python3 -m pip install reportlab
python3 whitepaper/build_pdf.py
```

## Key notes to read

- `notes/day-03-threat-model.md` (security boundary and threat mapping)
- `notes/day-04-prior-art-survey.md` (comparative prior-art analysis)
- `notes/day-05-architecture-design.md` (target system architecture)
- `notes/day-06-whitepaper-drafting.md` (how to draft technical sections)
- `notes/day-07-publication-packaging.md` (final publication packaging)

## Why this work matters

Most custody designs optimize one axis:

1. single-HSM trust (strong hardware, concentrated risk),
2. threshold-only software signing (distributed trust, runtime exposure),
3. TEE-only single-key models (runtime isolation, key concentration).

Attested Custody combines threshold safety + attested trusted execution + rollback-aware policy controls.

## Author

Chinonso Amadi (`0xciph3r`)
