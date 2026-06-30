# Copilot Instructions for `attested-custody`

## Build, test, and lint commands

This repository is currently documentation-first. There is no runnable implementation or build/test/lint tooling configured yet in this repo (`reference-impl/` is empty and there are no `go.mod`, `Cargo.toml`, `package.json`, `Makefile`, or CI workflows).

When implementation code is added, document:
- full build command
- full test command
- single-test invocation (for the chosen test framework)
- lint/static-check command

## High-level architecture

This project’s target architecture combines FROST threshold signing with TEE-backed key protection and attestation-gated operations:

1. Key shares are generated and/or stored inside signer enclaves.
2. The coordinator/API layer is treated as untrusted orchestration.
3. Before sensitive operations (key share distribution, signing), clients verify enclave attestation.
4. Partial signatures are produced inside enclaves and aggregated externally.
5. Policy state must be protected against rollback (counter/anchor design), not just sealed.

Use these docs together for system context:
- `README.md` (project goal and structure)
- `notes/day-02-attestation.md` (attestation flow and verification requirements)
- `notes/day-03-threat-model.md` (attack surface and defense mapping)
- `whitepaper/outline.md` (intended production architecture and implementation direction)

## Key conventions in this repository

1. **Trust model is explicit and conservative**
   - Host OS/hypervisor/coordinator are untrusted by default.
   - Enclave boundary is the only trusted execution boundary for key material.
   - Trust assumptions are documented per TEE/vendor, not implied.

2. **Attestation is a hard gate, not a soft signal**
   - Verify certificate chain/signature, measurement values, and nonce freshness.
   - For Nitro flows, verify all relevant PCRs (not only PCR0).
   - Do not release secrets after attestation unless encrypting to enclave-held key material.

3. **Security properties are documented as “asset → threat → defense layer”**
   - Follow the threat mapping style in `notes/day-03-threat-model.md` when adding new design content.
   - Include what is out of scope (e.g., DoS, supply chain) and required mitigations where applicable.

4. **Learning content format is standardized**
   - Day-based notes in `notes/day-XX-*.md`.
   - Typical section shape: concept explanation, diagrams/flows, exercises, resources, summary.
   - Preserve this structure for new curriculum days to keep continuity.
