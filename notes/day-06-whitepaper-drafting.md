# Day 6: Whitepaper Drafting (Technical Depth + Clarity)

## Why This Day Matters

By Day 5, you have architecture.  
Day 6 is where architecture becomes a paper that reviewers and hiring managers can trust.

A strong security paper is not only "correct"; it is:
- explicit about trust assumptions,
- precise about failure modes,
- reproducible in reasoning,
- clear enough for independent critique.

---

## Deliverable for Day 6

Produce a complete technical draft that includes:

1. Introduction and problem framing
2. Background and definitions
3. Threat model
4. System architecture and protocol flow
5. Security analysis
6. Limitations and future work

Target quality: a reviewer should understand exactly **what is trusted**, **what can fail**, and **why your controls are sufficient** for stated goals.

---

## Writing Strategy: Claim -> Evidence -> Boundary

Every important claim should follow this pattern:

1. **Claim**: "This design prevents X under Y assumptions."
2. **Evidence**: protocol step, attestation check, state rule, or implementation control.
3. **Boundary**: where claim stops being true (out-of-scope conditions).

Example:

```
Claim: Host root compromise does not directly expose key shares.
Evidence: signing and key operations occur inside attested enclaves only.
Boundary: does not eliminate side-channel leakage risk.
```

If a claim has no boundary, it will read as overconfident.  
If it has no evidence, it will read as hand-wavy.

---

## Section-by-Section Draft Guide

## 1) Introduction

Answer these quickly and concretely:

1. What custody problem exists today?
2. Why current models are insufficient?
3. What do you contribute?
4. Why this matters for real operators?

Keep this section practical; avoid hype language.

---

## 2) Background

Explain only what is needed for your design:

1. FROST basics relevant to your flow (DKG, threshold signing)
2. TEE and attestation concepts relevant to runtime trust
3. Why threshold-only and TEE-only are each incomplete alone

Do not turn background into a textbook chapter; focus on enabling your argument.

---

## 3) Threat Model

This is one of your highest-signal sections.

Required structure:

1. **Assets** (key shares, policy state, signing integrity)
2. **Adversaries** (external attacker, host root, malicious insider, etc.)
3. **Security goals** (confidentiality, integrity, auditability)
4. **Out-of-scope** (side-channel completeness, malicious silicon, global DoS)

Rule: state out-of-scope clearly without pretending those threats are irrelevant.

---

## 4) Architecture

Show clean trust decomposition:

- trusted signer enclaves,
- untrusted coordinator plane,
- attestation verifier,
- monotonic state service.

Minimum architecture content:

1. Enrollment flow (attestation gate)
2. DKG/share flow (attested participants only)
3. Signing flow (policy + attestation + threshold aggregation)
4. Rollback-resistant state model

A reviewer must be able to trace where secrets can exist in plaintext.

---

## 5) Security Analysis

Use asset -> threat -> defense mapping.

Example row:

| Asset | Threat | Defense | Layer |
|---|---|---|---|
| Policy state | rollback replay | monotonic signed state root | Application |

Then discuss residual risks honestly:
- side channels,
- trust root/attestation dependency,
- signer collusion and governance.

---

## 6) Limitations and Future Work

Limitations are a strength when written precisely.

Include:

1. what v1 does not prove formally,
2. where hardening is heuristic not absolute,
3. planned path for multi-TEE and verification upgrades.

Avoid generic "future work" lists with no security relevance.

---

## Diagram Requirements (for this paper)

You should have at least these diagrams:

1. Trust boundary diagram
2. Enrollment/attestation sequence
3. DKG/share provisioning sequence
4. Signing session sequence
5. Rollback defense/state versioning flow

Each diagram should answer one security question, not just look pretty.

---

## Pseudocode Standards

When including pseudocode:

1. Use deterministic reason codes (`PCR_MISMATCH`, `NONCE_STALE`, etc.)
2. Make fail-closed behavior explicit
3. Separate verification from business logic
4. Show session binding inputs (request ID, nonce, TTL)

Good pseudocode is auditable pseudocode.

---

## Common Draft Failure Modes (Avoid These)

1. Saying "secure" without naming assumptions
2. Treating attestation as one-time boot check only
3. Ignoring rollback in policy-state design
4. Blending trusted and untrusted components in one box
5. Not defining rejection behavior on failed verification

---

## Day 6 Quality Checklist

Before moving to Day 7, verify:

1. Every major claim has evidence and boundary
2. Threat model includes explicit out-of-scope section
3. Architecture includes attestation at all sensitive phases
4. Rollback model is external and monotonic, not enclave-local only
5. Security analysis includes residual risk and incident posture

---

## Exercises

1. Rewrite one paragraph in your draft to remove vague language ("secure", "robust") and replace with testable claims.

2. For each architecture component, label it trusted/untrusted and justify in one sentence.

3. Write a 6-line fail-closed pseudocode policy for attestation mismatch during signing.

4. Create one new threat mapping row for "coordinator compromise + replay attempt."

---

## Resources

- Existing `whitepaper/attested-custody-preprint.md`
- `notes/day-03-threat-model.md`
- `notes/day-05-architecture-design.md`
- FROST standard references (RFC 9591 and related material)

---

## Summary

Day 6 outcome:

```
A complete technical draft where:
├── assumptions are explicit
├── flows are auditable
├── controls map to threats
└── limits are honestly documented
```

Tomorrow (Day 7): finalization, publication packaging, and repo-level polish for public credibility.
