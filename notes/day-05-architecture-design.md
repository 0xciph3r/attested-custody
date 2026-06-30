# Day 5: Architecture Design

## Why This Day Matters

Days 1-4 built your foundations:
- what TEEs can and cannot protect
- how attestation establishes runtime trust
- where real systems fail (rollback, side-channel, ops complexity)

Day 5 turns that into a concrete architecture you can defend in front of:
- a security auditor
- a protocol engineer
- an incident response team

If Day 4 was "what to borrow," Day 5 is "what we are actually building."

---

## Design Goals

1. **Key shares never leave trusted execution in plaintext**
2. **Signing occurs only in attested signer enclaves**
3. **Coordinator remains untrusted orchestration**
4. **Policy state is rollback-resistant (monotonic)**
5. **Compromise of one host does not imply fund loss**

---

## Non-Goals (for v1)

1. Perfect side-channel immunity
2. Trustless protection against malicious hardware vendor
3. DoS-proof operation under total infrastructure compromise
4. Multi-cloud / multi-TEE portability in first release

---

## System Components

## 1) Client / Requester
- Submits signing requests
- Verifies signer attestation evidence before accepting partial signatures

## 2) API Gateway (Untrusted)
- Authenticates request origin
- Rate-limits and normalizes request shape
- Forwards to coordinator

## 3) Coordinator (Untrusted)
- Session orchestration only
- Selects eligible signer set
- Collects attestation bundles + partial signatures
- Never receives plaintext key shares

## 4) Signer Enclave (Trusted for key operations)
- Runs signer binary inside TEE
- Holds local share material (or creates/derives it internally)
- Evaluates policy checks bound to monotonic state
- Produces FROST nonce commitments and partial signatures

## 5) Attestation Verification Service
- Verifies certificate chain + signature + measurements + freshness
- Maintains allowlist of approved enclave measurements
- Issues signed "attestation verdict" object for each signer/session

## 6) Monotonic State Service
- External source of monotonic policy version/state root
- Prevents replay/rollback of sealed old policy state
- Quorum-signed updates (or anchored checkpoint model)

## 7) Audit Log Pipeline
- Append-only signed event trail
- Stores decisions, policy versions, attestation verdict IDs, signer participation

---

## Trust Boundary Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                       UNTRUSTED PLANE                               │
│                                                                      │
│  Client ──► API Gateway ──► Coordinator ──► Storage / Message Bus    │
│                                 │                                    │
│                                 │ requests only                      │
│                                 ▼                                    │
│                       Attestation Verifier                           │
│                       Monotonic State Service                        │
│                                                                      │
│  (All above can be root-compromised without direct key disclosure)   │
└──────────────────────────────────────────────────────────────────────┘
                    ══════════ HARDWARE BOUNDARY ══════════
┌──────────────────────────────────────────────────────────────────────┐
│                         TRUSTED PLANE                                │
│                                                                      │
│                     Signer Enclave A (share A)                       │
│                     Signer Enclave B (share B)                       │
│                     Signer Enclave C (share C)                       │
│                                                                      │
│       Key operations + policy evaluation + partial signing           │
└──────────────────────────────────────────────────────────────────────┘
```

Key rule: **coordinator compromise must not be enough to extract key shares or forge signatures.**

---

## Reference Signing Architecture (t-of-n)

Assume `n=5`, threshold `t=3` for example.

```
Signers: S1 S2 S3 S4 S5
Need: any 3 valid partial signatures for aggregate signature

Coordinator picks an eligible 3-of-5 set per request:
- availability
- policy eligibility
- attestation validity
```

Security effect:
- 1 compromised signer enclave is insufficient
- untrusted coordinator cannot produce signatures alone

---

## End-to-End Flows

## Flow A: Signer Enrollment (Hard Gate)

```
1. Signer enclave boots with signed image
2. Enclave generates attestation doc (with nonce challenge)
3. Verifier checks:
   - cert chain and signature
   - measurements (PCR0/PCR1/PCR2 or enclave measurement set)
   - freshness (nonce + timestamp)
4. Verifier issues signed verdict: ALLOW / DENY
5. Only ALLOW signers are admitted to signing pool
```

If any check fails -> signer is quarantined (not soft-warning).

---

## Flow B: DKG / Share Provisioning

```
1. Coordinator opens DKG session with candidate signers
2. Each signer provides fresh attestation proof
3. Participants verify every signer's proof before DKG messages accepted
4. DKG executes; each signer finalizes local secret share
5. Share state sealed locally + bound to policy state version
6. Session artifact logged with signer measurements + policy version root
```

Critical rule: **never transmit plaintext share material to non-attested destination.**

---

## Flow C: Signing Request

```
1. Client sends request (tx digest + policy context + nonce)
2. Coordinator selects signer subset (>= threshold)
3. For each signer:
   a) fetch fresh attestation proof
   b) verify policy state monotonicity
   c) run local policy checks
4. Eligible signers produce partial signatures inside enclave
5. Coordinator aggregates partial signatures
6. Client verifies:
   - aggregate signature validity
   - signer attestation verdict IDs
   - policy decision evidence
7. Final decision: accept / reject
```

---

## Attestation Verification Contract

Attestation is a **hard precondition** for sensitive actions.

Minimum checks per signer:

1. **Certificate chain validity**
2. **Attestation signature validity**
3. **Measurement allowlist match**
4. **Nonce match (freshness)**
5. **Timestamp within max age window**
6. **Expected signer identity binding** (instance identity / key binding)
7. **Revocation status clean**

Nitro-specific minimum:
- verify relevant PCR set (`PCR0`, `PCR1`, `PCR2`) not only `PCR0`

Pseudo-policy:

```python
def allow_signer(att_doc, expected, nonce, now):
    verify_cert_chain(att_doc)
    verify_signature(att_doc)
    require(att_doc.nonce == nonce)
    require(now - att_doc.timestamp <= expected.max_age)
    require(att_doc.pcr0 in expected.allowed_pcr0)
    require(att_doc.pcr1 in expected.allowed_pcr1)
    require(att_doc.pcr2 in expected.allowed_pcr2)
    require(not is_revoked(att_doc))
    return True
```

If `False`: signer excluded from session and incident event emitted.

---

## Policy Engine Placement

Policy decisions happen **inside signer enclave**, not in coordinator.

Why:
- prevents compromised coordinator from bypassing policy
- attestation can prove which policy binary/measurement made the decision

Policy examples:
- destination allowlist
- velocity/window limits
- approval quorum thresholds
- signing schedule restrictions

---

## Rollback-Resistant Policy State Model

Sealing alone encrypts state, but does not prove freshness.

Use a monotonic state record:

```
PolicyStateRecord {
  policy_version: uint64,        # monotonically increasing
  state_root: bytes32,           # hash of policy data + counters
  prev_state_root: bytes32,      # chain linkage
  epoch_time: uint64,
  signer_quorum_sig: bytes,      # quorum approval over new root
}
```

Enclave must verify on load:
1. quorum signature valid
2. `policy_version` > local last accepted version
3. `prev_state_root` matches expected chain head

On mismatch:
- fail closed (deny signing)
- raise rollback alert
- require operator recovery workflow

---

## State Update Protocol (Fail-Safe)

```
1. Proposed policy update created
2. Threshold admin approval collected (M-of-N)
3. New state_root computed and signed
4. Monotonic service commits new version atomically
5. Signer enclaves fetch + verify new record
6. Enclave accepts update only if version strictly increases
7. Audit log stores update evidence bundle
```

No strict increase -> reject update.

---

## Asset -> Threat -> Defense Mapping

| Asset | Threat | Defense | Layer |
|---|---|---|---|
| Key shares | Host root memory dump | Enclave memory isolation + in-enclave signing only | Hardware/Code |
| Signer identity | Fake enclave impersonation | Attestation chain + measurement allowlist + nonce freshness | Protocol |
| Signing authorization | Coordinator policy bypass | In-enclave policy evaluation + attested policy binary | Code/Protocol |
| Policy state | Rollback replay | Monotonic versioning + quorum-signed state root | Application |
| Signature session integrity | Replay of old session artifacts | Session nonce + request binding + TTL checks | Protocol |
| System availability | Signer outage/DoS | Threshold redundancy and signer rotation | Architecture |

---

## Side-Channel and Hardening Requirements

1. Keep enclave TCB minimal (only critical signing + policy logic)
2. Use constant-time crypto primitives where applicable
3. Avoid secret-dependent branching/memory access in critical paths
4. Pin and audit cryptographic dependencies
5. Enforce microcode/TEE patch baseline before signer admission

Residual risk remains; document it explicitly in whitepaper.

---

## Failure Modes and Incident Procedures

## Scenario 1: Attestation Mismatch
- Action: quarantine signer immediately
- Impact: signer removed from active quorum pool
- Recovery: redeploy approved enclave image and re-attest

## Scenario 2: Rollback Detection
- Action: fail closed for signing decisions on affected signer(s)
- Impact: temporary reduction in available signers
- Recovery: reconstruct canonical state from monotonic service + signed history

## Scenario 3: Suspected Signer Host Compromise
- Action: revoke signer identity, rotate signer set, re-run DKG/reshare workflow
- Impact: temporary operational degradation
- Recovery: post-incident forensic review + hardening

## Scenario 4: Attestation Root/TCB Recovery Event
- Action: pause signing lanes dependent on affected trust chain
- Impact: controlled service interruption
- Recovery: patched rollout + new measurement allowlist + staged re-enable

---

## Versioned Measurement Policy

Use explicit measurement policy document:

```
AttestationPolicy {
  policy_id: "signer-prod-v3",
  allowed_pcr0: [ ... ],
  allowed_pcr1: [ ... ],
  allowed_pcr2: [ ... ],
  min_tcb_level: "...",
  max_attestation_age_sec: 60,
  created_at: ...,
  expires_at: ...,
}
```

Rules:
- no wildcard "allow all measurements"
- time-bound policy expiration
- emergency revoke path for compromised builds

---

## Logging and Audit Evidence

Each signing decision should produce an evidence bundle:

1. Request ID / transaction digest
2. Selected signer IDs
3. Attestation verdict IDs + measurement hashes
4. Policy version + state_root
5. Per-signer decision (allow/deny with reason code)
6. Aggregate signature metadata

This makes post-mortem and auditor review tractable.

---

## v1 Technology Decision (Recommended)

For this project's v1 reference architecture:

- **TEE choice:** AWS Nitro Enclaves
- **Language target:** Go service integration + Rust where memory safety is critical
- **Rationale:** easier deployment path, strong isolation model, practical operational envelope

Tradeoff:
- larger trust assumption in cloud provider vs pure silicon-centric models

---

## What This Architecture Still Does Not Solve

1. Complete prevention of advanced microarchitectural leakage
2. Malicious hardware root/supply-chain compromise
3. Global outages affecting attestation dependencies
4. Organization-level key misuse by colluding threshold participants

Those require additional organizational and multi-vendor controls.

---

## Exercises

1. **Draw your own trust boundary diagram** for `3-of-5` signers and mark exactly where secrets can exist in plaintext.

2. **Write an attestation reject policy** with explicit reason codes (`CHAIN_INVALID`, `PCR_MISMATCH`, `NONCE_STALE`, `TCB_REVOKED`).

3. **Design a rollback test case** where attacker restores stale sealed data and show how monotonic verification fails closed.

4. **Incident drill:** one signer is quarantined during high-volume period. Explain how threshold and coordinator should rebalance safely.

5. **Architecture defense:** in 8-10 sentences, defend why coordinator remains untrusted and why this is stronger than centralized policy enforcement.

---

## Resources

- AWS Nitro Enclaves attestation documentation
- FROST paper (protocol assumptions and signing flow)
- Teechain and Ekiden/Oasis papers (state continuity and trust decomposition)
- SGX/Nitro threat analyses from Day 3 materials

---

## Summary

```
Day 5 Architecture Core:
├── Untrusted coordinator orchestrates only
├── Attested enclaves hold and use key shares
├── Attestation is mandatory for sensitive actions
├── Policy runs inside enclave with measurable identity
├── Monotonic state prevents rollback acceptance
└── Threshold redundancy preserves safety under failures
```

If you can explain this architecture clearly, you are now thinking like a custody security engineer, not just an implementer.
