# Day 4: Prior Art Survey

## Why This Day Matters

Strong security architecture is rarely invented from scratch.  
Today is about studying what already works (and what fails) so your attested-custody design is grounded in real systems, not theory only.

---

## Evaluation Framework (Use this for every project)

For each prior-art system, answer:

1. **Trust boundary** — what is trusted vs untrusted?
2. **Key model** — where are keys generated/stored/used?
3. **Attestation model** — how does a client verify runtime integrity?
4. **Rollback/State integrity** — how is stale state prevented?
5. **Side-channel posture** — what leakage risks remain?
6. **Operational tradeoffs** — how hard is it to run in production?

---

## 1) Fortanix (SGX-focused confidential computing)

### What it is
Commercial platform for running sensitive workloads with SGX enclaves (key management and confidential services).

### Security model
- Uses SGX enclave isolation for key material and sensitive logic.
- Attestation gates trust in enclave identity.

### What to learn
- **Good:** clear use of attestation to establish trust before key use.
- **Risk:** SGX side-channel exposure and operational complexity around SGX lifecycle/patching.

### Relevance to attested-custody
- Strong template for enclave-backed key custody.
- Must add stronger anti-rollback and side-channel hardening for signing workflows.

---

## 2) Anjuna (Confidential workloads at app/platform layer)

### What it is
Platform approach to running existing workloads inside TEEs with minimal app rewrites.

### Security model
- Emphasizes deployment/operator usability.
- Security depends on correct enclave policy and attestation enforcement.

### What to learn
- **Good:** developer ergonomics matter; secure systems fail if too hard to operate.
- **Risk:** abstraction layers can hide security assumptions from engineers.

### Relevance to attested-custody
- Borrow operational patterns (deployment, policy management, upgrades).
- Keep cryptographic trust assumptions explicit; do not hide them behind tooling.

---

## 3) Ekiden / Oasis lineage (TEE + blockchain execution)

### What it is
Academic-to-production lineage exploring confidential smart-contract execution with TEEs.

### Security model
- Separates consensus from confidential execution.
- Uses attested enclaves for private computation.

### What to learn
- **Good:** clean separation of concerns (consensus layer vs confidential compute).
- **Risk:** TEE integrity does not remove need for protocol-level safety and anti-rollback design.

### Relevance to attested-custody
- Coordinator can remain untrusted if enclave proofs + protocol checks are strict.
- Great model for combining cryptographic protocol guarantees with TEE guarantees.

---

## 4) Teechain (TEE-based payment-channel security)

### What it is
Research system using TEEs to secure payment channel operations.

### Security model
- TEEs protect critical state transitions in channel logic.
- Safety depends on state continuity and protocol discipline, not enclave isolation alone.

### What to learn
- **Good:** explicit handling of asynchronous behavior and failure modes.
- **Risk:** rollback/state desynchronization becomes a first-class attack vector.

### Relevance to attested-custody
- Treat policy state continuity as a cryptographic requirement.
- Enclave sealing is insufficient without external monotonicity/consensus anchor.

---

## 5) Fedimint (FROST threshold signing baseline, non-TEE)

### What it is
Production-oriented federation model using threshold cryptography (FROST-related approach in ecosystem context) without requiring TEE trust as a core primitive.

### Security model
- Security comes from threshold/federation assumptions.
- Key safety depends on distribution of trust among operators.

### What to learn
- **Good:** threshold design removes single key holder risk.
- **Risk:** software/runtime compromise risk remains if shares are handled outside hardened enclaves.

### Relevance to attested-custody
- This is your baseline comparison: **threshold only** vs **threshold + attested enclave**.
- Your value-add is reducing share-extraction risk under host compromise.

---

## Comparative Matrix (Condensed)

| System | Core Trust Anchor | Key Handling | Attestation Role | Main Weakness |
|---|---|---|---|---|
| Fortanix | SGX hardware + vendor chain | Enclave-protected | Required for enclave identity | SGX side-channels + ops complexity |
| Anjuna | TEE runtime + platform controls | App moved into enclave model | Policy/runtime validation | Hidden assumptions via abstraction |
| Ekiden/Oasis lineage | Protocol + TEE split model | Confidential execution state in TEE | TEE validity for private compute | Rollback/protocol integration complexity |
| Teechain | TEE state protection + protocol | Channel/security-critical state in TEE | Supports trusted state transitions | State continuity/rollback challenges |
| Fedimint | Federation/threshold assumptions | Distributed shares (non-TEE baseline) | Not central in baseline model | Runtime/share exposure outside TEE |

---

## What Attested-Custody Should Borrow

1. **From Fortanix:** strict attestation-gated key handling.
2. **From Anjuna:** operational simplicity and deployment discipline.
3. **From Ekiden/Oasis:** protocol/compute separation with explicit trust edges.
4. **From Teechain:** first-class rollback/state continuity defenses.
5. **From Fedimint:** robust threshold/federation patterns and fault tolerance.

---

## Design Decisions for Your Architecture (Day 5 Prep)

1. **Untrusted coordinator by design**  
   Coordinator orchestrates only; no key trust.

2. **Attestation required at each sensitive phase**  
   - signer onboarding (DKG/join)  
   - key-share delivery  
   - signing session

3. **State continuity must be externally verifiable**  
   Policy state versioning with monotonicity proof (counter or signed/anchored state root).

4. **Defense in depth for side channels**  
   Constant-time crypto paths, minimal enclave code, strict dependency review, hardware/TCB patch policy.

5. **Versioned measurement policy**  
   Accept-list of approved enclave measurements to support safe upgrades.

---

## Exercises

1. **Comparison:** In 5-7 sentences, explain the difference between Fedimint’s trust model and your target attested-custody trust model.

2. **Architecture choice:** Pick one TEE stack for v1 (SGX or Nitro) and justify with threat model + operational constraints.

3. **Anti-rollback design:** Propose one concrete monotonicity mechanism for policy state and explain how it fails safe.

4. **Attestation policy:** Define what must be verified before accepting a partial signature (minimum fields/checks).

---

## Summary

Day 4 is about extracting proven patterns:
- Threshold cryptography is necessary but not sufficient.
- TEE isolation is valuable but not sufficient.
- Attestation is required but not sufficient.

Secure custody emerges when all three are combined with explicit rollback and operational controls.

Tomorrow: **Day 5 — Architecture Design** (turn these lessons into your concrete system design).
