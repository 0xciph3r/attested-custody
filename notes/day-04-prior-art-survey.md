# Day 4: Prior Art Survey (Detailed)

## Why This Day Matters

If Day 1-3 taught you **what TEEs can do** and **where they fail**, Day 4 teaches you how serious teams have already tried to solve similar problems.

In security architecture, prior art is leverage:
- It shows what survives contact with production.
- It exposes common design mistakes early.
- It gives you language and patterns auditors already recognize.

Your goal today is not to copy any one system.  
Your goal is to extract reusable security patterns for **attested-custody**:

1. threshold signing safety
2. enclave isolation benefits
3. attestation-based trust establishment
4. rollback/state continuity protections
5. operational realism under incident conditions

---

## Evaluation Method (Use This for Every System)

For each project/vendor/research system, analyze these dimensions:

### 1) Security Boundary
- What exact component is trusted?
- What remains explicitly untrusted?
- Is the trust boundary easy to reason about under incident pressure?

### 2) Key Lifecycle
- Where are keys generated?
- Where are keys stored at rest?
- Where are signing operations executed?
- Can secrets appear in plaintext outside trusted memory?

### 3) Attestation Semantics
- Is attestation mandatory or optional?
- What measurements/claims are verified?
- How are upgrades/measurement rotations handled?
- Is freshness (nonce/timestamp) enforced?

### 4) State Integrity / Rollback
- Does the system guarantee monotonic state transitions?
- What happens after crash/restart/redeployment?
- Can an attacker replay stale sealed state?

### 5) Side-Channel and Runtime Hardening
- Does the design acknowledge microarchitectural leakage?
- Are there coding constraints (constant-time, memory-safe)?
- Are patching and TCB update processes defined?

### 6) Operational Viability
- Can teams actually run this in production?
- What are failure modes (revocation, outage, platform deprecation)?
- Is incident response model practical?

---

## System 1: Fortanix (SGX-first Confidential Computing)

## What It Represents

Fortanix is important as a real-world SGX-centered approach to confidential workloads and key management.  
From a custody perspective, it demonstrates how enclave-backed trust can be productized, audited, and operated over time.

## Conceptual Architecture (Simplified)

```
Client / Operator
      │
      │  request + identity
      ▼
Control Plane / Policy Layer
      │
      │  policy + attestation checks
      ▼
SGX Enclave Service
      │
      ├── key generation / key use
      ├── cryptographic operations
      └── sealed storage artifacts
```

## Trust Model

- **Trusted:** SGX hardware guarantees + enclave code identity (as measured)
- **Conditionally trusted:** vendor attestation roots and update processes
- **Untrusted:** host OS, most surrounding infrastructure, network path

## Security Strengths

1. **Explicit attestation-centric trust establishment**  
   Keys should only be provisioned to measured enclave code.

2. **Hardware-backed isolation for key material**  
   Root on host does not automatically imply plaintext key exposure.

3. **Clear enterprise security narrative**  
   Easier to explain to auditors than “custom crypto + ad hoc enclaves.”

## Security Weaknesses / Residual Risk

1. **SGX side-channel exposure remains a serious concern**  
   Isolation is not equivalent to side-channel immunity.

2. **Patch/revocation lifecycle complexity**  
   If TCB changes require revalidation, operational downtime and trust decisions get hard fast.

3. **Vendor and supply-chain trust still exists**  
   TEE reduces trust surface, but does not eliminate trust dependencies.

## Lessons for Attested-Custody

Borrow:
- strict attestation before secret material delivery
- explicit measurement policy management
- security controls that survive audit scrutiny

Avoid:
- assuming SGX alone solves all runtime attack classes
- treating enclave sealing as rollback protection by itself

---

## System 2: Anjuna (Abstraction + Operability for Confidential Workloads)

## What It Represents

Anjuna-style platforms emphasize developer/operator ergonomics: run existing workloads in TEEs with minimal invasive rewrites.

This matters because many strong security designs fail operationally when tooling is too painful.

## Conceptual Architecture (Simplified)

```
Developer Workload
      │
      │ package/deploy
      ▼
Confidential Runtime Layer
      │
      ├── workload isolation
      ├── policy application
      └── attestation integration
      ▼
Underlying TEE Platform
```

## Trust Model

- **Trusted:** confidentiality runtime policy correctness + TEE guarantees
- **Untrusted:** host operating system and generic infrastructure path
- **Key question:** does abstraction hide assumptions engineers must still understand?

## Security Strengths

1. **Usability focus**  
   Easier adoption means fewer “security bypasses for productivity.”

2. **Deployment discipline**  
   Repeatable deployment patterns reduce configuration drift.

3. **Potential for policy centralization**  
   Better consistency than hand-managed enclave rollouts.

## Security Weaknesses / Residual Risk

1. **Abstraction risk**  
   Teams may rely on platform defaults without understanding trust boundaries.

2. **Policy opacity risk**  
   If the attestation/measurement policy is not explicit, operators cannot reason about compromise scenarios.

3. **False confidence under complexity**  
   “Works with minimal changes” is not proof that critical logic is hardened for hostile runtimes.

## Lessons for Attested-Custody

Borrow:
- operational ergonomics (automated rollout, version controls, policy automation)
- strong release discipline around measured artifacts

Avoid:
- burying cryptographic trust assumptions inside opaque platform abstractions

---

## System 3: Ekiden / Oasis Lineage (Protocol + TEE Separation)

## What It Represents

This lineage is valuable because it separates:
- public consensus / coordination logic
- confidential execution in attested TEEs

That split is directly relevant to custody, where your coordinator can be untrusted while enclaves hold signing authority.

## Conceptual Architecture (Simplified)

```
Users / Clients
      │
      ▼
Consensus / Coordination Layer (untrusted for secrets)
      │
      │ routes tasks / records commitments
      ▼
Confidential Compute Layer (attested TEEs)
      │
      └── executes sensitive logic over private state
```

## Trust Model

- **Trusted:** attested enclave execution identity + protocol correctness assumptions
- **Untrusted:** external coordinator/consensus nodes for secret confidentiality
- **Critical:** protocol integrity must complement enclave integrity

## Security Strengths

1. **Clean trust decomposition**  
   Easier to reason about who can break what.

2. **Attested private execution model**  
   Supports confidentiality even when orchestration is hostile.

3. **Protocol-first thinking**  
   Encourages cryptographic guarantees beyond “trust enclave.”

## Security Weaknesses / Residual Risk

1. **State continuity complexity**  
   Confidential state evolution across epochs/upgrades is hard.

2. **Rollback and replay integration risk**  
   TEE sealing + protocol consensus can still desync without robust monotonic mechanisms.

3. **Operational and cryptographic complexity**  
   More moving parts means more ways to fail under pressure.

## Lessons for Attested-Custody

Borrow:
- explicit separation between untrusted coordinator and trusted signer enclave
- protocol checks as first-class controls (not post-hoc logging)

Avoid:
- relying on enclave identity without state continuity guarantees

---

## System 4: Teechain (Research on TEE-Protected Payment Channels)

## What It Represents

Teechain is a useful cautionary and educational case: it shows how TEEs can improve payment-channel safety, but also how state evolution and failure recovery dominate security complexity.

## Conceptual Architecture (Simplified)

```
Participants
   │
   │ off-chain channel operations
   ▼
TEE-protected channel logic/state
   │
   ├── state transitions
   ├── balance/accounting updates
   └── settlement safety guarantees
```

## Trust Model

- **Trusted:** enclave-enforced channel transition logic
- **Untrusted:** external infrastructure and potentially adversarial peers
- **Critical assumption:** state transition ordering is preserved safely

## Security Strengths

1. **State-transition centric security**  
   Security not reduced to “key secrecy only.”

2. **Asynchrony-aware design**  
   Acknowledges real distributed failure behavior.

3. **Protocol + TEE coupling**  
   Good precedent for layered defenses.

## Security Weaknesses / Residual Risk

1. **Rollback/desynchronization danger**  
   Stale state can break safety despite enclave protection.

2. **Operational complexity during failures**  
   Recovery logic can become attack surface.

3. **Practical deployment friction**  
   Research-grade assurances can be difficult to maintain in production environments.

## Lessons for Attested-Custody

Borrow:
- treating state continuity as a primary security property
- designing fail-safe behavior for crash/recovery paths

Avoid:
- assuming sealed local state alone is trustworthy after restart

---

## System 5: Fedimint (Federated Threshold Custody, Non-TEE Baseline)

## What It Represents

Fedimint is a useful baseline because it emphasizes federated trust and threshold safety rather than TEE trust as a core primitive.

For your project, this answers: **what does threshold alone already solve, and what remains?**

## Conceptual Architecture (Simplified)

```
Users
  │
  ▼
Federation of independent operators
  │
  ├── threshold approvals/signing logic
  ├── policy/governance assumptions
  └── distributed operational trust
```

## Trust Model

- **Trusted:** federation threshold assumptions (enough honest operators)
- **Untrusted:** single operator machine integrity in isolation
- **Not primary:** hardware attestation as trust root

## Security Strengths

1. **No single key-holder failure mode**  
   Threshold/federation reduces catastrophic single-node compromise risk.

2. **Social and organizational decentralization**  
   Security can survive one operator compromise.

3. **Production-oriented distributed trust posture**  
   Valuable baseline for real operations.

## Security Weaknesses / Residual Risk

1. **Runtime exposure of shares without TEE guarantees**  
   Host compromise remains meaningful where shares are handled.

2. **Operational security variance across operators**  
   Federation is only as strong as its weakest operational discipline.

3. **Attestation gap for runtime integrity claims**  
   Harder to prove code identity at execution time to external verifiers.

## Lessons for Attested-Custody

Borrow:
- federation and threshold resilience patterns
- operational fault-tolerance mindset

Add (your differentiator):
- attested enclaves to reduce key-share extraction risk under host compromise

---

## Cross-System Comparison: Security-Critical Dimensions

| Dimension | Fortanix | Anjuna | Ekiden/Oasis lineage | Teechain | Fedimint |
|---|---|---|---|---|---|
| Primary trust anchor | SGX + attestation chain | Platform runtime + TEE | Protocol + attested confidential compute | TEE + channel protocol | Federation threshold assumptions |
| Main value | Enclave-based key ops | Operable confidential deployment | Trust separation between coordination and private compute | State-aware TEE channel safety | Decentralized trust without single operator |
| Biggest residual risk | SGX side-channels / TCB events | Hidden assumptions in abstraction | Rollback + protocol integration complexity | State continuity under failure | Share/runtime exposure without TEE |
| Attestation centrality | High | Medium/High (depends on deployment model) | High | Medium | Low (baseline model) |
| Relevance to your design | Strong for key protection | Strong for operational model | Strong for trust decomposition | Strong for rollback handling | Strong as threshold baseline comparator |

---

## Attack Mapping: What Prior Art Teaches You to Defend Explicitly

| Threat | Prior-art lesson | Required control in attested-custody |
|---|---|---|
| Host root compromise | TEE isolation helps but is not complete | Enclave-only key use + strict attestation + side-channel-aware coding |
| Fake signer runtime | Attestation must be hard-gated | Verify chain, measurement allowlist, nonce freshness |
| Rollback of policy state | Sealed data alone is insufficient | External monotonicity proof (counter/quorum-signed state root/anchor) |
| Side-channel leakage | Known recurring issue in SGX-class systems | Constant-time critical paths, minimal TCB, patch governance |
| Upgrade misconfiguration | Measurement drift breaks trust silently | Versioned measurement policy with explicit rollout/rollback controls |
| Coordinator compromise | Protocol decomposition is viable | Keep coordinator untrusted; require enclave proof per sensitive action |

---

## Concrete Design Rules You Should Carry into Day 5

1. **No implicit trust in orchestration layer**  
   API/coordinator can schedule but never hold key authority.

2. **Attestation before every sensitive state transition**  
   Not just at boot. Enforce at:
   - signer enrollment
   - key share provisioning
   - signing session acceptance

3. **Monotonic policy state is mandatory**  
   Every policy decision must reference a verifiable monotonic version.

4. **Measurement policy must be versioned and explicit**  
   `allowed_measurements` with change-control and emergency revoke path.

5. **Incident mode must be designed before launch**  
   Define behavior for:
   - revoked/expired attestation chain
   - enclave measurement mismatch
   - failed monotonicity proof
   - signer enclave outage

---

## Day 5 Input Blueprint (What to Write Next)

Tomorrow’s architecture doc should include:

1. **Trust boundary diagram**  
   Show untrusted coordinator and trusted signer enclaves.

2. **Attestation verification contract**  
   Minimum checks and rejection semantics.

3. **State continuity mechanism**  
   Exact anti-rollback protocol and fail-safe behavior.

4. **Signing flow with gates**  
   Request intake → policy check → attestation check → partial signing → aggregation.

5. **Upgrade and incident procedures**  
   Measurement rotation and emergency revocation handling.

---

## Exercises (Detailed)

1. **Deep comparison (10-12 sentences):**  
   Compare Fortanix-style SGX trust to Fedimint-style federation trust.  
   Explain what each protects well, what each leaves exposed, and why combining threshold + attestation is stronger for custody.

2. **Threat-driven TEE choice:**  
   Choose SGX or Nitro for v1.  
   Justify with:
   - threat model assumptions
   - operational constraints
   - side-channel posture
   - incident response complexity

3. **Rollback protocol design:**  
   Define a concrete anti-rollback mechanism for policy state with:
   - state version format
   - write/update flow
   - verification on enclave restart
   - fail-safe behavior on mismatch

4. **Attestation policy specification:**  
   Write a strict “accept partial signature” policy containing:
   - required claims/measurements
   - freshness checks
   - certificate/chain requirements
   - version allowlist handling
   - rejection/audit semantics

5. **Failure-mode drill:**  
   Enclave attestation suddenly fails due to TCB recovery event.  
   Write a 6-step incident response procedure that maintains key safety and avoids unsafe signing.

---

## Suggested References for This Day

- Teechain paper (TEE-based payment channels)
- Ekiden paper (confidential smart-contract execution)
- Oasis confidentiality architecture materials
- Fortanix SGX/confidential computing technical docs
- Anjuna confidential workload architecture docs
- Fedimint architecture/design docs

(When writing external-facing reports, cite exact versions/dates because confidential computing stacks evolve quickly.)

---

## Summary

Day 4 insight:

```
No single mechanism is enough:
├── Threshold only      → still runtime/share exposure risk
├── TEE only            → still protocol/rollback/ops risks
├── Attestation only    → still state continuity + side-channel risks
└── Combined approach   → strongest path for custody
    (threshold + attested execution + monotonic policy state)
```

This is the bridge from learning to design.  
Tomorrow (Day 5), you convert these lessons into a concrete, defensible architecture.
