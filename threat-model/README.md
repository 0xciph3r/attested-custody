# Attested Custody: STRIDE Threat Model & Security Analysis

## Overview

This directory contains comprehensive STRIDE threat modeling for the attested custody system—a multi-party threshold signing architecture combining FROST cryptography with TEE-based enclaves (AWS Nitro / Intel SGX).

**Core principle**: Security comes from **attestation** (hardware-signed proofs of enclave identity) + **threshold cryptography** (t-of-n quorum), not from trusting the coordinator.

---

## Documents

### 1. Technical Threat Model (`threat-model/STRIDE.md`)

**Audience**: Security engineers, architects  
**Length**: ~19KB  
**Purpose**: Complete reference document with detailed attack vectors, mitigations, and recommendations

**Includes**:
- System architecture and trust boundaries
- Full STRIDE analysis (6 categories × 3-5 threats each)
- Risk matrix with 25 threat scenarios
- High-priority recommendations (Phase 2A/2B)

**Key findings**:
- **5 HIGH-risk items** (plaintext gRPC, DoS, parser robustness)
- **9 MEDIUM-risk items** (client/coordinator spoofing, nonce reuse, privilege escalation)
- **12 LOW-risk items** (signer spoofing, state tampering, repudiation)

---

### 2. Public Article (`articles/STRIDE-threat-model.md`)

**Audience**: Security practitioners, developers, decision-makers  
**Length**: ~14KB  
**Purpose**: Accessible security analysis with design principles and lessons

**Includes**:
- Executive summary of threat categories
- Deep-dive into each STRIDE category with examples
- Risk matrix (simplified)
- Priority recommendations
- Design principles for custody systems
- Lessons learned

**Best for**: Blog posts, conference talks, onboarding new team members

---

## Threat Summary

| Category | Threats | Residual Risk | Status |
|----------|---------|---------------|--------|
| **Spoofing** | Client/signer/coordinator identity | LOW-MEDIUM | Partial (add mTLS) |
| **Tampering** | State/attestation/audit logs | LOW-MEDIUM | Strong (quorum + crypto) |
| **Repudiation** | Signer/coordinator denial | LOW | Strong (audit + hardware sig) |
| **Disclosure** | Key reads / nonce reuse / plaintext | NEGLIGIBLE-HIGH | Mixed (TLS enforcement needed) |
| **DoS** | Session flood / parser crash / slow clients | MEDIUM-HIGH | Weak (rate limiting needed) |
| **Elevation** | Unauthorized signers / root compromise | LOW-MEDIUM | Partial (container hardening needed) |

---

## High-Priority Actions

### Immediate (Phase 2A)
- [ ] **Enforce TLS** — Reject plaintext gRPC connections (blocks threat 4.4)
- [ ] **Rate Limiting** — 10 sessions/min per IP (blocks threat 5.1)
- [ ] **Nonce Encryption** — Encrypt session state at rest (blocks threat 4.2)
- [ ] **Audit Forwarding** — Ship logs to S3/SIEM (blocks threat 2.4)

### Week 2 (Phase 2B)
- [ ] **mTLS** — Client certificate authentication (blocks threat 1.1)
- [ ] **Nonce Signing** — Coordinator signs challenges (blocks threat 1.3)
- [ ] **Parser Fuzzing** — Test CBOR parser robustness (blocks threat 5.3)
- [ ] **Connection Limits** — HTTP/2 stream limits (blocks threat 5.5)
- [ ] **Container Hardening** — Read-only FS, AppArmor, seccomp (blocks threat 6.2)

---

## Design Principles (Why This Works)

1. **Zero-Trust Coordinator**  
   Assume coordinator is compromised; security comes from attestation + crypto, not coordinator trust.

2. **Hardware-Backed Proofs**  
   PCRs (code integrity) + attestation signatures (identity) cannot be forged without hardware breach.

3. **Quorum Validation**  
   t-of-n threshold means attacker must compromise t signers to forge valid state transitions.

4. **Monotonic Versioning**  
   State is versioned and immutable; cannot downgrade even with disk access.

5. **Nonce Freshness**  
   Each attestation tied to unique session; prevents replay and enables session-level deduplication.

6. **Defense in Depth**  
   Multiple independent checks at each boundary (PCR + CA + policy + quorum + version).

---

## Mitigations by Threat ID

| Threat | Category | Current Status | Fix | Priority |
|--------|----------|---|---|---|
| 1.1 | Spoofing (client) | TLS only | mTLS + API key | HIGH |
| 1.2 | Spoofing (signer) | PCR + CA + policy | Alert on PCR mismatch | MEDIUM |
| 1.3 | Spoofing (coordinator) | Not yet | Sign nonces | HIGH |
| 2.1 | Tampering (state) | Quorum + version | Append-only log | MEDIUM |
| 2.2 | Tampering (attestation) | Hardware sig | Enforce TLS 1.3 | LOW |
| 2.3 | Tampering (request) | TLS only | Client payload sig | MEDIUM |
| 2.4 | Tampering (audit) | On-disk | Immutable SIEM | HIGH |
| 3.1 | Repudiation (signer) | Audit + hardware | Post-sig ack | LOW |
| 3.2 | Repudiation (coordinator) | Audit + state | Signed checkpoints | LOW |
| 4.1 | Disclosure (keys) | Architectural | None (by design) | N/A |
| 4.2 | Disclosure (nonces) | One-time use | TPM encryption | MEDIUM |
| 4.3 | Disclosure (policy) | File perms | Document observability | LOW |
| 4.4 | Disclosure (plaintext) | Not enforced | **Enforce TLS** | **CRITICAL** |
| 4.5 | Disclosure (enclave keys) | Out of scope | Side-channel testing | N/A |
| 5.1 | DoS (session flood) | No rate limit | IP-based rate limit | **CRITICAL** |
| 5.2 | DoS (nonce exhaust) | Cheap generation | Covered by 5.1 | LOW |
| 5.3 | DoS (parser crash) | Partial error handling | Fuzz + panic recovery | HIGH |
| 5.4 | DoS (state thrash) | Batched updates | Acceptable | LOW |
| 5.5 | DoS (slow client) | Timeout | Connection limits | MEDIUM |
| 6.1 | Elevation (unauthorized signer) | PCR + policy + quorum | Acceptable | LOW |
| 6.2 | Elevation (root compromise) | Non-root + external audit | Container hardening | HIGH |
| 6.3 | Elevation (signer compromise) | Out of scope | Firmware + rotation | N/A |
| 6.4 | Elevation (state advance) | In-memory + verify | Acceptable | LOW |
| 6.5 | Elevation (TOCTOU) | Cryptographic guarantee | Acceptable | N/A |

---

## Key Insight: Why Keys Are Safe

**Threat 4.1 (key disclosure)** is **NEGLIGIBLE** because:
1. **Architectural guarantee**: Coordinator never sees key material
2. Keys are generated and stored **inside enclaves**
3. Enclaves are **isolated from OS** (hardware-enforced boundary)
4. Coordinator only sees **PCR hashes and attestations**, not keys
5. Even if coordinator is pwned (root access), **keys stay in enclave**

This is the critical difference from traditional hot wallets or coordinators that hold keys.

---

## Next Steps

1. **Read the full threat model** (`threat-model/STRIDE.md`) for implementation details
2. **Implement Phase 2A** fixes (TLS, rate limiting, nonce encryption, audit forwarding)
3. **Create security runbook** (incident response for enclave compromise)
4. **Add fuzzing tests** for CBOR parser and gRPC handlers
5. **Container hardening** (AppArmor profile, seccomp filter)

---

## References

- [STRIDE Threat Model](https://en.wikipedia.org/wiki/STRIDE_%28security%29) — Microsoft's six categories
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Model_Info)
- [Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)
- Attested custody whitepaper: `../whitepaper/attested-custody-preprint.md`
- Reference implementation: `../reference-impl/`
