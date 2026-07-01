# STRIDE Threat Model: Attested Custody System

**System**: Multi-party threshold signing coordinator with TEE-based signer enclaves  
**Threat Model Date**: 2026-07-01  
**Author**: 0xciph3r

---

## 1. System Overview

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ UNTRUSTED NETWORK                                           │
│  - Client requests (may be malicious)                       │
│  - Network in/out (may be intercepted)                      │
└─────────────────────────────────────────────────────────────┘
            │
            │ gRPC (TLS required)
            ▼
┌─────────────────────────────────────────────────────────────┐
│ UNTRUSTED COORDINATOR (Linux VM)                            │
│  - Session orchestration only                               │
│  - NO key material                                          │
│  - Durable policy state (file or SQLite)                    │
│  - gRPC API server                                          │
└─────────────────────────────────────────────────────────────┘
            │
            │ Attestation challenge/response
            ▼
┌─────────────────────────────────────────────────────────────┐
│ TRUSTED TEE ENCLAVE (AWS Nitro / Intel SGX)                 │
│  - Key share material (never leaves enclave)                │
│  - FROST threshold protocol                                 │
│  - Attestation generation (signed by hardware)              │
│  - PCR-based code integrity                                 │
└─────────────────────────────────────────────────────────────┘
```

### Key Assumptions

1. **PCRs (Platform Configuration Registers)** are trustworthy — hardware computes them from enclave code
2. **Attestation signatures** are trustworthy — signed by hardware root (Nitro/SGX CA)
3. **Hardware root CAs** are secure and properly managed
4. **Threshold quorum** (t-of-n) is correctly configured; no t-1 collusion possible
5. **FROST crypto** is correctly implemented (not in scope of this threat model)
6. **Nonce challenge** prevents replay and ensures freshness

---

## 2. STRIDE Analysis by Component

### 2.1 Spoofing Identity

**Threat 1.1**: Client spoofs another client's identity in gRPC request

- **Attack**: Attacker creates a request with a different `RequestID` claiming to be another entity
- **Impact**: Masquerade as legitimate client, start unauthorized signing sessions
- **Existing Mitigation**:
  - gRPC TLS (mutual auth required)
  - Request tracking via `RequestID`
- **Residual Risk**: **MEDIUM** (TLS alone doesn't authenticate clients; need mTLS or API key)
- **Recommendation**: Implement mTLS with client certificates or API key + signature

**Threat 1.2**: Attacker spoofs a signer enclave identity

- **Attack**: Malicious enclave claims to be enrolled signer "alice" and submits attestation
- **Impact**: Forge attestations for unauthorized signers, bypass policy checks
- **Existing Mitigation**:
  - PCR verification (code hash must match allowlist)
  - Attestation signature verification (Nitro/SGX CA validates)
  - Signer enrollment policy (only approved signers allowed)
- **Residual Risk**: **LOW** (PCRs + CA signatures + policy checks are layered)
- **Recommendation**: Log all PCR mismatches; alert on repeated failures from same enclave ID

**Threat 1.3**: Attacker spoofs the Coordinator identity to signers

- **Attack**: Rogue coordinator pretends to be the real coordinator, sends fake challenges to signers
- **Impact**: Trick signers into using wrong nonce, bypass freshness checks
- **Existing Mitigation**:
  - Nonce signed by coordinator's private key (if implemented)
  - Signers verify coordinator cert (if cert pinning implemented)
- **Residual Risk**: **MEDIUM** (not yet implemented)
- **Recommendation**: Sign nonces with coordinator key; signers verify signature + certificate chain

---

### 2.2 Tampering with Data

**Threat 2.1**: Attacker modifies session state in durable store (file or SQLite)

- **Attack**: Gain root access to coordinator VM, modify `state.json` or SQLite to change policy
- **Impact**: Lower threshold, add rogue signers, bypass monotonic version checks
- **Existing Mitigation**:
  - Quorum signatures validate state on load (threshold t-of-n must agree)
  - Monotonic version check (cannot rewind state)
  - Integrity key = `sha256(state_json)` used as chain-of-custody token
- **Residual Risk**: **LOW** (quorum + version check prevents casual tampering)
- **Caveat**: If attacker compromises **t signers**, they can create valid quorum signatures
- **Recommendation**: Persist state in append-only log (immutable beyond coordinator); sign each entry

**Threat 2.2**: Attacker modifies attestation document in flight (man-in-the-middle)

- **Attack**: Intercept attestation from signer to coordinator, swap PCRs or nonce
- **Impact**: Submit out-of-policy attestation, bypass verification
- **Existing Mitigation**:
  - Attestation signed by hardware (Nitro quote, SGX signature)
  - Signature verification rejects tampering
  - TLS encrypts wire (if configured)
- **Residual Risk**: **LOW** (hardware signature is cryptographic proof)
- **Recommendation**: Enforce TLS 1.3 with ciphersuite audit

**Threat 2.3**: Attacker modifies gRPC request payload (e.g., payload_hash)

- **Attack**: Modify `CreateSession` request to change which payload is being signed
- **Impact**: Create session for unintended payload, trick caller into signing wrong data
- **Existing Mitigation**:
  - gRPC TLS encrypts payload
  - Caller specifies payload_hash; coordinator echoes it back
  - Caller can verify matching
- **Residual Risk**: **MEDIUM** (relies on caller verification; no server-side integrity guarantee)
- **Recommendation**: Implement optional payload signature by client (client signs hash + nonce)

**Threat 2.4**: Attacker modifies audit log entries

- **Attack**: Gain root access, delete or alter audit events from log
- **Impact**: Cover tracks of unauthorized signing, violate non-repudiation
- **Existing Mitigation**:
  - Audit events are structured JSON with timestamps
  - Can be sent to external SIEM/log service (outside coordinator)
- **Residual Risk**: **MEDIUM** (if audit stays on coordinator, root can tamper)
- **Recommendation**: Ship audit logs to immutable external system (S3 with object lock, syslog-NG with signed forwarding)

---

### 2.3 Repudiation of Actions

**Threat 3.1**: Signer denies they approved a signature

- **Attack**: Signer claims "I never attested to this payload" after signing
- **Impact**: Dispute over whether signing was authorized
- **Existing Mitigation**:
  - Audit trail logs all attestations by signer ID + session ID + timestamp
  - Nonce in attestation ties to specific session (freshness proof)
  - Attestation signed by signer's enclave (non-repudiation by hardware)
- **Residual Risk**: **LOW** (hardware signature proves signer enclave participated)
- **Caveat**: Signer *can* claim their key was compromised, but that's a different threat
- **Recommendation**: Require signers to acknowledge signing in post-signature audit event

**Threat 3.2**: Coordinator denies it collected threshold attestations

- **Attack**: Coordinator claims "I never received attestation from alice", then signs anyway
- **Impact**: Violate threshold requirement, forge transaction without quorum
- **Existing Mitigation**:
  - Audit log records all received attestations (signer ID, timestamp, nonce, PCRs)
  - State transitions only advance if threshold met
  - Completed signature state is durable
- **Residual Risk**: **LOW** (audit log + state persistence provide evidence)
- **Recommendation**: Export signed audit checkpoints (merkle tree of events) for dispute resolution

---

### 2.4 Information Disclosure

**Threat 4.1**: Attacker reads key shares from memory on coordinator

- **Attack**: Gain root access to coordinator, dump memory, extract signer key shares
- **Impact**: Complete compromise — attacker can sign arbitrary transactions
- **Existing Mitigation**:
  - **Coordinator NEVER stores key material** — only session metadata + policy state
  - Key shares stay inside enclaves
  - Coordinator cannot see attestations (only verifies and stores PCR proofs)
- **Residual Risk**: **NEGLIGIBLE** (architectural guarantee: no keys on coordinator)

**Threat 4.2**: Attacker reads nonce material or challenge data

- **Attack**: Root access to coordinator, dump session data including nonces
- **Impact**: Reuse nonces, forge attestations offline
- **Existing Mitigation**:
  - Nonces are random 32-byte values, one-time use
  - Nonce is stored in session state; expiry destroys it
  - Verifier rejects repeated nonces (prevents replay)
- **Residual Risk**: **MEDIUM** (if all nonces in memory are exposed, attacker can replay old ones)
- **Recommendation**: Encrypt nonce storage at rest (e.g., derive key from coordinator's TPM)

**Threat 4.3**: Attacker reads policy state (signer allowlist, threshold)

- **Attack**: Root access to coordinator, read SQLite or JSON state file
- **Impact**: Learn threshold (t), number of signers (n), which signers are enrolled
- **Existing Mitigation**:
  - Policy state is durable but not encrypted (design choice for transparency)
  - Policy is considered semi-public (signers are known to clients)
- **Residual Risk**: **LOW** (policy is not cryptographic secret; signers are identifiable anyway)
- **Recommendation**: Document that policy is observable; consider file permissions (0600 for state file)

**Threat 4.4**: Attacker intercepts gRPC traffic (no TLS)

- **Attack**: MITM attack on unencrypted gRPC channel
- **Impact**: Read payload hashes, session IDs, nonces; modify requests
- **Existing Mitigation**:
  - Design assumes TLS is enabled (not enforced in code yet)
- **Residual Risk**: **HIGH** (if TLS not configured, all data is exposed)
- **Recommendation**: **Enforce TLS requirement in code** (reject plaintext; config error if TLS missing)

**Threat 4.5**: Attacker steals signer's enclave key pair

- **Attack**: Compromise enclave (e.g., side-channel attack on SGX, or Nitro breakout)
- **Impact**: Forge valid attestations, sign arbitrary transactions
- **Existing Mitigation**:
  - Enclave attestations are signed by hardware root (Nitro CA, SGX enclave key)
  - Attacker with stolen key could forge signatures
  - Not in scope (assumes enclave is secure)
- **Residual Risk**: **OUT OF SCOPE** (requires breach of hardware security)
- **Recommendation**: Enclave code audit + side-channel testing (e.g., SGX cache timing attacks)

---

### 2.5 Denial of Service

**Threat 5.1**: Attacker floods coordinator with CreateSession requests

- **Attack**: Send 1000 requests/sec, exhaust memory with session objects
- **Impact**: Legitimate sessions fail, signing halts
- **Existing Mitigation**:
  - Sessions expire after timeout (default 5 min)
  - Collision detection reuses sessions for identical payloads (saves resources)
- **Residual Risk**: **HIGH** (no rate limiting in code yet)
- **Recommendation**: 
  - Rate limit per client IP: max 10 sessions/min
  - Implement session queue (pending → active with priority)
  - Monitor memory usage

**Threat 5.2**: Attacker sends IssueChallenge requests to exhaust nonce generator

- **Attack**: For each session, call IssueChallenge repeatedly
- **Impact**: Slow nonce generation, delay signing
- **Existing Mitigation**:
  - One nonce per signer per session (issuing new nonce overwrites old)
  - Nonce generation is O(1)
- **Residual Risk**: **LOW** (nonce gen is cheap; rate limiting on CreateSession bounds impact)

**Threat 5.3**: Attacker sends malformed attestations (invalid CBOR, wrong signature)

- **Attack**: Send garbage attestation documents
- **Impact**: Parser crashes or hangs, coordinator hangs processing malformed data
- **Existing Mitigation**:
  - Parser has timeout in attestation parsing
  - VerifyRaw validates signature before accepting
  - Failed attestations are logged and rejected with error response
- **Residual Risk**: **MEDIUM** (if parser panics on malformed CBOR, coordinator crashes)
- **Recommendation**: 
  - Add fuzzing test for CBOR parser
  - Wrap parser in recover() to catch panics
  - Implement attestation size limit (e.g., max 10KB)

**Threat 5.4**: Attacker causes policy state reload to thrash disk/SQLite

- **Attack**: Issue SubmitAttestation repeatedly to trigger many state transitions
- **Impact**: Slow coordinator, high disk I/O
- **Existing Mitigation**:
  - State transitions only happen at session boundary (not per-request)
  - SQLite transactions are atomic
- **Residual Risk**: **LOW** (state changes are batched; not per-request)

**Threat 5.5**: Slow-client attack: send gRPC requests very slowly

- **Attack**: Open gRPC stream, send 1 byte/sec, hold connection open
- **Impact**: Exhaust connection pool, prevent legitimate clients
- **Existing Mitigation**:
  - gRPC connection timeout (default ~5 sec for idle)
  - Session timeout (5 min default)
- **Residual Risk**: **MEDIUM** (very slow attacks may bypass timeout)
- **Recommendation**: 
  - Set `http2.Settings.MaxConcurrentStreams` in gRPC config
  - Monitor connection count; alert on high numbers

---

### 2.6 Elevation of Privilege

**Threat 6.1**: Non-approved signer tries to participate in signing

- **Attack**: Attacker's enclave (with PCR mismatch or unknown identity) sends attestation
- **Impact**: Bypass policy, allow signing without quorum
- **Existing Mitigation**:
  - Policy validator rejects attestations with PCRs not in allowlist
  - Signer enrollment policy enforced
  - Threshold quorum required (cannot sign with fewer than t signers)
- **Residual Risk**: **LOW** (layered checks: PCR + enrollment + quorum)

**Threat 6.2**: Coordinator process running as non-root but gains root privileges

- **Attack**: Exploit Linux privilege escalation vulnerability (e.g., CVE-2024-XXXXX)
- **Impact**: Root access to coordinator, read/write all state and audit logs
- **Existing Mitigation**:
  - Coordinator runs as non-root user (by deployment recommendation)
  - Policy state file has restricted permissions (0600)
  - Audit logs sent to external service
- **Residual Risk**: **MEDIUM** (root exploit is possible; external audit helps)
- **Recommendation**:
  - Run coordinator in container with read-only FS (except for state dir)
  - Enable AppArmor or SELinux profile
  - Use seccomp to block dangerous syscalls

**Threat 6.3**: Attacker compromises t-of-n signers, then forges signatures

- **Attack**: Breach t signer enclaves (e.g., side-channel or remote exploit)
- **Impact**: Generate valid FROST signatures for unauthorized payloads
- **Existing Mitigation**:
  - Enclave security is outside coordinator's control
  - Audit trail shows which signers participated (forensic trace)
- **Residual Risk**: **OUT OF SCOPE** (requires enclave compromise)
- **Recommendation**: 
  - Enclave firmware updates (Nitro: AWS updates; SGX: Intel)
  - Side-channel testing during development
  - Key rotation protocol (signer loss recovery)

**Threat 6.4**: Attacker causes session to advance without collecting threshold attestations

- **Attack**: Modify session state to mark signers as "attested" when they are not
- **Impact**: Advance to signing phase without quorum, forge signature
- **Existing Mitigation**:
  - Session state is in-memory, not persisted (no opportunity to tamper)
  - State transitions checked: MaybeAdvanceSession verifies count before advancing
  - Audit log records state changes
- **Residual Risk**: **LOW** (in-memory state + explicit verification)

**Threat 6.5**: Attacker escalates from local coordinator user to key material

- **Attack**: Exploit TOCTOU (time-of-check-to-time-of-use) in attestation verification
- **Impact**: Change attestation or PCRs after verification passes
- **Existing Mitigation**:
  - Attestation is signed by hardware — verification covers integrity
  - PCRs are immutable (hardware computes them)
- **Residual Risk**: **NEGLIGIBLE** (cryptographic signatures prevent this)

---

## 3. Summary Matrix

| Threat ID | Category | Risk | Mitigation Status | Recommendation |
|-----------|----------|------|-------------------|-----------------|
| 1.1 | Spoofing | MEDIUM | Partial (TLS only) | Add mTLS or API key + signature |
| 1.2 | Spoofing | LOW | Strong (PCR + CA + policy) | Log/alert on PCR mismatches |
| 1.3 | Spoofing | MEDIUM | Not yet | Sign nonces; verify coordinator cert |
| 2.1 | Tampering | LOW | Strong (quorum + version) | Use append-only log |
| 2.2 | Tampering | LOW | Strong (hardware sig) | Enforce TLS 1.3 |
| 2.3 | Tampering | MEDIUM | Partial (TLS only) | Client payload signature |
| 2.4 | Tampering | MEDIUM | Partial (on coord) | Ship to immutable SIEM |
| 3.1 | Repudiation | LOW | Strong (hardware sig + audit) | Post-signature audit ack |
| 3.2 | Repudiation | LOW | Strong (audit + state) | Signed audit checkpoints |
| 4.1 | Disclosure | NEGLIGIBLE | Architectural (no keys) | N/A |
| 4.2 | Disclosure | MEDIUM | Partial (session expiry) | Encrypt nonce storage |
| 4.3 | Disclosure | LOW | Acceptable (semi-public) | File permissions (0600) |
| 4.4 | Disclosure | HIGH | Not enforced | **Enforce TLS in code** |
| 4.5 | Disclosure | OUT OF SCOPE | Enclave security | Side-channel testing |
| 5.1 | DoS | HIGH | Not yet | Rate limiting + queue |
| 5.2 | DoS | LOW | Acceptable | (Covered by 5.1) |
| 5.3 | DoS | MEDIUM | Partial (error handling) | Fuzzing + panic recovery |
| 5.4 | DoS | LOW | Acceptable | (State batched) |
| 5.5 | DoS | MEDIUM | Partial (timeout) | Connection pool limits |
| 6.1 | Elevation | LOW | Strong (layered checks) | (Acceptable) |
| 6.2 | Elevation | MEDIUM | Partial (non-root) | Container + AppArmor |
| 6.3 | Elevation | OUT OF SCOPE | Enclave security | Firmware + rotation |
| 6.4 | Elevation | LOW | Strong (in-mem + verify) | (Acceptable) |
| 6.5 | Elevation | NEGLIGIBLE | Cryptographic | (Acceptable) |

---

## 4. High-Priority Recommendations (Next Phase)

### Phase 2A: Security Controls (Immediate)

1. **TLS Enforcement** — Reject plaintext gRPC connections
2. **Rate Limiting** — Per-IP session creation limit (10 sessions/min)
3. **Nonce Encryption** — Encrypt nonce storage at rest
4. **Audit Log Forwarding** — Ship logs to external SIEM/S3

### Phase 2B: Hardening (Week 2)

5. **mTLS + Client Certificates** — Verify caller identity
6. **Coordinator Nonce Signing** — Sign challenges with coordinator key
7. **Fuzzing** — Test CBOR parser + gRPC handlers with malformed input
8. **Connection Pool Limits** — Limit max concurrent streams
9. **Container Hardening** — SELinux profile, read-only FS, seccomp

---

## 5. Conclusion

The attested custody system achieves **defense in depth** through layered validation:
- **Spoofing**: Mitigated by hardware signatures + policy checks
- **Tampering**: Mitigated by quorum signatures + monotonic version control
- **Repudiation**: Mitigated by non-repudiation through attestation + audit trail
- **Disclosure**: Mitigated by architectural guarantee (keys in enclaves, not coordinator)
- **DoS**: Partially mitigated; rate limiting + input validation needed
- **Elevation**: Mitigated by strict policy validation + quorum requirement

**Residual risks are primarily in deployment and DoS vectors**, not in the core security model. Implementing the Phase 2A recommendations will reduce residual risk from HIGH to LOW across all categories.
