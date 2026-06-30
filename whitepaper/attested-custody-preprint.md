# Attested Custody: FROST Threshold Signing with TEE-backed Key Protection

**Author:** Chinonso Amadi (0xciph3r)  

**Affiliation:** Independent Security Researcher  

**Contact email:** amadijustice2@gmail.com 

**Date:** 2026-06-30

---

## Abstract

This paper presents Attested Custody, a practical architecture for digital asset custody that combines FROST threshold signatures, trusted execution environments (TEEs), and remote attestation. The design goal is to remove single points of key compromise while reducing runtime key-share exposure under host compromise. Existing custody designs typically rely on one of three models: single-HSM trust, software-only threshold signing, or enclave-protected single key material. We propose a layered design where key shares are generated and used inside attested enclaves, the coordinator is explicitly untrusted, and signing is gated by verified attestation evidence. We also address rollback attacks on policy state through monotonic state validation anchored outside enclave-local storage. We describe enrollment, distributed key generation, and signing flows; define required attestation checks; and map threats to controls across hardware, protocol, and application layers. The result is an implementable reference architecture suitable for high-assurance custody systems that need strong compromise resistance with operationally feasible deployment.

## 1. Introduction

Institutional digital asset custody requires two properties that are often in tension: strong key protection and operational practicality. In practice, many systems optimize one at the expense of the other:

1. **Single-HSM model:** strong hardware isolation but concentration of trust.
2. **Software threshold model:** stronger distribution of trust but broad runtime exposure.
3. **Single-key TEE model:** strong host-compromise resistance but still a single key-holder trust anchor.

Threshold cryptography, especially FROST, is attractive because it avoids a single signing key and supports efficient two-round signing. TEEs are attractive because they can protect sensitive execution even when host operating systems are compromised. Remote attestation provides cryptographic evidence about the identity and state of trusted runtime environments.

This work combines these three in one custody architecture and focuses on security boundaries and operational behavior under failure.

### 1.1 Contributions

This paper contributes:

1. A reference custody architecture that combines FROST threshold signing with attested TEE signers.
2. A strict trust model where coordinator and host plane remain untrusted.
3. An attestation-gated signing contract with concrete verification requirements.
4. A rollback-resistant policy-state model for fail-closed behavior on stale state replay.
5. A threat mapping and limitations analysis for production-oriented deployment.

## 2. Background

### 2.1 FROST threshold signatures

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is a threshold signature protocol where participants hold distributed shares and collaboratively produce a valid Schnorr signature once threshold participation is reached. Key properties for custody:

- No single private key holder.
- Efficient signing rounds.
- Flexible signer set selection (t-of-n).

### 2.2 Trusted Execution Environments

TEEs provide isolated execution and memory protection for sensitive code/data. In custody designs, the target property is that host root compromise does not imply direct key-share extraction. TEEs do not automatically solve:

- side-channel leakage,
- rollback/state replay,
- denial of service,
- bugs in trusted code.

### 2.3 Remote attestation

Remote attestation is the mechanism by which a verifier checks:

1. Runtime authenticity (hardware trust chain),
2. runtime integrity (measurements/PCRs),
3. freshness (nonce/timestamp),
4. revocation state.

In this architecture, attestation is not advisory; it is a hard gate for sensitive operations.

## 3. Threat model

### 3.1 Assets

Primary assets:

1. Signer key shares,
2. signing/policy logic identity,
3. monotonic policy state,
4. signing session integrity.

### 3.2 Adversaries

1. **External attacker:** network access, phishing, request tampering.
2. **Malicious insider:** host root and infrastructure access.
3. **Compromised operator node:** runtime control on signer host.
4. **Advanced actor:** supply-chain and hardware-level capabilities.

### 3.3 Security goals

1. Key-share confidentiality under host compromise.
2. Signing integrity bound to approved code identity.
3. Policy enforcement that cannot be bypassed by coordinator compromise.
4. Rollback detection for policy state.
5. Auditable signing decisions and evidence.

### 3.4 Out of scope

Out of scope for v1:

1. Complete immunity to all microarchitectural side channels.
2. Full defense against malicious hardware roots.
3. Perfect availability under broad infrastructure denial-of-service.

## 4. Architecture

### 4.1 High-level design

Attested Custody separates untrusted orchestration from trusted signing.

```text
Client -> API Gateway (untrusted) -> Coordinator (untrusted) -> Signer Enclaves (trusted)
                                           |                         ^
                                           v                         |
                                     Attestation Verifier -----------+
                                           |
                                           v
                                  Monotonic State Service
```

Key rule: compromise of API/coordinator must not be sufficient to extract shares or forge threshold signatures.

### 4.2 Components

1. **Client:** submits signing request and validates evidence.
2. **API Gateway:** authentication and request normalization only.
3. **Coordinator:** session orchestration, signer selection, result aggregation.
4. **Signer Enclave:** policy evaluation + partial signing in trusted execution.
5. **Attestation Verifier:** verifies chain/signature/measurements/freshness.
6. **Monotonic State Service:** external anti-rollback source of truth.
7. **Audit Pipeline:** append-only evidence records.

### 4.3 Trust boundaries

- **Trusted for key operations:** signer enclaves with approved measurements.
- **Explicitly untrusted:** coordinator, host OS, hypervisor/operator plane, storage/network path.
- **Conditionally trusted:** attestation roots and TEE vendor update channels.

### 4.4 Enrollment flow

1. Signer boots enclave image.
2. Verifier issues nonce challenge.
3. Signer returns attestation document.
4. Verifier checks trust chain, signature, measurements, freshness, revocation.
5. On success, signer is admitted to active set; otherwise quarantined.

### 4.5 DKG/share flow

1. Coordinator creates DKG session.
2. Each candidate signer must pass attestation for session.
3. DKG messages accepted only from attested participants.
4. Local share material is sealed and bound to policy-state version.
5. Session evidence (measurements, participants, policy root) is logged.

### 4.6 Signing flow

1. Client submits request with nonce and policy context.
2. Coordinator selects signer subset >= threshold.
3. Each signer:
   - passes attestation checks,
   - verifies monotonic policy state,
   - evaluates local policy,
   - generates partial signature in enclave.
4. Coordinator aggregates partial signatures.
5. Client verifies aggregate signature and evidence bundle.

## 5. Attestation contract

A signer is eligible only if all checks pass:

1. Certificate chain validation.
2. Attestation signature validation.
3. Measurement allowlist validation.
4. Nonce equality check.
5. Timestamp/age bound check.
6. Revocation/TCB policy check.

For Nitro-style flows, the verifier checks all required PCRs, not only image PCR.

```python
def allow_signer(att_doc, expected, nonce, now):
    verify_cert_chain(att_doc, expected.root_ca)
    verify_attestation_signature(att_doc)
    if att_doc.nonce != nonce:
        return False, "NONCE_MISMATCH"
    if now - att_doc.timestamp > expected.max_age:
        return False, "ATTESTATION_STALE"
    if att_doc.pcr0 not in expected.allowed_pcr0:
        return False, "PCR0_MISMATCH"
    if att_doc.pcr1 not in expected.allowed_pcr1:
        return False, "PCR1_MISMATCH"
    if att_doc.pcr2 not in expected.allowed_pcr2:
        return False, "PCR2_MISMATCH"
    if is_revoked(att_doc):
        return False, "TCB_REVOKED"
    return True, "OK"
```

## 6. Rollback-resistant policy state

### 6.1 Problem

Sealed local storage can protect confidentiality/integrity of local blobs but does not guarantee freshness. An attacker controlling storage can replay an older sealed state.

### 6.2 State record

```text
PolicyStateRecord {
  policy_version: uint64,
  state_root: bytes32,
  prev_state_root: bytes32,
  epoch_time: uint64,
  quorum_signature: bytes
}
```

### 6.3 Verification rule

Signer accepts state only if:

1. quorum signature is valid,
2. `policy_version` is strictly increasing,
3. `prev_state_root` matches known chain head.

On failure: fail closed and emit rollback event.

## 7. Implementation approach (v1)

### 7.1 Runtime and languages

- Initial TEE target: AWS Nitro Enclaves.
- Host/coordinator integration: Go.
- Memory-critical signing logic: Rust or constant-time audited libraries.

### 7.2 Communication

- Parent/enclave channel via vsock.
- Request IDs and session IDs for replay-safe correlation.
- Strict bounded TTL for attestation and signing sessions.

### 7.3 Evidence bundle

Each signing decision emits:

1. request hash,
2. selected signer IDs,
3. attestation verdict IDs,
4. measurement set hash,
5. policy version/state root,
6. per-signer decision codes,
7. aggregate signature metadata.

## 8. Security analysis

### 8.1 Asset -> threat -> defense mapping

| Asset | Threat | Defense | Layer |
|---|---|---|---|
| Key shares | Host memory scraping | In-enclave key use only | Hardware/Code |
| Signer identity | Fake signer runtime | Attestation chain + measurements + nonce | Protocol |
| Policy enforcement | Coordinator bypass | In-enclave policy checks | Code/Protocol |
| Policy state | Stale sealed replay | Monotonic state root verification | Application |
| Session integrity | Replay of prior artifacts | Session nonce + TTL + request binding | Protocol |
| Availability | Signer outage | Threshold redundancy and signer rotation | Architecture |

### 8.2 Comparison with alternatives

1. **Single HSM:** strong local hardware, but trust concentration and single failure domain.
2. **Software-only threshold:** distributed trust, but broader runtime exposure.
3. **TEE-only single key:** host-compromise resistance, but no threshold fault tolerance.

Attested Custody aims to combine the strengths:

- threshold fault tolerance,
- enclave-isolated key-share handling,
- externally verifiable runtime identity.

### 8.3 Residual risk

1. Side-channel attacks remain possible and require code/hardware controls.
2. TEE vendor trust and revocation events are operational risk factors.
3. Collusion at threshold level remains a governance and operational challenge.

## 9. Operational incident handling

### 9.1 Measurement mismatch

Action: quarantine signer, exclude from quorum, redeploy approved image, re-attest.

### 9.2 Rollback detection

Action: fail closed for affected signer, rebuild canonical state from signed monotonic source.

### 9.3 TCB recovery/revocation event

Action: pause affected signing lane, patch and re-enroll signers under updated policy allowlist.

## 10. Related work

Attested Custody builds on:

1. FROST threshold signature literature and implementations,
2. TEE deployment and attestation models in SGX/Nitro ecosystems,
3. prior work on confidential execution and state-continuity challenges.

Relevant categories include commercial confidential-compute key management systems, TEE-blockchain research platforms, and federated threshold custody models.

## 11. Limitations and future work

### 11.1 Limitations

1. No formal proof for the full composed system in current version.
2. Side-channel mitigation is hardening-based, not absolute.
3. Single-vendor TEE strategy in v1.
4. **State persistence assumptions:** Coordinator session state is intentionally ephemeral — sessions can be recreated on failure. However, critical policy state (enrolled signers, policy version) requires external durable storage (database, consensus cluster). Security does not depend on storage confidentiality; it depends on quorum-signed state records and monotonic version validation. An attacker with root access to storage can read policy records but cannot forge valid quorum signatures or roll back to earlier versions without detection. Implementers must ensure policy state survives coordinator restarts and enclave reboots.

### 11.2 Future work

1. Multi-TEE implementation (Nitro + SGX/SEV variants),
2. formal modeling of rollback and attestation session binding,
3. stronger automated evidence verification tooling,
4. integration with additional custody and Lightning workflows.

## 12. Conclusion

Custody systems need both distributed trust and runtime integrity evidence. Threshold cryptography alone does not prove trusted execution. TEEs alone do not eliminate key concentration. Attestation alone does not solve state continuity. Attested Custody combines these mechanisms into a practical architecture where key shares remain inside attested enclaves, policy decisions are verifiable, rollback attempts fail closed, and coordinator compromise does not directly imply key compromise. This provides a security-forward and implementable baseline for next-generation digital asset custody systems.

---

## References (selected)

1. Komlo, C., Goldberg, I. FROST: Flexible Round-Optimized Schnorr Threshold Signatures.
2. RFC 9591: The FROST Protocol for Two-Round Schnorr Threshold Signatures.
3. Costan, V., Devadas, S. Intel SGX Explained.
4. AWS Nitro Enclaves technical documentation.
5. Teechain and Ekiden/Oasis papers on TEE-enabled blockchain/confidential execution.
