# Whitepaper Outline

## Title

**Attested Custody: FROST Threshold Signing with TEE-backed Key Protection**

## Abstract

~200 words summarizing:
- Problem: Current custody either trusts single HSM or has software-only threshold signing
- Solution: Combine FROST with TEE attestation
- Contribution: Architecture + reference implementation
- Result: Threshold signing where key shares never leave attested enclaves

## 1. Introduction

- Rise of institutional Bitcoin custody
- Limitations of current approaches
- Our contribution

## 2. Background

### 2.1 Threshold Signatures
- FROST protocol recap
- DKG, 2-round signing
- Why threshold > single key

### 2.2 Trusted Execution Environments
- SGX, Nitro, SEV overview
- Attestation model
- Threat model

### 2.3 Hardware Security Modules
- Traditional HSM approach
- PKCS#11 interface
- Limitations (single device, vendor trust)

## 3. Threat Model

### 3.1 Adversary Capabilities
- Compromised host OS
- Network MITM
- Colluding signers (< threshold)
- Physical access

### 3.2 Security Goals
- Key confidentiality
- Signing integrity
- Policy enforcement
- Auditability

### 3.3 Out of Scope
- Side-channel attacks (discuss mitigations)
- Supply chain attacks
- Nation-state adversaries

## 4. Architecture

### 4.1 System Overview
- Enclave per signer
- Attestation service
- Coordinator (untrusted)

### 4.2 Key Generation (DKG in Enclave)
- Each enclave generates key share
- Shares never leave enclave
- Public key aggregation

### 4.3 Signing Protocol
1. Request arrives at coordinator
2. Coordinator requests attestation from each enclave
3. Client verifies attestations
4. Signing proceeds inside enclaves
5. Partial signatures aggregated

### 4.4 Policy Enforcement
- Policy embedded in enclave code
- Code hash in attestation
- Changing policy = new enclave version

### 4.5 Key Sealing and Recovery
- Sealing keys to enclave identity
- Recovery from sealed state
- Handling enclave upgrades

## 5. Implementation

### 5.1 Reference Architecture
- AWS Nitro for initial implementation
- Go + vsock communication
- Integration with btc-custody

### 5.2 Attestation Verification
- PCR validation
- Nonce freshness
- Certificate chain verification

### 5.3 FROST Integration
- DKG inside enclave
- Signing session management
- Partial signature flow

## 6. Security Analysis

### 6.1 STRIDE Analysis
- Spoofing: Attestation prevents
- Tampering: Enclave isolation prevents
- Repudiation: Audit logs
- Information disclosure: Memory encryption
- Denial of service: Out of scope
- Elevation: Policy in enclave

### 6.2 Comparison with Alternatives
- Software-only FROST
- Single HSM
- MPC without TEE

## 7. Limitations and Future Work

### 7.1 Current Limitations
- TEE vendor trust
- Side-channel risks
- Attestation availability

### 7.2 Future Directions
- Multi-vendor TEE support
- Formal verification
- Integration with Lightning

## 8. Related Work

- Fortanix, Anjuna (commercial)
- Teechain, Ekiden (academic)
- Fedimint (FROST without TEE)

## 9. Conclusion

## References

---

## Figures Needed

1. System architecture diagram
2. Attestation flow sequence diagram
3. DKG in enclave diagram
4. Signing protocol sequence diagram
5. Threat model diagram
6. Comparison table (our approach vs alternatives)

## Target Length

~15-20 pages (academic format)
