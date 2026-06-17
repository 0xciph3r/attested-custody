# Day 2: Attestation Deep-dive

## What is Attestation?

Attestation is cryptographic proof that:
1. **Specific code** is running inside the enclave
2. **On genuine hardware** (not a simulator)
3. **In a known state** (freshly initialized, not tampered)

Without attestation, a TEE is just "trust me bro." With attestation, it's "verify, then trust."

---

## Why Attestation Matters for Custody

**The problem:** You want to send a key share to an enclave. How do you know:
- It's really running your signing code (not malware)?
- It's on real TEE hardware (not an emulator stealing keys)?
- It hasn't been compromised since boot?

**The solution:** Before sending secrets, demand an attestation report. Verify it cryptographically. Only then proceed.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTESTATION FLOW                              │
│                                                                  │
│  Client                         Enclave           Attestation    │
│    │                              │                Service       │
│    │  1. "Prove yourself"         │                   │          │
│    │     + nonce (freshness)      │                   │          │
│    │ ────────────────────────────►│                   │          │
│    │                              │                   │          │
│    │                              │  2. Generate      │          │
│    │                              │     report        │          │
│    │                              │ ─────────────────►│          │
│    │                              │                   │          │
│    │                              │  3. Signed        │          │
│    │                              │     attestation   │          │
│    │                              │ ◄─────────────────│          │
│    │                              │                   │          │
│    │  4. Attestation report       │                   │          │
│    │     (hardware-signed)        │                   │          │
│    │ ◄────────────────────────────│                   │          │
│    │                              │                   │          │
│    │  5. Verify:                  │                   │          │
│    │     - Signature valid?       │                   │          │
│    │     - Nonce matches?         │                   │          │
│    │     - Code hash expected?    │                   │          │
│    │     - Hardware genuine?      │                   │          │
│    │                              │                   │          │
│    │  6. If valid: send secrets   │                   │          │
│    │ ────────────────────────────►│                   │          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Attestation Components

### 1. Measurement (Code Hash)

Before an enclave runs, the CPU measures (hashes) everything loaded into it:
- Code binary
- Initial data
- Configuration

This produces a **measurement** — a cryptographic fingerprint of exactly what's running.

```
┌────────────────────────────────────────┐
│            ENCLAVE LOADING             │
│                                        │
│  Code.bin ─────┐                       │
│                │   ┌─────────────┐     │
│  Config ───────┼──►│   SHA-256   │────►│ MRENCLAVE
│                │   └─────────────┘     │ (measurement)
│  Init data ────┘                       │
│                                        │
└────────────────────────────────────────┘
```

**SGX terminology:**
- `MRENCLAVE` — Hash of enclave contents (code identity)
- `MRSIGNER` — Hash of signing key (developer identity)

**Nitro terminology:**
- `PCR0` — Hash of enclave image
- `PCR1` — Hash of Linux kernel
- `PCR2` — Hash of application

### 2. Nonce (Freshness)

A nonce prevents replay attacks:

```
Without nonce:
  Attacker captures valid attestation report
  Attacker replays it later (after compromising enclave)
  Client fooled into trusting compromised enclave

With nonce:
  Client sends random nonce with request
  Enclave includes nonce in signed report
  Client verifies nonce matches
  Old reports rejected (wrong nonce)
```

### 3. Hardware Root of Trust

The attestation signature chain terminates at hardware:

```
┌─────────────────────────────────────────────────────────────┐
│                 TRUST CHAIN                                  │
│                                                              │
│  ┌─────────────┐                                             │
│  │ Intel/AMD/  │  Root of Trust                              │
│  │ AWS Root CA │  (burned into silicon or HSM)               │
│  └──────┬──────┘                                             │
│         │ signs                                              │
│         ▼                                                    │
│  ┌─────────────┐                                             │
│  │ Platform    │  Intermediate cert                          │
│  │ Certificate │  (per-CPU or per-instance)                  │
│  └──────┬──────┘                                             │
│         │ signs                                              │
│         ▼                                                    │
│  ┌─────────────┐                                             │
│  │ Attestation │  The actual report                          │
│  │ Report      │  (code hash + nonce + timestamp)            │
│  └─────────────┘                                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Intel SGX Attestation Models

### EPID (Enhanced Privacy ID) — Legacy

**How it works:**
1. Enclave generates quote (attestation report)
2. Quote sent to Intel Attestation Service (IAS)
3. IAS verifies and signs
4. Client trusts IAS signature

```
Enclave ──► Quote ──► Intel IAS ──► Signed Report ──► Client
```

**Pros:**
- Privacy-preserving (EPID group signatures hide individual CPUs)
- Intel handles verification complexity

**Cons:**
- Requires internet access to Intel
- Intel is a single point of trust/failure
- Intel can see all attestation requests

### DCAP (Data Center Attestation Primitives) — Modern

**How it works:**
1. Platform collects Intel-signed certificates at setup time
2. Enclave generates quote locally
3. Verification done locally (no Intel round-trip)

```
Setup: Intel ──► Platform Certificates ──► Cache locally

Runtime: Enclave ──► Quote ──► Local Verification
```

**Pros:**
- No runtime dependency on Intel
- Lower latency
- Works air-gapped

**Cons:**
- More complex setup
- Must manage certificate freshness
- Intel still roots the trust chain

---

## AWS Nitro Attestation

Nitro attestation is simpler than SGX because AWS controls the whole stack.

### Attestation Document Structure

```json
{
  "module_id": "enclave-id",
  "timestamp": 1623456789,
  "digest": "SHA384",
  "pcrs": {
    "0": "base64-encoded-hash",  // Enclave image
    "1": "base64-encoded-hash",  // Kernel
    "2": "base64-encoded-hash",  // Application
    "3": "base64-encoded-hash",  // IAM role (optional)
    "4": "base64-encoded-hash",  // Instance ID (optional)
    "8": "base64-encoded-hash"   // Enclave certificate (optional)
  },
  "certificate": "base64-encoded-cert",
  "cabundle": ["intermediate-certs"],
  "public_key": "optional-enclave-public-key",
  "user_data": "optional-custom-data",
  "nonce": "client-provided-nonce"
}
```

### PCR (Platform Configuration Register) Values

| PCR | Contents | Use |
|-----|----------|-----|
| PCR0 | Enclave image hash | Verify correct code |
| PCR1 | Linux kernel hash | Verify boot chain |
| PCR2 | Application hash | Verify app identity |
| PCR3 | IAM role ARN hash | Verify AWS permissions |
| PCR4 | Instance ID hash | Verify specific machine |
| PCR8 | Signing cert hash | Verify who built it |

### Verification Flow

```python
# Pseudocode for Nitro attestation verification

def verify_attestation(attestation_doc, expected_pcrs, nonce):
    # 1. Parse COSE-signed document
    doc = parse_cose(attestation_doc)
    
    # 2. Verify certificate chain
    # Root: AWS Nitro Attestation Root CA
    verify_cert_chain(doc.certificate, doc.cabundle, AWS_ROOT_CA)
    
    # 3. Verify signature
    verify_signature(doc, doc.certificate.public_key)
    
    # 4. Check freshness
    if doc.nonce != nonce:
        raise ReplayAttack("Nonce mismatch")
    
    if doc.timestamp < now() - MAX_AGE:
        raise StaleAttestation("Too old")
    
    # 5. Verify measurements
    for pcr_index, expected_hash in expected_pcrs.items():
        if doc.pcrs[pcr_index] != expected_hash:
            raise CodeMismatch(f"PCR{pcr_index} mismatch")
    
    return True  # Attestation valid
```

---

## Attestation for FROST Custody

In our attested-custody design, attestation gates every sensitive operation:

### Key Share Distribution

```
┌──────────────────────────────────────────────────────────────────┐
│              KEY SHARE DISTRIBUTION WITH ATTESTATION              │
│                                                                   │
│  Key Ceremony                    Enclave                          │
│  Coordinator                        │                             │
│       │                             │                             │
│       │  1. Request attestation     │                             │
│       │     + nonce                 │                             │
│       │ ───────────────────────────►│                             │
│       │                             │                             │
│       │  2. Attestation doc         │                             │
│       │     (PCR0 = signer code)    │                             │
│       │ ◄───────────────────────────│                             │
│       │                             │                             │
│       │  3. Verify:                 │                             │
│       │     - PCR0 == expected?     │                             │
│       │     - Cert chain valid?     │                             │
│       │     - Nonce fresh?          │                             │
│       │                             │                             │
│       │  4. Encrypt key share       │                             │
│       │     to enclave public key   │                             │
│       │ ───────────────────────────►│                             │
│       │                             │                             │
│       │                   5. Decrypt & store                      │
│       │                      (sealed to enclave)                  │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Signing Requests

```
┌──────────────────────────────────────────────────────────────────┐
│                 SIGNING WITH PRE-ATTESTATION                      │
│                                                                   │
│  Client                          Enclave                          │
│    │                               │                              │
│    │  1. Sign request + nonce      │                              │
│    │ ─────────────────────────────►│                              │
│    │                               │                              │
│    │  2. Attestation + partial sig │                              │
│    │ ◄─────────────────────────────│                              │
│    │                               │                              │
│    │  3. Verify attestation        │                              │
│    │     (proves signing code      │                              │
│    │      is unmodified)           │                              │
│    │                               │                              │
│    │  4. Accept partial signature  │                              │
│    │     (aggregate with others)   │                              │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Trust Assumptions

Be explicit about what you're trusting:

### Intel SGX

| Component | Trust assumption |
|-----------|------------------|
| Intel CPU silicon | Not backdoored |
| Intel microcode | Not malicious |
| Intel root CA | Not compromised |
| DCAP certificate cache | Fresh and authentic |

### AWS Nitro

| Component | Trust assumption |
|-----------|------------------|
| AWS Nitro hardware | Not backdoored |
| AWS hypervisor | Not malicious |
| AWS Nitro Attestation CA | Not compromised |
| AWS itself | Not colluding against you |

### Your enclave code

| Component | Trust assumption |
|-----------|------------------|
| Your signing logic | No bugs |
| Your policy engine | Correctly implemented |
| Dependencies | No vulnerabilities |

---

## Common Pitfalls

### 1. Not checking all PCRs

```
BAD:  Only check PCR0 (enclave image)
GOOD: Check PCR0, PCR1, PCR2 (image + kernel + app)
```

If you only verify the enclave image, an attacker could modify the kernel.

### 2. Accepting stale attestations

```
BAD:  No timestamp check
GOOD: Reject attestations older than X seconds
```

An attacker might capture a valid attestation, compromise the enclave, then replay.

### 3. Hardcoding expected measurements

```
BAD:  if pcr0 == "abc123..."  // Hardcoded
GOOD: if pcr0 in allowed_versions  // Configurable
```

You need to update expected hashes when you deploy new code.

### 4. Trusting attestation without encryption

```
BAD:  Attestation valid → send key in plaintext
GOOD: Attestation valid → encrypt key to enclave's ephemeral pubkey
```

Attestation proves identity, not confidentiality. Still need encryption.

---

## Exercises

1. **Explain:** What is a replay attack on attestation, and how does a nonce prevent it?

2. **Compare:** What's the tradeoff between EPID (Intel online) and DCAP (local verification)?

3. **Design:** In our FROST custody system, when should attestation be required? (List at least 3 operations)

4. **Think about:** If AWS is compromised (malicious insider), what can they do despite Nitro attestation? What can't they do?

---

## Resources

### Intel SGX Attestation
- [Intel SGX DCAP Documentation](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/)
- [Remote Attestation in Intel SGX](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions/attestation-services.html)

### AWS Nitro Attestation
- [Nitro Enclaves Attestation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
- [AWS Nitro Attestation Document Format](https://docs.aws.amazon.com/enclaves/latest/user/attestation-document.html)
- [Cryptographic Attestation of Nitro Enclaves](https://github.com/aws/aws-nitro-enclaves-nsm-api)

### Papers
- "Formal Analysis of Intel SGX Remote Attestation" — Academic treatment
- "Understanding and Hardening Linux Containers" — Context on isolation

---

## Summary

Attestation is the linchpin of TEE security for custody:

```
Attestation proves:
├── CODE IDENTITY    → Correct signer binary (MRENCLAVE / PCR0)
├── HARDWARE GENUINE → Real TEE, not emulator (cert chain)
└── FRESHNESS        → Not a replay (nonce)

Trust chains:
├── SGX EPID   → Intel IAS online
├── SGX DCAP   → Local verification, cached certs
└── Nitro      → AWS CA, simple cert chain

For custody:
├── Attest before key distribution
├── Attest before signing (or bundle with response)
├── Verify ALL relevant PCRs
└── Encrypt secrets to enclave pubkey
```

Tomorrow: **Day 3 — TEE Threat Model** (side-channels, rollback attacks, what attestation doesn't protect against)
