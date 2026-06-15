# Day 1: TEE Fundamentals

## What is a Trusted Execution Environment?

A TEE is a hardware-enforced isolated execution environment that protects code and data from:
- The operating system
- The hypervisor
- Other applications
- Physical access (to some extent)

The core idea: even if an attacker has root access to the machine, they cannot read or tamper with what's inside the TEE.

---

## Key Concepts

### 1. Trusted Computing Base (TCB)

The TCB is the set of components you must trust for security to hold.

**Traditional server:**
- CPU, firmware, BIOS, bootloader, OS kernel, hypervisor, all drivers, all services...
- TCB is massive — any compromise breaks security

**With TEE:**
- CPU + enclave code only
- TCB is minimal — OS compromise doesn't break enclave security

### 2. Memory Encryption

TEEs encrypt memory contents with keys held inside the CPU.

```
┌─────────────────────────────────────┐
│              DRAM                    │
│  ┌─────────────────────────────┐    │
│  │  Encrypted enclave memory   │◄───┼── CPU decrypts on-the-fly
│  └─────────────────────────────┘    │
│  ┌─────────────────────────────┐    │
│  │  Normal memory (plaintext)  │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

Even a cold boot attack or memory dump reveals only ciphertext.

### 3. Isolation Boundary

Code inside the TEE cannot be inspected or modified by code outside.

```
┌────────────────────────────────────────────┐
│                  Host OS                    │
│  ┌──────────────────────────────────────┐  │
│  │            Application                │  │
│  │  ┌────────────────────────────────┐  │  │
│  │  │         ENCLAVE                 │  │  │
│  │  │  ┌────────────────────────┐    │  │  │
│  │  │  │  Secret keys           │    │  │  │
│  │  │  │  Signing logic         │    │  │  │
│  │  │  │  Policy enforcement    │    │  │  │
│  │  │  └────────────────────────┘    │  │  │
│  │  │                                 │  │  │
│  │  │  ◄── Hardware boundary ──►     │  │  │
│  │  └────────────────────────────────┘  │  │
│  └──────────────────────────────────────┘  │
└────────────────────────────────────────────┘
```

### 4. Attestation

Attestation proves to a remote party:
1. **What code** is running inside the enclave
2. **On what hardware** (genuine Intel/AMD/AWS)
3. **In what state** (freshly initialized, not tampered)

This is the killer feature for custody: before sending a key share, you verify the enclave is running the correct code.

---

## Major TEE Implementations

### Intel SGX (Software Guard Extensions)

**How it works:**
- Application-level enclaves
- Code compiled with SGX SDK
- Enclave loaded into protected memory region
- CPU enforces isolation

**Pros:**
- Fine-grained (per-function isolation)
- Strong attestation (Intel Attestation Service)
- Mature ecosystem

**Cons:**
- Limited enclave memory (128-256MB typical)
- Side-channel vulnerabilities (Spectre, Foreshadow, etc.)
- Requires specific Intel CPUs
- Intel can revoke attestation keys

**Use cases:**
- Signal's contact discovery
- Fortanix key management
- Oasis Network

### AWS Nitro Enclaves

**How it works:**
- Isolated virtual machine (not process-level)
- No persistent storage, no network
- Communicates with parent via vsock
- KMS integration for key management

**Pros:**
- Simple mental model (it's a VM)
- No side-channel attacks on parent
- Integrated with AWS KMS
- No special CPU required

**Cons:**
- AWS-only
- Coarser isolation (whole VM)
- Attestation tied to AWS

**Use cases:**
- Cryptocurrency custody
- Secret management
- Secure credential processing

### ARM TrustZone

**How it works:**
- Two "worlds": Secure and Normal
- Hardware switch between worlds
- Secure world runs trusted OS

**Pros:**
- Ubiquitous in mobile devices
- Low overhead
- Hardware-backed

**Cons:**
- Secure world is complex (full OS)
- Vendor-controlled
- Less suitable for cloud

**Use cases:**
- Mobile payment (Apple Pay, Google Pay)
- DRM
- Biometric storage

### AMD SEV (Secure Encrypted Virtualization)

**How it works:**
- Encrypts entire VM memory
- Different keys per VM
- Hypervisor cannot read VM memory

**Pros:**
- Protects VMs from hypervisor
- No code changes required
- Works with existing VMs

**Cons:**
- Coarse-grained (whole VM)
- Attestation still maturing
- SEV-SNP required for full protection

---

## Comparison Table

| Feature | Intel SGX | AWS Nitro | ARM TrustZone | AMD SEV |
|---------|-----------|-----------|---------------|---------|
| Isolation level | Process | VM | World | VM |
| Memory encryption | Yes | Yes | Partial | Yes |
| Attestation | Remote | AWS-based | Limited | Remote (SNP) |
| Side-channel risk | High | Low | Medium | Medium |
| Cloud availability | Azure, IBM | AWS only | Mobile | Azure, GCP |
| Code changes needed | Yes (SDK) | Yes (vsock) | Yes | No |

---

## Why TEE for Custody?

### The Problem

Traditional custody:
```
┌─────────────────────────────────┐
│         Server                   │
│  ┌─────────────────────────┐    │
│  │  Private Key (in RAM)   │◄───┼── Attacker with root can dump
│  └─────────────────────────┘    │
└─────────────────────────────────┘
```

### The Solution

TEE custody:
```
┌─────────────────────────────────┐
│         Server                   │
│  ┌─────────────────────────┐    │
│  │       ENCLAVE            │    │
│  │  ┌─────────────────┐    │    │
│  │  │  Private Key    │    │◄───┼── Root access cannot read
│  │  └─────────────────┘    │    │
│  └─────────────────────────┘    │
└─────────────────────────────────┘
```

Plus attestation:
```
Client                          Enclave
  │                                │
  │  1. Request attestation        │
  │ ──────────────────────────────►│
  │                                │
  │  2. Attestation report         │
  │     (signed by hardware)       │
  │ ◄──────────────────────────────│
  │                                │
  │  3. Verify report              │
  │     - Correct code hash?       │
  │     - Genuine hardware?        │
  │     - Fresh nonce?             │
  │                                │
  │  4. Send key share             │
  │ ──────────────────────────────►│
```

---

## Exercises

1. **Explain in your own words:** Why can't the OS read enclave memory even with root access?

2. **Compare:** What's the key difference between SGX (process-level) and Nitro (VM-level) isolation?

3. **Think about:** If you were building a custody system, which TEE would you choose and why?

4. **Research:** Find one real-world attack on Intel SGX. What was the vulnerability?

---

## Resources

### Primary Sources
- [Intel SGX Developer Guide](https://download.01.org/intel-sgx/sgx-linux/2.14/docs/)
- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [AMD SEV-SNP Whitepaper](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf)

### Academic Papers
- "Intel SGX Explained" (Costan & Devadas, 2016) — The definitive SGX reference
- "Foreshadow: Extracting the Keys to the Intel SGX Kingdom" (2018) — Major SGX attack

### Practical
- [Fortanix Rust SGX SDK](https://github.com/fortanix/rust-sgx)
- [Edgeless Systems EGo](https://github.com/edgelesssys/ego) — Go SDK for SGX
- [AWS Nitro Enclaves CLI](https://github.com/aws/aws-nitro-enclaves-cli)

---

## Summary

TEEs provide:
1. **Isolated execution** — Code runs in hardware-protected environment
2. **Memory encryption** — Data encrypted with CPU-held keys
3. **Attestation** — Remote verification of enclave code and state

For custody, this means:
- Keys stored where OS cannot reach
- Signing policy enforced by hardware
- Clients verify enclave before trusting it

Tomorrow: Deep-dive into attestation — how it works, verification chains, and what it actually proves.
