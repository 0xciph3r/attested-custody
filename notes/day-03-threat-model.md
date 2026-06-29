# Day 3: TEE Threat Model

## Why Threat Models Matter

A TEE is not magic. It protects against specific threats and is vulnerable to others. If you don't understand the boundaries, you'll either:
- Over-trust it (and get exploited)
- Under-trust it (and not use it when you should)

For custody, precision matters. You need to articulate exactly what attacks your system blocks and which ones require additional mitigations.

---

## The TEE Security Boundary

```
┌─────────────────────────────────────────────────────────────────┐
│                    OUTSIDE TEE (UNTRUSTED)                       │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │     OS      │  │ Hypervisor  │  │   Other     │              │
│  │   (root)    │  │             │  │   Apps      │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                                                                  │
│  ════════════════════════════════════════════════════════════   │
│                    HARDWARE BOUNDARY                             │
│  ════════════════════════════════════════════════════════════   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                 INSIDE TEE (TRUSTED)                     │    │
│  │                                                          │    │
│  │   ┌──────────────┐  ┌──────────────┐                    │    │
│  │   │  Your Code   │  │  Your Data   │                    │    │
│  │   │  (signing)   │  │  (key share) │                    │    │
│  │   └──────────────┘  └──────────────┘                    │    │
│  │                                                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**The promise:** Code and data inside the TEE are protected from everything outside the hardware boundary.

**The reality:** Several attack classes can cross this boundary or work around it.

---

## What TEEs Protect Against

### 1. Privileged Software Attacks
**Threat:** Malicious OS or hypervisor trying to read enclave memory.

**Protection:** Hardware blocks all non-enclave access to protected memory regions.

```
Malicious OS                    Enclave Memory
    │                               │
    │  read(0x7fff0000)             │
    │ ─────────────────────────────►│
    │                               │
    │  ◄─── CPU returns 0xFF ───    │
    │       (abort, dummy value)    │
```

### 2. Physical Memory Attacks
**Threat:** Cold boot attack, memory bus probing, DMA attacks.

**Protection:** Memory Encryption Engine (MEE) encrypts all data leaving the CPU.

```
┌────────────────┐         ┌─────────────────────┐
│     CPU        │         │       DRAM          │
│  ┌──────────┐  │         │                     │
│  │ Plaintext│  │ encrypt │  ┌───────────────┐  │
│  │   Data   │──┼────────►│  │  Ciphertext   │  │
│  └──────────┘  │         │  └───────────────┘  │
│                │         │                     │
└────────────────┘         └─────────────────────┘
```

### 3. Software Tampering
**Threat:** Attacker modifies enclave code to exfiltrate secrets.

**Protection:** Measurement (hash) of loaded code is included in attestation. Any modification changes the hash.

### 4. Remote Impersonation
**Threat:** Attacker runs fake enclave to harvest secrets.

**Protection:** Attestation proves genuine hardware + correct code before secrets are sent.

---

## What TEEs DON'T Protect Against

This is where it gets interesting for security engineers.

### 1. Side-Channel Attacks

Side channels leak information through observable system behavior, not direct memory access.

#### A. Cache Timing Attacks

**How it works:**
1. Attacker fills CPU cache with known data
2. Enclave runs and evicts some cache lines
3. Attacker measures which lines were evicted
4. Eviction pattern reveals memory access pattern
5. Memory access pattern reveals secrets (e.g., which branch was taken)

```
┌─────────────────────────────────────────────────────────────┐
│                    PRIME + PROBE                             │
│                                                              │
│  Attacker              CPU Cache              Enclave        │
│     │                     │                      │           │
│     │  1. Fill cache      │                      │           │
│     │ ──────────────────► │                      │           │
│     │                     │                      │           │
│     │                     │  2. Enclave runs     │           │
│     │                     │ ◄────────────────────│           │
│     │                     │     (evicts lines)   │           │
│     │                     │                      │           │
│     │  3. Measure timing  │                      │           │
│     │ ◄────────────────── │                      │           │
│     │     (slow = evicted)│                      │           │
│     │                     │                      │           │
│     │  4. Deduce secret   │                      │           │
│     │     access pattern  │                      │           │
└─────────────────────────────────────────────────────────────┘
```

**Example attack:** If your signing code has `if (secret_bit) { access(A); } else { access(B); }`, the attacker can learn the secret bit by seeing which cache line was accessed.

#### B. Page Fault Attacks (Controlled-Channel)

**How it works:**
1. Malicious OS unmaps enclave memory pages
2. When enclave accesses a page, it triggers a page fault
3. OS sees which page was accessed
4. Page access sequence reveals execution path

**Example:** If page 1 contains "approve transaction" code and page 2 contains "reject transaction" code, the OS knows which decision was made.

#### C. Speculative Execution Attacks (Foreshadow, Spectre)

**How it works:**
1. CPU speculatively executes instructions before permission checks complete
2. Speculative execution accesses enclave memory
3. Data is loaded into cache
4. Speculation is rolled back, but cache state remains
5. Attacker uses cache timing to extract the data

**Foreshadow (L1TF):**
- Specifically targets SGX enclaves
- Exploits how CPU handles page table entries
- Can extract attestation keys (!!)

**Mitigations:**
- Microcode updates (L1 cache flush on enclave exit)
- Hardware fixes in newer CPUs (Ice Lake+)
- HyperThreading disabled on same core

### 2. Rollback Attacks

**The problem:** Sealed data can be replayed from an earlier state.

```
Time T1: Enclave seals state { balance: 100 BTC }
Time T2: User spends 50 BTC
Time T2: Enclave seals state { balance: 50 BTC }
Time T3: Attacker restores T1 sealed data
Time T3: Enclave unseals { balance: 100 BTC }  ← Double spend!
```

**Why it happens:**
- TEE sealing encrypts data but doesn't enforce monotonicity
- Attacker controls storage, can restore old sealed blobs
- Enclave can't tell if it's seeing "current" or "old" data

**Mitigations:**
- External monotonic counter (but who guards the counter?)
- Blockchain-based state anchoring
- ROTE (Rollback-resilient TEE) protocols
- SGX trusted counters (limited, wear-leveling issues)

### 3. Denial of Service

**The problem:** Attacker can always prevent enclave from running.

```
Malicious OS can:
- Refuse to schedule enclave threads
- Kill enclave process
- Starve enclave of resources
- Power off the machine
```

**Why TEEs can't prevent this:**
- TEEs protect confidentiality and integrity, not availability
- OS controls scheduling and resource allocation
- Hardware requires power to operate

**For custody:** This means an attacker can prevent signing, but can't steal keys. Annoying, but not catastrophic.

### 4. Bugs in Enclave Code

**The problem:** TEE protects your code from external tampering, not from itself.

```c
// Inside enclave
void sign_transaction(char* tx_data, int len) {
    char buffer[256];
    memcpy(buffer, tx_data, len);  // Buffer overflow if len > 256!
    // Attacker-controlled data now on enclave stack
}
```

**Attack surface:**
- Buffer overflows
- Use-after-free
- Integer overflows
- Logic bugs

**Mitigations:**
- Memory-safe languages (Rust)
- Minimal TCB (less code = fewer bugs)
- Formal verification (expensive but possible)
- Extensive fuzzing and auditing

### 5. Supply Chain Attacks

**The problem:** What if the hardware itself is compromised?

```
Scenarios:
- Backdoored CPU (nation-state)
- Compromised firmware/microcode
- Malicious BIOS
- Intercepted hardware shipment
```

**Why it matters:**
- Attestation relies on hardware root of trust
- If root is compromised, attestation is meaningless
- Intel/AMD/AWS are trusted by design

**Mitigations:**
- Hardware from trusted suppliers
- Physical security of supply chain
- Multi-vendor TEE diversity (defense in depth)
- Open-source hardware (long-term)

### 6. Microarchitectural Attacks Summary

| Attack | Vector | Leaked Info | Mitigation |
|--------|--------|-------------|------------|
| Prime+Probe | L1/L2 cache | Memory access pattern | Constant-time code |
| Flush+Reload | Shared libraries | Code execution path | No sharing with attacker |
| Page fault | OS page tables | Page-level access | ORAM, TSX |
| Foreshadow | Speculative exec | Arbitrary enclave data | Microcode, new CPUs |
| Plundervolt | Voltage glitching | Crypto key bits | Voltage locking |
| SGAxe | Cache + attestation | Attestation keys | Key refresh, patches |

---

## Threat Model for FROST + TEE Custody

Let's apply this to our attested-custody design:

### Assets to Protect
1. **Key shares** — Must never leave enclave
2. **Signing logic** — Must not be tampered with
3. **Policy state** — Must not be rolled back

### Threat Actors

| Actor | Capabilities | Goal |
|-------|--------------|------|
| External attacker | Network access, phishing | Steal keys, forge signatures |
| Malicious insider | Root on host, physical access | Extract keys, bypass policy |
| Cloud provider | Full infra access | Steal keys (if malicious) |
| Nation-state | Supply chain, 0-days | Targeted key extraction |

### Attack Surface Analysis

```
┌─────────────────────────────────────────────────────────────────┐
│                    CUSTODY SYSTEM ATTACK SURFACE                 │
│                                                                  │
│  ┌─────────────────┐                                             │
│  │  Client Request │─────┐                                       │
│  └─────────────────┘     │                                       │
│                          ▼                                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   API Gateway   │─►│   Coordinator   │─►│    Enclave      │  │
│  │   (untrusted)   │  │   (untrusted)   │  │   (trusted)     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│         ▲                     ▲                    ▲             │
│         │                     │                    │             │
│    [Network]             [Host OS]           [Side-channel]      │
│    [Auth bypass]         [Rollback]          [Speculation]       │
│                          [DoS]               [Code bugs]         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Defense Mapping

| Threat | Defense | Layer |
|--------|---------|-------|
| Key extraction via OS | TEE memory isolation | Hardware |
| Fake enclave | Remote attestation | Protocol |
| Replay signing | Nonce in request | Protocol |
| Rollback policy state | Monotonic counter / chain anchor | Application |
| Side-channel (cache) | Constant-time crypto | Code |
| Side-channel (page) | Single-page hot path | Code |
| DoS | Redundant signers (threshold) | Architecture |
| Code bugs | Rust, minimal TCB, audit | Code |
| Supply chain | Multi-vendor, physical security | Operations |

---

## SGX vs Nitro: Threat Model Comparison

| Threat | SGX | Nitro |
|--------|-----|-------|
| Malicious OS | ✅ Protected | ✅ Protected |
| Malicious hypervisor | ✅ Protected | ⚠️ Trust AWS Nitro |
| Cache side-channels | ❌ Vulnerable | ✅ Better isolated |
| Page fault channels | ❌ Vulnerable | ✅ Own kernel |
| Speculative execution | ❌ Vulnerable (patched) | ⚠️ Less exposed |
| Rollback | ❌ Possible | ❌ Possible |
| DoS | ❌ Possible | ❌ Possible |
| Network exfil | ⚠️ If host compromised | ✅ No network |
| Cloud provider trust | ✅ Trust Intel silicon | ⚠️ Trust AWS |

**Key insight:** SGX has a smaller trust perimeter but more side-channel exposure. Nitro is simpler to defend but requires trusting AWS.

---

## Exercises

1. **Analyze:** You're building a custody system. An auditor asks: "What happens if an attacker has root on the host?" Write a 3-sentence response explaining what they can and cannot do.

2. **Design:** How would you prevent rollback attacks on policy state (e.g., velocity limits) in an enclave? Propose a solution.

3. **Evaluate:** A competitor claims their custody solution is "100% secure because it uses SGX." What questions would you ask to probe their threat model?

4. **Research:** Find one side-channel attack published after 2022. What was the vulnerability and was SGX affected?

---
## Answers
1. **Analyze:** An attacker with root can fully control the operating system, schedule or terminate enclave execution, manipulate networking, deny service, and observe many side channels, but they cannot directly read or modify enclave memory if the SGX hardware guarantees hold. They can attempt rollback, replay, I/O tampering, or exploit implementation flaws and microarchitectural vulnerabilities, so SGX alone does not guarantee complete system security. The custody system must therefore combine SGX with authenticated storage, remote attestation, anti-rollback mechanisms, audited protocols, and defenses against known side-channel attacks.

2. **Design:** The enclave should never rely solely on local storage for its source of truth. When updating a critical policy (like velocity limits), the enclave must require a cryptographic receipt or signed timestamp from an external cluster of peer enclaves or a high-availability database. Upon reboot, it queries the cluster for the latest state hash before accepting local data. Some TEE architectures offer non-volatile monotonic counters baked into the hardware platform. The enclave can increment this counter every time it seals data and include the counter's value in the sealed payload. When unsealing, the enclave verifies that the payload's counter matches the hardware's current counter, rejecting older versions

3. **Evaluate:**
My next questions would be:

**Threat model**
- What threats are you defending against?
- Are you assuming a malicious OS?
- Are you assuming a malicious hypervisor?
- Do you assume physical access?
- Do you defend against privileged insiders?
**Side channels**
- Which cache side-channel attacks have you mitigated?
- How do you handle page-fault attacks?
- Have you considered speculative execution attacks?
- Is your code constant-time?
**Persistence**
- How do you prevent rollback attacks?
- How are secrets sealed?
- How do you guarantee freshness after reboot?
**Attestation**
- How is remote attestation performed?
- How are measurements verified?
- How do clients pin enclave identities?
- How do you rotate enclave versions safely?
**Key management**
- Are private keys generated inside the enclave?
- Can keys ever leave plaintext memory?
- What happens during backup and recovery?
**Operational security**
- What happens if Intel revokes the platform?
- How are microcode updates handled?
- What happens if SGX must be disabled?
- Can the system continue operating safely?
**Availability**
- Can a root attacker prevent signatures?
- How do you recover from denial-of-service?
- What is the recovery process after enclave failure?

The phrase "100% secure" is itself a red flag. Every security system has assumptions, and understanding those assumptions is more important than the technology choice.

4. Research: Post-2022 Side-Channel Attack

The Attack: Downfall (CVE-2022-40982), publicly disclosed in August 2023 (after a year-long embargo).

The Vulnerability: Downfall is a transient execution (speculative execution) side-channel attack. It exploited a microarchitectural flaw in the Gather instructions of Intel's Advanced Vector Extensions (AVX). The CPU's memory optimization features unintentionally revealed internal hardware registers to software during speculative execution. An attacker could trick the CPU into speculatively reading out-of-bounds memory, leaking sensitive data left behind in the vector registers by other processes or threads.

Was SGX Affected? Yes. Downfall completely bypassed Intel SGX's hardware isolation. An attacker controlling the host OS could use Downfall to extract plaintext cryptographic keys and passwords directly from an actively running SGX enclave. Intel had to issue microcode updates to patch the vulnerability and force a "TCB Recovery," which revoked the attestation validity of unpatched CPUs.


---

## Resources

### Side-Channel Attacks
- [A Survey of Microarchitectural Timing Attacks](https://eprint.iacr.org/2019/636.pdf)
- [Foreshadow: Breaking the Virtual Memory Abstraction](https://foreshadowattack.eu/)
- [Plundervolt: Software-based Fault Injection](https://plundervolt.com/)

### TEE Security Analysis
- [SoK: Hardware-supported TEEs](https://arxiv.org/abs/1910.02244)
- [SGX Security Landscape](https://github.com/m1ghtym0/sgx-security)

### Rollback Protection
- [ROTE: Rollback Protection for Trusted Execution](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic)

---

## Summary

```
TEEs PROTECT AGAINST:
├── Privileged software (OS, hypervisor)
├── Physical memory attacks (cold boot, probing)
├── Software tampering (attestation detects)
└── Remote impersonation (attestation proves)

TEEs DON'T PROTECT AGAINST:
├── Side-channels (cache timing, page faults, speculation)
├── Rollback attacks (storage controlled by attacker)
├── Denial of service (availability not guaranteed)
├── Bugs in your code (TEE protects code, not from code)
└── Supply chain compromise (hardware root of trust)

FOR CUSTODY:
├── Side-channels → Constant-time code, minimal branching
├── Rollback → Monotonic counters, chain anchoring
├── DoS → Threshold redundancy (FROST)
├── Code bugs → Rust, small TCB, audit
└── Supply chain → Multi-vendor, physical security
```
