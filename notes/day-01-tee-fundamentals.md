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


### Solutions to the Exercise

1. Explain in your own words: Why can't the OS read enclave memory even with root access?
The reason the Operating System (OS) or Hypervisor cannot read enclave memory—even if it is compromised and running with Ring 0 (root/admin) privileges—comes down to hardware-enforced access controls.

In traditional architecture, the OS is the ultimate arbiter of memory access; it manages the page tables and decides who gets to see what. Intel SGX bypasses this entirely:

The CPU is the gatekeeper: When the system boots, the BIOS carves out a specific chunk of RAM called the Processor Reserved Memory (PRM). The CPU hardware is hardwired to reject any non-enclave instruction that tries to touch this memory.

Hardware Abort: If a malicious OS tries to read an address within the PRM, the CPU's hardware memory controller intercepts the request before it even happens. Instead of returning the secret data, the CPU aborts the read and returns a dummy value (like all 1s or 0xFF), or it triggers a hardware fault.

The Memory Encryption Engine (MEE): Even if an attacker ignores the OS and tries a physical attack (like freezing the RAM sticks or using a physical memory probe), they still can't read the data. Data inside the CPU registers is in plaintext, but the moment it leaves the CPU silicon to travel to the physical RAM, the CPU's MEE automatically encrypts it. The OS only ever sees encrypted ciphertext.

2. Compare: What's the key difference between SGX (process-level) and Nitro (VM-level) isolation?
The fundamental difference lies in the boundary of the trust perimeter.

Intel SGX (Process-Level Isolation): SGX operates inside a standard application. It carves out a tiny, secure vault (the enclave) within the virtual memory space of a user-level process. The application executes normally, and when it needs to do something sensitive (like sign a transaction), it uses a special CPU instruction to "jump" into the enclave.

Pros: The Trusted Computing Base (TCB) is incredibly small—just the specific enclave code and the CPU.

Cons: It is incredibly difficult to write code for. You typically have to rewrite your application using specific C/C++ or Rust SDKs, and the enclave still shares the same underlying OS kernel as the untrusted application, making it more vulnerable to certain side-channel attacks.

AWS Nitro Enclaves (VM-Level Isolation): Nitro creates a completely separate, highly constrained Virtual Machine. It runs alongside your main EC2 instance, but it has no persistent storage, no network connectivity, and no interactive access (no SSH). The only way to talk to it is via a local socket connection (vsock) from the parent instance.

Pros: It is much easier to use. You can take an entire existing application (e.g., a Python web server or a Docker container), package it, and drop it straight into the Nitro Enclave. It also benefits from running its own isolated kernel, shielding it from OS-level side channels.

Cons: The TCB is larger because it includes a lightweight Linux kernel. Furthermore, trust is rooted in AWS's proprietary Nitro security chips and hypervisor architecture, rather than the raw silicon manufacturer.

3. Think about: If you were building a custody system, which TEE would you choose and why?
If I were building an institutional crypto custody system (like a cold storage or transaction signing engine), I would choose AWS Nitro Enclaves, with a few caveats.

Why Nitro?

Operational Security & Isolation: A custody system's primary threat is network-based exfiltration. Nitro Enclaves physically lack external networking capability. Even if an attacker finds an RCE (Remote Code Execution) vulnerability in my signing code, they have absolutely no way to send the stolen private keys out to the internet because the enclave has no network interface.

Development Velocity: Custody systems often rely on complex cryptographic libraries (like ECDSA or threshold signatures) written in Go, Rust, or C++. With Nitro, I can run these standard binaries inside a stripped-down Linux environment without having to refactor them for the rigid memory constraints of an SGX SDK.

Defense-in-Depth: Because Nitro operates at the VM level, the attacker cannot easily monitor page faults or CPU cache line evictions from the parent OS, which mitigates many of the side-channel attacks that plague SGX.

The Caveat: I would only choose Nitro if my threat model assumes AWS itself is NOT a malicious actor. If the requirement is absolute "Zero Trust" against the cloud provider (e.g., state-level secrets), I would deploy bare-metal Intel SGX servers in a colocation facility, ensuring trust is rooted purely in the silicon and my own code.

4. Research: Find one real-world attack on Intel SGX. What was the vulnerability?
One of the most famous and devastating real-world attacks on Intel SGX was Foreshadow (CVE-2018-3615), discovered in 2018.

The Vulnerability: Foreshadow exploited a flaw in the CPU's speculative execution engine (similar to the famous Spectre and Meltdown attacks), combined with how SGX handles page faults. It is technically known as an "L1 Terminal Fault" (L1TF).

How it worked: Modern CPUs try to guess what instructions are coming next and execute them ahead of time ("speculatively") to save time. In Foreshadow, an attacker with control of the OS would unmap the memory page belonging to an SGX enclave. When the CPU subsequently tried to read that enclave memory, it would logically trigger a page fault (a "Terminal Fault") because the access was illegal.

The Leak: However, before the CPU fully realized the access was illegal and aborted it, it speculatively executed the read anyway and pulled the secret enclave data into the CPU's L1 Cache. The attacker then used a standard side-channel technique (like Prime+Probe) to measure the cache and extract the plaintext secret from the L1 cache.

The Defense: Intel had to release major microcode updates that forced the CPU to flush (wipe clean) the L1 cache completely every time the CPU exited an enclave, ensuring no secrets were left behind for an attacker to find. Future generations of Intel chips included silicon-level fixes for this vulnerability.
## Summary

TEEs provide:
1. **Isolated execution** — Code runs in hardware-protected environment
2. **Memory encryption** — Data encrypted with CPU-held keys
3. **Attestation** — Remote verification of enclave code and state

For custody, this means:
- Keys stored where OS cannot reach
- Signing policy enforced by hardware
- Clients verify enclave before trusting it
