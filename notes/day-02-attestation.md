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


## Solutions 

1. A replay attack occurs when an attacker intercepts and records a perfectly valid, mathematically sound attestation quote from a genuine enclave.Later,  after the server has been compromised or downgraded to vulnerable code—the attacker "replays" this old, recorded quote to a client. Because the quote's hardware signature is technically authentic, the client is tricked into believing the server is currently secure.

A Nonce (Number used ONCE) is the cryptographic defense against this. Before requesting an attestation quote, the client generates a random, unpredictable string (the nonce) and sends it to the enclave. The enclave code takes this nonce and explicitly embeds it into the user_data field of the hardware report. The CPU hardware then cryptographically signs the entire report, including the nonce. When the client receives the quote, they verify the signature and check that the nonce perfectly matches the one they just generated. Because the attacker cannot forge the hardware's signature over a new nonce, their old, recorded quotes become completely useless

2. The tradeoff is primarily between Privacy vs. Availability/Decentralization. EPID (Enhanced Privacy ID): This is the legacy architecture. It uses a specialized group signature scheme. To verify an EPID quote, the client must make a live API call to the Intel Attestation Service (IAS).  The Tradeoff: EPID is highly privacy-preserving (Intel can verify that a valid CPU signed the quote, but cannot identify which specific CPU it was, preventing hardware tracking). However, it creates a massive centralized dependency. If Intel's servers go down, or if your system is in an air-gapped environment, attestation completely fails. While the later is the modern, cloud-native architecture. It uses standard ECDSA signatures. Instead of contacting Intel at runtime, the cloud provider (or you) runs a local Provisioning Certificate Caching Service (PCCS) that stores Intel's hardware certificate chains.

The Tradeoff: DCAP removes the runtime dependency on Intel, allowing for local, ultra-fast, and highly available offline verification. The cost is a loss of privacy—the Provisioning Certification Key (PCK) maps directly to the specific CPU hardware, meaning the hardware identity is known to the verifier.

3. FROST (Flexible Round-Optimized Schnorr Threshold) requires multiple nodes to collaborate to sign a transaction without ever reconstructing the full private key. If you are building this inside TEEs, attestation must be enforced at three critical boundaries:

Node Onboarding & Distributed Key Generation (DKG):
Before a new node is permitted to join the cluster and receive its encrypted secret key share, the coordinator (or peer nodes) must challenge it. Attestation ensures the new node is running the exact, un-tampered FROST binary. If a node is running modified code designed to exfiltrate key shares, the PCR (Platform Configuration Register) hashes will mismatch, and onboarding will be rejected.

Establishing Peer-to-Peer Secure Channels (mTLS):
FROST requires multiple rounds of communication to exchange nonces and signature shares. Nodes should embed their attestation quotes directly into their TLS handshakes (e.g., via X.509 certificate extensions). This guarantees that a node is communicating exclusively with other genuine enclaves, neutralizing Man-in-the-Middle attacks or rogue nodes attempting to harvest signature shares.

Client Transaction Submission:
When a user (the client) wants to initiate a transaction, their local application must challenge the FROST coordinator with a Nonce. The coordinator returns an attestation quote. The client verifies this quote locally to ensure the remote server hasn't been compromised since the last check, and only then encrypts the transaction payload using a key bound to the enclave.

4. 
Conversation with Gemini
Help me to distil this document. I am trying to learn Intel SGX and confidential computing from first principles, and I need to understand it well enough to defend it when called upon. I need to understand every primitive, every possible attack and defence against it.

To defend Intel SGX and Confidential Computing from first principles, you need to understand the fundamental problem it solves, the hardware primitives it relies on, how it establishes trust, and exactly where its armor is weak.

Here is a comprehensive distillation of Confidential Computing and Intel SGX.

1. First Principles: Why Confidential Computing?
Historically, we have been very good at protecting data in two states:

At Rest: Encrypted on disk (e.g., BitLocker, AES-NI).

In Transit: Encrypted over the network (e.g., TLS/SSL).

However, to compute on data, it must be decrypted in the system's memory (RAM) and processed by the CPU. This is data In Use.

The Threat Model: Traditional security assumes the Operating System (OS) or Hypervisor is a "trusted" entity. If a malicious cloud provider, a rogue sysadmin, or malware compromises the OS with root privileges, they can read the RAM and steal the data.

Confidential Computing fundamentally flips this threat model. It assumes the OS, hypervisor, BIOS, and hardware peripherals are all untrusted. The trust boundary is shrunk to exactly two things:

The CPU silicon.

The specific application code you want to run.

To achieve this, the CPU uses hardware-backed Trusted Execution Environments (TEEs)—or Enclaves.

2. The Core Primitives of Intel SGX
Intel Software Guard Extensions (SGX) is an instruction set extension that allows developers to carve out private, encrypted regions of memory.

A. The Processor Reserved Memory (PRM) & Enclave Page Cache (EPC)
PRM: A continuous range of memory set aside by the BIOS that the OS/Hypervisor simply cannot access. Any non-enclave instruction trying to read this memory gets a dummy value (like -1 or 0xFF).

EPC (Enclave Page Cache): The actual memory pages inside the PRM where enclave code and data live.

B. The Memory Encryption Engine (MEE)
If an attacker physically opens the server and clips a logic analyzer to the memory bus, they could theoretically read data moving from the CPU to the RAM. SGX defends against this using the MEE.

Whenever data leaves the CPU package to go to RAM, the MEE encrypts it (typically using AES-CTR) and adds an integrity tag.

Whenever data is fetched from RAM to the CPU, it is decrypted and its integrity is verified. If the data was tampered with (a physical memory injection), the CPU halts the system.

C. Instruction Sets (ENCLS and ENCLU)
SGX introduces specific CPU instructions:

ENCLS (Supervisor): Used by the OS to manage enclaves (ECREATE to build one, EADD to add pages, EINIT to finalize and lock it).

ENCLU (User): Used by applications to interact with enclaves (EENTER to jump into the enclave, EEXIT to leave).

3. The Lifecycle of Trust: Measurement, Attestation, and Sealing
If the OS is untrusted, how do you know the OS actually loaded your secure code and didn't just load a fake enclave designed to steal your passwords?

A. Measurement (MRENCLAVE & MRSIGNER)
When an enclave is built (via EADD), the CPU keeps a running cryptographic hash (SHA-256) of every byte of code and data being loaded.

MRENCLAVE: The final hash of the enclave's memory. It is the absolute, unforgeable identity of the code. Even a 1-bit change in the code radically changes this hash.

MRSIGNER: The hash of the public key of the developer who signed the enclave.

B. Remote Attestation
This is how a client (e.g., your laptop) proves that a server in the cloud is running the genuine enclave on genuine Intel hardware. 1. Your client challenges the enclave.
2. The enclave generates an EREPORT (containing MRENCLAVE and user data) and passes it to a special Intel-provided enclave called the Quoting Enclave (QE).
3. The QE verifies the report locally and signs it using an Intel-fused hardware key, creating a Quote.
4. The Quote is sent back to you. You forward it to the Intel Attestation Service (IAS) or a decentralized Data Center Attestation Primitive (DCAP).
5. If valid, you now have mathematical proof you are talking to your exact code running on real Intel silicon. Now you can establish a TLS tunnel directly into the enclave and send your secrets.

C. Sealing
When the server reboots, the enclave is destroyed. To save state securely, the enclave uses an EGETKEY instruction to derive a unique encryption key based on the hardware CPU key and the MRENCLAVE. It encrypts the data and stores it on the untrusted hard drive. Only that exact enclave on that exact CPU can decrypt it later.

4. Attacks and Defenses (How to Defend the Perimeter)
To defend SGX in a debate, you must concede that SGX is not magic; it has structural limitations. Attacks fall into three main categories:

A. Software Vulnerabilities inside the Enclave
The Attack: SGX does not protect you from writing bad code. If your enclave code has a buffer overflow, an attacker (even the malicious OS) can exploit it to hijack control flow within the enclave and read its memory.

The Defense: Keep the Trusted Computing Base (TCB) as small as possible. Write enclaves in memory-safe languages like Rust, or use vetted library OS frameworks (like Gramine or Occlum) that sandbox legacy code safely.

B. Side-Channel Attacks (The Achilles' Heel)
Because the enclave shares the same physical CPU cache (L1/L2/L3) and execution units as the untrusted OS, an attacker can observe how the CPU behaves to deduce what the enclave is doing.

Page Fault Attacks (Controlled-Channel): The OS manages page tables. It can unmap an enclave's memory pages and watch which pages the enclave tries to access by observing page faults.

Defense: Use Oblivious RAM (ORAM) algorithms so memory accesses look completely random, or use TSX (Transactional Synchronization Extensions) to hide page faults.

Cache-Timing Attacks (Prime+Probe): The attacker fills the CPU cache with their own data, lets the enclave run, and measures which cache lines the enclave evicted.

Defense: Write code in "Constant Time"—meaning the code executes the same instructions and accesses the same memory regardless of the secret data (especially for cryptography).

Transient/Speculative Execution (e.g., Foreshadow/L1TF, Spectre): CPUs guess future instructions to speed up processing. Attackers exploit this to trick the CPU into temporarily reading enclave secrets into the cache before the CPU realizes it shouldn't have.

Defense: Intel microcode updates, hardware redesigns in newer CPUs (Ice Lake and beyond), and CPU microcode flushing the L1 cache whenever the CPU exits an enclave.

C. Physical/Hardware Attacks
Plundervolt / Fault Injection: Attackers with root access undervolt the CPU slightly. This causes mathematical errors inside the enclave, which can be used to leak cryptographic keys.

Defense: Intel released a microcode update that allows the BIOS to lock the CPU voltage interface, preventing software from tampering with it.

Summary: How to Argue for SGX
When defending SGX, your core argument should be: "SGX minimizes the Trusted Computing Base." Without SGX, your security depends on millions of lines of code in Linux, hypervisors, and sysadmins remaining perfectly secure—which is impossible. With SGX, your security relies strictly on the hardware architecture and the few thousand lines of code you wrote. While side-channel attacks exist, they are highly sophisticated, require local access, and can be mitigated by writing side-channel resistant code and keeping CPU microcode up to date.

Your uploads may be too large for the best results. Learn moreOpens in a new window
1. **Explain in your own words:** Why can't the OS read enclave memory even with root access?



2. **Compare:** What's the key difference between SGX (process-level) and Nitro (VM-level) isolation?



3. **Think about:** If you were building a custody system, which TEE would you choose and why?



4. **Research:** Find one real-world attack on Intel SGX. What was the vulnerability?

Here are detailed answers to help you deeply understand and defend the principles of Confidential Computing:

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

1. **Explain:** What is a replay attack on attestation, and how does a nonce prevent it?



2. **Compare:** What's the tradeoff between EPID (Intel online) and DCAP (local verification)?



3. **Design:** In our FROST custody system, when should attestation be required? (List at least 3 operations)



4. **Think about:** If AWS is compromised (malicious insider), what can they do despite Nitro attestation? What can't they do?

Here are the technical breakdowns of these concepts to help you deeply understand and defend your architectural choices.

1. Replay Attacks on Attestation & Nonces
A replay attack occurs when an attacker intercepts and records a perfectly valid, mathematically sound attestation quote from a genuine enclave. Later—perhaps after the server has been compromised or downgraded to vulnerable code—the attacker "replays" this old, recorded quote to a client. Because the quote's hardware signature is technically authentic, the client is tricked into believing the server is currently secure.

A Nonce (Number used ONCE) is the cryptographic defense against this.

Before requesting an attestation quote, the client generates a random, unpredictable string (the nonce) and sends it to the enclave.

The enclave code takes this nonce and explicitly embeds it into the user_data field of the hardware report.

The CPU hardware then cryptographically signs the entire report, including the nonce.

When the client receives the quote, they verify the signature and check that the nonce perfectly matches the one they just generated. Because the attacker cannot forge the hardware's signature over a new nonce, their old, recorded quotes become completely useless.



Was this visual helpful?

2. Compare: EPID vs. DCAP
These are the two fundamental architectures for verifying an Intel SGX quote. The tradeoff is primarily between Privacy vs. Availability/Decentralization.

EPID (Enhanced Privacy ID): This is the legacy architecture. It uses a specialized group signature scheme. To verify an EPID quote, the client must make a live API call to the Intel Attestation Service (IAS).  
Gramine documentation - Read the Docs

The Tradeoff: EPID is highly privacy-preserving (Intel can verify that a valid CPU signed the quote, but cannot identify which specific CPU it was, preventing hardware tracking). However, it creates a massive centralized dependency. If Intel's servers go down, or if your system is in an air-gapped environment, attestation completely fails. (Note: Intel is officially sunsetting EPID for SGX in 2025).  
Crust Wiki - Crust Network

DCAP (Data Center Attestation Primitives): This is the modern, cloud-native architecture. It uses standard ECDSA signatures. Instead of contacting Intel at runtime, the cloud provider (or you) runs a local Provisioning Certificate Caching Service (PCCS) that stores Intel's hardware certificate chains.

The Tradeoff: DCAP removes the runtime dependency on Intel, allowing for local, ultra-fast, and highly available offline verification. The cost is a loss of privacy—the Provisioning Certification Key (PCK) maps directly to the specific CPU hardware, meaning the hardware identity is known to the verifier.

3. Design: Attestation in a FROST Custody System
FROST (Flexible Round-Optimized Schnorr Threshold) requires multiple nodes to collaborate to sign a transaction without ever reconstructing the full private key. If you are building this inside TEEs, attestation must be enforced at three critical boundaries:

Node Onboarding & Distributed Key Generation (DKG):
Before a new node is permitted to join the cluster and receive its encrypted secret key share, the coordinator (or peer nodes) must challenge it. Attestation ensures the new node is running the exact, un-tampered FROST binary. If a node is running modified code designed to exfiltrate key shares, the PCR (Platform Configuration Register) hashes will mismatch, and onboarding will be rejected.

Establishing Peer-to-Peer Secure Channels (mTLS):
FROST requires multiple rounds of communication to exchange nonces and signature shares. Nodes should embed their attestation quotes directly into their TLS handshakes (e.g., via X.509 certificate extensions). This guarantees that a node is communicating exclusively with other genuine enclaves, neutralizing Man-in-the-Middle attacks or rogue nodes attempting to harvest signature shares.

Client Transaction Submission:
When a user (the client) wants to initiate a transaction, their local application must challenge the FROST coordinator with a Nonce. The coordinator returns an attestation quote. The client verifies this quote locally to ensure the remote server hasn't been compromised since the last check, and only then encrypts the transaction payload using a key bound to the enclave.

4. Think About: AWS Malicious Insider vs. Nitro Enclaves
AWS Nitro Enclaves operate via VM-level isolation using the Nitro Hypervisor. If an AWS insider (or an attacker who has rooted the parent EC2 instance) attempts to compromise your custody system, the threat model looks like this:  
AWS

What the Malicious Insider CANNOT Do:

Read memory or extract private keys: The Nitro Security Chip encrypts the enclave's memory. Even if a hypervisor admin forces a RAM dump of the physical server, they will only retrieve ciphertext.

SSH into the environment: Nitro Enclaves are heavily stripped down. They have no interactive shell, no SSH daemon, and no persistent storage.  
Futurum Research

Modify code undetectably: If the insider tries to inject a backdoor into your FROST code, the cryptographic measurement (PCR hashes) of the Enclave Image File (.eif) will change. Your attestation checks will immediately fail, and your KMS will refuse to decrypt the enclave's operational keys.

What the Malicious Insider CAN Do:

Denial of Service (DoS) & Resource Starvation: The insider owns the parent EC2 instance. They can simply terminate the EC2 instance, sever the vsock connection (the only way the enclave communicates), or throttle the CPU/RAM, effectively taking your custody system offline.

Network Observation: Nitro Enclaves have no external network interface; all traffic is routed through the parent EC2 via local sockets. The insider can capture all packets leaving the parent instance. If your enclave fails to enforce strict end-to-end encryption (TLS) with external services, the insider will see the plaintext payloads.  
AWS - Amazon.com

Side-Channel Timing Attacks: While Nitro mitigates many SGX-style cache attacks by dedicating entire isolated vCPU cores to the enclave, the insider controls the parent OS. They can monitor the exact timing of network I/O over the vsock to infer what the enclave is doing (e.g., deducing when specific cryptographic operations occur based on traffic bursts).

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
