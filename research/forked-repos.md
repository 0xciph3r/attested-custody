# Forked Repos for Study

## TEE Development

### edgelesssys/ego
**Priority: HIGH** — Go SDK for Intel SGX
- Study: How to build SGX enclaves in Go
- Focus files: `enclave/`, `ecrypto/`, attestation examples
- https://github.com/0xciph3r/ego

### aws/aws-nitro-enclaves-cli
**Priority: HIGH** — Nitro enclave tooling
- Study: How to build, run, debug Nitro enclaves
- Focus: `enclave_build/`, `vsock-proxy/`
- https://github.com/0xciph3r/aws-nitro-enclaves-cli

### aws/aws-nitro-enclaves-sdk-c
**Priority: MEDIUM** — SDK for building enclaves
- Study: C SDK patterns, attestation document handling
- Focus: `containers/`, `attestation/`
- https://github.com/0xciph3r/aws-nitro-enclaves-sdk-c

---

## FROST / Threshold Cryptography

### ZcashFoundation/frost
**Priority: HIGH** — Reference FROST implementation (Rust)
- Study: Production-grade FROST code
- Focus: `frost-core/`, `frost-secp256k1-tr/` (Taproot)
- This is what you'd wrap in TEE
- https://github.com/0xciph3r/frost

### fedimint/fedimint
**Priority: HIGH** — Production FROST in custody context
- Study: How Fedi structures their threshold signing
- Focus: `modules/wallet/`, `crypto/`
- Real-world integration patterns
- https://github.com/0xciph3r/fedimint

---

## Security Research & Intelligence

### trailofbits/publications
**Priority: HIGH** — Audit reports and research papers
- Study: How top auditors document findings
- Focus: Blockchain audits, cryptography papers
- Learn vulnerability patterns
- https://github.com/0xciph3r/publications

### RustSec/advisory-db
**Priority: MEDIUM** — Rust vulnerability database
- Study: CVE patterns in crypto libraries
- Useful when you start writing Rust
- https://github.com/0xciph3r/advisory-db

### google/oss-fuzz
**Priority: LOW (reference)** — Continuous fuzzing infrastructure
- Study: How to set up fuzzing for crypto code
- Future reference when building test infra
- https://github.com/0xciph3r/oss-fuzz

---

## Offensive Security Fundamentals

### OWASP/CheatSheetSeries
**Priority: MEDIUM** — Security best practices
- Study: Quick reference for secure coding
- Focus: Crypto storage, auth, session management
- https://github.com/0xciph3r/CheatSheetSeries

### swisskyrepo/PayloadsAllTheThings
**Priority: MEDIUM** — Attack patterns encyclopedia
- Study: Understand attacker techniques
- Focus: Injection, privilege escalation, crypto attacks
- https://github.com/0xciph3r/PayloadsAllTheThings

---

## Bitcoin Fundamentals

### bitcoinbook/bitcoinbook
**Priority: MEDIUM** — Mastering Bitcoin (O'Reilly)
- Study: Full Bitcoin protocol understanding
- Focus: Ch 4 (keys), Ch 6 (transactions), Ch 7 (scripts)
- https://github.com/0xciph3r/bitcoinbook

### in3rsha/learnmeabitcoin-code
**Priority: MEDIUM** — Bitcoin code examples
- Study: Working code for Bitcoin primitives
- Good for hands-on understanding
- https://github.com/0xciph3r/learnmeabitcoin-code

---

## Reading Order

### Week 1: TEE + Attestation
1. ego docs → build hello world enclave
2. aws-nitro-enclaves-cli → understand enclave lifecycle
3. trailofbits → read 2-3 blockchain audit reports

### Week 2: FROST Deep Dive
1. frost repo → read frost-core, understand API
2. fedimint → see real integration
3. RustSec → check crypto lib advisories

### Week 3: Security Engineering
1. OWASP CheatSheet → secure coding patterns
2. PayloadsAllTheThings → attack surface knowledge
3. Continue building reference implementation

---

## Not Forked (Star Instead)

These are worth starring but not forking:

- `bitcoin/bitcoin` — Too large, just reference
- `lightningnetwork/lnd` — You already contributed, know codebase
- `confidential-containers/confidential-containers` — K8s focus, later
- `sigp/lighthouse` — Ethereum, not your focus now
