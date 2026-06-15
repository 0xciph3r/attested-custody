# Attested Custody

FROST threshold signing with TEE-backed key protection.

## Goal

Publish a whitepaper and reference implementation demonstrating how to combine:
- **FROST threshold signatures** (distributed key generation, 2-round signing)
- **Trusted Execution Environments** (hardware-isolated key storage)
- **Remote attestation** (cryptographic proof of enclave integrity)

The result: a custody architecture where key shares live inside enclaves and signing requires attestation verification.

## Structure

```
notes/           # Learning notes, day by day
whitepaper/      # Paper drafts and figures
reference-impl/  # Code (Go, will integrate with btc-custody)
research/        # Academic papers, prior art
```

## Learning Roadmap

| Day | Topic | Status |
|-----|-------|--------|
| 1 | TEE Fundamentals | |
| 2 | Attestation Deep-dive | |
| 3 | TEE Threat Model | |
| 4 | Prior Art Survey | |
| 5 | Architecture Design | |
| 6-7 | Whitepaper Draft | |
| 8+ | Reference Implementation | |

## Why This Matters

Current custody solutions either:
- Trust a single HSM (single point of failure)
- Use threshold signing without hardware protection (keys in software)
- Use TEEs without threshold signing (single key in enclave)

Combining FROST + TEE gives:
- No single point of compromise (threshold)
- Hardware-enforced key isolation (TEE)
- Verifiable execution (attestation)

## Prior Work

- Fortanix: SGX-based key management
- AWS Nitro Enclaves: Isolated compute for sensitive workloads
- Fedimint: FROST-based custody (software keys)
- This project: Bridging FROST and TEE

## Author

0xciph3r
