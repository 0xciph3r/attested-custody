# Day 7: Publication Packaging and Repository Quality

## Why This Day Matters

Great research can be ignored if packaging is weak.

Day 7 is about turning your technical draft into a public artifact that:
- is easy to review,
- is easy to verify,
- signals engineering maturity.

This is where you move from "I wrote something" to "people can trust and cite this."

---

## Deliverable for Day 7

A publication-ready package with:

1. polished abstract and title
2. consistent diagrams and pseudocode formatting
3. clean repository structure and README
4. reproducible PDF generation path
5. clear roadmap from paper -> reference implementation

---

## Final Paper Pass (Editorial + Technical)

Run one focused pass on each dimension:

## 1) Technical correctness pass
- verify trust boundaries are consistent across all sections
- verify all flow steps match pseudocode semantics
- verify out-of-scope threats are not accidentally claimed as solved

## 2) Consistency pass
- same terms everywhere (`attestation verdict`, `policy version`, `state_root`)
- same threshold examples (`3-of-5`, etc.)
- same reason codes for reject paths

## 3) Readability pass
- remove long vague sentences
- shorten over-dense paragraphs
- front-load the core claim in each section

---

## Abstract Optimization Framework

A strong abstract has five moves:

1. **Problem**: what current custody models miss
2. **Approach**: FROST + TEE + attestation gate
3. **Mechanism**: monotonic policy-state defense
4. **Scope**: what threat class is addressed
5. **Outcome**: practical architecture + implementation direction

If one of these is missing, readers lose context quickly.

---

## Pseudocode and Flow Packaging Rules

For each pseudocode block:

1. Include explicit input and output semantics
2. Return structured reject reasons
3. Avoid hidden helper assumptions
4. Show replay/freshness checks

For each sequence diagram:

1. mark trusted vs untrusted actors
2. annotate gate conditions at decision steps
3. include fail path, not only success path

---

## Reference Implementation Bridge (Paper -> Code)

Day 7 should define immediate code milestones:

1. Attestation verifier module
2. Signer session manager
3. Monotonic policy-state validator
4. Evidence bundle generator

This keeps the paper from becoming "theory only."

---

## Repository Cleanliness Standard

A clean research repo should satisfy:

1. no OS junk files or temp artifacts
2. README clearly explains purpose, status, and structure
3. all day-based notes follow consistent naming
4. build scripts for artifacts are documented
5. roadmap states what is complete and what is next

---

## Publication Readiness Checklist

Before broad sharing:

1. PDF title/author/contact are correct
2. links in paper/repo are valid
3. abstract has no broken UTF-8/formatting artifacts
4. terminology is stable and consistent
5. evidence and threat mapping tables are readable
6. "limitations" section is explicit and non-defensive
7. implementation path is clearly stated

---

## Communications Pack (Post-Review)

Prepare these in advance:

1. **30-second summary**  
   "We combine FROST threshold signing with attested enclaves and rollback-resistant policy state to reduce key-share exposure under host compromise."

2. **1-paragraph summary**  
   Problem, approach, result in plain engineering language.

3. **3-bullet reviewer hook**  
   - untrusted coordinator by design  
   - hard-gated attestation checks  
   - monotonic anti-rollback enforcement

---

## Day 7 Exercises

1. Rewrite your abstract in <= 180 words while preserving all five abstract moves.

2. Choose one pseudocode block and add explicit fail paths with reason codes.

3. Build a publication checklist table and mark current status per item.

4. Write a 5-sentence "why this matters for institutional custody" statement with no marketing language.

---

## Resources

- `whitepaper/attested-custody-preprint.md`
- `whitepaper/build_pdf.py`
- `README.md`
- Day 3 and Day 5 notes (threat and architecture source of truth)

---

## Summary

Day 7 outcome:

```
A publishable, inspectable, and credible artifact:
├── technically coherent
├── operationally honest
├── easy to review
└── ready to bridge into implementation
```

