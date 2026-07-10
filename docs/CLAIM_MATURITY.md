# Evidence Claim Maturity

TohuPono uses strong claim language only when the evidence layer can support it.

High-risk claim zones include:

- legally proven
- court-ready
- guaranteed authentic
- impossible to fake
- not AI
- proof of reality
- proof-of-reality
- integrity
- truth
- authorship
- admissibility

These phrases may be discussed internally as development goals, research areas, or evidence-strength targets. They must not be used as final product claims, report claims, marketing claims, or legal-support claims unless the project has enough supporting architecture, testing, documentation, and legal review to justify them.

## Legal Proof Boundary

The phrase "legally proven" must be treated literally and seriously.

A tool cannot declare something legally proven. Legal proof depends on jurisdiction, procedure, admissibility rules, chain of custody, witness credibility, expert interpretation, evidential standards, and the decision-maker.

TohuPono may help support legal proof by producing deterministic evidence records, but it must distinguish between:

- technical verification;
- evidence preparation;
- chain-of-custody support;
- legal argument;
- legal admissibility;
- legal proof.

## Integrity Rule

Integrity means the file identity is stable, the manifest is reproducible, signatures are verifiable, the evidence chain is tamper-evident, reports reflect proof packets honestly, warnings are not hidden, failures are not softened, metadata is not overstated, and claims do not exceed evidence.

Any weakness in the proof model, implementation, documentation, report wording, signing layer, key handling, verification logic, or evidence chain must be fixed, hardened, documented, or explicitly warned about.

## Proof-Of-Reality Direction

Proof-of-reality is a strategic direction, not a casual product claim.

The project moves toward stronger reality support by layering evidence:

- file byte identity;
- deterministic manifest;
- manifest signature;
- evidence-chain hash linking;
- copy and rename verification;
- amendment lineage;
- report signing;
- trusted timestamping;
- witness signatures;
- device or context attestations;
- external anchoring;
- legal-support documentation.

A single hash proves byte identity. A signature proves control of a signing key. A timestamp supports proof of existence at or before a time. A custody chain supports continuity. A report supports human review. These layers strengthen evidence, but none should be overstated alone.

## Integrity Gap Classification

- `FAIL`: breaks verification or allows false confidence. Fix before release.
- `WARN`: does not break verification but weakens evidential strength. Document it and test warning behavior.
- `LIMIT`: outside current scope but must be disclosed clearly.
- `TODO`: accepted improvement target for the roadmap.

## Maturity Levels

Level 1: Technical Identity

Safe when hash verification works:

- byte-identical;
- digest match;
- file identity match;
- verified file integrity.

Level 2: Packet Integrity

Safe when manifest, signatures, and chain checks pass:

- manifest verified;
- signature valid;
- evidence chain intact;
- packet integrity verified.

Level 3: Evidence Support

Safe when reports, warnings, and custody records are complete:

- evidence-support packet;
- legal-prep evidence bundle;
- chain-of-custody support;
- verification report.

Level 4: Reality Support

Use carefully when multiple evidence layers support the claim:

- proof-of-existence support;
- proof-of-continuity support;
- proof-of-file-state support;
- reality-evidence support.

Level 5: Legal Proof

Use only with legal review and jurisdiction-specific framing:

- legally assessed;
- admissibility reviewed;
- legal proof argument supported;
- court-submitted evidence.

Do not collapse Level 1 into Level 5.
