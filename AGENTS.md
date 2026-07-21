# AGENTS.md - TohuPono Operating Contract

## Mission
Build TohuPono as a headless, deterministic, local-first proof protocol and proof engine organised around modular Proof Concepts.

TohuPono must not be defined solely as a file-origin proof system, Proof of Records, Proof of Reality, or Proof of Lineage. Those are narrower claim models or long-term assessment directions inside the broader protocol.

## Architecture
- Core proof logic remains UI-independent.
- CLI handlers orchestrate core functions and must not contain durable business logic.
- Proof Concepts live in `tohupono/concepts/`.
- Timestamp integrations extend `tohupono/timestamping/`.
- Trust and key logic remain under `tohupono/trust/`.
- Report generation remains under `tohupono/reporting/`.
- Reusable security primitives live under `tohupono/security/`.
- Deterministic identifiers must not depend on descriptive registry metadata.

## Proof Concepts
Proof Concepts are separate claim models. Implementation of one concept does not establish another.

Examples include integrity, existence, records, authenticity, origin, lineage, provenance, custody, transaction, ownership, possession, authorship, identity, authority, consent, receipt, publication, preservation, transformation, derivation, witness, verification, compliance, and reality as a long-term layered assessment.

Each Proof Concept must define:

- exact claim;
- subject of the claim;
- required evidence;
- verification procedure;
- trust assumptions;
- failure conditions;
- implementation maturity;
- known limitations;
- privacy implications;
- legal boundary.

Registry presence does not imply implemented capability.

## Claim Boundaries
- Digest integrity does not automatically prove authenticity.
- Possession does not automatically prove ownership.
- A valid signature does not automatically prove legal identity or authorship.
- A timestamp does not prove content truth.
- Recorded lineage does not prove that no history is missing.
- Proof of Reality requires layered independent evidence.
- Missing evidence must be disclosed.
- Ambiguous integrity results must fail closed or warn clearly according to the command policy.

## Repository Structure
- `tohupono/core/`: canonical proof logic and packet handling.
- `tohupono/concepts/`: Proof Concept registry and maturity model.
- `tohupono/security/`: path, text, atomic-write, lock, and limit helpers.
- `tohupono/timestamping/`: timestamp models, receipt policy, and provider interfaces.
- `tohupono/trust/`: key purposes, signing, lifecycle metadata, and key hygiene.
- `tohupono/reporting/`: human-readable report generation.
- `tohupono/verdicts/`: verification verdict classification.
- `tests/`: focused unit and CLI integration tests.
- `docs/`: protocol, security, claim-boundary, and release documentation.

## Development Workflow
Before editing, agents must:

1. confirm branch and repository status;
2. inspect `AGENTS.md`, `SECURITY.md`, relevant source, and tests;
3. identify the smallest coherent implementation slice;
4. review security-sensitive paths;
5. preserve backward compatibility;
6. add success and failure tests;
7. update documentation;
8. run validation;
9. stop before commit unless explicitly authorised.

## Security Workflow
For security-sensitive or release-bound work, agents must:

- review the threat model;
- use Codex Security when requested;
- distinguish candidates from validated findings;
- avoid speculative remediation;
- fix validated critical and high findings before feature expansion;
- fix validated architecture-relevant medium findings before feature expansion;
- document deferred findings with exact reasons;
- fail closed on ambiguous integrity results;
- avoid unsupported legal, authenticity, ownership, authorship, or reality claims.

## Cryptographic Rules
Agents must:

- never invent custom cryptography;
- use reviewed cryptographic tools and libraries;
- preserve key-purpose separation;
- never expose private key material;
- never use shell command strings for OpenSSL;
- validate generated key material;
- use bounded subprocess output and timeouts;
- preserve old valid keys during replacement and rotation;
- calculate fingerprints from public-key bytes.

## Key Lifecycle Rules
- `key create --force` records `KEY_REPLACED`, not `KEY_ROTATED`.
- `key rotate` records `KEY_ROTATED` and makes the new generation active.
- Previous valid generations must remain available for historical verification.
- Compromise metadata is a WARN and review trigger unless an explicit trust policy makes it fatal.
- Lifecycle logs are tamper-evident under the local key lifecycle model, not immutable.
- Internal chain gaps and removal of events referenced by later retained events are detectable.
- Removal of an unreferenced tail may not be detectable without a retained, signed, or externally anchored head checkpoint.

## Timestamp-Provider Rules
- Existing persisted timestamp values remain compatible.
- Provider imports must not trigger network calls.
- No provider performs network activity unless explicitly implemented and authorised.
- A verified timestamp can support that a specific digest existed no later than a verified time boundary.
- Timestamps do not establish truth, ownership, authorship, identity, intent, or legal admissibility.

## Determinism Rules
- Use canonical JSON for deterministic data.
- File identity is based on bytes, not paths.
- Proof, manifest, event, packet, and record identifiers must not include descriptive Proof Concept registry metadata.
- Paths, names, extensions, MIME guesses, and OS timestamps are supporting metadata.

## Persistence And Path Rules
Critical state should use:

- bounded structured input;
- canonical JSON;
- restrictive private-file modes;
- atomic replacement;
- parent-directory fsync where supported;
- operation-specific locks;
- symlink checks;
- path-escape prevention;
- stable errors.

Sensitive paths must reject traversal, absolute child paths where relative paths are required, NUL characters, ASCII control characters, Unicode bidirectional controls, symlinked sensitive files, and forbidden locations such as `.git` and `.ssh`.

## Testing Requirements
Every behavioural change requires:

- unit tests;
- integration tests where applicable;
- negative tests;
- tampering tests;
- compatibility tests;
- deterministic-output tests;
- offline tests for provider placeholders;
- no-macron validation.

## Documentation Requirements
Update documentation whenever behaviour, command output, proof semantics, security limits, or claim boundaries change.

Documentation must distinguish technical verification, evidence preparation, legal argument, legal admissibility, and legal proof.

## Language Rule
Do not use macrons in project-authored source code, comments, docstrings, identifiers, filenames, tests, examples, documentation, terminal output, generated reports, configuration, or workflow files.

Use `Maori` and `te reo Maori`.

## Git And Release Discipline
Agents must not:

- create commits unless authorised;
- create or move tags unless authorised;
- force-push;
- merge release branches without instruction;
- bump versions outside a release gate;
- commit keys, signatures, packets, receipts, reports, caches, local scan artefacts, local skills, or development packs.

## Definition Of Done
A task is complete only when:

- implementation exists;
- tests pass;
- documentation is updated;
- CLI usage is demonstrated where relevant;
- outputs are deterministic where required;
- security constraints are preserved;
- no-macron validation passes;
- user-facing language avoids unsupported legal, authenticity, ownership, authorship, or reality claims;
- final status reports changed files, validation results, known limitations, and remaining risks.
