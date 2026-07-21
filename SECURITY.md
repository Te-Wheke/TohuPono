# Security

TohuPono is local-first and offline by default. It is a headless proof protocol and proof engine organised around modular Proof Concepts.

## Supported Versions

Security review currently tracks the active development branch and the latest tagged release. Older versions may be reviewed when a maintainer explicitly scopes the review.

## Reporting

Private vulnerability reporting contact is pending. Maintainers should configure GitHub private vulnerability reporting before public release. Do not publish an unconfirmed security email address.

## Attacker Assumptions

TohuPono treats source files, proof packets, manifests, JSONL logs, timestamp receipts, filenames, paths and reports as potentially hostile input.

Local multi-user attackers may attempt to read private keys, substitute public keys, race file writes, replace lifecycle logs, or inject terminal/report control characters.

## Claim Boundary

TohuPono can support technical verification and evidence preparation. It does not by itself prove content truth, authorship, ownership, legal identity, legal admissibility or Proof of Reality.

## Key Separation

- Manifest-signing keys sign proof packet manifests.
- Report-signing keys sign human-readable PDF reports.
- Amendment keys sign amendment records.
- Future direct file-signing keys must remain separate.

Private keys are local secrets and must not be committed.

## Key Lifecycle

Private keys must be created with restrictive permissions. `key create --force` is a forced replacement and records `KEY_REPLACED`. `key rotate` creates a new active generation and records `KEY_ROTATED`.

OpenSSL Ed25519 operations use the system `openssl` command with argument arrays. This is not custom cryptography.

Lifecycle logs are tamper-evident under the local key lifecycle model. They are not immutable. Internal chain gaps and removal of events referenced by later retained events are detectable. Removal of the unreferenced tail of a purely local lifecycle log may not be detectable without a separately retained, signed or externally anchored head checkpoint.

Compromise metadata is a WARN and review trigger unless an explicit trust policy makes it fatal.

## Path And Permission Policy

Sensitive paths must reject traversal, absolute child paths where relative paths are required, NUL characters, ASCII control characters, Unicode bidirectional controls, sensitive symlinks and forbidden locations such as `.git` and `.ssh`.

Private directories should use `0700`. Private files should use `0600`. Public verification material may use `0644` only when intentionally classified as public.

Hardlink detection is best-effort where supported by the platform.

## Persistence Policy

Critical JSON, JSONL and key state should use bounded input, canonical JSON, atomic replacement, operation-specific locks and parent-directory fsync where supported. Fallback limitations must be documented rather than overstated.

## Provider Policy

Timestamp provider placeholders perform no network calls. External provider implementations, including OpenTimestamps and RFC 3161, must be explicit, opt-in and documented before use.

## Dependency Policy

Do not add large or fragile dependencies without review. Do not implement custom cryptography.

## Language Policy

Project-authored material must not contain macrons. Use `Maori` and `te reo Maori`.

## Confidentiality

Security reports may contain sensitive local paths, proof material or operational details. Do not commit security scan artefacts or publish private report material unless maintainers intentionally approve publication.
