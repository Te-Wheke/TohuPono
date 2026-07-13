# Changelog

## Unreleased

- Added Proof Concepts governance for distinct proof claim models and maturity boundaries.
- Added a conservative Proof Concepts registry with deterministic output.
- Added `tohupono concept list` and `tohupono concept inspect` for deterministic Proof Concept inspection.
- Added executable Proof Concept handling for `integrity` and `existence` only.
- Added repeatable `prove --concept` selection with default `integrity` and `existence` concepts.
- Added manifest `proof_concepts` declarations with stable claim IDs and no mutable registry prose.
- Added audit, verify-file, and report integration for declared Proof Concept results.
- Preserved legacy packet verification with a warning when explicit Proof Concept declarations are absent.
- Added executable Proof of Records support through strict JSON record descriptors, canonical record envelopes, deterministic `rec_...` record IDs, and records claim linkage.
- Added repeatable `prove --record-json` for explicit `--concept records` proofs.
- Added `tohupono record validate` and `tohupono record inspect` for descriptor validation and packet record inspection.
- Added audit and report integration for Proof of Records without asserting metadata truth, authority, ownership, authorship, authenticity, identity, legal validity, or legal admissibility.
- Added executable Proof of Custody support through strict JSON custody descriptors, canonical custody-event envelopes, deterministic `cue_...` event IDs, hash-linked retained event sequences, chain-head validation, and custody claim linkage.
- Added repeatable `prove --custody-json` for explicit `--concept custody` proofs.
- Added `tohupono custody validate` and `tohupono custody inspect` for descriptor validation and packet custody inspection.
- Added audit and report integration for Proof of Custody without asserting physical possession, actor identity, legal custody, complete history, event occurrence, ownership, authorship, authenticity, authority, truth, immutability, or legal admissibility.
- Rewrote `AGENTS.md` as the operating contract for TohuPono development agents.
- Added shared security helpers for path validation, atomic writes, local locks, bounded diagnostics, and text validation.
- Hardened key replacement so `key create --force` records `KEY_REPLACED` and does not delete the active keypair before replacement material is generated and validated.
- Changed `key rotate` to promote a new active key generation while retaining the previous generation for historical verification.
- Added rollback behaviour for key replacement or rotation when lifecycle event persistence fails after key promotion.
- Added canonical key lifecycle events with local tamper-evident hash chaining while preserving legacy rotation and compromise log readability.
- Documented lifecycle truncation limits: unreferenced tail removal may not be detectable without a retained, signed, or externally anchored head checkpoint.
- Added timestamp provider registry placeholders for OpenTimestamps and RFC 3161 without network calls.
- Added project-authored no-macron validation.
- Added timestamp proof model and adapter interface.
- Added `none` and `local` timestamp adapters without network calls.
- Added manifest `timestamping` metadata with `local_only` status for locally created proof packets.
- Added `tohupono timestamp inspect <packet>` human and JSON diagnostics.
- Added offline `tohupono timestamp import <packet> <receipt-file>` receipt metadata import.
- Added `tohupono timestamp verify <packet>` with permissive, evidence-review, and strict-external policies.
- Added timestamp receipt type/status vocabulary and receipt SHA-256 recording.
- Added receipt conflict diagnostics for target mismatch, missing stored receipt bytes, receipt hash mismatch, duplicate IDs, unsupported types, and invalid statuses.
- Added audit warnings for imported but unverified timestamp receipts.
- Added audit FAIL integration for corrupted timestamp receipt metadata under the default evidence-review policy.
- Added audit reporting for missing and local-only timestamp states as `WARN`, not `FAIL`.
- Documented timestamp status vocabulary, imported receipt limits, local-only limits, and planned OpenTimestamps/RFC 3161 adapters.

## v0.4.0 - 2026-07-10

- Added key purpose registry entries for manifest, report, witness, amendment, release, and test purposes.
- Added `tohupono key inspect` for human and JSON key purpose inspection.
- Added `tohupono key check` for local key hygiene diagnostics.
- Added `tohupono key create` for local OpenSSL Ed25519 keypair creation by purpose.
- Added `tohupono key rotate` with JSONL rotation metadata and no old-key deletion.
- Added `tohupono key compromise` with JSONL compromise metadata and warning propagation.
- Added key lifecycle JSON output for rotation and compromise summaries.
- Added `--output-dir` support to `key inspect` and `key check` for key-directory diagnostics.
- Added rotation metadata and compromise metadata records for local key lifecycle review.
- Kept compromise warnings as `WARN`, not `FAIL`, so trust-policy review does not automatically destroy old proofs.
- Added packet audit WARN output for local compromised-key metadata where visible.
- Added `audit --key-directory` to read key lifecycle metadata from an explicit key directory.
- Added audit JSON key lifecycle fields for selected key directories.
- Added a v0.4.0 release checklist for key-management hardening gates.
- Documented key management, key rotation, and key compromise handling.
- Kept OpenSSL CLI Ed25519 signing and existing default key paths.

## v0.3.0 - 2026-07-10

- Added a universal byte-first file object model with `file_id` equal to the SHA-256 byte digest.
- Added deterministic file, proof, manifest, event, and packet identifiers.
- Refused proof packet overwrite by default.
- Added copied and renamed file verification by byte digest.
- Added `compare <file-a> <file-b>` byte-digest comparison.
- Added explicit `verify-file <file> <packet>` verification.
- Added packet-only `verify <packet>` diagnostics.
- Added amendment lineage with `amend <packet> --note` without mutating original packets.
- Added `audit <packet>` technical packet diagnostics.
- Strengthened PASS, WARN, and FAIL verification output.
- Added local timestamp warning behavior for offline proof packets.
- Improved report signature verification material for packet diagnostics.
- Added claim maturity governance for high-risk evidence and legal language.
- Framed proof-of-reality as a layered maturity target, not a current product claim.
- Split the growing MVP test file into focused test suites.

## v0.2.0 - 2026-07-10

- Hardened manifest signing and verification for proof packet tamper evidence.
- Hardened deterministic proof IDs with schema version, tool version, file SHA-256, file size, sealed timestamp, and manifest version.
- Added a manifest version field.
- Added deterministic evidence-chain event hashes and previous-event links.
- Added evidence-chain verification helpers and tamper detection.
- Clarified that file digest is identity and path is metadata.
- Added copied and renamed file verification by byte digest.
- Preserved an any-file, byte-first proof model.
- Extended manifest signature status vocabulary for valid, missing, invalid, unverified, and error states.
- Added evidence-chain status reporting.
- Added `verify --json` structured verification output.
- Added `verify-chain` human and JSON diagnostics for standalone evidence chains.
- Added `inspect-proof` human and JSON proof manifest inspection without source-file verification.
- Strengthened Markdown verification reports with explicit signature, chain, notes, warnings, reasons, and legal-support sections.
- Added CLI exit-code policy for success, verification failure, input errors, and runtime errors.
- Added stable JSON error shape for JSON-mode command failures.
- Added diagnostics workflow and v0.2.0 release-gate documentation.
- Preserved manifest-key and report-key separation.
- Preserved local-first/offline operation and legal-support evidence bundle language.

## v0.1.0

- Added the CLI MVP foundation with `inspect`, `hash`, `prove`, `verify`, and `report` commands.
- Added deterministic proof packet generation with canonical JSON manifests.
- Added manifest signing and verification for proof packet tamper evidence.
- Added verification verdicts including `VERIFIED_INTEGRITY`, `ALTERED_AFTER_PROOF`, `UNPROVEN`, and `PROVENANCE_CONFLICT`.
- Added PDF report generation for legal-support evidence bundle workflows.
- Added detached report signatures over final PDF bytes.
- Added dedicated report-signing key separation from manifest-signing keys.
- Added Community mode branding only, with no feature restrictions.
- Preserved local-first and offline-by-default operation.
- Used OpenSSL CLI Ed25519 signing in this environment because Python `cryptography` is broken at runtime here; this is not custom cryptography.
