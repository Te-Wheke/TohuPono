# Changelog

## v0.5.0 - 2026-07-21

- Added modular Proof Concepts governance, registry inspection, deterministic concept claims, and executable verification for `integrity`, `existence`, `records`, `custody`, `provenance`, `transaction`, and `identity`.
- Kept default Proof Concepts limited to `existence` and `integrity`; non-default concepts require explicit `--concept` selection and their descriptor flags.
- Added strict descriptor parsing, canonical manifest sections, deterministic IDs, subject-digest binding, exact claim linkage, audit integration, report integration, validation CLI commands, and inspection CLI commands for Records, Custody, Provenance, Transaction, and Identity.
- Preserved concept separation: Records, Custody, Provenance, Transaction, and Identity remain packet-internal declared metadata consistency checks and do not establish truth, authenticity, authorship, ownership, consent, authority, legal effect, payment, delivery, verified identity, external registration, or complete history.
- Added timestamp adapter interfaces, `none` and `local` adapters, offline receipt import, receipt diagnostics, timestamp verification policies, and placeholder OpenTimestamps/RFC 3161 provider interfaces without network calls or external timestamp verification.
- Hardened timestamp evidence handling so packet-controlled `anchored` or `verified` metadata cannot self-authorise external timestamp status; stored receipts use bounded regular-file reads, path containment, symlink rejection, and no-follow write protections.
- Strengthened deterministic integrity by preserving canonical manifests, deterministic proof identifiers, manifest IDs, packet IDs, evidence-chain validation, deterministic claim ordering, copy/rename byte-digest semantics, and tamper detection.
- Hardened malformed concept data handling with strict collection-level field validation for Records, Custody, Provenance, Transaction, and Identity, fail-closed claim linkage, duplicate detection, and reordered Records claim rejection.
- Preserved the active key interface as `--key-directory` / `key_directory` and kept active `--key-workspace` / `key_workspace` use absent.
- Preserved `create_proof_packet` positional compatibility by appending new descriptor parameters after existing Provenance and Transaction slots.
- Added lazy report-renderer imports so CLI version/help and non-report commands start without eager ReportLab/Pillow loading, while report generation and detached report signatures remain supported.
- Added project-authored no-macron validation, C1 control-character rejection, shared path/atomic/lock/bounded-input helpers, and key lifecycle hardening with legacy log compatibility.
- Preserved v0.4.0 packet audit, report, proof-ID, manifest-signature, and report-signature compatibility.
- Deferred non-blocking hardening: broader descriptor no-follow helper reuse, key lifecycle JSONL concurrency hardening, further human-output path sanitisation, and hostile-symlink hardening for `scripts/check_no_macrons.py`.

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
