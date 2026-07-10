# Changelog

## Unreleased

- Added key purpose registry entries for manifest, report, witness, amendment, release, and test purposes.
- Added `tohupono key inspect` for human and JSON key purpose inspection.
- Added `tohupono key check` for local key hygiene diagnostics.
- Added `tohupono key create` for local OpenSSL Ed25519 keypair creation by purpose.
- Added `tohupono key rotate` with JSONL rotation metadata and no old-key deletion.
- Added `tohupono key compromise` with JSONL compromise metadata and warning propagation.
- Added `--output-dir` support to `key inspect` and `key check` for workspace-aware key diagnostics.
- Added packet audit WARN output for local compromised-key metadata where visible.
- Documented key management, rotation, and compromise handling.
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
