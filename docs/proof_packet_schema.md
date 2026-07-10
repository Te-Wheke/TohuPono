# Proof Packet Schema Notes

MVP proof packets use `tohupono.proof_manifest.v0.1`.

The manifest is written as canonical JSON using UTF-8, sorted keys, and stable separators. `proof_id` is deterministic and derived from canonical proof data.

## v0.3.0 Development Notes

The file object is byte-first. `file_id` is the SHA-256 digest of the source bytes. The object may also include original path, filename, extension, MIME guess, size, and OS timestamps, but those values are labelled as `untrusted_supporting_metadata`.

Deterministic identifiers:

- `file_id`: SHA-256 of file bytes.
- `proof_id`: SHA-256 over stable proof fields, excluding unstable paths.
- `manifest_id`: SHA-256 over the canonical manifest with signatures and self-referential packet IDs removed.
- `event_id`: SHA-256 over previous event hash plus canonical event payload.
- `packet_id`: SHA-256 over `manifest_id` plus evidence-chain root.

Proof packet verification checks required files, manifest schema, reproducible IDs, evidence-chain hashes, manifest signature, optional report signature material, and local timestamp limitations. Missing external timestamp anchoring is a `WARN`, not a `FAIL`.

`tohupono amend <packet> --note "..."` creates a separate amendment record beside the original packet. The original packet is not modified.

## v0.2.0 Development Notes

`proof_id` is derived from canonical seed data:

- `schema_version`
- `tool_version`
- `file_sha256`
- `file_size`
- `manifest_version`

The source file path, name, extension, and MIME type are observed metadata. They are not file identity. A copied or renamed file verifies when its byte digest matches the proof manifest.

`tohupono inspect-proof <manifest.json>` reads a manifest and nearby proof packet artefacts without verifying a source file. It reports packet status only. `tohupono verify <file> --proof <manifest.json>` is required to compare file bytes with the proof manifest.

`evidence_chain.jsonl` contains deterministic JSON lines. Each event includes:

- `event_id`
- `event_type`
- `timestamp`
- `actor`
- `file_sha256`
- `previous_event_hash`
- `event_hash`

`event_hash` is calculated over the canonical event without `event_hash`. This makes recorded chain events tamper-evident within the proof packet. It does not prove external truth or legal admissibility.

Manifest signature status values:

- `valid`
- `missing`
- `invalid`
- `unverified`
- `error`

Evidence-chain status values:

- `valid`
- `missing`
- `invalid`
- `error`

`tohupono verify --json`, `tohupono verify-chain --json`, and `tohupono inspect-proof --json` produce parseable JSON for automation. Human-readable diagnostics are used only when JSON mode is not selected.

Legal-support boundary: This report supports evidence review by recording deterministic file identity, verification results, signatures, and proof-packet status. It does not by itself prove real-world truth, authorship, intent, or legal admissibility.

## CLI Diagnostics

`verify --json` includes verdict, classification, file digest, expected digest, manifest signature status, evidence-chain status, warnings, reasons, and notes.

`verify-chain` checks a standalone `evidence_chain.jsonl` and reports one of `valid`, `missing`, `invalid`, or `error`.

`inspect-proof` reads a manifest and nearby proof packet files without checking a source file. It is useful for packet triage, but source-file verification still requires `verify <file> --proof <manifest.json>`.

JSON-mode command errors use:

```json
{
  "status": "error",
  "error": {
    "code": "MISSING_FILE",
    "message": "..."
  }
}
```

CLI exit codes:

- `0`: success
- `1`: verification failed or proof conflict
- `2`: user or input error
- `3`: internal or runtime error
