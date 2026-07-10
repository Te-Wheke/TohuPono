# Proof Packet Schema Notes

MVP proof packets use `tohupono.proof_manifest.v0.1`.

The manifest is written as canonical JSON using UTF-8, sorted keys, and stable separators. `proof_id` is deterministic and derived from canonical proof data.

## v0.2.0 Development Notes

`proof_id` is derived from canonical seed data:

- `schema_version`
- `tool_version`
- `file_sha256`
- `file_size`
- `sealed_timestamp`
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
