# Proof Model

The core authority is the file digest.

- `file_id` is the SHA-256 digest of file bytes.
- Files are read as raw bytes before metadata is considered.
- Paths, names, extensions, MIME guesses, and OS timestamps are context only.
- Metadata is recorded as `untrusted_supporting_metadata`.

Deterministic IDs:

- `proof_id`: stable proof fields such as schema version, tool version, manifest version, file size, and SHA-256.
- `manifest_id`: canonical manifest with signatures and self-referential packet IDs removed.
- `event_id`: previous event hash plus canonical event payload.
- `packet_id`: manifest ID plus evidence-chain root.

Proof packets are immutable by default. A correction is represented by an amendment packet, not by editing the sealed packet.

Timestamping:

- proof manifests may include a `timestamping` section;
- `local_only` records local system time and target digest only;
- local timestamps are not external anchors;
- missing or local-only timestamping is a warning, not a verification failure;
- OpenTimestamps and RFC 3161 are planned adapter types, not implemented network integrations in this slice.
- imported timestamp receipts are stored as packet evidence with receipt hash, size, target digest, import time, and warning metadata;
- imported receipts remain `unverified` until an adapter can verify the receipt format and external timestamp service.
- timestamp verification policies are `permissive`, `evidence_review`, and `strict_external`;
- packet audit uses `evidence_review`, where local-only and unverified receipts are WARN but receipt conflicts are FAIL.

The proof ID seed remains based on stable file and proof fields. Timestamping metadata is recorded for evidence review but must not be overstated as legal finality.
