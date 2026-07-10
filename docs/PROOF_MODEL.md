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
