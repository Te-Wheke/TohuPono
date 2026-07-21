# Proof Model

TohuPono is organised around modular Proof Concepts. Each concept defines its own claim, subject, evidence, verification procedure, trust assumptions, failure conditions, implementation maturity, limitations, privacy implications, and legal boundary.

The core authority for file identity is the file digest.

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
- OpenTimestamps and RFC 3161 are planned adapter types, not implemented network integrations in v0.5.0.
- imported timestamp receipts are stored as packet evidence with receipt hash, size, target digest, import time, and warning metadata;
- imported receipts remain `unverified` until an adapter can verify the receipt format and external timestamp service.
- timestamp verification policies are `permissive`, `evidence_review`, and `strict_external`;
- packet audit uses `evidence_review`, where local-only and unverified receipts are WARN but receipt conflicts are FAIL.

The proof ID seed remains based on stable file and proof fields. Timestamping metadata is recorded for evidence review but must not be overstated as legal finality.

Proof Concept registry metadata is descriptive governance data. It must not alter deterministic proof identifiers.

## Executable Proof Concepts

Executable Proof Concepts are:

- `integrity`;
- `existence`;
- `records`;
- `custody`;
- `provenance`;
- `transaction`;
- `identity`.

Registered concepts such as `authenticity`, `ownership`, and `reality` are not made executable merely by appearing in the registry.

New proof manifests include a top-level `proof_concepts` declaration:

```json
{
  "schema_version": "tohupono.proof_concepts.v1",
  "requested": ["existence", "integrity"],
  "claims": []
}
```

Claim records contain stable machine data: `claim_id`, `concept_id`, `subject`, and `parameters`. They do not embed display names, roadmap text, maturity descriptions, legal commentary, or other mutable registry prose.

When no `--concept` option is supplied, `prove` defaults to `integrity` and `existence`. Concept IDs are sorted after validation, so CLI order does not alter proof identity. Changing the selected concept set does alter proof identity.

Proof of Records is explicit and descriptor-driven. It is not included in the default concept set. A records proof requires `--concept records` and at least one `--record-json` descriptor. New records packets include a top-level `records` section:

```json
{
  "schema_version": "tohupono.records.v1",
  "items": [
    {
      "record_id": "rec_...",
      "schema_version": "tohupono.record.v1",
      "record_type": "generic",
      "namespace": "local",
      "reference": null,
      "subject": {
        "algorithm": "sha256",
        "digest": "..."
      },
      "attributes": {}
    }
  ]
}
```

`record_id` is derived from the canonical record body excluding `record_id`. Record envelopes are sorted by record ID, and descriptor file paths, descriptor filenames, registry prose, display names, maturity wording, and report text are excluded from record identity and proof identity.

The `records` Proof Concept claim references every stored record ID exactly once. Verification fails if stored records and claimed record IDs diverge, if a record ID does not recompute, or if a record subject digest does not match the packet subject digest.

Proof of Custody is explicit and descriptor-driven. It is not included in the default concept set. A custody proof requires `--concept custody` and at least one `--custody-json` descriptor. New custody packets include a top-level `custody` section:

```json
{
  "schema_version": "tohupono.custody.v1",
  "event_count": 1,
  "chain_head": "...",
  "events": [
    {
      "event_id": "cue_...",
      "event_hash": "...",
      "schema_version": "tohupono.custody_event.v1",
      "event_type": "received",
      "subject": {
        "algorithm": "sha256",
        "digest": "..."
      },
      "actor": {
        "namespace": "local",
        "identifier": "operator-1"
      },
      "occurred_at": null,
      "location": null,
      "reference": null,
      "attributes": {},
      "sequence": 1,
      "previous_event_hash": "GENESIS"
    }
  ]
}
```

`event_hash` is SHA-256 over the canonical event body excluding `event_hash` and `event_id`; `event_id` is `cue_` plus the first 32 hexadecimal characters of that hash. Sequence values are contiguous, the first previous hash is `GENESIS`, later previous hashes match the prior retained event, and the chain head is the final retained event hash. This is tamper-evident for the retained sequence, not immutable and not proof of complete real-world history.

The `custody` Proof Concept claim references event IDs in retained sequence order and the stored chain head. Verification fails if the claim and stored custody section diverge.

Proof of Provenance is explicit and descriptor-driven. It is not included in the default concept set. A provenance proof requires `--concept provenance` and at least one `--provenance-json` descriptor. New provenance packets include a top-level `provenance` section with `schema_version`, `edge_count`, and canonical edges sorted by `edge_id`.

`edge_id` is `prv_` plus the first 32 hexadecimal characters of SHA-256 over the canonical edge body excluding `edge_id`. The child digest is injected from the proved subject. Parent digests, operations, actors, references, occurred-time values, and attributes are declared metadata only.

The `provenance` Proof Concept claim references stored edge IDs and the child digest. Verification fails if the claim and stored provenance section diverge.

Proof of Transaction is explicit and descriptor-driven. It is not included in the default concept set. A transaction proof requires `--concept transaction` and at least one `--transaction-json` descriptor. New transaction packets include a top-level `transactions` section with `schema_version`, `transaction_count`, and canonical transaction envelopes sorted by `transaction_id`.

`transaction_id` is `txn_` plus the first 32 hexadecimal characters of SHA-256 over the canonical transaction body excluding `transaction_id`. The subject digest is injected from the proved subject. Participants, references, terms, occurred-time values, and attributes are declared metadata only.

The `transaction` Proof Concept claim references stored transaction IDs and the subject digest. Verification fails if the claim and stored transaction section diverge.

Proof of Identity is explicit and descriptor-driven. It is not included in the default concept set. An identity proof requires `--concept identity` and at least one `--identity-json` descriptor. New identity packets include a top-level `identities` section with `schema_version`, `assertion_count`, and canonical identity assertion envelopes sorted by `assertion_id`.

`assertion_id` is `idn_` plus the first 32 hexadecimal characters of SHA-256 over the canonical assertion body excluding `assertion_id`. The subject digest is injected from the proved subject. Namespaces, identifiers, display names, key fingerprints, references, and attributes are declared metadata only.

The `identity` Proof Concept claim references stored assertion IDs and the subject digest. Verification fails if the claim and stored identity section diverge.

Legacy manifests without `proof_concepts` remain verifiable. TohuPono does not fabricate stored declarations for legacy packets; it reports inferred legacy checks separately.

Initial maturity assignments:

- `integrity`: `locally_supported`;
- `existence`: `locally_supported`, limited to local timestamp and imported-receipt handling;
- `records`: `locally_supported`, limited to canonical packet-internal record envelopes and subject-digest linkage;
- `custody`: `locally_supported`, limited to canonical packet-internal custody-event envelopes and retained hash-link consistency;
- `provenance`: `locally_supported`, limited to canonical packet-internal declared lineage edges and child/parent digest linkage;
- `transaction`: `locally_supported`, limited to canonical packet-internal declared transaction envelopes and subject/participant linkage;
- `identity`: `locally_supported`, limited to canonical packet-internal declared identity assertions and subject/identifier linkage;
- `lineage`: `locally_supported`, limited to recorded relationships;
- `authenticity`: `modelled`;
- `ownership`: `modelled`;
- `reality`: `modelled`.
