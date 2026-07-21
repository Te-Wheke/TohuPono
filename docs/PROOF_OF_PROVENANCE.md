# Proof of Provenance

Proof of Provenance is one executable Proof Concept inside TohuPono. It does not redefine the project and it is not included in the default concept set.

## Exact Claim

The proof packet contains canonical declared lineage relationships binding the recorded subject digest to declared parent digests, and the retained lineage declarations are internally consistent.

## What It Does Not Prove

Proof of Provenance does not prove that a parent file exists, that a parent digest belongs to a genuine source, that the current file was actually derived from a declared parent, who created or modified either file, authorship, ownership, authenticity, verified origin, identity, authority, consent, content truth, originality, first creation, complete lineage, absence of omitted intermediate versions, legal validity, external registration, or external timestamp validity.

## Descriptor Schema

Provenance descriptors are strict JSON:

```json
{
  "schema_version": "tohupono.provenance_descriptor.v1",
  "relation_type": "derived_from",
  "parent": {
    "algorithm": "sha256",
    "digest": "<64 lowercase hexadecimal characters>"
  },
  "operation": {
    "name": "declared-transformation",
    "version": null
  },
  "occurred_at": null,
  "actor": null,
  "reference": null,
  "attributes": {}
}
```

Supported relation types are `derived_from`, `copied_from`, `converted_from`, `edited_from`, `generated_from`, `extracted_from`, and `transcoded_from`. They are declared lineage categories only.

Only SHA-256 parent digests are supported in this schema version. Parent digests are user-declared and are not fetched, resolved, or externally verified. A `copied_from` relation may use the same parent and child digest. Other relation types reject equal parent and child digests because they imply a transformation or generation relationship.

`occurred_at`, when present, must use canonical UTC form `YYYY-MM-DDTHH:MM:SSZ`. It is declared metadata, not external timestamp evidence.

Operation, actor, reference, and attributes are declarative only. TohuPono does not execute operation names, resolve references, contact actors, or upload provenance data.

The loader rejects duplicate JSON keys, floating-point values, non-finite numbers, excessive depth, excessive item counts, oversized descriptors, unsafe text, directories, symlinks, and material mutation during read.

## Edge Envelope

TohuPono injects the child subject from the proved file digest. Descriptors cannot provide `child` or `edge_id`.

The manifest edge envelope contains:

- `edge_id`;
- `schema_version`;
- `relation_type`;
- `child`;
- `parent`;
- `operation`;
- `occurred_at`;
- `actor`;
- `reference`;
- `attributes`.

The envelope does not store descriptor paths, descriptor filenames, source paths, hostnames, operating-system timestamps, registry prose, report wording, or maturity labels.

## Edge IDs

`edge_id` is `prv_` plus the first 32 hexadecimal characters of SHA-256 over the canonical edge body excluding `edge_id`.

Changing the child digest, parent digest, relation type, operation, occurred time, actor, reference, or attributes changes the edge ID. Descriptor paths and JSON key ordering do not.

## Manifest and Claim Linkage

A provenance proof includes a top-level `provenance` section only when `--concept provenance` is selected. The section stores `schema_version`, `edge_count`, and canonical edges sorted by `edge_id`.

The `provenance` Proof Concept claim stores the provenance schema version, sorted edge IDs, and the child digest. Verification fails if the claim and stored provenance section diverge.

## CLI

```bash
python -m tohupono prove ./file.bin --concept provenance --provenance-json ./lineage.json
python -m tohupono provenance validate ./lineage.json
python -m tohupono provenance inspect ./proof_packet
```

Supplying `--provenance-json` without `--concept provenance` is an input error. Selecting `provenance` without at least one descriptor is also an input error. Provenance is not part of the default concept set; default proof generation remains `existence` and `integrity`.

## Privacy

Provenance descriptors and manifest edges may expose parent digests, operations, actors, references, and attributes. Do not place credentials, private keys, secrets, unnecessary personal information, or sensitive operational details in provenance descriptors.

## Legacy Behavior

Packets without a `provenance` section or explicit `provenance` Proof Concept remain loadable, verifiable, auditable, reportable, proof-ID-compatible, and signature-compatible. TohuPono does not infer Provenance from Records, Custody, or older metadata fields.
