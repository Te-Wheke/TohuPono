# Proof of Records

Proof of Records is one executable Proof Concept inside TohuPono. It is not the entire TohuPono architecture.

## Exact Claim

A canonical record envelope describing the subject digest and declared metadata is present in the proof packet and remains internally consistent with the packet's recorded subject.

Proof of Records can support review that:

- the record envelope is present;
- the record envelope has a deterministic identifier;
- the record envelope is canonical;
- the record envelope references the packet subject digest;
- the records claim references the expected record identifiers;
- the packet contains the record metadata declared during proof generation.

It does not prove:

- declared metadata truth;
- external authority;
- legal authority;
- ownership;
- possession;
- authorship;
- authenticity;
- identity;
- consent;
- legal admissibility;
- legal status;
- completeness of history;
- accuracy of an external reference;
- recognition by a government, court, registry, or institution.

## Descriptor Schema

Record descriptors are strict JSON:

```json
{
  "schema_version": "tohupono.record_descriptor.v1",
  "record_type": "generic",
  "namespace": "local",
  "reference": null,
  "attributes": {}
}
```

`record_type` currently supports only `generic`.

`namespace` is a declarative classification. It does not prove registration, authority, ownership, or institutional recognition.

`reference` is an optional user-declared string. TohuPono does not fetch, resolve, or verify it.

`attributes` is a canonical JSON object of user-declared metadata. Attributes are stored in the proof manifest, so do not place secrets, private keys, credentials, or unnecessarily sensitive information in attributes.

## Strict JSON Rules

Descriptor parsing rejects:

- duplicate object keys;
- floating-point values;
- NaN and Infinity;
- excessive descriptor size;
- excessive nesting;
- excessive object or array size;
- NUL characters;
- ASCII control characters;
- Unicode bidirectional controls;
- unsupported fields;
- unsupported schema versions;
- unsupported record types.

Descriptor paths are treated as local input and are not stored in the manifest. Descriptor symlinks, directories, and unsafe paths are rejected.

## Record Envelope

TohuPono injects the subject digest into the canonical envelope:

```json
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
```

Descriptors cannot provide the subject digest. This prevents a descriptor from binding itself to a different subject.

The envelope does not include descriptor paths, descriptor filenames, source paths, host information, OS timestamps, registry prose, maturity descriptions, CLI formatting, or report text.

## Record IDs

`record_id` is:

```text
rec_<first 32 hexadecimal characters of SHA-256>
```

The hash input is the canonical record body excluding `record_id`.

Changing attributes, namespace, reference, or subject digest changes the record ID. JSON object key order, descriptor filename, descriptor path, and CLI descriptor ordering do not change the record ID.

## Proof Generation

Proof of Records is explicit:

```bash
python -m tohupono prove ./file.bin --concept records --record-json ./record.json
```

Multiple descriptors are allowed:

```bash
python -m tohupono prove ./file.bin --concept records --record-json ./first.json --record-json ./second.json
```

When `records` is selected, at least one descriptor is required. Supplying `--record-json` without `--concept records` is an input error. Records are not included in the default concept set; default proof generation remains `existence` and `integrity`.

## Manifest Storage

New records proofs include:

```json
{
  "records": {
    "schema_version": "tohupono.records.v1",
    "items": []
  }
}
```

Record envelopes are sorted by `record_id`. Duplicate record IDs fail. The records claim references every stored record exactly once. Verification fails if claimed and stored record IDs diverge.

## Verification

Proof of Records passes only when:

- the records section schema is supported;
- at least one record is stored;
- every record envelope is structurally valid;
- every record ID recomputes correctly;
- every record subject digest matches the packet subject digest;
- all record IDs are unique;
- the records concept claim references exactly the stored records.

Malformed explicit records claims fail closed. Packets that do not declare `records` are not evaluated for Proof of Records.

## CLI

```bash
python -m tohupono record validate ./record.json
python -m tohupono record validate ./record.json --json
python -m tohupono record inspect ./proof_packet
python -m tohupono record inspect ./proof_packet --json
```

Human output summarizes records without dumping full attributes by default. JSON inspection includes canonical stored envelopes because the user explicitly requested machine-readable output.

## Reports

Reports include a Proof of Records section for records proofs. Reports show record IDs, record type, namespace, declared reference, subject-binding status, and limitations. Reports do not present declared metadata as true, authoritative, complete, or legally valid.

## Legacy Packets

Legacy packets without a `records` section or explicit `records` Proof Concept remain loadable, verifiable, auditable, reportable, and signature-compatible. TohuPono does not infer Proof of Records for legacy packets.
