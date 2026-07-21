# Proof of Custody

Proof of Custody is one executable Proof Concept inside TohuPono. It does not redefine the project.

## Exact Claim

The proof packet contains a canonical, hash-linked sequence of declared custody events bound to the recorded subject digest, and the retained sequence is internally consistent.

## What It Does Not Prove

Proof of Custody does not prove physical possession, verified actor identity, legal custody, ownership, authorship, authenticity, authority, consent, content truth, complete event history, independently witnessed transfer, external timestamp validity, immutability, legal validity, or legal admissibility.

## Descriptor Schema

Custody descriptors are strict JSON:

```json
{
  "schema_version": "tohupono.custody_descriptor.v1",
  "event_type": "received",
  "actor": {
    "namespace": "local",
    "identifier": "operator-1"
  },
  "occurred_at": null,
  "location": null,
  "reference": null,
  "attributes": {}
}
```

Allowed event types are `created`, `received`, `transferred`, `copied`, `verified`, `stored`, and `released`. Actor fields are declarative only and are not external identity verification. `occurred_at` may be null for a single event. For multiple events it must use canonical UTC form `YYYY-MM-DDTHH:MM:SSZ`. Declared times are metadata, not external timestamp evidence.

The loader rejects duplicate JSON keys, floating-point values, non-finite numbers, excessive depth, excessive item counts, oversized descriptors, unsafe text, directories, symlinks, and material mutation during read.

## Event Envelope

TohuPono injects the subject, sequence, previous-event hash, event hash, and event ID. Descriptors cannot provide those values.

The manifest event envelope contains:

- `event_id`;
- `event_hash`;
- `schema_version`;
- `event_type`;
- `subject`;
- `actor`;
- `occurred_at`;
- `location`;
- `reference`;
- `attributes`;
- `sequence`;
- `previous_event_hash`.

The envelope does not store descriptor paths, descriptor filenames, source paths, hostnames, operating-system timestamps, registry prose, report wording, or maturity labels.

## Hashes and IDs

`event_hash` is SHA-256 over canonical event body data excluding `event_hash` and `event_id`.

`event_id` is `cue_` plus the first 32 hexadecimal characters of `event_hash`.

Changing actor, event type, declared time, location, reference, attributes, subject digest, sequence, or previous-event hash changes the event hash and ID. Descriptor paths and JSON key ordering do not.

## Chain Rules

The first event uses `GENESIS` as `previous_event_hash`. Later events link to the previous retained event hash. Sequence values are contiguous: `1`, `2`, `3`, and so on. The chain head is the final retained event hash.

This is tamper-evident for the retained packet sequence. It is not immutable. Removal of an unreferenced tail or omission of history outside the retained packet may not be detectable without an independently retained, signed, or externally anchored head checkpoint.

## CLI

Proof generation requires explicit concept selection:

```bash
python -m tohupono prove ./file.bin --concept custody --custody-json ./received.json
```

`--custody-json` is repeatable. Supplying it without `--concept custody` is an error. Custody is not part of the default concept set, which remains `existence` and `integrity`.

Inspection commands:

```bash
python -m tohupono custody validate ./received.json
python -m tohupono custody validate ./received.json --json
python -m tohupono custody inspect ./proof_packet
python -m tohupono custody inspect ./proof_packet --json
```

Human output does not dump full arbitrary attributes by default.

## Records and Existence

Records and Custody are separate Proof Concepts with separate manifest sections, claims, result statuses, and limitations. A valid Records result does not establish custody. A valid Custody result does not establish record metadata truth.

Existence evaluates packet timestamp evidence. A declared custody `occurred_at` value is not external timestamp evidence, and a successful Existence result does not automatically verify every custody event time.

## Privacy

Custody actors, locations, references, and attributes are stored in the manifest. Do not place credentials, private keys, secrets, unnecessary personal information, or sensitive location information in custody descriptors.
