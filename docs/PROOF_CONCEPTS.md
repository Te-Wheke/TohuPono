# Proof Concepts

TohuPono is a headless, deterministic, local-first proof protocol organised around modular Proof Concepts.

A Proof Concept is a bounded claim model. It defines what is being claimed, what evidence is required, how verification works, what assumptions are trusted, what failure looks like, and what the current implementation maturity is.

Registry presence does not imply operational support.

Executable status is controlled by a separate execution registry. In this slice, `integrity`, `existence`, and `records` are executable.

## Maturity Values

- `unmodelled`
- `modelled`
- `interface_defined`
- `locally_supported`
- `externally_supported`
- `verified_implementation`
- `experimental`
- `deprecated`

Do not store or emit undeclared maturity values.

## Layered Assessment Values

- `unassessed`
- `unsupported`
- `weakly_supported`
- `moderately_supported`
- `strong_local_evidence_support`
- `strong_externally_verified_support`
- `conflicting_evidence`
- `altered_after_proof`
- `unable_to_verify`

These are not binary REAL or FAKE labels.

## Initial Support Matrix

| Concept | Maturity | Boundary |
| --- | --- | --- |
| integrity | locally_supported | Digest and packet checks support byte-level integrity only. |
| existence | locally_supported | Local timestamp and imported-receipt handling are available; independently verified external timestamping is absent. |
| records | locally_supported | Canonical record envelopes can be declared, stored, linked to the subject digest, and verified for packet-internal consistency. Declared metadata truth, authority, completeness, ownership, identity, authorship, authenticity, legal validity, and external record-management requirements are not established. |
| lineage | locally_supported | Recorded relationships are assessed; completeness of history is not proven. |
| authenticity | modelled | Digest and signature checks do not establish real-world authenticity. |
| ownership | modelled | Requires identity, authority, entitlement and jurisdiction-specific external evidence. |
| reality | modelled | Long-term layered assessment only; no current binary or conclusive implementation. |

## Claim Boundary Rules

- Integrity does not imply authenticity.
- Possession does not imply ownership.
- A signature does not imply legal identity or authorship.
- A timestamp does not prove content truth.
- Recorded lineage does not prove that no history is missing.
- Proof of Reality requires layered independent evidence.

## Extension Rules

Every new concept entry must define:

- exact claim;
- subject of the claim;
- required evidence;
- verification procedure;
- trust assumptions;
- failure conditions;
- implementation maturity;
- known limitations;
- privacy implications;
- legal boundary.

Concept metadata is governance data. It must not alter deterministic proof identifiers.

## CLI

```bash
python -m tohupono concept list
python -m tohupono concept list --json
python -m tohupono concept inspect integrity
python -m tohupono concept inspect existence --json
python -m tohupono concept inspect records --json
```

`concept list` reports concept ID, display name, maturity, executable status, and concise claim boundary. `concept inspect` expands the exact claim, subject, evidence, verification procedure, trust assumptions, failure conditions, limitations, privacy implications, and legal boundary.

## Proof Generation

`prove` accepts repeatable concept selection:

```bash
python -m tohupono prove ./file.bin --concept integrity
python -m tohupono prove ./file.bin --concept integrity --concept existence
python -m tohupono prove ./file.bin --concept records --record-json ./record.json
```

When no concept is supplied, `prove` requests `integrity` and `existence`. TohuPono does not provide `--all`; a proof operation must not silently claim every registered concept.

The selected concept IDs are canonicalised and stored in the manifest. Changing selected concept IDs changes proof identity. Changing registry descriptions, display names, maturity wording, or legal text does not change proof identity.

`records` is not part of the default concept set. To request Proof of Records, select `--concept records` and provide at least one strict JSON descriptor with `--record-json`. Supplying `--record-json` without selecting `records` is an input error.

## Proof of Records

Proof of Records makes a narrow packet-internal claim: a canonical record envelope describing the subject digest and declared metadata is present in the proof packet and remains internally consistent with the packet's recorded subject.

It can verify that:

- a record envelope is present;
- the envelope has a deterministic `rec_...` identifier;
- the envelope is canonical;
- the envelope references the packet subject digest;
- the records claim references the stored record identifiers exactly.

It does not verify that declared metadata is true, authoritative, complete, externally registered, legally valid, or connected to ownership, possession, authorship, authenticity, identity, consent, or authority.

Record descriptors use strict JSON:

```json
{
  "schema_version": "tohupono.record_descriptor.v1",
  "record_type": "generic",
  "namespace": "local",
  "reference": null,
  "attributes": {}
}
```

Record attributes are stored in the manifest. Do not place secrets, private keys, credentials, or unnecessarily sensitive information in record attributes.

## Legacy Packets

Packets created before explicit Proof Concept declarations remain loadable and verifiable. They are reported as legacy packets with inferred diagnostic coverage. TohuPono does not mutate the stored manifest or claim that older packets explicitly requested concepts.
