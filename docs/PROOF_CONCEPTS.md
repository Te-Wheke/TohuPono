# Proof Concepts

TohuPono is a headless, deterministic, local-first proof protocol organised around modular Proof Concepts.

A Proof Concept is a bounded claim model. It defines what is being claimed, what evidence is required, how verification works, what assumptions are trusted, what failure looks like, and what the current implementation maturity is.

Registry presence does not imply operational support.

Executable status is controlled by a separate execution registry. In this slice, `integrity`, `existence`, `records`, `custody`, `provenance`, `transaction`, and `identity` are executable.

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
| custody | locally_supported | Canonical custody-event envelopes can be declared, hash-linked, bound to the subject digest, and verified for retained packet-internal consistency. Physical possession, actor identity, legal custody, complete history, event occurrence, ownership, authorship, authenticity, authority, truth, immutability, and legal admissibility are not established. |
| provenance | locally_supported | Canonical declared lineage edges can be bound to the subject digest and declared parent digests. Parent existence, actual derivation, verified origin, authorship, ownership, authenticity, authority, truth, complete lineage, legal validity, and external registration are not established. |
| transaction | locally_supported | Canonical declared transaction envelopes can be bound to the subject digest and declared participants. Transaction occurrence, payment, delivery, participant identity, consent, authority, ownership transfer, legal effect, authenticity, authorship, and enforceability are not established. |
| identity | locally_supported | Canonical declared identity assertions can be bound to the subject digest and declared identifiers. Verified identity, personhood, organisational status, account ownership, key control, authority, authorship, ownership, consent, legal identity, and external validation are not established. |
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
python -m tohupono concept inspect custody --json
python -m tohupono concept inspect provenance --json
python -m tohupono concept inspect transaction --json
python -m tohupono concept inspect identity --json
```

`concept list` reports concept ID, display name, maturity, executable status, and concise claim boundary. `concept inspect` expands the exact claim, subject, evidence, verification procedure, trust assumptions, failure conditions, limitations, privacy implications, and legal boundary.

## Proof Generation

`prove` accepts repeatable concept selection:

```bash
python -m tohupono prove ./file.bin --concept integrity
python -m tohupono prove ./file.bin --concept integrity --concept existence
python -m tohupono prove ./file.bin --concept records --record-json ./record.json
python -m tohupono prove ./file.bin --concept custody --custody-json ./custody.json
python -m tohupono prove ./file.bin --concept provenance --provenance-json ./lineage.json
python -m tohupono prove ./file.bin --concept transaction --transaction-json ./transfer.json
python -m tohupono prove ./file.bin --concept identity --identity-json ./identity.json
```

When no concept is supplied, `prove` requests `integrity` and `existence`. TohuPono does not provide `--all`; a proof operation must not silently claim every registered concept.

The selected concept IDs are canonicalised and stored in the manifest. Changing selected concept IDs changes proof identity. Changing registry descriptions, display names, maturity wording, or legal text does not change proof identity.

`records` is not part of the default concept set. To request Proof of Records, select `--concept records` and provide at least one strict JSON descriptor with `--record-json`. Supplying `--record-json` without selecting `records` is an input error.

`custody` is not part of the default concept set. To request Proof of Custody, select `--concept custody` and provide at least one strict JSON descriptor with `--custody-json`. Supplying `--custody-json` without selecting `custody` is an input error.

`provenance` is not part of the default concept set. To request Proof of Provenance, select `--concept provenance` and provide at least one strict JSON descriptor with `--provenance-json`. Supplying `--provenance-json` without selecting `provenance` is an input error.

`transaction` is not part of the default concept set. To request Proof of Transaction, select `--concept transaction` and provide at least one strict JSON descriptor with `--transaction-json`. Supplying `--transaction-json` without selecting `transaction` is an input error.

`identity` is not part of the default concept set. To request Proof of Identity, select `--concept identity` and provide at least one strict JSON descriptor with `--identity-json`. Supplying `--identity-json` without selecting `identity` is an input error.

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

## Proof of Custody

Proof of Custody makes a narrow packet-internal claim: the proof packet contains a canonical, hash-linked sequence of declared custody events bound to the recorded subject digest, and the retained sequence is internally consistent.

It can verify that:

- custody event envelopes are present;
- event IDs use deterministic `cue_...` identifiers derived from canonical event bodies;
- each event is bound to the packet subject digest;
- each retained event links to the expected previous event hash;
- the retained chain head matches the final event hash;
- the custody claim references the retained event IDs and chain head exactly.

It does not prove physical possession, actor identity, legal custody, ownership, authorship, authenticity, authority, consent, content truth, complete event history, absence of earlier or later events, independently witnessed transfer, external timestamp validity, immutability, legal validity, or legal admissibility.

Custody descriptors use strict JSON:

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

Allowed event types are `created`, `received`, `transferred`, `copied`, `verified`, `stored`, and `released`. Actor, location, reference, occurred-time, and attributes are declared metadata only. Declared `occurred_at` values use `YYYY-MM-DDTHH:MM:SSZ` when present and are not external timestamp evidence.

For multiple custody events, descriptors must provide `occurred_at`; events are ordered by occurred time and then by canonical descriptor digest as a deterministic tiebreaker. A single event may omit `occurred_at`.

Custody data is stored in the manifest. Do not place credentials, private keys, secrets, unnecessary personal information, or sensitive location information in custody descriptors.

## Proof of Provenance

Proof of Provenance makes a narrow packet-internal claim: the proof packet contains canonical declared lineage relationships binding the recorded subject digest to declared parent digests, and the retained lineage declarations are internally consistent.

It does not prove that parent files exist, that declared transformations occurred, verified origin, authorship, ownership, authenticity, authority, consent, content truth, complete lineage, legal validity, external registration, or external timestamp validity. Parent digests, operations, actors, references, occurred-time values, and attributes are declared metadata only.

Provenance descriptors use strict JSON and create canonical `prv_...` edge identifiers. The current proved subject digest is injected as the child; descriptors cannot provide child digests or edge IDs.

## Proof of Transaction

Proof of Transaction makes a narrow packet-internal claim: the proof packet contains canonical declared transaction envelopes binding the recorded subject digest to declared participants and transaction metadata, and the retained declarations are internally consistent.

It does not prove that a transaction occurred, payment occurred, delivery occurred, participants are verified identities, participants consented, participants had authority, ownership transferred, a contract formed, legal validity, enforceability, authenticity, authorship, external registration, external timestamp validity, or complete transaction history. Participants, references, terms, occurred-time values, and attributes are declared metadata only.

Transaction descriptors use strict JSON and create canonical `txn_...` identifiers. The current proved subject digest is injected; descriptors cannot provide subject digests, transaction IDs, proof IDs, or claim IDs.

Proof of Identity makes a narrow packet-internal claim: the proof packet contains canonical declared identity assertions binding the recorded subject digest to declared identifiers, and the retained assertions are internally consistent.

It does not prove that an identifier belongs to a real person or organisation, that an identity exists outside the packet, verified personhood, verified organisational status, government recognition, account ownership, control of a cryptographic key, authorship, ownership, authority, consent, authenticity, legal identity, legal capacity, external registration, or external validation.

Identity descriptors use strict JSON and create canonical `idn_...` identifiers. The current proved subject digest is injected; descriptors cannot provide subject digests, assertion IDs, proof IDs, claim IDs, or verification status. Identity descriptor data is stored in the manifest. Do not place credentials, private keys, authentication tokens, government identifier numbers, unnecessary personal information, or sensitive identity data in identity descriptors.

## Legacy Packets

Packets created before explicit Proof Concept declarations remain loadable and verifiable. They are reported as legacy packets with inferred diagnostic coverage. TohuPono does not mutate the stored manifest or claim that older packets explicitly requested concepts.
