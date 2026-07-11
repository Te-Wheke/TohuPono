# Proof Concepts

TohuPono is a headless, deterministic, local-first proof protocol organised around modular Proof Concepts.

A Proof Concept is a bounded claim model. It defines what is being claimed, what evidence is required, how verification works, what assumptions are trusted, what failure looks like, and what the current implementation maturity is.

Registry presence does not imply operational support.

Executable status is controlled by a separate execution registry. In this slice, only `integrity` and `existence` are executable.

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
| records | locally_supported | Manifests, signatures, evidence chains, amendments and reports are supported; external record-management requirements are not fully established. |
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
```

`concept list` reports concept ID, display name, maturity, executable status, and concise claim boundary. `concept inspect` expands the exact claim, subject, evidence, verification procedure, trust assumptions, failure conditions, limitations, privacy implications, and legal boundary.

## Proof Generation

`prove` accepts repeatable concept selection:

```bash
python -m tohupono prove ./file.bin --concept integrity
python -m tohupono prove ./file.bin --concept integrity --concept existence
```

When no concept is supplied, `prove` requests `integrity` and `existence`. TohuPono does not provide `--all`; a proof operation must not silently claim every registered concept.

The selected concept IDs are canonicalised and stored in the manifest. Changing selected concept IDs changes proof identity. Changing registry descriptions, display names, maturity wording, or legal text does not change proof identity.

## Legacy Packets

Packets created before explicit Proof Concept declarations remain loadable and verifiable. They are reported as legacy packets with inferred diagnostic coverage. TohuPono does not mutate the stored manifest or claim that older packets explicitly requested concepts.
