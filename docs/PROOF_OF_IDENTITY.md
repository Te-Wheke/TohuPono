# Proof of Identity

Proof of Identity is one executable Proof Concept inside TohuPono. It is a packet-internal identity-declaration model, not an identity provider, account resolver, certificate authority, biometric system, or legal identity service.

## Exact Claim

The proof packet contains canonical declared identity assertions binding the recorded subject digest to declared identifiers, and the retained assertions are internally consistent.

## What It Does Not Prove

Proof of Identity does not prove that an identifier belongs to a real person or organisation, that an identity exists outside the packet, verified personhood, verified organisational status, government recognition, account ownership, control of a cryptographic key, authorship, ownership, authority, consent, authenticity, legal identity, legal capacity, external registration, or external validation.

## Descriptor Schema

Identity descriptors are strict JSON:

```json
{
  "schema_version": "tohupono.identity_descriptor.v1",
  "assertion_type": "associated_with",
  "identity": {
    "namespace": "local",
    "identifier": "party-a",
    "display_name": null
  },
  "key_fingerprint": null,
  "reference": null,
  "attributes": {}
}
```

The only supported assertion type in this schema version is `associated_with`. It means only that the packet declares an association between the subject digest and identifier.

Namespaces are bounded lowercase tokens matching `[a-z][a-z0-9._-]{0,31}`. Identifiers are bounded safe strings. Display names are presentation metadata only.

Optional key fingerprints use:

```json
{
  "algorithm": "sha256",
  "digest": "<64 lowercase hexadecimal characters>"
}
```

A key fingerprint is declared metadata only. It does not prove the key exists, belongs to the declared identity, is controlled by the declarant, or signed the packet.

References and attributes are declarative only. TohuPono does not resolve identifiers, resolve DIDs or URIs, contact identity providers, fetch references, inspect accounts, execute attributes, verify government records, or upload identity data.

The loader rejects duplicate JSON keys, floating-point values, non-finite numbers, excessive depth, excessive item counts, oversized descriptors, unsafe text, directories, symlinks, and material mutation during read.

## Assertion Envelope

TohuPono injects the proved subject digest. Descriptors cannot provide `subject`, `assertion_id`, `proof_id`, `claim_id`, `verified`, or `verification_status`.

The manifest assertion envelope contains:

- `assertion_id`;
- `schema_version`;
- `assertion_type`;
- `subject`;
- `identity`;
- `key_fingerprint`;
- `reference`;
- `attributes`.

The envelope does not store descriptor paths, source paths, hostnames, usernames, device identifiers, operating-system timestamps, registry prose, report wording, CLI formatting, or inferred verification status.

## Assertion IDs

`assertion_id` is `idn_` plus the first 32 hexadecimal characters of SHA-256 over the canonical assertion body excluding `assertion_id`.

Changing the subject digest, namespace, identifier, display name, key fingerprint, reference, or attributes changes the assertion ID. Descriptor paths, descriptor ordering, and JSON key ordering do not.

## Manifest and Claim Linkage

An identity proof includes a top-level `identities` section only when `--concept identity` is selected. The section stores `schema_version`, `assertion_count`, and canonical assertions sorted by `assertion_id`.

The `identity` Proof Concept claim stores the identities schema version, sorted assertion IDs, and the subject digest. Verification fails if the claim and stored identities section diverge.

## CLI

```bash
python -m tohupono prove ./file.bin --concept identity --identity-json ./identity.json
python -m tohupono identity validate ./identity.json
python -m tohupono identity inspect ./proof_packet
```

Supplying `--identity-json` without `--concept identity` is an input error. Selecting `identity` without at least one descriptor is also an input error. Identity is not part of the default concept set; default proof generation remains `existence` and `integrity`.

## Privacy

Identity descriptors and manifest assertions may expose identifiers, display names, key fingerprints, references, and attributes. Do not place credentials, private keys, authentication tokens, government identifier numbers, unnecessary personal information, or sensitive identity data in identity descriptors.

## Legacy Behavior

Packets without an `identities` section or explicit `identity` Proof Concept remain loadable, verifiable, auditable, reportable, proof-ID-compatible, and signature-compatible. TohuPono does not infer Identity from Transaction participants, Custody actors, Provenance actors, Records metadata, signing keys, or legacy fields.
