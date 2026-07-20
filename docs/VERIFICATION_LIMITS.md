# Verification Limits

TohuPono verifies byte identity and packet integrity within the local proof model.

It does not prove real-world truth, authorship, intent, or legal admissibility by itself.

The project distinguishes:

- technical verification;
- evidence preparation;
- chain-of-custody support;
- legal argument;
- legal admissibility;
- legal proof.

Proof Concepts are not interchangeable. Registry presence does not imply operational support, and support for integrity does not imply support for authenticity, ownership, authorship, truth, or Proof of Reality.

Executable concept support is currently limited to `integrity`, `existence`, `records`, `custody`, `provenance`, `transaction`, and `identity`.

- `integrity` checks whether supplied bytes match the recorded digest.
- `existence` reviews available timestamp evidence for the recorded digest.
- `records` verifies canonical record envelopes and their link to the packet subject digest.
- `custody` verifies canonical custody-event envelopes, retained hash links, subject binding, and claim linkage.

`integrity` does not prove authenticity, authorship, ownership, legal identity, original creation, truth, or absence of earlier manipulation.

`existence` does not prove content truth. Local timestamps are local evidence only, not authoritative time, external witnessing, immutability, legal proof, or independent anchoring.

Other registered concepts remain non-executable until a future implementation defines the required evidence and verification procedure.

`records` does not prove declared metadata truth, external registration, authority, ownership, identity, authorship, authenticity, legal validity, legal admissibility, completeness of history, or accuracy of an external reference. Record attributes are user-declared manifest data and may be sensitive; do not place secrets, private keys, credentials, or unnecessary private metadata in record attributes.

`custody` does not prove physical possession, actor identity, legal custody, ownership, authorship, authenticity, authority, consent, content truth, complete event history, absence of earlier or later events, external timestamp validity, immutability, legal validity, or legal admissibility. Custody actors, locations, references, occurred-time values, and attributes are user-declared manifest data. Do not place credentials, private keys, secrets, unnecessary personal information, or sensitive location information in custody descriptors.

`docs/CLAIM_MATURITY.md` defines which claim language is safe at each maturity level and how integrity gaps are classified.

Local timestamps are useful context, but they are not externally anchored in the offline default mode. `local_only` and `missing` timestamp states are reported as `WARN`, not `FAIL`.

Timestamping can support proof-of-existence once external anchoring exists. A timestamp alone does not prove content truth, authorship, intent, or legal admissibility.

Imported timestamp receipts are recorded as `unverified` unless TohuPono can verify the receipt format and external timestamp service. The receipt hash proves the attached receipt bytes were recorded; it does not prove external validity by itself.

The default timestamp policy is `evidence_review`. It reports missing external anchoring, local-only timestamps, and unverified receipts as WARN, while corrupted receipt metadata, receipt target mismatch, missing stored receipt bytes, and receipt hash mismatch are FAIL. `strict_external` is opt-in and fails when verified external timestamp evidence is absent.

Manifest signatures and report signatures are separate trust layers:

- the manifest key signs the proof manifest;
- the report key signs final PDF bytes;
- future direct file-signing keys may be separate again.

If a manifest or evidence chain is edited after sealing, verification should fail where the edit is detectable.

`provenance` does not prove parent file existence, actual derivation, verified origin, authorship, ownership, authenticity, identity, authority, consent, content truth, originality, first creation, complete lineage, absence of omitted intermediate versions, legal validity, external registration, or external timestamp validity. Provenance parents, operations, actors, references, occurred-time values, and attributes are user-declared manifest data. Do not place credentials, private keys, secrets, unnecessary personal information, or sensitive operational details in provenance descriptors.

`transaction` does not prove transaction occurrence, payment, delivery, participant identity, consent, authority, ownership before or after the declaration, ownership transfer, contractual formation, legal validity, enforceability, authenticity, authorship, external registration, external timestamp validity, or completeness of transaction history. Transaction participants, references, terms, occurred-time values, and attributes are user-declared manifest data. Do not place credentials, private keys, secrets, payment credentials, unnecessary personal information, or sensitive contractual information in transaction descriptors.

`identity` does not prove that an identifier belongs to a real person or organisation, that an identity exists outside the packet, verified personhood, verified organisational status, government recognition, account ownership, control of a cryptographic key, authorship, ownership, authority, consent, authenticity, legal identity, legal capacity, external registration, or external validation. Identity namespaces, identifiers, display names, key fingerprints, references, and attributes are user-declared manifest data. Do not place credentials, private keys, authentication tokens, government identifier numbers, unnecessary personal information, or sensitive identity data in identity descriptors.
