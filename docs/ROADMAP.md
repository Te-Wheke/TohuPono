# Roadmap

## v0.5.0

- Proof Concepts governance and registry;
- no-macron validation for project-authored text;
- secure path, atomic-write, lock, and bounded-input primitives;
- safe key replacement using `KEY_REPLACED`;
- active key generation rotation using `KEY_ROTATED`;
- canonical key lifecycle event chaining with legacy log compatibility;
- timestamp proof model;
- timestamp adapter interface;
- `none` and `local` timestamp adapters;
- `timestamp inspect` diagnostics;
- manual/offline timestamp receipt import;
- receipt metadata and unverified receipt warnings;
- timestamp verification policies and receipt conflict diagnostics;
- audit warnings for missing and local-only timestamp states;
- OpenTimestamps and RFC 3161 interfaces before implementations.
- CI workflow addition is deferred until third-party GitHub Action full commit SHAs can be verified without guessing.

## v0.4.0

- key purpose registry;
- key inspection and hygiene checks;
- local key creation by explicit purpose;
- key rotation metadata without deleting old keys;
- key compromise metadata with WARN-level trust-policy review prompts;
- key directory-aware inspect/check commands;
- packet audit warnings for visible compromised-key metadata;
- audit key-directory selection for lifecycle warning review;
- v0.4.0 release checklist for key-management gates;
- continued separation of manifest, report, amendment, witness, release, and test key purposes.

## v0.3.0

- universal byte-first file proof model;
- deterministic file, proof, manifest, event, and packet identifiers;
- packet-only verification;
- explicit file-against-packet verification;
- byte-digest file comparison;
- immutable amendment records;
- technical packet audit command.

## Later

External integrations remain out of the offline default path and should be added only behind explicit user options.

Proof-of-reality is a serious long-term direction, not a current product claim. It should be approached by hardening layered evidence:

- trusted timestamping implementations;
- witness signatures;
- device and context attestations;
- external anchoring;
- clearer claim maturity tests;
- legal-support documentation review.

Planned order:

1. OpenTimestamps
2. RFC3161 TSA
3. C2PA
4. BagIt
5. Sigstore/Rekor
