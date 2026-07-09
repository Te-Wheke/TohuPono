# Security

TohuPono is local-first and offline by default.

- Private keys must be created with restrictive permissions.
- Private keys are local secrets and must not be committed.
- Manifest-signing keys sign proof packet manifests.
- Report-signing keys sign human-readable PDF reports.
- Future file-signing keys may sign direct file claims.
- Manifest, report, and future file-signing keys must remain separate.
- Verification fails closed on ambiguous proof input.
- Raw sensitive file content and private key material must not be logged.
- Network anchoring and external evidence integrations are opt-in future features.
- MVP manifest and report signatures use OpenSSL Ed25519 keys through the system `openssl` command. This is not custom cryptography.

Reports are legal-support evidence bundle artefacts. They do not provide legal advice or guarantee admissibility.
