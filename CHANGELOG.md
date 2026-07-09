# Changelog

## v0.1.0

- Added the CLI MVP foundation with `inspect`, `hash`, `prove`, `verify`, and `report` commands.
- Added deterministic proof packet generation with canonical JSON manifests.
- Added manifest signing and verification for proof packet tamper evidence.
- Added verification verdicts including `VERIFIED_INTEGRITY`, `ALTERED_AFTER_PROOF`, `UNPROVEN`, and `PROVENANCE_CONFLICT`.
- Added PDF report generation for legal-support evidence bundle workflows.
- Added detached report signatures over final PDF bytes.
- Added dedicated report-signing key separation from manifest-signing keys.
- Added Community mode branding only, with no feature restrictions.
- Preserved local-first and offline-by-default operation.
- Used OpenSSL CLI Ed25519 signing in this environment because Python `cryptography` is broken at runtime here; this is not custom cryptography.
