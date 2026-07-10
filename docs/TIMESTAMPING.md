# Timestamping

TohuPono v0.5.0 development starts with timestamp adapter architecture before external timestamp implementations.

Timestamp statuses:

- `missing`: no timestamp proof is present.
- `local_only`: local system time was recorded, but it is not externally anchored.
- `pending`: timestamp request exists but is not complete.
- `anchored`: timestamp proof is externally anchored.
- `invalid`: timestamp proof failed validation.
- `unsupported`: adapter cannot perform the requested operation.
- `error`: timestamp inspection or verification hit a runtime error.

Adapter types:

- `none`
- `local`
- `opentimestamps`
- `rfc3161`
- `manual`

This slice implements only `none` and `local` adapters. It does not call OpenTimestamps, RFC 3161 timestamp authorities, blockchains, transparency logs, C2PA services, Sigstore, Rekor, W3C VC systems, or any network service.

`local_only` means the proof packet records local system time and the target digest. It supports review of local proof creation context, but it is not trusted external anchoring and must remain a `WARN` in audit output.

Missing or local-only timestamping is not a verification failure by itself. It weakens timestamp evidence strength and should be disclosed as a warning.

Timestamping can support proof-of-existence at or before a time once external anchoring exists. Timestamping alone does not prove content truth, authorship, intent, or legal admissibility.
