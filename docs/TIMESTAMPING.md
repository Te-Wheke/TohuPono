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

Imported receipts:

```bash
python -m tohupono timestamp import proof_packet/ ./receipt.bin --type manual
python -m tohupono timestamp inspect proof_packet/ --json
```

Receipt types:

- `manual`
- `opentimestamps`
- `rfc3161`
- `unknown`

Receipt statuses:

- `imported`
- `unverified`
- `verified`
- `invalid`
- `unsupported`
- `missing`

Manual receipt import records receipt metadata and a copy of the receipt bytes under the proof packet. The receipt record includes receipt ID, type, stored path, receipt hash, receipt size, target digest, import time, status, and warnings.

Imported receipts are `unverified` unless TohuPono can verify the receipt format and external service. In this slice, imported receipts are not externally verified. A receipt hash proves the receipt file was attached or imported into the packet; it does not prove the external timestamp is valid.

Timestamping can support proof-of-existence at or before a time once external anchoring exists. Timestamping alone does not prove content truth, authorship, intent, or legal admissibility.
