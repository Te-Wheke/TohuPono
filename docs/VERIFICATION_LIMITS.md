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
