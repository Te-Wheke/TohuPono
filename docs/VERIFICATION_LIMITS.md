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

Local timestamps are useful context, but they are not externally anchored in the offline default mode. Missing external timestamp anchoring is reported as `WARN`.

Manifest signatures and report signatures are separate trust layers:

- the manifest key signs the proof manifest;
- the report key signs final PDF bytes;
- future direct file-signing keys may be separate again.

If a manifest or evidence chain is edited after sealing, verification should fail where the edit is detectable.
