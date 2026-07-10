# Verification Limits

TohuPono verifies byte identity and packet integrity within the local proof model.

It does not prove real-world truth, authorship, intent, or legal admissibility by itself.

Local timestamps are useful context, but they are not externally anchored in the offline default mode. Missing external timestamp anchoring is reported as `WARN`.

Manifest signatures and report signatures are separate trust layers:

- the manifest key signs the proof manifest;
- the report key signs final PDF bytes;
- future direct file-signing keys may be separate again.

If a manifest or evidence chain is edited after sealing, verification should fail where the edit is detectable.
