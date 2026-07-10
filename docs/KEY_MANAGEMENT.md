# Key Management

TohuPono uses explicit key purposes so signing and verification layers remain separate.

Current key purposes:

- `manifest`: signs and verifies proof packet manifests.
- `report`: signs and verifies final PDF report bytes.
- `witness`: reserved for future witness signatures.
- `amendment`: signs and verifies amendment lineage records.
- `release`: reserved for future release artefact signatures.
- `test`: reserved for runtime test fixtures and temporary keys.

Default key paths:

```text
keys/manifest_signing_key.pem
keys/manifest_signing_key.pub
keys/report_signing_key.pem
keys/report_signing_key.pub
keys/witness_signing_key.pem
keys/witness_signing_key.pub
keys/amendment_signing_key.pem
keys/amendment_signing_key.pub
keys/release_signing_key.pem
keys/release_signing_key.pub
```

Private keys must never be committed. The repository excludes `keys/`, `*.pem`, `*.key`, and generated signature material.

Inspect configured key purposes:

```bash
python -m tohupono key inspect
python -m tohupono key inspect --purpose manifest --json
```

Check local key hygiene:

```bash
python -m tohupono key check
python -m tohupono key check --json
```

Missing keys are warnings unless an operation currently needs the key. This lets a fresh offline workspace inspect its configuration before first signing.

The current signing backend uses the system OpenSSL CLI with Ed25519 keys. This uses a reviewed cryptographic implementation and is not custom cryptography.
