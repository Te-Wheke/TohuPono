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
python -m tohupono key inspect --purpose manifest --output-dir /path/to/key-workspace --json
```

Check local key hygiene:

```bash
python -m tohupono key check
python -m tohupono key check --json
python -m tohupono key check --output-dir /path/to/key-workspace --json
```

Missing keys are warnings unless an operation currently needs the key. This lets a fresh offline workspace inspect its configuration before first signing.

Create a keypair for a purpose:

```bash
python -m tohupono key create --purpose manifest
python -m tohupono key create --purpose report --output-dir keys/
python -m tohupono key create --purpose witness --json
```

Key creation uses OpenSSL CLI Ed25519. It creates parent directories as needed, writes the private key with restrictive permissions where the platform supports them, exports the public key, and never prints private key contents. Existing key files are not overwritten unless `--force` is explicitly supplied.

Lifecycle metadata is stored locally under `keys/`:

```text
keys/key_rotation_log.jsonl
keys/key_compromise_log.jsonl
```

These logs are local trust records. They must not be committed with private keys, generated proof packets, generated reports, or signatures.

A key workspace is the directory containing purpose key files and lifecycle metadata logs. The default workspace is `keys/`. If keys are created, rotated, or marked compromised with `--output-dir`, use the same `--output-dir` when running `key inspect` or `key check`; otherwise those commands read the default `keys/` workspace.

Missing key workspaces are handled as empty local workspaces. Inspection and check commands report missing-key warnings instead of creating files or failing.

The current signing backend uses the system OpenSSL CLI with Ed25519 keys. This uses a reviewed cryptographic implementation and is not custom cryptography.
