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
python -m tohupono key inspect --purpose manifest --output-dir /path/to/key-directory --json
```

Check local key hygiene:

```bash
python -m tohupono key check
python -m tohupono key check --json
python -m tohupono key check --output-dir /path/to/key-directory --json
```

Missing keys are warnings unless an operation currently needs the key. This lets a fresh offline key directory inspect its configuration before first signing.

Create a keypair for a purpose:

```bash
python -m tohupono key create --purpose manifest
python -m tohupono key create --purpose report --output-dir keys/
python -m tohupono key create --purpose witness --json
```

Key creation uses OpenSSL CLI Ed25519. It creates parent directories as needed, writes the private key with restrictive permissions where the platform supports them, exports the public key, and never prints private key contents. Existing key files are not overwritten unless `--force` is explicitly supplied.

`key create --force` is forced replacement, not rotation. It records `KEY_REPLACED`, retains the previous active pair under backup names, and promotes the replacement pair only after the new private and public keys have been generated and validated.

If lifecycle event persistence fails after promotion, TohuPono attempts to roll back the active pair to the previous generation and retains the attempted promoted material under incomplete recovery names for operator review. It does not report replacement success without lifecycle metadata.

Lifecycle metadata is stored locally under `keys/`:

```text
keys/key_rotation_log.jsonl
keys/key_compromise_log.jsonl
keys/key_lifecycle_log.jsonl
```

These logs are local trust records. They must not be committed with private keys, generated proof packets, generated reports, or signatures.

The key directory contains purpose key files and lifecycle metadata logs. The default key directory is `keys/`. If keys are created, rotated, or marked compromised with `--output-dir`, use the same `--output-dir` when running `key inspect` or `key check`; otherwise those commands read the default `keys/` directory.

Missing key directories are handled as empty local key directories. Inspection and check commands report missing-key warnings instead of creating files or failing.

Packet audit can also read key lifecycle metadata from a key directory:

```bash
python -m tohupono audit proof_packet/ --key-directory /path/to/key-directory
```

Audit reports visible compromise metadata as `WARN`. It does not treat compromise metadata as automatic proof destruction and does not add timestamp anchoring.

The current signing backend uses the system OpenSSL CLI with Ed25519 keys. This uses a reviewed cryptographic implementation and is not custom cryptography.

`key_lifecycle_log.jsonl` contains canonical chained lifecycle events. Older `key_rotation_log.jsonl` and `key_compromise_log.jsonl` entries remain inspectable as legacy unlinked evidence.

Lifecycle logs are tamper-evident under the local key lifecycle model. They are not immutable. Internal chain gaps and removal of events referenced by later retained events are detectable. Removal of the unreferenced tail of a purely local lifecycle log may not be detectable without a separately retained, signed or externally anchored head checkpoint.
