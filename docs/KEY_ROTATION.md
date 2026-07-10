# Key Rotation

Key rotation means creating a new key for a purpose and clearly recording when new proof or report material starts using it.

Conceptual rotation flow:

1. Stop using the old private key for new signatures.
2. Generate a new private/public key pair for the same purpose.
3. Preserve old public keys so older signatures remain verifiable.
4. Record the rotation in operational notes or future amendment/release metadata.
5. Run `tohupono key inspect` and `tohupono key check`.

Record a local rotation:

```bash
python -m tohupono key rotate --purpose manifest --reason "routine rotation"
python -m tohupono key rotate --purpose report --reason "operator handover" --json
python -m tohupono key rotate --purpose manifest --reason "workspace rotation" --output-dir /path/to/key-workspace --json
```

The command does not delete old keys. It creates replacement key material for the selected purpose and appends a JSONL record to:

```text
keys/key_rotation_log.jsonl
```

Each rotation record includes:

- `event_type = KEY_ROTATED`
- purpose
- old public key path
- new public key path
- reason
- timestamp
- tool version
- rotation event ID

Rotation does not rewrite old proof packets. Old packets should remain immutable and be verified with the public key material recorded with or near the signed artefact.

Rotation metadata is visible to `key inspect` and `key check` when those commands read the same key workspace:

```bash
python -m tohupono key inspect --purpose manifest --output-dir /path/to/key-workspace --json
python -m tohupono key check --purpose manifest --output-dir /path/to/key-workspace --json
```

Rotation metadata supports continuity review. It does not automatically change historical packet verdicts.

If a key was rotated only as routine hygiene, historical signatures may remain valid. If a key was rotated because of compromise, follow `docs/KEY_COMPROMISE.md`.
