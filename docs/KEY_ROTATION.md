# Key Rotation

Key rotation means creating a new active key generation for a purpose and clearly recording when new proof or report material starts using it.

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
python -m tohupono key rotate --purpose manifest --reason "key directory rotation" --output-dir /path/to/key-directory --json
```

The command does not delete old keys. It promotes the new keypair to the standard active paths, retains the previous active generation under backup names, and appends lifecycle metadata to:

```text
keys/key_rotation_log.jsonl
keys/key_lifecycle_log.jsonl
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

If lifecycle event persistence fails after the new generation is promoted, TohuPono attempts to roll back the active pair to the previous generation and retains the attempted promoted material under incomplete recovery names for operator review. A rotation is not reported as successful unless the lifecycle event is recorded.

Rotation does not rewrite old proof packets. Old packets should remain immutable and be verified with the public key material recorded with or near the signed artefact.

Rotation metadata is visible to `key inspect` and `key check` when those commands read the same key directory:

```bash
python -m tohupono key inspect --purpose manifest --output-dir /path/to/key-directory --json
python -m tohupono key check --purpose manifest --output-dir /path/to/key-directory --json
```

Rotation metadata supports continuity review. It does not automatically change historical packet verdicts.

`audit --key-directory` includes rotation event counts in JSON output so reviewers can see lifecycle context alongside packet checks.

`key create --force` is not rotation. It records `KEY_REPLACED`; `key rotate` records `KEY_ROTATED`.

Lifecycle logs are tamper-evident under the local key lifecycle model. They are not immutable. Internal chain gaps and removal of events referenced by later retained events are detectable. Removal of the unreferenced tail of a purely local lifecycle log may not be detectable without a separately retained, signed or externally anchored head checkpoint.

If a key was rotated only as routine hygiene, historical signatures may remain valid. If a key was rotated because of compromise, follow `docs/KEY_COMPROMISE.md`.
