# Key Compromise

A compromised private key weakens trust in signatures made with that key. It does not automatically change file bytes, digests, or immutable packet contents, but it can weaken the evidential value of signatures.

If compromise is suspected:

1. Stop using the private key.
2. Preserve evidence of when compromise was detected.
3. Generate a replacement key for the same purpose.
4. Preserve public keys and signed artefacts for review.
5. Mark affected packets, reports, or amendments with a warning or future amendment record.
6. Run `tohupono key inspect` and `tohupono key check`.

Record local compromise metadata:

```bash
python -m tohupono key compromise --purpose manifest --reason "suspected exposure"
python -m tohupono key compromise --purpose report --reason "lost device review" --json
python -m tohupono key compromise --purpose manifest --reason "key directory marker" --output-dir /path/to/key-directory --json
```

The command does not delete keys and does not modify old proof packets. It appends a JSONL record to:

```text
keys/key_compromise_log.jsonl
```

Each compromise record includes:

- `event_type = KEY_COMPROMISED`
- purpose
- public key path
- reason
- timestamp
- tool version
- compromise event ID

When compromise metadata exists for a purpose, `key inspect` and `key check` warn:

```text
WARN: compromise metadata exists for this key purpose. Existing signatures may require review under the applicable trust policy.
```

Use the same key directory for inspection/checking that was used when recording compromise metadata:

```bash
python -m tohupono key inspect --purpose manifest --output-dir /path/to/key-directory
python -m tohupono key check --purpose manifest --output-dir /path/to/key-directory --json
```

Key compromise should be treated as at least `WARN` for affected evidence strength. It may become `FAIL` for workflows that require a trustworthy signature from that purpose.

Compromise is a trust-policy review trigger, not automatic proof destruction. Do not delete old proof packets to hide compromise. Preserve them and add clear context. Future trust policies may choose stricter enforcement for specific workflows.

Packet audit can read compromise metadata from a selected key directory:

```bash
python -m tohupono audit proof_packet/ --key-directory /path/to/key-directory
```

When metadata is visible, audit reports:

```text
WARN: compromise metadata exists for the manifest key purpose. Existing signatures may require review under the applicable trust policy.
```

Compromise events are recorded in local lifecycle metadata. Existing legacy `key_compromise_log.jsonl` records remain inspectable as unlinked evidence, while new canonical lifecycle events are chained in `key_lifecycle_log.jsonl`.

Lifecycle logs are tamper-evident under the local key lifecycle model. They are not immutable. Internal chain gaps and removal of events referenced by later retained events are detectable. Removal of the unreferenced tail of a purely local lifecycle log may not be detectable without a separately retained, signed or externally anchored head checkpoint.
