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

Key compromise should be treated as at least `WARN` for affected evidence strength. It may become `FAIL` for workflows that require a trustworthy signature from that purpose.

Do not delete old proof packets to hide compromise. Preserve them and add clear context.
