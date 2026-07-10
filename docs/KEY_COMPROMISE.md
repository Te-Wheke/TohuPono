# Key Compromise

A compromised private key weakens trust in signatures made with that key. It does not automatically change file bytes, digests, or immutable packet contents, but it can weaken the evidential value of signatures.

If compromise is suspected:

1. Stop using the private key.
2. Preserve evidence of when compromise was detected.
3. Generate a replacement key for the same purpose.
4. Preserve public keys and signed artefacts for review.
5. Mark affected packets, reports, or amendments with a warning or future amendment record.
6. Run `tohupono key inspect` and `tohupono key check`.

Key compromise should be treated as at least `WARN` for affected evidence strength. It may become `FAIL` for workflows that require a trustworthy signature from that purpose.

Do not delete old proof packets to hide compromise. Preserve them and add clear context.
