# AGENTS.md - Codex Operating Guide for TohuPono

## Mission
Build TohuPono as a deterministic, local-first file-origin proof system. The product must generate, verify, package, sign, timestamp, and report evidence about digital files without making unsupported claims about real-world truth.

The system proves evidence state: file identity, integrity, timestamped existence, signer claims, provenance signals, chain-of-custody continuity, and contradictions between claims and evidence.

## Non-negotiable principles
1. Do not invent custom cryptography.
2. Do not claim a file is "real", "true", "not AI", or "court-proof" unless the evidence model explicitly supports the narrower claim.
3. Default to offline/private operation. Network anchoring is opt-in.
4. Treat provenance as layered evidence, not a single score.
5. Keep the report-signing key separate from file-signing and manifest-signing keys.
6. Preserve chain-of-custody as append-only events.
7. Make all output deterministic unless a random key, nonce, timestamp, or signature is explicitly part of the operation.
8. Never log private keys, secrets, raw sensitive file content, or private metadata by default.
9. Prefer open standards and well-reviewed libraries: C2PA, Sigstore/cosign, Rekor, OpenTimestamps, RFC 3161, SLSA, BagIt, NIST PQ signatures.
10. Community Tier must remain fully functional. Branding may differ; features must not be restricted.

## Architecture guardrails
- Core logic lives in `tohupono/core/` and must be UI-independent.
- CLI code only orchestrates core functions. Do not bury business logic in command handlers.
- Evidence integrations live under `tohupono/evidence/`.
- Trust policy and key handling live under `tohupono/trust/`.
- Report generation lives under `tohupono/reporting/`.
- Verdict classification lives under `tohupono/verdicts/`.
- Vault and persistence live under `tohupono/vault/`.
- Tests must cover both success and failure paths.

## Required initial commands for Codex
Before editing, run:

```bash
pwd
find . -maxdepth 3 -type f | sort
python --version || true
pytest --version || true
```

If this is a new repo, initialise the structure from TODO.md before implementing features.

## Development workflow
1. Read `TODO.md` and choose the smallest incomplete task.
2. Inspect existing code before editing.
3. Make one coherent change at a time.
4. Add or update tests with every behaviour change.
5. Run the relevant tests.
6. Update documentation and examples.
7. Summarise what changed, what was tested, and what remains.

## Coding standards
- Python target: 3.11+.
- Use type hints for public functions.
- Use `pydantic` or dataclasses for structured data.
- Use canonical JSON: UTF-8, sorted keys, stable separators.
- Use explicit exceptions with actionable messages.
- Avoid global mutable state.
- Keep functions small and testable.
- Use clear enum values for verdicts and evidence classes.
- Use British English in user-facing documentation.
- Use te reo Maori names only where they clarify project meaning. Do not use macrons in filenames, package names, or identifiers unless explicitly requested.

## Security rules
- Private keys must be created with restrictive file permissions.
- Report-signing keys must be separate from file and manifest keys.
- CLI must refuse to overwrite existing keys unless `--force` is explicitly supplied.
- Never upload files or proof packets unless the user selected an anchoring or hosted mode.
- External calls must be behind explicit flags: `--ots`, `--rekor`, `--c2pa`, `--public-anchor`, or similar.
- Verification must fail closed when signature, hash, policy, or timestamp validation is ambiguous.
- Missing evidence is `UNPROVEN`, not `FAKE`.
- Contradictory evidence is `PROVENANCE_CONFLICT` or `FAKE_BY_CONTRADICTION` only where hard evidence contradicts a claim.

## Testing expectations
Every milestone needs:
- unit tests for pure functions;
- integration tests for CLI flows;
- golden fixture tests for proof packet stability;
- negative tests for altered files, bad signatures, missing keys, invalid manifests, and revoked/disputed proofs;
- report generation tests ensuring PDF and detached `.sig` are created.

Minimum test command:

```bash
pytest -q
```

Recommended local quality gate:

```bash
python -m compileall tohupono tests
pytest -q
ruff check . || true
mypy tohupono || true
```

## Documentation expectations
Update documentation whenever behaviour changes:
- README quickstart;
- CLI help examples;
- proof packet schema notes;
- trust policy schema;
- verdict definitions;
- legal-support disclaimer;
- enterprise/offline deployment notes.

## Commit discipline
Use small commits. Suggested format:

```text
feat(cli): add report command
fix(verify): fail closed on missing manifest digest
test(report): cover detached PDF signature generation
docs(trust): document report-signing key separation
```

Codex should propose commit messages but must not assume commits were made unless it actually ran git commit.

## Definition of done
A task is complete only when:
- implementation exists;
- tests pass;
- documentation is updated;
- CLI usage is demonstrated;
- outputs are deterministic where expected;
- security constraints are preserved;
- user-facing language avoids unsupported legal or authenticity claims.
