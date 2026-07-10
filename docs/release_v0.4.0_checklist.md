# TohuPono v0.4.0 Release Checklist

Use this checklist only during the v0.4.0 release gate.

- Confirm branch is `develop/v0.4.0`.
- Confirm working tree is clean before the release bump.
- Run `pytest -q`.
- Run `python -m compileall tohupono tests`.
- Run `python -m tohupono --help`.
- Run `python -m tohupono --version`.
- Run `python -m tohupono key inspect --json`.
- Run `python -m tohupono key check --json`.
- Run key create, rotate, and compromise smoke tests in `/tmp` only.
- Run `audit --key-workspace` smoke test in `/tmp` only.
- Confirm no keys or key lifecycle logs are tracked.
- Confirm no generated reports, signatures, proof packets, caches, or local artefacts are tracked.
- Bump version to `0.4.0` only during the release gate.
- Finalise `CHANGELOG.md` for `v0.4.0`.
- Commit the release.
- Create annotated tag `v0.4.0`.
- Push the branch and tag.
- Verify remote branch and peeled tag target.

v0.4.0 focuses on key-management hardening. It does not add timestamp anchoring, network integrations, or stronger legal-proof claims.
