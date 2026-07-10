# v0.2.0 Release Checklist

- Confirm branch is `develop/v0.2.0`.
- Run `pytest -q`.
- Run `python -m compileall tohupono tests`.
- Run `python -m tohupono --help`.
- Run `python -m tohupono --version`.
- Run a manual prove, verify, verify-chain, inspect-proof, and report smoke test.
- Confirm JSON diagnostics work.
- Confirm copied and renamed files verify by digest.
- Confirm invalid manifest signature returns `PROVENANCE_CONFLICT`.
- Confirm altered file returns `ALTERED_AFTER_PROOF`.
- Confirm no keys, `.ssh`, signatures, proof packets, generated PDFs, caches, virtualenvs, or local artefacts are tracked.
- Bump package version to `0.2.0` only during the release gate.
- Update changelog from `v0.2.0 in development` to `v0.2.0`.
- Commit the release.
- Tag `v0.2.0`.
- Push branch and tag.
