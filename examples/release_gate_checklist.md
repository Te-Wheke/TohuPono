# Release Gate Checklist

Before a release commit:

- Confirm the current branch.
- Run `pytest -q`.
- Run `python -m compileall tohupono tests`.
- Run `python -m tohupono --help`.
- Run `python -m tohupono --version`.
- Run `git diff --check`.
- Run a manual prove, verify, verify-chain, inspect-proof, and report workflow.
- Confirm no keys, signatures, generated proof packets, generated reports, caches, virtualenvs, or local artefacts are tracked.

Generated proof packets, reports, signatures, and keys must remain local.
