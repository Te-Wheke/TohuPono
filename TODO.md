# TODO.md - Codex Guided Development Plan for TohuPono

## Current target
Integrate the Pro Report Generator into the main CLI and produce an end-to-end proof workflow:

```bash
tohupono prove ./file.pdf --output proof_packet/
tohupono verify ./file.pdf --proof proof_packet/manifest.json
tohupono report --proof proof_packet/manifest.json --format pdf --output verification_report.pdf --community false
```

The report command must create:

```text
verification_report.pdf
verification_report.pdf.sig
```

The `.sig` must be produced with a dedicated report-signing key, not the file proof key.

---

## Milestone 0 - Repository foundation

### Tasks
- Create Python package structure.
- Add `pyproject.toml`.
- Add CLI entry point `tohupono`.
- Add README, AGENTS.md, TODO.md, LICENSE placeholder, SECURITY.md.
- Add tests folder with smoke test.

### Acceptance criteria
- `python -m tohupono --help` works.
- `pytest -q` runs.
- Package imports cleanly.

### Suggested structure

```text
tohupono/
  __init__.py
  __main__.py
  cli.py
  core/
  evidence/
  reporting/
  trust/
  verdicts/
  vault/
tests/
docs/
examples/
keys/.gitkeep
```

---

## Milestone 1 - Deterministic file identity engine

### Tasks
- Implement SHA-256, SHA-512, and BLAKE3 where available.
- Detect file size.
- Detect MIME by magic bytes where possible.
- Record filesystem timestamps as observed metadata, not proof of origin.
- Create canonical JSON helper.

### CLI

```bash
tohupono inspect ./file.pdf
tohupono hash ./file.pdf --algorithm sha256
```

### Acceptance criteria
- Same file produces same digest on repeated runs.
- Extension mismatch is warned, not fatal.
- Tests cover empty file, binary file, renamed extension, and missing file.

---

## Milestone 2 - Proof packet v0.1

### Tasks
- Create `ProofManifest` schema.
- Create proof packet directory layout.
- Add manifest writing.
- Add evidence chain JSONL with first `sealed` event.
- Add warnings file.

### Output

```text
proof_packet/
  manifest.json
  hashes.txt
  metadata.json
  evidence_chain.jsonl
  warnings.json
```

### CLI

```bash
tohupono prove ./file.pdf --output proof_packet/
```

### Acceptance criteria
- Proof packet validates against schema.
- Manifest has stable field order.
- Hashes match the source file.
- No source file content is copied unless `--include-payload` is provided.

---

## Milestone 3 - Verification engine

### Tasks
- Load manifest.
- Recalculate current file digest.
- Compare against manifest digest.
- Evaluate evidence classes.
- Produce verdict JSON and Markdown summary.

### CLI

```bash
tohupono verify ./file.pdf --proof proof_packet/manifest.json --output verification_report.md
```

### Verdicts
- `VERIFIED_INTEGRITY`
- `ALTERED_AFTER_PROOF`
- `UNPROVEN`
- `SIGNED_CLAIM_ONLY`
- `TIMESTAMPED_EXISTENCE`
- `PROVENANCE_CONFLICT`
- `FAKE_BY_CONTRADICTION`

### Acceptance criteria
- Original file verifies as `VERIFIED_INTEGRITY`.
- Modified file verifies as `ALTERED_AFTER_PROOF`.
- Missing evidence is `UNPROVEN`, not `FAKE`.

---

## Milestone 4 - Pro Report Generator integration

### Tasks
- Move or wrap `pro_report.py` under `tohupono/reporting/pro_report.py`.
- Add CLI command `tohupono report`.
- Add `--proof`, `--format`, `--output`, `--community`, and `--report-key` options.
- Generate a dedicated report signing key on first use when not supplied.
- Create detached `report.pdf.sig`.
- Include legal-support/evidence-bundle disclaimer.

### CLI

```bash
tohupono report --proof proof_packet/manifest.json --format pdf --output verification_report.pdf
```

Community Tier:

```bash
tohupono report --proof proof_packet/manifest.json --format pdf --output community_report.pdf --community
```

### Acceptance criteria
- PDF report exists.
- Detached `.sig` exists.
- Report key is separate from manifest/file keys.
- Community report has banner/footer but no feature restrictions.
- Tests verify all above.

---

## Milestone 5 - Signing and trust policy

### Tasks
- Add key generation command.
- Add manifest signing.
- Add signature verification.
- Add trust policy YAML.
- Add key status: active, revoked, lost, compromised, retired.

### CLI

```bash
tohupono keygen --purpose manifest --out keys/manifest_key.pem
tohupono keygen --purpose report --out keys/report_signing_key.pem
tohupono attest --proof proof_packet/manifest.json --key keys/manifest_key.pem
```

### Acceptance criteria
- Signature verifies against public key.
- Wrong key fails verification.
- Revoked key fails for new proofs.
- Proofs created before loss date can remain historically valid unless compromise is declared.

---

## Milestone 6 - Timestamp support

### Tasks
- Add RFC 3161-ready interface.
- Add OpenTimestamps optional integration.
- Store timestamp evidence separately.
- Verify timestamp proofs where available.

### CLI

```bash
tohupono timestamp --proof proof_packet/manifest.json --ots
tohupono verify ./file.pdf --proof proof_packet/manifest.json --check-timestamps
```

### Acceptance criteria
- No network call occurs unless timestamp option is selected.
- Pending OpenTimestamps state is represented clearly.
- Failed timestamp validation is a warning or failure according to policy.

---

## Milestone 7 - C2PA media provenance

### Tasks
- Add optional c2patool/c2pa-rs adapter.
- Extract C2PA manifests where present.
- Validate C2PA status and record validation results.
- Detect absence or stripping of C2PA as `metadata_absent`, not fake.

### CLI

```bash
tohupono inspect ./image.jpg --c2pa
tohupono verify ./image.jpg --proof proof_packet/manifest.json --c2pa
```

### Acceptance criteria
- Supported file with C2PA reports signer, claim, validation status.
- Unsupported file gives clear message.
- C2PA conflict becomes `PROVENANCE_CONFLICT`.

---

## Milestone 8 - BagIt archival package

### Tasks
- Add BagIt export.
- Include proof packet and optional payload.
- Generate manifest-sha256.txt.
- Validate bag integrity.

### CLI

```bash
tohupono bag --proof proof_packet/manifest.json --payload ./file.pdf --output sealed_bag/
tohupono bag-verify sealed_bag/
```

### Acceptance criteria
- Bag validates after creation.
- Removing a file fails validation.
- Changing payload fails validation.

---

## Milestone 9 - Enterprise offline vault

### Tasks
- Add local SQLite vault.
- Add append-only events table.
- Add import/export proof packet.
- Add offline policy mode.
- Add air-gapped deployment guide.

### CLI

```bash
tohupono vault init
tohupono vault import proof_packet/
tohupono vault search --sha256 <digest>
```

### Acceptance criteria
- Vault works without internet.
- Vault export produces portable proof packet.
- Audit events are append-only.

---

## Milestone 10 - API and web verifier

### Tasks
- Add FastAPI verification service.
- Add public hash lookup endpoint.
- Add proof upload endpoint for verification only.
- Add QR proof summary model.
- Add authentication for private/hosted mode.

### Acceptance criteria
- Local API verifies file + proof.
- Hosted mode does not store source file unless configured.
- Public verifier exposes only approved fields.

---

## Milestone 11 - Desktop and Android companion

### Desktop
- Build later using Tauri or Electron shell around the CLI/core library.
- Drag-and-drop file verification.
- Report preview.
- Key management UI.

### Android
- Capture-time hashing.
- Local proof packet creation.
- Optional device key integration.
- QR proof export.
- Offline-first design.

### Acceptance criteria
- Both clients rely on the same core evidence model.
- No separate verdict logic is implemented in UI clients.

---

## Milestone 12 - Post-quantum roadmap

### Tasks
- Add algorithm registry abstraction.
- Add metadata fields for ML-DSA and SLH-DSA readiness.
- Test PQ signatures using experimental libraries only behind feature flags.
- Do not make PQ signatures mandatory until deployment libraries are mature.

### Acceptance criteria
- Classical signatures remain supported.
- PQ fields are represented cleanly in manifests.
- Verification fails clearly if PQ verifier is unavailable.

---

## Immediate Codex task order
1. Create or inspect repo structure.
2. Add/confirm `tohupono` CLI entrypoint.
3. Add `report` subcommand.
4. Move/wrap `pro_report.py` into package.
5. Implement report key generation if missing.
6. Generate PDF and `.sig` from `manifest.json`.
7. Add tests for pro report generation.
8. Update README examples.
9. Run test suite.
10. Summarise results.

## Final release gate for MVP
- `tohupono prove` works.
- `tohupono verify` works.
- `tohupono report` works.
- PDF report and detached signature are created.
- Original file and altered file produce different verdicts.
- Community Tier is fully functional.
- Enterprise/offline mode is documented.
- No unsupported legal or authenticity claims remain in user-facing output.
