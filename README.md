# TohuPono

TohuPono is a deterministic, local-first file-origin proof system. It records evidence about digital files and produces evidence-based verification outputs for a legal-support evidence bundle.

It verifies technical file identity, digest matches, packet integrity, observed metadata, and report signatures within the local proof model. It does not make unsupported claims about external truth.

## Quickstart

```bash
python -m tohupono --help
python -m tohupono --version
tohupono inspect ./file.pdf
tohupono hash ./file.pdf --algorithm sha256
tohupono prove ./file.pdf --output proof_packet/
tohupono compare ./file.pdf ./copy.pdf
tohupono verify proof_packet/
tohupono verify-file ./copy.pdf proof_packet/
tohupono verify ./file.pdf --proof proof_packet/manifest.json --output verification_report.md
tohupono verify ./file.pdf --proof proof_packet/manifest.json --json
tohupono verify-chain proof_packet/evidence_chain.jsonl --json
tohupono inspect-proof proof_packet/manifest.json --json
tohupono amend proof_packet/ --note "Custody note"
tohupono audit proof_packet/
tohupono key inspect
tohupono key check --json
tohupono key create --purpose manifest
tohupono key rotate --purpose manifest --reason "routine rotation"
tohupono key compromise --purpose manifest --reason "suspected exposure"
tohupono report --proof proof_packet/manifest.json --format pdf --output verification_report.pdf
tohupono report --proof proof_packet/manifest.json --format pdf --output community_report.pdf --community
```

The report command writes:

```text
verification_report.pdf
verification_report.pdf.sig
```

The detached signature is made over the final PDF bytes using a dedicated report-signing key.

MVP report signing uses the system OpenSSL CLI with Ed25519 keys. This keeps signing on a reviewed cryptographic implementation and avoids custom cryptography.
Private keys are generated locally under `keys/` by default. Do not commit private keys, generated proof packets, generated reports, or detached signature files.

Proof packets also include a manifest signature:

```text
proof_packet/signatures/manifest.sig
proof_packet/signatures/manifest.pub
```

The manifest signature protects the proof packet before the PDF report layer. The PDF report signature is separate and protects the human-readable report file.

Key purposes are inspectable:

```bash
python -m tohupono key inspect --purpose manifest
python -m tohupono key inspect --purpose manifest --output-dir keys/
python -m tohupono key check --json
python -m tohupono key check --output-dir keys/ --json
python -m tohupono key create --purpose manifest
python -m tohupono key rotate --purpose manifest --reason "routine rotation"
python -m tohupono key compromise --purpose manifest --reason "suspected exposure"
```

Key creation refuses to overwrite existing key files unless `--force` is supplied. Rotation records local JSONL metadata and creates replacement key material without deleting old keys. Compromise marking records local JSONL metadata and causes inspection/check commands to warn that signatures may need trust-policy review.

A key workspace is the directory containing purpose key files plus `key_rotation_log.jsonl` and `key_compromise_log.jsonl`. The default workspace is `keys/`. Use `--output-dir` with create, rotate, compromise, inspect, and check when operating on another local workspace.

See `docs/KEY_MANAGEMENT.md`, `docs/KEY_ROTATION.md`, and `docs/KEY_COMPROMISE.md` for key purpose, rotation, and compromise guidance. Local key logs under `keys/` must not be committed.

## v0.3.0 Development Goals

The v0.3.0 cycle makes the proof core universal-file and byte-first.

- `file_id` is the SHA-256 digest of file bytes.
- `proof_id`, `manifest_id`, `event_id`, and `packet_id` are deterministic hashes over canonical proof data.
- Paths, filenames, extensions, MIME guesses, and OS timestamps are untrusted supporting metadata.
- Copied and renamed files pass byte-level verification when SHA-256 matches.
- `compare` checks two files by digest.
- `verify-file` explicitly verifies a file against a packet.
- `verify` without `--proof` verifies the packet itself.
- `amend` creates a separate amendment record and does not mutate the original packet.
- `audit` prints technical packet checks using PASS, WARN, and FAIL lines.

## v0.2.0 Development Goals

The v0.2.0 cycle hardens deterministic proof lineage for any file type.

- File identity is the byte digest. Path, name, extension, and MIME type are observed metadata only.
- Copied or renamed files verify when their byte digest matches the proof manifest.
- Proof IDs are derived from stable canonical seed data: schema version, tool version, file SHA-256, file size, and manifest version.
- `evidence_chain.jsonl` events include canonical event hashes and previous-event links.
- Manifest keys sign proof manifests. Report keys sign final PDF bytes. These keys must remain separate.
- `verify --json` emits deterministic structured diagnostics for automation.
- `verify-chain` checks standalone evidence-chain JSONL files.
- `inspect-proof` inspects proof packet metadata without verifying a source file.

Inspecting a proof is not the same as verifying a source file. `inspect-proof` reports manifest and packet status only. `verify` compares a supplied file's byte digest with the proof manifest.

## Proof Packet

```text
proof_packet/
  manifest.json
  hashes.txt
  metadata.json
  evidence_chain.jsonl
  warnings.json
  signatures/
    manifest.sig
    manifest.pub
```

Source file content is not copied unless `--include-payload` is explicitly used.

Evidence-chain hashes make recorded events tamper-evident under the local proof packet model. They do not prove external truth, complete custody, or legal admissibility by themselves.

## Claim Maturity

TohuPono treats stronger claim language as a maturity target, not a slogan. `docs/CLAIM_MATURITY.md` defines safe technical claim levels, restricted high-risk claim zones, and the FAIL/WARN/LIMIT/TODO response model for integrity gaps.

Use terms such as `byte-identical`, `digest match`, `verified file integrity`, `manifest verified`, `signature valid`, `evidence chain intact`, and `packet integrity verified` only when the matching technical checks support them. Legal proof, admissibility, authorship, truth, and proof-of-reality language requires stronger evidence layers and legal review.

## Verdicts

- `VERIFIED_INTEGRITY`: current digest matches the sealed digest.
- `ALTERED_AFTER_PROOF`: current digest differs from the sealed digest.
- `UNPROVEN`: available evidence is insufficient.

Manifest signature status values are `valid`, `missing`, `invalid`, `unverified`, and `error`.

Evidence-chain status values are `valid`, `missing`, `invalid`, and `error`.

Legal-support boundary: This report supports evidence review by recording deterministic file identity, verification results, signatures, and proof-packet status. It does not by itself prove real-world truth, authorship, intent, or legal admissibility.

## CLI Exit Codes

TohuPono commands use a small exit-code policy:

- `0`: success
- `1`: verification failed or proof conflict
- `2`: user or input error
- `3`: internal or runtime error

For example, `verify` returns `0` for `VERIFIED_INTEGRITY`, `1` for `ALTERED_AFTER_PROOF` or `PROVENANCE_CONFLICT`, and `2` for missing input files or missing proof manifests.

JSON-mode command errors use this shape:

```json
{
  "status": "error",
  "error": {
    "code": "MISSING_FILE",
    "message": "..."
  }
}
```

Current error codes include `MISSING_FILE`, `MISSING_PROOF`, `INVALID_JSONL`, `INVALID_MANIFEST`, `INVALID_ARGUMENT`, `SIGNATURE_ERROR`, `CHAIN_ERROR`, and `INTERNAL_ERROR`.

## Diagnostics Workflow

```bash
python -m tohupono prove ./sample.txt --output proof_packet
python -m tohupono verify ./sample.txt --proof proof_packet/manifest.json --json
python -m tohupono verify-chain proof_packet/evidence_chain.jsonl --json
python -m tohupono inspect-proof proof_packet/manifest.json --json
python -m tohupono report --proof proof_packet/manifest.json --format pdf --output verification_report.pdf
```

Generated proof packets, reports, signatures, and keys are local artefacts and must not be committed.

## Offline Default

TohuPono performs no network calls in the MVP. External integrations such as OpenTimestamps, RFC3161 TSA, C2PA, BagIt, and Sigstore/Rekor are planned later behind explicit user options.

Reports use legal-support evidence bundle language and must avoid unsupported legal sufficiency claims.
