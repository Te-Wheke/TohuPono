# TohuPono

TohuPono is a deterministic, local-first file-origin proof system. It records evidence about digital files and produces evidence-based verification outputs for a legal-support evidence bundle.

It proves file identity, integrity relative to a sealed digest, observed metadata, and report integrity. It does not make unsupported claims about external truth.

## Quickstart

```bash
python -m tohupono --help
python -m tohupono --version
tohupono inspect ./file.pdf
tohupono hash ./file.pdf --algorithm sha256
tohupono prove ./file.pdf --output proof_packet/
tohupono verify ./file.pdf --proof proof_packet/manifest.json --output verification_report.md
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

## v0.2.0 Development Goals

The v0.2.0 cycle hardens deterministic proof lineage for any file type.

- File identity is the byte digest. Path, name, extension, and MIME type are observed metadata only.
- Copied or renamed files verify when their byte digest matches the proof manifest.
- Proof IDs are derived from canonical seed data: schema version, tool version, file SHA-256, file size, sealed timestamp, and manifest version.
- `evidence_chain.jsonl` events include canonical event hashes and previous-event links.
- Manifest keys sign proof manifests. Report keys sign final PDF bytes. These keys must remain separate.

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

## Verdicts

- `VERIFIED_INTEGRITY`: current digest matches the sealed digest.
- `ALTERED_AFTER_PROOF`: current digest differs from the sealed digest.
- `UNPROVEN`: available evidence is insufficient.

## Offline Default

TohuPono performs no network calls in the MVP. External integrations such as OpenTimestamps, RFC3161 TSA, C2PA, BagIt, and Sigstore/Rekor are planned later behind explicit user options.

Reports use legal-support evidence bundle language and must avoid unsupported legal sufficiency claims.
