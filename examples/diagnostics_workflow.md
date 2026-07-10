# Diagnostics Workflow

Run these commands from a working directory containing `sample.txt`.

```bash
python -m tohupono prove ./sample.txt --output proof_packet
python -m tohupono verify ./sample.txt --proof proof_packet/manifest.json --json
python -m tohupono verify-chain proof_packet/evidence_chain.jsonl --json
python -m tohupono inspect-proof proof_packet/manifest.json --json
python -m tohupono report --proof proof_packet/manifest.json --format pdf --output verification_report.pdf
```

`verify` checks supplied file bytes against the proof manifest. `inspect-proof` inspects the proof packet without verifying a source file.

Generated proof packets, reports, signatures, and keys must not be committed.
