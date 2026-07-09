from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import tohupono
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.file_identity import Blake3UnavailableError, hash_file
from tohupono.core.proof import create_proof_packet, load_manifest
from tohupono.reporting.pro_report import COMMUNITY_TEXT, FORBIDDEN_LANGUAGE, generate_report
from tohupono.trust.keys import export_public_key, verify_signature
from tohupono.verdicts.classifier import (
    ALTERED_AFTER_PROOF,
    PROVENANCE_CONFLICT,
    UNPROVEN,
    VERIFIED_INTEGRITY,
    verify_file,
)


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tohupono", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_package_imports() -> None:
    assert tohupono.__version__ == "0.1.0"


def test_cli_help() -> None:
    result = run_cli("--help")
    assert result.returncode == 0
    assert "tohupono" in result.stdout


def test_hash_stability(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("evidence\n", encoding="utf-8")
    assert hash_file(sample, "sha256") == hash_file(sample, "sha256")
    assert hash_file(sample, "sha512") == hash_file(sample, "sha512")


def test_missing_file() -> None:
    result = run_cli("hash", "missing.txt", "--algorithm", "sha256")
    assert result.returncode == 1
    assert "File not found" in result.stderr


def test_blake3_unavailable_is_clean(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("evidence\n", encoding="utf-8")
    try:
        digest = hash_file(sample, "blake3")
    except Blake3UnavailableError as exc:
        assert "BLAKE3 support is unavailable" in str(exc)
    else:
        assert len(digest) == 64


def test_canonical_json_ordering() -> None:
    assert canonical_json_text({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_proof_packet_creation_without_payload(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    out = tmp_path / "proof_packet"
    manifest = create_proof_packet(sample, out)
    assert manifest.proof_id.startswith("tp_")
    for name in ["manifest.json", "hashes.txt", "metadata.json", "evidence_chain.jsonl", "warnings.json"]:
        assert (out / name).exists()
    assert (out / "signatures" / "manifest.sig").exists()
    assert (out / "signatures" / "manifest.pub").exists()
    assert not (out / "payload").exists()


def test_include_payload_copies_payload(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    out = tmp_path / "proof_packet"
    create_proof_packet(sample, out, include_payload=True)
    assert (out / "payload" / "contract.pdf").exists()


def test_verify_original_and_modified(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    out = tmp_path / "proof_packet"
    create_proof_packet(sample, out)
    result = verify_file(sample, out / "manifest.json")
    assert result.verdict == VERIFIED_INTEGRITY
    assert result.manifest_signature_status == "valid"
    sample.write_bytes(b"%PDF-1.7\nchanged")
    changed = verify_file(sample, out / "manifest.json")
    assert changed.verdict == ALTERED_AFTER_PROOF


def test_missing_evidence_is_unproven(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    proof = tmp_path / "manifest.json"
    proof.write_text(json.dumps({"proof_id": "tp_missing", "file": {}}), encoding="utf-8")
    result = verify_file(sample, proof)
    assert result.verdict == UNPROVEN
    assert result.manifest_signature_status == "missing"
    assert "manifest_signature_missing" in result.warnings


def test_report_pdf_signature_and_key_separation(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    report = tmp_path / "verification_report.pdf"
    report_key = tmp_path / "keys" / "report_signing_key.pem"
    sig = generate_report(proof_dir / "manifest.json", report, report_key)
    assert report.exists()
    assert sig.exists()
    assert oct(os.stat(report_key).st_mode & 0o777) == "0o600"
    public_key = export_public_key(report_key)
    assert verify_signature(public_key, sig.read_bytes(), report.read_bytes())
    assert (proof_dir / "signatures" / "manifest.pub").read_bytes() != public_key.read_bytes()
    future_manifest_key = tmp_path / "keys" / "manifest_key.pem"
    assert report_key.name != future_manifest_key.name


def test_community_mode_changes_branding_only(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest_before = load_manifest(proof_dir / "manifest.json")
    report = tmp_path / "community_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(proof_dir / "manifest.json", report, key, community=True)
    manifest_after = load_manifest(proof_dir / "manifest.json")
    assert manifest_before == manifest_after
    assert COMMUNITY_TEXT


def test_generated_report_has_no_forbidden_language(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    report = tmp_path / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(proof_dir / "manifest.json", report, key)
    text = report.read_bytes().decode("latin-1", errors="ignore").lower()
    for phrase in FORBIDDEN_LANGUAGE:
        assert phrase.lower() not in text


def test_tampered_manifest_is_provenance_conflict(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest_path = proof_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tool"]["version"] = "tampered"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    result = verify_file(sample, manifest_path)
    assert result.verdict == PROVENANCE_CONFLICT
    assert result.manifest_signature_status == "invalid"
    assert "Manifest signature validation failed" in result.reasons


def test_missing_manifest_signature_warns_without_false_classification(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    (proof_dir / "signatures" / "manifest.sig").unlink()
    result = verify_file(sample, proof_dir / "manifest.json")
    assert result.verdict == VERIFIED_INTEGRITY
    assert result.manifest_signature_status == "missing"
    assert "manifest_signature_missing" in result.warnings


def test_report_includes_manifest_signature_status(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    report = tmp_path / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(proof_dir / "manifest.json", report, key)
    text = report.read_bytes().decode("latin-1", errors="ignore")
    assert "Manifest signature status" in text
    assert "valid" in text


def test_cli_end_to_end_default_report_key(tmp_path: Path) -> None:
    sample = tmp_path / "file.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    prove = run_cli("prove", str(sample), "--output", "proof_packet", cwd=tmp_path)
    assert prove.returncode == 0, prove.stderr
    verify = run_cli(
        "verify",
        str(sample),
        "--proof",
        "proof_packet/manifest.json",
        "--output",
        "verification_report.md",
        cwd=tmp_path,
    )
    assert verify.returncode == 0, verify.stderr
    assert (tmp_path / "proof_packet" / "verdict.json").exists()
    report = run_cli(
        "report",
        "--proof",
        "proof_packet/manifest.json",
        "--format",
        "pdf",
        "--output",
        "verification_report.pdf",
        cwd=tmp_path,
    )
    assert report.returncode == 0, report.stderr
    assert (tmp_path / "verification_report.pdf").exists()
    assert (tmp_path / "verification_report.pdf.sig").exists()
    assert (tmp_path / "proof_packet" / "signatures" / "manifest.sig").exists()
    assert (tmp_path / "proof_packet" / "signatures" / "manifest.pub").exists()
    assert (tmp_path / "keys" / "report_signing_key.pem").exists()
