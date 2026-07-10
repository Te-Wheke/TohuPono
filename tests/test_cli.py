from __future__ import annotations

import json
import os
from pathlib import Path

import tohupono
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.file_identity import Blake3UnavailableError, hash_file, inspect_file
from tohupono.core.proof import (
    GENESIS_EVENT_HASH,
    build_evidence_event,
    create_proof_packet,
    evidence_chain_diagnostics,
    event_hash,
    load_manifest,
    make_proof_id,
    packet_diagnostics,
    verify_evidence_chain,
)
from tohupono.reporting.pro_report import COMMUNITY_TEXT, FORBIDDEN_LANGUAGE, generate_report
from tohupono.trust.keys import export_public_key, verify_signature
from tohupono.verdicts.classifier import (
    ALTERED_AFTER_PROOF,
    PATH_DIFFERS_NOTE,
    PROVENANCE_CONFLICT,
    UNPROVEN,
    VERIFIED_INTEGRITY,
    verify_file,
)

from tests.support import run_cli


def test_package_imports() -> None:
    assert tohupono.__version__ == "0.3.0"

def test_cli_help() -> None:
    result = run_cli("--help")
    assert result.returncode == 0
    assert "tohupono" in result.stdout
    for command in [
        "inspect",
        "hash",
        "prove",
        "verify",
        "verify-file",
        "verify-chain",
        "inspect-proof",
        "compare",
        "amend",
        "audit",
        "report",
    ]:
        assert command in result.stdout

def test_missing_file() -> None:
    result = run_cli("hash", "missing.txt", "--algorithm", "sha256")
    assert result.returncode == 2
    assert "File not found" in result.stderr

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

def test_verify_json_missing_file_error_shape(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("source\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli(
        "verify",
        str(tmp_path / "missing.txt"),
        "--proof",
        str(proof_dir / "manifest.json"),
        "--json",
    )
    assert result.returncode == 2
    data = json.loads(result.stdout)
    assert data["status"] == "error"
    assert data["error"]["code"] == "MISSING_FILE"

def test_verify_json_missing_proof_error_shape(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("source\n", encoding="utf-8")
    result = run_cli("verify", str(sample), "--proof", str(tmp_path / "missing_manifest.json"), "--json")
    assert result.returncode == 2
    data = json.loads(result.stdout)
    assert data["status"] == "error"
    assert data["error"]["code"] == "MISSING_PROOF"

def test_verify_exit_codes_for_altered_and_conflict(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("before\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    sample.write_text("after\n", encoding="utf-8")
    altered = run_cli("verify", str(sample), "--proof", str(proof_dir / "manifest.json"), "--json")
    assert altered.returncode == 1
    assert json.loads(altered.stdout)["verdict"] == ALTERED_AFTER_PROOF

    manifest = json.loads((proof_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["tool"]["version"] = "tampered"
    (proof_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    conflict = run_cli("verify", str(sample), "--proof", str(proof_dir / "manifest.json"), "--json")
    assert conflict.returncode == 1
    assert json.loads(conflict.stdout)["verdict"] == PROVENANCE_CONFLICT

def test_inspect_proof_cli_human_and_json(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("inspect\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest = proof_dir / "manifest.json"
    human = run_cli("inspect-proof", str(manifest))
    assert human.returncode == 0, human.stderr
    assert "Proof manifest inspected. Source file was not verified in this command." in human.stdout
    assert "Proof ID:" in human.stdout
    machine = run_cli("inspect-proof", str(manifest), "--json")
    assert machine.returncode == 0, machine.stderr
    data = json.loads(machine.stdout)
    assert data["proof_id"]
    assert data["manifest_signature_status"] == "valid"
    assert data["evidence_chain_status"] == "valid"
    assert data["boundary"] == "Proof manifest inspected. Source file was not verified in this command."
    assert machine.returncode == 0

def test_inspect_proof_json_missing_manifest_error_shape(tmp_path: Path) -> None:
    result = run_cli("inspect-proof", str(tmp_path / "missing_manifest.json"), "--json")
    assert result.returncode == 2
    data = json.loads(result.stdout)
    assert data["status"] == "error"
    assert data["error"]["code"] == "MISSING_PROOF"

def test_v030_audit_command_reports_pass_warn_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("audit\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("audit", str(proof_dir))
    assert result.returncode == 0
    assert "PASS: manifest schema valid." in result.stdout
    assert "WARN: timestamp is local-only and not externally anchored." in result.stdout
