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


def test_verify_original_and_modified(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    out = tmp_path / "proof_packet"
    create_proof_packet(sample, out)
    result = verify_file(sample, out / "manifest.json")
    assert result.verdict == VERIFIED_INTEGRITY
    assert result.manifest_signature_status == "valid"
    assert result.evidence_chain_status == "valid"
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

def test_renamed_and_copied_files_verify_by_digest(tmp_path: Path) -> None:
    original = tmp_path / "original.txt"
    renamed = tmp_path / "renamed.bin"
    copied_dir = tmp_path / "copy"
    copied_dir.mkdir()
    copied = copied_dir / "copied_without_extension"
    original.write_bytes(b"same bytes\n")
    renamed.write_bytes(original.read_bytes())
    copied.write_bytes(original.read_bytes())
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(original, proof_dir)
    renamed_result = verify_file(renamed, proof_dir / "manifest.json")
    copied_result = verify_file(copied, proof_dir / "manifest.json")
    assert renamed_result.verdict == VERIFIED_INTEGRITY
    assert PATH_DIFFERS_NOTE in renamed_result.notes
    assert copied_result.verdict == VERIFIED_INTEGRITY
    assert PATH_DIFFERS_NOTE in copied_result.notes

def test_verify_json_returns_required_keys(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    copied = tmp_path / "copied.txt"
    sample.write_text("slice two bytes\n", encoding="utf-8")
    copied.write_text("slice two bytes\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("verify", str(copied), "--proof", str(proof_dir / "manifest.json"), "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert set(
        [
            "verdict",
            "classification",
            "file_sha256",
            "expected_sha256",
            "manifest_signature_status",
            "evidence_chain_status",
            "warnings",
            "reasons",
            "notes",
        ]
    ).issubset(data)
    assert data["verdict"] == VERIFIED_INTEGRITY
    assert data["manifest_signature_status"] == "valid"
    assert data["evidence_chain_status"] == "valid"
    assert PATH_DIFFERS_NOTE in data["notes"]
    assert result.returncode == 0

def test_missing_signature_verify_exit_code_success_for_matching_digest(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("source\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    (proof_dir / "signatures" / "manifest.sig").unlink()
    result = run_cli("verify", str(sample), "--proof", str(proof_dir / "manifest.json"), "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["verdict"] == VERIFIED_INTEGRITY
    assert data["manifest_signature_status"] == "missing"

def test_modified_source_bytes_still_altered_after_proof_with_valid_signature(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("before\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    sample.write_text("after\n", encoding="utf-8")
    result = run_cli("verify", str(sample), "--proof", str(proof_dir / "manifest.json"), "--json")
    data = json.loads(result.stdout)
    assert result.returncode == 1
    assert data["verdict"] == ALTERED_AFTER_PROOF
    assert data["manifest_signature_status"] == "valid"

def test_v030_verify_file_accepts_copied_and_renamed_files(tmp_path: Path) -> None:
    original = tmp_path / "source.log"
    renamed = tmp_path / "renamed.archive"
    copied = tmp_path / "nested" / "copy"
    copied.parent.mkdir()
    original.write_bytes(b"custody bytes")
    renamed.write_bytes(original.read_bytes())
    copied.write_bytes(original.read_bytes())
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(original, proof_dir)
    for candidate in [renamed, copied]:
        result = run_cli("verify-file", str(candidate), str(proof_dir), "--json")
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data["verdict"] == VERIFIED_INTEGRITY
        assert PATH_DIFFERS_NOTE in data["notes"]
    human = run_cli("verify-file", str(renamed), str(proof_dir))
    assert "PASS: file hash matches manifest." in human.stdout
    assert "WARN: current path differs from original recorded path." in human.stdout

def test_v030_verify_file_rejects_modified_file(tmp_path: Path) -> None:
    original = tmp_path / "source.txt"
    changed = tmp_path / "changed.txt"
    original.write_bytes(b"original")
    changed.write_bytes(b"changed")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(original, proof_dir)
    result = run_cli("verify-file", str(changed), str(proof_dir), "--json")
    assert result.returncode == 1
    assert json.loads(result.stdout)["verdict"] == ALTERED_AFTER_PROOF
