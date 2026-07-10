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
    assert "Evidence chain status" in text

def test_markdown_report_has_required_sections(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("markdown\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    report = tmp_path / "verification_report.md"
    result = run_cli("verify", str(sample), "--proof", str(proof_dir / "manifest.json"), "--output", str(report))
    assert result.returncode == 0, result.stderr
    text = report.read_text(encoding="utf-8")
    for section in [
        "# TohuPono Verification Report",
        "## Verdict",
        "## File Identity",
        "## Manifest Signature",
        "## Evidence Chain",
        "## Notes",
        "## Warnings",
        "## Reasons",
        "## Legal-Support Boundary",
    ]:
        assert section in text
    assert (
        "This report supports evidence review by recording deterministic file identity, verification results, "
        "signatures, and proof-packet status. It does not by itself prove real-world truth, authorship, intent, "
        "or legal admissibility."
    ) in text

def test_v030_report_signature_mismatch_fails_packet_diagnostics(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("report\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    report = proof_dir / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(proof_dir / "manifest.json", report, key)
    report.write_bytes(report.read_bytes() + b"tamper")
    result = packet_diagnostics(proof_dir)
    assert result["report_signature_status"] == "invalid"
    assert "report_signature_invalid" in result["failures"]
