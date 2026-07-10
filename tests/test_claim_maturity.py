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


def test_claim_maturity_doc_defines_integrity_rules() -> None:
    text = Path("docs/CLAIM_MATURITY.md").read_text(encoding="utf-8")
    for required in [
        "legally proven",
        "proof-of-reality",
        "technical verification",
        "chain-of-custody support",
        "legal admissibility",
        "legal proof",
        "`FAIL`: breaks verification or allows false confidence",
        "`WARN`: does not break verification but weakens evidential strength",
        "`LIMIT`: outside current scope but must be disclosed clearly",
        "`TODO`: accepted improvement target for the roadmap",
        "Level 1: Technical Identity",
        "Level 2: Packet Integrity",
        "Level 3: Evidence Support",
        "Level 4: Reality Support",
        "Level 5: Legal Proof",
    ]:
        assert required in text

def test_claim_maturity_doc_allows_bounded_technical_claims() -> None:
    text = Path("docs/CLAIM_MATURITY.md").read_text(encoding="utf-8")
    for allowed in [
        "byte-identical",
        "digest match",
        "file identity match",
        "verified file integrity",
        "manifest verified",
        "signature valid",
        "evidence chain intact",
        "packet integrity verified",
    ]:
        assert allowed in text

def test_generated_outputs_do_not_make_restricted_final_claims(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    copied = tmp_path / "copied.txt"
    sample.write_text("claims\n", encoding="utf-8")
    copied.write_text("claims\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)

    compare = run_cli("compare", str(sample), str(copied))
    audit = run_cli("audit", str(proof_dir))
    report = tmp_path / "verification_report.md"
    verify = run_cli("verify", str(sample), "--proof", str(proof_dir / "manifest.json"), "--output", str(report))
    assert compare.returncode == 0
    assert audit.returncode == 0
    assert verify.returncode == 0

    combined = "\n".join([compare.stdout, audit.stdout, report.read_text(encoding="utf-8")]).lower()
    for restricted in [
        "legally proven",
        "court-ready",
        "guaranteed authentic",
        "impossible to fake",
        "not ai",
        "proof of reality",
        "proof-of-reality",
    ]:
        assert restricted not in combined

def test_generated_outputs_keep_allowed_mature_claims_bounded(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    copied = tmp_path / "copied.txt"
    sample.write_text("bounded\n", encoding="utf-8")
    copied.write_text("bounded\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)

    compare = run_cli("compare", str(sample), str(copied))
    audit = run_cli("audit", str(proof_dir))
    assert "PASS: files are byte-identical." in compare.stdout
    assert "PASS: file_id matches." in compare.stdout
    assert "PASS: evidence chain intact." in audit.stdout
    assert "PASS: manifest signature valid." in audit.stdout
