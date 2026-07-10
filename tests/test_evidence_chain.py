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


def test_event_hash_ignores_event_hash_field() -> None:
    event = build_evidence_event(
        event_type="sealed",
        timestamp="2026-07-10T00:00:00Z",
        actor="tohupono",
        file_sha256="abc123",
        previous_event_hash=GENESIS_EVENT_HASH,
    )
    changed = dict(event)
    changed["event_hash"] = "different"
    assert event_hash(event) == event_hash(changed)

def test_evidence_chain_verification_detects_tampering(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    chain = proof_dir / "evidence_chain.jsonl"
    ok, errors = verify_evidence_chain(chain)
    assert ok
    assert errors == []
    event = json.loads(chain.read_text(encoding="utf-8"))
    event["actor"] = "tampered"
    chain.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    ok, errors = verify_evidence_chain(chain)
    assert not ok
    assert "event_1_hash_mismatch" in errors

def test_evidence_chain_diagnostics_missing_and_malformed(tmp_path: Path) -> None:
    missing = evidence_chain_diagnostics(tmp_path / "missing.jsonl")
    assert missing["status"] == "missing"
    malformed_path = tmp_path / "bad.jsonl"
    malformed_path.write_text("{not-json\n", encoding="utf-8")
    malformed = evidence_chain_diagnostics(malformed_path)
    assert malformed["status"] == "invalid"
    assert "event_1_invalid_json" in malformed["errors"]

def test_evidence_chain_diagnostics_missing_required_field(tmp_path: Path) -> None:
    event = build_evidence_event(
        event_type="sealed",
        timestamp="2026-07-10T00:00:00Z",
        actor="tohupono",
        file_sha256="abc123",
        previous_event_hash=GENESIS_EVENT_HASH,
    )
    del event["actor"]
    chain = tmp_path / "evidence_chain.jsonl"
    chain.write_text(canonical_json_text(event) + "\n", encoding="utf-8")
    result = evidence_chain_diagnostics(chain)
    assert result["status"] == "invalid"
    assert "event_1_missing_actor" in result["errors"]

def test_evidence_chain_links_previous_event_hash(tmp_path: Path) -> None:
    first = build_evidence_event(
        event_type="sealed",
        timestamp="2026-07-10T00:00:00Z",
        actor="tohupono",
        file_sha256="abc123",
        previous_event_hash=GENESIS_EVENT_HASH,
    )
    second = build_evidence_event(
        event_type="witnessed",
        timestamp="2026-07-10T00:01:00Z",
        actor="tohupono",
        file_sha256="abc123",
        previous_event_hash=str(first["event_hash"]),
    )
    chain = tmp_path / "evidence_chain.jsonl"
    chain.write_text(
        canonical_json_text(first) + "\n" + canonical_json_text(second) + "\n",
        encoding="utf-8",
    )
    assert verify_evidence_chain(chain) == (True, [])
    second["previous_event_hash"] = "broken"
    chain.write_text(
        canonical_json_text(first) + "\n" + canonical_json_text(second) + "\n",
        encoding="utf-8",
    )
    ok, errors = verify_evidence_chain(chain)
    assert not ok
    assert "event_2_previous_hash_mismatch" in errors

def test_verify_chain_cli_human_and_json(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("chain\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    chain = proof_dir / "evidence_chain.jsonl"
    human = run_cli("verify-chain", str(chain))
    assert human.returncode == 0, human.stderr
    assert "Evidence chain status: valid" in human.stdout
    machine = run_cli("verify-chain", str(chain), "--json")
    assert machine.returncode == 0, machine.stderr
    data = json.loads(machine.stdout)
    assert data["status"] == "valid"
    assert data["event_count"] == 1
    assert machine.returncode == 0

def test_verify_chain_cli_missing_and_malformed_exit_codes(tmp_path: Path) -> None:
    missing = run_cli("verify-chain", str(tmp_path / "missing.jsonl"), "--json")
    assert missing.returncode == 2
    missing_data = json.loads(missing.stdout)
    assert missing_data["status"] == "missing"

    malformed = tmp_path / "malformed.jsonl"
    malformed.write_text("{not-json\n", encoding="utf-8")
    result = run_cli("verify-chain", str(malformed), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert data["status"] == "invalid"
    assert "event_1_invalid_json" in data["errors"]

def test_verify_chain_cli_reports_broken_previous_hash(tmp_path: Path) -> None:
    first = build_evidence_event(
        event_type="sealed",
        timestamp="2026-07-10T00:00:00Z",
        actor="tohupono",
        file_sha256="abc123",
        previous_event_hash=GENESIS_EVENT_HASH,
    )
    second = build_evidence_event(
        event_type="witnessed",
        timestamp="2026-07-10T00:01:00Z",
        actor="tohupono",
        file_sha256="abc123",
        previous_event_hash="broken",
    )
    chain = tmp_path / "evidence_chain.jsonl"
    chain.write_text(canonical_json_text(first) + "\n" + canonical_json_text(second) + "\n", encoding="utf-8")
    result = run_cli("verify-chain", str(chain), "--json")
    data = json.loads(result.stdout)
    assert result.returncode == 1
    assert data["status"] == "invalid"
    assert "event_2_previous_hash_mismatch" in data["errors"]

def test_v030_empty_evidence_chain_is_invalid(tmp_path: Path) -> None:
    chain = tmp_path / "evidence_chain.jsonl"
    chain.write_text("\n\n", encoding="utf-8")
    ok, errors = verify_evidence_chain(chain)
    assert not ok
    assert "evidence_chain_empty" in errors
    assert evidence_chain_diagnostics(chain)["status"] == "invalid"
