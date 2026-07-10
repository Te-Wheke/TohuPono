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
    chain_event = json.loads((out / "evidence_chain.jsonl").read_text(encoding="utf-8"))
    for key in [
        "event_id",
        "event_type",
        "timestamp",
        "actor",
        "file_sha256",
        "previous_event_hash",
        "event_hash",
    ]:
        assert key in chain_event
    assert not (out / "payload").exists()

def test_include_payload_copies_payload(tmp_path: Path) -> None:
    sample = tmp_path / "contract.pdf"
    sample.write_bytes(b"%PDF-1.7\nsample")
    out = tmp_path / "proof_packet"
    create_proof_packet(sample, out, include_payload=True)
    assert (out / "payload" / "contract.pdf").exists()

def test_proof_id_is_deterministic_for_canonical_seed(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("same bytes\n", encoding="utf-8")
    identity = inspect_file(sample)
    sealed_at = "2026-07-10T00:00:00Z"
    assert make_proof_id(identity, sealed_at) == make_proof_id(identity, sealed_at)

def test_changed_digest_changes_proof_id(tmp_path: Path) -> None:
    one = tmp_path / "one.txt"
    two = tmp_path / "two.txt"
    one.write_text("one\n", encoding="utf-8")
    two.write_text("two\n", encoding="utf-8")
    sealed_at = "2026-07-10T00:00:00Z"
    assert make_proof_id(inspect_file(one), sealed_at) != make_proof_id(inspect_file(two), sealed_at)

def test_any_file_types_prove_and_verify(tmp_path: Path) -> None:
    files = [
        ("text.txt", b"text file\n"),
        ("binary.bin", bytes([0, 1, 2, 3, 255])),
        ("extensionless", b"no extension\n"),
    ]
    for name, data in files:
        sample = tmp_path / name
        sample.write_bytes(data)
        proof_dir = tmp_path / f"{name}_proof"
        create_proof_packet(sample, proof_dir)
        result = verify_file(sample, proof_dir / "manifest.json")
        assert result.verdict == VERIFIED_INTEGRITY

def test_v030_packet_verify_detects_manifest_and_chain_tampering(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_bytes(b"packet")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    ok = run_cli("verify", str(proof_dir), "--json")
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["status"] == "warn"

    manifest_path = proof_dir / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest["tool"]["version"] = "tampered"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    tampered_manifest = run_cli("verify", str(proof_dir), "--json")
    assert tampered_manifest.returncode == 1
    assert "manifest_id_mismatch" in json.loads(tampered_manifest.stdout)["failures"]

    create_proof_packet(sample, tmp_path / "proof_packet_chain")
    chain_dir = tmp_path / "proof_packet_chain"
    event = json.loads((chain_dir / "evidence_chain.jsonl").read_text(encoding="utf-8"))
    event["actor"] = "edited"
    (chain_dir / "evidence_chain.jsonl").write_text(canonical_json_text(event) + "\n", encoding="utf-8")
    tampered_chain = run_cli("verify", str(chain_dir), "--json")
    assert tampered_chain.returncode == 1
    assert "event_1_hash_mismatch" in json.loads(tampered_chain.stdout)["failures"]

def test_v030_packet_overwrite_refused(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("overwrite\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    first = run_cli("prove", str(sample), "--output", str(proof_dir))
    assert first.returncode == 0, first.stderr
    second = run_cli("prove", str(sample), "--output", str(proof_dir))
    assert second.returncode == 2
    assert "Refusing to overwrite existing proof packet" in second.stderr

def test_v030_amendment_does_not_mutate_original_packet(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("amend\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    before = {
        path.relative_to(proof_dir): hash_file(path, "sha256")
        for path in proof_dir.rglob("*")
        if path.is_file()
    }
    result = run_cli("amend", str(proof_dir), "--note", "clarify custody", "--json")
    assert result.returncode == 0, result.stderr
    after = {
        path.relative_to(proof_dir): hash_file(path, "sha256")
        for path in proof_dir.rglob("*")
        if path.is_file()
    }
    assert before == after
    amendment_dir = Path(json.loads(result.stdout)["amendment"])
    assert (amendment_dir / "amendment.json").exists()
    amendment = json.loads((amendment_dir / "amendment.json").read_text(encoding="utf-8"))
    assert amendment["parent_packet_id"]
    assert amendment["note"] == "clarify custody"

def test_v030_deterministic_ids_reproduce_with_same_inputs(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_bytes(b"stable")
    first = tmp_path / "first_packet"
    second = tmp_path / "second_packet"
    sealed_at = "2026-07-10T00:00:00Z"
    create_proof_packet(sample, first, sealed_at_utc=sealed_at)
    create_proof_packet(sample, second, sealed_at_utc=sealed_at)
    first_manifest = load_manifest(first / "manifest.json")
    second_manifest = load_manifest(second / "manifest.json")
    assert first_manifest["proof_id"] == second_manifest["proof_id"]
    assert first_manifest["identifiers"] == second_manifest["identifiers"]

def test_v030_changed_digest_changes_deterministic_ids(tmp_path: Path) -> None:
    one = tmp_path / "one.txt"
    two = tmp_path / "two.txt"
    one.write_bytes(b"one")
    two.write_bytes(b"two")
    sealed_at = "2026-07-10T00:00:00Z"
    one_dir = tmp_path / "one_packet"
    two_dir = tmp_path / "two_packet"
    create_proof_packet(one, one_dir, sealed_at_utc=sealed_at)
    create_proof_packet(two, two_dir, sealed_at_utc=sealed_at)
    one_ids = load_manifest(one_dir / "manifest.json")["identifiers"]
    two_ids = load_manifest(two_dir / "manifest.json")["identifiers"]
    assert one_ids["file_id"] != two_ids["file_id"]
    assert one_ids["proof_id"] != two_ids["proof_id"]
    assert one_ids["manifest_id"] != two_ids["manifest_id"]
    assert one_ids["packet_id"] != two_ids["packet_id"]
