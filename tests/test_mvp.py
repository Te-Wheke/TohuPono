from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import tohupono
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.file_identity import Blake3UnavailableError, hash_file
from tohupono.core.file_identity import inspect_file
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


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tohupono", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_package_imports() -> None:
    assert tohupono.__version__ == "0.2.0"


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


def test_hash_stability(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("evidence\n", encoding="utf-8")
    assert hash_file(sample, "sha256") == hash_file(sample, "sha256")
    assert hash_file(sample, "sha512") == hash_file(sample, "sha512")


def test_missing_file() -> None:
    result = run_cli("hash", "missing.txt", "--algorithm", "sha256")
    assert result.returncode == 2
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


def test_v030_universal_file_object_fields(tmp_path: Path) -> None:
    sample = tmp_path / "photo_like.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\nnot really an image")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest = load_manifest(proof_dir / "manifest.json")
    file_info = manifest["file"]
    assert file_info["file_id"] == file_info["sha256"]
    assert file_info["original_path"] == str(sample)
    assert file_info["filename"] == "photo_like.png"
    assert file_info["extension"] == ".png"
    assert file_info["metadata_trust_level"] == "untrusted_supporting_metadata"
    assert "os_created_time" in file_info
    assert "os_modified_time" in file_info
    assert "os_accessed_time" in file_info


def test_v030_empty_binary_video_and_unicode_names_prove(tmp_path: Path) -> None:
    cases = {
        "empty": b"",
        "binary.bin": bytes(range(32)),
        "clip.mp4": b"\x00\x00\x00\x18ftypmp42",
        "taonga_\u0101hua.dat": b"unicode filename bytes",
    }
    for name, payload in cases.items():
        sample = tmp_path / name
        sample.write_bytes(payload)
        proof_dir = tmp_path / f"{name}_proof"
        create_proof_packet(sample, proof_dir)
        result = verify_file(sample, proof_dir / "manifest.json")
        assert result.verdict == VERIFIED_INTEGRITY


def test_v030_compare_command_reports_match_and_difference(tmp_path: Path) -> None:
    one = tmp_path / "one.txt"
    copied = tmp_path / "copied.txt"
    changed = tmp_path / "changed.txt"
    one.write_bytes(b"same")
    copied.write_bytes(b"same")
    changed.write_bytes(b"different")
    match = run_cli("compare", str(one), str(copied), "--json")
    assert match.returncode == 0, match.stderr
    match_data = json.loads(match.stdout)
    assert match_data["status"] == "MATCH"
    assert match_data["file_id_same"] is True
    different = run_cli("compare", str(one), str(changed))
    assert different.returncode == 1
    assert "FAIL: files are not byte-identical." in different.stdout


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


def test_v030_empty_evidence_chain_is_invalid(tmp_path: Path) -> None:
    chain = tmp_path / "evidence_chain.jsonl"
    chain.write_text("\n\n", encoding="utf-8")
    ok, errors = verify_evidence_chain(chain)
    assert not ok
    assert "evidence_chain_empty" in errors
    assert evidence_chain_diagnostics(chain)["status"] == "invalid"


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


def test_v030_audit_command_reports_pass_warn_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("audit\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("audit", str(proof_dir))
    assert result.returncode == 0
    assert "PASS: manifest schema valid." in result.stdout
    assert "WARN: timestamp is local-only and not externally anchored." in result.stdout
