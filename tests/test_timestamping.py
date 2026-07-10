from __future__ import annotations

import json
from pathlib import Path

from tohupono.core.proof import create_proof_packet, load_manifest, make_manifest_id
from tohupono.timestamping.adapters import LocalTimestampAdapter, NoneTimestampAdapter
from tohupono.timestamping.model import LOCAL_TIMESTAMP_WARNING, TIMESTAMP_STATUSES

from tests.support import run_cli


def test_timestamp_status_vocabulary() -> None:
    assert TIMESTAMP_STATUSES == (
        "missing",
        "local_only",
        "pending",
        "anchored",
        "invalid",
        "unsupported",
        "error",
    )


def test_none_timestamp_adapter_returns_missing_and_unsupported() -> None:
    adapter = NoneTimestampAdapter()
    proof = adapter.create_timestamp("abc123")
    assert proof.status == "missing"
    assert proof.adapter == "none"
    result = adapter.verify_timestamp(proof)
    assert result.status == "unsupported"
    assert result.reasons


def test_local_timestamp_adapter_returns_local_only_warning() -> None:
    adapter = LocalTimestampAdapter()
    proof = adapter.create_timestamp("abc123")
    assert proof.status == "local_only"
    assert proof.adapter == "local"
    assert proof.target_digest == "abc123"
    assert LOCAL_TIMESTAMP_WARNING in proof.warnings
    result = adapter.verify_timestamp(proof)
    assert result.status == "local_only"
    assert LOCAL_TIMESTAMP_WARNING in result.warnings


def test_proof_manifest_includes_local_only_timestamping(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("timestamp manifest\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest = load_manifest(proof_dir / "manifest.json")
    assert manifest["timestamping"]["status"] == "local_only"
    assert manifest["timestamping"]["adapter"] == "local"
    assert manifest["timestamping"]["target_digest"] == manifest["file"]["sha256"]
    assert LOCAL_TIMESTAMP_WARNING in manifest["timestamping"]["warnings"]


def test_timestamping_metadata_does_not_change_manifest_id_seed(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("timestamp identity seed\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest = load_manifest(proof_dir / "manifest.json")
    original_id = make_manifest_id(manifest)
    manifest["timestamping"]["created_at"] = "2099-01-01T00:00:00Z"
    manifest["timestamping"]["status"] = "pending"
    assert make_manifest_id(manifest) == original_id


def test_timestamp_inspect_missing_timestamp_returns_missing(tmp_path: Path) -> None:
    packet = tmp_path / "packet"
    packet.mkdir()
    manifest = packet / "manifest.json"
    manifest.write_text(json.dumps({"file": {"sha256": "abc123"}}), encoding="utf-8")
    result = run_cli("timestamp", "inspect", str(packet))
    assert result.returncode == 0, result.stderr
    assert "Timestamp status: missing" in result.stdout


def test_timestamp_inspect_json_is_parseable(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("timestamp json\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "inspect", str(proof_dir), "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "local_only"
    assert data["timestamping"]["adapter"] == "local"
    assert LOCAL_TIMESTAMP_WARNING in data["warnings"]


def test_audit_reports_local_only_timestamp_as_warn(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("audit local timestamp\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("audit", str(proof_dir))
    assert result.returncode == 0, result.stderr
    assert "WARN: timestamp is local-only and not externally anchored." in result.stdout


def test_audit_reports_missing_timestamp_as_warn(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("audit missing timestamp\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest_path = proof_dir / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest.pop("timestamping", None)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    result = run_cli("audit", str(proof_dir))
    assert "WARN: no timestamp proof is present." in result.stdout


def test_missing_timestamp_does_not_cause_verification_failure(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("verify without timestamp\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest_path = proof_dir / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest.pop("timestamping", None)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    (proof_dir / "signatures" / "manifest.sig").unlink()
    result = run_cli("verify", str(sample), "--proof", str(manifest_path), "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)["verdict"] == "VERIFIED_INTEGRITY"


def test_cli_help_lists_timestamp_inspect() -> None:
    help_result = run_cli("--help")
    assert help_result.returncode == 0
    assert "timestamp" in help_result.stdout
    timestamp_help = run_cli("timestamp", "inspect", "--help")
    assert timestamp_help.returncode == 0
    assert "Inspect packet timestamp proof metadata" in timestamp_help.stdout


def test_timestamping_doc_exists_and_defines_local_only() -> None:
    text = Path("docs/TIMESTAMPING.md").read_text(encoding="utf-8")
    assert "local_only" in text
    assert "OpenTimestamps" in text
    assert "RFC 3161" in text
