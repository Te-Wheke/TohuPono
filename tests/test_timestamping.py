from __future__ import annotations

import json
from pathlib import Path

import pytest

import tohupono.core.proof as proof_core
from tohupono.core.proof import create_proof_packet, load_manifest, make_manifest_id
from tohupono.timestamping.adapters import LocalTimestampAdapter, NoneTimestampAdapter
from tohupono.timestamping.model import (
    LOCAL_TIMESTAMP_WARNING,
    TIMESTAMP_RECEIPT_STATUSES,
    TIMESTAMP_RECEIPT_TYPES,
    TIMESTAMP_STATUSES,
    UNVERIFIED_RECEIPT_WARNING,
)

from tests.support import run_cli


def test_timestamp_status_vocabulary() -> None:
    assert TIMESTAMP_STATUSES == (
        "missing",
        "local_only",
        "pending",
        "receipt_present",
        "anchored",
        "unverified",
        "provider_unavailable",
        "invalid",
        "unsupported",
        "deferred",
        "error",
    )


def test_timestamp_receipt_model_vocabulary() -> None:
    assert TIMESTAMP_RECEIPT_TYPES == ("manual", "opentimestamps", "rfc3161", "unknown")
    assert TIMESTAMP_RECEIPT_STATUSES == (
        "imported",
        "unverified",
        "verified",
        "invalid",
        "unsupported",
        "missing",
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
    assert data["status"] == "ok"
    assert data["timestamp_status"] == "local_only"
    assert data["timestamping"]["adapter"] == "local"
    assert data["receipts"] == []
    assert data["warning_count"] == 1
    assert data["failure_count"] == 0
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


def test_timestamp_import_records_receipt_metadata(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("receipt import\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "import", str(proof_dir), str(receipt), "--type", "manual", "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    record = data["receipt"]
    assert data["status"] == "ok"
    assert record["receipt_type"] == "manual"
    assert record["receipt_status"] == "unverified"
    assert record["target_digest"] == load_manifest(proof_dir / "manifest.json")["file"]["sha256"]
    assert record["receipt_size"] == receipt.stat().st_size
    assert UNVERIFIED_RECEIPT_WARNING in record["warnings"]
    assert (proof_dir / record["receipt_path"]).read_bytes() == receipt.read_bytes()


def test_timestamp_import_refuses_missing_packet(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    result = run_cli("timestamp", "import", str(tmp_path / "missing_packet"), str(receipt), "--json")
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"]["code"] == "MISSING_PROOF"


def test_timestamp_import_refuses_missing_receipt_file(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("missing receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "import", str(proof_dir), str(tmp_path / "missing_receipt.txt"), "--json")
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"]["code"] == "MISSING_FILE"


def test_timestamp_import_json_is_parseable(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("json receipt import\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt json\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "import", str(proof_dir), str(receipt), "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)["receipt"]["receipt_status"] == "unverified"


def test_timestamp_inspect_lists_imported_receipts(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("inspect receipt\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual inspect receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    run_cli("timestamp", "import", str(proof_dir), str(receipt), "--type", "manual")
    result = run_cli("timestamp", "inspect", str(proof_dir))
    assert result.returncode == 0
    assert "Receipt count: 1" in result.stdout
    assert "Receipt type: manual" in result.stdout
    assert "Receipt status: unverified" in result.stdout


def test_timestamp_inspect_json_includes_receipts_list(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("inspect receipt json\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual inspect receipt json\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    run_cli("timestamp", "import", str(proof_dir), str(receipt), "--type", "manual")
    result = run_cli("timestamp", "inspect", str(proof_dir), "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["receipt_count"] == 1
    assert data["receipts"][0]["receipt_status"] == "unverified"
    assert UNVERIFIED_RECEIPT_WARNING in data["receipts"][0]["warnings"]


def test_audit_warns_about_unverified_imported_receipt(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("audit receipt warning\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual audit receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    run_cli("timestamp", "import", str(proof_dir), str(receipt))
    result = run_cli("audit", str(proof_dir))
    assert result.returncode == 0
    assert "WARN: imported timestamp receipt is present but not externally verified by TohuPono." in result.stdout


def test_imported_receipt_does_not_alter_file_verification_verdict(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("verify with receipt\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual verify receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    run_cli("timestamp", "import", str(proof_dir), str(receipt))
    result = run_cli("verify", str(sample), "--proof", str(proof_dir / "manifest.json"), "--json")
    assert result.returncode == 0
    assert json.loads(result.stdout)["verdict"] == "VERIFIED_INTEGRITY"


def test_receipt_hash_matches_imported_receipt_bytes(tmp_path: Path) -> None:
    import hashlib

    sample = tmp_path / "source.txt"
    sample.write_text("receipt hash\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_bytes(b"manual receipt bytes\n")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "import", str(proof_dir), str(receipt), "--json")
    record = json.loads(result.stdout)["receipt"]
    assert record["receipt_sha256"] == hashlib.sha256(receipt.read_bytes()).hexdigest()


def test_unsupported_receipt_type_returns_input_error(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("bad receipt type\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "import", str(proof_dir), str(receipt), "--type", "badtype")
    assert result.returncode == 2


def test_cli_help_lists_timestamp_import() -> None:
    result = run_cli("timestamp", "import", "--help")
    assert result.returncode == 0
    assert "Import an offline timestamp receipt" in result.stdout


def test_cli_help_lists_timestamp_verify() -> None:
    result = run_cli("timestamp", "verify", "--help")
    assert result.returncode == 0
    assert "Verify timestamp metadata and imported receipt integrity" in result.stdout


def test_timestamp_verify_json_is_parseable(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("timestamp verify json\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["policy"] == "evidence_review"
    assert data["status"] == "warn"
    assert data["timestamping_status"] == "local_only"


def test_default_policy_warns_for_local_only_timestamp(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("timestamp default policy\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["failure_count"] == 0
    assert LOCAL_TIMESTAMP_WARNING in data["warnings"]


def test_strict_external_fails_for_local_only_without_external_timestamp(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("timestamp strict policy\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "verify", str(proof_dir), "--policy", "strict_external", "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert data["status"] == "fail"
    assert "timestamp_local_only" in data["failures"]


def test_manifest_declared_anchored_timestamp_fails_without_external_verification(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("forged anchored timestamp\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest_path = proof_dir / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest["timestamping"] = {
        "adapter": "manual",
        "created_at": manifest["sealed_at_utc"],
        "receipt": {"type": "self-declared"},
        "status": "anchored",
        "target_digest": manifest["file"]["sha256"],
        "warnings": [],
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--policy", "strict_external", "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert data["status"] == "fail"
    assert "timestamp_anchored_unverified" in data["failures"]
    assert data["receipt_count"] == 0


def test_unverified_imported_receipt_warns_under_evidence_review(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("receipt evidence review\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    run_cli("timestamp", "import", str(proof_dir), str(receipt))
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["failure_count"] == 0
    assert UNVERIFIED_RECEIPT_WARNING in data["warnings"]


def test_unverified_imported_receipt_fails_under_strict_external(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("receipt strict review\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    run_cli("timestamp", "import", str(proof_dir), str(receipt))
    result = run_cli("timestamp", "verify", str(proof_dir), "--policy", "strict_external", "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert data["status"] == "fail"
    assert any("unverified_under_strict_external" in failure for failure in data["failures"])


def _receipt_metadata_path(proof_dir: Path) -> Path:
    return next((proof_dir / "timestamp_receipts").glob("receipt_*.json"))


def _import_receipt(proof_dir: Path, receipt: Path) -> dict[str, object]:
    result = run_cli("timestamp", "import", str(proof_dir), str(receipt), "--json")
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["receipt"]


def test_self_declared_verified_receipt_status_is_not_trusted(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("self verified receipt\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    record["receipt_status"] = "verified"
    _receipt_metadata_path(proof_dir).write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--policy", "strict_external", "--json")
    assert result.returncode == 1
    failures = json.loads(result.stdout)["failures"]
    assert any("verified_receipt_untrusted" in failure for failure in failures)
    assert "strict_external_timestamp_missing" in failures


def test_timestamp_import_refuses_symlinked_receipt_directory(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("symlink import dir\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    outside = tmp_path / "outside_receipts"
    outside.mkdir()
    try:
        (proof_dir / "timestamp_receipts").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    result = run_cli("timestamp", "import", str(proof_dir), str(receipt), "--json")
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"]["code"] == "INVALID_ARGUMENT"
    assert list(outside.iterdir()) == []


def test_manifest_symlink_is_rejected_before_timestamp_read(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("manifest symlink\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest_path = proof_dir / "manifest.json"
    outside = tmp_path / "outside_manifest.json"
    outside.write_text(manifest_path.read_text(encoding="utf-8"), encoding="utf-8")
    manifest_path.unlink()
    try:
        manifest_path.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    result = run_cli("timestamp", "inspect", str(proof_dir), "--json")
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"]["code"] == "INVALID_ARGUMENT"


def test_receipt_metadata_symlink_is_rejected_before_timestamp_read(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("receipt metadata symlink\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    metadata_path = _receipt_metadata_path(proof_dir)
    outside = tmp_path / "outside_receipt.json"
    outside.write_text(metadata_path.read_text(encoding="utf-8"), encoding="utf-8")
    metadata_path.unlink()
    try:
        metadata_path.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    failures = json.loads(result.stdout)["failures"]
    assert any("metadata_missing_fields" in failure for failure in failures)
    assert record["receipt_id"] in result.stdout


def test_receipt_target_digest_mismatch_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("target mismatch\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    record["target_digest"] = "0" * 64
    _receipt_metadata_path(proof_dir).write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert any("target_digest_mismatch" in failure for failure in json.loads(result.stdout)["failures"])


def test_receipt_missing_stored_file_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("missing stored receipt\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    (proof_dir / str(record["receipt_path"])).unlink()
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert any("stored_file_missing" in failure for failure in json.loads(result.stdout)["failures"])


def _receipt_path_failure(tmp_path: Path, receipt_path_value: object, expected_failure: str) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("receipt path failure\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    record["receipt_path"] = receipt_path_value
    _receipt_metadata_path(proof_dir).write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert any(expected_failure in failure for failure in json.loads(result.stdout)["failures"])


def test_receipt_absolute_path_is_fail(tmp_path: Path) -> None:
    _receipt_path_failure(tmp_path, str(tmp_path / "outside.bin"), "stored_file_path_invalid")


def test_receipt_parent_traversal_is_fail(tmp_path: Path) -> None:
    _receipt_path_failure(tmp_path, "../outside.bin", "stored_file_path_invalid")


def test_receipt_nested_traversal_is_fail(tmp_path: Path) -> None:
    _receipt_path_failure(tmp_path, "timestamp_receipts/nested/../../outside.bin", "stored_file_path_invalid")


def test_receipt_symlink_file_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("symlink receipt\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    stored = proof_dir / str(record["receipt_path"])
    target = tmp_path / "outside.bin"
    target.write_text("outside\n", encoding="utf-8")
    stored.unlink()
    try:
        stored.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert any("stored_file_path_invalid" in failure for failure in data["failures"])


def test_receipt_symlinked_receipt_directory_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("symlink receipt dir\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    receipts = proof_dir / "timestamp_receipts"
    receipts.mkdir()
    outside = tmp_path / "outside_receipts"
    outside.mkdir()
    receipts.rmdir()
    try:
        receipts.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    record = {
        "adapter_type": "manual",
        "imported_at": "2026-01-01T00:00:00Z",
        "receipt_id": "tr_symlink_dir",
        "receipt_path": "timestamp_receipts/receipt.bin",
        "receipt_sha256": "0" * 64,
        "receipt_size": 1,
        "receipt_status": "unverified",
        "receipt_type": "manual",
        "target_digest": load_manifest(proof_dir / "manifest.json")["file"]["sha256"],
    }
    (outside / "receipt_symlink_dir.json").write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert any("metadata_missing_fields" in failure for failure in data["failures"])
    assert data["receipts"][0]["warnings"] == ["Timestamp receipt directory is unsafe."]


def test_receipt_directory_instead_of_regular_file_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("receipt directory\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    stored = proof_dir / str(record["receipt_path"])
    stored.unlink()
    stored.mkdir()
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert any("stored_file_not_regular" in failure for failure in json.loads(result.stdout)["failures"])


def test_receipt_oversized_stored_file_is_fail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("oversized stored receipt\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    stored = proof_dir / str(record["receipt_path"])
    stored.write_bytes(b"x" * 8)
    monkeypatch.setattr(proof_core, "MAX_RECEIPT_BYTES", 4)
    data = proof_core.timestamp_verification_diagnostics(proof_dir)
    assert data["status"] == "fail"
    assert any("stored_file_too_large" in failure for failure in data["failures"])


def test_receipt_sha256_mismatch_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("sha mismatch\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    (proof_dir / str(record["receipt_path"])).write_text("changed receipt\n", encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert any("sha256_mismatch" in failure for failure in json.loads(result.stdout)["failures"])


def test_duplicate_receipt_id_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("duplicate receipt\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    duplicate_path = proof_dir / "timestamp_receipts" / "receipt_duplicate.json"
    duplicate_path.write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert "timestamp_receipt_duplicate_id" in json.loads(result.stdout)["failures"]


def test_receipt_metadata_missing_required_field_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("missing receipt metadata field\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    record.pop("receipt_sha256")
    _receipt_metadata_path(proof_dir).write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert any("metadata_missing_fields" in failure for failure in json.loads(result.stdout)["failures"])


def test_receipt_metadata_unsupported_type_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("unsupported receipt type metadata\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    record["receipt_type"] = "badtype"
    _receipt_metadata_path(proof_dir).write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert any("unsupported_receipt_type" in failure for failure in json.loads(result.stdout)["failures"])


def test_receipt_metadata_invalid_status_is_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("invalid receipt status metadata\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    record["receipt_status"] = "strange"
    _receipt_metadata_path(proof_dir).write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("timestamp", "verify", str(proof_dir), "--json")
    assert result.returncode == 1
    assert any("invalid_receipt_status" in failure for failure in json.loads(result.stdout)["failures"])


def test_timestamp_verify_unsupported_policy_returns_exit_code_2(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("bad policy\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    result = run_cli("timestamp", "verify", str(proof_dir), "--policy", "unsupported")
    assert result.returncode == 2


def test_timestamp_inspect_json_includes_diagnostic_counts(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("inspect counts\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    run_cli("timestamp", "import", str(proof_dir), str(receipt))
    result = run_cli("timestamp", "inspect", str(proof_dir), "--json")
    data = json.loads(result.stdout)
    assert data["receipt_count"] == 1
    assert data["warning_count"] >= 2
    assert data["failure_count"] == 0


def test_audit_includes_timestamp_failure_for_receipt_target_mismatch(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("audit timestamp fail\n", encoding="utf-8")
    receipt = tmp_path / "receipt.txt"
    receipt.write_text("manual receipt\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    record = _import_receipt(proof_dir, receipt)
    record["target_digest"] = "f" * 64
    _receipt_metadata_path(proof_dir).write_text(json.dumps(record), encoding="utf-8")
    result = run_cli("audit", str(proof_dir))
    assert result.returncode == 1
    assert "FAIL: timestamp receipt target digest does not match packet manifest digest." in result.stdout


def test_timestamping_doc_documents_imported_receipts() -> None:
    text = Path("docs/TIMESTAMPING.md").read_text(encoding="utf-8")
    assert "imported receipts" in text.lower()
    assert "unverified" in text
    assert "receipt hash" in text.lower()


def test_timestamping_doc_documents_policies() -> None:
    text = Path("docs/TIMESTAMPING.md").read_text(encoding="utf-8")
    assert "evidence_review" in text
    assert "strict_external" in text
    assert "receipt target digest" in text.lower()
