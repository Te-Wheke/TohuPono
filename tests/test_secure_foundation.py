from __future__ import annotations

import json
import socket
import subprocess
import urllib.request
import http.client
from pathlib import Path

from tohupono.concepts.model import MATURITY_VALUES
from tohupono.concepts.registry import concept_registry, get_concept
from tohupono.core.proof import create_proof_packet, timestamp_verification_diagnostics
from tohupono.timestamping.model import TimestampReceipt
from tohupono.timestamping.provider import TimestampRequest
from tohupono.timestamping.registry import timestamp_provider_registry
from tohupono.trust.keys import verify_lifecycle_chain

from tests.support import run_cli


def test_agents_operating_contract_mentions_proof_concepts_and_security_rules() -> None:
    text = Path("AGENTS.md").read_text(encoding="utf-8")
    assert "Proof Concepts" in text
    assert "Digest integrity does not automatically prove authenticity" in text
    assert "Possession does not automatically prove ownership" in text
    assert "never use shell command strings for OpenSSL" in text
    assert "Do not use macrons" in text
    assert "must not:" in text


def test_proof_concepts_use_declared_maturity_values_only() -> None:
    registry = concept_registry()
    assert {item["concept_id"] for item in registry} >= {
        "integrity",
        "existence",
        "records",
        "lineage",
        "authenticity",
        "ownership",
        "reality",
    }
    for item in registry:
        assert item["implementation_maturity"] in MATURITY_VALUES
        assert item["claim_boundary"]
        assert item["known_limitations"]


def test_initial_proof_concept_maturity_assignments() -> None:
    assert get_concept("integrity").implementation_maturity == "locally_supported"
    assert get_concept("existence").implementation_maturity == "locally_supported"
    assert get_concept("records").implementation_maturity == "locally_supported"
    assert get_concept("lineage").implementation_maturity == "locally_supported"
    assert get_concept("authenticity").implementation_maturity == "modelled"
    assert get_concept("ownership").implementation_maturity == "modelled"
    assert get_concept("reality").implementation_maturity == "modelled"


def test_concept_registry_output_is_deterministic() -> None:
    first = json.dumps(concept_registry(), sort_keys=True, separators=(",", ":"))
    second = json.dumps(concept_registry(), sort_keys=True, separators=(",", ":"))
    assert first == second


def test_timestamp_provider_registry_lists_offline_placeholders() -> None:
    registry = timestamp_provider_registry()
    assert registry.names() == ["opentimestamps", "rfc3161"]
    for name in registry.names():
        provider = registry.get(name)
        assert provider.supports_create is False
        assert provider.supports_verify is False


def test_timestamp_provider_placeholders_return_unavailable_without_network() -> None:
    registry = timestamp_provider_registry()
    request = TimestampRequest(target_digest="a" * 64, adapter_type="opentimestamps")
    result = registry.get("opentimestamps").create(request)
    assert result.status == "provider_unavailable"
    assert "No network timestamp request was made." in result.reasons


def test_timestamp_provider_placeholders_do_not_call_network_or_subprocess(monkeypatch) -> None:
    calls: list[str] = []

    def blocked(*_args: object, **_kwargs: object) -> None:
        calls.append("blocked")
        raise AssertionError("network or subprocess call attempted")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(http.client.HTTPConnection, "request", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)

    registry = timestamp_provider_registry()
    request = TimestampRequest(target_digest="b" * 64, adapter_type="opentimestamps")
    receipt = TimestampReceipt(
        receipt_id="test_receipt",
        receipt_type="opentimestamps",
        receipt_path="timestamp_receipts/test.bin",
        receipt_sha256="c" * 64,
        receipt_size=19,
        receipt_format="bin",
        receipt_status="unverified",
        adapter_type="opentimestamps",
        target_digest="b" * 64,
        imported_at="2026-01-01T00:00:00Z",
        warnings=[],
    )
    for provider_name in registry.names():
        provider = registry.get(provider_name)
        assert provider.create(request).status == "provider_unavailable"
        assert provider.verify(receipt).status in {"provider_unavailable", "deferred"}
    assert calls == []


def test_timestamp_receipt_path_escape_fails(tmp_path: Path) -> None:
    packet = tmp_path / "packet"
    source = tmp_path / "source.txt"
    source.write_text("receipt path escape\n", encoding="utf-8")
    create_proof_packet(source, packet)
    receipts = packet / "timestamp_receipts"
    receipts.mkdir()
    record = {
        "adapter_type": "manual",
        "imported_at": "2026-01-01T00:00:00Z",
        "receipt_id": "tr_escape",
        "receipt_path": "../outside.bin",
        "receipt_sha256": "0" * 64,
        "receipt_size": 1,
        "receipt_status": "unverified",
        "receipt_type": "manual",
        "target_digest": json.loads((packet / "manifest.json").read_text(encoding="utf-8"))["file"]["sha256"],
    }
    (receipts / "receipt_escape.json").write_text(json.dumps(record), encoding="utf-8")
    result = timestamp_verification_diagnostics(packet)
    assert result["status"] == "fail"
    assert any("stored_file_path_invalid" in failure for failure in result["failures"])


def test_lifecycle_chain_tampering_fails(tmp_path: Path) -> None:
    key_dir = tmp_path / "keys"
    assert run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json").returncode == 0
    assert (
        run_cli(
            "key",
            "rotate",
            "--purpose",
            "manifest",
            "--reason",
            "chain tamper",
            "--output-dir",
            str(key_dir),
            "--json",
        ).returncode
        == 0
    )
    log_path = key_dir / "key_lifecycle_log.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[-1])
    event["reason"] = "edited"
    lines[-1] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify_lifecycle_chain(key_dir)
    assert result["status"] == "invalid"
    assert any("hash_mismatch" in failure for failure in result["failures"])


def test_no_macron_scan_passes_project_text() -> None:
    result = subprocess.run(
        ["python", "scripts/check_no_macrons.py"],
        cwd=Path.cwd(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout


def test_no_hidden_runtime_storage_architecture_terms_in_new_docs() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            Path("AGENTS.md"),
            Path("docs/PROOF_CONCEPTS.md"),
            Path("docs/SECURITY_ARCHITECTURE.md"),
        ]
    )
    assert ("WH" + "KPP") not in combined
    assert ("." + "whkpp") not in combined
    assert "runtime storage resolver" not in combined.lower()
