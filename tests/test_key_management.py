from __future__ import annotations

import json
from pathlib import Path

from tohupono.trust.keys import KEY_PURPOSES

from tests.support import run_cli


def test_key_purpose_registry_contains_manifest_and_report() -> None:
    assert "manifest" in KEY_PURPOSES
    assert "report" in KEY_PURPOSES


def test_key_purpose_registry_has_stable_default_paths() -> None:
    assert KEY_PURPOSES["manifest"].private_key_path.as_posix() == "keys/manifest_signing_key.pem"
    assert KEY_PURPOSES["manifest"].public_key_path.as_posix() == "keys/manifest_signing_key.pub"
    assert KEY_PURPOSES["report"].private_key_path.as_posix() == "keys/report_signing_key.pem"
    assert KEY_PURPOSES["report"].public_key_path.as_posix() == "keys/report_signing_key.pub"


def test_key_inspect_human_mode_does_not_print_private_key_contents(tmp_path: Path) -> None:
    result = run_cli("key", "inspect", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Purpose: manifest" in result.stdout
    assert "Private key path: keys/manifest_signing_key.pem" in result.stdout
    assert "BEGIN PRIVATE KEY" not in result.stdout


def test_key_inspect_json_is_parseable(tmp_path: Path) -> None:
    result = run_cli("key", "inspect", "--json", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "ok"
    assert isinstance(data["keys"], list)
    assert {item["purpose"] for item in data["keys"]} >= {"manifest", "report"}


def test_key_inspect_purpose_manifest_filters_correctly(tmp_path: Path) -> None:
    result = run_cli("key", "inspect", "--purpose", "manifest", "--json", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert [item["purpose"] for item in data["keys"]] == ["manifest"]
    assert data["keys"][0]["private_key_path"] == "keys/manifest_signing_key.pem"


def test_key_unknown_purpose_returns_input_error(tmp_path: Path) -> None:
    result = run_cli("key", "inspect", "--purpose", "unknown", cwd=tmp_path)
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_key_check_json_is_parseable(tmp_path: Path) -> None:
    result = run_cli("key", "check", "--json", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] in {"ok", "warn"}
    assert isinstance(data["openssl_available"], bool)
    assert isinstance(data["keys"], list)


def test_private_key_files_are_excluded_by_gitignore() -> None:
    text = Path(".gitignore").read_text(encoding="utf-8")
    assert "keys/" in text
    assert "*.pem" in text
    assert "*.key" in text
