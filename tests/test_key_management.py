from __future__ import annotations

import json
from pathlib import Path

from tohupono.trust.keys import COMPROMISE_WARNING, KEY_PURPOSES

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


def test_key_create_manifest_creates_private_and_public_key_in_temp_dir(tmp_path: Path) -> None:
    key_dir = tmp_path / "keys"
    result = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    private_key = Path(data["private_key_path"])
    public_key = Path(data["public_key_path"])
    assert data["status"] == "ok"
    assert private_key.exists()
    assert public_key.exists()
    assert "BEGIN PRIVATE KEY" not in result.stdout


def test_key_create_refuses_overwrite_without_force(tmp_path: Path) -> None:
    key_dir = tmp_path / "keys"
    first = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert first.returncode == 0, first.stderr
    second = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert second.returncode == 1
    data = json.loads(second.stdout)
    assert data["status"] == "error"
    assert data["error"]["code"] == "KEY_EXISTS"


def test_key_create_json_is_parseable(tmp_path: Path) -> None:
    result = run_cli("key", "create", "--purpose", "report", "--output-dir", str(tmp_path), "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["purpose"] == "report"
    assert data["created"] is True
    assert Path(data["private_key_path"]).name == "report_signing_key.pem"
    assert Path(data["public_key_path"]).name == "report_signing_key.pub"


def test_key_create_unknown_purpose_returns_input_error(tmp_path: Path) -> None:
    result = run_cli("key", "create", "--purpose", "unknown", "--output-dir", str(tmp_path), cwd=tmp_path)
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_key_rotate_records_metadata_and_keeps_old_keys(tmp_path: Path) -> None:
    key_dir = tmp_path / "keys"
    created = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert created.returncode == 0, created.stderr
    created_data = json.loads(created.stdout)
    old_private = Path(created_data["private_key_path"])
    old_public = Path(created_data["public_key_path"])
    old_private_bytes = old_private.read_bytes()
    old_public_bytes = old_public.read_bytes()

    rotated = run_cli(
        "key",
        "rotate",
        "--purpose",
        "manifest",
        "--reason",
        "test rotation",
        "--output-dir",
        str(key_dir),
        "--json",
    )
    assert rotated.returncode == 0, rotated.stderr
    data = json.loads(rotated.stdout)
    assert data["status"] == "ok"
    assert Path(data["new_private_key_path"]).exists()
    assert Path(data["new_public_key_path"]).exists()
    assert old_private.exists()
    assert old_public.exists()
    assert old_private.read_bytes() == old_private_bytes
    assert old_public.read_bytes() == old_public_bytes
    log_path = Path(data["rotation_log_path"])
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["event_type"] == "KEY_ROTATED"
    assert entry["purpose"] == "manifest"
    assert "rotation_event_id" in entry
    assert "PRIVATE KEY" not in log_path.read_text(encoding="utf-8")


def test_key_rotate_requires_reason(tmp_path: Path) -> None:
    result = run_cli("key", "rotate", "--purpose", "manifest", "--output-dir", str(tmp_path))
    assert result.returncode == 2
    assert "--reason" in result.stderr


def test_key_compromise_records_metadata_and_keeps_keys(tmp_path: Path) -> None:
    key_dir = tmp_path / "keys"
    created = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert created.returncode == 0, created.stderr
    created_data = json.loads(created.stdout)
    private_key = Path(created_data["private_key_path"])
    public_key = Path(created_data["public_key_path"])
    private_bytes = private_key.read_bytes()
    public_bytes = public_key.read_bytes()

    compromised = run_cli(
        "key",
        "compromise",
        "--purpose",
        "manifest",
        "--reason",
        "test compromise marker",
        "--output-dir",
        str(key_dir),
        "--json",
    )
    assert compromised.returncode == 0, compromised.stderr
    data = json.loads(compromised.stdout)
    log_path = Path(data["compromise_log_path"])
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["event_type"] == "KEY_COMPROMISED"
    assert entry["purpose"] == "manifest"
    assert private_key.read_bytes() == private_bytes
    assert public_key.read_bytes() == public_bytes
    assert "PRIVATE KEY" not in log_path.read_text(encoding="utf-8")


def test_key_compromise_requires_reason(tmp_path: Path) -> None:
    result = run_cli("key", "compromise", "--purpose", "manifest", "--output-dir", str(tmp_path))
    assert result.returncode == 2
    assert "--reason" in result.stderr


def test_key_check_warns_when_compromise_metadata_exists(tmp_path: Path) -> None:
    created = run_cli("key", "create", "--purpose", "manifest", "--json", cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    compromised = run_cli(
        "key",
        "compromise",
        "--purpose",
        "manifest",
        "--reason",
        "test compromise marker",
        "--json",
        cwd=tmp_path,
    )
    assert compromised.returncode == 0, compromised.stderr
    checked = run_cli("key", "check", "--purpose", "manifest", "--json", cwd=tmp_path)
    assert checked.returncode == 0, checked.stderr
    data = json.loads(checked.stdout)
    warnings = data["keys"][0]["warnings"]
    assert COMPROMISE_WARNING in warnings
    assert data["keys"][0]["compromise_event_count"] == 1


def test_key_inspect_and_check_do_not_print_private_key_contents(tmp_path: Path) -> None:
    created = run_cli("key", "create", "--purpose", "manifest", "--json", cwd=tmp_path)
    assert created.returncode == 0, created.stderr
    inspected = run_cli("key", "inspect", "--purpose", "manifest", cwd=tmp_path)
    checked = run_cli("key", "check", "--purpose", "manifest", cwd=tmp_path)
    assert inspected.returncode == 0, inspected.stderr
    assert checked.returncode == 0, checked.stderr
    assert "BEGIN PRIVATE KEY" not in inspected.stdout
    assert "BEGIN PRIVATE KEY" not in checked.stdout


def test_key_lifecycle_commands_appear_in_cli_help(tmp_path: Path) -> None:
    result = run_cli("key", "--help", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "create" in result.stdout
    assert "rotate" in result.stdout
    assert "compromise" in result.stdout


def test_private_key_files_are_excluded_by_gitignore() -> None:
    text = Path(".gitignore").read_text(encoding="utf-8")
    assert "keys/" in text
    assert "*.pem" in text
    assert "*.key" in text
