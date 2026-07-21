from __future__ import annotations

import json
import ast
import subprocess
from pathlib import Path

import pytest

import tohupono.trust.keys as key_module
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


def test_run_openssl_passes_finite_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["args"] = args
        observed["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(key_module.subprocess, "run", fake_run)
    key_module._run_openssl(["version"])
    assert observed["timeout"] == key_module.OPENSSL_OPERATION_TIMEOUT_SECONDS


def test_openssl_available_timeout_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("timeout") == key_module.OPENSSL_PROBE_TIMEOUT_SECONDS
        raise subprocess.TimeoutExpired(cmd=["openssl", "version"], timeout=key_module.OPENSSL_PROBE_TIMEOUT_SECONDS)

    monkeypatch.setattr(key_module.subprocess, "run", fake_run)
    assert key_module.openssl_available() is False
    result = key_module.check_keys("manifest")
    json.dumps(result)
    assert result["openssl_available"] is False


def test_run_openssl_timeout_raises_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=["openssl"], timeout=key_module.OPENSSL_OPERATION_TIMEOUT_SECONDS)

    monkeypatch.setattr(key_module.subprocess, "run", fake_run)
    with pytest.raises(key_module.KeyErrorWithAction, match="OpenSSL command timed out"):
        key_module._run_openssl(["version"])


def test_verify_signature_valid_invalid_and_timeout_behaviour(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = key_module.create_key("manifest", output_dir=tmp_path)
    private_key = Path(str(created["private_key_path"]))
    public_key = Path(str(created["public_key_path"]))
    data = b"signature timeout regression"
    signature = key_module.sign_bytes(private_key, data)
    assert key_module.verify_signature(public_key, signature, data) is True
    assert key_module.verify_signature(public_key, signature, b"changed") is False

    observed: dict[str, object] = {}

    def fake_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["timeout"] = kwargs.get("timeout")
        raise subprocess.TimeoutExpired(cmd=["openssl"], timeout=key_module.OPENSSL_OPERATION_TIMEOUT_SECONDS)

    monkeypatch.setattr(key_module.subprocess, "run", fake_run)
    assert key_module.verify_signature(public_key, signature, data) is False
    assert observed["timeout"] == key_module.OPENSSL_OPERATION_TIMEOUT_SECONDS


def test_all_openssl_subprocess_calls_have_finite_timeout() -> None:
    source = Path("tohupono/trust/keys.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    missing: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ):
            continue
        if not node.args:
            continue
        first_arg = node.args[0]
        first_value = None
        if isinstance(first_arg, ast.List) and first_arg.elts and isinstance(first_arg.elts[0], ast.Constant):
            first_value = first_arg.elts[0].value
        if first_value == "openssl" and not any(keyword.arg == "timeout" for keyword in node.keywords):
            missing.append(node.lineno)
    assert missing == []


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
    assert old_private.read_bytes() != old_private_bytes
    assert old_public.read_bytes() != old_public_bytes
    assert Path(data["backup_private_key_path"]).read_bytes() == old_private_bytes
    assert Path(data["backup_public_key_path"]).read_bytes() == old_public_bytes
    assert data["event_type"] == "KEY_ROTATED"
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
    assert data["keys"][0]["compromise_events"] == 1


def test_key_create_force_records_replaced_and_retains_backup(tmp_path: Path) -> None:
    key_dir = tmp_path / "keys"
    created = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert created.returncode == 0, created.stderr
    old_private = Path(json.loads(created.stdout)["private_key_path"])
    old_private_bytes = old_private.read_bytes()

    replaced = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--force", "--json")
    assert replaced.returncode == 0, replaced.stderr
    data = json.loads(replaced.stdout)
    assert data["event_type"] == "KEY_REPLACED"
    assert old_private.read_bytes() != old_private_bytes
    assert Path(data["backup_private_key_path"]).read_bytes() == old_private_bytes


def test_key_create_force_lifecycle_failure_rolls_back_active_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_dir = tmp_path / "keys"
    created = key_module.create_key("manifest", output_dir=key_dir)
    private_key = Path(str(created["private_key_path"]))
    public_key = Path(str(created["public_key_path"]))
    old_private_bytes = private_key.read_bytes()
    old_public_bytes = public_key.read_bytes()

    def fail_append(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated lifecycle write failure")

    monkeypatch.setattr(key_module, "_append_lifecycle_event", fail_append)
    with pytest.raises(key_module.KeyErrorWithAction):
        key_module.create_key("manifest", output_dir=key_dir, force=True)

    assert private_key.read_bytes() == old_private_bytes
    assert public_key.read_bytes() == old_public_bytes
    assert list(key_dir.glob("*.incomplete.*"))


def test_key_rotate_lifecycle_failure_rolls_back_active_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_dir = tmp_path / "keys"
    created = key_module.create_key("manifest", output_dir=key_dir)
    private_key = Path(str(created["private_key_path"]))
    public_key = Path(str(created["public_key_path"]))
    old_private_bytes = private_key.read_bytes()
    old_public_bytes = public_key.read_bytes()

    def fail_append(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated lifecycle write failure")

    monkeypatch.setattr(key_module, "_append_lifecycle_event", fail_append)
    with pytest.raises(key_module.KeyErrorWithAction):
        key_module.rotate_key("manifest", "simulated failed rotation", output_dir=key_dir)

    assert private_key.read_bytes() == old_private_bytes
    assert public_key.read_bytes() == old_public_bytes
    assert list(key_dir.glob("*.incomplete.*"))


def test_key_replacement_private_generation_failure_preserves_active_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_dir = tmp_path / "keys"
    created = key_module.create_key("manifest", output_dir=key_dir)
    private_key = Path(str(created["private_key_path"]))
    public_key = Path(str(created["public_key_path"]))
    old_private_bytes = private_key.read_bytes()
    old_public_bytes = public_key.read_bytes()

    def fail_openssl(*_args: object, **_kwargs: object) -> None:
        raise key_module.KeyErrorWithAction("simulated private generation failure")

    monkeypatch.setattr(key_module, "_run_openssl", fail_openssl)
    with pytest.raises(key_module.KeyErrorWithAction):
        key_module.create_key("manifest", output_dir=key_dir, force=True)

    assert private_key.read_bytes() == old_private_bytes
    assert public_key.read_bytes() == old_public_bytes


def test_key_replacement_public_export_failure_preserves_active_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_dir = tmp_path / "keys"
    created = key_module.create_key("manifest", output_dir=key_dir)
    private_key = Path(str(created["private_key_path"]))
    public_key = Path(str(created["public_key_path"]))
    old_private_bytes = private_key.read_bytes()
    old_public_bytes = public_key.read_bytes()

    def fail_export(*_args: object, **_kwargs: object) -> None:
        raise key_module.KeyErrorWithAction("simulated public export failure")

    monkeypatch.setattr(key_module, "export_public_key", fail_export)
    with pytest.raises(key_module.KeyErrorWithAction):
        key_module.create_key("manifest", output_dir=key_dir, force=True)

    assert private_key.read_bytes() == old_private_bytes
    assert public_key.read_bytes() == old_public_bytes


def test_key_replacement_validation_failure_preserves_active_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_dir = tmp_path / "keys"
    created = key_module.create_key("manifest", output_dir=key_dir)
    private_key = Path(str(created["private_key_path"]))
    public_key = Path(str(created["public_key_path"]))
    old_private_bytes = private_key.read_bytes()
    old_public_bytes = public_key.read_bytes()

    def fail_validation(*_args: object, **_kwargs: object) -> None:
        raise key_module.KeyErrorWithAction("simulated validation failure")

    monkeypatch.setattr(key_module, "_validate_public_key", fail_validation)
    with pytest.raises(key_module.KeyErrorWithAction):
        key_module.create_key("manifest", output_dir=key_dir, force=True)

    assert private_key.read_bytes() == old_private_bytes
    assert public_key.read_bytes() == old_public_bytes


def test_key_inspect_output_dir_reads_key_directory(tmp_path: Path) -> None:
    key_dir = tmp_path / "local_keys"
    created = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert created.returncode == 0, created.stderr

    result = run_cli(
        "key",
        "inspect",
        "--purpose",
        "manifest",
        "--output-dir",
        str(key_dir),
        "--json",
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    item = data["keys"][0]
    assert data["key_directory"] == str(key_dir)
    assert item["purpose"] == "manifest"
    assert item["private_key_path"] == str(key_dir / "manifest_signing_key.pem")
    assert item["public_key_path"] == str(key_dir / "manifest_signing_key.pub")
    assert item["private_key_exists"] is True
    assert item["public_key_exists"] is True


def test_key_check_output_dir_reads_lifecycle_metadata(tmp_path: Path) -> None:
    key_dir = tmp_path / "local_keys"
    created = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert created.returncode == 0, created.stderr
    rotated = run_cli(
        "key",
        "rotate",
        "--purpose",
        "manifest",
        "--reason",
        "key directory rotation",
        "--output-dir",
        str(key_dir),
        "--json",
    )
    assert rotated.returncode == 0, rotated.stderr
    compromised = run_cli(
        "key",
        "compromise",
        "--purpose",
        "manifest",
        "--reason",
        "key directory compromise",
        "--output-dir",
        str(key_dir),
        "--json",
    )
    assert compromised.returncode == 0, compromised.stderr

    result = run_cli("key", "check", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    item = data["keys"][0]
    assert item["rotation_events"] == 1
    assert item["compromise_events"] == 1
    assert item["latest_rotation_event_id"] == json.loads(rotated.stdout)["rotation_event_id"]
    assert item["latest_compromise_event_id"] == json.loads(compromised.stdout)["compromise_event_id"]
    assert COMPROMISE_WARNING in item["warnings"]


def test_key_inspect_json_includes_lifecycle_counts(tmp_path: Path) -> None:
    key_dir = tmp_path / "local_keys"
    assert run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json").returncode == 0
    assert (
        run_cli(
            "key",
            "rotate",
            "--purpose",
            "manifest",
            "--reason",
            "count rotation",
            "--output-dir",
            str(key_dir),
            "--json",
        ).returncode
        == 0
    )
    assert (
        run_cli(
            "key",
            "compromise",
            "--purpose",
            "manifest",
            "--reason",
            "count compromise",
            "--output-dir",
            str(key_dir),
            "--json",
        ).returncode
        == 0
    )
    result = run_cli("key", "inspect", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert result.returncode == 0, result.stderr
    item = json.loads(result.stdout)["keys"][0]
    assert item["rotation_events"] == 1
    assert item["compromise_events"] == 1
    assert item["latest_rotation_event_id"]
    assert item["latest_compromise_event_id"]


def test_key_inspect_output_dir_human_mode_does_not_print_private_key_contents(tmp_path: Path) -> None:
    key_dir = tmp_path / "local_keys"
    created = run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert created.returncode == 0, created.stderr
    compromised = run_cli(
        "key",
        "compromise",
        "--purpose",
        "manifest",
        "--reason",
        "human warning",
        "--output-dir",
        str(key_dir),
        "--json",
    )
    assert compromised.returncode == 0, compromised.stderr
    result = run_cli("key", "inspect", "--purpose", "manifest", "--output-dir", str(key_dir))
    assert result.returncode == 0, result.stderr
    assert "Rotation events: 0" in result.stdout
    assert "Compromise events: 1" in result.stdout
    assert f"WARN: {COMPROMISE_WARNING}" in result.stdout
    assert "BEGIN PRIVATE KEY" not in result.stdout


def test_key_inspect_output_dir_missing_key_directory_is_sane(tmp_path: Path) -> None:
    key_dir = tmp_path / "missing_keys"
    result = run_cli("key", "inspect", "--purpose", "manifest", "--output-dir", str(key_dir), "--json")
    assert result.returncode == 0, result.stderr
    item = json.loads(result.stdout)["keys"][0]
    assert item["private_key_exists"] is False
    assert item["public_key_exists"] is False
    assert item["rotation_events"] == 0
    assert item["compromise_events"] == 0


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
