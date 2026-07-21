from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from tohupono import __version__
from tohupono.core.canonical_json import canonical_json_bytes, canonical_json_text
from tohupono.security.atomic import atomic_append_jsonl
from tohupono.security.limits import MAX_LIFECYCLE_JSONL_LINE_BYTES, MAX_OPENSSL_DIAGNOSTIC_BYTES, MAX_REASON_LENGTH
from tohupono.security.locking import FileLock
from tohupono.security.paths import PathSecurityError, ensure_sensitive_path_safe, validate_terminal_text


class KeyErrorWithAction(Exception):
    """Raised when key handling cannot proceed safely."""


class KeyConflictError(Exception):
    """Raised when key handling refuses to overwrite local key material."""


DEFAULT_MANIFEST_KEY = Path("keys/manifest_signing_key.pem")
DEFAULT_MANIFEST_PUBLIC_KEY = Path("keys/manifest_signing_key.pub")
DEFAULT_REPORT_KEY = Path("keys/report_signing_key.pem")
DEFAULT_REPORT_PUBLIC_KEY = Path("keys/report_signing_key.pub")
DEFAULT_AMENDMENT_KEY = Path("keys/amendment_signing_key.pem")
DEFAULT_AMENDMENT_PUBLIC_KEY = Path("keys/amendment_signing_key.pub")
DEFAULT_ROTATION_LOG = Path("keys/key_rotation_log.jsonl")
DEFAULT_COMPROMISE_LOG = Path("keys/key_compromise_log.jsonl")
DEFAULT_LIFECYCLE_LOG = Path("keys/key_lifecycle_log.jsonl")
LIFECYCLE_SCHEMA_VERSION = "tohupono.key_lifecycle.v1"
GENESIS_EVENT_HASH = "GENESIS"
OPENSSL_OPERATION_TIMEOUT_SECONDS = 15
OPENSSL_PROBE_TIMEOUT_SECONDS = 5
COMPROMISE_WARNING = (
    "compromise metadata exists for this key purpose. Existing signatures may "
    "require review under the applicable trust policy."
)


@dataclass(frozen=True)
class KeyPurpose:
    purpose: str
    description: str
    private_key_path: Path
    public_key_path: Path
    private_required_for_signing: bool
    public_required_for_verification: bool
    allowed_operations: tuple[str, ...]
    status: str = "active"

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["private_key_path"] = str(self.private_key_path)
        value["public_key_path"] = str(self.public_key_path)
        value["allowed_operations"] = list(self.allowed_operations)
        return value


KEY_PURPOSES: dict[str, KeyPurpose] = {
    "manifest": KeyPurpose(
        purpose="manifest",
        description="Signs and verifies proof packet manifests.",
        private_key_path=DEFAULT_MANIFEST_KEY,
        public_key_path=DEFAULT_MANIFEST_PUBLIC_KEY,
        private_required_for_signing=True,
        public_required_for_verification=True,
        allowed_operations=("sign_manifest", "verify_manifest"),
    ),
    "report": KeyPurpose(
        purpose="report",
        description="Signs and verifies final human-readable reports.",
        private_key_path=DEFAULT_REPORT_KEY,
        public_key_path=DEFAULT_REPORT_PUBLIC_KEY,
        private_required_for_signing=True,
        public_required_for_verification=True,
        allowed_operations=("sign_report", "verify_report"),
    ),
    "witness": KeyPurpose(
        purpose="witness",
        description="Reserved for future witness signatures.",
        private_key_path=Path("keys/witness_signing_key.pem"),
        public_key_path=Path("keys/witness_signing_key.pub"),
        private_required_for_signing=True,
        public_required_for_verification=True,
        allowed_operations=("sign_witness", "verify_witness"),
        status="reserved",
    ),
    "amendment": KeyPurpose(
        purpose="amendment",
        description="Signs and verifies amendment lineage records.",
        private_key_path=DEFAULT_AMENDMENT_KEY,
        public_key_path=DEFAULT_AMENDMENT_PUBLIC_KEY,
        private_required_for_signing=True,
        public_required_for_verification=True,
        allowed_operations=("sign_amendment", "verify_amendment"),
    ),
    "release": KeyPurpose(
        purpose="release",
        description="Reserved for future release artefact signatures.",
        private_key_path=Path("keys/release_signing_key.pem"),
        public_key_path=Path("keys/release_signing_key.pub"),
        private_required_for_signing=True,
        public_required_for_verification=True,
        allowed_operations=("sign_release", "verify_release"),
        status="reserved",
    ),
    "test": KeyPurpose(
        purpose="test",
        description="Reserved for runtime test fixtures and temporary keys.",
        private_key_path=Path("tests/fixtures/keys/test_signing_key.pem"),
        public_key_path=Path("tests/fixtures/keys/test_signing_key.pub"),
        private_required_for_signing=False,
        public_required_for_verification=False,
        allowed_operations=("test_sign", "test_verify"),
        status="test-only",
    ),
}


def _sanitise_openssl_output(value: str) -> str:
    value = value.replace("\x00", "")
    value = "".join(char if (ord(char) >= 32 or char in "\n\t") else "?" for char in value)
    return value[:MAX_OPENSSL_DIAGNOSTIC_BYTES]


def _run_openssl(args: list[str], *, timeout: int = OPENSSL_OPERATION_TIMEOUT_SECONDS) -> None:
    try:
        subprocess.run(["openssl", *args], check=True, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise KeyErrorWithAction("OpenSSL is required for MVP signing.") from exc
    except subprocess.TimeoutExpired as exc:
        raise KeyErrorWithAction("OpenSSL command timed out.") from exc
    except subprocess.CalledProcessError as exc:
        message = _sanitise_openssl_output(exc.stderr.strip() or exc.stdout.strip() or str(exc))
        raise KeyErrorWithAction(f"OpenSSL command failed: {message}") from exc


def openssl_available() -> bool:
    try:
        subprocess.run(
            ["openssl", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=OPENSSL_PROBE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return False
    return True


def key_purpose_names() -> list[str]:
    return sorted(KEY_PURPOSES)


def get_key_purpose(purpose: str) -> KeyPurpose:
    try:
        return KEY_PURPOSES[purpose]
    except KeyError as exc:
        raise KeyErrorWithAction(f"Unknown key purpose: {purpose}") from exc


def selected_key_purposes(purpose: str | None = None) -> list[KeyPurpose]:
    if purpose:
        return [get_key_purpose(purpose)]
    return [KEY_PURPOSES[name] for name in key_purpose_names()]


def _now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _paths_for_purpose(purpose: KeyPurpose, output_dir: Path | None = None) -> tuple[Path, Path]:
    if output_dir is None:
        return purpose.private_key_path, purpose.public_key_path
    return (
        output_dir / f"{purpose.purpose}_signing_key.pem",
        output_dir / f"{purpose.purpose}_signing_key.pub",
    )


def _rotation_log_path(output_dir: Path | None = None) -> Path:
    return (output_dir / "key_rotation_log.jsonl") if output_dir else DEFAULT_ROTATION_LOG


def _compromise_log_path(output_dir: Path | None = None) -> Path:
    return (output_dir / "key_compromise_log.jsonl") if output_dir else DEFAULT_COMPROMISE_LOG


def _lifecycle_log_path(output_dir: Path | None = None) -> Path:
    return (output_dir / "key_lifecycle_log.jsonl") if output_dir else DEFAULT_LIFECYCLE_LOG


def _lock_path(purpose: KeyPurpose, output_dir: Path | None = None) -> Path:
    private_key, _ = _paths_for_purpose(purpose, output_dir)
    return private_key.parent / f".{purpose.purpose}.key.lock"


def _event_id(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _append_jsonl(path: Path, value: dict[str, object]) -> None:
    atomic_append_jsonl(path, value, max_line_bytes=MAX_LIFECYCLE_JSONL_LINE_BYTES)


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    entries: list[dict[str, object]] = []
    ensure_sensitive_path_safe(path, private=False)
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > MAX_LIFECYCLE_JSONL_LINE_BYTES:
            entries.append({"event_type": "INVALID", "parse_error": "line_too_large"})
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            entries.append(value)
    return entries


def _entries_for_purpose(path: Path, purpose: str, event_type: str) -> list[dict[str, object]]:
    return [
        entry
        for entry in _read_jsonl(path)
        if entry.get("purpose") == purpose and entry.get("event_type") == event_type
    ]


def _path_warnings(path: Path, *, private: bool, output_dir: Path | None = None) -> list[str]:
    warnings: list[str] = []
    normalized = path.as_posix()
    if (
        private
        and output_dir is None
        and not normalized.startswith("keys/")
        and not normalized.startswith("tests/")
    ):
        warnings.append("private key path is outside the expected local key directories")
    if any(part in path.parts for part in [".git", ".ssh"]):
        warnings.append("key path is inside a forbidden location")
    try:
        warnings.extend(ensure_sensitive_path_safe(path, private=private))
    except PathSecurityError as exc:
        warnings.append(str(exc))
    return warnings


def public_key_fingerprint(public_key: Path) -> str:
    return f"sha256:{hashlib.sha256(public_key.read_bytes()).hexdigest()}"


def _event_hash(event: dict[str, object]) -> str:
    body = {key: value for key, value in event.items() if key not in {"event_hash", "event_id"}}
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def _lifecycle_entries(output_dir: Path | None = None) -> list[dict[str, object]]:
    return _read_jsonl(_lifecycle_log_path(output_dir))


def verify_lifecycle_chain(output_dir: Path | None = None) -> dict[str, object]:
    path = _lifecycle_log_path(output_dir)
    entries = _lifecycle_entries(output_dir)
    errors: list[str] = []
    warnings: list[str] = []
    previous = GENESIS_EVENT_HASH
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    required = {
        "event_hash",
        "event_id",
        "event_type",
        "previous_event_hash",
        "previous_public_key_fingerprint",
        "public_key_fingerprint",
        "purpose",
        "reason",
        "schema_version",
        "timestamp",
        "tool_version",
    }
    for index, entry in enumerate(entries, start=1):
        if entry.get("parse_error"):
            errors.append(f"event_{index}_{entry['parse_error']}")
            continue
        missing = sorted(required - set(entry))
        if missing:
            errors.append(f"event_{index}_missing_{','.join(missing)}")
            continue
        if entry.get("schema_version") != LIFECYCLE_SCHEMA_VERSION:
            errors.append(f"event_{index}_unsupported_schema")
        if entry.get("event_type") not in {"KEY_CREATED", "KEY_REPLACED", "KEY_ROTATED", "KEY_COMPROMISED"}:
            errors.append(f"event_{index}_invalid_event_type")
        if entry.get("purpose") not in KEY_PURPOSES:
            errors.append(f"event_{index}_invalid_purpose")
        if entry.get("previous_event_hash") != previous:
            errors.append(f"event_{index}_previous_hash_mismatch")
        expected_hash = _event_hash(entry)
        if entry.get("event_hash") != expected_hash:
            errors.append(f"event_{index}_hash_mismatch")
        expected_id = f"kle_{expected_hash[:32]}"
        if entry.get("event_id") != expected_id:
            errors.append(f"event_{index}_event_id_mismatch")
        event_id = str(entry.get("event_id"))
        event_hash_value = str(entry.get("event_hash"))
        if event_id in seen_ids:
            errors.append(f"event_{index}_duplicate_event_id")
        if event_hash_value in seen_hashes:
            errors.append(f"event_{index}_duplicate_event_hash")
        seen_ids.add(event_id)
        seen_hashes.add(event_hash_value)
        for key in ("public_key_fingerprint", "previous_public_key_fingerprint"):
            value = entry.get(key)
            if value is not None and (not isinstance(value, str) or not value.startswith("sha256:")):
                errors.append(f"event_{index}_invalid_{key}")
        previous = event_hash_value
    if not path.exists():
        warnings.append("canonical lifecycle log missing")
    return {
        "event_count": len(entries),
        "failures": errors,
        "latest_event_hash": previous if entries and not errors else None,
        "latest_event_id": entries[-1].get("event_id") if entries and isinstance(entries[-1], dict) else None,
        "path": str(path),
        "status": "invalid" if errors else ("valid" if entries else "missing"),
        "warnings": warnings,
    }


def _make_lifecycle_event(
    *,
    event_type: str,
    purpose: str,
    reason: str,
    public_key_fingerprint_value: str | None,
    previous_public_key_fingerprint_value: str | None,
    output_dir: Path | None = None,
) -> dict[str, object]:
    if len(reason) > MAX_REASON_LENGTH:
        raise ValueError("Key lifecycle reason exceeds the configured length limit.")
    validate_terminal_text(reason, field="reason")
    previous = str(verify_lifecycle_chain(output_dir).get("latest_event_hash") or GENESIS_EVENT_HASH)
    event: dict[str, object] = {
        "event_type": event_type,
        "previous_event_hash": previous,
        "previous_public_key_fingerprint": previous_public_key_fingerprint_value,
        "public_key_fingerprint": public_key_fingerprint_value,
        "purpose": purpose,
        "reason": reason,
        "schema_version": LIFECYCLE_SCHEMA_VERSION,
        "timestamp": _now_utc(),
        "tool_version": __version__,
    }
    event["event_hash"] = _event_hash(event)
    event["event_id"] = f"kle_{str(event['event_hash'])[:32]}"
    return event


def _append_lifecycle_event(event: dict[str, object], output_dir: Path | None = None) -> None:
    _append_jsonl(_lifecycle_log_path(output_dir), event)


def key_lifecycle_summary(purpose_name: str, output_dir: Path | None = None) -> dict[str, object]:
    purpose = get_key_purpose(purpose_name)
    canonical_entries = [
        entry
        for entry in _lifecycle_entries(output_dir)
        if entry.get("purpose") == purpose.purpose and not entry.get("parse_error")
    ]
    rotation_entries = [entry for entry in canonical_entries if entry.get("event_type") == "KEY_ROTATED"]
    compromise_entries = [entry for entry in canonical_entries if entry.get("event_type") == "KEY_COMPROMISED"]
    legacy_rotation_entries = _entries_for_purpose(_rotation_log_path(output_dir), purpose.purpose, "KEY_ROTATED")
    legacy_compromise_entries = _entries_for_purpose(_compromise_log_path(output_dir), purpose.purpose, "KEY_COMPROMISED")
    warnings: list[str] = []
    if compromise_entries or legacy_compromise_entries:
        warnings.append(COMPROMISE_WARNING)
    if legacy_rotation_entries or legacy_compromise_entries:
        warnings.append("legacy unlinked key lifecycle metadata is present")
    lifecycle_verification = verify_lifecycle_chain(output_dir)
    return {
        "compromise_events": len(compromise_entries) if compromise_entries else len(legacy_compromise_entries),
        "event_count": len(canonical_entries),
        "latest_compromise_event_id": (
            compromise_entries[-1].get("event_id")
            if compromise_entries
            else (legacy_compromise_entries[-1].get("compromise_event_id") if legacy_compromise_entries else None)
        ),
        "latest_event_hash": lifecycle_verification.get("latest_event_hash"),
        "latest_event_id": lifecycle_verification.get("latest_event_id"),
        "latest_rotation_event_id": (
            rotation_entries[-1].get("event_id")
            if rotation_entries
            else (legacy_rotation_entries[-1].get("rotation_event_id") if legacy_rotation_entries else None)
        ),
        "legacy_record_count": len(legacy_rotation_entries) + len(legacy_compromise_entries),
        "lifecycle_failures": lifecycle_verification.get("failures", []),
        "lifecycle_status": lifecycle_verification.get("status"),
        "rotation_events": len(rotation_entries) if rotation_entries else len(legacy_rotation_entries),
        "warnings": warnings,
    }


def inspect_key_purpose(purpose: KeyPurpose, output_dir: Path | None = None) -> dict[str, object]:
    private_key, public_key = _paths_for_purpose(purpose, output_dir)
    private_exists = private_key.exists()
    public_exists = public_key.exists()
    lifecycle = key_lifecycle_summary(purpose.purpose, output_dir)
    warnings = [str(warning) for warning in lifecycle["warnings"]]
    if not private_exists:
        warnings.append("private key missing")
    if not public_exists:
        warnings.append("public key missing")
    warnings.extend(_path_warnings(private_key, private=True, output_dir=output_dir))
    warnings.extend(_path_warnings(public_key, private=False, output_dir=output_dir))
    return {
        "allowed_operations": list(purpose.allowed_operations),
        "compromise_event_count": lifecycle["compromise_events"],
        "compromise_events": lifecycle["compromise_events"],
        "description": purpose.description,
        "private_key_exists": private_exists,
        "private_key_path": str(private_key),
        "private_required_for_signing": purpose.private_required_for_signing,
        "public_key_exists": public_exists,
        "public_key_path": str(public_key),
        "public_required_for_verification": purpose.public_required_for_verification,
        "purpose": purpose.purpose,
        "rotation_event_count": lifecycle["rotation_events"],
        "rotation_events": lifecycle["rotation_events"],
        "latest_rotation_event_id": lifecycle["latest_rotation_event_id"],
        "latest_compromise_event_id": lifecycle["latest_compromise_event_id"],
        "latest_lifecycle_event_hash": lifecycle["latest_event_hash"],
        "latest_lifecycle_event_id": lifecycle["latest_event_id"],
        "legacy_record_count": lifecycle["legacy_record_count"],
        "lifecycle_failures": lifecycle["lifecycle_failures"],
        "lifecycle_status": lifecycle["lifecycle_status"],
        "status": purpose.status,
        "warnings": warnings,
    }


def inspect_keys(purpose: str | None = None, output_dir: Path | None = None) -> dict[str, object]:
    keys = [inspect_key_purpose(item, output_dir) for item in selected_key_purposes(purpose)]
    return {"key_directory": str(output_dir or Path("keys")), "keys": keys, "status": "ok"}


def check_key_purpose(purpose: KeyPurpose, output_dir: Path | None = None) -> dict[str, object]:
    item = inspect_key_purpose(purpose, output_dir)
    warnings = [str(warning) for warning in item["warnings"]]
    failures: list[str] = []
    if purpose.private_required_for_signing and not item["private_key_exists"]:
        warnings.append("private key required for signing is missing")
    if purpose.public_required_for_verification and not item["public_key_exists"]:
        warnings.append("public key required for verification is missing")
    private_key, _ = _paths_for_purpose(purpose, output_dir)
    if private_key.exists():
        try:
            mode = private_key.stat().st_mode & 0o777
        except OSError as exc:
            warnings.append(f"could not inspect private key permissions: {exc}")
        else:
            if mode & 0o077:
                warnings.append("private key permissions are broader than recommended")
    if any("forbidden location" in warning for warning in warnings):
        failures.append("key_path_forbidden")
    failures.extend(str(failure) for failure in item.get("lifecycle_failures", []))
    status = "fail" if failures else ("warn" if warnings else "ok")
    return {
        **item,
        "failures": failures,
        "status": status,
        "warnings": warnings,
    }


def check_keys(purpose: str | None = None, output_dir: Path | None = None) -> dict[str, object]:
    keys = [check_key_purpose(item, output_dir) for item in selected_key_purposes(purpose)]
    openssl_ok = openssl_available()
    warnings = [] if openssl_ok else ["OpenSSL is unavailable"]
    status = "fail" if any(item["status"] == "fail" for item in keys) else ("warn" if warnings or any(item["status"] == "warn" for item in keys) else "ok")
    return {
        "key_directory": str(output_dir or Path("keys")),
        "keys": keys,
        "openssl_available": openssl_ok,
        "status": status,
        "warnings": warnings,
    }


def _validate_destination(private_key: Path, public_key: Path) -> list[str]:
    warnings: list[str] = []
    warnings.extend(ensure_sensitive_path_safe(private_key, private=True))
    warnings.extend(ensure_sensitive_path_safe(public_key, private=False))
    private_key.parent.mkdir(parents=True, exist_ok=True)
    if private_key.parent != public_key.parent:
        public_key.parent.mkdir(parents=True, exist_ok=True)
    return warnings


def _temp_key_paths(private_key: Path) -> tuple[Path, Path]:
    suffix = secrets.token_hex(12)
    return (
        private_key.with_name(f".{private_key.name}.tmp.{suffix}"),
        private_key.with_name(f".{private_key.stem}.pub.tmp.{suffix}"),
    )


def _backup_path(path: Path, *, purpose: str, event_type: str) -> Path:
    suffix = secrets.token_hex(12)
    return path.with_name(f"{path.stem}.{purpose}.{event_type.lower()}.{suffix}{path.suffix}")


def _validate_private_key(path: Path) -> None:
    _run_openssl(["pkey", "-in", str(path), "-noout"])


def _validate_public_key(path: Path) -> None:
    _run_openssl(["pkey", "-pubin", "-in", str(path), "-noout"])


def _generate_validated_pair(private_key: Path) -> tuple[Path, Path]:
    temp_private, temp_public = _temp_key_paths(private_key)
    try:
        _run_openssl(["genpkey", "-algorithm", "ED25519", "-out", str(temp_private)])
        os.chmod(temp_private, 0o600)
        _validate_private_key(temp_private)
        export_public_key(temp_private, temp_public)
        _validate_public_key(temp_public)
        return temp_private, temp_public
    except Exception:
        for path in (temp_private, temp_public):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def _fsync_path(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    _fsync_path(path)


def _promote_pair(
    *,
    purpose: KeyPurpose,
    private_key: Path,
    public_key: Path,
    temp_private: Path,
    temp_public: Path,
    event_type: str,
) -> dict[str, str | None]:
    backup_private: Path | None = None
    backup_public: Path | None = None
    moved_private = False
    moved_public = False
    try:
        if private_key.exists():
            backup_private = _backup_path(private_key, purpose=purpose.purpose, event_type=event_type)
            os.replace(private_key, backup_private)
            moved_private = True
        if public_key.exists():
            backup_public = _backup_path(public_key, purpose=purpose.purpose, event_type=event_type)
            os.replace(public_key, backup_public)
            moved_public = True
        os.replace(temp_private, private_key)
        os.chmod(private_key, 0o600)
        os.replace(temp_public, public_key)
        _fsync_path(private_key)
        _fsync_path(public_key)
        _fsync_dir(private_key.parent)
        return {
            "backup_private_key_path": str(backup_private) if backup_private else None,
            "backup_public_key_path": str(backup_public) if backup_public else None,
        }
    except Exception:
        for target, backup, moved in (
            (private_key, backup_private, moved_private),
            (public_key, backup_public, moved_public),
        ):
            if moved and backup and backup.exists() and not target.exists():
                try:
                    os.replace(backup, target)
                except OSError:
                    pass
        for path in (temp_private, temp_public):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def _recovery_path(path: Path, *, purpose: str, event_type: str) -> Path:
    suffix = secrets.token_hex(12)
    return path.with_name(f"{path.stem}.{purpose}.{event_type.lower()}.incomplete.{suffix}{path.suffix}")


def _rollback_after_lifecycle_failure(
    *,
    purpose: KeyPurpose,
    private_key: Path,
    public_key: Path,
    backups: dict[str, str | None],
    event_type: str,
) -> dict[str, str | None]:
    recovery_private: Path | None = None
    recovery_public: Path | None = None
    backup_private = Path(backups["backup_private_key_path"]) if backups.get("backup_private_key_path") else None
    backup_public = Path(backups["backup_public_key_path"]) if backups.get("backup_public_key_path") else None

    for active, backup, label in (
        (private_key, backup_private, "private"),
        (public_key, backup_public, "public"),
    ):
        recovery = _recovery_path(active, purpose=purpose.purpose, event_type=event_type)
        try:
            if active.exists():
                os.replace(active, recovery)
                if label == "private":
                    recovery_private = recovery
                else:
                    recovery_public = recovery
            if backup and backup.exists():
                os.replace(backup, active)
        except OSError:
            # Preserve whatever material remains and let the caller report failure.
            pass
    _fsync_dir(private_key.parent)
    return {
        "recovery_private_key_path": str(recovery_private) if recovery_private else None,
        "recovery_public_key_path": str(recovery_public) if recovery_public else None,
    }


def _record_key_event(
    *,
    purpose: KeyPurpose,
    event_type: str,
    reason: str,
    public_key: Path,
    previous_public_key_fingerprint_value: str | None,
    output_dir: Path | None,
) -> dict[str, object]:
    event = _make_lifecycle_event(
        event_type=event_type,
        purpose=purpose.purpose,
        reason=reason,
        public_key_fingerprint_value=public_key_fingerprint(public_key),
        previous_public_key_fingerprint_value=previous_public_key_fingerprint_value,
        output_dir=output_dir,
    )
    _append_lifecycle_event(event, output_dir)
    return event


def generate_private_key(path: Path, force: bool = False) -> Path:
    if path.exists() and not force:
        return path
    if path.exists() and force:
        temp_private, temp_public = _generate_validated_pair(path)
        os.replace(temp_private, path)
        try:
            temp_public.unlink()
        except FileNotFoundError:
            pass
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        _run_openssl(["genpkey", "-algorithm", "ED25519", "-out", str(path)])
    os.chmod(path, 0o600)
    _validate_private_key(path)
    return path


def create_key(
    purpose_name: str,
    *,
    output_dir: Path | None = None,
    force: bool = False,
) -> dict[str, object]:
    purpose = get_key_purpose(purpose_name)
    if purpose.status == "test-only":
        raise ValueError("Key creation is not supported for the test purpose.")
    private_key, public_key = _paths_for_purpose(purpose, output_dir)
    if not force and (private_key.exists() or public_key.exists()):
        raise KeyConflictError("Refusing to overwrite existing key files without --force.")
    warnings = _validate_destination(private_key, public_key)
    event_type = "KEY_REPLACED" if force and (private_key.exists() or public_key.exists()) else "KEY_CREATED"
    previous_fingerprint = public_key_fingerprint(public_key) if public_key.exists() else None
    with FileLock(_lock_path(purpose, output_dir), operation=f"key_{purpose.purpose}_{event_type.lower()}"):
        temp_private, temp_public = _generate_validated_pair(private_key)
        backups = _promote_pair(
            purpose=purpose,
            private_key=private_key,
            public_key=public_key,
            temp_private=temp_private,
            temp_public=temp_public,
            event_type=event_type,
        )
        try:
            event = _record_key_event(
                purpose=purpose,
                event_type=event_type,
                reason="forced replacement" if event_type == "KEY_REPLACED" else "initial key creation",
                public_key=public_key,
                previous_public_key_fingerprint_value=previous_fingerprint,
                output_dir=output_dir,
            )
        except Exception as exc:
            _rollback_after_lifecycle_failure(
                purpose=purpose,
                private_key=private_key,
                public_key=public_key,
                backups=backups,
                event_type=event_type,
            )
            raise KeyErrorWithAction(
                "Key operation failed while recording lifecycle metadata; active keypair was rolled back "
                "and recovery material was retained for operator review."
            ) from exc
    return {
        **backups,
        "created": True,
        "event_id": event["event_id"],
        "event_type": event_type,
        "public_key_fingerprint": public_key_fingerprint(public_key),
        "private_key_path": str(private_key),
        "public_key_path": str(public_key),
        "purpose": purpose.purpose,
        "status": "ok",
        "warnings": warnings,
    }


def rotate_key(
    purpose_name: str,
    reason: str,
    *,
    output_dir: Path | None = None,
) -> dict[str, object]:
    if not reason.strip():
        raise ValueError("Rotation reason is required.")
    purpose = get_key_purpose(purpose_name)
    if purpose.status == "test-only":
        raise ValueError("Key rotation is not supported for the test purpose.")
    old_private, old_public = _paths_for_purpose(purpose, output_dir)
    warnings = _validate_destination(old_private, old_public)
    if old_private.exists():
        _validate_private_key(old_private)
    if old_public.exists():
        _validate_public_key(old_public)
    previous_fingerprint = public_key_fingerprint(old_public) if old_public.exists() else None
    with FileLock(_lock_path(purpose, output_dir), operation=f"key_{purpose.purpose}_rotate"):
        temp_private, temp_public = _generate_validated_pair(old_private)
        backups = _promote_pair(
            purpose=purpose,
            private_key=old_private,
            public_key=old_public,
            temp_private=temp_private,
            temp_public=temp_public,
            event_type="KEY_ROTATED",
        )
        try:
            event = _record_key_event(
                purpose=purpose,
                event_type="KEY_ROTATED",
                reason=reason,
                public_key=old_public,
                previous_public_key_fingerprint_value=previous_fingerprint,
                output_dir=output_dir,
            )
        except Exception as exc:
            _rollback_after_lifecycle_failure(
                purpose=purpose,
                private_key=old_private,
                public_key=old_public,
                backups=backups,
                event_type="KEY_ROTATED",
            )
            raise KeyErrorWithAction(
                "Key rotation failed while recording lifecycle metadata; active keypair was rolled back "
                "and recovery material was retained for operator review."
            ) from exc
    legacy_entry = {
        "event_type": "KEY_ROTATED",
        "new_public_key_path": str(old_public),
        "old_public_key_path": backups.get("backup_public_key_path") or str(old_public),
        "purpose": purpose.purpose,
        "reason": reason,
        "rotation_event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "tool_version": __version__,
    }
    log_path = _rotation_log_path(output_dir)
    _append_jsonl(log_path, legacy_entry)
    return {
        **backups,
        "created": True,
        "event_id": event["event_id"],
        "event_type": "KEY_ROTATED",
        "new_private_key_path": str(old_private),
        "new_public_key_path": str(old_public),
        "old_public_key_path": backups.get("backup_public_key_path") or str(old_public),
        "previous_public_key_fingerprint": previous_fingerprint,
        "public_key_fingerprint": public_key_fingerprint(old_public),
        "purpose": purpose.purpose,
        "rotation_event_id": event["event_id"],
        "rotation_log_path": str(log_path),
        "status": "ok",
        "warnings": warnings,
    }


def mark_key_compromised(
    purpose_name: str,
    reason: str,
    *,
    output_dir: Path | None = None,
) -> dict[str, object]:
    if not reason.strip():
        raise ValueError("Compromise reason is required.")
    purpose = get_key_purpose(purpose_name)
    if purpose.status == "test-only":
        raise ValueError("Key compromise marking is not supported for the test purpose.")
    _, public_key = _paths_for_purpose(purpose, output_dir)
    _validate_destination(public_key.with_suffix(".private-placeholder"), public_key)
    fingerprint = public_key_fingerprint(public_key) if public_key.exists() else None
    entry = _make_lifecycle_event(
        event_type="KEY_COMPROMISED",
        purpose=purpose.purpose,
        reason=reason,
        public_key_fingerprint_value=fingerprint,
        previous_public_key_fingerprint_value=fingerprint,
        output_dir=output_dir,
    )
    _append_lifecycle_event(entry, output_dir)
    legacy_entry = {
        "compromise_event_id": entry["event_id"],
        "event_type": "KEY_COMPROMISED",
        "public_key_path": str(public_key),
        "purpose": purpose.purpose,
        "reason": reason,
        "timestamp": entry["timestamp"],
        "tool_version": __version__,
    }
    log_path = _compromise_log_path(output_dir)
    _append_jsonl(log_path, legacy_entry)
    warnings: list[str] = []
    if not public_key.exists():
        warnings.append("public key missing; compromise metadata still recorded")
    return {
        "compromise_event_id": entry["event_id"],
        "event_id": entry["event_id"],
        "event_type": "KEY_COMPROMISED",
        "compromise_log_path": str(log_path),
        "created": True,
        "public_key_path": str(public_key),
        "purpose": purpose.purpose,
        "status": "ok",
        "warnings": warnings,
    }


def generate_report_key(path: Path, force: bool = False) -> Path:
    return generate_private_key(path, force=force)


def generate_manifest_key(path: Path = DEFAULT_MANIFEST_KEY, force: bool = False) -> Path:
    return generate_private_key(path, force=force)


def generate_amendment_key(path: Path = DEFAULT_AMENDMENT_KEY, force: bool = False) -> Path:
    return generate_private_key(path, force=force)


def public_key_path(private_key_path: Path) -> Path:
    return private_key_path.with_suffix(private_key_path.suffix + ".pub")


def sign_bytes(path: Path, data: bytes, force_key: bool = False) -> bytes:
    generate_private_key(path, force=force_key)
    with tempfile.TemporaryDirectory() as tmp:
        data_path = Path(tmp) / "data.bin"
        sig_path = Path(tmp) / "data.sig"
        data_path.write_bytes(data)
        _run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-inkey",
                str(path),
                "-rawin",
                "-in",
                str(data_path),
                "-out",
                str(sig_path),
            ]
        )
        return sig_path.read_bytes()


def export_public_key(private_key_path: Path, output: Path | None = None) -> Path:
    pub_path = output or public_key_path(private_key_path)
    _run_openssl(["pkey", "-in", str(private_key_path), "-pubout", "-out", str(pub_path)])
    return pub_path


def sign_manifest_bytes(
    data: bytes,
    private_key: Path = DEFAULT_MANIFEST_KEY,
    public_key: Path = DEFAULT_MANIFEST_PUBLIC_KEY,
) -> tuple[bytes, bytes]:
    generate_manifest_key(private_key)
    export_public_key(private_key, public_key)
    return sign_bytes(private_key, data), public_key.read_bytes()


def sign_amendment_bytes(
    data: bytes,
    private_key: Path = DEFAULT_AMENDMENT_KEY,
    public_key: Path = DEFAULT_AMENDMENT_PUBLIC_KEY,
) -> tuple[bytes, bytes]:
    generate_amendment_key(private_key)
    export_public_key(private_key, public_key)
    return sign_bytes(private_key, data), public_key.read_bytes()


def verify_signature(public_key: Path, signature: bytes, data: bytes) -> bool:
    try:
        with tempfile.TemporaryDirectory() as tmp:
            data_path = Path(tmp) / "data.bin"
            sig_path = Path(tmp) / "data.sig"
            data_path.write_bytes(data)
            sig_path.write_bytes(signature)
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-in",
                    str(data_path),
                    "-sigfile",
                    str(sig_path),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=OPENSSL_OPERATION_TIMEOUT_SECONDS,
            )
            if result.returncode != 0:
                return False
            return True
    except subprocess.TimeoutExpired:
        return False
