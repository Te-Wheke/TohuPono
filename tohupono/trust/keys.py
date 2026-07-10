from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from tohupono import __version__
from tohupono.core.canonical_json import canonical_json_bytes, canonical_json_text


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


def _run_openssl(args: list[str]) -> None:
    try:
        subprocess.run(["openssl", *args], check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise KeyErrorWithAction("OpenSSL is required for MVP signing.") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise KeyErrorWithAction(f"OpenSSL command failed: {message}") from exc


def openssl_available() -> bool:
    try:
        subprocess.run(["openssl", "version"], check=False, capture_output=True, text=True)
    except FileNotFoundError:
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


def _event_id(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _append_jsonl(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json_text(value))
        handle.write("\n")


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    entries: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
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
    return warnings


def key_lifecycle_summary(purpose_name: str, output_dir: Path | None = None) -> dict[str, object]:
    purpose = get_key_purpose(purpose_name)
    rotation_entries = _entries_for_purpose(_rotation_log_path(output_dir), purpose.purpose, "KEY_ROTATED")
    compromise_entries = _entries_for_purpose(_compromise_log_path(output_dir), purpose.purpose, "KEY_COMPROMISED")
    warnings: list[str] = []
    if compromise_entries:
        warnings.append(COMPROMISE_WARNING)
    return {
        "compromise_events": len(compromise_entries),
        "latest_compromise_event_id": compromise_entries[-1].get("compromise_event_id") if compromise_entries else None,
        "latest_rotation_event_id": rotation_entries[-1].get("rotation_event_id") if rotation_entries else None,
        "rotation_events": len(rotation_entries),
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
        "status": purpose.status,
        "warnings": warnings,
    }


def inspect_keys(purpose: str | None = None, output_dir: Path | None = None) -> dict[str, object]:
    keys = [inspect_key_purpose(item, output_dir) for item in selected_key_purposes(purpose)]
    return {"keys": keys, "key_workspace": str(output_dir or Path("keys")), "status": "ok"}


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
        "key_workspace": str(output_dir or Path("keys")),
        "keys": keys,
        "openssl_available": openssl_ok,
        "status": status,
        "warnings": warnings,
    }


def generate_private_key(path: Path, force: bool = False) -> Path:
    if path.exists() and not force:
        return path
    if path.exists() and force:
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    _run_openssl(["genpkey", "-algorithm", "ED25519", "-out", str(path)])
    os.chmod(path, 0o600)
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
    if force:
        for path in (private_key, public_key):
            if path.exists():
                path.unlink()
    generate_private_key(private_key)
    export_public_key(private_key, public_key)
    return {
        "created": True,
        "private_key_path": str(private_key),
        "public_key_path": str(public_key),
        "purpose": purpose.purpose,
        "status": "ok",
        "warnings": [],
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
    timestamp = _now_utc()
    seed = {
        "event_type": "KEY_ROTATED",
        "old_public_key_path": str(old_public),
        "purpose": purpose.purpose,
        "reason": reason,
        "timestamp": timestamp,
        "tool_version": __version__,
    }
    rotation_event_id = _event_id(seed)
    new_private = old_private.with_name(f"{old_private.stem}_rotated_{rotation_event_id[:12]}{old_private.suffix}")
    new_public = old_public.with_name(f"{old_public.stem}_rotated_{rotation_event_id[:12]}{old_public.suffix}")
    if new_private.exists() or new_public.exists():
        raise KeyConflictError("Refusing to overwrite existing rotated key files.")
    generate_private_key(new_private)
    export_public_key(new_private, new_public)
    warnings: list[str] = []
    if not old_public.exists():
        warnings.append("old public key missing; rotation metadata still recorded")
    entry = {
        **seed,
        "new_public_key_path": str(new_public),
        "rotation_event_id": rotation_event_id,
    }
    log_path = _rotation_log_path(output_dir)
    _append_jsonl(log_path, entry)
    return {
        "created": True,
        "new_private_key_path": str(new_private),
        "new_public_key_path": str(new_public),
        "old_public_key_path": str(old_public),
        "purpose": purpose.purpose,
        "rotation_event_id": rotation_event_id,
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
    timestamp = _now_utc()
    seed = {
        "event_type": "KEY_COMPROMISED",
        "public_key_path": str(public_key),
        "purpose": purpose.purpose,
        "reason": reason,
        "timestamp": timestamp,
        "tool_version": __version__,
    }
    entry = {
        **seed,
        "compromise_event_id": _event_id(seed),
    }
    log_path = _compromise_log_path(output_dir)
    _append_jsonl(log_path, entry)
    warnings: list[str] = []
    if not public_key.exists():
        warnings.append("public key missing; compromise metadata still recorded")
    return {
        "compromise_event_id": entry["compromise_event_id"],
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
        )
        if result.returncode != 0:
            return False
        return True
