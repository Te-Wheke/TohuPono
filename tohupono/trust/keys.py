from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


class KeyErrorWithAction(Exception):
    """Raised when key handling cannot proceed safely."""


DEFAULT_MANIFEST_KEY = Path("keys/manifest_signing_key.pem")
DEFAULT_MANIFEST_PUBLIC_KEY = Path("keys/manifest_signing_key.pub")
DEFAULT_REPORT_KEY = Path("keys/report_signing_key.pem")
DEFAULT_REPORT_PUBLIC_KEY = Path("keys/report_signing_key.pub")
DEFAULT_AMENDMENT_KEY = Path("keys/amendment_signing_key.pem")
DEFAULT_AMENDMENT_PUBLIC_KEY = Path("keys/amendment_signing_key.pub")


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


def _path_warnings(path: Path, *, private: bool) -> list[str]:
    warnings: list[str] = []
    normalized = path.as_posix()
    if private and not normalized.startswith("keys/") and not normalized.startswith("tests/"):
        warnings.append("private key path is outside the expected local key directories")
    if any(part in path.parts for part in [".git", ".ssh"]):
        warnings.append("key path is inside a forbidden location")
    return warnings


def inspect_key_purpose(purpose: KeyPurpose) -> dict[str, object]:
    private_exists = purpose.private_key_path.exists()
    public_exists = purpose.public_key_path.exists()
    warnings: list[str] = []
    if not private_exists:
        warnings.append("private key missing")
    if not public_exists:
        warnings.append("public key missing")
    warnings.extend(_path_warnings(purpose.private_key_path, private=True))
    warnings.extend(_path_warnings(purpose.public_key_path, private=False))
    return {
        "allowed_operations": list(purpose.allowed_operations),
        "description": purpose.description,
        "private_key_exists": private_exists,
        "private_key_path": str(purpose.private_key_path),
        "private_required_for_signing": purpose.private_required_for_signing,
        "public_key_exists": public_exists,
        "public_key_path": str(purpose.public_key_path),
        "public_required_for_verification": purpose.public_required_for_verification,
        "purpose": purpose.purpose,
        "status": purpose.status,
        "warnings": warnings,
    }


def inspect_keys(purpose: str | None = None) -> dict[str, object]:
    keys = [inspect_key_purpose(item) for item in selected_key_purposes(purpose)]
    return {"keys": keys, "status": "ok"}


def check_key_purpose(purpose: KeyPurpose) -> dict[str, object]:
    item = inspect_key_purpose(purpose)
    warnings = [str(warning) for warning in item["warnings"]]
    failures: list[str] = []
    if purpose.private_required_for_signing and not item["private_key_exists"]:
        warnings.append("private key required for signing is missing")
    if purpose.public_required_for_verification and not item["public_key_exists"]:
        warnings.append("public key required for verification is missing")
    if purpose.private_key_path.exists():
        try:
            mode = purpose.private_key_path.stat().st_mode & 0o777
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


def check_keys(purpose: str | None = None) -> dict[str, object]:
    keys = [check_key_purpose(item) for item in selected_key_purposes(purpose)]
    openssl_ok = openssl_available()
    warnings = [] if openssl_ok else ["OpenSSL is unavailable"]
    status = "fail" if any(item["status"] == "fail" for item in keys) else ("warn" if warnings or any(item["status"] == "warn" for item in keys) else "ok")
    return {
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
