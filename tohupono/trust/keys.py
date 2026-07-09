from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


class KeyErrorWithAction(Exception):
    """Raised when key handling cannot proceed safely."""


DEFAULT_MANIFEST_KEY = Path("keys/manifest_signing_key.pem")
DEFAULT_MANIFEST_PUBLIC_KEY = Path("keys/manifest_signing_key.pub")
DEFAULT_REPORT_KEY = Path("keys/report_signing_key.pem")


def _run_openssl(args: list[str]) -> None:
    try:
        subprocess.run(["openssl", *args], check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise KeyErrorWithAction("OpenSSL is required for MVP signing.") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise KeyErrorWithAction(f"OpenSSL command failed: {message}") from exc


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
