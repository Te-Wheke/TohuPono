from __future__ import annotations

import hashlib
import mimetypes
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

HashAlgorithm = Literal["sha256", "sha512", "blake3"]


class TohuPonoError(Exception):
    """Base exception for actionable CLI errors."""


class Blake3UnavailableError(TohuPonoError):
    """Raised when BLAKE3 is requested but the optional package is missing."""


@dataclass(frozen=True)
class FileIdentity:
    path_observed: str
    name: str
    extension: str
    size_bytes: int
    mime_observed: str
    mime_guess: str
    sha256: str
    sha512: str
    blake3: str | None
    created_at_observed: float | None
    modified_at_observed: float | None
    accessed_at_observed: float | None
    metadata_trust_level: str = "untrusted_supporting_metadata"

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.update(
            {
                "file_id": self.sha256,
                "original_path": self.path_observed,
                "filename": self.name,
                "os_created_time": self.created_at_observed,
                "os_modified_time": self.modified_at_observed,
                "os_accessed_time": self.accessed_at_observed,
            }
        )
        return value


def _blake3_hasher():
    try:
        import blake3  # type: ignore
    except ImportError as exc:
        raise Blake3UnavailableError(
            "BLAKE3 support is unavailable. Install the optional 'blake3' package to use this algorithm."
        ) from exc
    return blake3.blake3()


def hash_file(path: Path, algorithm: HashAlgorithm) -> str:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise TohuPonoError(f"Path is not a file: {path}")

    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha512":
        hasher = hashlib.sha512()
    elif algorithm == "blake3":
        hasher = _blake3_hasher()
    else:
        raise TohuPonoError(f"Unsupported hash algorithm: {algorithm}")

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def detect_mime(path: Path) -> str:
    with path.open("rb") as handle:
        head = handle.read(16)
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"PK\x03\x04"):
        return "application/zip"
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def inspect_file(path: Path, include_blake3: bool = True) -> FileIdentity:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise TohuPonoError(f"Path is not a file: {path}")

    stat = path.stat()
    blake3_digest: str | None = None
    if include_blake3:
        try:
            blake3_digest = hash_file(path, "blake3")
        except Blake3UnavailableError:
            blake3_digest = None

    return FileIdentity(
        path_observed=str(path),
        name=path.name,
        extension=path.suffix,
        size_bytes=stat.st_size,
        mime_observed=detect_mime(path),
        mime_guess=detect_mime(path),
        sha256=hash_file(path, "sha256"),
        sha512=hash_file(path, "sha512"),
        blake3=blake3_digest,
        created_at_observed=getattr(stat, "st_ctime", None),
        modified_at_observed=getattr(stat, "st_mtime", None),
        accessed_at_observed=getattr(stat, "st_atime", None),
    )
