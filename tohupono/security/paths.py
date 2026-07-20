from __future__ import annotations

import os
import stat
import unicodedata
from pathlib import Path


class PathSecurityError(ValueError):
    """Raised when a local path violates TohuPono safety rules."""


BIDI_CONTROL_CATEGORIES = {"RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI"}


def validate_terminal_text(value: str, *, field: str = "value") -> None:
    if "\x00" in value:
        raise PathSecurityError(f"{field} contains a NUL character")
    for char in value:
        code = ord(char)
        if code < 32 or code == 127 or 0x80 <= code <= 0x9F:
            raise PathSecurityError(f"{field} contains an ASCII control character")
        if unicodedata.bidirectional(char) in BIDI_CONTROL_CATEGORIES:
            raise PathSecurityError(f"{field} contains a Unicode bidirectional control character")


def _reject_symlink(path: Path, *, label: str) -> None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise PathSecurityError(f"{label} must not be a symlink: {path}")


def _reject_hardlink(path: Path, *, label: str) -> list[str]:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return []
    if stat.S_ISREG(st.st_mode) and getattr(st, "st_nlink", 1) > 1:
        return [f"{label} has multiple hardlinks and may need operator review: {path}"]
    return []


def ensure_sensitive_path_safe(path: Path, *, private: bool = True) -> list[str]:
    validate_terminal_text(str(path), field="path")
    warnings: list[str] = []
    parts = path.parts
    if any(part in {".git", ".ssh"} for part in parts):
        raise PathSecurityError("sensitive path is inside a forbidden location")
    current = Path(parts[0]) if path.is_absolute() else Path(".")
    for part in parts[1:] if path.is_absolute() else parts:
        current = current / part
        _reject_symlink(current, label="sensitive path component")
    _reject_symlink(path, label="sensitive path")
    if private:
        warnings.extend(_reject_hardlink(path, label="private file"))
    return warnings


def safe_child_path(root: Path, child: str | Path) -> Path:
    raw = Path(child)
    validate_terminal_text(str(raw), field="relative path")
    if raw.is_absolute():
        raise PathSecurityError("absolute child paths are not allowed")
    if any(part in {"..", ""} for part in raw.parts):
        raise PathSecurityError("path traversal is not allowed")
    root_resolved = root.resolve(strict=False)
    candidate = (root / raw).resolve(strict=False)
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise PathSecurityError("path escapes the expected root") from exc
    return candidate


def open_no_follow(path: Path, flags: int, mode: int = 0o600) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags | nofollow, mode)
