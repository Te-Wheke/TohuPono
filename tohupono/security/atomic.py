from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Callable

from tohupono.core.canonical_json import canonical_json_text


def _fsync_parent(path: Path) -> None:
    try:
        fd = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600, validate: Callable[[bytes], None] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp.{secrets.token_hex(8)}")
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            fd = -1
        if validate is not None:
            validate(data)
        os.replace(temp, path)
        _fsync_parent(path)
    except Exception:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def atomic_append_jsonl(path: Path, value: dict[str, object], *, max_line_bytes: int) -> None:
    line = canonical_json_text(value) + "\n"
    if len(line.encode("utf-8")) > max_line_bytes:
        raise ValueError("JSONL entry exceeds configured line size limit")
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    atomic_write_text(path, existing + line, mode=0o600)
