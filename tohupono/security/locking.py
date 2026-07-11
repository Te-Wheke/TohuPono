from __future__ import annotations

import json
import os
import secrets
import socket
from datetime import UTC, datetime
from pathlib import Path

from tohupono.core.canonical_json import canonical_json_text


class FileLock:
    """Small exclusive-create lock for local state changes."""

    def __init__(self, path: Path, *, operation: str) -> None:
        self.path = path
        self.operation = operation
        self._fd: int | None = None

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "hostname": socket.gethostname(),
            "nonce": secrets.token_hex(16),
            "operation": self.operation,
            "pid": os.getpid(),
            "schema_version": "tohupono.lock.v1",
        }
        data = canonical_json_text(record).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        self._fd = os.open(self.path, flags, 0o600)
        os.write(self._fd, data)
        os.fsync(self._fd)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    @staticmethod
    def read_lock(path: Path) -> dict[str, object] | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None
