from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RecordDescriptor:
    schema_version: str
    record_type: str
    namespace: str
    reference: str | None
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RecordEnvelope:
    record_id: str
    schema_version: str
    record_type: str
    namespace: str
    reference: str | None
    subject: dict[str, str]
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RecordValidationResult:
    status: str
    record_count: int
    record_ids: list[str]
    records: list[dict[str, object]]
    failures: list[str]
    warnings: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
