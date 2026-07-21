from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class CustodyDescriptor:
    schema_version: str
    event_type: str
    actor: dict[str, str]
    occurred_at: str | None
    location: str | None
    reference: str | None
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CustodyEvent:
    event_id: str
    event_hash: str
    schema_version: str
    event_type: str
    subject: dict[str, str]
    actor: dict[str, str]
    occurred_at: str | None
    location: str | None
    reference: str | None
    attributes: dict[str, Any]
    sequence: int
    previous_event_hash: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CustodyValidationResult:
    status: str
    custody_schema_status: str
    event_count: int
    chain_head: str | None
    event_ids: list[str]
    events: list[dict[str, object]]
    failures: list[str]
    warnings: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
