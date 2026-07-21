from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class TransactionDescriptor:
    schema_version: str
    transaction_type: str
    participants: list[dict[str, str]]
    occurred_at: str | None
    reference: str | None
    terms: dict[str, Any]
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TransactionEnvelope:
    transaction_id: str
    schema_version: str
    transaction_type: str
    subject: dict[str, str]
    participants: list[dict[str, str]]
    occurred_at: str | None
    reference: str | None
    terms: dict[str, Any]
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TransactionValidationResult:
    status: str
    transaction_schema_status: str
    transaction_count: int
    transaction_ids: list[str]
    transactions: list[dict[str, object]]
    failures: list[str]
    warnings: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
