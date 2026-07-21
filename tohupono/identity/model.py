from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class IdentityDescriptor:
    schema_version: str
    assertion_type: str
    identity: dict[str, str | None]
    key_fingerprint: dict[str, str] | None
    reference: str | None
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class IdentityAssertion:
    assertion_id: str
    schema_version: str
    assertion_type: str
    subject: dict[str, str]
    identity: dict[str, str | None]
    key_fingerprint: dict[str, str] | None
    reference: str | None
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class IdentityValidationResult:
    status: str
    identity_schema_status: str
    assertion_count: int
    assertion_ids: list[str]
    assertions: list[dict[str, object]]
    failures: list[str]
    warnings: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
