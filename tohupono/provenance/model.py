from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ProvenanceDescriptor:
    schema_version: str
    relation_type: str
    parent: dict[str, str]
    operation: dict[str, str | None] | None
    occurred_at: str | None
    actor: dict[str, str] | None
    reference: str | None
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProvenanceEdge:
    edge_id: str
    schema_version: str
    relation_type: str
    child: dict[str, str]
    parent: dict[str, str]
    operation: dict[str, str | None] | None
    occurred_at: str | None
    actor: dict[str, str] | None
    reference: str | None
    attributes: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProvenanceValidationResult:
    status: str
    provenance_schema_status: str
    edge_count: int
    edge_ids: list[str]
    edges: list[dict[str, object]]
    failures: list[str]
    warnings: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
