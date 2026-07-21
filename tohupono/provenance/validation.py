from __future__ import annotations

import hashlib
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from tohupono.core.canonical_json import canonical_json_bytes
from tohupono.provenance.model import ProvenanceDescriptor, ProvenanceEdge, ProvenanceValidationResult
from tohupono.records.validation import _strict_json_loads, _validate_attribute_value
from tohupono.security.limits import (
    MAX_PROVENANCE_ACTOR_IDENTIFIER_LENGTH,
    MAX_PROVENANCE_ACTOR_NAMESPACE_LENGTH,
    MAX_PROVENANCE_DESCRIPTOR_BYTES,
    MAX_PROVENANCE_EDGES_PER_PACKET,
    MAX_PROVENANCE_OPERATION_NAME_LENGTH,
    MAX_PROVENANCE_OPERATION_VERSION_LENGTH,
    MAX_PROVENANCE_REFERENCE_LENGTH,
    MAX_PROVENANCE_RELATION_TYPE_LENGTH,
)
from tohupono.security.paths import PathSecurityError, ensure_sensitive_path_safe, validate_terminal_text

PROVENANCE_DESCRIPTOR_SCHEMA_VERSION = "tohupono.provenance_descriptor.v1"
PROVENANCE_EDGE_SCHEMA_VERSION = "tohupono.provenance_edge.v1"
PROVENANCE_COLLECTION_SCHEMA_VERSION = "tohupono.provenance.v1"
SUPPORTED_PROVENANCE_RELATIONS = (
    "copied_from",
    "converted_from",
    "derived_from",
    "edited_from",
    "extracted_from",
    "generated_from",
    "transcoded_from",
)
PROVENANCE_LIMITATIONS = [
    "Parent existence and parent bytes are not independently verified.",
    "Declared lineage relationships are not proof that a real-world derivation or transformation occurred.",
    "Authorship, ownership, authenticity, origin, authority, truth, and complete lineage are not established.",
    "Declared occurred_at values are metadata and are not external timestamp evidence.",
]
_STATIC_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,99}$")
_RFC3339_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EDGE_ID_RE = re.compile(r"^prv_[0-9a-f]{32}$")
_DESCRIPTOR_FIELDS = {"schema_version", "relation_type", "parent", "operation", "occurred_at", "actor", "reference", "attributes"}
_EDGE_FIELDS = {"edge_id", "schema_version", "relation_type", "child", "parent", "operation", "occurred_at", "actor", "reference", "attributes"}
_COLLECTION_FIELDS = {"edge_count", "edges", "schema_version"}


class ProvenanceValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _validate_descriptor_path(path: Path) -> None:
    try:
        ensure_sensitive_path_safe(path, private=False)
    except PathSecurityError as exc:
        raise ProvenanceValidationError("provenance_descriptor_path_invalid", "provenance descriptor path is unsafe") from exc
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(str(path)) from exc
    if stat.S_ISLNK(st.st_mode):
        raise ProvenanceValidationError("provenance_descriptor_symlink", "provenance descriptor must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise ProvenanceValidationError("provenance_descriptor_not_file", "provenance descriptor must be a regular file")
    if st.st_size > MAX_PROVENANCE_DESCRIPTOR_BYTES:
        raise ProvenanceValidationError("provenance_descriptor_too_large", "provenance descriptor exceeds configured size")


def _validate_static_identifier(value: object, *, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value:
        raise ProvenanceValidationError(f"provenance_{field}_invalid", f"provenance {field} must be a non-empty string")
    if len(value) > limit:
        raise ProvenanceValidationError(f"provenance_{field}_invalid", f"provenance {field} exceeds configured length")
    try:
        validate_terminal_text(value, field=field)
    except PathSecurityError as exc:
        raise ProvenanceValidationError(f"provenance_{field}_invalid", str(exc)) from exc
    if not _STATIC_ID_RE.fullmatch(value):
        raise ProvenanceValidationError(f"provenance_{field}_invalid", f"provenance {field} must be a static identifier")
    return value


def _validate_text(value: object, *, code: str, field: str, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProvenanceValidationError(code, f"provenance {field} must be null or a string")
    if len(value) > limit:
        raise ProvenanceValidationError(code, f"provenance {field} exceeds configured length")
    try:
        validate_terminal_text(value, field=field)
    except PathSecurityError as exc:
        raise ProvenanceValidationError(code, str(exc)) from exc
    return value


def _validate_occurred_at(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _RFC3339_UTC_RE.fullmatch(value):
        raise ProvenanceValidationError("provenance_occurred_at_invalid", "provenance occurred_at must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ProvenanceValidationError("provenance_occurred_at_invalid", "provenance occurred_at must be a valid UTC timestamp") from exc
    return value


def _validate_digest_object(value: object, *, code: str, field: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"algorithm", "digest"}:
        raise ProvenanceValidationError(code, f"provenance {field} must contain algorithm and digest")
    if value.get("algorithm") != "sha256":
        raise ProvenanceValidationError(code, f"provenance {field} algorithm must be sha256")
    digest = value.get("digest")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise ProvenanceValidationError(code, f"provenance {field} digest must be a lowercase SHA-256 digest")
    return {"algorithm": "sha256", "digest": digest}


def _validate_actor(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"namespace", "identifier"}:
        raise ProvenanceValidationError("provenance_actor_invalid", "provenance actor fields are invalid")
    return {
        "identifier": _validate_static_identifier(
            value.get("identifier"), field="actor_identifier", limit=MAX_PROVENANCE_ACTOR_IDENTIFIER_LENGTH
        ),
        "namespace": _validate_static_identifier(
            value.get("namespace"), field="actor_namespace", limit=MAX_PROVENANCE_ACTOR_NAMESPACE_LENGTH
        ),
    }


def _validate_operation(value: object) -> dict[str, str | None] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"name", "version"}:
        raise ProvenanceValidationError("provenance_operation_invalid", "provenance operation fields are invalid")
    name = _validate_static_identifier(value.get("name"), field="operation_name", limit=MAX_PROVENANCE_OPERATION_NAME_LENGTH)
    version = _validate_text(
        value.get("version"),
        code="provenance_operation_version_invalid",
        field="operation version",
        limit=MAX_PROVENANCE_OPERATION_VERSION_LENGTH,
    )
    return {"name": name, "version": version}


def _validate_attributes(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProvenanceValidationError("provenance_attributes_invalid", "provenance attributes must be an object")
    try:
        validated = _validate_attribute_value(value)
    except ValueError as exc:
        raise ProvenanceValidationError("provenance_attributes_invalid", str(exc)) from exc
    if not isinstance(validated, dict):
        raise ProvenanceValidationError("provenance_attributes_invalid", "provenance attributes must be an object")
    return validated


def load_provenance_descriptor(path: Path) -> ProvenanceDescriptor:
    _validate_descriptor_path(path)
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ProvenanceValidationError("provenance_descriptor_changed", "provenance descriptor changed during read")
    if len(data) > MAX_PROVENANCE_DESCRIPTOR_BYTES:
        raise ProvenanceValidationError("provenance_descriptor_too_large", "provenance descriptor exceeds configured size")
    try:
        value = _strict_json_loads(data)
    except ValueError as exc:
        code = getattr(exc, "code", "provenance_json_invalid")
        raise ProvenanceValidationError(str(code).replace("record_", "provenance_"), str(exc)) from exc
    if not isinstance(value, dict):
        raise ProvenanceValidationError("provenance_descriptor_invalid", "provenance descriptor must be an object")
    if sorted(set(value) - _DESCRIPTOR_FIELDS):
        raise ProvenanceValidationError("provenance_descriptor_invalid", "provenance descriptor contains unsupported fields")
    missing = sorted({"schema_version", "relation_type", "parent", "attributes"} - set(value))
    if missing:
        raise ProvenanceValidationError("provenance_descriptor_invalid", "provenance descriptor is missing required fields")
    if value.get("schema_version") != PROVENANCE_DESCRIPTOR_SCHEMA_VERSION:
        raise ProvenanceValidationError("provenance_descriptor_schema_unsupported", "provenance descriptor schema is unsupported")
    relation_type = _validate_static_identifier(
        value.get("relation_type"), field="relation_type", limit=MAX_PROVENANCE_RELATION_TYPE_LENGTH
    )
    if relation_type not in SUPPORTED_PROVENANCE_RELATIONS:
        raise ProvenanceValidationError("provenance_relation_type_unsupported", "provenance relation type is unsupported")
    return ProvenanceDescriptor(
        schema_version=PROVENANCE_DESCRIPTOR_SCHEMA_VERSION,
        relation_type=relation_type,
        parent=_validate_digest_object(value.get("parent"), code="provenance_parent_invalid", field="parent"),
        operation=_validate_operation(value.get("operation")),
        occurred_at=_validate_occurred_at(value.get("occurred_at")),
        actor=_validate_actor(value.get("actor")),
        reference=_validate_text(value.get("reference"), code="provenance_reference_invalid", field="reference", limit=MAX_PROVENANCE_REFERENCE_LENGTH),
        attributes=_validate_attributes(value.get("attributes")),
    )


def _edge_body(edge: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in edge.items() if key != "edge_id"}


def provenance_edge_id_for_body(body: dict[str, object]) -> str:
    return "prv_" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()[:32]


def _validate_parent_child_relation(relation_type: str, parent_digest: str, child_digest: str) -> None:
    if relation_type != "copied_from" and parent_digest == child_digest:
        raise ProvenanceValidationError("provenance_parent_digest_invalid", "parent digest must differ from child digest for this relation")


def build_provenance_edge(
    descriptor: ProvenanceDescriptor,
    *,
    child_algorithm: str,
    child_digest: str,
) -> ProvenanceEdge:
    if child_algorithm != "sha256" or not _SHA256_RE.fullmatch(child_digest):
        raise ProvenanceValidationError("provenance_child_invalid", "provenance child must be a SHA-256 digest")
    _validate_parent_child_relation(descriptor.relation_type, descriptor.parent["digest"], child_digest)
    body: dict[str, object] = {
        "actor": descriptor.actor,
        "attributes": descriptor.attributes,
        "child": {"algorithm": child_algorithm, "digest": child_digest},
        "occurred_at": descriptor.occurred_at,
        "operation": descriptor.operation,
        "parent": descriptor.parent,
        "reference": descriptor.reference,
        "relation_type": descriptor.relation_type,
        "schema_version": PROVENANCE_EDGE_SCHEMA_VERSION,
    }
    edge_id = provenance_edge_id_for_body(body)
    return ProvenanceEdge(edge_id=edge_id, **body)  # type: ignore[arg-type]


def build_provenance_collection(edges: list[ProvenanceEdge]) -> dict[str, object]:
    if not edges:
        raise ProvenanceValidationError("provenance_empty", "provenance concept requires at least one edge")
    if len(edges) > MAX_PROVENANCE_EDGES_PER_PACKET:
        raise ProvenanceValidationError("provenance_collection_too_large", "provenance edge collection exceeds configured size")
    items = sorted((edge.to_dict() for edge in edges), key=lambda item: str(item["edge_id"]))
    ids = [str(item["edge_id"]) for item in items]
    if len(ids) != len(set(ids)):
        raise ProvenanceValidationError("provenance_edge_duplicate_id", "duplicate provenance edge IDs are not allowed")
    bodies = [hashlib.sha256(canonical_json_bytes(_edge_body(item))).hexdigest() for item in items]
    if len(bodies) != len(set(bodies)):
        raise ProvenanceValidationError("provenance_edge_duplicate_body", "duplicate provenance edge bodies are not allowed")
    return {"edge_count": len(items), "edges": items, "schema_version": PROVENANCE_COLLECTION_SCHEMA_VERSION}


def provenance_edge_ids_from_collection(collection: dict[str, object] | None) -> list[str]:
    if not isinstance(collection, dict):
        return []
    edges = collection.get("edges")
    if not isinstance(edges, list):
        return []
    return sorted(str(item.get("edge_id")) for item in edges if isinstance(item, dict) and isinstance(item.get("edge_id"), str))


def _failure(code: str, *, edges: list[dict[str, object]] | None = None) -> ProvenanceValidationResult:
    return ProvenanceValidationResult(
        status="fail",
        provenance_schema_status="invalid",
        edge_count=len(edges or []),
        edge_ids=[str(item.get("edge_id")) for item in edges or [] if isinstance(item.get("edge_id"), str)],
        edges=edges or [],
        failures=[code],
        warnings=[],
        limitations=PROVENANCE_LIMITATIONS,
    )


def _validate_edge(value: object, *, child_digest: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProvenanceValidationError("provenance_edge_malformed", "provenance edge must be an object")
    if sorted(set(value) - _EDGE_FIELDS):
        raise ProvenanceValidationError("provenance_edge_malformed", "provenance edge contains unsupported fields")
    if sorted(_EDGE_FIELDS - set(value)):
        raise ProvenanceValidationError("provenance_edge_malformed", "provenance edge is missing required fields")
    if value.get("schema_version") != PROVENANCE_EDGE_SCHEMA_VERSION:
        raise ProvenanceValidationError("provenance_edge_schema_unsupported", "provenance edge schema is unsupported")
    edge_id = value.get("edge_id")
    if not isinstance(edge_id, str) or not _EDGE_ID_RE.fullmatch(edge_id):
        raise ProvenanceValidationError("provenance_edge_id_invalid", "provenance edge ID is invalid")
    relation_type = _validate_static_identifier(value.get("relation_type"), field="relation_type", limit=MAX_PROVENANCE_RELATION_TYPE_LENGTH)
    if relation_type not in SUPPORTED_PROVENANCE_RELATIONS:
        raise ProvenanceValidationError("provenance_relation_type_unsupported", "provenance relation type is unsupported")
    child = _validate_digest_object(value.get("child"), code="provenance_child_invalid", field="child")
    if child["digest"] != child_digest:
        raise ProvenanceValidationError("provenance_child_digest_mismatch", "provenance edge child digest does not match packet subject")
    parent = _validate_digest_object(value.get("parent"), code="provenance_parent_invalid", field="parent")
    _validate_parent_child_relation(relation_type, parent["digest"], child_digest)
    _validate_operation(value.get("operation"))
    _validate_occurred_at(value.get("occurred_at"))
    _validate_actor(value.get("actor"))
    _validate_text(value.get("reference"), code="provenance_reference_invalid", field="reference", limit=MAX_PROVENANCE_REFERENCE_LENGTH)
    _validate_attributes(value.get("attributes"))
    expected_id = provenance_edge_id_for_body(_edge_body(value))
    if edge_id != expected_id:
        raise ProvenanceValidationError("provenance_edge_id_mismatch", "provenance edge ID does not match canonical body")
    return dict(value)


def validate_manifest_provenance(
    manifest: dict[str, object],
    *,
    expected_edge_ids: list[str] | tuple[str, ...] | None = None,
    expected_child: dict[str, object] | None = None,
) -> ProvenanceValidationResult:
    file_info = manifest.get("file")
    if not isinstance(file_info, dict) or not isinstance(file_info.get("sha256"), str):
        return _failure("provenance_child_invalid")
    child_digest = str(file_info["sha256"])
    if not _SHA256_RE.fullmatch(child_digest):
        return _failure("provenance_child_invalid")
    if expected_child is not None:
        if not isinstance(expected_child, dict) or expected_child.get("algorithm") != "sha256" or expected_child.get("digest") != child_digest:
            return _failure("provenance_claim_child_mismatch")
    section = manifest.get("provenance")
    if section is None:
        return _failure("provenance_section_missing")
    if not isinstance(section, dict):
        return _failure("provenance_edges_invalid")
    if sorted(set(section) - _COLLECTION_FIELDS):
        return _failure("provenance_edges_invalid")
    if section.get("schema_version") != PROVENANCE_COLLECTION_SCHEMA_VERSION:
        return _failure("provenance_schema_unsupported")
    edges_value = section.get("edges")
    if not isinstance(edges_value, list):
        return _failure("provenance_edges_invalid")
    if not edges_value:
        return _failure("provenance_empty")
    if len(edges_value) > MAX_PROVENANCE_EDGES_PER_PACKET:
        return _failure("provenance_collection_too_large")
    if section.get("edge_count") != len(edges_value):
        return _failure("provenance_edge_count_mismatch")
    edges: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_bodies: set[str] = set()
    for raw_edge in edges_value:
        try:
            edge = _validate_edge(raw_edge, child_digest=child_digest)
        except ProvenanceValidationError as exc:
            return _failure(exc.code, edges=edges)
        edge_id = str(edge["edge_id"])
        if edge_id in seen_ids:
            return _failure("provenance_edge_duplicate_id", edges=edges)
        body_hash = hashlib.sha256(canonical_json_bytes(_edge_body(edge))).hexdigest()
        if body_hash in seen_bodies:
            return _failure("provenance_edge_duplicate_body", edges=edges)
        seen_ids.add(edge_id)
        seen_bodies.add(body_hash)
        edges.append(edge)
    if list(edges_value) != sorted(edges_value, key=lambda item: str(item.get("edge_id")) if isinstance(item, dict) else ""):
        return _failure("provenance_edges_invalid", edges=edges)
    edge_ids = sorted(seen_ids)
    if expected_edge_ids is not None:
        expected = list(expected_edge_ids)
        if not all(isinstance(item, str) and _EDGE_ID_RE.fullmatch(item) for item in expected):
            return _failure("provenance_claim_edge_ids_invalid", edges=edges)
        if len(expected) != len(set(expected)):
            return _failure("provenance_claim_edge_duplicate", edges=edges)
        if expected != edge_ids:
            missing = sorted(set(expected) - set(edge_ids))
            if missing:
                return _failure("provenance_claim_edge_missing", edges=edges)
            return _failure("provenance_claim_edge_undeclared", edges=edges)
    return ProvenanceValidationResult(
        status="pass",
        provenance_schema_status="valid",
        edge_count=len(edges),
        edge_ids=edge_ids,
        edges=edges,
        failures=[],
        warnings=["Declared provenance parents, actors, references, operations, and times are not independently verified."],
        limitations=PROVENANCE_LIMITATIONS,
    )
