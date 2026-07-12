from __future__ import annotations

import json
import hashlib
import math
import re
import stat
from pathlib import Path
from typing import Any

from tohupono.core.canonical_json import canonical_json_bytes
from tohupono.records.model import RecordDescriptor, RecordEnvelope, RecordValidationResult
from tohupono.security.limits import (
    MAX_RECORD_ATTRIBUTE_DEPTH,
    MAX_RECORD_ATTRIBUTE_ITEMS,
    MAX_RECORD_DESCRIPTOR_BYTES,
    MAX_RECORD_NAMESPACE_LENGTH,
    MAX_RECORD_REFERENCE_LENGTH,
    MAX_RECORD_STRING_LENGTH,
    MAX_RECORD_TYPE_LENGTH,
    MAX_RECORDS_PER_PACKET,
)
from tohupono.security.paths import PathSecurityError, ensure_sensitive_path_safe, validate_terminal_text

RECORD_DESCRIPTOR_SCHEMA_VERSION = "tohupono.record_descriptor.v1"
RECORD_ENVELOPE_SCHEMA_VERSION = "tohupono.record.v1"
RECORDS_COLLECTION_SCHEMA_VERSION = "tohupono.records.v1"
SUPPORTED_RECORD_TYPES = ("generic",)
RECORD_LIMITATION = (
    "Proof of Records verifies the packet's canonical record envelope and subject link; "
    "it does not independently establish truth, authority, completeness, or legal validity for declared metadata."
)
_STATIC_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,99}$")
_RECORD_ID_RE = re.compile(r"^rec_[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DESCRIPTOR_FIELDS = {"schema_version", "record_type", "namespace", "reference", "attributes"}
_RECORD_FIELDS = {"record_id", "schema_version", "record_type", "namespace", "reference", "subject", "attributes"}


class RecordValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RecordValidationError("record_json_duplicate_key", "record descriptor contains duplicate keys")
        result[key] = value
    return result


def _reject_float(value: str) -> object:
    raise RecordValidationError("record_float_invalid", "record descriptor floats are not supported")


def _reject_constant(value: str) -> object:
    raise RecordValidationError("record_non_finite_invalid", "record descriptor non-finite values are not supported")


def _strict_json_loads(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise RecordValidationError("record_json_invalid", "record descriptor must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise RecordValidationError("record_json_invalid", "record descriptor JSON is invalid") from exc


def _validate_static_identifier(value: object, *, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value:
        raise RecordValidationError(f"record_{field}_invalid", f"record {field} must be a non-empty string")
    if len(value) > limit:
        raise RecordValidationError(f"record_{field}_invalid", f"record {field} exceeds configured length")
    try:
        validate_terminal_text(value, field=field)
    except PathSecurityError as exc:
        raise RecordValidationError(f"record_{field}_invalid", str(exc)) from exc
    if not _STATIC_ID_RE.fullmatch(value):
        raise RecordValidationError(f"record_{field}_invalid", f"record {field} must be a static identifier")
    return value


def _validate_reference(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RecordValidationError("record_reference_invalid", "record reference must be null or a string")
    if len(value) > MAX_RECORD_REFERENCE_LENGTH:
        raise RecordValidationError("record_reference_invalid", "record reference exceeds configured length")
    try:
        validate_terminal_text(value, field="reference")
    except PathSecurityError as exc:
        raise RecordValidationError("record_reference_invalid", str(exc)) from exc
    return value


def _validate_attribute_value(value: Any, *, depth: int = 0) -> Any:
    if depth > MAX_RECORD_ATTRIBUTE_DEPTH:
        raise RecordValidationError("record_attributes_invalid", "record attributes exceed configured depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 2**63 - 1:
            raise RecordValidationError("record_attributes_invalid", "record integer attribute exceeds configured range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RecordValidationError("record_attributes_invalid", "record non-finite attribute is invalid")
        raise RecordValidationError("record_attributes_invalid", "record float attributes are not supported")
    if isinstance(value, str):
        if len(value) > MAX_RECORD_STRING_LENGTH:
            raise RecordValidationError("record_attributes_invalid", "record string attribute exceeds configured length")
        try:
            validate_terminal_text(value, field="record attribute")
        except PathSecurityError as exc:
            raise RecordValidationError("record_attributes_invalid", str(exc)) from exc
        return value
    if isinstance(value, list):
        if len(value) > MAX_RECORD_ATTRIBUTE_ITEMS:
            raise RecordValidationError("record_attributes_invalid", "record attribute array exceeds configured size")
        return [_validate_attribute_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_RECORD_ATTRIBUTE_ITEMS:
            raise RecordValidationError("record_attributes_invalid", "record attribute object exceeds configured size")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise RecordValidationError("record_attributes_invalid", "record attribute keys must be non-empty strings")
            if len(key) > MAX_RECORD_STRING_LENGTH:
                raise RecordValidationError("record_attributes_invalid", "record attribute key exceeds configured length")
            try:
                validate_terminal_text(key, field="record attribute key")
            except PathSecurityError as exc:
                raise RecordValidationError("record_attributes_invalid", str(exc)) from exc
            result[key] = _validate_attribute_value(item, depth=depth + 1)
        return result
    raise RecordValidationError("record_attributes_invalid", "record attribute contains an unsupported value type")


def _validate_attributes(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RecordValidationError("record_attributes_invalid", "record attributes must be an object")
    return _validate_attribute_value(value)


def _validate_descriptor_path(path: Path) -> None:
    try:
        ensure_sensitive_path_safe(path, private=False)
    except PathSecurityError as exc:
        raise RecordValidationError("record_descriptor_path_invalid", "record descriptor path is unsafe") from exc
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(str(path)) from exc
    if stat.S_ISLNK(st.st_mode):
        raise RecordValidationError("record_descriptor_symlink", "record descriptor must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise RecordValidationError("record_descriptor_not_file", "record descriptor must be a regular file")
    if st.st_size > MAX_RECORD_DESCRIPTOR_BYTES:
        raise RecordValidationError("record_descriptor_too_large", "record descriptor exceeds configured size")


def load_record_descriptor(path: Path) -> RecordDescriptor:
    _validate_descriptor_path(path)
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise RecordValidationError("record_descriptor_changed", "record descriptor changed during read")
    if len(data) > MAX_RECORD_DESCRIPTOR_BYTES:
        raise RecordValidationError("record_descriptor_too_large", "record descriptor exceeds configured size")
    value = _strict_json_loads(data)
    if not isinstance(value, dict):
        raise RecordValidationError("record_descriptor_invalid", "record descriptor must be an object")
    extra = sorted(set(value) - _DESCRIPTOR_FIELDS)
    if extra:
        raise RecordValidationError("record_descriptor_invalid", "record descriptor contains unsupported fields")
    missing = sorted({"schema_version", "record_type", "namespace", "attributes"} - set(value))
    if missing:
        raise RecordValidationError("record_descriptor_invalid", "record descriptor is missing required fields")
    if value.get("schema_version") != RECORD_DESCRIPTOR_SCHEMA_VERSION:
        raise RecordValidationError("record_descriptor_schema_unsupported", "record descriptor schema is unsupported")
    record_type = _validate_static_identifier(value.get("record_type"), field="type", limit=MAX_RECORD_TYPE_LENGTH)
    if record_type not in SUPPORTED_RECORD_TYPES:
        raise RecordValidationError("record_type_unsupported", "record type is not supported")
    namespace = _validate_static_identifier(value.get("namespace"), field="namespace", limit=MAX_RECORD_NAMESPACE_LENGTH)
    reference = _validate_reference(value.get("reference"))
    attributes = _validate_attributes(value.get("attributes"))
    return RecordDescriptor(
        schema_version=RECORD_DESCRIPTOR_SCHEMA_VERSION,
        record_type=record_type,
        namespace=namespace,
        reference=reference,
        attributes=attributes,
    )


def _record_body(envelope: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in envelope.items() if key != "record_id"}


def record_id_for_body(body: dict[str, object]) -> str:
    digest = canonical_json_bytes(body)
    return "rec_" + hashlib.sha256(digest).hexdigest()[:32]


def build_record_envelope(
    descriptor: RecordDescriptor,
    *,
    subject_algorithm: str,
    subject_digest: str,
) -> RecordEnvelope:
    if subject_algorithm != "sha256" or not _SHA256_RE.fullmatch(subject_digest):
        raise RecordValidationError("record_subject_invalid", "record subject must be a SHA-256 digest")
    body: dict[str, object] = {
        "attributes": descriptor.attributes,
        "namespace": descriptor.namespace,
        "record_type": descriptor.record_type,
        "reference": descriptor.reference,
        "schema_version": RECORD_ENVELOPE_SCHEMA_VERSION,
        "subject": {"algorithm": subject_algorithm, "digest": subject_digest},
    }
    record_id = record_id_for_body(body)
    return RecordEnvelope(record_id=record_id, **body)  # type: ignore[arg-type]


def build_record_collection(envelopes: list[RecordEnvelope]) -> dict[str, object]:
    if not envelopes:
        raise RecordValidationError("records_empty", "records concept requires at least one record")
    if len(envelopes) > MAX_RECORDS_PER_PACKET:
        raise RecordValidationError("record_collection_too_large", "record collection exceeds configured size")
    items = sorted((item.to_dict() for item in envelopes), key=lambda item: str(item["record_id"]))
    ids = [str(item["record_id"]) for item in items]
    if len(ids) != len(set(ids)):
        raise RecordValidationError("record_duplicate_id", "duplicate record IDs are not allowed")
    return {"items": items, "schema_version": RECORDS_COLLECTION_SCHEMA_VERSION}


def record_ids_from_collection(collection: dict[str, object] | None) -> list[str]:
    if not isinstance(collection, dict):
        return []
    items = collection.get("items")
    if not isinstance(items, list):
        return []
    return sorted(str(item.get("record_id")) for item in items if isinstance(item, dict) and isinstance(item.get("record_id"), str))


def _failure(code: str, message: str, *, records: list[dict[str, object]] | None = None) -> RecordValidationResult:
    return RecordValidationResult(
        status="fail",
        record_count=len(records or []),
        record_ids=[str(item.get("record_id")) for item in records or [] if isinstance(item.get("record_id"), str)],
        records=records or [],
        failures=[code],
        warnings=[],
        limitations=[RECORD_LIMITATION],
    )


def _validate_record_envelope(value: object, *, subject_digest: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RecordValidationError("record_envelope_malformed", "record envelope must be an object")
    extra = sorted(set(value) - _RECORD_FIELDS)
    if extra:
        raise RecordValidationError("record_envelope_malformed", "record envelope contains unsupported fields")
    missing = sorted(_RECORD_FIELDS - set(value))
    if missing:
        raise RecordValidationError("record_envelope_malformed", "record envelope is missing required fields")
    if not isinstance(value.get("record_id"), str) or not _RECORD_ID_RE.fullmatch(str(value["record_id"])):
        raise RecordValidationError("record_id_invalid", "record ID is invalid")
    if value.get("schema_version") != RECORD_ENVELOPE_SCHEMA_VERSION:
        raise RecordValidationError("record_schema_unsupported", "record schema is unsupported")
    record_type = _validate_static_identifier(value.get("record_type"), field="type", limit=MAX_RECORD_TYPE_LENGTH)
    if record_type not in SUPPORTED_RECORD_TYPES:
        raise RecordValidationError("record_type_unsupported", "record type is not supported")
    _validate_static_identifier(value.get("namespace"), field="namespace", limit=MAX_RECORD_NAMESPACE_LENGTH)
    _validate_reference(value.get("reference"))
    _validate_attributes(value.get("attributes"))
    subject = value.get("subject")
    if not isinstance(subject, dict) or subject.get("algorithm") != "sha256" or not isinstance(subject.get("digest"), str):
        raise RecordValidationError("record_subject_invalid", "record subject is invalid")
    if subject["digest"] != subject_digest:
        raise RecordValidationError("record_subject_digest_mismatch", "record subject digest does not match packet subject")
    body = _record_body(value)
    expected_id = record_id_for_body(body)
    if value["record_id"] != expected_id:
        raise RecordValidationError("record_id_mismatch", "record ID does not match canonical record body")
    return dict(value)


def validate_manifest_records(
    manifest: dict[str, object],
    *,
    expected_record_ids: list[str] | tuple[str, ...] | None = None,
) -> RecordValidationResult:
    file_info = manifest.get("file")
    if not isinstance(file_info, dict) or not isinstance(file_info.get("sha256"), str):
        return _failure("record_subject_invalid", "record subject digest is unavailable")
    subject_digest = str(file_info["sha256"])
    if not _SHA256_RE.fullmatch(subject_digest):
        return _failure("record_subject_invalid", "record subject digest is invalid")
    section = manifest.get("records")
    if section is None:
        return _failure("records_section_missing", "records section is missing")
    if not isinstance(section, dict):
        return _failure("records_items_invalid", "records section must be an object")
    if section.get("schema_version") != RECORDS_COLLECTION_SCHEMA_VERSION:
        return _failure("records_schema_unsupported", "records schema is unsupported")
    items = section.get("items")
    if not isinstance(items, list):
        return _failure("records_items_invalid", "records items must be a list")
    if not items:
        return _failure("records_empty", "records collection is empty")
    if len(items) > MAX_RECORDS_PER_PACKET:
        return _failure("record_collection_too_large", "record collection exceeds configured size")
    records: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for item in items:
        try:
            record = _validate_record_envelope(item, subject_digest=subject_digest)
        except RecordValidationError as exc:
            return _failure(exc.code, str(exc), records=records)
        record_id = str(record["record_id"])
        if record_id in seen_ids:
            return _failure("record_duplicate_id", "duplicate record IDs are not allowed", records=records)
        seen_ids.add(record_id)
        records.append(record)
    record_ids = sorted(seen_ids)
    if list(items) != sorted(items, key=lambda item: str(item.get("record_id")) if isinstance(item, dict) else ""):
        return _failure("records_items_invalid", "records items are not in canonical order", records=records)
    if expected_record_ids is not None:
        expected = list(expected_record_ids)
        if not all(isinstance(item, str) and _RECORD_ID_RE.fullmatch(item) for item in expected):
            return _failure("record_claim_ids_invalid", "record claim IDs are invalid", records=records)
        if len(expected) != len(set(expected)):
            return _failure("record_claim_duplicate_id", "record claim contains duplicate IDs", records=records)
        expected_sorted = sorted(expected)
        missing = sorted(set(expected_sorted) - set(record_ids))
        extra = sorted(set(record_ids) - set(expected_sorted))
        if missing:
            return _failure("record_claim_missing", "record claim references missing records", records=records)
        if extra:
            return _failure("record_claim_undeclared", "record collection contains unclaimed records", records=records)
    warnings = [
        "Declared record metadata is not independently verified for truth, authority, completeness, or legal validity."
    ]
    return RecordValidationResult(
        status="pass",
        record_count=len(records),
        record_ids=record_ids,
        records=records,
        failures=[],
        warnings=warnings,
        limitations=[RECORD_LIMITATION],
    )
