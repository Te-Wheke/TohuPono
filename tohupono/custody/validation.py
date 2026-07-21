from __future__ import annotations

import hashlib
import json
import math
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from tohupono.core.canonical_json import canonical_json_bytes
from tohupono.custody.model import CustodyDescriptor, CustodyEvent, CustodyValidationResult
from tohupono.records.validation import _strict_json_loads, _validate_attribute_value
from tohupono.security.limits import (
    MAX_CUSTODY_ACTOR_IDENTIFIER_LENGTH,
    MAX_CUSTODY_ACTOR_NAMESPACE_LENGTH,
    MAX_CUSTODY_DESCRIPTOR_BYTES,
    MAX_CUSTODY_EVENTS_PER_PACKET,
    MAX_CUSTODY_EVENT_TYPE_LENGTH,
    MAX_CUSTODY_LOCATION_LENGTH,
    MAX_CUSTODY_REFERENCE_LENGTH,
)
from tohupono.security.paths import PathSecurityError, ensure_sensitive_path_safe, validate_terminal_text

CUSTODY_DESCRIPTOR_SCHEMA_VERSION = "tohupono.custody_descriptor.v1"
CUSTODY_EVENT_SCHEMA_VERSION = "tohupono.custody_event.v1"
CUSTODY_COLLECTION_SCHEMA_VERSION = "tohupono.custody.v1"
GENESIS_CUSTODY_HASH = "GENESIS"
SUPPORTED_CUSTODY_EVENT_TYPES = ("copied", "created", "received", "released", "stored", "transferred", "verified")
CUSTODY_LIMITATIONS = [
    "Actors are declared, not independently verified identities.",
    "Proof of Custody does not independently prove physical possession, legal custody, complete history, or that declared events occurred.",
    "Declared custody event times are metadata and are not external timestamps unless separately supported by Proof of Existence.",
]
_STATIC_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,99}$")
_RFC3339_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EVENT_ID_RE = re.compile(r"^cue_[0-9a-f]{32}$")
_DESCRIPTOR_FIELDS = {"schema_version", "event_type", "actor", "occurred_at", "location", "reference", "attributes"}
_EVENT_FIELDS = {
    "actor",
    "attributes",
    "event_hash",
    "event_id",
    "event_type",
    "location",
    "occurred_at",
    "previous_event_hash",
    "reference",
    "schema_version",
    "sequence",
    "subject",
}
_COLLECTION_FIELDS = {"chain_head", "event_count", "events", "schema_version"}


class CustodyValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _validate_descriptor_path(path: Path) -> None:
    try:
        ensure_sensitive_path_safe(path, private=False)
    except PathSecurityError as exc:
        raise CustodyValidationError("custody_descriptor_path_invalid", "custody descriptor path is unsafe") from exc
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(str(path)) from exc
    if stat.S_ISLNK(st.st_mode):
        raise CustodyValidationError("custody_descriptor_symlink", "custody descriptor must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise CustodyValidationError("custody_descriptor_not_file", "custody descriptor must be a regular file")
    if st.st_size > MAX_CUSTODY_DESCRIPTOR_BYTES:
        raise CustodyValidationError("custody_descriptor_too_large", "custody descriptor exceeds configured size")


def _validate_static_identifier(value: object, *, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value:
        raise CustodyValidationError(f"custody_{field}_invalid", f"custody {field} must be a non-empty string")
    if len(value) > limit:
        raise CustodyValidationError(f"custody_{field}_invalid", f"custody {field} exceeds configured length")
    try:
        validate_terminal_text(value, field=field)
    except PathSecurityError as exc:
        raise CustodyValidationError(f"custody_{field}_invalid", str(exc)) from exc
    if not _STATIC_ID_RE.fullmatch(value):
        raise CustodyValidationError(f"custody_{field}_invalid", f"custody {field} must be a static identifier")
    return value


def _validate_text(value: object, *, code: str, field: str, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CustodyValidationError(code, f"custody {field} must be null or a string")
    if len(value) > limit:
        raise CustodyValidationError(code, f"custody {field} exceeds configured length")
    try:
        validate_terminal_text(value, field=field)
    except PathSecurityError as exc:
        raise CustodyValidationError(code, str(exc)) from exc
    return value


def _validate_occurred_at(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _RFC3339_UTC_RE.fullmatch(value):
        raise CustodyValidationError("custody_occurred_at_invalid", "custody occurred_at must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise CustodyValidationError("custody_occurred_at_invalid", "custody occurred_at must be a valid UTC timestamp") from exc
    return value


def _validate_actor(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise CustodyValidationError("custody_actor_invalid", "custody actor must be an object")
    if set(value) != {"namespace", "identifier"}:
        raise CustodyValidationError("custody_actor_invalid", "custody actor fields are invalid")
    return {
        "identifier": _validate_static_identifier(
            value.get("identifier"), field="actor_identifier", limit=MAX_CUSTODY_ACTOR_IDENTIFIER_LENGTH
        ),
        "namespace": _validate_static_identifier(
            value.get("namespace"), field="actor_namespace", limit=MAX_CUSTODY_ACTOR_NAMESPACE_LENGTH
        ),
    }


def _validate_attributes(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CustodyValidationError("custody_attributes_invalid", "custody attributes must be an object")
    try:
        validated = _validate_attribute_value(value)
    except ValueError as exc:
        raise CustodyValidationError("custody_attributes_invalid", str(exc)) from exc
    if not isinstance(validated, dict):
        raise CustodyValidationError("custody_attributes_invalid", "custody attributes must be an object")
    return validated


def load_custody_descriptor(path: Path) -> CustodyDescriptor:
    _validate_descriptor_path(path)
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise CustodyValidationError("custody_descriptor_changed", "custody descriptor changed during read")
    if len(data) > MAX_CUSTODY_DESCRIPTOR_BYTES:
        raise CustodyValidationError("custody_descriptor_too_large", "custody descriptor exceeds configured size")
    try:
        value = _strict_json_loads(data)
    except ValueError as exc:
        code = getattr(exc, "code", "custody_json_invalid")
        raise CustodyValidationError(str(code).replace("record_", "custody_"), str(exc)) from exc
    if not isinstance(value, dict):
        raise CustodyValidationError("custody_descriptor_invalid", "custody descriptor must be an object")
    if sorted(set(value) - _DESCRIPTOR_FIELDS):
        raise CustodyValidationError("custody_descriptor_invalid", "custody descriptor contains unsupported fields")
    missing = sorted({"schema_version", "event_type", "actor", "attributes"} - set(value))
    if missing:
        raise CustodyValidationError("custody_descriptor_invalid", "custody descriptor is missing required fields")
    if value.get("schema_version") != CUSTODY_DESCRIPTOR_SCHEMA_VERSION:
        raise CustodyValidationError("custody_descriptor_schema_unsupported", "custody descriptor schema is unsupported")
    event_type = _validate_static_identifier(
        value.get("event_type"), field="event_type", limit=MAX_CUSTODY_EVENT_TYPE_LENGTH
    )
    if event_type not in SUPPORTED_CUSTODY_EVENT_TYPES:
        raise CustodyValidationError("custody_event_type_unsupported", "custody event type is not supported")
    return CustodyDescriptor(
        schema_version=CUSTODY_DESCRIPTOR_SCHEMA_VERSION,
        event_type=event_type,
        actor=_validate_actor(value.get("actor")),
        occurred_at=_validate_occurred_at(value.get("occurred_at")),
        location=_validate_text(
            value.get("location"), code="custody_location_invalid", field="location", limit=MAX_CUSTODY_LOCATION_LENGTH
        ),
        reference=_validate_text(
            value.get("reference"), code="custody_reference_invalid", field="reference", limit=MAX_CUSTODY_REFERENCE_LENGTH
        ),
        attributes=_validate_attributes(value.get("attributes")),
    )


def custody_event_hash_for_body(body: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def custody_event_id_for_body(body: dict[str, object]) -> str:
    return "cue_" + custody_event_hash_for_body(body)[:32]


def _event_body(event: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in event.items() if key not in {"event_hash", "event_id"}}


def build_custody_event(
    descriptor: CustodyDescriptor,
    *,
    subject_algorithm: str,
    subject_digest: str,
    previous_event_hash: str,
    sequence: int,
) -> CustodyEvent:
    if subject_algorithm != "sha256" or not _SHA256_RE.fullmatch(subject_digest):
        raise CustodyValidationError("custody_subject_invalid", "custody subject must be a SHA-256 digest")
    body: dict[str, object] = {
        "actor": descriptor.actor,
        "attributes": descriptor.attributes,
        "event_type": descriptor.event_type,
        "location": descriptor.location,
        "occurred_at": descriptor.occurred_at,
        "previous_event_hash": previous_event_hash,
        "reference": descriptor.reference,
        "schema_version": CUSTODY_EVENT_SCHEMA_VERSION,
        "sequence": sequence,
        "subject": {"algorithm": subject_algorithm, "digest": subject_digest},
    }
    event_hash = custody_event_hash_for_body(body)
    event_id = "cue_" + event_hash[:32]
    return CustodyEvent(event_id=event_id, event_hash=event_hash, **body)  # type: ignore[arg-type]


def build_custody_chain(descriptors: list[CustodyDescriptor], *, subject_algorithm: str, subject_digest: str) -> dict[str, object]:
    if not descriptors:
        raise CustodyValidationError("custody_empty", "custody concept requires at least one event")
    if len(descriptors) > MAX_CUSTODY_EVENTS_PER_PACKET:
        raise CustodyValidationError("custody_collection_too_large", "custody event collection exceeds configured size")
    if len(descriptors) > 1 and any(item.occurred_at is None for item in descriptors):
        raise CustodyValidationError("custody_order_ambiguous", "multiple custody events require occurred_at values")
    ordered = sorted(descriptors, key=lambda item: (item.occurred_at or "", canonical_json_bytes(item.to_dict())))
    descriptor_digests = [hashlib.sha256(canonical_json_bytes(item.to_dict())).hexdigest() for item in ordered]
    if len(descriptor_digests) != len(set(descriptor_digests)):
        raise CustodyValidationError("custody_event_duplicate_body", "duplicate custody event descriptors are not allowed")
    previous = GENESIS_CUSTODY_HASH
    events: list[CustodyEvent] = []
    for sequence, descriptor in enumerate(ordered, start=1):
        event = build_custody_event(
            descriptor,
            subject_algorithm=subject_algorithm,
            subject_digest=subject_digest,
            previous_event_hash=previous,
            sequence=sequence,
        )
        events.append(event)
        previous = event.event_hash
    event_dicts = [event.to_dict() for event in events]
    event_ids = [event.event_id for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise CustodyValidationError("custody_event_duplicate_id", "duplicate custody event IDs are not allowed")
    event_hashes = [event.event_hash for event in events]
    if len(event_hashes) != len(set(event_hashes)):
        raise CustodyValidationError("custody_event_duplicate_hash", "duplicate custody event hashes are not allowed")
    return {
        "chain_head": events[-1].event_hash,
        "event_count": len(events),
        "events": event_dicts,
        "schema_version": CUSTODY_COLLECTION_SCHEMA_VERSION,
    }


def _failure(code: str, *, events: list[dict[str, object]] | None = None, chain_head: str | None = None) -> CustodyValidationResult:
    return CustodyValidationResult(
        status="fail",
        custody_schema_status="invalid",
        event_count=len(events or []),
        chain_head=chain_head,
        event_ids=[str(item.get("event_id")) for item in events or [] if isinstance(item.get("event_id"), str)],
        events=events or [],
        failures=[code],
        warnings=[],
        limitations=CUSTODY_LIMITATIONS,
    )


def _validate_event(value: object, *, subject_digest: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CustodyValidationError("custody_event_malformed", "custody event must be an object")
    if sorted(set(value) - _EVENT_FIELDS):
        raise CustodyValidationError("custody_event_malformed", "custody event contains unsupported fields")
    if sorted(_EVENT_FIELDS - set(value)):
        raise CustodyValidationError("custody_event_malformed", "custody event is missing required fields")
    if value.get("schema_version") != CUSTODY_EVENT_SCHEMA_VERSION:
        raise CustodyValidationError("custody_event_schema_unsupported", "custody event schema is unsupported")
    event_type = _validate_static_identifier(
        value.get("event_type"), field="event_type", limit=MAX_CUSTODY_EVENT_TYPE_LENGTH
    )
    if event_type not in SUPPORTED_CUSTODY_EVENT_TYPES:
        raise CustodyValidationError("custody_event_type_unsupported", "custody event type is unsupported")
    _validate_actor(value.get("actor"))
    _validate_occurred_at(value.get("occurred_at"))
    _validate_text(value.get("location"), code="custody_location_invalid", field="location", limit=MAX_CUSTODY_LOCATION_LENGTH)
    _validate_text(value.get("reference"), code="custody_reference_invalid", field="reference", limit=MAX_CUSTODY_REFERENCE_LENGTH)
    _validate_attributes(value.get("attributes"))
    sequence = value.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise CustodyValidationError("custody_sequence_invalid", "custody sequence is invalid")
    previous = value.get("previous_event_hash")
    if not isinstance(previous, str) or (previous != GENESIS_CUSTODY_HASH and not _SHA256_RE.fullmatch(previous)):
        raise CustodyValidationError("custody_previous_hash_invalid", "custody previous hash is invalid")
    event_hash = value.get("event_hash")
    if not isinstance(event_hash, str) or not _SHA256_RE.fullmatch(event_hash):
        raise CustodyValidationError("custody_event_hash_invalid", "custody event hash is invalid")
    event_id = value.get("event_id")
    if not isinstance(event_id, str) or not _EVENT_ID_RE.fullmatch(event_id):
        raise CustodyValidationError("custody_event_id_invalid", "custody event ID is invalid")
    subject = value.get("subject")
    if not isinstance(subject, dict) or subject.get("algorithm") != "sha256" or not isinstance(subject.get("digest"), str):
        raise CustodyValidationError("custody_subject_invalid", "custody subject is invalid")
    if subject["digest"] != subject_digest:
        raise CustodyValidationError("custody_subject_digest_mismatch", "custody subject digest does not match packet subject")
    body = _event_body(value)
    expected_hash = custody_event_hash_for_body(body)
    if event_hash != expected_hash:
        raise CustodyValidationError("custody_event_hash_mismatch", "custody event hash does not match canonical body")
    if event_id != "cue_" + expected_hash[:32]:
        raise CustodyValidationError("custody_event_id_mismatch", "custody event ID does not match canonical body")
    return dict(value)


def validate_manifest_custody(
    manifest: dict[str, object],
    *,
    expected_event_ids: list[str] | tuple[str, ...] | None = None,
    expected_chain_head: str | None = None,
) -> CustodyValidationResult:
    file_info = manifest.get("file")
    if not isinstance(file_info, dict) or not isinstance(file_info.get("sha256"), str):
        return _failure("custody_subject_invalid")
    subject_digest = str(file_info["sha256"])
    if not _SHA256_RE.fullmatch(subject_digest):
        return _failure("custody_subject_invalid")
    section = manifest.get("custody")
    if section is None:
        return _failure("custody_section_missing")
    if not isinstance(section, dict):
        return _failure("custody_events_invalid")
    if sorted(set(section) - _COLLECTION_FIELDS):
        return _failure("custody_events_invalid")
    if section.get("schema_version") != CUSTODY_COLLECTION_SCHEMA_VERSION:
        return _failure("custody_schema_unsupported")
    events_value = section.get("events")
    if not isinstance(events_value, list):
        return _failure("custody_events_invalid")
    if not events_value:
        return _failure("custody_empty")
    if len(events_value) > MAX_CUSTODY_EVENTS_PER_PACKET:
        return _failure("custody_collection_too_large")
    if section.get("event_count") != len(events_value):
        return _failure("custody_event_count_mismatch")
    chain_head = section.get("chain_head")
    if not isinstance(chain_head, str) or not _SHA256_RE.fullmatch(chain_head):
        return _failure("custody_chain_head_invalid")
    events: list[dict[str, object]] = []
    seen_sequences: set[int] = set()
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    expected_previous = GENESIS_CUSTODY_HASH
    for index, raw_event in enumerate(events_value, start=1):
        try:
            event = _validate_event(raw_event, subject_digest=subject_digest)
        except CustodyValidationError as exc:
            return _failure(exc.code, events=events, chain_head=chain_head)
        sequence = int(event["sequence"])
        if sequence in seen_sequences:
            return _failure("custody_sequence_duplicate", events=events, chain_head=chain_head)
        seen_sequences.add(sequence)
        if sequence != index:
            return _failure("custody_sequence_gap", events=events, chain_head=chain_head)
        if event["previous_event_hash"] != expected_previous:
            return _failure("custody_chain_link_mismatch", events=events, chain_head=chain_head)
        event_id = str(event["event_id"])
        event_hash = str(event["event_hash"])
        if event_id in seen_ids:
            return _failure("custody_event_duplicate_id", events=events, chain_head=chain_head)
        if event_hash in seen_hashes:
            return _failure("custody_event_duplicate_hash", events=events, chain_head=chain_head)
        seen_ids.add(event_id)
        seen_hashes.add(event_hash)
        events.append(event)
        expected_previous = event_hash
    if chain_head != expected_previous:
        return _failure("custody_chain_head_mismatch", events=events, chain_head=chain_head)
    if expected_event_ids is not None:
        expected = list(expected_event_ids)
        if not all(isinstance(item, str) and _EVENT_ID_RE.fullmatch(item) for item in expected):
            return _failure("custody_claim_event_ids_invalid", events=events, chain_head=chain_head)
        if len(expected) != len(set(expected)):
            return _failure("custody_claim_event_duplicate", events=events, chain_head=chain_head)
        actual_ids = [str(item["event_id"]) for item in events]
        if expected != actual_ids:
            if set(expected) == set(actual_ids):
                return _failure("custody_claim_event_order_mismatch", events=events, chain_head=chain_head)
            missing = set(expected) - set(actual_ids)
            if missing:
                return _failure("custody_claim_event_missing", events=events, chain_head=chain_head)
            return _failure("custody_claim_event_undeclared", events=events, chain_head=chain_head)
    if expected_chain_head is not None and expected_chain_head != chain_head:
        return _failure("custody_claim_head_mismatch", events=events, chain_head=chain_head)
    return CustodyValidationResult(
        status="pass",
        custody_schema_status="valid",
        event_count=len(events),
        chain_head=chain_head,
        event_ids=[str(item["event_id"]) for item in events],
        events=events,
        failures=[],
        warnings=[
            "Declared custody actors, locations, references, and event times are not independently verified."
        ],
        limitations=CUSTODY_LIMITATIONS,
    )
