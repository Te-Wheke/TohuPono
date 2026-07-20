from __future__ import annotations

import hashlib
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from tohupono.core.canonical_json import canonical_json_bytes
from tohupono.records.validation import _strict_json_loads, _validate_attribute_value
from tohupono.security.limits import (
    MAX_TRANSACTION_ATTRIBUTES_ITEMS,
    MAX_TRANSACTION_DESCRIPTOR_BYTES,
    MAX_TRANSACTION_IDENTIFIER_LENGTH,
    MAX_TRANSACTION_NAMESPACE_LENGTH,
    MAX_TRANSACTION_PARTICIPANTS,
    MAX_TRANSACTION_REFERENCE_LENGTH,
    MAX_TRANSACTION_ROLE_LENGTH,
    MAX_TRANSACTION_TERMS_ITEMS,
    MAX_TRANSACTION_TYPE_LENGTH,
    MAX_TRANSACTIONS_PER_PACKET,
)
from tohupono.security.paths import PathSecurityError, ensure_sensitive_path_safe, validate_terminal_text
from tohupono.transaction.model import TransactionDescriptor, TransactionEnvelope, TransactionValidationResult

TRANSACTION_DESCRIPTOR_SCHEMA_VERSION = "tohupono.transaction_descriptor.v1"
TRANSACTION_ENVELOPE_SCHEMA_VERSION = "tohupono.transaction.v1"
TRANSACTION_COLLECTION_SCHEMA_VERSION = "tohupono.transactions.v1"
SUPPORTED_TRANSACTION_TYPES = ("assignment", "exchange", "gift", "license", "receipt", "sale", "transfer")
SUPPORTED_TRANSACTION_ROLES = (
    "assignee",
    "assignor",
    "buyer",
    "customer",
    "giver",
    "licensee",
    "licensor",
    "other",
    "provider",
    "receiver",
    "recipient",
    "seller",
    "sender",
    "witness",
)
ONE_PARTICIPANT_TRANSACTION_TYPES = ("receipt",)
TRANSACTION_LIMITATIONS = [
    "Participants are declared metadata and are not independently identity-verified.",
    "Transaction occurrence, payment, delivery, consent, authority, ownership transfer, and legal effect are not proven.",
    "Declared occurred_at values are metadata and are not external timestamp evidence.",
]
_STATIC_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,99}$")
_RFC3339_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TRANSACTION_ID_RE = re.compile(r"^txn_[0-9a-f]{32}$")
_DESCRIPTOR_FIELDS = {"schema_version", "transaction_type", "participants", "occurred_at", "reference", "terms", "attributes"}
_ENVELOPE_FIELDS = {"transaction_id", "schema_version", "transaction_type", "subject", "participants", "occurred_at", "reference", "terms", "attributes"}
_COLLECTION_FIELDS = {"items", "schema_version", "transaction_count"}


class TransactionValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _validate_descriptor_path(path: Path) -> None:
    try:
        ensure_sensitive_path_safe(path, private=False)
    except PathSecurityError as exc:
        raise TransactionValidationError("transaction_descriptor_path_invalid", "transaction descriptor path is unsafe") from exc
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(str(path)) from exc
    if stat.S_ISLNK(st.st_mode):
        raise TransactionValidationError("transaction_descriptor_symlink", "transaction descriptor must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise TransactionValidationError("transaction_descriptor_not_file", "transaction descriptor must be a regular file")
    if st.st_size > MAX_TRANSACTION_DESCRIPTOR_BYTES:
        raise TransactionValidationError("transaction_descriptor_too_large", "transaction descriptor exceeds configured size")


def _validate_static_identifier(value: object, *, code: str, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value:
        raise TransactionValidationError(code, f"transaction {field} must be a non-empty string")
    if len(value) > limit:
        raise TransactionValidationError(code, f"transaction {field} exceeds configured length")
    try:
        validate_terminal_text(value, field=field)
    except PathSecurityError as exc:
        raise TransactionValidationError(code, str(exc)) from exc
    if not _STATIC_ID_RE.fullmatch(value):
        raise TransactionValidationError(code, f"transaction {field} must be a static identifier")
    return value


def _validate_text(value: object, *, code: str, field: str, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TransactionValidationError(code, f"transaction {field} must be null or a string")
    if len(value) > limit:
        raise TransactionValidationError(code, f"transaction {field} exceeds configured length")
    try:
        validate_terminal_text(value, field=field)
    except PathSecurityError as exc:
        raise TransactionValidationError(code, str(exc)) from exc
    return value


def _validate_occurred_at(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _RFC3339_UTC_RE.fullmatch(value):
        raise TransactionValidationError("transaction_occurred_at_invalid", "transaction occurred_at must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise TransactionValidationError("transaction_occurred_at_invalid", "transaction occurred_at must be a valid UTC timestamp") from exc
    return value


def _validate_subject(value: object, *, code: str = "transaction_subject_invalid") -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"algorithm", "digest"}:
        raise TransactionValidationError(code, "transaction subject must contain algorithm and digest")
    if value.get("algorithm") != "sha256":
        raise TransactionValidationError(code, "transaction subject algorithm must be sha256")
    digest = value.get("digest")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise TransactionValidationError(code, "transaction subject digest must be a lowercase SHA-256 digest")
    return {"algorithm": "sha256", "digest": digest}


def _validate_participant(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"role", "namespace", "identifier"}:
        raise TransactionValidationError("transaction_participants_invalid", "transaction participant fields are invalid")
    role = _validate_static_identifier(value.get("role"), code="transaction_participants_invalid", field="participant role", limit=MAX_TRANSACTION_ROLE_LENGTH)
    if role not in SUPPORTED_TRANSACTION_ROLES:
        raise TransactionValidationError("transaction_participants_invalid", "transaction participant role is unsupported")
    return {
        "identifier": _validate_static_identifier(value.get("identifier"), code="transaction_participants_invalid", field="participant identifier", limit=MAX_TRANSACTION_IDENTIFIER_LENGTH),
        "namespace": _validate_static_identifier(value.get("namespace"), code="transaction_participants_invalid", field="participant namespace", limit=MAX_TRANSACTION_NAMESPACE_LENGTH),
        "role": role,
    }


def _validate_participants(value: object, *, transaction_type: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise TransactionValidationError("transaction_participants_invalid", "transaction participants must be a list")
    if not value:
        raise TransactionValidationError("transaction_participants_invalid", "transaction participants must not be empty")
    if len(value) > MAX_TRANSACTION_PARTICIPANTS:
        raise TransactionValidationError("transaction_participants_invalid", "transaction participant count exceeds configured limit")
    participants = sorted((_validate_participant(item) for item in value), key=lambda item: (item["role"], item["namespace"], item["identifier"]))
    keys = [(item["role"], item["namespace"], item["identifier"]) for item in participants]
    if len(keys) != len(set(keys)):
        raise TransactionValidationError("transaction_participant_duplicate", "duplicate transaction participants are not allowed")
    if transaction_type not in ONE_PARTICIPANT_TRANSACTION_TYPES and len(participants) < 2:
        raise TransactionValidationError("transaction_participants_invalid", "transaction type requires at least two participants")
    return participants


def _validate_object_value(value: object, *, code: str, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TransactionValidationError(code, f"transaction {field} must be an object")
    try:
        validated = _validate_attribute_value(value)
    except ValueError as exc:
        raise TransactionValidationError(code, str(exc)) from exc
    if not isinstance(validated, dict):
        raise TransactionValidationError(code, f"transaction {field} must be an object")
    return validated


def _validate_terms(value: object) -> dict[str, Any]:
    terms = _validate_object_value(value, code="transaction_terms_invalid", field="terms")
    if len(terms) > MAX_TRANSACTION_TERMS_ITEMS:
        raise TransactionValidationError("transaction_terms_invalid", "transaction terms exceed configured item limit")
    return terms


def _validate_attributes(value: object) -> dict[str, Any]:
    attributes = _validate_object_value(value, code="transaction_attributes_invalid", field="attributes")
    if len(attributes) > MAX_TRANSACTION_ATTRIBUTES_ITEMS:
        raise TransactionValidationError("transaction_attributes_invalid", "transaction attributes exceed configured item limit")
    return attributes


def load_transaction_descriptor(path: Path) -> TransactionDescriptor:
    _validate_descriptor_path(path)
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise TransactionValidationError("transaction_descriptor_changed", "transaction descriptor changed during read")
    if len(data) > MAX_TRANSACTION_DESCRIPTOR_BYTES:
        raise TransactionValidationError("transaction_descriptor_too_large", "transaction descriptor exceeds configured size")
    try:
        value = _strict_json_loads(data)
    except ValueError as exc:
        code = getattr(exc, "code", "transaction_json_invalid")
        raise TransactionValidationError(str(code).replace("record_", "transaction_"), str(exc)) from exc
    if not isinstance(value, dict):
        raise TransactionValidationError("transaction_descriptor_invalid", "transaction descriptor must be an object")
    if sorted(set(value) - _DESCRIPTOR_FIELDS):
        raise TransactionValidationError("transaction_descriptor_invalid", "transaction descriptor contains unsupported fields")
    missing = sorted({"schema_version", "transaction_type", "participants", "terms", "attributes"} - set(value))
    if missing:
        raise TransactionValidationError("transaction_descriptor_invalid", "transaction descriptor is missing required fields")
    if value.get("schema_version") != TRANSACTION_DESCRIPTOR_SCHEMA_VERSION:
        raise TransactionValidationError("transaction_descriptor_schema_unsupported", "transaction descriptor schema is unsupported")
    transaction_type = _validate_static_identifier(value.get("transaction_type"), code="transaction_type_unsupported", field="transaction_type", limit=MAX_TRANSACTION_TYPE_LENGTH)
    if transaction_type not in SUPPORTED_TRANSACTION_TYPES:
        raise TransactionValidationError("transaction_type_unsupported", "transaction type is unsupported")
    return TransactionDescriptor(
        schema_version=TRANSACTION_DESCRIPTOR_SCHEMA_VERSION,
        transaction_type=transaction_type,
        participants=_validate_participants(value.get("participants"), transaction_type=transaction_type),
        occurred_at=_validate_occurred_at(value.get("occurred_at")),
        reference=_validate_text(value.get("reference"), code="transaction_reference_invalid", field="reference", limit=MAX_TRANSACTION_REFERENCE_LENGTH),
        terms=_validate_terms(value.get("terms")),
        attributes=_validate_attributes(value.get("attributes")),
    )


def _transaction_body(transaction: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in transaction.items() if key != "transaction_id"}


def transaction_id_for_body(body: dict[str, object]) -> str:
    return "txn_" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()[:32]


def build_transaction_envelope(
    descriptor: TransactionDescriptor,
    *,
    subject_algorithm: str,
    subject_digest: str,
) -> TransactionEnvelope:
    if subject_algorithm != "sha256" or not _SHA256_RE.fullmatch(subject_digest):
        raise TransactionValidationError("transaction_subject_invalid", "transaction subject must be a SHA-256 digest")
    body: dict[str, object] = {
        "attributes": descriptor.attributes,
        "occurred_at": descriptor.occurred_at,
        "participants": descriptor.participants,
        "reference": descriptor.reference,
        "schema_version": TRANSACTION_ENVELOPE_SCHEMA_VERSION,
        "subject": {"algorithm": subject_algorithm, "digest": subject_digest},
        "terms": descriptor.terms,
        "transaction_type": descriptor.transaction_type,
    }
    transaction_id = transaction_id_for_body(body)
    return TransactionEnvelope(transaction_id=transaction_id, **body)  # type: ignore[arg-type]


def build_transaction_collection(transactions: list[TransactionEnvelope]) -> dict[str, object]:
    if not transactions:
        raise TransactionValidationError("transaction_empty", "transaction concept requires at least one transaction")
    if len(transactions) > MAX_TRANSACTIONS_PER_PACKET:
        raise TransactionValidationError("transaction_collection_too_large", "transaction collection exceeds configured size")
    items = sorted((transaction.to_dict() for transaction in transactions), key=lambda item: str(item["transaction_id"]))
    ids = [str(item["transaction_id"]) for item in items]
    if len(ids) != len(set(ids)):
        raise TransactionValidationError("transaction_duplicate_id", "duplicate transaction IDs are not allowed")
    bodies = [hashlib.sha256(canonical_json_bytes(_transaction_body(item))).hexdigest() for item in items]
    if len(bodies) != len(set(bodies)):
        raise TransactionValidationError("transaction_duplicate_body", "duplicate transaction bodies are not allowed")
    return {"items": items, "schema_version": TRANSACTION_COLLECTION_SCHEMA_VERSION, "transaction_count": len(items)}


def transaction_ids_from_collection(collection: dict[str, object] | None) -> list[str]:
    if not isinstance(collection, dict):
        return []
    items = collection.get("items")
    if not isinstance(items, list):
        return []
    return sorted(str(item.get("transaction_id")) for item in items if isinstance(item, dict) and isinstance(item.get("transaction_id"), str))


def _failure(code: str, *, transactions: list[dict[str, object]] | None = None) -> TransactionValidationResult:
    return TransactionValidationResult(
        status="fail",
        transaction_schema_status="invalid",
        transaction_count=len(transactions or []),
        transaction_ids=[str(item.get("transaction_id")) for item in transactions or [] if isinstance(item.get("transaction_id"), str)],
        transactions=transactions or [],
        failures=[code],
        warnings=[],
        limitations=TRANSACTION_LIMITATIONS,
    )


def _validate_transaction(value: object, *, subject_digest: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TransactionValidationError("transaction_item_malformed", "transaction item must be an object")
    if sorted(set(value) - _ENVELOPE_FIELDS):
        raise TransactionValidationError("transaction_item_malformed", "transaction item contains unsupported fields")
    if sorted(_ENVELOPE_FIELDS - set(value)):
        raise TransactionValidationError("transaction_item_malformed", "transaction item is missing required fields")
    if value.get("schema_version") != TRANSACTION_ENVELOPE_SCHEMA_VERSION:
        raise TransactionValidationError("transaction_item_schema_unsupported", "transaction item schema is unsupported")
    transaction_id = value.get("transaction_id")
    if not isinstance(transaction_id, str) or not _TRANSACTION_ID_RE.fullmatch(transaction_id):
        raise TransactionValidationError("transaction_id_invalid", "transaction ID is invalid")
    transaction_type = _validate_static_identifier(value.get("transaction_type"), code="transaction_type_unsupported", field="transaction_type", limit=MAX_TRANSACTION_TYPE_LENGTH)
    if transaction_type not in SUPPORTED_TRANSACTION_TYPES:
        raise TransactionValidationError("transaction_type_unsupported", "transaction type is unsupported")
    subject = _validate_subject(value.get("subject"))
    if subject["digest"] != subject_digest:
        raise TransactionValidationError("transaction_subject_digest_mismatch", "transaction subject digest does not match packet subject")
    _validate_participants(value.get("participants"), transaction_type=transaction_type)
    _validate_occurred_at(value.get("occurred_at"))
    _validate_text(value.get("reference"), code="transaction_reference_invalid", field="reference", limit=MAX_TRANSACTION_REFERENCE_LENGTH)
    _validate_terms(value.get("terms"))
    _validate_attributes(value.get("attributes"))
    expected_id = transaction_id_for_body(_transaction_body(value))
    if transaction_id != expected_id:
        raise TransactionValidationError("transaction_id_mismatch", "transaction ID does not match canonical body")
    return dict(value)


def validate_manifest_transactions(
    manifest: dict[str, object],
    *,
    expected_transaction_ids: list[str] | tuple[str, ...] | None = None,
    expected_subject: dict[str, object] | None = None,
) -> TransactionValidationResult:
    file_info = manifest.get("file")
    if not isinstance(file_info, dict) or not isinstance(file_info.get("sha256"), str):
        return _failure("transaction_subject_invalid")
    subject_digest = str(file_info["sha256"])
    if not _SHA256_RE.fullmatch(subject_digest):
        return _failure("transaction_subject_invalid")
    if expected_subject is not None:
        if not isinstance(expected_subject, dict) or expected_subject.get("algorithm") != "sha256" or expected_subject.get("digest") != subject_digest:
            return _failure("transaction_claim_subject_mismatch")
    section = manifest.get("transactions")
    if section is None:
        return _failure("transaction_section_missing")
    if not isinstance(section, dict):
        return _failure("transaction_items_invalid")
    if sorted(set(section) - _COLLECTION_FIELDS):
        return _failure("transaction_items_invalid")
    if section.get("schema_version") != TRANSACTION_COLLECTION_SCHEMA_VERSION:
        return _failure("transaction_schema_unsupported")
    items_value = section.get("items")
    if not isinstance(items_value, list):
        return _failure("transaction_items_invalid")
    if not items_value:
        return _failure("transaction_empty")
    if len(items_value) > MAX_TRANSACTIONS_PER_PACKET:
        return _failure("transaction_collection_too_large")
    if section.get("transaction_count") != len(items_value):
        return _failure("transaction_count_mismatch")
    transactions: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_bodies: set[str] = set()
    for raw_item in items_value:
        try:
            item = _validate_transaction(raw_item, subject_digest=subject_digest)
        except TransactionValidationError as exc:
            return _failure(exc.code, transactions=transactions)
        transaction_id = str(item["transaction_id"])
        if transaction_id in seen_ids:
            return _failure("transaction_duplicate_id", transactions=transactions)
        body_hash = hashlib.sha256(canonical_json_bytes(_transaction_body(item))).hexdigest()
        if body_hash in seen_bodies:
            return _failure("transaction_duplicate_body", transactions=transactions)
        seen_ids.add(transaction_id)
        seen_bodies.add(body_hash)
        transactions.append(item)
    if list(items_value) != sorted(items_value, key=lambda item: str(item.get("transaction_id")) if isinstance(item, dict) else ""):
        return _failure("transaction_items_invalid", transactions=transactions)
    transaction_ids = sorted(seen_ids)
    if expected_transaction_ids is not None:
        expected = list(expected_transaction_ids)
        if not all(isinstance(item, str) and _TRANSACTION_ID_RE.fullmatch(item) for item in expected):
            return _failure("transaction_claim_ids_invalid", transactions=transactions)
        if len(expected) != len(set(expected)):
            return _failure("transaction_claim_id_duplicate", transactions=transactions)
        if expected != transaction_ids:
            missing = sorted(set(expected) - set(transaction_ids))
            if missing:
                return _failure("transaction_claim_id_missing", transactions=transactions)
            return _failure("transaction_claim_id_undeclared", transactions=transactions)
    return TransactionValidationResult(
        status="pass",
        transaction_schema_status="valid",
        transaction_count=len(transactions),
        transaction_ids=transaction_ids,
        transactions=transactions,
        failures=[],
        warnings=["Declared transaction participants, references, terms, attributes, and times are not independently verified."],
        limitations=TRANSACTION_LIMITATIONS,
    )
