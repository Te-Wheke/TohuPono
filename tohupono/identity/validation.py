from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path
from typing import Any

from tohupono.core.canonical_json import canonical_json_bytes
from tohupono.identity.model import IdentityAssertion, IdentityDescriptor, IdentityValidationResult
from tohupono.records.validation import _strict_json_loads, _validate_attribute_value
from tohupono.security.limits import (
    MAX_IDENTITY_ASSERTIONS_PER_PACKET,
    MAX_IDENTITY_ATTRIBUTE_ITEMS,
    MAX_IDENTITY_DESCRIPTOR_BYTES,
    MAX_IDENTITY_DISPLAY_NAME_LENGTH,
    MAX_IDENTITY_IDENTIFIER_LENGTH,
    MAX_IDENTITY_NAMESPACE_LENGTH,
    MAX_IDENTITY_REFERENCE_LENGTH,
)
from tohupono.security.paths import PathSecurityError, ensure_sensitive_path_safe, validate_terminal_text

IDENTITY_DESCRIPTOR_SCHEMA_VERSION = "tohupono.identity_descriptor.v1"
IDENTITY_ASSERTION_SCHEMA_VERSION = "tohupono.identity_assertion.v1"
IDENTITY_COLLECTION_SCHEMA_VERSION = "tohupono.identities.v1"
SUPPORTED_ASSERTION_TYPES = ("associated_with",)
IDENTITY_LIMITATIONS = [
    "Identifiers are declared metadata and are not externally verified.",
    "Identity existence, personhood, organisational status, account ownership, key ownership, and key control are not proven.",
    "Authorship, authority, ownership, consent, authenticity, legal identity, and external validation are not established.",
]
_NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9._-]{0,31}$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+ -]{0,199}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ASSERTION_ID_RE = re.compile(r"^idn_[0-9a-f]{32}$")
_DESCRIPTOR_FIELDS = {"schema_version", "assertion_type", "identity", "key_fingerprint", "reference", "attributes"}
_ASSERTION_FIELDS = {"assertion_id", "schema_version", "assertion_type", "subject", "identity", "key_fingerprint", "reference", "attributes"}
_FORBIDDEN_DESCRIPTOR_FIELDS = {"assertion_id", "subject", "proof_id", "claim_id", "verified", "verification_status"}


class IdentityValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _validate_descriptor_path(path: Path) -> None:
    try:
        ensure_sensitive_path_safe(path, private=False)
    except PathSecurityError as exc:
        raise IdentityValidationError("identity_descriptor_path_invalid", "identity descriptor path is unsafe") from exc
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError(str(path)) from exc
    if stat.S_ISLNK(st.st_mode):
        raise IdentityValidationError("identity_descriptor_symlink", "identity descriptor must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise IdentityValidationError("identity_descriptor_not_file", "identity descriptor must be a regular file")
    if st.st_size > MAX_IDENTITY_DESCRIPTOR_BYTES:
        raise IdentityValidationError("identity_descriptor_too_large", "identity descriptor exceeds configured size")


def _validate_namespace(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise IdentityValidationError("identity_namespace_invalid", "identity namespace must be a non-empty string")
    if len(value) > MAX_IDENTITY_NAMESPACE_LENGTH:
        raise IdentityValidationError("identity_namespace_invalid", "identity namespace exceeds configured length")
    try:
        validate_terminal_text(value, field="identity namespace")
    except PathSecurityError as exc:
        raise IdentityValidationError("identity_namespace_invalid", str(exc)) from exc
    if not _NAMESPACE_RE.fullmatch(value):
        raise IdentityValidationError("identity_namespace_invalid", "identity namespace must be a lowercase static token")
    return value


def _validate_identifier(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise IdentityValidationError("identity_identifier_invalid", "identity identifier must be a non-empty string")
    if len(value) > MAX_IDENTITY_IDENTIFIER_LENGTH:
        raise IdentityValidationError("identity_identifier_invalid", "identity identifier exceeds configured length")
    try:
        validate_terminal_text(value, field="identity identifier")
    except PathSecurityError as exc:
        raise IdentityValidationError("identity_identifier_invalid", str(exc)) from exc
    if not _SAFE_IDENTIFIER_RE.fullmatch(value):
        raise IdentityValidationError("identity_identifier_invalid", "identity identifier contains unsupported characters")
    return value


def _validate_text(value: object, *, code: str, field: str, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise IdentityValidationError(code, f"identity {field} must be null or a string")
    if len(value) > limit:
        raise IdentityValidationError(code, f"identity {field} exceeds configured length")
    try:
        validate_terminal_text(value, field=field)
    except PathSecurityError as exc:
        raise IdentityValidationError(code, str(exc)) from exc
    return value


def _validate_fingerprint(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"algorithm", "digest"}:
        raise IdentityValidationError("identity_fingerprint_invalid", "identity key_fingerprint must contain algorithm and digest")
    if value.get("algorithm") != "sha256":
        raise IdentityValidationError("identity_fingerprint_invalid", "identity key_fingerprint algorithm must be sha256")
    digest = value.get("digest")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise IdentityValidationError("identity_fingerprint_invalid", "identity key_fingerprint digest must be a lowercase SHA-256 digest")
    return {"algorithm": "sha256", "digest": digest}


def _validate_identity_object(value: object, *, require_display_name: bool = False) -> dict[str, str | None]:
    if not isinstance(value, dict):
        raise IdentityValidationError("identity_object_invalid", "identity must be an object")
    allowed = {"namespace", "identifier", "display_name"}
    if sorted(set(value) - allowed):
        raise IdentityValidationError("identity_object_invalid", "identity contains unsupported fields")
    if sorted({"namespace", "identifier"} - set(value)):
        raise IdentityValidationError("identity_object_invalid", "identity is missing required fields")
    if require_display_name and set(value) != allowed:
        raise IdentityValidationError("identity_assertion_malformed", "identity assertion identity object is not canonical")
    return {
        "display_name": _validate_text(value.get("display_name"), code="identity_display_name_invalid", field="display_name", limit=MAX_IDENTITY_DISPLAY_NAME_LENGTH),
        "identifier": _validate_identifier(value.get("identifier")),
        "namespace": _validate_namespace(value.get("namespace")),
    }


def _validate_subject(value: object, *, code: str = "identity_subject_invalid") -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"algorithm", "digest"}:
        raise IdentityValidationError(code, "identity subject must contain algorithm and digest")
    if value.get("algorithm") != "sha256":
        raise IdentityValidationError(code, "identity subject algorithm must be sha256")
    digest = value.get("digest")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        raise IdentityValidationError(code, "identity subject digest must be a lowercase SHA-256 digest")
    return {"algorithm": "sha256", "digest": digest}


def _validate_attributes(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IdentityValidationError("identity_attributes_invalid", "identity attributes must be an object")
    try:
        attributes = _validate_attribute_value(value)
    except ValueError as exc:
        raise IdentityValidationError("identity_attributes_invalid", str(exc)) from exc
    if not isinstance(attributes, dict):
        raise IdentityValidationError("identity_attributes_invalid", "identity attributes must be an object")
    if len(attributes) > MAX_IDENTITY_ATTRIBUTE_ITEMS:
        raise IdentityValidationError("identity_attributes_invalid", "identity attributes exceed configured item limit")
    return attributes


def load_identity_descriptor(path: Path) -> IdentityDescriptor:
    _validate_descriptor_path(path)
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise IdentityValidationError("identity_descriptor_changed", "identity descriptor changed during read")
    if len(data) > MAX_IDENTITY_DESCRIPTOR_BYTES:
        raise IdentityValidationError("identity_descriptor_too_large", "identity descriptor exceeds configured size")
    try:
        value = _strict_json_loads(data)
    except ValueError as exc:
        code = getattr(exc, "code", "identity_json_invalid")
        raise IdentityValidationError(str(code).replace("record_", "identity_"), str(exc)) from exc
    if not isinstance(value, dict):
        raise IdentityValidationError("identity_descriptor_invalid", "identity descriptor must be an object")
    if _FORBIDDEN_DESCRIPTOR_FIELDS & set(value):
        raise IdentityValidationError("identity_descriptor_invalid", "identity descriptor contains derived or verification fields")
    if sorted(set(value) - _DESCRIPTOR_FIELDS):
        raise IdentityValidationError("identity_descriptor_invalid", "identity descriptor contains unsupported fields")
    missing = sorted({"schema_version", "assertion_type", "identity", "attributes"} - set(value))
    if missing:
        raise IdentityValidationError("identity_descriptor_invalid", "identity descriptor is missing required fields")
    if value.get("schema_version") != IDENTITY_DESCRIPTOR_SCHEMA_VERSION:
        raise IdentityValidationError("identity_descriptor_schema_unsupported", "identity descriptor schema is unsupported")
    assertion_type = value.get("assertion_type")
    if assertion_type not in SUPPORTED_ASSERTION_TYPES:
        raise IdentityValidationError("identity_assertion_type_unsupported", "identity assertion type is unsupported")
    return IdentityDescriptor(
        schema_version=IDENTITY_DESCRIPTOR_SCHEMA_VERSION,
        assertion_type=str(assertion_type),
        identity=_validate_identity_object(value.get("identity")),
        key_fingerprint=_validate_fingerprint(value.get("key_fingerprint")),
        reference=_validate_text(value.get("reference"), code="identity_reference_invalid", field="reference", limit=MAX_IDENTITY_REFERENCE_LENGTH),
        attributes=_validate_attributes(value.get("attributes")),
    )


def _assertion_body(assertion: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in assertion.items() if key != "assertion_id"}


def identity_assertion_id_for_body(body: dict[str, object]) -> str:
    return "idn_" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()[:32]


def build_identity_assertion(
    descriptor: IdentityDescriptor,
    *,
    subject_algorithm: str,
    subject_digest: str,
) -> IdentityAssertion:
    if subject_algorithm != "sha256" or not _SHA256_RE.fullmatch(subject_digest):
        raise IdentityValidationError("identity_subject_invalid", "identity subject must be a SHA-256 digest")
    body: dict[str, object] = {
        "assertion_type": descriptor.assertion_type,
        "attributes": descriptor.attributes,
        "identity": descriptor.identity,
        "key_fingerprint": descriptor.key_fingerprint,
        "reference": descriptor.reference,
        "schema_version": IDENTITY_ASSERTION_SCHEMA_VERSION,
        "subject": {"algorithm": subject_algorithm, "digest": subject_digest},
    }
    assertion_id = identity_assertion_id_for_body(body)
    return IdentityAssertion(assertion_id=assertion_id, **body)  # type: ignore[arg-type]


def build_identity_collection(assertions: list[IdentityAssertion]) -> dict[str, object]:
    if not assertions:
        raise IdentityValidationError("identity_empty", "identity concept requires at least one assertion")
    if len(assertions) > MAX_IDENTITY_ASSERTIONS_PER_PACKET:
        raise IdentityValidationError("identity_collection_too_large", "identity collection exceeds configured size")
    items = sorted((assertion.to_dict() for assertion in assertions), key=lambda item: str(item["assertion_id"]))
    ids = [str(item["assertion_id"]) for item in items]
    if len(ids) != len(set(ids)):
        raise IdentityValidationError("identity_duplicate_id", "duplicate identity assertion IDs are not allowed")
    bodies = [hashlib.sha256(canonical_json_bytes(_assertion_body(item))).hexdigest() for item in items]
    if len(bodies) != len(set(bodies)):
        raise IdentityValidationError("identity_duplicate_body", "duplicate identity assertion bodies are not allowed")
    return {"assertion_count": len(items), "items": items, "schema_version": IDENTITY_COLLECTION_SCHEMA_VERSION}


def identity_assertion_ids_from_collection(collection: dict[str, object] | None) -> list[str]:
    if not isinstance(collection, dict):
        return []
    items = collection.get("items")
    if not isinstance(items, list):
        return []
    return sorted(str(item.get("assertion_id")) for item in items if isinstance(item, dict) and isinstance(item.get("assertion_id"), str))


def _failure(code: str, *, assertions: list[dict[str, object]] | None = None) -> IdentityValidationResult:
    return IdentityValidationResult(
        status="fail",
        identity_schema_status="invalid",
        assertion_count=len(assertions or []),
        assertion_ids=[str(item.get("assertion_id")) for item in assertions or [] if isinstance(item.get("assertion_id"), str)],
        assertions=assertions or [],
        failures=[code],
        warnings=[],
        limitations=IDENTITY_LIMITATIONS,
    )


def _validate_assertion(value: object, *, subject_digest: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise IdentityValidationError("identity_assertion_malformed", "identity assertion must be an object")
    if sorted(set(value) - _ASSERTION_FIELDS):
        raise IdentityValidationError("identity_assertion_malformed", "identity assertion contains unsupported fields")
    if sorted(_ASSERTION_FIELDS - set(value)):
        raise IdentityValidationError("identity_assertion_malformed", "identity assertion is missing required fields")
    if value.get("schema_version") != IDENTITY_ASSERTION_SCHEMA_VERSION:
        raise IdentityValidationError("identity_assertion_schema_unsupported", "identity assertion schema is unsupported")
    assertion_id = value.get("assertion_id")
    if not isinstance(assertion_id, str) or not _ASSERTION_ID_RE.fullmatch(assertion_id):
        raise IdentityValidationError("identity_assertion_id_invalid", "identity assertion ID is invalid")
    if value.get("assertion_type") not in SUPPORTED_ASSERTION_TYPES:
        raise IdentityValidationError("identity_assertion_type_unsupported", "identity assertion type is unsupported")
    subject = _validate_subject(value.get("subject"))
    if subject["digest"] != subject_digest:
        raise IdentityValidationError("identity_subject_digest_mismatch", "identity subject digest does not match packet subject")
    _validate_identity_object(value.get("identity"), require_display_name=True)
    _validate_fingerprint(value.get("key_fingerprint"))
    _validate_text(value.get("reference"), code="identity_reference_invalid", field="reference", limit=MAX_IDENTITY_REFERENCE_LENGTH)
    _validate_attributes(value.get("attributes"))
    expected_id = identity_assertion_id_for_body(_assertion_body(value))
    if assertion_id != expected_id:
        raise IdentityValidationError("identity_assertion_id_mismatch", "identity assertion ID does not match canonical body")
    return dict(value)


def validate_manifest_identities(
    manifest: dict[str, object],
    *,
    expected_assertion_ids: list[str] | tuple[str, ...] | None = None,
    expected_subject: dict[str, object] | None = None,
) -> IdentityValidationResult:
    file_info = manifest.get("file")
    if not isinstance(file_info, dict) or not isinstance(file_info.get("sha256"), str):
        return _failure("identity_subject_invalid")
    subject_digest = str(file_info["sha256"])
    if not _SHA256_RE.fullmatch(subject_digest):
        return _failure("identity_subject_invalid")
    if expected_subject is not None:
        if not isinstance(expected_subject, dict) or expected_subject.get("algorithm") != "sha256" or expected_subject.get("digest") != subject_digest:
            return _failure("identity_claim_subject_mismatch")
    section = manifest.get("identities")
    if section is None:
        return _failure("identity_section_missing")
    if not isinstance(section, dict):
        return _failure("identity_items_invalid")
    if section.get("schema_version") != IDENTITY_COLLECTION_SCHEMA_VERSION:
        return _failure("identity_schema_unsupported")
    items_value = section.get("items")
    if not isinstance(items_value, list):
        return _failure("identity_items_invalid")
    if not items_value:
        return _failure("identity_empty")
    if len(items_value) > MAX_IDENTITY_ASSERTIONS_PER_PACKET:
        return _failure("identity_collection_too_large")
    if section.get("assertion_count") != len(items_value):
        return _failure("identity_count_mismatch")
    assertions: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_bodies: set[str] = set()
    for raw_item in items_value:
        try:
            item = _validate_assertion(raw_item, subject_digest=subject_digest)
        except IdentityValidationError as exc:
            return _failure(exc.code, assertions=assertions)
        assertion_id = str(item["assertion_id"])
        if assertion_id in seen_ids:
            return _failure("identity_duplicate_id", assertions=assertions)
        body_hash = hashlib.sha256(canonical_json_bytes(_assertion_body(item))).hexdigest()
        if body_hash in seen_bodies:
            return _failure("identity_duplicate_body", assertions=assertions)
        seen_ids.add(assertion_id)
        seen_bodies.add(body_hash)
        assertions.append(item)
    if list(items_value) != sorted(items_value, key=lambda item: str(item.get("assertion_id")) if isinstance(item, dict) else ""):
        return _failure("identity_items_invalid", assertions=assertions)
    assertion_ids = sorted(seen_ids)
    if expected_assertion_ids is not None:
        expected = list(expected_assertion_ids)
        if not all(isinstance(item, str) and _ASSERTION_ID_RE.fullmatch(item) for item in expected):
            return _failure("identity_claim_ids_invalid", assertions=assertions)
        if len(expected) != len(set(expected)):
            return _failure("identity_claim_id_duplicate", assertions=assertions)
        if expected != assertion_ids:
            if set(expected) == set(assertion_ids):
                return _failure("identity_claim_order_mismatch", assertions=assertions)
            missing = sorted(set(expected) - set(assertion_ids))
            if missing:
                return _failure("identity_claim_id_missing", assertions=assertions)
            return _failure("identity_claim_id_undeclared", assertions=assertions)
    return IdentityValidationResult(
        status="pass",
        identity_schema_status="valid",
        assertion_count=len(assertions),
        assertion_ids=assertion_ids,
        assertions=assertions,
        failures=[],
        warnings=["Declared identifiers, fingerprints, references, and attributes are not independently verified."],
        limitations=IDENTITY_LIMITATIONS,
    )
