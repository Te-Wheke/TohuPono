from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from tohupono.concepts.registry import concept_registry, get_concept
from tohupono.core.canonical_json import canonical_json_bytes
from tohupono.core.file_identity import inspect_file
from tohupono.custody.validation import (
    CUSTODY_COLLECTION_SCHEMA_VERSION,
    validate_manifest_custody,
)
from tohupono.provenance.validation import (
    PROVENANCE_COLLECTION_SCHEMA_VERSION,
    provenance_edge_ids_from_collection,
    validate_manifest_provenance,
)
from tohupono.records.validation import (
    RECORDS_COLLECTION_SCHEMA_VERSION,
    validate_manifest_records,
)
from tohupono.security.limits import MAX_LABEL_LENGTH
from tohupono.timestamping.model import DEFAULT_TIMESTAMP_POLICY
from tohupono.transaction.validation import (
    TRANSACTION_COLLECTION_SCHEMA_VERSION,
    transaction_ids_from_collection,
    validate_manifest_transactions,
)

PROOF_CONCEPTS_SCHEMA_VERSION = "tohupono.proof_concepts.v1"
DEFAULT_EXECUTABLE_CONCEPTS: tuple[str, ...] = ("existence", "integrity")
EXECUTABLE_CONCEPTS: tuple[str, ...] = ("custody", "existence", "integrity", "provenance", "records", "transaction")
CONCEPT_RESULT_STATUSES: tuple[str, ...] = ("PASS", "WARN", "FAIL", "UNPROVEN")
_CONCEPT_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_BIDI_CONTROLS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


def _validate_static_concept_id(concept_id: str) -> str:
    if not isinstance(concept_id, str) or not concept_id:
        raise ValueError("Proof Concept ID must not be empty.")
    if len(concept_id) > MAX_LABEL_LENGTH:
        raise ValueError("Proof Concept ID exceeds the configured length limit.")
    if any(ord(char) < 32 or char == "\x7f" for char in concept_id):
        raise ValueError("Proof Concept ID contains a control character.")
    if any(char in _BIDI_CONTROLS for char in concept_id):
        raise ValueError("Proof Concept ID contains a bidirectional control character.")
    if not _CONCEPT_ID_RE.fullmatch(concept_id):
        raise ValueError("Proof Concept ID must be a static lowercase identifier.")
    return concept_id


def is_executable_concept(concept_id: str) -> bool:
    return concept_id in EXECUTABLE_CONCEPTS


def concept_list_records() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for item in concept_registry():
        concept_id = str(item["concept_id"])
        records.append(
            {
                "claim_boundary": item["claim_boundary"],
                "concept_id": concept_id,
                "display_name": item["display_name"],
                "executable": is_executable_concept(concept_id),
                "implementation_maturity": item["implementation_maturity"],
            }
        )
    return sorted(records, key=lambda item: str(item["concept_id"]))


def inspect_concept_record(concept_id: str) -> dict[str, object]:
    concept_id = _validate_static_concept_id(concept_id)
    try:
        concept = get_concept(concept_id)
    except KeyError as exc:
        raise ValueError(f"Unknown Proof Concept: {concept_id}") from exc
    value = concept.to_dict()
    value["executable"] = is_executable_concept(concept_id)
    return value


def validate_requested_concepts(concept_ids: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    requested = tuple(concept_ids or DEFAULT_EXECUTABLE_CONCEPTS)
    seen: set[str] = set()
    validated: list[str] = []
    for raw_id in requested:
        concept_id = _validate_static_concept_id(raw_id)
        if concept_id in seen:
            raise ValueError(f"Duplicate Proof Concept requested: {concept_id}")
        seen.add(concept_id)
        try:
            get_concept(concept_id)
        except KeyError as exc:
            raise ValueError(f"Unknown Proof Concept: {concept_id}") from exc
        if not is_executable_concept(concept_id):
            raise ValueError(f"Proof Concept is not executable in this release: {concept_id}")
        validated.append(concept_id)
    return tuple(sorted(validated))


def proof_concept_seed(concept_ids: tuple[str, ...]) -> dict[str, object]:
    return {"schema_version": PROOF_CONCEPTS_SCHEMA_VERSION, "requested": list(concept_ids)}


def make_claim_id(concept_id: str, subject: dict[str, object], parameters: dict[str, object] | None = None) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "concept_id": concept_id,
                "parameters": parameters or {},
                "schema_version": PROOF_CONCEPTS_SCHEMA_VERSION,
                "subject": subject,
            }
        )
    ).hexdigest()
    return f"pcl_{digest[:32]}"


def _record_ids_from_manifest_records(records: dict[str, object] | None) -> list[str]:
    if not isinstance(records, dict):
        return []
    items = records.get("items")
    if not isinstance(items, list):
        return []
    return sorted(
        str(item["record_id"])
        for item in items
        if isinstance(item, dict) and isinstance(item.get("record_id"), str)
    )


def _custody_claim_parameters(custody: dict[str, object] | None) -> dict[str, object]:
    if not isinstance(custody, dict):
        return {"chain_head": None, "custody_schema_version": CUSTODY_COLLECTION_SCHEMA_VERSION, "event_ids": []}
    events = custody.get("events")
    event_ids = [
        str(item["event_id"])
        for item in events
        if isinstance(item, dict) and isinstance(item.get("event_id"), str)
    ] if isinstance(events, list) else []
    return {
        "chain_head": custody.get("chain_head") if isinstance(custody.get("chain_head"), str) else None,
        "custody_schema_version": CUSTODY_COLLECTION_SCHEMA_VERSION,
        "event_ids": event_ids,
    }


def _provenance_claim_parameters(file_sha256: str, provenance: dict[str, object] | None) -> dict[str, object]:
    return {
        "child": {"algorithm": "sha256", "digest": file_sha256},
        "edge_ids": provenance_edge_ids_from_collection(provenance),
        "provenance_schema_version": PROVENANCE_COLLECTION_SCHEMA_VERSION,
    }


def _transaction_claim_parameters(file_sha256: str, transactions: dict[str, object] | None) -> dict[str, object]:
    return {
        "subject": {"algorithm": "sha256", "digest": file_sha256},
        "transaction_ids": transaction_ids_from_collection(transactions),
        "transactions_schema_version": TRANSACTION_COLLECTION_SCHEMA_VERSION,
    }


def build_proof_concepts_declaration(
    file_sha256: str,
    concept_ids: tuple[str, ...],
    records: dict[str, object] | None = None,
    custody: dict[str, object] | None = None,
    provenance: dict[str, object] | None = None,
    transactions: dict[str, object] | None = None,
) -> dict[str, object]:
    claims: list[dict[str, object]] = []
    for concept_id in concept_ids:
        subject = {"algorithm": "sha256", "digest": file_sha256}
        parameters: dict[str, object] = {}
        if concept_id == "existence":
            parameters = {"timestamp_policy": DEFAULT_TIMESTAMP_POLICY}
        elif concept_id == "custody":
            parameters = _custody_claim_parameters(custody)
        elif concept_id == "provenance":
            parameters = _provenance_claim_parameters(file_sha256, provenance)
        elif concept_id == "transaction":
            parameters = _transaction_claim_parameters(file_sha256, transactions)
        elif concept_id == "records":
            parameters = {
                "record_ids": _record_ids_from_manifest_records(records),
                "records_schema_version": RECORDS_COLLECTION_SCHEMA_VERSION,
            }
        claims.append(
            {
                "claim_id": make_claim_id(concept_id, subject, parameters),
                "concept_id": concept_id,
                "parameters": parameters,
                "subject": subject,
            }
        )
    return {
        "claims": claims,
        "requested": list(concept_ids),
        "schema_version": PROOF_CONCEPTS_SCHEMA_VERSION,
    }


def declared_concepts(manifest: dict[str, Any]) -> tuple[str, ...]:
    declaration = manifest.get("proof_concepts")
    if not isinstance(declaration, dict):
        return ()
    requested = declaration.get("requested")
    if not isinstance(requested, list):
        return ()
    values = [item for item in requested if isinstance(item, str)]
    return validate_requested_concepts(values)


def _manifest_file_digest(manifest: dict[str, Any]) -> str:
    file_info = manifest.get("file")
    if not isinstance(file_info, dict) or not isinstance(file_info.get("sha256"), str):
        raise ValueError("Proof Concept declaration cannot be validated without a recorded SHA-256 digest.")
    digest = str(file_info["sha256"])
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Proof Concept declaration references an invalid recorded SHA-256 digest.")
    return digest


def _raw_declared_concept_ids(manifest: dict[str, Any]) -> list[object]:
    declaration = manifest.get("proof_concepts")
    if not isinstance(declaration, dict):
        return []
    requested = declaration.get("requested")
    return requested if isinstance(requested, list) else []


def _invalid_declaration_result(message: str) -> dict[str, object]:
    return {
        "checks": [{"status": "FAIL", "message": message}],
        "claim_boundary": "Unsupported or invalid Proof Concept declarations are not executable.",
        "claim_id": None,
        "concept_id": "invalid",
        "display_name": "Invalid Proof Concept Declaration",
        "evidence_summary": "The manifest declares an unsupported or invalid Proof Concept.",
        "executable": False,
        "implementation_maturity": "unmodelled",
        "limitations": ["Registry presence does not imply execution support."],
        "status": "FAIL",
    }


def _expected_claim(concept_id: str, file_sha256: str, manifest: dict[str, Any]) -> dict[str, object]:
    subject = {"algorithm": "sha256", "digest": file_sha256}
    parameters: dict[str, object] = {}
    if concept_id == "existence":
        parameters = {"timestamp_policy": DEFAULT_TIMESTAMP_POLICY}
    elif concept_id == "custody":
        parameters = _custody_claim_parameters(manifest.get("custody") if isinstance(manifest.get("custody"), dict) else None)
    elif concept_id == "provenance":
        parameters = _provenance_claim_parameters(file_sha256, manifest.get("provenance") if isinstance(manifest.get("provenance"), dict) else None)
    elif concept_id == "transaction":
        parameters = _transaction_claim_parameters(file_sha256, manifest.get("transactions") if isinstance(manifest.get("transactions"), dict) else None)
    elif concept_id == "records":
        parameters = {
            "record_ids": _record_ids_from_manifest_records(
                manifest.get("records") if isinstance(manifest.get("records"), dict) else None
            ),
            "records_schema_version": RECORDS_COLLECTION_SCHEMA_VERSION,
        }
    return {
        "claim_id": make_claim_id(concept_id, subject, parameters),
        "concept_id": concept_id,
        "parameters": parameters,
        "subject": subject,
    }


def _validate_claim(
    claim: object,
    *,
    requested: tuple[str, ...],
    file_sha256: str,
    manifest: dict[str, Any],
    seen_claim_ids: set[str],
) -> tuple[str, dict[str, object]]:
    if not isinstance(claim, dict):
        raise ValueError("Proof Concept claim must be an object.")
    required = {"claim_id", "concept_id", "parameters", "subject"}
    missing = sorted(required - set(claim))
    if missing:
        raise ValueError(f"Proof Concept claim is missing required fields: {', '.join(missing)}")
    claim_id = claim.get("claim_id")
    concept_id = claim.get("concept_id")
    if not isinstance(claim_id, str) or not claim_id.startswith("pcl_"):
        raise ValueError("Proof Concept claim_id is invalid.")
    if claim_id in seen_claim_ids:
        raise ValueError("Duplicate Proof Concept claim_id declared.")
    seen_claim_ids.add(claim_id)
    if not isinstance(concept_id, str):
        raise ValueError("Proof Concept claim concept_id is invalid.")
    concept_id = _validate_static_concept_id(concept_id)
    if concept_id not in requested:
        raise ValueError(f"Proof Concept claim is not requested: {concept_id}")

    expected = _expected_claim(concept_id, file_sha256, manifest)
    if claim.get("subject") != expected["subject"]:
        raise ValueError(f"Proof Concept claim subject is invalid for {concept_id}.")
    if concept_id == "records":
        parameters = claim.get("parameters")
        if not isinstance(parameters, dict):
            raise ValueError("Proof of Records claim parameters must be an object.")
        expected_claim_id = make_claim_id(concept_id, expected["subject"], parameters)
    elif concept_id == "custody":
        parameters = claim.get("parameters")
        if not isinstance(parameters, dict):
            raise ValueError("Proof of Custody claim parameters must be an object.")
        expected_claim_id = make_claim_id(concept_id, expected["subject"], parameters)
    elif concept_id == "provenance":
        parameters = claim.get("parameters")
        if not isinstance(parameters, dict):
            raise ValueError("Proof of Provenance claim parameters must be an object.")
        expected_claim_id = make_claim_id(concept_id, expected["subject"], parameters)
    elif concept_id == "transaction":
        parameters = claim.get("parameters")
        if not isinstance(parameters, dict):
            raise ValueError("Proof of Transaction claim parameters must be an object.")
        expected_claim_id = make_claim_id(concept_id, expected["subject"], parameters)
    else:
        if claim.get("parameters") != expected["parameters"]:
            raise ValueError(f"Proof Concept claim parameters are invalid for {concept_id}.")
        expected_claim_id = str(expected["claim_id"])
    if claim_id != expected_claim_id:
        raise ValueError(f"Proof Concept claim_id does not match canonical claim data for {concept_id}.")
    return concept_id, dict(claim)


def validate_proof_concepts_declaration(
    manifest: dict[str, Any],
) -> tuple[tuple[str, ...], dict[str, dict[str, object]]]:
    declaration = manifest.get("proof_concepts")
    if declaration is None:
        return (), {}
    if not isinstance(declaration, dict):
        raise ValueError("Proof Concepts declaration must be an object.")
    if declaration.get("schema_version") != PROOF_CONCEPTS_SCHEMA_VERSION:
        raise ValueError("Proof Concepts declaration schema version is unsupported.")
    requested_raw = declaration.get("requested")
    if not isinstance(requested_raw, list):
        raise ValueError("Proof Concepts declaration requested field must be a list.")
    if not all(isinstance(item, str) for item in requested_raw):
        raise ValueError("Proof Concepts declaration requested field must contain only strings.")
    requested = validate_requested_concepts(requested_raw)

    claims = declaration.get("claims")
    if not isinstance(claims, list):
        raise ValueError("Proof Concepts declaration claims field must be a list.")
    file_sha256 = _manifest_file_digest(manifest)
    seen_claim_ids: set[str] = set()
    seen_concepts: set[str] = set()
    result: dict[str, dict[str, object]] = {}
    for claim in claims:
        concept_id, validated_claim = _validate_claim(
            claim,
            requested=requested,
            file_sha256=file_sha256,
            manifest=manifest,
            seen_claim_ids=seen_claim_ids,
        )
        if concept_id in seen_concepts:
            raise ValueError(f"Duplicate Proof Concept claim declared: {concept_id}")
        seen_concepts.add(concept_id)
        result[concept_id] = validated_claim
    missing = sorted(set(requested) - seen_concepts)
    if missing:
        raise ValueError(f"Proof Concepts declaration is missing claims for: {', '.join(missing)}")
    extra = sorted(seen_concepts - set(requested))
    if extra:
        raise ValueError(f"Proof Concepts declaration includes unrequested claims for: {', '.join(extra)}")
    return requested, result


def _summary_status(summary: dict[str, int]) -> str:
    if summary.get("FAIL", 0):
        return "FAIL"
    if summary.get("WARN", 0):
        return "WARN"
    if summary.get("UNPROVEN", 0):
        return "UNPROVEN"
    return "PASS"


def _summary(results: list[dict[str, object]]) -> dict[str, object]:
    summary: dict[str, int] = {status: 0 for status in CONCEPT_RESULT_STATUSES}
    for result in results:
        status = str(result.get("status"))
        if status in summary:
            summary[status] += 1
    return {**summary, "overall_status": _summary_status(summary)}


def _result(
    *,
    concept_id: str,
    status: str,
    claim_id: str | None,
    checks: list[dict[str, str]],
    limitations: list[str],
    evidence_summary: str,
) -> dict[str, object]:
    concept = get_concept(concept_id)
    return {
        "checks": checks,
        "claim_boundary": concept.claim_boundary,
        "claim_id": claim_id,
        "concept_id": concept_id,
        "display_name": concept.display_name,
        "evidence_summary": evidence_summary,
        "executable": True,
        "implementation_maturity": concept.implementation_maturity,
        "limitations": limitations,
        "status": status,
    }


def evaluate_integrity(
    manifest: dict[str, Any],
    *,
    source_path: Path | None,
    claim_id: str | None,
) -> dict[str, object]:
    file_info = manifest.get("file")
    if not isinstance(file_info, dict) or not file_info.get("sha256"):
        return _result(
            concept_id="integrity",
            status="UNPROVEN",
            claim_id=claim_id,
            checks=[{"status": "UNPROVEN", "message": "recorded SHA-256 digest evidence is unavailable."}],
            limitations=["Integrity requires a recorded digest and supplied bytes."],
            evidence_summary="Recorded digest evidence is unavailable.",
        )
    expected = str(file_info["sha256"])
    if source_path is None:
        return _result(
            concept_id="integrity",
            status="UNPROVEN",
            claim_id=claim_id,
            checks=[{"status": "UNPROVEN", "message": "source bytes were not supplied for concept verification."}],
            limitations=["Packet-only inspection cannot prove current byte equality."],
            evidence_summary=f"Recorded SHA-256 digest: {expected}",
        )
    identity = inspect_file(source_path)
    if identity.sha256 == expected:
        status = "PASS"
        message = "supplied bytes match the recorded SHA-256 digest."
    else:
        status = "FAIL"
        message = "supplied bytes do not match the recorded SHA-256 digest."
    return _result(
        concept_id="integrity",
        status=status,
        claim_id=claim_id,
        checks=[{"status": status, "message": message}],
        limitations=["Digest equality does not prove authenticity, ownership, authorship, or truth."],
        evidence_summary=f"Current SHA-256 {identity.sha256}; recorded SHA-256 {expected}.",
    )


def evaluate_existence(
    manifest_path: Path,
    manifest: dict[str, Any],
    *,
    claim_id: str | None,
    timestamp_policy: str = DEFAULT_TIMESTAMP_POLICY,
) -> dict[str, object]:
    from tohupono.core.proof import timestamp_verification_diagnostics

    diagnostics = timestamp_verification_diagnostics(manifest_path, timestamp_policy)
    failures = diagnostics.get("failures") or []
    warnings = diagnostics.get("warnings") or []
    timestamp_status = str(diagnostics.get("timestamping_status", "missing"))
    if failures:
        status = "FAIL"
    elif timestamp_status == "missing":
        status = "UNPROVEN"
    elif warnings:
        status = "WARN"
    else:
        status = "PASS"
    checks = [
        {"status": str(check.get("status")), "message": str(check.get("message"))}
        for check in diagnostics.get("checks", [])
        if isinstance(check, dict)
    ]
    if status == "UNPROVEN" and not checks:
        checks = [{"status": "UNPROVEN", "message": "no usable timestamp evidence is present."}]
    return _result(
        concept_id="existence",
        status=status,
        claim_id=claim_id,
        checks=checks,
        limitations=[
            "Local timestamp evidence is not independently anchored.",
            "Imported receipts remain unverified unless a future adapter verifies them.",
            "A timestamp does not prove content truth, authorship, ownership, or admissibility.",
        ],
        evidence_summary=f"Timestamp status {timestamp_status}; receipt count {diagnostics.get('receipt_count', 0)}.",
    )


def evaluate_records(
    manifest: dict[str, Any],
    *,
    claim_id: str | None,
    expected_record_ids: list[str],
) -> dict[str, object]:
    validation = validate_manifest_records(manifest, expected_record_ids=expected_record_ids)
    checks: list[dict[str, str]] = []
    for failure in validation.failures:
        checks.append({"status": "FAIL", "message": failure})
    for warning in validation.warnings:
        checks.append({"status": "WARN", "message": warning})
    if validation.status == "pass":
        checks.insert(0, {"status": "PASS", "message": "record envelopes are canonical and linked to the subject digest."})
    status = "PASS" if validation.status == "pass" else "FAIL"
    evidence_summary = (
        f"Record count {validation.record_count}; record IDs {', '.join(validation.record_ids) if validation.record_ids else 'none'}."
    )
    result = _result(
        concept_id="records",
        status=status,
        claim_id=claim_id,
        checks=checks,
        limitations=validation.limitations,
        evidence_summary=evidence_summary,
    )
    result["records"] = [
        {
            "attribute_count": len(record.get("attributes", {})) if isinstance(record.get("attributes"), dict) else 0,
            "namespace": record.get("namespace"),
            "record_id": record.get("record_id"),
            "record_type": record.get("record_type"),
            "reference": record.get("reference"),
            "subject": record.get("subject"),
        }
        for record in validation.records
    ]
    result["record_count"] = validation.record_count
    result["record_ids"] = validation.record_ids
    result["failures"] = validation.failures
    result["warnings"] = validation.warnings
    return result


def evaluate_custody(
    manifest: dict[str, Any],
    *,
    claim_id: str | None,
    expected_event_ids: list[str],
    expected_chain_head: str | None,
) -> dict[str, object]:
    validation = validate_manifest_custody(
        manifest,
        expected_event_ids=expected_event_ids,
        expected_chain_head=expected_chain_head,
    )
    checks: list[dict[str, str]] = []
    for failure in validation.failures:
        checks.append({"status": "FAIL", "message": failure})
    for warning in validation.warnings:
        checks.append({"status": "WARN", "message": warning})
    if validation.status == "pass":
        checks.insert(0, {"status": "PASS", "message": "custody event sequence is canonical and hash-linked."})
    status = "PASS" if validation.status == "pass" else "FAIL"
    evidence_summary = (
        f"Custody event count {validation.event_count}; chain head {validation.chain_head or 'none'}."
    )
    result = _result(
        concept_id="custody",
        status=status,
        claim_id=claim_id,
        checks=checks,
        limitations=validation.limitations,
        evidence_summary=evidence_summary,
    )
    result["custody_schema_status"] = validation.custody_schema_status
    result["event_count"] = validation.event_count
    result["chain_head"] = validation.chain_head
    result["event_ids"] = validation.event_ids
    result["events"] = [
        {
            "actor": event.get("actor"),
            "attribute_count": len(event.get("attributes", {})) if isinstance(event.get("attributes"), dict) else 0,
            "event_hash": event.get("event_hash"),
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "location_present": event.get("location") is not None,
            "occurred_at": event.get("occurred_at"),
            "previous_event_hash": event.get("previous_event_hash"),
            "reference": event.get("reference"),
            "sequence": event.get("sequence"),
            "subject": event.get("subject"),
        }
        for event in validation.events
    ]
    result["failures"] = validation.failures
    result["warnings"] = validation.warnings
    return result


def evaluate_provenance(
    manifest: dict[str, Any],
    *,
    claim_id: str | None,
    expected_edge_ids: list[str],
    expected_child: dict[str, object] | None,
) -> dict[str, object]:
    validation = validate_manifest_provenance(
        manifest,
        expected_edge_ids=expected_edge_ids,
        expected_child=expected_child,
    )
    checks: list[dict[str, str]] = []
    for failure in validation.failures:
        checks.append({"status": "FAIL", "message": failure})
    for warning in validation.warnings:
        checks.append({"status": "WARN", "message": warning})
    if validation.status == "pass":
        checks.insert(0, {"status": "PASS", "message": "provenance edges are canonical and linked to the subject digest."})
    status = "PASS" if validation.status == "pass" else "FAIL"
    evidence_summary = (
        f"Provenance edge count {validation.edge_count}; edge IDs {', '.join(validation.edge_ids) if validation.edge_ids else 'none'}."
    )
    result = _result(
        concept_id="provenance",
        status=status,
        claim_id=claim_id,
        checks=checks,
        limitations=validation.limitations,
        evidence_summary=evidence_summary,
    )
    result["provenance_schema_status"] = validation.provenance_schema_status
    result["edge_count"] = validation.edge_count
    result["edge_ids"] = validation.edge_ids
    result["edges"] = [
        {
            "actor": edge.get("actor"),
            "attribute_count": len(edge.get("attributes", {})) if isinstance(edge.get("attributes"), dict) else 0,
            "child": edge.get("child"),
            "edge_id": edge.get("edge_id"),
            "operation": edge.get("operation"),
            "occurred_at": edge.get("occurred_at"),
            "parent": edge.get("parent"),
            "reference": edge.get("reference"),
            "relation_type": edge.get("relation_type"),
        }
        for edge in validation.edges
    ]
    result["failures"] = validation.failures
    result["warnings"] = validation.warnings
    return result


def evaluate_transaction(
    manifest: dict[str, Any],
    *,
    claim_id: str | None,
    expected_transaction_ids: list[str],
    expected_subject: dict[str, object] | None,
) -> dict[str, object]:
    validation = validate_manifest_transactions(
        manifest,
        expected_transaction_ids=expected_transaction_ids,
        expected_subject=expected_subject,
    )
    checks: list[dict[str, str]] = []
    for failure in validation.failures:
        checks.append({"status": "FAIL", "message": failure})
    for warning in validation.warnings:
        checks.append({"status": "WARN", "message": warning})
    if validation.status == "pass":
        checks.insert(0, {"status": "PASS", "message": "transaction envelopes are canonical and linked to the subject digest."})
    status = "PASS" if validation.status == "pass" else "FAIL"
    evidence_summary = (
        f"Transaction count {validation.transaction_count}; transaction IDs {', '.join(validation.transaction_ids) if validation.transaction_ids else 'none'}."
    )
    result = _result(
        concept_id="transaction",
        status=status,
        claim_id=claim_id,
        checks=checks,
        limitations=validation.limitations,
        evidence_summary=evidence_summary,
    )
    result["transaction_schema_status"] = validation.transaction_schema_status
    result["transaction_count"] = validation.transaction_count
    result["transaction_ids"] = validation.transaction_ids
    result["transactions"] = [
        {
            "attribute_count": len(item.get("attributes", {})) if isinstance(item.get("attributes"), dict) else 0,
            "occurred_at": item.get("occurred_at"),
            "participant_count": len(item.get("participants", [])) if isinstance(item.get("participants"), list) else 0,
            "participants": item.get("participants"),
            "reference": item.get("reference"),
            "subject": item.get("subject"),
            "terms_count": len(item.get("terms", {})) if isinstance(item.get("terms"), dict) else 0,
            "transaction_id": item.get("transaction_id"),
            "transaction_type": item.get("transaction_type"),
        }
        for item in validation.transactions
    ]
    result["failures"] = validation.failures
    result["warnings"] = validation.warnings
    return result


def evaluate_declared_concepts(
    manifest_path: Path,
    manifest: dict[str, Any],
    *,
    source_path: Path | None = None,
    timestamp_policy: str = DEFAULT_TIMESTAMP_POLICY,
) -> dict[str, object]:
    try:
        requested, claims = validate_proof_concepts_declaration(manifest)
    except ValueError as exc:
        raw_values = [str(item) for item in _raw_declared_concept_ids(manifest) if isinstance(item, str)]
        return {
            "declared": sorted(raw_values),
            "inferred_legacy_checks": [],
            "legacy_warning": None,
            "results": [_invalid_declaration_result(str(exc))],
            "summary": {"FAIL": 1, "PASS": 0, "UNPROVEN": 0, "WARN": 0, "overall_status": "FAIL"},
        }
    if not requested:
        return {
            "declared": [],
            "inferred_legacy_checks": ["integrity", "existence"],
            "legacy_warning": "explicit Proof Concepts declarations are absent; showing inferred legacy checks separately.",
            "results": [],
            "summary": {"FAIL": 0, "PASS": 0, "UNPROVEN": 0, "WARN": 0, "overall_status": "UNPROVEN"},
        }
    results: list[dict[str, object]] = []
    for concept_id in requested:
        claim = claims.get(concept_id, {})
        claim_id = str(claim.get("claim_id")) if claim.get("claim_id") else None
        if concept_id == "integrity":
            results.append(evaluate_integrity(manifest, source_path=source_path, claim_id=claim_id))
        elif concept_id == "custody":
            parameters = claim.get("parameters") if isinstance(claim.get("parameters"), dict) else {}
            raw_event_ids = parameters.get("event_ids") if isinstance(parameters, dict) else []
            if parameters.get("custody_schema_version") != CUSTODY_COLLECTION_SCHEMA_VERSION:
                expected_event_ids = ["__invalid_custody_schema__"]
            else:
                expected_event_ids = [str(item) for item in raw_event_ids] if isinstance(raw_event_ids, list) else []
            chain_head = parameters.get("chain_head") if isinstance(parameters.get("chain_head"), str) else "__invalid_custody_chain_head__"
            results.append(
                evaluate_custody(
                    manifest,
                    claim_id=claim_id,
                    expected_event_ids=expected_event_ids,
                    expected_chain_head=chain_head,
                )
            )
        elif concept_id == "existence":
            results.append(
                evaluate_existence(manifest_path, manifest, claim_id=claim_id, timestamp_policy=timestamp_policy)
            )
        elif concept_id == "provenance":
            parameters = claim.get("parameters") if isinstance(claim.get("parameters"), dict) else {}
            raw_edge_ids = parameters.get("edge_ids") if isinstance(parameters, dict) else []
            if parameters.get("provenance_schema_version") != PROVENANCE_COLLECTION_SCHEMA_VERSION:
                expected_edge_ids = ["__invalid_provenance_schema__"]
            else:
                expected_edge_ids = [str(item) for item in raw_edge_ids] if isinstance(raw_edge_ids, list) else []
            child = parameters.get("child") if isinstance(parameters.get("child"), dict) else {"algorithm": "sha256", "digest": "__invalid_provenance_child__"}
            results.append(
                evaluate_provenance(
                    manifest,
                    claim_id=claim_id,
                    expected_edge_ids=expected_edge_ids,
                    expected_child=child,
                )
            )
        elif concept_id == "records":
            parameters = claim.get("parameters") if isinstance(claim.get("parameters"), dict) else {}
            raw_record_ids = parameters.get("record_ids") if isinstance(parameters, dict) else []
            if parameters.get("records_schema_version") != RECORDS_COLLECTION_SCHEMA_VERSION:
                expected_record_ids = ["__invalid_records_schema__"]
            else:
                expected_record_ids = [str(item) for item in raw_record_ids] if isinstance(raw_record_ids, list) else []
            results.append(evaluate_records(manifest, claim_id=claim_id, expected_record_ids=expected_record_ids))
        elif concept_id == "transaction":
            parameters = claim.get("parameters") if isinstance(claim.get("parameters"), dict) else {}
            raw_transaction_ids = parameters.get("transaction_ids") if isinstance(parameters, dict) else []
            if parameters.get("transactions_schema_version") != TRANSACTION_COLLECTION_SCHEMA_VERSION:
                expected_transaction_ids = ["__invalid_transaction_schema__"]
            else:
                expected_transaction_ids = [str(item) for item in raw_transaction_ids] if isinstance(raw_transaction_ids, list) else []
            subject = parameters.get("subject") if isinstance(parameters.get("subject"), dict) else {"algorithm": "sha256", "digest": "__invalid_transaction_subject__"}
            results.append(
                evaluate_transaction(
                    manifest,
                    claim_id=claim_id,
                    expected_transaction_ids=expected_transaction_ids,
                    expected_subject=subject,
                )
            )
    return {
        "declared": list(requested),
        "inferred_legacy_checks": [],
        "legacy_warning": None,
        "results": results,
        "summary": _summary(results),
    }
