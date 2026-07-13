from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from tohupono import __version__
from tohupono.concepts.execution import (
    concept_list_records,
    inspect_concept_record,
)
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.file_identity import Blake3UnavailableError, TohuPonoError, hash_file, inspect_file
from tohupono.core.proof import (
    create_amendment,
    create_proof_packet,
    evidence_chain_diagnostics,
    import_timestamp_receipt,
    list_timestamp_receipts,
    load_manifest,
    packet_diagnostics,
    resolve_packet_manifest,
    timestamp_verification_diagnostics,
)
from tohupono.custody.validation import load_custody_descriptor, validate_manifest_custody
from tohupono.reporting.pro_report import generate_report
from tohupono.provenance.validation import load_provenance_descriptor, validate_manifest_provenance
from tohupono.records.validation import load_record_descriptor, validate_manifest_records
from tohupono.timestamping.model import (
    DEFAULT_TIMESTAMP_POLICY,
    TIMESTAMP_POLICIES,
    TIMESTAMP_RECEIPT_TYPES,
    TimestampReceiptConflictError,
    inspect_manifest_timestamping,
)
from tohupono.trust.keys import (
    KeyConflictError,
    KeyErrorWithAction,
    check_keys,
    create_key,
    inspect_keys,
    key_purpose_names,
    mark_key_compromised,
    rotate_key,
)
from tohupono.verdicts.classifier import (
    VERIFIED_INTEGRITY,
    manifest_signature_status,
    verify_file,
    write_markdown,
    write_verdict,
)

EXIT_SUCCESS = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USER_ERROR = 2
EXIT_INTERNAL_ERROR = 3


def _print_json(value: object) -> None:
    print(canonical_json_text(value))


def _json_error(code: str, message: str) -> dict[str, object]:
    return {"error": {"code": code, "message": message}, "status": "error"}


def _emit_error(code: str, message: str, *, json_mode: bool, exit_code: int) -> int:
    if json_mode:
        _print_json(_json_error(code, message))
    else:
        print(f"error: {message}", file=sys.stderr)
    return exit_code


def _missing_path_code(command: str, path_arg: str) -> str:
    if command in {"verify", "verify-file", "report", "inspect-proof", "audit", "amend", "timestamp"} and (
        "manifest" in path_arg.lower() or "packet" in path_arg.lower()
    ):
        return "MISSING_PROOF"
    return "MISSING_FILE"


def _json_mode(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json", False))


def _proof_artefacts(manifest: Path) -> list[str]:
    proof_dir = manifest.parent
    names = [
        "manifest.json",
        "hashes.txt",
        "metadata.json",
        "evidence_chain.jsonl",
        "warnings.json",
        "signatures/manifest.sig",
        "signatures/manifest.pub",
    ]
    return [name for name in names if (proof_dir / name).exists()]


def inspect_proof_manifest(manifest_path: Path) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    file_info = manifest.get("file", {})
    if not isinstance(file_info, dict):
        file_info = {}
    tool_info = manifest.get("tool", {})
    if not isinstance(tool_info, dict):
        tool_info = {}
    warnings = manifest.get("warnings", [])
    warnings_count = len(warnings) if isinstance(warnings, list) else 0
    chain_result = evidence_chain_diagnostics(manifest_path.parent / "evidence_chain.jsonl")
    return {
        "available_artefacts": _proof_artefacts(manifest_path),
        "boundary": "Proof manifest inspected. Source file was not verified in this command.",
        "evidence_chain_status": chain_result["status"],
        "file_sha256": file_info.get("sha256"),
        "file_size": file_info.get("size_bytes"),
        "manifest_signature_status": manifest_signature_status(manifest_path),
        "manifest_version": manifest.get("manifest_version"),
        "original_observed_file_path": file_info.get("path_observed"),
        "proof_id": manifest.get("proof_id"),
        "schema_version": manifest.get("schema_version"),
        "sealed_timestamp": manifest.get("sealed_at_utc"),
        "tool_version": tool_info.get("version"),
        "warnings_count": warnings_count,
    }


def _print_verify_chain_human(result: dict[str, object]) -> None:
    print(f"Evidence chain status: {result['status']}")
    print(f"Path: {result['path']}")
    print(f"Events: {result['event_count']}")
    errors = result.get("errors", [])
    if errors:
        print("Diagnostics:")
        for error in errors:
            print(f"- {error}")


def _print_inspect_proof_human(result: dict[str, object]) -> None:
    print("Proof manifest inspected. Source file was not verified in this command.")
    print(f"Proof ID: {result.get('proof_id') or 'unknown'}")
    print(f"Schema version: {result.get('schema_version') or 'unknown'}")
    print(f"Manifest version: {result.get('manifest_version') or 'unknown'}")
    print(f"Tool version: {result.get('tool_version') or 'unknown'}")
    print(f"Sealed timestamp: {result.get('sealed_timestamp') or 'unknown'}")
    print(f"Original observed file path: {result.get('original_observed_file_path') or 'unknown'}")
    print(f"File size: {result.get('file_size') if result.get('file_size') is not None else 'unknown'}")
    print(f"SHA-256: {result.get('file_sha256') or 'unknown'}")
    print(f"Manifest signature status: {result.get('manifest_signature_status') or 'unknown'}")
    print(f"Evidence chain status: {result.get('evidence_chain_status') or 'unknown'}")
    print(f"Warnings count: {result.get('warnings_count')}")
    print("Available proof packet artefacts:")
    for artefact in result.get("available_artefacts", []):
        print(f"- {artefact}")


def _print_packet_checks(result: dict[str, object]) -> None:
    for check in result.get("checks", []):
        if isinstance(check, dict):
            print(f"{check.get('status')}: {check.get('message')}")
    concept_results = result.get("proof_concept_results") or []
    if isinstance(concept_results, list):
        print("Proof Concepts:")
        if not concept_results:
            legacy = result.get("inferred_legacy_checks") or []
            print(f"UNPROVEN: no declared Proof Concepts; inferred legacy checks: {', '.join(legacy) if legacy else 'none'}.")
        for item in concept_results:
            if not isinstance(item, dict):
                continue
            print(
                f"{item.get('status')}: {item.get('concept_id')} - "
                f"{item.get('evidence_summary') or item.get('claim_boundary')}"
            )
            if item.get("concept_id") == "records":
                print(f"  records: {item.get('record_count', 0)}")
                for record in item.get("records") or []:
                    if not isinstance(record, dict):
                        continue
                    print(
                        "  - "
                        f"{record.get('record_id')} "
                        f"type={record.get('record_type')} "
                        f"namespace={record.get('namespace')} "
                        f"reference={record.get('reference') if record.get('reference') is not None else 'none'}"
                    )
                for failure in item.get("failures") or []:
                    print(f"  FAIL: {failure}")
                for limitation in item.get("limitations") or []:
                    print(f"  LIMIT: {limitation}")
            if item.get("concept_id") == "custody":
                print(f"  custody events: {item.get('event_count', 0)}")
                print(f"  chain head: {item.get('chain_head') or 'none'}")
                for event in item.get("events") or []:
                    if not isinstance(event, dict):
                        continue
                    actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
                    actor_text = (
                        f"{actor.get('namespace')}/{actor.get('identifier')}"
                        if isinstance(actor, dict)
                        else "unknown"
                    )
                    print(
                        "  - "
                        f"seq={event.get('sequence')} "
                        f"{event.get('event_id')} "
                        f"type={event.get('event_type')} "
                        f"actor={actor_text} "
                        f"declared_time={event.get('occurred_at') or 'none'}"
                    )
                for failure in item.get("failures") or []:
                    print(f"  FAIL: {failure}")
                for limitation in item.get("limitations") or []:
                    print(f"  LIMIT: {limitation}")
            if item.get("concept_id") == "provenance":
                print(f"  provenance edges: {item.get('edge_count', 0)}")
                for edge in item.get("edges") or []:
                    if not isinstance(edge, dict):
                        continue
                    parent = edge.get("parent") if isinstance(edge.get("parent"), dict) else {}
                    print(
                        "  - "
                        f"{edge.get('edge_id')} "
                        f"relation={edge.get('relation_type')} "
                        f"parent={parent.get('digest') if isinstance(parent, dict) else 'unknown'}"
                    )
                for failure in item.get("failures") or []:
                    print(f"  FAIL: {failure}")
                for limitation in item.get("limitations") or []:
                    print(f"  LIMIT: {limitation}")


def _print_concept_list_human(records: list[dict[str, object]]) -> None:
    for item in records:
        print(f"{item['concept_id']}: {item['display_name']}")
        print(f"  maturity: {item['implementation_maturity']}")
        print(f"  executable: {'yes' if item['executable'] else 'no'}")
        print(f"  boundary: {item['claim_boundary']}")


def _print_concept_inspect_human(record: dict[str, object]) -> None:
    print(f"Concept ID: {record['concept_id']}")
    print(f"Display name: {record['display_name']}")
    print(f"Maturity: {record['implementation_maturity']}")
    print(f"Executable: {'yes' if record['executable'] else 'no'}")
    print(f"Exact claim: {record['exact_claim']}")
    print(f"Subject: {record['subject']}")
    print("Required evidence:")
    for item in record.get("required_evidence", []):
        print(f"- {item}")
    print("Verification procedure:")
    for item in record.get("verification_procedure", []):
        print(f"- {item}")
    print("Trust assumptions:")
    for item in record.get("trust_dependencies", []):
        print(f"- {item}")
    print("Failure conditions:")
    for item in record.get("failure_conditions", []):
        print(f"- {item}")
    print("Known limitations:")
    for item in record.get("known_limitations", []):
        print(f"- {item}")
    print("Privacy implications:")
    for item in record.get("privacy_implications", []):
        print(f"- {item}")
    print(f"Legal boundary: {record['legal_boundary']}")


def _provenance_validation_summary(path: Path) -> dict[str, object]:
    descriptor = load_provenance_descriptor(path)
    attributes = descriptor.attributes
    return {
        "actor_present": descriptor.actor is not None,
        "attribute_count": len(attributes),
        "declared_time_present": descriptor.occurred_at is not None,
        "descriptor_schema_version": descriptor.schema_version,
        "failures": [],
        "operation_present": descriptor.operation is not None,
        "parent_algorithm": descriptor.parent["algorithm"],
        "parent_digest_valid": True,
        "reference_present": descriptor.reference is not None,
        "relation_type": descriptor.relation_type,
        "status": "ok",
        "warnings": [
            "Descriptor validation does not prove that the parent file exists or that a lineage relationship occurred.",
            "Do not place credentials, private keys, secrets, unnecessary personal information, or sensitive operational details in provenance descriptors.",
        ],
    }


def _provenance_inspection(packet: Path) -> dict[str, object]:
    manifest_path = resolve_packet_manifest(packet)
    manifest = load_manifest(manifest_path)
    validation = validate_manifest_provenance(manifest)
    return {
        "edge_count": validation.edge_count,
        "edge_ids": validation.edge_ids,
        "edges": validation.edges,
        "failures": validation.failures,
        "limitations": validation.limitations,
        "manifest": str(manifest_path),
        "provenance_schema_status": validation.provenance_schema_status,
        "status": validation.status,
        "warnings": validation.warnings,
    }


def _print_provenance_validate_human(result: dict[str, object]) -> None:
    print(f"Status: {result.get('status')}")
    print(f"Descriptor schema: {result.get('descriptor_schema_version')}")
    print(f"Relation type: {result.get('relation_type')}")
    print(f"Parent algorithm: {result.get('parent_algorithm')}")
    print(f"Parent digest valid: {'yes' if result.get('parent_digest_valid') else 'no'}")
    print(f"Operation present: {'yes' if result.get('operation_present') else 'no'}")
    print(f"Actor present: {'yes' if result.get('actor_present') else 'no'}")
    print(f"Declared time present: {'yes' if result.get('declared_time_present') else 'no'}")
    print(f"Reference present: {'yes' if result.get('reference_present') else 'no'}")
    print(f"Attribute count: {result.get('attribute_count')}")
    for warning in result.get("warnings", []):
        print(f"WARN: {warning}")


def _print_provenance_inspect_human(result: dict[str, object]) -> None:
    print(f"Status: {result.get('status')}")
    print(f"Provenance schema: {result.get('provenance_schema_status')}")
    print(f"Edge count: {result.get('edge_count')}")
    for edge in result.get("edges", []):
        if not isinstance(edge, dict):
            continue
        child = edge.get("child") if isinstance(edge.get("child"), dict) else {}
        parent = edge.get("parent") if isinstance(edge.get("parent"), dict) else {}
        operation = edge.get("operation") if isinstance(edge.get("operation"), dict) else None
        actor = edge.get("actor") if isinstance(edge.get("actor"), dict) else None
        attributes = edge.get("attributes") if isinstance(edge.get("attributes"), dict) else {}
        print(f"Edge ID: {edge.get('edge_id')}")
        print(f"Relation type: {edge.get('relation_type')}")
        print(f"Child digest: {child.get('digest') if isinstance(child, dict) else 'unknown'}")
        print(f"Parent digest: {parent.get('digest') if isinstance(parent, dict) else 'unknown'}")
        print(f"Operation: {operation.get('name') if isinstance(operation, dict) else 'none'}")
        print(f"Declared actor: {actor.get('namespace') + '/' + actor.get('identifier') if isinstance(actor, dict) else 'none'}")
        print(f"Declared time: {edge.get('occurred_at') or 'none'}")
        print(f"Attribute count: {len(attributes) if isinstance(attributes, dict) else 0}")
    for failure in result.get("failures", []):
        print(f"FAIL: {failure}")
    for warning in result.get("warnings", []):
        print(f"WARN: {warning}")
    for limitation in result.get("limitations", []):
        print(f"LIMIT: {limitation}")


def _record_validation_summary(path: Path) -> dict[str, object]:
    descriptor = load_record_descriptor(path)
    attributes = descriptor.attributes
    return {
        "attribute_count": len(attributes),
        "descriptor_schema_version": descriptor.schema_version,
        "failures": [],
        "namespace": descriptor.namespace,
        "record_type": descriptor.record_type,
        "reference_present": descriptor.reference is not None,
        "status": "ok",
        "warnings": [
            "Descriptor validation does not prove declared metadata is true, authoritative, complete, or legally valid.",
            "Do not place secret, credential, private-key, or unnecessarily sensitive information in record attributes.",
        ],
    }


def _record_inspection(packet: Path) -> dict[str, object]:
    manifest_path = resolve_packet_manifest(packet)
    manifest = load_manifest(manifest_path)
    validation = validate_manifest_records(manifest)
    return {
        "failures": validation.failures,
        "limitations": validation.limitations,
        "manifest": str(manifest_path),
        "record_count": validation.record_count,
        "record_ids": validation.record_ids,
        "records": validation.records,
        "status": validation.status,
        "warnings": validation.warnings,
    }


def _custody_validation_summary(path: Path) -> dict[str, object]:
    descriptor = load_custody_descriptor(path)
    attributes = descriptor.attributes
    return {
        "actor_identifier": descriptor.actor["identifier"],
        "actor_namespace": descriptor.actor["namespace"],
        "attribute_count": len(attributes),
        "declared_time_present": descriptor.occurred_at is not None,
        "descriptor_schema_version": descriptor.schema_version,
        "event_type": descriptor.event_type,
        "failures": [],
        "location_present": descriptor.location is not None,
        "reference_present": descriptor.reference is not None,
        "status": "ok",
        "warnings": [
            "Descriptor validation does not prove that a custody event occurred or that an actor identity is verified.",
            "Do not place credentials, private keys, secrets, unnecessary personal information, or sensitive location information in custody descriptors.",
        ],
    }


def _custody_inspection(packet: Path) -> dict[str, object]:
    manifest_path = resolve_packet_manifest(packet)
    manifest = load_manifest(manifest_path)
    validation = validate_manifest_custody(manifest)
    return {
        "chain_head": validation.chain_head,
        "custody_schema_status": validation.custody_schema_status,
        "event_count": validation.event_count,
        "event_ids": validation.event_ids,
        "events": validation.events,
        "failures": validation.failures,
        "limitations": validation.limitations,
        "manifest": str(manifest_path),
        "status": validation.status,
        "warnings": validation.warnings,
    }


def _print_custody_validate_human(result: dict[str, object]) -> None:
    print(f"Status: {result.get('status')}")
    print(f"Descriptor schema: {result.get('descriptor_schema_version')}")
    print(f"Event type: {result.get('event_type')}")
    print(f"Actor namespace: {result.get('actor_namespace')}")
    print(f"Actor identifier: {result.get('actor_identifier')}")
    print(f"Declared time present: {'yes' if result.get('declared_time_present') else 'no'}")
    print(f"Location present: {'yes' if result.get('location_present') else 'no'}")
    print(f"Reference present: {'yes' if result.get('reference_present') else 'no'}")
    print(f"Attribute count: {result.get('attribute_count')}")
    for warning in result.get("warnings", []):
        print(f"WARN: {warning}")


def _print_custody_inspect_human(result: dict[str, object]) -> None:
    print(f"Status: {result.get('status')}")
    print(f"Custody schema: {result.get('custody_schema_status')}")
    print(f"Event count: {result.get('event_count')}")
    print(f"Chain head: {result.get('chain_head') or 'none'}")
    for event in result.get("events", []):
        if not isinstance(event, dict):
            continue
        actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
        attributes = event.get("attributes") if isinstance(event.get("attributes"), dict) else {}
        print(f"Event sequence: {event.get('sequence')}")
        print(f"Event ID: {event.get('event_id')}")
        print(f"Event type: {event.get('event_type')}")
        print(f"Declared actor: {actor.get('namespace')}/{actor.get('identifier')}" if isinstance(actor, dict) else "Declared actor: unknown")
        print(f"Declared time: {event.get('occurred_at') or 'none'}")
        print(f"Previous hash: {event.get('previous_event_hash')}")
        print(f"Event hash: {event.get('event_hash')}")
        print(f"Attribute count: {len(attributes) if isinstance(attributes, dict) else 0}")
    for failure in result.get("failures", []):
        print(f"FAIL: {failure}")
    for warning in result.get("warnings", []):
        print(f"WARN: {warning}")
    for limitation in result.get("limitations", []):
        print(f"LIMIT: {limitation}")


def _print_record_validate_human(result: dict[str, object]) -> None:
    print(f"Status: {result.get('status')}")
    print(f"Descriptor schema: {result.get('descriptor_schema_version')}")
    print(f"Record type: {result.get('record_type')}")
    print(f"Namespace: {result.get('namespace')}")
    print(f"Reference present: {'yes' if result.get('reference_present') else 'no'}")
    print(f"Attribute count: {result.get('attribute_count')}")
    for warning in result.get("warnings", []):
        print(f"WARN: {warning}")


def _print_record_inspect_human(result: dict[str, object]) -> None:
    print(f"Status: {result.get('status')}")
    print(f"Record count: {result.get('record_count')}")
    for record in result.get("records", []):
        if not isinstance(record, dict):
            continue
        subject = record.get("subject") if isinstance(record.get("subject"), dict) else {}
        attributes = record.get("attributes") if isinstance(record.get("attributes"), dict) else {}
        print(f"Record ID: {record.get('record_id')}")
        print(f"Record type: {record.get('record_type')}")
        print(f"Namespace: {record.get('namespace')}")
        print(f"Reference: {record.get('reference') if record.get('reference') is not None else 'none'}")
        print(f"Subject algorithm: {subject.get('algorithm') if isinstance(subject, dict) else 'unknown'}")
        print(f"Subject digest: {subject.get('digest') if isinstance(subject, dict) else 'unknown'}")
        print(f"Attribute count: {len(attributes) if isinstance(attributes, dict) else 0}")
    for failure in result.get("failures", []):
        print(f"FAIL: {failure}")
    for warning in result.get("warnings", []):
        print(f"WARN: {warning}")
    for limitation in result.get("limitations", []):
        print(f"LIMIT: {limitation}")


def _inspect_timestamp(packet: Path) -> dict[str, object]:
    manifest_path = resolve_packet_manifest(packet)
    manifest = load_manifest(manifest_path)
    result = inspect_manifest_timestamping(manifest)
    receipts = list_timestamp_receipts(manifest_path)
    diagnostics = timestamp_verification_diagnostics(manifest_path, DEFAULT_TIMESTAMP_POLICY)
    return {
        "failure_count": diagnostics["failure_count"],
        "manifest": str(manifest_path),
        "receipts": receipts,
        "receipt_count": len(receipts),
        "status": "ok",
        "timestamping": result,
        "timestamp_status": result.get("status", "missing"),
        "warning_count": diagnostics["warning_count"],
        "warnings": diagnostics.get("warnings", []),
    }


def _print_timestamp_human(result: dict[str, object]) -> None:
    timestamping = result.get("timestamping", {})
    if not isinstance(timestamping, dict):
        timestamping = {}
    print(f"Timestamp status: {result.get('timestamp_status')}")
    print(f"Adapter: {timestamping.get('adapter', 'none')}")
    print(f"Target digest: {timestamping.get('target_digest') or 'unknown'}")
    print(f"Created at: {timestamping.get('created_at') or 'unknown'}")
    receipts = result.get("receipts") or []
    print(f"Receipt count: {len(receipts) if isinstance(receipts, list) else 0}")
    if isinstance(receipts, list):
        for receipt in receipts:
            if not isinstance(receipt, dict):
                continue
            print(f"Receipt ID: {receipt.get('receipt_id') or 'unknown'}")
            print(f"Receipt type: {receipt.get('receipt_type') or 'unknown'}")
            print(f"Receipt status: {receipt.get('receipt_status') or 'unknown'}")
            print(f"Receipt SHA-256: {receipt.get('receipt_sha256') or 'unknown'}")
            for warning in receipt.get("warnings") or []:
                print(f"WARN: {warning}")
    for warning in result.get("warnings") or []:
        print(f"WARN: {warning}")


def _print_timestamp_verify_human(result: dict[str, object]) -> None:
    print(f"Timestamp verification status: {result.get('status')}")
    print(f"Policy: {result.get('policy')}")
    print(f"Timestamping status: {result.get('timestamping_status')}")
    print(f"Receipt count: {result.get('receipt_count')}")
    for check in result.get("checks") or []:
        if isinstance(check, dict):
            print(f"{check.get('status')}: {check.get('message')}")


def _print_verify_file_human(result: object) -> None:
    verdict = getattr(result, "verdict")
    if verdict == VERIFIED_INTEGRITY:
        print("PASS: file hash matches manifest.")
        print("PASS: file_id matches.")
        for warning in getattr(result, "warnings"):
            print(f"WARN: {warning}")
        for note in getattr(result, "notes"):
            if "path differs" in note.lower():
                print("WARN: current path differs from original recorded path.")
            print(f"NOTE: {note}")
        print("NOTE: copy or rename does not weaken byte-level proof.")
    else:
        for reason in getattr(result, "reasons"):
            print(f"FAIL: {reason}")
        print("FAIL: file hash does not match manifest.")
        print("FAIL: file_id mismatch.")


def _compare_files(file_a: Path, file_b: Path) -> dict[str, object]:
    a = inspect_file(file_a, include_blake3=False)
    b = inspect_file(file_b, include_blake3=False)
    same = a.sha256 == b.sha256
    return {
        "conclusion": "files are byte-identical" if same else "files are not byte-identical",
        "file_a": {"path": str(file_a), "sha256": a.sha256, "size_bytes": a.size_bytes},
        "file_b": {"path": str(file_b), "sha256": b.sha256, "size_bytes": b.size_bytes},
        "file_id_same": same,
        "paths_differ": str(file_a) != str(file_b),
        "status": "MATCH" if same else "DIFFERENT",
    }


def _print_compare_human(result: dict[str, object]) -> None:
    print(str(result["status"]))
    a = result["file_a"]
    b = result["file_b"]
    if isinstance(a, dict) and isinstance(b, dict):
        print(f"File A SHA-256: {a['sha256']}")
        print(f"File A size: {a['size_bytes']}")
        print(f"File B SHA-256: {b['sha256']}")
        print(f"File B size: {b['size_bytes']}")
    print(f"file_id same: {result['file_id_same']}")
    print(f"paths differ: {result['paths_differ']}")
    if result["file_id_same"]:
        print("PASS: files are byte-identical.")
        print("PASS: file_id matches.")
        print("NOTE: differing names or paths do not weaken byte-level integrity.")
    else:
        print("FAIL: files are not byte-identical.")
        print("FAIL: file_id differs.")
    print(f"Conclusion: {result['conclusion']}")


def _print_key_inspect_human(result: dict[str, object]) -> None:
    for item in result.get("keys", []):
        if not isinstance(item, dict):
            continue
        print(f"Purpose: {item['purpose']}")
        print(f"Private key path: {item['private_key_path']}")
        print(f"Private key exists: {'yes' if item['private_key_exists'] else 'no'}")
        print(f"Public key path: {item['public_key_path']}")
        print(f"Public key exists: {'yes' if item['public_key_exists'] else 'no'}")
        print(f"Allowed operations: {', '.join(item['allowed_operations'])}")
        print(f"Rotation events: {item.get('rotation_events', item.get('rotation_event_count', 0))}")
        print(f"Compromise events: {item.get('compromise_events', item.get('compromise_event_count', 0))}")
        print(f"Status: {item['status']}")
        warnings = item.get("warnings") or []
        if warnings:
            print("Warnings:")
            for warning in warnings:
                print(f"WARN: {warning}")
        print("")


def _print_key_check_human(result: dict[str, object]) -> None:
    print(f"OpenSSL available: {'yes' if result.get('openssl_available') else 'no'}")
    print(f"Status: {result.get('status')}")
    for item in result.get("keys", []):
        if not isinstance(item, dict):
            continue
        print(f"Purpose: {item['purpose']}")
        print(f"Rotation events: {item.get('rotation_events', item.get('rotation_event_count', 0))}")
        print(f"Compromise events: {item.get('compromise_events', item.get('compromise_event_count', 0))}")
        print(f"Status: {item['status']}")
        for warning in item.get("warnings") or []:
            print(f"WARN: {warning}")
        for failure in item.get("failures") or []:
            print(f"FAIL: {failure}")
        print("")


def _print_key_lifecycle_human(result: dict[str, object], action: str) -> None:
    print(f"Status: {result.get('status')}")
    print(f"Purpose: {result.get('purpose')}")
    if action == "create":
        print(f"Private key path: {result.get('private_key_path')}")
        print(f"Public key path: {result.get('public_key_path')}")
    elif action == "rotate":
        print(f"Old public key path: {result.get('old_public_key_path')}")
        print(f"New private key path: {result.get('new_private_key_path')}")
        print(f"New public key path: {result.get('new_public_key_path')}")
        print(f"Rotation log path: {result.get('rotation_log_path')}")
        print(f"Rotation event ID: {result.get('rotation_event_id')}")
    elif action == "compromise":
        print(f"Public key path: {result.get('public_key_path')}")
        print(f"Compromise log path: {result.get('compromise_log_path')}")
        print(f"Compromise event ID: {result.get('compromise_event_id')}")
    for warning in result.get("warnings") or []:
        print(f"WARN: {warning}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tohupono", description="Local-first proof protocol tooling.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_cmd = sub.add_parser("inspect", help="Inspect observed file identity.")
    inspect_cmd.add_argument("file")

    hash_cmd = sub.add_parser("hash", help="Hash a file.")
    hash_cmd.add_argument("file")
    hash_cmd.add_argument("--algorithm", choices=["sha256", "sha512", "blake3"], default="sha256")

    prove_cmd = sub.add_parser("prove", help="Create a proof packet.")
    prove_cmd.add_argument("file")
    prove_cmd.add_argument("--output", default="proof_packet")
    prove_cmd.add_argument("--include-payload", action="store_true")
    prove_cmd.add_argument("--concept", action="append", dest="concepts")
    prove_cmd.add_argument("--record-json", action="append", dest="record_json")
    prove_cmd.add_argument("--custody-json", action="append", dest="custody_json")
    prove_cmd.add_argument("--provenance-json", action="append", dest="provenance_json")

    concept_cmd = sub.add_parser("concept", help="Inspect Proof Concept registry entries.")
    concept_sub = concept_cmd.add_subparsers(dest="concept_command", required=True)
    concept_list_cmd = concept_sub.add_parser("list", help="List registered Proof Concepts.")
    concept_list_cmd.add_argument("--json", action="store_true")
    concept_inspect_cmd = concept_sub.add_parser("inspect", help="Inspect one registered Proof Concept.")
    concept_inspect_cmd.add_argument("concept_id")
    concept_inspect_cmd.add_argument("--json", action="store_true")

    record_cmd = sub.add_parser("record", help="Validate and inspect Proof of Records metadata.")
    record_sub = record_cmd.add_subparsers(dest="record_command", required=True)
    record_validate_cmd = record_sub.add_parser("validate", help="Validate a record descriptor JSON file.")
    record_validate_cmd.add_argument("descriptor")
    record_validate_cmd.add_argument("--json", action="store_true")
    record_inspect_cmd = record_sub.add_parser("inspect", help="Inspect records stored in a proof packet.")
    record_inspect_cmd.add_argument("packet")
    record_inspect_cmd.add_argument("--json", action="store_true")

    custody_cmd = sub.add_parser("custody", help="Validate and inspect Proof of Custody metadata.")
    custody_sub = custody_cmd.add_subparsers(dest="custody_command", required=True)
    custody_validate_cmd = custody_sub.add_parser("validate", help="Validate a custody descriptor JSON file.")
    custody_validate_cmd.add_argument("descriptor")
    custody_validate_cmd.add_argument("--json", action="store_true")
    custody_inspect_cmd = custody_sub.add_parser("inspect", help="Inspect custody events stored in a proof packet.")
    custody_inspect_cmd.add_argument("packet")
    custody_inspect_cmd.add_argument("--json", action="store_true")

    provenance_cmd = sub.add_parser("provenance", help="Validate and inspect Proof of Provenance metadata.")
    provenance_sub = provenance_cmd.add_subparsers(dest="provenance_command", required=True)
    provenance_validate_cmd = provenance_sub.add_parser("validate", help="Validate a provenance descriptor JSON file.")
    provenance_validate_cmd.add_argument("descriptor")
    provenance_validate_cmd.add_argument("--json", action="store_true")
    provenance_inspect_cmd = provenance_sub.add_parser("inspect", help="Inspect provenance edges stored in a proof packet.")
    provenance_inspect_cmd.add_argument("packet")
    provenance_inspect_cmd.add_argument("--json", action="store_true")

    verify_cmd = sub.add_parser("verify", help="Verify a packet, or verify a file with --proof.")
    verify_cmd.add_argument("target")
    verify_cmd.add_argument("--proof")
    verify_cmd.add_argument("--output")
    verify_cmd.add_argument("--json", action="store_true")

    verify_file_cmd = sub.add_parser("verify-file", help="Verify a file against a proof packet.")
    verify_file_cmd.add_argument("file")
    verify_file_cmd.add_argument("packet")
    verify_file_cmd.add_argument("--json", action="store_true")

    verify_chain_cmd = sub.add_parser("verify-chain", help="Verify an evidence chain JSONL file.")
    verify_chain_cmd.add_argument("evidence_chain")
    verify_chain_cmd.add_argument("--json", action="store_true")

    inspect_proof_cmd = sub.add_parser("inspect-proof", help="Inspect a proof manifest without a source file.")
    inspect_proof_cmd.add_argument("manifest")
    inspect_proof_cmd.add_argument("--json", action="store_true")

    compare_cmd = sub.add_parser("compare", help="Compare two files by byte digest.")
    compare_cmd.add_argument("file_a")
    compare_cmd.add_argument("file_b")
    compare_cmd.add_argument("--json", action="store_true")

    amend_cmd = sub.add_parser("amend", help="Create an amendment packet without mutating the original.")
    amend_cmd.add_argument("packet")
    amend_cmd.add_argument("--note", required=True)
    amend_cmd.add_argument("--json", action="store_true")

    audit_cmd = sub.add_parser("audit", help="Produce a technical proof packet audit.")
    audit_cmd.add_argument("packet")
    audit_cmd.add_argument("--key-directory", dest="key_directory")
    audit_cmd.add_argument("--json", action="store_true")

    timestamp_cmd = sub.add_parser("timestamp", help="Inspect and import timestamp proof metadata.")
    timestamp_sub = timestamp_cmd.add_subparsers(dest="timestamp_command", required=True)
    timestamp_inspect_cmd = timestamp_sub.add_parser(
        "inspect",
        description="Inspect packet timestamp proof metadata.",
        help="Inspect packet timestamp proof metadata.",
    )
    timestamp_inspect_cmd.add_argument("packet")
    timestamp_inspect_cmd.add_argument("--json", action="store_true")
    timestamp_import_cmd = timestamp_sub.add_parser(
        "import",
        description="Import an offline timestamp receipt without external verification.",
        help="Import an offline timestamp receipt.",
    )
    timestamp_import_cmd.add_argument("packet")
    timestamp_import_cmd.add_argument("receipt_file")
    timestamp_import_cmd.add_argument("--type", choices=TIMESTAMP_RECEIPT_TYPES, default="manual")
    timestamp_import_cmd.add_argument("--json", action="store_true")
    timestamp_verify_cmd = timestamp_sub.add_parser(
        "verify",
        description="Verify timestamp metadata and imported receipt integrity.",
        help="Verify timestamp metadata and imported receipt integrity.",
    )
    timestamp_verify_cmd.add_argument("packet")
    timestamp_verify_cmd.add_argument("--policy", choices=TIMESTAMP_POLICIES, default=DEFAULT_TIMESTAMP_POLICY)
    timestamp_verify_cmd.add_argument("--json", action="store_true")

    key_cmd = sub.add_parser("key", help="Manage local key purposes and lifecycle metadata.")
    key_sub = key_cmd.add_subparsers(dest="key_command", required=True)
    key_inspect_cmd = key_sub.add_parser("inspect", help="Inspect configured key purposes.")
    key_inspect_cmd.add_argument("--purpose", choices=key_purpose_names())
    key_inspect_cmd.add_argument("--output-dir")
    key_inspect_cmd.add_argument("--json", action="store_true")
    key_check_cmd = key_sub.add_parser("check", help="Check local key hygiene.")
    key_check_cmd.add_argument("--purpose", choices=key_purpose_names())
    key_check_cmd.add_argument("--output-dir")
    key_check_cmd.add_argument("--json", action="store_true")
    key_create_cmd = key_sub.add_parser("create", help="Create a local Ed25519 keypair for a purpose.")
    key_create_cmd.add_argument("--purpose", required=True, choices=key_purpose_names())
    key_create_cmd.add_argument("--output-dir")
    key_create_cmd.add_argument("--force", action="store_true")
    key_create_cmd.add_argument("--json", action="store_true")
    key_rotate_cmd = key_sub.add_parser("rotate", help="Rotate key material and record local metadata.")
    key_rotate_cmd.add_argument("--purpose", required=True, choices=key_purpose_names())
    key_rotate_cmd.add_argument("--reason", required=True)
    key_rotate_cmd.add_argument("--output-dir")
    key_rotate_cmd.add_argument("--json", action="store_true")
    key_compromise_cmd = key_sub.add_parser("compromise", help="Record local key compromise metadata.")
    key_compromise_cmd.add_argument("--purpose", required=True, choices=key_purpose_names())
    key_compromise_cmd.add_argument("--reason", required=True)
    key_compromise_cmd.add_argument("--output-dir")
    key_compromise_cmd.add_argument("--json", action="store_true")

    report_cmd = sub.add_parser("report", help="Generate a signed PDF report.")
    report_cmd.add_argument("--proof", required=True)
    report_cmd.add_argument("--format", choices=["pdf"], default="pdf")
    report_cmd.add_argument("--output", required=True)
    report_cmd.add_argument("--community", action="store_true")
    report_cmd.add_argument("--report-key", default="keys/report_signing_key.pem")

    return parser


def run(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            _print_json(inspect_file(Path(args.file)).to_dict())
            return EXIT_SUCCESS
        elif args.command == "hash":
            try:
                digest = hash_file(Path(args.file), args.algorithm)
            except Blake3UnavailableError as exc:
                print(str(exc), file=sys.stderr)
                return EXIT_USER_ERROR
            print(digest)
            return EXIT_SUCCESS
        elif args.command == "prove":
            manifest = create_proof_packet(
                Path(args.file),
                Path(args.output),
                args.include_payload,
                concept_ids=args.concepts,
                record_descriptor_paths=[Path(item) for item in (args.record_json or [])],
                custody_descriptor_paths=[Path(item) for item in (args.custody_json or [])],
                provenance_descriptor_paths=[Path(item) for item in (args.provenance_json or [])],
            )
            _print_json({"proof_id": manifest.proof_id, "manifest": str(Path(args.output) / "manifest.json")})
            return EXIT_SUCCESS
        elif args.command == "concept":
            if args.concept_command == "list":
                records = concept_list_records()
                if args.json:
                    _print_json({"concepts": records, "status": "ok"})
                else:
                    _print_concept_list_human(records)
                return EXIT_SUCCESS
            if args.concept_command == "inspect":
                record = inspect_concept_record(args.concept_id)
                if args.json:
                    _print_json({"concept": record, "status": "ok"})
                else:
                    _print_concept_inspect_human(record)
                return EXIT_SUCCESS
            parser.error("Unknown concept command")
        elif args.command == "record":
            if args.record_command == "validate":
                result = _record_validation_summary(Path(args.descriptor))
                if args.json:
                    _print_json(result)
                else:
                    _print_record_validate_human(result)
                return EXIT_SUCCESS
            if args.record_command == "inspect":
                result = _record_inspection(Path(args.packet))
                if args.json:
                    _print_json(result)
                else:
                    _print_record_inspect_human(result)
                return EXIT_VERIFICATION_FAILED if result["status"] == "fail" else EXIT_SUCCESS
            parser.error("Unknown record command")
        elif args.command == "custody":
            if args.custody_command == "validate":
                result = _custody_validation_summary(Path(args.descriptor))
                if args.json:
                    _print_json(result)
                else:
                    _print_custody_validate_human(result)
                return EXIT_SUCCESS
            if args.custody_command == "inspect":
                result = _custody_inspection(Path(args.packet))
                if args.json:
                    _print_json(result)
                else:
                    _print_custody_inspect_human(result)
                return EXIT_VERIFICATION_FAILED if result["status"] == "fail" else EXIT_SUCCESS
            parser.error("Unknown custody command")
        elif args.command == "provenance":
            if args.provenance_command == "validate":
                result = _provenance_validation_summary(Path(args.descriptor))
                if args.json:
                    _print_json(result)
                else:
                    _print_provenance_validate_human(result)
                return EXIT_SUCCESS
            if args.provenance_command == "inspect":
                result = _provenance_inspection(Path(args.packet))
                if args.json:
                    _print_json(result)
                else:
                    _print_provenance_inspect_human(result)
                return EXIT_VERIFICATION_FAILED if result["status"] == "fail" else EXIT_SUCCESS
            parser.error("Unknown provenance command")
        elif args.command == "verify":
            if args.proof:
                result = verify_file(Path(args.target), Path(args.proof))
                write_verdict(Path(args.proof), result)
                if args.output:
                    write_markdown(Path(args.output), result)
                _print_json(result.to_cli_json() if args.json else result.to_dict())
                return EXIT_SUCCESS if result.verdict == VERIFIED_INTEGRITY else EXIT_VERIFICATION_FAILED
            packet_result = packet_diagnostics(Path(args.target))
            if args.output:
                Path(args.output).write_text(canonical_json_text(packet_result) + "\n", encoding="utf-8")
            if args.json:
                _print_json(packet_result)
            else:
                _print_packet_checks(packet_result)
            return EXIT_SUCCESS if packet_result["status"] != "fail" else EXIT_VERIFICATION_FAILED
        elif args.command == "verify-file":
            manifest_path = resolve_packet_manifest(Path(args.packet))
            result = verify_file(Path(args.file), manifest_path)
            write_verdict(manifest_path, result)
            if args.json:
                _print_json(result.to_cli_json())
            else:
                _print_verify_file_human(result)
            return EXIT_SUCCESS if result.verdict == VERIFIED_INTEGRITY else EXIT_VERIFICATION_FAILED
        elif args.command == "compare":
            result = _compare_files(Path(args.file_a), Path(args.file_b))
            if args.json:
                _print_json(result)
            else:
                _print_compare_human(result)
            return EXIT_SUCCESS if result["file_id_same"] else EXIT_VERIFICATION_FAILED
        elif args.command == "verify-chain":
            result = evidence_chain_diagnostics(Path(args.evidence_chain))
            if args.json:
                _print_json(result)
            else:
                _print_verify_chain_human(result)
            status = result["status"]
            if status == "valid":
                return EXIT_SUCCESS
            if status == "missing":
                return EXIT_USER_ERROR
            if status == "error":
                return EXIT_INTERNAL_ERROR
            return EXIT_VERIFICATION_FAILED
        elif args.command == "inspect-proof":
            result = inspect_proof_manifest(Path(args.manifest))
            if args.json:
                _print_json(result)
            else:
                _print_inspect_proof_human(result)
            return EXIT_SUCCESS
        elif args.command == "amend":
            out = create_amendment(Path(args.packet), args.note)
            result = {"amendment": str(out), "status": "created"}
            if args.json:
                _print_json(result)
            else:
                print(f"PASS: amendment packet created at {out}")
                print("PASS: original packet was not modified.")
            return EXIT_SUCCESS
        elif args.command == "audit":
            key_directory = Path(args.key_directory) if args.key_directory else None
            result = packet_diagnostics(Path(args.packet), key_directory=key_directory)
            if args.json:
                _print_json(result)
            else:
                _print_packet_checks(result)
            return EXIT_SUCCESS if result["status"] != "fail" else EXIT_VERIFICATION_FAILED
        elif args.command == "timestamp":
            if args.timestamp_command == "inspect":
                result = _inspect_timestamp(Path(args.packet))
                if args.json:
                    _print_json(result)
                else:
                    _print_timestamp_human(result)
                return EXIT_SUCCESS
            if args.timestamp_command == "import":
                result = import_timestamp_receipt(Path(args.packet), Path(args.receipt_file), args.type)
                if args.json:
                    _print_json(result)
                else:
                    receipt = result.get("receipt", {})
                    print("PASS: timestamp receipt import recorded.")
                    if isinstance(receipt, dict):
                        print(f"Receipt ID: {receipt.get('receipt_id')}")
                        print(f"Receipt type: {receipt.get('receipt_type')}")
                        print(f"Receipt status: {receipt.get('receipt_status')}")
                        print(f"Receipt SHA-256: {receipt.get('receipt_sha256')}")
                        for warning in receipt.get("warnings") or []:
                            print(f"WARN: {warning}")
                return EXIT_SUCCESS
            if args.timestamp_command == "verify":
                result = timestamp_verification_diagnostics(Path(args.packet), args.policy)
                if args.json:
                    _print_json(result)
                else:
                    _print_timestamp_verify_human(result)
                return EXIT_VERIFICATION_FAILED if result["status"] == "fail" else EXIT_SUCCESS
            parser.error("Unknown timestamp command")
        elif args.command == "key":
            if args.key_command == "inspect":
                output_dir = Path(args.output_dir) if args.output_dir else None
                result = inspect_keys(args.purpose, output_dir=output_dir)
                if args.json:
                    _print_json(result)
                else:
                    _print_key_inspect_human(result)
                return EXIT_SUCCESS
            if args.key_command == "check":
                output_dir = Path(args.output_dir) if args.output_dir else None
                result = check_keys(args.purpose, output_dir=output_dir)
                if args.json:
                    _print_json(result)
                else:
                    _print_key_check_human(result)
                return EXIT_VERIFICATION_FAILED if result["status"] == "fail" else EXIT_SUCCESS
            if args.key_command == "create":
                output_dir = Path(args.output_dir) if args.output_dir else None
                result = create_key(args.purpose, output_dir=output_dir, force=args.force)
                if args.json:
                    _print_json(result)
                else:
                    _print_key_lifecycle_human(result, "create")
                return EXIT_SUCCESS
            if args.key_command == "rotate":
                output_dir = Path(args.output_dir) if args.output_dir else None
                result = rotate_key(args.purpose, args.reason, output_dir=output_dir)
                if args.json:
                    _print_json(result)
                else:
                    _print_key_lifecycle_human(result, "rotate")
                return EXIT_SUCCESS
            if args.key_command == "compromise":
                output_dir = Path(args.output_dir) if args.output_dir else None
                result = mark_key_compromised(args.purpose, args.reason, output_dir=output_dir)
                if args.json:
                    _print_json(result)
                else:
                    _print_key_lifecycle_human(result, "compromise")
                return EXIT_SUCCESS
            parser.error("Unknown key command")
        elif args.command == "report":
            sig_path = generate_report(
                proof=Path(args.proof),
                output=Path(args.output),
                report_key=Path(args.report_key),
                community=args.community,
                fmt=args.format,
            )
            _print_json({"report": args.output, "signature": str(sig_path)})
            return EXIT_SUCCESS
        else:
            parser.error("Unknown command")
    except FileNotFoundError as exc:
        missing_path = exc.filename or str(exc)
        return _emit_error(
            _missing_path_code(args.command, str(missing_path)),
            str(exc),
            json_mode=_json_mode(args),
            exit_code=EXIT_USER_ERROR,
        )
    except json.JSONDecodeError as exc:
        code = "INVALID_JSONL" if args.command == "verify-chain" else "INVALID_MANIFEST"
        return _emit_error(code, str(exc), json_mode=_json_mode(args), exit_code=EXIT_USER_ERROR)
    except TohuPonoError as exc:
        return _emit_error("INVALID_ARGUMENT", str(exc), json_mode=_json_mode(args), exit_code=EXIT_USER_ERROR)
    except ValueError as exc:
        return _emit_error("INVALID_ARGUMENT", str(exc), json_mode=_json_mode(args), exit_code=EXIT_USER_ERROR)
    except KeyConflictError as exc:
        return _emit_error("KEY_EXISTS", str(exc), json_mode=_json_mode(args), exit_code=EXIT_VERIFICATION_FAILED)
    except TimestampReceiptConflictError as exc:
        return _emit_error("RECEIPT_EXISTS", str(exc), json_mode=_json_mode(args), exit_code=EXIT_VERIFICATION_FAILED)
    except KeyErrorWithAction as exc:
        return _emit_error("SIGNATURE_ERROR", str(exc), json_mode=_json_mode(args), exit_code=EXIT_INTERNAL_ERROR)
    except Exception as exc:
        return _emit_error("INTERNAL_ERROR", str(exc), json_mode=_json_mode(args), exit_code=EXIT_INTERNAL_ERROR)
    return EXIT_SUCCESS


def main(argv: Sequence[str] | None = None) -> None:
    raise SystemExit(run(argv))
