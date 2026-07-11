from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from tohupono import __version__
from tohupono.concepts.execution import (
    build_proof_concepts_declaration,
    evaluate_declared_concepts,
    proof_concept_seed,
    validate_requested_concepts,
)
from tohupono.core.canonical_json import canonical_json_bytes, canonical_json_text
from tohupono.core.file_identity import FileIdentity, inspect_file
from tohupono.timestamping.model import (
    DEFAULT_TIMESTAMP_POLICY,
    LOCAL_TIMESTAMP_WARNING,
    MISSING_TIMESTAMP_WARNING,
    TIMESTAMP_POLICIES,
    TIMESTAMP_RECEIPT_STATUSES,
    TIMESTAMP_RECEIPT_TYPES,
    UNVERIFIED_RECEIPT_WARNING,
    TimestampReceipt,
    TimestampReceiptConflictError,
    inspect_manifest_timestamping,
    local_timestamp_proof,
    make_receipt_id,
)
from tohupono.security.limits import MAX_RECEIPT_BYTES, MAX_RECEIPT_METADATA_BYTES
from tohupono.security.paths import safe_child_path
from tohupono.trust.keys import (
    DEFAULT_MANIFEST_KEY,
    DEFAULT_MANIFEST_PUBLIC_KEY,
    sign_amendment_bytes,
    sign_manifest_bytes,
)

SCHEMA_VERSION = "tohupono.proof_manifest.v0.1"
MANIFEST_VERSION = "0.4.0"
GENESIS_EVENT_HASH = "GENESIS"
CHAIN_STATUS_VALID = "valid"
CHAIN_STATUS_MISSING = "missing"
CHAIN_STATUS_INVALID = "invalid"
CHAIN_STATUS_ERROR = "error"
ChainStatus = Literal["valid", "missing", "invalid", "error"]
PacketStatus = Literal["pass", "warn", "fail"]


@dataclass(frozen=True)
class ProofManifest:
    schema_version: str
    manifest_version: str
    proof_id: str
    sealed_at_utc: str
    tool: dict[str, str]
    file: dict[str, object]
    claims: list[dict[str, object]]
    proof_concepts: dict[str, object]
    evidence: dict[str, list[dict[str, object]]]
    timestamping: dict[str, object]
    trust_policy: dict[str, str]
    warnings: list[str]
    community: bool
    identifiers: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def proof_id_seed(
    identity: FileIdentity,
    sealed_at_utc: str,
    concept_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    concepts = validate_requested_concepts(list(concept_ids)) if concept_ids is not None else ()
    seed = {
        "file_id": identity.sha256,
        "file_sha256": identity.sha256,
        "file_size": identity.size_bytes,
        "manifest_version": MANIFEST_VERSION,
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
    }
    if concepts:
        seed["proof_concepts"] = proof_concept_seed(concepts)
    return seed


def make_proof_id(
    identity: FileIdentity,
    sealed_at_utc: str,
    concept_ids: tuple[str, ...] | None = None,
) -> str:
    digest = hashlib.sha256(canonical_json_bytes(proof_id_seed(identity, sealed_at_utc, concept_ids))).hexdigest()
    return f"tp_{digest[:32]}"


def event_hash(event: dict[str, object]) -> str:
    event_without_hash = {key: value for key, value in event.items() if key != "event_hash"}
    return hashlib.sha256(canonical_json_bytes(event_without_hash)).hexdigest()


def build_evidence_event(
    *,
    event_type: str,
    timestamp: str,
    actor: str,
    file_sha256: str,
    previous_event_hash: str,
) -> dict[str, object]:
    payload = {
        "actor": actor,
        "event_type": event_type,
        "file_sha256": file_sha256,
        "previous_event_hash": previous_event_hash,
        "timestamp": timestamp,
    }
    event: dict[str, object] = {
        "actor": actor,
        "event_type": event_type,
        "file_sha256": file_sha256,
        "previous_event_hash": previous_event_hash,
        "timestamp": timestamp,
    }
    event["event_id"] = hashlib.sha256(
        previous_event_hash.encode("utf-8") + canonical_json_bytes(payload)
    ).hexdigest()
    event["event_hash"] = event_hash(event)
    return event


def verify_evidence_chain(path: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    previous_hash = GENESIS_EVENT_HASH
    event_count = 0
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        event_count += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"event_{index}_invalid_json")
            continue
        if not isinstance(event, dict):
            errors.append(f"event_{index}_not_object")
            continue
        required = {
            "actor",
            "event_id",
            "event_type",
            "timestamp",
            "file_sha256",
            "previous_event_hash",
            "event_hash",
        }
        missing = sorted(required - set(event))
        if missing:
            errors.append(f"event_{index}_missing_{','.join(missing)}")
            continue
        if event["previous_event_hash"] != previous_hash:
            errors.append(f"event_{index}_previous_hash_mismatch")
        expected_event_id = hashlib.sha256(
            str(event["previous_event_hash"]).encode("utf-8")
            + canonical_json_bytes(
                {
                    "actor": event["actor"],
                    "event_type": event["event_type"],
                    "file_sha256": event["file_sha256"],
                    "previous_event_hash": event["previous_event_hash"],
                    "timestamp": event["timestamp"],
                }
            )
        ).hexdigest()
        if event["event_id"] != expected_event_id:
            errors.append(f"event_{index}_event_id_mismatch")
        expected_hash = event_hash(event)
        if event["event_hash"] != expected_hash:
            errors.append(f"event_{index}_hash_mismatch")
        previous_hash = str(event.get("event_hash"))
    if event_count == 0:
        errors.append("evidence_chain_empty")
    return not errors, errors


def evidence_chain_diagnostics(path: Path) -> dict[str, object]:
    if not path.exists():
        return {
            "status": CHAIN_STATUS_MISSING,
            "path": str(path),
            "errors": ["evidence_chain_missing"],
            "event_count": 0,
        }
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        ok, errors = verify_evidence_chain(path)
    except OSError as exc:
        return {
            "status": CHAIN_STATUS_ERROR,
            "path": str(path),
            "errors": [str(exc)],
            "event_count": 0,
        }
    event_count = sum(1 for line in lines if line.strip())
    return {
        "status": CHAIN_STATUS_VALID if ok else CHAIN_STATUS_INVALID,
        "path": str(path),
        "errors": errors,
        "event_count": event_count,
    }


def build_manifest(
    identity: FileIdentity,
    sealed_at_utc: str,
    concept_ids: tuple[str, ...] | None = None,
) -> ProofManifest:
    selected_concepts = validate_requested_concepts(list(concept_ids) if concept_ids is not None else None)
    warnings: list[str] = []
    if identity.blake3 is None:
        warnings.append("BLAKE3 unavailable; optional BLAKE3 digest was not recorded.")
    proof_id = make_proof_id(identity, sealed_at_utc, selected_concepts)

    return ProofManifest(
        schema_version=SCHEMA_VERSION,
        manifest_version=MANIFEST_VERSION,
        proof_id=proof_id,
        sealed_at_utc=sealed_at_utc,
        tool={"name": "tohupono", "version": __version__},
        file=identity.to_dict(),
        claims=[
            {
                "claim_id": "claim_001",
                "type": "received_from_user",
                "statement": "User supplied file for proof sealing.",
                "issuer": "local_user",
                "evidence_refs": [],
            }
        ],
        proof_concepts=build_proof_concepts_declaration(identity.sha256, selected_concepts),
        evidence={
            "hashes": [],
            "timestamps": [],
            "signatures": [],
            "c2pa": [],
            "transparency_logs": [],
            "custody_events": [],
        },
        timestamping={},
        trust_policy={"policy_id": "local_default", "policy_digest": "unconfigured"},
        warnings=warnings,
        community=False,
        identifiers={
            "file_id": identity.sha256,
            "proof_id": proof_id,
        },
    )


def write_json(path: Path, value: Any) -> None:
    path.write_text(canonical_json_text(value) + "\n", encoding="utf-8")


def sha256_text(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_manifest_for_id(manifest: dict[str, Any]) -> dict[str, Any]:
    normalized = json.loads(canonical_json_text(manifest))
    normalized.pop("signatures", None)
    normalized.pop("timestamping", None)
    identifiers = normalized.get("identifiers")
    if isinstance(identifiers, dict):
        identifiers.pop("manifest_id", None)
        identifiers.pop("packet_id", None)
        identifiers.pop("evidence_chain_root", None)
    return normalized


def make_manifest_id(manifest: dict[str, Any]) -> str:
    return sha256_text(canonical_json_bytes(canonical_manifest_for_id(manifest)))


def evidence_chain_root(path: Path) -> str:
    previous_hash = GENESIS_EVENT_HASH
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if isinstance(event, dict):
            previous_hash = str(event.get("event_hash", previous_hash))
    return previous_hash


def make_packet_id(manifest_id: str, chain_root: str) -> str:
    return sha256_text(
        canonical_json_bytes({"evidence_chain_root": chain_root, "manifest_id": manifest_id})
    )


def resolve_packet_manifest(packet: Path) -> Path:
    if packet.is_dir():
        return packet / "manifest.json"
    return packet


def packet_dir(packet: Path) -> Path:
    manifest = resolve_packet_manifest(packet)
    return manifest.parent


def timestamp_receipts_dir(packet: Path) -> Path:
    return packet_dir(packet) / "timestamp_receipts"


def _assert_can_create_packet(output: Path) -> None:
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"Refusing to overwrite existing proof packet: {output}")


def create_proof_packet(
    source: Path,
    output: Path,
    include_payload: bool = False,
    manifest_key: Path = DEFAULT_MANIFEST_KEY,
    manifest_public_key: Path = DEFAULT_MANIFEST_PUBLIC_KEY,
    sealed_at_utc: str | None = None,
    concept_ids: list[str] | tuple[str, ...] | None = None,
) -> ProofManifest:
    identity = inspect_file(source)
    sealed_at = sealed_at_utc or utc_now_iso()
    selected_concepts = validate_requested_concepts(list(concept_ids) if concept_ids is not None else None)
    manifest = build_manifest(identity, sealed_at, selected_concepts)
    _assert_can_create_packet(output)
    output.mkdir(parents=True, exist_ok=True)

    manifest_path = output / "manifest.json"
    manifest_dict = manifest.to_dict()
    manifest_dict["timestamping"] = local_timestamp_proof(identity.sha256, sealed_at).to_dict()
    sealed_event = build_evidence_event(
        event_type="sealed",
        timestamp=sealed_at,
        actor="tohupono",
        file_sha256=identity.sha256,
        previous_event_hash=GENESIS_EVENT_HASH,
    )
    chain_path = output / "evidence_chain.jsonl"
    chain_path.write_text(canonical_json_text(sealed_event) + "\n", encoding="utf-8")
    manifest_id = make_manifest_id(manifest_dict)
    chain_root = evidence_chain_root(chain_path)
    packet_id = make_packet_id(manifest_id, chain_root)
    manifest_dict["identifiers"] = {
        **dict(manifest_dict.get("identifiers", {})),
        "evidence_chain_root": chain_root,
        "file_id": identity.sha256,
        "manifest_id": manifest_id,
        "packet_id": packet_id,
        "proof_id": manifest.proof_id,
    }
    write_json(manifest_path, manifest_dict)
    signatures_dir = output / "signatures"
    signatures_dir.mkdir(exist_ok=True)
    signature, public_key = sign_manifest_bytes(
        manifest_path.read_bytes(),
        private_key=manifest_key,
        public_key=manifest_public_key,
    )
    (signatures_dir / "manifest.sig").write_bytes(signature)
    (signatures_dir / "manifest.pub").write_bytes(public_key)
    hashes = [
        f"sha256  {identity.sha256}",
        f"sha512  {identity.sha512}",
    ]
    if identity.blake3:
        hashes.append(f"blake3  {identity.blake3}")
    (output / "hashes.txt").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    write_json(output / "metadata.json", identity.to_dict())
    write_json(output / "warnings.json", {"warnings": manifest.warnings})

    if include_payload:
        payload_dir = output / "payload"
        payload_dir.mkdir(exist_ok=True)
        shutil.copy2(source, payload_dir / source.name)

    return manifest


def load_manifest(path: Path) -> dict[str, Any]:
    if path.exists() and path.stat().st_size > MAX_RECEIPT_METADATA_BYTES * 4:
        raise ValueError("Structured proof input exceeds configured size limit.")
    return json.loads(path.read_text(encoding="utf-8"))


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def list_timestamp_receipts(packet: Path) -> list[dict[str, object]]:
    receipts_dir = timestamp_receipts_dir(packet)
    if not receipts_dir.exists():
        return []
    receipts: list[dict[str, object]] = []
    for receipt_path in sorted(receipts_dir.glob("receipt_*.json")):
        try:
            if receipt_path.stat().st_size > MAX_RECEIPT_METADATA_BYTES:
                raise ValueError("timestamp receipt metadata exceeds configured size limit")
            receipt = load_manifest(receipt_path)
        except (OSError, ValueError, json.JSONDecodeError):
            receipts.append(
                {
                    "receipt_id": receipt_path.stem.removeprefix("receipt_"),
                    "receipt_path": str(receipt_path),
                    "receipt_status": "invalid",
                    "warnings": ["Timestamp receipt metadata could not be read."],
                }
            )
            continue
        if isinstance(receipt, dict):
            receipts.append(receipt)
    return receipts


def _resolve_stored_receipt_path(proof_dir: Path, receipt_path_value: object) -> Path:
    if not isinstance(receipt_path_value, str) or not receipt_path_value:
        raise ValueError("timestamp receipt path is empty")
    raw = Path(receipt_path_value)
    if raw.is_absolute():
        raise ValueError("timestamp receipt path must be relative")
    if any(part in {"", ".."} for part in raw.parts):
        raise ValueError("timestamp receipt path contains traversal")

    receipts_root = proof_dir / "timestamp_receipts"
    if receipts_root.exists() and receipts_root.is_symlink():
        raise ValueError("timestamp receipt directory must not be a symlink")

    raw_parts = raw.parts
    if raw_parts and raw_parts[0] == "timestamp_receipts":
        raw = Path(*raw_parts[1:]) if len(raw_parts) > 1 else Path("")
    if not raw.parts:
        raise ValueError("timestamp receipt path is empty")

    receipts_root_resolved = receipts_root.resolve(strict=False)
    receipt_path = safe_child_path(receipts_root, raw)
    current = receipts_root
    for part in receipt_path.relative_to(receipts_root_resolved).parts[:-1]:
        current = current / part
        if current.exists() and current.is_symlink():
            raise ValueError("timestamp receipt path contains a symlinked parent")
    if receipt_path.exists() and receipt_path.is_symlink():
        raise ValueError("timestamp receipt file must not be a symlink")
    return receipt_path


def import_timestamp_receipt(packet: Path, receipt_file: Path, receipt_type: str = "manual") -> dict[str, object]:
    if receipt_type not in TIMESTAMP_RECEIPT_TYPES:
        raise ValueError(f"Unsupported timestamp receipt type: {receipt_type}")
    manifest_path = resolve_packet_manifest(packet)
    manifest = load_manifest(manifest_path)
    file_info = manifest.get("file", {})
    if not isinstance(file_info, dict) or not file_info.get("sha256"):
        raise ValueError("Proof manifest does not contain a target file digest.")
    if not receipt_file.exists() or not receipt_file.is_file():
        raise FileNotFoundError(str(receipt_file))
    if receipt_file.stat().st_size > MAX_RECEIPT_BYTES:
        raise ValueError("Timestamp receipt exceeds configured size limit.")

    target_digest = str(file_info["sha256"])
    receipt_sha256 = _file_sha256(receipt_file)
    receipt_size = receipt_file.stat().st_size
    receipt_id = make_receipt_id(
        receipt_type=receipt_type,
        receipt_sha256=receipt_sha256,
        receipt_size=receipt_size,
        target_digest=target_digest,
    )
    receipts_dir = manifest_path.parent / "timestamp_receipts"
    receipt_metadata_path = receipts_dir / f"receipt_{receipt_id}.json"
    stored_receipt_path = receipts_dir / f"receipt_{receipt_id}.bin"
    if receipt_metadata_path.exists() or stored_receipt_path.exists():
        raise TimestampReceiptConflictError("Refusing to overwrite existing timestamp receipt import.")

    receipts_dir.mkdir(exist_ok=True)
    shutil.copyfile(receipt_file, stored_receipt_path)
    adapter_type = receipt_type if receipt_type in {"manual", "opentimestamps", "rfc3161"} else "none"
    record = TimestampReceipt(
        receipt_id=receipt_id,
        receipt_type=receipt_type,  # type: ignore[arg-type]
        receipt_path=str(stored_receipt_path.relative_to(manifest_path.parent)),
        receipt_sha256=receipt_sha256,
        receipt_size=receipt_size,
        receipt_format=receipt_file.suffix.lower().lstrip(".") or "unknown",
        receipt_status="unverified",
        adapter_type=adapter_type,  # type: ignore[arg-type]
        target_digest=target_digest,
        imported_at=utc_now_iso(),
        warnings=[UNVERIFIED_RECEIPT_WARNING],
    ).to_dict()
    write_json(receipt_metadata_path, record)
    return {
        "receipt": record,
        "receipt_metadata_path": str(receipt_metadata_path),
        "stored_receipt_path": str(stored_receipt_path),
        "status": "ok",
    }


def timestamp_verification_diagnostics(
    packet: Path,
    policy: str = DEFAULT_TIMESTAMP_POLICY,
) -> dict[str, Any]:
    if policy not in TIMESTAMP_POLICIES:
        raise ValueError(f"Unsupported timestamp policy: {policy}")
    manifest_path = resolve_packet_manifest(packet)
    proof_dir = manifest_path.parent
    manifest = load_manifest(manifest_path)
    file_info = manifest.get("file", {})
    if not isinstance(file_info, dict) or not file_info.get("sha256"):
        raise ValueError("Proof manifest does not contain a target file digest.")
    manifest_digest = str(file_info["sha256"])
    timestamping = inspect_manifest_timestamping(manifest)
    timestamp_status = str(timestamping.get("status", "missing"))
    warnings: list[str] = []
    failures: list[str] = []
    checks: list[dict[str, str]] = []

    if timestamp_status == "anchored":
        checks.append({"status": "PASS", "message": "timestamp proof is externally anchored."})
    elif timestamp_status == "local_only":
        message = "timestamp is local-only and not externally anchored."
        if policy == "strict_external":
            failures.append("timestamp_local_only")
            checks.append({"status": "FAIL", "message": message})
        else:
            warnings.append(LOCAL_TIMESTAMP_WARNING)
            checks.append({"status": "WARN", "message": message})
    elif timestamp_status == "missing":
        message = "no timestamp proof is present."
        if policy == "strict_external":
            failures.append("timestamp_missing")
            checks.append({"status": "FAIL", "message": message})
        else:
            warnings.append(MISSING_TIMESTAMP_WARNING)
            checks.append({"status": "WARN", "message": message})
    else:
        message = f"Timestamp status is {timestamp_status}."
        failures.append(f"timestamp_{timestamp_status}")
        checks.append({"status": "FAIL", "message": message})

    receipts = list_timestamp_receipts(manifest_path)
    seen_receipt_ids: set[str] = set()
    verified_external_receipt = False
    required_fields = {
        "adapter_type",
        "imported_at",
        "receipt_id",
        "receipt_path",
        "receipt_sha256",
        "receipt_size",
        "receipt_status",
        "receipt_type",
        "target_digest",
    }
    for index, receipt in enumerate(receipts, start=1):
        receipt_id = str(receipt.get("receipt_id") or f"receipt_{index}")
        missing = sorted(required_fields - set(receipt))
        if missing:
            failures.append(f"{receipt_id}_metadata_missing_fields")
            checks.append(
                {
                    "status": "FAIL",
                    "message": f"timestamp receipt metadata missing required fields: {', '.join(missing)}.",
                }
            )
            continue
        if receipt_id in seen_receipt_ids:
            failures.append("timestamp_receipt_duplicate_id")
            checks.append({"status": "FAIL", "message": "duplicate timestamp receipt_id detected."})
        seen_receipt_ids.add(receipt_id)
        if receipt.get("receipt_type") not in TIMESTAMP_RECEIPT_TYPES:
            failures.append(f"{receipt_id}_unsupported_receipt_type")
            checks.append({"status": "FAIL", "message": "unsupported timestamp receipt type."})
        if receipt.get("receipt_status") not in TIMESTAMP_RECEIPT_STATUSES:
            failures.append(f"{receipt_id}_invalid_receipt_status")
            checks.append({"status": "FAIL", "message": "timestamp receipt status is invalid."})
        if str(receipt.get("target_digest")) != manifest_digest:
            failures.append(f"{receipt_id}_target_digest_mismatch")
            checks.append(
                {
                    "status": "FAIL",
                    "message": "timestamp receipt target digest does not match packet manifest digest.",
                }
            )
        try:
            receipt_path = _resolve_stored_receipt_path(proof_dir, receipt.get("receipt_path"))
        except ValueError:
            failures.append(f"{receipt_id}_stored_file_path_invalid")
            checks.append({"status": "FAIL", "message": "timestamp receipt path is invalid or escapes packet storage."})
            continue
        if not receipt_path.exists():
            failures.append(f"{receipt_id}_stored_file_missing")
            checks.append({"status": "FAIL", "message": "timestamp receipt file is missing from packet storage."})
        elif not receipt_path.is_file():
            failures.append(f"{receipt_id}_stored_file_not_regular")
            checks.append({"status": "FAIL", "message": "timestamp receipt file is not a regular file."})
        else:
            actual_sha256 = _file_sha256(receipt_path)
            if str(receipt.get("receipt_sha256")) != actual_sha256:
                failures.append(f"{receipt_id}_sha256_mismatch")
                checks.append({"status": "FAIL", "message": "timestamp receipt SHA-256 does not match stored bytes."})
        if receipt.get("receipt_status") == "verified":
            verified_external_receipt = True
        elif receipt.get("receipt_status") == "unverified":
            message = "imported timestamp receipt is present but not externally verified by TohuPono."
            if policy == "strict_external":
                failures.append(f"{receipt_id}_unverified_under_strict_external")
                checks.append({"status": "FAIL", "message": message})
            else:
                warnings.append(UNVERIFIED_RECEIPT_WARNING)
                checks.append({"status": "WARN", "message": message})

    if policy == "strict_external" and timestamp_status != "anchored" and not verified_external_receipt:
        failures.append("strict_external_timestamp_missing")
        checks.append({"status": "FAIL", "message": "strict_external policy requires a verified external timestamp."})

    status = "fail" if failures else ("warn" if warnings else "pass")
    return {
        "checks": checks,
        "failure_count": len(failures),
        "failures": failures,
        "policy": policy,
        "receipt_count": len(receipts),
        "receipts": receipts,
        "status": status,
        "timestamping": timestamping,
        "timestamping_status": timestamp_status,
        "warning_count": len(warnings),
        "warnings": warnings,
    }


def packet_diagnostics(packet: Path, key_directory: Path | None = None) -> dict[str, Any]:
    manifest_path = resolve_packet_manifest(packet)
    proof_dir = manifest_path.parent
    checks: list[dict[str, str]] = []
    failures: list[str] = []
    warnings: list[str] = []
    required = ["manifest.json", "evidence_chain.jsonl", "hashes.txt", "metadata.json", "warnings.json"]
    for name in required:
        if (proof_dir / name).exists():
            checks.append({"status": "PASS", "message": f"{name} exists."})
        else:
            checks.append({"status": "FAIL", "message": f"{name} is missing."})
            failures.append(f"{name}_missing")
    try:
        manifest = load_manifest(manifest_path)
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "fail",
            "checks": checks + [{"status": "FAIL", "message": f"manifest unreadable: {exc}"}],
            "warnings": warnings,
            "failures": failures + ["manifest_unreadable"],
        }

    if manifest.get("schema_version") == SCHEMA_VERSION:
        checks.append({"status": "PASS", "message": "manifest schema valid."})
    else:
        checks.append({"status": "FAIL", "message": "manifest schema invalid."})
        failures.append("manifest_schema_invalid")

    identifiers = manifest.get("identifiers", {})
    if not isinstance(identifiers, dict):
        identifiers = {}
    expected_manifest_id = make_manifest_id(manifest)
    if identifiers.get("manifest_id") == expected_manifest_id:
        checks.append({"status": "PASS", "message": "manifest_id reproducible."})
    else:
        checks.append({"status": "FAIL", "message": "manifest_id mismatch."})
        failures.append("manifest_id_mismatch")

    chain_path = proof_dir / "evidence_chain.jsonl"
    chain = evidence_chain_diagnostics(chain_path)
    if chain["status"] == CHAIN_STATUS_VALID:
        checks.append({"status": "PASS", "message": "evidence chain intact."})
    elif chain["status"] == CHAIN_STATUS_MISSING:
        checks.append({"status": "FAIL", "message": "evidence chain missing."})
        failures.append("evidence_chain_missing")
    else:
        checks.append({"status": "FAIL", "message": "evidence chain invalid."})
        failures.extend(str(error) for error in chain.get("errors", []))

    if chain_path.exists() and chain["status"] == CHAIN_STATUS_VALID:
        root = evidence_chain_root(chain_path)
        expected_packet_id = make_packet_id(expected_manifest_id, root)
        if identifiers.get("packet_id") == expected_packet_id:
            checks.append({"status": "PASS", "message": "packet_id reproducible."})
        else:
            checks.append({"status": "FAIL", "message": "packet_id mismatch."})
            failures.append("packet_id_mismatch")

    from tohupono.verdicts.classifier import manifest_signature_status

    signature_status = manifest_signature_status(manifest_path)
    if signature_status == "valid":
        checks.append({"status": "PASS", "message": "manifest signature valid."})
    elif signature_status == "missing":
        checks.append({"status": "WARN", "message": "manifest signature missing."})
        warnings.append("manifest_signature_missing")
    else:
        checks.append({"status": "FAIL", "message": "manifest signature invalid or unavailable."})
        failures.append("manifest_signature_invalid")

    report_status = verify_packet_report_signature(proof_dir)
    if report_status == "valid":
        checks.append({"status": "PASS", "message": "report signature valid."})
    elif report_status == "missing":
        checks.append({"status": "WARN", "message": "report signature not present in packet."})
        warnings.append("report_signature_missing")
    elif report_status == "unverified":
        checks.append({"status": "WARN", "message": "report signature present without public key."})
        warnings.append("report_signature_unverified")
    else:
        checks.append({"status": "FAIL", "message": "report signature invalid."})
        failures.append("report_signature_invalid")

    from tohupono.trust.keys import key_lifecycle_summary

    key_lifecycle: dict[str, object] = {}
    key_warnings: list[str] = []
    for purpose in ["manifest", "report", "amendment"]:
        lifecycle = key_lifecycle_summary(purpose, key_directory)
        key_lifecycle[purpose] = {
            "compromise_events": lifecycle.get("compromise_events", 0),
            "latest_compromise_event_id": lifecycle.get("latest_compromise_event_id"),
            "latest_rotation_event_id": lifecycle.get("latest_rotation_event_id"),
            "rotation_events": lifecycle.get("rotation_events", 0),
        }
        if int(lifecycle.get("compromise_events", 0)):
            message = (
                f"compromise metadata exists for the {purpose} key purpose. "
                "Existing signatures may require review under the applicable trust policy."
            )
            checks.append({"status": "WARN", "message": message})
            key_warnings.append(message)
            warnings.append(f"{purpose}_key_compromise_review")

    timestamp_diagnostics = timestamp_verification_diagnostics(manifest_path, DEFAULT_TIMESTAMP_POLICY)
    checks.extend(
        {"status": str(check.get("status")), "message": str(check.get("message"))}
        for check in timestamp_diagnostics.get("checks", [])
        if isinstance(check, dict)
    )
    failures.extend(str(failure) for failure in timestamp_diagnostics.get("failures", []))
    warnings.extend(str(warning) for warning in timestamp_diagnostics.get("warnings", []))
    concept_diagnostics = evaluate_declared_concepts(manifest_path, manifest)
    legacy_warning = concept_diagnostics.get("legacy_warning")
    if legacy_warning:
        checks.append({"status": "WARN", "message": str(legacy_warning)})
        warnings.append("proof_concepts_absent")
    for result in concept_diagnostics.get("results", []):
        if not isinstance(result, dict):
            continue
        concept_status = str(result.get("status"))
        concept_id = str(result.get("concept_id"))
        checks.append({"status": concept_status, "message": f"Proof Concept {concept_id}: {concept_status}."})
        if concept_status == "FAIL":
            failures.append(f"proof_concept_{concept_id}_failed")
        elif concept_status == "WARN":
            warnings.append(f"proof_concept_{concept_id}_warning")
    status = "fail" if failures else ("warn" if warnings else "pass")
    return {
        "checks": checks,
        "declared_proof_concepts": concept_diagnostics.get("declared", []),
        "evidence_chain_status": chain["status"],
        "failures": failures,
        "inferred_legacy_checks": concept_diagnostics.get("inferred_legacy_checks", []),
        "key_lifecycle": key_lifecycle,
        "key_warnings": key_warnings,
        "key_directory": str(key_directory or Path("keys")),
        "manifest_id": identifiers.get("manifest_id"),
        "packet_id": identifiers.get("packet_id"),
        "proof_concept_results": concept_diagnostics.get("results", []),
        "proof_concept_summary": concept_diagnostics.get("summary", {}),
        "report_signature_status": report_status,
        "status": status,
        "timestamp_diagnostics": timestamp_diagnostics,
        "timestamp_receipts": timestamp_diagnostics.get("receipts", []),
        "timestamping": timestamp_diagnostics.get("timestamping"),
        "timestamp_status": timestamp_diagnostics.get("timestamping_status"),
        "warnings": warnings,
    }


def verify_packet_report_signature(proof_dir: Path) -> str:
    from tohupono.trust.keys import verify_signature

    report = proof_dir / "verification_report.pdf"
    signature = proof_dir / "verification_report.pdf.sig"
    public_key = proof_dir / "verification_report.pdf.pub"
    if not report.exists() and not signature.exists():
        return "missing"
    if not report.exists() or not signature.exists():
        return "invalid"
    if not public_key.exists():
        return "unverified"
    return "valid" if verify_signature(public_key, signature.read_bytes(), report.read_bytes()) else "invalid"


def create_amendment(packet: Path, note: str) -> Path:
    if not note.strip():
        raise ValueError("Amendment note must not be empty.")
    manifest_path = resolve_packet_manifest(packet)
    manifest = load_manifest(manifest_path)
    identifiers = manifest.get("identifiers", {})
    if not isinstance(identifiers, dict):
        identifiers = {}
    parent_manifest_id = str(identifiers.get("manifest_id") or make_manifest_id(manifest))
    chain_path = manifest_path.parent / "evidence_chain.jsonl"
    previous = evidence_chain_root(chain_path) if chain_path.exists() else GENESIS_EVENT_HASH
    timestamp = utc_now_iso()
    event = build_evidence_event(
        event_type="amended",
        timestamp=timestamp,
        actor="tohupono",
        file_sha256=str(manifest.get("file", {}).get("sha256", "")) if isinstance(manifest.get("file"), dict) else "",
        previous_event_hash=previous,
    )
    amendment_id = sha256_text(
        canonical_json_bytes(
            {
                "event_hash": event["event_hash"],
                "note": note,
                "parent_manifest_id": parent_manifest_id,
                "timestamp": timestamp,
            }
        )
    )
    amendment = {
        "amendment_id": amendment_id,
        "amendment_event_hash": event["event_hash"],
        "event": event,
        "note": note,
        "parent_manifest_id": parent_manifest_id,
        "parent_packet_id": identifiers.get("packet_id"),
        "signer": "local_manifest_key",
        "timestamp": timestamp,
    }
    out_dir = manifest_path.parent.parent / "amendments" / amendment_id
    _assert_can_create_packet(out_dir)
    out_dir.mkdir(parents=True)
    write_json(out_dir / "amendment.json", amendment)
    signature, public_key = sign_amendment_bytes(canonical_json_bytes(amendment))
    sig_dir = out_dir / "signatures"
    sig_dir.mkdir()
    (sig_dir / "amendment.sig").write_bytes(signature)
    (sig_dir / "amendment.pub").write_bytes(public_key)
    return out_dir
