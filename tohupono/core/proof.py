from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from tohupono import __version__
from tohupono.core.canonical_json import canonical_json_bytes, canonical_json_text
from tohupono.core.file_identity import FileIdentity, inspect_file
from tohupono.timestamping.model import inspect_manifest_timestamping, local_timestamp_proof
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


def proof_id_seed(identity: FileIdentity, sealed_at_utc: str) -> dict[str, object]:
    return {
        "file_id": identity.sha256,
        "file_sha256": identity.sha256,
        "file_size": identity.size_bytes,
        "manifest_version": MANIFEST_VERSION,
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
    }


def make_proof_id(identity: FileIdentity, sealed_at_utc: str) -> str:
    digest = hashlib.sha256(canonical_json_bytes(proof_id_seed(identity, sealed_at_utc))).hexdigest()
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


def build_manifest(identity: FileIdentity, sealed_at_utc: str) -> ProofManifest:
    warnings: list[str] = []
    if identity.blake3 is None:
        warnings.append("BLAKE3 unavailable; optional BLAKE3 digest was not recorded.")

    return ProofManifest(
        schema_version=SCHEMA_VERSION,
        manifest_version=MANIFEST_VERSION,
        proof_id=make_proof_id(identity, sealed_at_utc),
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
            "proof_id": make_proof_id(identity, sealed_at_utc),
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
) -> ProofManifest:
    identity = inspect_file(source)
    sealed_at = sealed_at_utc or utc_now_iso()
    manifest = build_manifest(identity, sealed_at)
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
    return json.loads(path.read_text(encoding="utf-8"))


def packet_diagnostics(packet: Path, key_workspace: Path | None = None) -> dict[str, Any]:
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
        lifecycle = key_lifecycle_summary(purpose, key_workspace)
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

    timestamping = inspect_manifest_timestamping(manifest)
    timestamp_status = str(timestamping.get("status"))
    if timestamp_status == "local_only":
        checks.append({"status": "WARN", "message": "timestamp is local-only and not externally anchored."})
        warnings.append("timestamp_local_only")
    elif timestamp_status == "missing":
        checks.append({"status": "WARN", "message": "no timestamp proof is present."})
        warnings.append("timestamp_missing")
    elif timestamp_status == "anchored":
        checks.append({"status": "PASS", "message": "timestamp proof is externally anchored."})
    else:
        checks.append({"status": "WARN", "message": f"timestamp status is {timestamp_status}."})
        warnings.append(f"timestamp_{timestamp_status}")
    status = "fail" if failures else ("warn" if warnings else "pass")
    return {
        "checks": checks,
        "evidence_chain_status": chain["status"],
        "failures": failures,
        "key_lifecycle": key_lifecycle,
        "key_warnings": key_warnings,
        "key_workspace": str(key_workspace or Path("keys")),
        "manifest_id": identifiers.get("manifest_id"),
        "packet_id": identifiers.get("packet_id"),
        "report_signature_status": report_status,
        "status": status,
        "timestamping": timestamping,
        "timestamp_status": timestamp_status,
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
