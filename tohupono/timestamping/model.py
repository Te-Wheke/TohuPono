from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Literal

from tohupono.core.canonical_json import canonical_json_bytes

TimestampStatus = Literal["missing", "local_only", "pending", "anchored", "invalid", "unsupported", "error"]
TimestampAdapterType = Literal["none", "local", "opentimestamps", "rfc3161", "manual"]
TimestampReceiptType = Literal["manual", "opentimestamps", "rfc3161", "unknown"]
TimestampReceiptStatus = Literal["imported", "unverified", "verified", "invalid", "unsupported", "missing"]
TimestampPolicy = Literal["permissive", "evidence_review", "strict_external"]

TIMESTAMP_STATUSES: tuple[TimestampStatus, ...] = (
    "missing",
    "local_only",
    "pending",
    "anchored",
    "invalid",
    "unsupported",
    "error",
)
TIMESTAMP_ADAPTER_TYPES: tuple[TimestampAdapterType, ...] = (
    "none",
    "local",
    "opentimestamps",
    "rfc3161",
    "manual",
)
TIMESTAMP_RECEIPT_TYPES: tuple[TimestampReceiptType, ...] = (
    "manual",
    "opentimestamps",
    "rfc3161",
    "unknown",
)
TIMESTAMP_RECEIPT_STATUSES: tuple[TimestampReceiptStatus, ...] = (
    "imported",
    "unverified",
    "verified",
    "invalid",
    "unsupported",
    "missing",
)
TIMESTAMP_POLICIES: tuple[TimestampPolicy, ...] = (
    "permissive",
    "evidence_review",
    "strict_external",
)
DEFAULT_TIMESTAMP_POLICY: TimestampPolicy = "evidence_review"
LOCAL_TIMESTAMP_WARNING = "Local timestamp is not externally anchored."
MISSING_TIMESTAMP_WARNING = "No timestamp proof is present."
UNVERIFIED_RECEIPT_WARNING = "Imported timestamp receipt is recorded but not externally verified by TohuPono."


class TimestampReceiptConflictError(Exception):
    """Raised when a receipt import would overwrite existing receipt material."""


@dataclass(frozen=True)
class TimestampProof:
    status: TimestampStatus
    adapter: TimestampAdapterType
    target_digest: str | None
    created_at: str | None
    warnings: list[str]
    receipt: dict[str, object] | None = None
    policy: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        return {key: item for key, item in value.items() if item is not None}


@dataclass(frozen=True)
class TimestampVerificationResult:
    status: TimestampStatus
    adapter: TimestampAdapterType
    warnings: list[str]
    reasons: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TimestampReceipt:
    receipt_id: str
    receipt_type: TimestampReceiptType
    receipt_path: str
    receipt_sha256: str
    receipt_size: int
    receipt_format: str
    receipt_status: TimestampReceiptStatus
    adapter_type: TimestampAdapterType
    target_digest: str
    imported_at: str
    warnings: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def make_receipt_id(*, receipt_type: str, receipt_sha256: str, receipt_size: int, target_digest: str) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "receipt_sha256": receipt_sha256,
                "receipt_size": receipt_size,
                "receipt_type": receipt_type,
                "target_digest": target_digest,
            }
        )
    ).hexdigest()
    return f"tr_{digest[:32]}"


def local_timestamp_proof(target_digest: str, created_at: str) -> TimestampProof:
    return TimestampProof(
        status="local_only",
        adapter="local",
        target_digest=target_digest,
        created_at=created_at,
        warnings=[LOCAL_TIMESTAMP_WARNING],
        receipt={"type": "local_system_time"},
        policy={"external_anchor_required": False},
    )


def missing_timestamp_proof() -> TimestampProof:
    return TimestampProof(
        status="missing",
        adapter="none",
        target_digest=None,
        created_at=None,
        warnings=[MISSING_TIMESTAMP_WARNING],
    )


def inspect_manifest_timestamping(manifest: dict[str, Any]) -> dict[str, object]:
    timestamping = manifest.get("timestamping")
    if not isinstance(timestamping, dict):
        return missing_timestamp_proof().to_dict()
    status = timestamping.get("status")
    if status not in TIMESTAMP_STATUSES:
        return {
            "adapter": str(timestamping.get("adapter", "none")),
            "status": "invalid",
            "target_digest": timestamping.get("target_digest"),
            "warnings": ["Timestamping status is invalid."],
        }
    warnings = timestamping.get("warnings")
    return {
        "adapter": str(timestamping.get("adapter", "none")),
        "created_at": timestamping.get("created_at"),
        "receipt": timestamping.get("receipt"),
        "status": status,
        "target_digest": timestamping.get("target_digest"),
        "warnings": warnings if isinstance(warnings, list) else [],
    }
