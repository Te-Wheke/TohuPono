from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

TimestampStatus = Literal["missing", "local_only", "pending", "anchored", "invalid", "unsupported", "error"]
TimestampAdapterType = Literal["none", "local", "opentimestamps", "rfc3161", "manual"]

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
LOCAL_TIMESTAMP_WARNING = "Local timestamp is not externally anchored."
MISSING_TIMESTAMP_WARNING = "No timestamp proof is present."


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
