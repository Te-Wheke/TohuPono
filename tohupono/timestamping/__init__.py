"""Timestamp proof models and local adapter interfaces."""

from tohupono.timestamping.adapters import LocalTimestampAdapter, NoneTimestampAdapter, TimestampAdapter
from tohupono.timestamping.model import (
    LOCAL_TIMESTAMP_WARNING,
    DEFAULT_TIMESTAMP_POLICY,
    TIMESTAMP_STATUSES,
    TIMESTAMP_POLICIES,
    TIMESTAMP_RECEIPT_STATUSES,
    TIMESTAMP_RECEIPT_TYPES,
    UNVERIFIED_RECEIPT_WARNING,
    TimestampReceipt,
    TimestampReceiptConflictError,
    TimestampProof,
    TimestampVerificationResult,
    inspect_manifest_timestamping,
    local_timestamp_proof,
    make_receipt_id,
    missing_timestamp_proof,
)

__all__ = [
    "LOCAL_TIMESTAMP_WARNING",
    "DEFAULT_TIMESTAMP_POLICY",
    "TIMESTAMP_STATUSES",
    "TIMESTAMP_POLICIES",
    "TIMESTAMP_RECEIPT_STATUSES",
    "TIMESTAMP_RECEIPT_TYPES",
    "UNVERIFIED_RECEIPT_WARNING",
    "LocalTimestampAdapter",
    "NoneTimestampAdapter",
    "TimestampAdapter",
    "TimestampProof",
    "TimestampReceipt",
    "TimestampReceiptConflictError",
    "TimestampVerificationResult",
    "inspect_manifest_timestamping",
    "local_timestamp_proof",
    "make_receipt_id",
    "missing_timestamp_proof",
]
