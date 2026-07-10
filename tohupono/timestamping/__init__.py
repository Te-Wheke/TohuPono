"""Timestamp proof models and local adapter interfaces."""

from tohupono.timestamping.adapters import LocalTimestampAdapter, NoneTimestampAdapter, TimestampAdapter
from tohupono.timestamping.model import (
    LOCAL_TIMESTAMP_WARNING,
    TIMESTAMP_STATUSES,
    TimestampProof,
    TimestampVerificationResult,
    inspect_manifest_timestamping,
    local_timestamp_proof,
    missing_timestamp_proof,
)

__all__ = [
    "LOCAL_TIMESTAMP_WARNING",
    "TIMESTAMP_STATUSES",
    "LocalTimestampAdapter",
    "NoneTimestampAdapter",
    "TimestampAdapter",
    "TimestampProof",
    "TimestampVerificationResult",
    "inspect_manifest_timestamping",
    "local_timestamp_proof",
    "missing_timestamp_proof",
]
