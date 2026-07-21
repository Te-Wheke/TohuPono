from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from tohupono.timestamping.model import (
    LOCAL_TIMESTAMP_WARNING,
    MISSING_TIMESTAMP_WARNING,
    TimestampProof,
    TimestampVerificationResult,
    local_timestamp_proof,
    missing_timestamp_proof,
)


class TimestampAdapter(Protocol):
    name: str
    adapter_type: str
    supports_create: bool
    supports_verify: bool

    def create_timestamp(self, target_digest: str) -> TimestampProof:
        """Create a timestamp proof for a target digest."""

    def verify_timestamp(self, proof: TimestampProof) -> TimestampVerificationResult:
        """Verify a timestamp proof."""


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class NoneTimestampAdapter:
    name = "none"
    adapter_type = "none"
    supports_create = False
    supports_verify = False

    def create_timestamp(self, target_digest: str) -> TimestampProof:
        return missing_timestamp_proof()

    def verify_timestamp(self, proof: TimestampProof) -> TimestampVerificationResult:
        return TimestampVerificationResult(
            status="unsupported",
            adapter="none",
            warnings=[MISSING_TIMESTAMP_WARNING],
            reasons=["No timestamp adapter is configured."],
        )


class LocalTimestampAdapter:
    name = "local"
    adapter_type = "local"
    supports_create = True
    supports_verify = True

    def create_timestamp(self, target_digest: str) -> TimestampProof:
        return local_timestamp_proof(target_digest, _utc_now())

    def verify_timestamp(self, proof: TimestampProof) -> TimestampVerificationResult:
        if proof.status != "local_only":
            return TimestampVerificationResult(
                status="invalid",
                adapter="local",
                warnings=[],
                reasons=["LocalTimestampAdapter only verifies local_only timestamp proofs."],
            )
        return TimestampVerificationResult(
            status="local_only",
            adapter="local",
            warnings=[LOCAL_TIMESTAMP_WARNING],
            reasons=[],
        )
