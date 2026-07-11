from __future__ import annotations

from tohupono.timestamping.model import TimestampReceipt, TimestampVerificationResult
from tohupono.timestamping.provider import TimestampRequest


class OpenTimestampsProvider:
    provider_id = "opentimestamps"
    supports_create = False
    supports_verify = False

    def create(self, request: TimestampRequest) -> TimestampVerificationResult:
        return TimestampVerificationResult(
            status="provider_unavailable",
            adapter="opentimestamps",
            warnings=["OpenTimestamps provider is not implemented in this offline slice."],
            reasons=["No network timestamp request was made."],
        )

    def verify(self, receipt: TimestampReceipt) -> TimestampVerificationResult:
        return TimestampVerificationResult(
            status="deferred",
            adapter="opentimestamps",
            warnings=["OpenTimestamps receipt verification is not implemented in this offline slice."],
            reasons=["Receipt remains unverified until an adapter implementation is added."],
        )
