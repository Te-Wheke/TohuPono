from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from tohupono.timestamping.model import TimestampReceipt, TimestampVerificationResult


@dataclass(frozen=True)
class TimestampRequest:
    target_digest: str
    adapter_type: str
    policy: str = "evidence_review"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class TimestampProvider(Protocol):
    provider_id: str
    supports_create: bool
    supports_verify: bool

    def create(self, request: TimestampRequest) -> TimestampVerificationResult:
        """Create timestamp evidence for a digest."""

    def verify(self, receipt: TimestampReceipt) -> TimestampVerificationResult:
        """Verify timestamp evidence for a digest."""
