from __future__ import annotations

from tohupono.timestamping.provider import TimestampProvider
from tohupono.timestamping.providers.opentimestamps import OpenTimestampsProvider
from tohupono.timestamping.providers.rfc3161 import RFC3161Provider


class TimestampProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, TimestampProvider] = {
            "opentimestamps": OpenTimestampsProvider(),
            "rfc3161": RFC3161Provider(),
        }

    def names(self) -> list[str]:
        return sorted(self._providers)

    def get(self, provider_id: str) -> TimestampProvider:
        return self._providers[provider_id]

    def to_dict(self) -> dict[str, object]:
        return {
            "providers": [
                {
                    "provider_id": name,
                    "supports_create": self._providers[name].supports_create,
                    "supports_verify": self._providers[name].supports_verify,
                }
                for name in self.names()
            ]
        }


def timestamp_provider_registry() -> TimestampProviderRegistry:
    return TimestampProviderRegistry()
