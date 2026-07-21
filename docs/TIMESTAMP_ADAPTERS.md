# Timestamp Adapters

TohuPono v0.5.0 defines timestamp provider interfaces before external timestamp implementations.

Provider identifiers:

- `opentimestamps`
- `rfc3161`

The current providers are placeholders. They perform no network calls, execute no external commands and return structured unavailable or deferred results.

Existing timestamp packet values remain compatible. New enum-style names map to stable serialized values and must not silently rewrite persisted packets.

Timestamp evidence supports proof-of-existence review only when the evidence and policy support that narrower claim. It does not prove content truth, authorship, ownership, identity or legal admissibility.
