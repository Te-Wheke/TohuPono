# Chain Of Custody

The evidence chain records deterministic JSON events.

Each event includes:

- `event_id`
- `event_type`
- `timestamp`
- `actor`
- `file_sha256`
- `previous_event_hash`
- `event_hash`

`event_hash` is calculated over the canonical event without `event_hash`. Each new event links to the previous event hash. An empty chain is invalid.

Amendments add lineage without mutating the original proof packet. The amendment references the parent packet or manifest ID and records its own event hash.

The chain is tamper-evident within the packet model. It does not prove complete custody outside the recorded events.
