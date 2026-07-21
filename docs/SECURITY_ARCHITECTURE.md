# Security Architecture

TohuPono is local-first and offline by default. It treats files, proof packets, key directories, lifecycle logs and timestamp receipts as potentially hostile inputs unless they are created and verified inside the current operation.

## Local State Controls

Security-sensitive state should use:

- bounded structured input;
- canonical JSON;
- restrictive private-file modes;
- atomic replacement;
- parent-directory fsync where supported;
- operation-specific locks;
- symlink checks;
- path-escape prevention;
- stable errors.

## Path Policy

Sensitive paths must reject traversal, absolute child paths where relative paths are required, NUL characters, ASCII control characters, Unicode bidirectional controls, sensitive symlinks and forbidden locations such as `.git` and `.ssh`.

Hardlink detection is best-effort where the platform exposes link counts.

## Key Lifecycle

Key lifecycle logs are tamper-evident under the local key lifecycle model. They are not immutable.

Internal chain gaps and removal of events referenced by later retained events are detectable. Removal of the unreferenced tail of a purely local lifecycle log may not be detectable without a separately retained, signed or externally anchored head checkpoint.

## Timestamp Providers

Timestamp provider placeholders must not perform network calls or external commands. Future provider implementations must be explicit, opt-in and documented.

A verified timestamp can support that a digest existed no later than a verified time boundary. It does not prove content truth, authorship, ownership, identity or legal admissibility.
