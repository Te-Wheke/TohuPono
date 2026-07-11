# Threat Model

## Assets

- source file byte identity;
- proof packet integrity;
- manifest signatures;
- report signatures;
- private signing keys;
- key lifecycle metadata;
- timestamp receipt metadata;
- evidence-chain continuity;
- disciplined claim boundaries.

## Attacker-Controlled Inputs

- source files;
- proof packets;
- manifests;
- evidence-chain JSONL;
- timestamp receipts;
- lifecycle logs;
- filenames and paths;
- report text fields;
- local key output directories;
- future provider metadata.

## Threat Classes

- malformed or extremely large files;
- malformed JSON and JSONL;
- duplicate or reordered lifecycle events;
- path traversal and path escape;
- symlink and hardlink attacks;
- private-key disclosure;
- destructive key replacement;
- partial keypair generation;
- hostile OpenSSL output;
- filesystem races and interrupted writes;
- lifecycle rollback or truncation;
- terminal, filename and report injection;
- Unicode control and bidirectional characters;
- public-key substitution;
- receipt substitution and target mismatch;
- unsupported authenticity, ownership, authorship, reality or legal claims.

## Boundaries

TohuPono verifies local technical evidence. It does not by itself prove legal admissibility, ownership, authorship, content truth or Proof of Reality.
