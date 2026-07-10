# What TohuPono Proves

TohuPono records local, deterministic evidence about file bytes.

Claim wording follows `docs/CLAIM_MATURITY.md`. Level 1 and Level 2 technical claims must stay tied to the checks that support them.

TohuPono may claim:

- a supplied file matched a specific byte-state;
- a supplied file had a specific SHA-256 digest;
- a manifest was generated from that byte-state;
- a manifest signature was valid where present;
- an evidence chain has not been detectably tampered with;
- a copied or renamed file is byte-identical when hashes match;
- a report was generated from a specific proof packet where report signing material exists.

These are technical and evidence-support claims, not legal proof claims.

TohuPono must not claim:

- the content is factually true;
- the creator is definitely the real-world human;
- a local timestamp is legally final without trusted timestamping;
- the file was not manipulated before first proofing;
- the report alone guarantees legal admissibility;
- matching copies prove authorship by themselves.
