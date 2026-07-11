from __future__ import annotations

from tohupono.concepts.model import ProofConcept


def _concept(
    concept_id: str,
    display_name: str,
    category: str,
    maturity: str,
    definition: str,
    boundary: str,
    evidence: tuple[str, ...],
    limitations: tuple[str, ...],
    capabilities: tuple[str, ...] = (),
    trust: tuple[str, ...] = (),
) -> ProofConcept:
    return ProofConcept(
        concept_id=concept_id,
        display_name=display_name,
        definition=definition,
        category=category,  # type: ignore[arg-type]
        claim_boundary=boundary,
        required_evidence=evidence,
        trust_dependencies=trust,
        verification_capabilities=capabilities,
        known_limitations=limitations,
        implementation_maturity=maturity,  # type: ignore[arg-type]
    )


PROOF_CONCEPTS: tuple[ProofConcept, ...] = (
    _concept(
        "integrity",
        "Proof of Integrity",
        "object_and_existence",
        "locally_supported",
        "Assesses whether a current byte object matches a recorded digest state.",
        "Digest matches support byte-level integrity only.",
        ("file digest", "manifest identifiers", "packet checks"),
        ("Integrity does not establish authenticity, authorship, ownership, or truth."),
        ("sha256 verification", "packet integrity diagnostics"),
    ),
    _concept(
        "existence",
        "Proof of Existence",
        "object_and_existence",
        "locally_supported",
        "Assesses timestamp evidence for a recorded digest.",
        "Current support is local or imported evidence review, not external anchoring.",
        ("target digest", "local timestamp", "imported receipt metadata"),
        ("Only local timestamp and imported-receipt handling are currently available; independently verified external timestamping is absent."),
        ("local_only timestamp inspection", "timestamp receipt integrity checks"),
    ),
    _concept(
        "records",
        "Proof of Records",
        "records_and_history",
        "locally_supported",
        "Assesses whether a record packet consistently describes a byte object and related local evidence.",
        "Current support does not establish every external record-management requirement.",
        ("manifest", "signatures", "evidence chain", "amendments", "reports"),
        ("Current support covers manifests, signatures, evidence chains, amendments and reports, but does not establish every external record-management requirement."),
        ("manifest verification", "evidence-chain diagnostics", "report signature checks"),
    ),
    _concept(
        "lineage",
        "Proof of Lineage",
        "records_and_history",
        "locally_supported",
        "Assesses recorded relationships between packet events and amendments.",
        "Only recorded relationships are assessed; completeness of history is not proven.",
        ("event hashes", "previous-event links", "amendment references"),
        ("Only recorded relationships are assessed; completeness of history is not proven."),
        ("event-chain verification", "amendment lineage checks"),
    ),
    _concept(
        "authenticity",
        "Proof of Authenticity",
        "identity_and_authority",
        "modelled",
        "Would assess whether evidence supports a claim that an artefact is authentic under a defined policy.",
        "Digest and signature checks support narrower integrity and signer-key claims but do not establish real-world authenticity.",
        ("identity evidence", "authority evidence", "trusted signing policy"),
        ("Digest and signature checks do not establish real-world authenticity."),
    ),
    _concept(
        "ownership",
        "Proof of Ownership",
        "identity_and_authority",
        "modelled",
        "Would assess evidence connecting an artefact or right to an owner under a defined policy.",
        "Ownership requires identity, authority, entitlement, and jurisdiction-specific external evidence.",
        ("identity evidence", "entitlement evidence", "authority chain"),
        ("Requires identity, authority, entitlement and jurisdiction-specific external evidence."),
    ),
    _concept(
        "reality",
        "Proof of Reality",
        "assessment_and_verification",
        "modelled",
        "Long-term layered assessment of whether evidence supports a claim about real-world origin or transformation.",
        "There is no current binary or conclusive implementation.",
        ("device attestation", "trusted timestamps", "witness evidence", "custody continuity", "external corroboration"),
        ("Long-term layered assessment only; no current binary or conclusive implementation."),
    ),
)

_REGISTRY = {concept.concept_id: concept for concept in PROOF_CONCEPTS}


def concept_registry() -> list[dict[str, object]]:
    return [_REGISTRY[key].to_dict() for key in sorted(_REGISTRY)]


def get_concept(concept_id: str) -> ProofConcept:
    return _REGISTRY[concept_id]
