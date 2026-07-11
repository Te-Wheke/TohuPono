from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

ProofConceptCategory = Literal[
    "object_and_existence",
    "records_and_history",
    "identity_and_authority",
    "events_and_transactions",
    "assessment_and_verification",
]
ProofConceptMaturity = Literal[
    "unmodelled",
    "modelled",
    "interface_defined",
    "locally_supported",
    "externally_supported",
    "verified_implementation",
    "experimental",
    "deprecated",
]
ProofConceptAssessment = Literal[
    "unassessed",
    "unsupported",
    "weakly_supported",
    "moderately_supported",
    "strong_local_evidence_support",
    "strong_externally_verified_support",
    "conflicting_evidence",
    "altered_after_proof",
    "unable_to_verify",
]

MATURITY_VALUES: tuple[ProofConceptMaturity, ...] = (
    "unmodelled",
    "modelled",
    "interface_defined",
    "locally_supported",
    "externally_supported",
    "verified_implementation",
    "experimental",
    "deprecated",
)


@dataclass(frozen=True)
class ProofConcept:
    concept_id: str
    display_name: str
    definition: str
    category: ProofConceptCategory
    claim_boundary: str
    required_evidence: tuple[str, ...]
    trust_dependencies: tuple[str, ...]
    verification_capabilities: tuple[str, ...]
    known_limitations: tuple[str, ...]
    implementation_maturity: ProofConceptMaturity

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        for key in (
            "required_evidence",
            "trust_dependencies",
            "verification_capabilities",
            "known_limitations",
        ):
            value[key] = list(value[key])
        return value
