from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from tohupono.core.file_identity import inspect_file
from tohupono.core.proof import evidence_chain_diagnostics, load_manifest, write_json
from tohupono.trust.keys import verify_signature

VERIFIED_INTEGRITY = "VERIFIED_INTEGRITY"
ALTERED_AFTER_PROOF = "ALTERED_AFTER_PROOF"
UNPROVEN = "UNPROVEN"
PROVENANCE_CONFLICT = "PROVENANCE_CONFLICT"
MANIFEST_SIGNATURE_MISSING = "manifest_signature_missing"
MANIFEST_SIGNATURE_VALID = "valid"
MANIFEST_SIGNATURE_MISSING_STATUS = "missing"
MANIFEST_SIGNATURE_INVALID = "invalid"
MANIFEST_SIGNATURE_UNVERIFIED = "unverified"
MANIFEST_SIGNATURE_ERROR = "error"
PATH_DIFFERS_NOTE = (
    "Current file digest matches proof manifest. Observed path differs; path is metadata, not identity."
)
LEGAL_SUPPORT_BOUNDARY = (
    "This report supports evidence review by recording deterministic file identity, verification results, "
    "signatures, and proof-packet status. It does not by itself prove real-world truth, authorship, intent, "
    "or legal admissibility."
)


@dataclass(frozen=True)
class VerificationResult:
    verdict: str
    file_sha256: str | None
    manifest_sha256: str | None
    proof_id: str | None
    summary: str
    manifest_signature_status: str
    warnings: list[str]
    reasons: list[str]
    notes: list[str]
    signature_evidence: dict[str, object]
    evidence_chain_status: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_cli_json(self) -> dict[str, object]:
        return {
            "classification": self.verdict,
            "evidence_chain_status": self.evidence_chain_status,
            "expected_sha256": self.manifest_sha256,
            "file_sha256": self.file_sha256,
            "manifest_signature_status": self.manifest_signature_status,
            "notes": self.notes,
            "reasons": self.reasons,
            "verdict": self.verdict,
            "warnings": self.warnings,
        }


def manifest_signature_status(proof: Path) -> str:
    signatures_dir = proof.parent / "signatures"
    signature_path = signatures_dir / "manifest.sig"
    public_key_path = signatures_dir / "manifest.pub"
    if not signature_path.exists() or not public_key_path.exists():
        return MANIFEST_SIGNATURE_MISSING_STATUS
    try:
        if verify_signature(public_key_path, signature_path.read_bytes(), proof.read_bytes()):
            return MANIFEST_SIGNATURE_VALID
        return MANIFEST_SIGNATURE_INVALID
    except OSError:
        return MANIFEST_SIGNATURE_ERROR


def verify_file(source: Path, proof: Path) -> VerificationResult:
    manifest = load_manifest(proof)
    manifest_file = manifest.get("file")
    proof_id = manifest.get("proof_id") if isinstance(manifest.get("proof_id"), str) else None
    signature_status = manifest_signature_status(proof)
    warnings: list[str] = []
    reasons: list[str] = []
    notes: list[str] = []
    if signature_status == MANIFEST_SIGNATURE_MISSING_STATUS:
        warnings.append(MANIFEST_SIGNATURE_MISSING)
    if signature_status == MANIFEST_SIGNATURE_ERROR:
        warnings.append("manifest_signature_error")
    if signature_status == MANIFEST_SIGNATURE_INVALID:
        reasons.append("Manifest signature validation failed")
        return VerificationResult(
            verdict=PROVENANCE_CONFLICT,
            file_sha256=None,
            manifest_sha256=None,
            proof_id=proof_id,
            summary="Manifest signature validation failed.",
            manifest_signature_status=signature_status,
            warnings=warnings,
            reasons=reasons,
            notes=notes,
            signature_evidence={
                "manifest_signature": signature_status,
                "signature_path": str(proof.parent / "signatures" / "manifest.sig"),
                "public_key_path": str(proof.parent / "signatures" / "manifest.pub"),
            },
            evidence_chain_status="unverified",
        )
    chain_result = evidence_chain_diagnostics(proof.parent / "evidence_chain.jsonl")
    evidence_chain_status = str(chain_result["status"])
    chain_errors = [str(error) for error in chain_result["errors"]]
    warnings.extend(chain_errors)
    if evidence_chain_status == "invalid":
        reasons.append("Evidence chain validation failed")
        return VerificationResult(
            verdict=PROVENANCE_CONFLICT,
            file_sha256=None,
            manifest_sha256=None,
            proof_id=proof_id,
            summary="Evidence chain validation failed.",
            manifest_signature_status=signature_status,
            warnings=warnings,
            reasons=reasons,
            notes=notes,
            signature_evidence={"manifest_signature": signature_status},
            evidence_chain_status=evidence_chain_status,
        )
    if not isinstance(manifest_file, dict) or not manifest_file.get("sha256"):
        return VerificationResult(
            verdict=UNPROVEN,
            file_sha256=None,
            manifest_sha256=None,
            proof_id=proof_id,
            summary="The proof manifest does not contain enough digest evidence for verification.",
            manifest_signature_status=signature_status,
            warnings=warnings,
            reasons=["Missing sealed SHA-256 digest evidence."],
            notes=notes,
            signature_evidence={"manifest_signature": signature_status},
            evidence_chain_status=evidence_chain_status,
        )

    identity = inspect_file(source)
    manifest_sha256 = str(manifest_file["sha256"])
    verdict = VERIFIED_INTEGRITY if identity.sha256 == manifest_sha256 else ALTERED_AFTER_PROOF
    if verdict == VERIFIED_INTEGRITY:
        summary = "The current file digest matches the sealed digest."
        observed_path = manifest_file.get("path_observed")
        if isinstance(observed_path, str) and observed_path != str(source):
            notes.append(PATH_DIFFERS_NOTE)
    else:
        summary = "The current file digest differs from the sealed digest."
    return VerificationResult(
        verdict=verdict,
        file_sha256=identity.sha256,
        manifest_sha256=manifest_sha256,
        proof_id=proof_id,
        summary=summary,
        manifest_signature_status=signature_status,
        warnings=warnings,
        reasons=[],
        notes=notes,
        signature_evidence={
            "manifest_signature": signature_status,
            "signature_path": str(proof.parent / "signatures" / "manifest.sig"),
            "public_key_path": str(proof.parent / "signatures" / "manifest.pub"),
        },
        evidence_chain_status=evidence_chain_status,
    )


def write_verdict(proof: Path, result: VerificationResult) -> Path:
    out = proof.parent / "verdict.json"
    write_json(out, result.to_dict())
    return out


def write_markdown(path: Path, result: VerificationResult) -> None:
    notes = result.notes or ["None."]
    warnings = result.warnings or ["None."]
    reasons = result.reasons or ["None."]
    text = "\n".join(
        [
            "# TohuPono Verification Report",
            "",
            "## Verdict",
            "",
            f"Verdict: `{result.verdict}`",
            f"Proof ID: `{result.proof_id or 'unknown'}`",
            "",
            "## File Identity",
            "",
            f"Current SHA-256: `{result.file_sha256 or 'unknown'}`",
            f"Expected SHA-256: `{result.manifest_sha256 or 'unknown'}`",
            "",
            "## Manifest Signature",
            "",
            f"Manifest signature status: `{result.manifest_signature_status}`",
            "",
            "## Evidence Chain",
            "",
            f"Evidence chain status: `{result.evidence_chain_status}`",
            "",
            result.summary,
            "",
            "## Notes",
            "",
            *notes,
            "",
            "## Warnings",
            "",
            *warnings,
            "",
            "## Reasons",
            "",
            *reasons,
            "",
            "## Legal-Support Boundary",
            "",
            LEGAL_SUPPORT_BOUNDARY,
            "",
        ]
    )
    path.write_text(text, encoding="utf-8")
