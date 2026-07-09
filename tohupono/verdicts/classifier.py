from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from tohupono.core.file_identity import inspect_file
from tohupono.core.proof import load_manifest, write_json
from tohupono.trust.keys import verify_signature

VERIFIED_INTEGRITY = "VERIFIED_INTEGRITY"
ALTERED_AFTER_PROOF = "ALTERED_AFTER_PROOF"
UNPROVEN = "UNPROVEN"
PROVENANCE_CONFLICT = "PROVENANCE_CONFLICT"
MANIFEST_SIGNATURE_MISSING = "manifest_signature_missing"
MANIFEST_SIGNATURE_VALID = "valid"
MANIFEST_SIGNATURE_MISSING_STATUS = "missing"
MANIFEST_SIGNATURE_INVALID = "invalid"


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
    signature_evidence: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def manifest_signature_status(proof: Path) -> str:
    signatures_dir = proof.parent / "signatures"
    signature_path = signatures_dir / "manifest.sig"
    public_key_path = signatures_dir / "manifest.pub"
    if not signature_path.exists() or not public_key_path.exists():
        return MANIFEST_SIGNATURE_MISSING_STATUS
    if verify_signature(public_key_path, signature_path.read_bytes(), proof.read_bytes()):
        return MANIFEST_SIGNATURE_VALID
    return MANIFEST_SIGNATURE_INVALID


def verify_file(source: Path, proof: Path) -> VerificationResult:
    manifest = load_manifest(proof)
    manifest_file = manifest.get("file")
    proof_id = manifest.get("proof_id") if isinstance(manifest.get("proof_id"), str) else None
    signature_status = manifest_signature_status(proof)
    warnings: list[str] = []
    reasons: list[str] = []
    if signature_status == MANIFEST_SIGNATURE_MISSING_STATUS:
        warnings.append(MANIFEST_SIGNATURE_MISSING)
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
            signature_evidence={
                "manifest_signature": signature_status,
                "signature_path": str(proof.parent / "signatures" / "manifest.sig"),
                "public_key_path": str(proof.parent / "signatures" / "manifest.pub"),
            },
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
            signature_evidence={"manifest_signature": signature_status},
        )

    identity = inspect_file(source)
    manifest_sha256 = str(manifest_file["sha256"])
    verdict = VERIFIED_INTEGRITY if identity.sha256 == manifest_sha256 else ALTERED_AFTER_PROOF
    summary = (
        "The current file digest matches the sealed digest."
        if verdict == VERIFIED_INTEGRITY
        else "The current file digest differs from the sealed digest."
    )
    return VerificationResult(
        verdict=verdict,
        file_sha256=identity.sha256,
        manifest_sha256=manifest_sha256,
        proof_id=proof_id,
        summary=summary,
        manifest_signature_status=signature_status,
        warnings=warnings,
        reasons=[],
        signature_evidence={
            "manifest_signature": signature_status,
            "signature_path": str(proof.parent / "signatures" / "manifest.sig"),
            "public_key_path": str(proof.parent / "signatures" / "manifest.pub"),
        },
    )


def write_verdict(proof: Path, result: VerificationResult) -> Path:
    out = proof.parent / "verdict.json"
    write_json(out, result.to_dict())
    return out


def write_markdown(path: Path, result: VerificationResult) -> None:
    text = "\n".join(
        [
            "# TohuPono Verification Report",
            "",
            "This is an evidence-based verification summary for a legal-support evidence bundle.",
            "",
            f"Verdict: `{result.verdict}`",
            f"Proof ID: `{result.proof_id or 'unknown'}`",
            f"Current SHA-256: `{result.file_sha256 or 'unknown'}`",
            f"Manifest SHA-256: `{result.manifest_sha256 or 'unknown'}`",
            f"Manifest signature status: `{result.manifest_signature_status}`",
            "",
            result.summary,
            "",
        ]
    )
    path.write_text(text, encoding="utf-8")
