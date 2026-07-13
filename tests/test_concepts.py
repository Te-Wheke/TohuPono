from __future__ import annotations

import json
from pathlib import Path

from tohupono.concepts.execution import concept_list_records
from tohupono.core.proof import create_proof_packet, load_manifest, packet_diagnostics
from tohupono.reporting.pro_report import generate_report
from tohupono.verdicts.classifier import ALTERED_AFTER_PROOF, VERIFIED_INTEGRITY, verify_file

from tests.support import run_cli


def test_concept_list_json_is_deterministic_and_sorted() -> None:
    first = run_cli("concept", "list", "--json")
    second = run_cli("concept", "list", "--json")
    assert first.returncode == 0, first.stderr
    assert first.stdout == second.stdout
    data = json.loads(first.stdout)
    ids = [item["concept_id"] for item in data["concepts"]]
    assert ids == sorted(ids)
    executable = {item["concept_id"]: item["executable"] for item in data["concepts"]}
    assert executable["custody"] is True
    assert executable["integrity"] is True
    assert executable["existence"] is True
    assert executable["provenance"] is True
    assert executable["records"] is True
    assert executable["transaction"] is True
    assert executable["authenticity"] is False


def test_concept_inspect_known_and_unknown() -> None:
    known = run_cli("concept", "inspect", "integrity", "--json")
    assert known.returncode == 0, known.stderr
    data = json.loads(known.stdout)["concept"]
    assert data["concept_id"] == "integrity"
    assert data["executable"] is True
    assert data["exact_claim"]
    assert data["known_limitations"] == ["Integrity does not establish authenticity, authorship, ownership, or truth."]
    assert data["legal_boundary"]

    unknown = run_cli("concept", "inspect", "made_up", "--json")
    assert unknown.returncode == 2
    assert json.loads(unknown.stdout)["status"] == "error"


def test_concept_registry_presence_does_not_imply_execution() -> None:
    records = {item["concept_id"]: item for item in concept_list_records()}
    assert records["lineage"]["executable"] is False
    assert records["ownership"]["executable"] is False
    assert records["reality"]["executable"] is False


def test_prove_defaults_to_integrity_and_existence(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("default concepts\n", encoding="utf-8")
    proof_dir = tmp_path / "proof_packet"
    result = run_cli("prove", str(sample), "--output", str(proof_dir))
    assert result.returncode == 0, result.stderr
    manifest = load_manifest(proof_dir / "manifest.json")
    assert manifest["proof_concepts"]["requested"] == ["existence", "integrity"]


def test_prove_accepts_one_or_two_executable_concepts(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("selected concepts\n", encoding="utf-8")
    one = tmp_path / "one"
    two = tmp_path / "two"
    assert run_cli("prove", str(sample), "--output", str(one), "--concept", "integrity").returncode == 0
    assert (
        run_cli(
            "prove",
            str(sample),
            "--output",
            str(two),
            "--concept",
            "integrity",
            "--concept",
            "existence",
        ).returncode
        == 0
    )
    assert load_manifest(one / "manifest.json")["proof_concepts"]["requested"] == ["integrity"]
    assert load_manifest(two / "manifest.json")["proof_concepts"]["requested"] == ["existence", "integrity"]


def test_prove_rejects_duplicate_unknown_and_non_executable_concepts(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("bad concepts\n", encoding="utf-8")
    duplicate = run_cli(
        "prove",
        str(sample),
        "--output",
        str(tmp_path / "dup"),
        "--concept",
        "integrity",
        "--concept",
        "integrity",
    )
    assert duplicate.returncode == 2
    unknown = run_cli("prove", str(sample), "--output", str(tmp_path / "unknown"), "--concept", "unknown")
    assert unknown.returncode == 2
    non_executable = run_cli(
        "prove",
        str(sample),
        "--output",
        str(tmp_path / "authenticity"),
        "--concept",
        "authenticity",
    )
    assert non_executable.returncode == 2


def test_concept_order_does_not_change_identity_but_concept_set_does(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("identity concepts\n", encoding="utf-8")
    sealed_at = "2026-07-10T00:00:00Z"
    first = tmp_path / "first"
    second = tmp_path / "second"
    integrity_only = tmp_path / "integrity_only"
    create_proof_packet(sample, first, sealed_at_utc=sealed_at, concept_ids=["integrity", "existence"])
    create_proof_packet(sample, second, sealed_at_utc=sealed_at, concept_ids=["existence", "integrity"])
    create_proof_packet(sample, integrity_only, sealed_at_utc=sealed_at, concept_ids=["integrity"])

    first_manifest = load_manifest(first / "manifest.json")
    second_manifest = load_manifest(second / "manifest.json")
    integrity_manifest = load_manifest(integrity_only / "manifest.json")
    assert first_manifest["identifiers"] == second_manifest["identifiers"]
    assert first_manifest["identifiers"]["proof_id"] != integrity_manifest["identifiers"]["proof_id"]
    assert first_manifest["identifiers"]["manifest_id"] != integrity_manifest["identifiers"]["manifest_id"]


def test_manifest_concept_claims_are_stable_machine_data(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("claim data\n", encoding="utf-8")
    proof_dir = tmp_path / "packet"
    create_proof_packet(sample, proof_dir, concept_ids=["integrity", "existence"])
    declaration = load_manifest(proof_dir / "manifest.json")["proof_concepts"]
    assert declaration["schema_version"] == "tohupono.proof_concepts.v1"
    assert declaration["requested"] == ["existence", "integrity"]
    for claim in declaration["claims"]:
        assert set(claim) == {"claim_id", "concept_id", "parameters", "subject"}
        assert claim["claim_id"].startswith("pcl_")
        assert "display_name" not in claim
        assert "implementation_maturity" not in claim
        assert "legal_boundary" not in claim


def test_verify_file_concept_integrity_pass_and_fail(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("verify concepts\n", encoding="utf-8")
    proof_dir = tmp_path / "packet"
    create_proof_packet(sample, proof_dir, concept_ids=["integrity"])
    ok = verify_file(sample, proof_dir / "manifest.json")
    assert ok.verdict == VERIFIED_INTEGRITY
    assert ok.proof_concept_results[0]["status"] == "PASS"
    sample.write_text("changed\n", encoding="utf-8")
    changed = verify_file(sample, proof_dir / "manifest.json")
    assert changed.verdict == ALTERED_AFTER_PROOF
    assert changed.proof_concept_results[0]["status"] == "FAIL"


def test_audit_concept_results_and_legacy_warning(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("audit concepts\n", encoding="utf-8")
    proof_dir = tmp_path / "packet"
    create_proof_packet(sample, proof_dir, concept_ids=["integrity", "existence"])
    result = run_cli("audit", str(proof_dir), "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["declared_proof_concepts"] == ["existence", "integrity"]
    statuses = {item["concept_id"]: item["status"] for item in data["proof_concept_results"]}
    assert statuses["integrity"] == "UNPROVEN"
    assert statuses["existence"] == "WARN"

    legacy_manifest = tmp_path / "legacy_manifest.json"
    legacy_manifest.write_text(
        json.dumps({"proof_id": "legacy", "file": {"sha256": "0" * 64}}, sort_keys=True),
        encoding="utf-8",
    )
    legacy = verify_file(sample, legacy_manifest)
    assert legacy.declared_proof_concepts == []
    assert legacy.proof_concept_results == []


def test_non_executable_declared_concept_is_audit_failure(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("tampered concept declaration\n", encoding="utf-8")
    proof_dir = tmp_path / "packet"
    create_proof_packet(sample, proof_dir, concept_ids=["integrity"])
    manifest_path = proof_dir / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest["proof_concepts"]["requested"] = ["authenticity"]
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    result = run_cli("audit", str(proof_dir), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert data["proof_concept_summary"]["FAIL"] == 1
    assert data["proof_concept_summary"]["overall_status"] == "FAIL"
    assert "proof_concept_invalid_failed" in data["failures"]
    assert data["proof_concept_results"][0]["concept_id"] == "invalid"


def _audit_after_manifest_edit(tmp_path: Path, edit: object) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    sample = tmp_path / "source.txt"
    sample.write_text("tampered concept declaration\n", encoding="utf-8")
    proof_dir = tmp_path / "packet"
    create_proof_packet(sample, proof_dir, concept_ids=["integrity", "existence"])
    manifest_path = proof_dir / "manifest.json"
    manifest = load_manifest(manifest_path)
    if callable(edit):
        edit(manifest)
    else:
        manifest["proof_concepts"] = edit
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    result = run_cli("audit", str(proof_dir), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert data["proof_concept_summary"]["overall_status"] == "FAIL"
    assert data["proof_concept_summary"]["FAIL"] == 1
    assert "proof_concept_invalid_failed" in data["failures"]
    assert data["proof_concept_results"][0]["status"] == "FAIL"
    return data


def test_malformed_explicit_concept_declaration_fails_audit(tmp_path: Path) -> None:
    data = _audit_after_manifest_edit(tmp_path, "not-an-object")
    assert data["proof_concept_results"][0]["concept_id"] == "invalid"


def test_unsupported_concept_schema_fails_audit(tmp_path: Path) -> None:
    def edit(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        assert isinstance(declaration, dict)
        declaration["schema_version"] = "tohupono.proof_concepts.v99"

    _audit_after_manifest_edit(tmp_path, edit)


def test_missing_extra_and_duplicate_concept_claims_fail_audit(tmp_path: Path) -> None:
    def missing(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        assert isinstance(declaration, dict)
        declaration["claims"] = declaration["claims"][:1]

    _audit_after_manifest_edit(tmp_path / "missing", missing)

    def duplicate_claim_id(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        assert isinstance(declaration, dict)
        claims = declaration["claims"]
        assert isinstance(claims, list)
        claims[1]["claim_id"] = claims[0]["claim_id"]

    _audit_after_manifest_edit(tmp_path / "duplicate", duplicate_claim_id)

    def extra_claim(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        assert isinstance(declaration, dict)
        claims = declaration["claims"]
        assert isinstance(claims, list)
        extra = dict(claims[0])
        extra["concept_id"] = "authenticity"
        claims.append(extra)

    _audit_after_manifest_edit(tmp_path / "extra", extra_claim)


def test_non_canonical_concept_claim_id_fails_audit(tmp_path: Path) -> None:
    def edit(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        assert isinstance(declaration, dict)
        claims = declaration["claims"]
        assert isinstance(claims, list)
        claims[0]["claim_id"] = "pcl_" + ("0" * 32)

    _audit_after_manifest_edit(tmp_path, edit)


def test_report_contains_proof_concepts_section_and_boundaries(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("report concepts\n", encoding="utf-8")
    proof_dir = tmp_path / "packet"
    create_proof_packet(sample, proof_dir, concept_ids=["integrity", "existence"])
    report = tmp_path / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(proof_dir / "manifest.json", report, key)
    text = report.read_bytes().decode("latin-1", errors="ignore")
    assert "Proof Concepts" in text
    assert "A result for one Proof Concept does not establish another Proof Concept." in text
    assert "authenticity, ownership, authorship, or truth" in text
