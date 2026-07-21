from __future__ import annotations

import json
from pathlib import Path

import pytest

from tohupono.concepts.execution import make_claim_id
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.proof import create_proof_packet, load_manifest
from tohupono.provenance.validation import (
    PROVENANCE_COLLECTION_SCHEMA_VERSION,
    PROVENANCE_DESCRIPTOR_SCHEMA_VERSION,
    PROVENANCE_EDGE_SCHEMA_VERSION,
    ProvenanceValidationError,
    build_provenance_edge,
    load_provenance_descriptor,
    provenance_edge_id_for_body,
)
from tohupono.reporting.pro_report import generate_report
from tohupono.security.limits import MAX_PROVENANCE_DESCRIPTOR_BYTES, MAX_RECORD_ATTRIBUTE_DEPTH, MAX_RECORD_ATTRIBUTE_ITEMS

from tests.support import run_cli

PARENT_A = "a" * 64
PARENT_B = "b" * 64
CHILD = "c" * 64


def _descriptor(
    *,
    relation_type: str = "derived_from",
    parent_digest: str = PARENT_A,
    operation: dict[str, object] | None = None,
    occurred_at: str | None = None,
    actor: dict[str, object] | None = None,
    reference: str | None = None,
    attributes: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "actor": actor,
        "attributes": attributes or {},
        "occurred_at": occurred_at,
        "operation": operation,
        "parent": {"algorithm": "sha256", "digest": parent_digest},
        "reference": reference,
        "relation_type": relation_type,
        "schema_version": PROVENANCE_DESCRIPTOR_SCHEMA_VERSION,
    }


def _write_descriptor(path: Path, value: dict[str, object] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json_text(value or _descriptor()) + "\n", encoding="utf-8")
    return path


def _proof_with_provenance(tmp_path: Path, *descriptors: Path) -> tuple[Path, Path]:
    sample = tmp_path / "source.txt"
    sample.write_text("provenance subject\n", encoding="utf-8")
    packet = tmp_path / "packet"
    args = ["prove", str(sample), "--output", str(packet), "--concept", "provenance"]
    for descriptor in descriptors:
        args.extend(["--provenance-json", str(descriptor)])
    result = run_cli(*args)
    assert result.returncode == 0, result.stderr
    return sample, packet


@pytest.mark.parametrize("relation", ["derived_from", "copied_from", "converted_from", "edited_from", "generated_from", "extracted_from", "transcoded_from"])
def test_valid_descriptor_relation_types(tmp_path: Path, relation: str) -> None:
    descriptor = load_provenance_descriptor(_write_descriptor(tmp_path / f"{relation}.json", _descriptor(relation_type=relation)))
    assert descriptor.relation_type == relation


@pytest.mark.parametrize(
    ("name", "content", "code"),
    [
        ("duplicate.json", '{"schema_version":"tohupono.provenance_descriptor.v1","schema_version":"x","relation_type":"derived_from","parent":{"algorithm":"sha256","digest":"' + PARENT_A + '"},"attributes":{}}\n', "provenance_json_duplicate_key"),
        ("float.json", '{"schema_version":"tohupono.provenance_descriptor.v1","relation_type":"derived_from","parent":{"algorithm":"sha256","digest":"' + PARENT_A + '"},"attributes":{"x":1.5}}\n', "provenance_float_invalid"),
        ("nan.json", '{"schema_version":"tohupono.provenance_descriptor.v1","relation_type":"derived_from","parent":{"algorithm":"sha256","digest":"' + PARENT_A + '"},"attributes":{"x":NaN}}\n', "provenance_non_finite_invalid"),
        ("control.json", '{"schema_version":"tohupono.provenance_descriptor.v1","relation_type":"derived_from","parent":{"algorithm":"sha256","digest":"' + PARENT_A + '"},"attributes":{"x":"bad\\u0001"}}\n', "provenance_attributes_invalid"),
        ("bidi.json", '{"schema_version":"tohupono.provenance_descriptor.v1","relation_type":"derived_from","parent":{"algorithm":"sha256","digest":"' + PARENT_A + '"},"attributes":{"x":"bad\\u202e"}}\n', "provenance_attributes_invalid"),
    ],
)
def test_descriptor_strict_json_rejections(tmp_path: Path, name: str, content: str, code: str) -> None:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ProvenanceValidationError) as exc:
        load_provenance_descriptor(path)
    assert exc.value.code == code


def test_descriptor_validation_and_file_safety_rejections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ProvenanceValidationError) as unsupported:
        load_provenance_descriptor(_write_descriptor(tmp_path / "bad_relation.json", _descriptor(relation_type="signed_by")))
    assert unsupported.value.code == "provenance_relation_type_unsupported"

    with pytest.raises(ProvenanceValidationError) as schema:
        load_provenance_descriptor(_write_descriptor(tmp_path / "bad_schema.json", {**_descriptor(), "schema_version": "x"}))
    assert schema.value.code == "provenance_descriptor_schema_unsupported"

    with pytest.raises(ProvenanceValidationError) as algorithm:
        load_provenance_descriptor(_write_descriptor(tmp_path / "algo.json", {**_descriptor(), "parent": {"algorithm": "sha512", "digest": PARENT_A}}))
    assert algorithm.value.code == "provenance_parent_invalid"

    with pytest.raises(ProvenanceValidationError) as digest:
        load_provenance_descriptor(_write_descriptor(tmp_path / "digest.json", _descriptor(parent_digest=PARENT_A.upper())))
    assert digest.value.code == "provenance_parent_invalid"

    with pytest.raises(ProvenanceValidationError) as offset:
        load_provenance_descriptor(_write_descriptor(tmp_path / "offset.json", _descriptor(occurred_at="2026-07-13T01:02:03+12:00")))
    assert offset.value.code == "provenance_occurred_at_invalid"

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ProvenanceValidationError) as directory_error:
        load_provenance_descriptor(directory)
    assert directory_error.value.code == "provenance_descriptor_not_file"

    target = _write_descriptor(tmp_path / "target.json")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(ProvenanceValidationError):
        load_provenance_descriptor(link)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + (b" " * MAX_PROVENANCE_DESCRIPTOR_BYTES) + b"}")
    with pytest.raises(ProvenanceValidationError) as oversized_error:
        load_provenance_descriptor(oversized)
    assert oversized_error.value.code == "provenance_descriptor_too_large"

    value: object = "leaf"
    for _ in range(MAX_RECORD_ATTRIBUTE_DEPTH + 2):
        value = {"nested": value}
    with pytest.raises(ProvenanceValidationError):
        load_provenance_descriptor(_write_descriptor(tmp_path / "deep.json", _descriptor(attributes={"deep": value})))

    too_many = _write_descriptor(tmp_path / "too_many.json", _descriptor(attributes={f"k{i}": i for i in range(MAX_RECORD_ATTRIBUTE_ITEMS + 1)}))
    with pytest.raises(ProvenanceValidationError):
        load_provenance_descriptor(too_many)

    changed = _write_descriptor(tmp_path / "changed.json")
    original_read_bytes = Path.read_bytes

    def mutate_during_read(path: Path) -> bytes:
        data = original_read_bytes(path)
        if path == changed:
            path.write_text(canonical_json_text(_descriptor(attributes={"changed": True})) + "\n", encoding="utf-8")
        return data

    monkeypatch.setattr(Path, "read_bytes", mutate_during_read)
    with pytest.raises(ProvenanceValidationError) as changed_error:
        load_provenance_descriptor(changed)
    assert changed_error.value.code == "provenance_descriptor_changed"


def test_edge_id_is_deterministic_and_metadata_sensitive(tmp_path: Path) -> None:
    first = load_provenance_descriptor(_write_descriptor(tmp_path / "first.json", _descriptor(attributes={"b": 2, "a": "one"})))
    second = load_provenance_descriptor(_write_descriptor(tmp_path / "nested" / "second.json", _descriptor(attributes={"a": "one", "b": 2})))
    edge_a = build_provenance_edge(first, child_algorithm="sha256", child_digest=CHILD)
    edge_b = build_provenance_edge(second, child_algorithm="sha256", child_digest=CHILD)
    assert edge_a.edge_id == edge_b.edge_id
    assert edge_a.edge_id.startswith("prv_")
    assert len(edge_a.edge_id) == 36
    assert edge_a.edge_id == provenance_edge_id_for_body({k: v for k, v in edge_a.to_dict().items() if k != "edge_id"})

    variants = [
        _descriptor(relation_type="edited_from"),
        _descriptor(parent_digest=PARENT_B),
        _descriptor(operation={"name": "convert", "version": "1"}),
        _descriptor(occurred_at="2026-07-13T00:00:00Z"),
        _descriptor(actor={"namespace": "local", "identifier": "operator-1"}),
        _descriptor(reference="ref-1"),
        _descriptor(attributes={"a": "two"}),
    ]
    ids = {edge_a.edge_id}
    for index, value in enumerate(variants):
        descriptor = load_provenance_descriptor(_write_descriptor(tmp_path / f"variant_{index}.json", value))
        ids.add(build_provenance_edge(descriptor, child_algorithm="sha256", child_digest=CHILD).edge_id)
    ids.add(build_provenance_edge(first, child_algorithm="sha256", child_digest="d" * 64).edge_id)
    assert len(ids) == 9

    copied = load_provenance_descriptor(_write_descriptor(tmp_path / "copy.json", _descriptor(relation_type="copied_from", parent_digest=CHILD)))
    assert build_provenance_edge(copied, child_algorithm="sha256", child_digest=CHILD).edge_id.startswith("prv_")
    with pytest.raises(ProvenanceValidationError):
        build_provenance_edge(first, child_algorithm="sha256", child_digest=PARENT_A)


def test_prove_provenance_manifest_and_identity_rules(tmp_path: Path) -> None:
    descriptor_a = _write_descriptor(tmp_path / "a.json", _descriptor(parent_digest=PARENT_A, reference="a"))
    descriptor_b = _write_descriptor(tmp_path / "b.json", _descriptor(parent_digest=PARENT_B, reference="b"))
    sample = tmp_path / "source.txt"
    sample.write_text("provenance identity\n", encoding="utf-8")
    sealed_at = "2026-07-13T00:00:00Z"

    first = tmp_path / "first"
    second = tmp_path / "second"
    changed = tmp_path / "changed"
    default = tmp_path / "default"
    create_proof_packet(sample, first, sealed_at_utc=sealed_at, concept_ids=["provenance"], provenance_descriptor_paths=[descriptor_a, descriptor_b])
    create_proof_packet(sample, second, sealed_at_utc=sealed_at, concept_ids=["provenance"], provenance_descriptor_paths=[descriptor_b, descriptor_a])
    changed_descriptor = _write_descriptor(tmp_path / "changed.json", _descriptor(parent_digest="d" * 64))
    create_proof_packet(sample, changed, sealed_at_utc=sealed_at, concept_ids=["provenance"], provenance_descriptor_paths=[changed_descriptor])
    create_proof_packet(sample, default, sealed_at_utc=sealed_at)

    first_manifest = load_manifest(first / "manifest.json")
    second_manifest = load_manifest(second / "manifest.json")
    changed_manifest = load_manifest(changed / "manifest.json")
    default_manifest = load_manifest(default / "manifest.json")
    assert first_manifest["identifiers"] == second_manifest["identifiers"]
    assert first_manifest["identifiers"]["proof_id"] != changed_manifest["identifiers"]["proof_id"]
    assert "provenance" not in default_manifest
    assert default_manifest["proof_concepts"]["requested"] == ["existence", "integrity"]
    provenance = first_manifest["provenance"]
    assert provenance["schema_version"] == PROVENANCE_COLLECTION_SCHEMA_VERSION
    assert provenance["edge_count"] == 2
    assert [edge["edge_id"] for edge in provenance["edges"]] == sorted(edge["edge_id"] for edge in provenance["edges"])
    assert all("a.json" not in canonical_json_text(edge) for edge in provenance["edges"])
    claim = first_manifest["proof_concepts"]["claims"][0]
    assert claim["concept_id"] == "provenance"
    assert claim["parameters"]["edge_ids"] == [edge["edge_id"] for edge in provenance["edges"]]
    assert claim["parameters"]["child"] == {"algorithm": "sha256", "digest": first_manifest["file"]["sha256"]}


def test_prove_provenance_argument_rules(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("provenance args\n", encoding="utf-8")
    descriptor = _write_descriptor(tmp_path / "provenance.json")
    missing = run_cli("prove", str(sample), "--output", str(tmp_path / "missing"), "--concept", "provenance")
    assert missing.returncode == 2
    without_concept = run_cli("prove", str(sample), "--output", str(tmp_path / "without"), "--provenance-json", str(descriptor))
    assert without_concept.returncode == 2
    duplicate = run_cli(
        "prove", str(sample), "--output", str(tmp_path / "dup"), "--concept", "provenance", "--provenance-json", str(descriptor), "--provenance-json", str(descriptor)
    )
    assert duplicate.returncode == 2


def _tampered_provenance_audit(tmp_path: Path, edit: object) -> dict[str, object]:
    descriptor = _write_descriptor(tmp_path / "provenance.json")
    _sample, packet = _proof_with_provenance(tmp_path, descriptor)
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    if callable(edit):
        edit(manifest)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    result = run_cli("audit", str(packet), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    provenance_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "provenance")
    assert provenance_result["status"] == "FAIL"
    assert data["proof_concept_summary"]["overall_status"] == "FAIL"
    return provenance_result


@pytest.mark.parametrize(
    ("name", "edit", "failure"),
    [
        ("missing_section", lambda manifest: manifest.pop("provenance"), "provenance_section_missing"),
        ("empty", lambda manifest: manifest["provenance"].update({"edges": [], "edge_count": 0}), "provenance_empty"),
        ("count", lambda manifest: manifest["provenance"].update({"edge_count": 99}), "provenance_edge_count_mismatch"),
        ("extra_collection_field", lambda manifest: manifest["provenance"].update({"verified": True}), "provenance_edges_invalid"),
        ("schema", lambda manifest: manifest["provenance"].update({"schema_version": "tohupono.provenance.v99"}), "provenance_schema_unsupported"),
        ("edge_id", lambda manifest: manifest["provenance"]["edges"][0].update({"edge_id": "prv_" + "0" * 32}), "provenance_edge_id_mismatch"),
        ("child", lambda manifest: manifest["provenance"]["edges"][0]["child"].update({"digest": "0" * 64}), "provenance_child_digest_mismatch"),
        ("parent", lambda manifest: manifest["provenance"]["edges"][0]["parent"].update({"digest": "not-a-digest"}), "provenance_parent_invalid"),
        ("duplicate", lambda manifest: manifest["provenance"]["edges"].append(dict(manifest["provenance"]["edges"][0])), "provenance_edge_count_mismatch"),
    ],
)
def test_tampered_provenance_fails_audit(tmp_path: Path, name: str, edit: object, failure: str) -> None:
    result = _tampered_provenance_audit(tmp_path / name, edit)
    assert failure in result["failures"]


def test_claim_and_edge_mismatch_failures(tmp_path: Path) -> None:
    def extra_unclaimed(manifest: dict[str, object]) -> None:
        provenance = manifest["provenance"]
        edges = provenance["edges"]
        extra = dict(edges[0])
        body = {key: value for key, value in extra.items() if key != "edge_id"}
        body["reference"] = "extra"
        extra.update(body)
        extra["edge_id"] = provenance_edge_id_for_body(body)
        edges.append(extra)
        provenance["edge_count"] = len(edges)
        edges.sort(key=lambda item: item["edge_id"])

    assert "provenance_claim_edge_undeclared" in _tampered_provenance_audit(tmp_path / "extra", extra_unclaimed)["failures"]

    def missing_claimed(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        params["edge_ids"] = ["prv_" + "0" * 32]
        claim["claim_id"] = make_claim_id("provenance", claim["subject"], params)

    assert "provenance_claim_edge_missing" in _tampered_provenance_audit(tmp_path / "missing", missing_claimed)["failures"]

    def duplicate_claim(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        edge_ids = params["edge_ids"]
        params["edge_ids"] = [edge_ids[0], edge_ids[0]]
        claim["claim_id"] = make_claim_id("provenance", claim["subject"], params)

    assert "provenance_claim_edge_duplicate" in _tampered_provenance_audit(tmp_path / "duplicate", duplicate_claim)["failures"]

    def child_mismatch(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        params["child"] = {"algorithm": "sha256", "digest": "0" * 64}
        claim["claim_id"] = make_claim_id("provenance", claim["subject"], params)

    assert "provenance_claim_child_mismatch" in _tampered_provenance_audit(tmp_path / "child", child_mismatch)["failures"]


def test_provenance_cli_privacy_audit_and_report(tmp_path: Path) -> None:
    descriptor = _write_descriptor(
        tmp_path / "provenance.json",
        _descriptor(attributes={"private_note": "do-not-render"}, reference="lineage-ref", operation={"name": "convert", "version": None}),
    )
    validate = run_cli("provenance", "validate", str(descriptor), "--json")
    assert validate.returncode == 0
    assert json.loads(validate.stdout)["status"] == "ok"
    human_validate = run_cli("provenance", "validate", str(descriptor))
    assert "do-not-render" not in human_validate.stdout
    assert "does not prove" in human_validate.stdout

    _sample, packet = _proof_with_provenance(tmp_path, descriptor)
    inspect_json = run_cli("provenance", "inspect", str(packet), "--json")
    assert inspect_json.returncode == 0
    assert json.loads(inspect_json.stdout)["edge_count"] == 1
    inspect_human = run_cli("provenance", "inspect", str(packet))
    assert "do-not-render" not in inspect_human.stdout
    assert "Edge ID:" in inspect_human.stdout

    audit = run_cli("audit", str(packet), "--json")
    assert audit.returncode == 0
    data = json.loads(audit.stdout)
    provenance_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "provenance")
    assert provenance_result["status"] == "PASS"
    assert "parent" in provenance_result["limitations"][0].lower()

    report = tmp_path / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(packet / "manifest.json", report, key)
    text = report.read_bytes().decode("latin-1", errors="ignore")
    assert "Proof of Provenance Details" in text
    assert "do-not-render" not in text
    assert "does not independently prove" in text
    assert report.with_suffix(".pdf.sig").exists()


def test_records_custody_and_provenance_are_separate(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("combined concepts\n", encoding="utf-8")
    record = tmp_path / "record.json"
    record.write_text('{"schema_version":"tohupono.record_descriptor.v1","record_type":"generic","namespace":"local","reference":null,"attributes":{}}\n', encoding="utf-8")
    custody = tmp_path / "custody.json"
    custody.write_text('{"schema_version":"tohupono.custody_descriptor.v1","event_type":"received","actor":{"namespace":"local","identifier":"operator-1"},"occurred_at":null,"location":null,"reference":null,"attributes":{}}\n', encoding="utf-8")
    provenance = _write_descriptor(tmp_path / "provenance.json")
    packet = tmp_path / "packet"
    result = run_cli(
        "prove", str(sample), "--output", str(packet),
        "--concept", "records", "--concept", "custody", "--concept", "provenance",
        "--record-json", str(record), "--custody-json", str(custody), "--provenance-json", str(provenance),
    )
    assert result.returncode == 0, result.stderr
    audit = run_cli("audit", str(packet), "--json")
    data = json.loads(audit.stdout)
    statuses = {item["concept_id"]: item["status"] for item in data["proof_concept_results"]}
    assert statuses["records"] == "PASS"
    assert statuses["custody"] == "PASS"
    assert statuses["provenance"] == "PASS"

    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest["provenance"]["edges"][0]["edge_id"] = "prv_" + "0" * 32
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    tampered = run_cli("audit", str(packet), "--json")
    tampered_data = json.loads(tampered.stdout)
    tampered_statuses = {item["concept_id"]: item["status"] for item in tampered_data["proof_concept_results"]}
    assert tampered_statuses["provenance"] == "FAIL"
    assert tampered_statuses["records"] == "PASS"
    assert tampered_statuses["custody"] == "PASS"


def test_legacy_packet_without_provenance_remains_valid(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("legacy provenance\n", encoding="utf-8")
    packet = tmp_path / "packet"
    create_proof_packet(sample, packet, sealed_at_utc="2026-07-13T00:00:00Z")
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest.pop("proof_concepts", None)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    audit = run_cli("audit", str(packet), "--json")
    data = json.loads(audit.stdout)
    assert "provenance" not in data["declared_proof_concepts"]
    assert data["proof_concept_summary"]["overall_status"] == "UNPROVEN"
