from __future__ import annotations

import json
from pathlib import Path

import pytest

from tohupono.core.canonical_json import canonical_json_text
from tohupono.concepts.execution import make_claim_id
from tohupono.core.proof import create_proof_packet, load_manifest
from tohupono.records.validation import (
    RECORD_DESCRIPTOR_SCHEMA_VERSION,
    RECORD_ENVELOPE_SCHEMA_VERSION,
    RECORDS_COLLECTION_SCHEMA_VERSION,
    RecordValidationError,
    build_record_envelope,
    load_record_descriptor,
    record_id_for_body,
)
from tohupono.security.limits import MAX_RECORD_DESCRIPTOR_BYTES, MAX_RECORD_ATTRIBUTE_DEPTH, MAX_RECORD_ATTRIBUTE_ITEMS
from tohupono.reporting.pro_report import generate_report

from tests.support import run_cli


def _descriptor(
    *,
    attributes: dict[str, object] | None = None,
    namespace: str = "local",
    reference: str | None = None,
    record_type: str = "generic",
) -> dict[str, object]:
    return {
        "attributes": attributes or {},
        "namespace": namespace,
        "record_type": record_type,
        "reference": reference,
        "schema_version": RECORD_DESCRIPTOR_SCHEMA_VERSION,
    }


def _write_descriptor(path: Path, value: dict[str, object] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json_text(value or _descriptor()) + "\n", encoding="utf-8")
    return path


def _proof_with_records(tmp_path: Path, *descriptors: Path) -> tuple[Path, Path]:
    sample = tmp_path / "source.txt"
    sample.write_text("records subject\n", encoding="utf-8")
    proof_dir = tmp_path / "packet"
    args = ["prove", str(sample), "--output", str(proof_dir), "--concept", "records"]
    for descriptor in descriptors:
        args.extend(["--record-json", str(descriptor)])
    result = run_cli(*args)
    assert result.returncode == 0, result.stderr
    return sample, proof_dir


def _audit_json(packet: Path) -> dict[str, object]:
    result = run_cli("audit", str(packet), "--json")
    assert result.stdout
    return json.loads(result.stdout)


def test_valid_descriptor_and_record_id_are_deterministic(tmp_path: Path) -> None:
    first = _write_descriptor(
        tmp_path / "first.json",
        _descriptor(attributes={"b": 2, "a": "one"}, namespace="local", reference="internal-document-001"),
    )
    second = _write_descriptor(
        tmp_path / "nested" / "second.json",
        _descriptor(attributes={"a": "one", "b": 2}, namespace="local", reference="internal-document-001"),
    )
    subject = "a" * 64

    first_record = build_record_envelope(load_record_descriptor(first), subject_algorithm="sha256", subject_digest=subject)
    second_record = build_record_envelope(load_record_descriptor(second), subject_algorithm="sha256", subject_digest=subject)
    assert first_record.record_id == second_record.record_id
    assert first_record.record_id.startswith("rec_")
    assert len(first_record.record_id) == 36

    changed_attr = build_record_envelope(
        load_record_descriptor(_write_descriptor(tmp_path / "changed_attr.json", _descriptor(attributes={"a": "two"}))),
        subject_algorithm="sha256",
        subject_digest=subject,
    )
    changed_namespace = build_record_envelope(
        load_record_descriptor(_write_descriptor(tmp_path / "changed_namespace.json", _descriptor(namespace="archive"))),
        subject_algorithm="sha256",
        subject_digest=subject,
    )
    changed_reference = build_record_envelope(
        load_record_descriptor(_write_descriptor(tmp_path / "changed_reference.json", _descriptor(reference="ref-2"))),
        subject_algorithm="sha256",
        subject_digest=subject,
    )
    changed_subject = build_record_envelope(
        load_record_descriptor(first),
        subject_algorithm="sha256",
        subject_digest="b" * 64,
    )
    assert len({first_record.record_id, changed_attr.record_id, changed_namespace.record_id, changed_reference.record_id, changed_subject.record_id}) == 5


@pytest.mark.parametrize(
    ("filename", "content", "code"),
    [
        ("duplicate.json", '{"schema_version":"tohupono.record_descriptor.v1","schema_version":"x","record_type":"generic","namespace":"local","attributes":{}}\n', "record_json_duplicate_key"),
        ("float.json", '{"schema_version":"tohupono.record_descriptor.v1","record_type":"generic","namespace":"local","attributes":{"x":1.5}}\n', "record_float_invalid"),
        ("nan.json", '{"schema_version":"tohupono.record_descriptor.v1","record_type":"generic","namespace":"local","attributes":{"x":NaN}}\n', "record_non_finite_invalid"),
        ("control.json", '{"schema_version":"tohupono.record_descriptor.v1","record_type":"generic","namespace":"local","attributes":{"x":"bad\\u0001"}}\n', "record_attributes_invalid"),
        ("bidi.json", '{"schema_version":"tohupono.record_descriptor.v1","record_type":"generic","namespace":"local","attributes":{"x":"bad\\u202e"}}\n', "record_attributes_invalid"),
    ],
)
def test_descriptor_strict_json_rejections(tmp_path: Path, filename: str, content: str, code: str) -> None:
    descriptor = tmp_path / filename
    descriptor.write_text(content, encoding="utf-8")
    with pytest.raises(RecordValidationError) as exc:
        load_record_descriptor(descriptor)
    assert exc.value.code == code


def test_descriptor_file_safety_rejections(tmp_path: Path) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(RecordValidationError) as directory_error:
        load_record_descriptor(directory)
    assert directory_error.value.code == "record_descriptor_not_file"

    target = _write_descriptor(tmp_path / "target.json")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(RecordValidationError) as link_error:
        load_record_descriptor(link)
    assert link_error.value.code == "record_descriptor_path_invalid"


def test_descriptor_size_depth_item_and_mutation_rejections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + (b" " * MAX_RECORD_DESCRIPTOR_BYTES) + b"}")
    with pytest.raises(RecordValidationError) as oversized_error:
        load_record_descriptor(oversized)
    assert oversized_error.value.code == "record_descriptor_too_large"

    value: object = "leaf"
    for _ in range(MAX_RECORD_ATTRIBUTE_DEPTH + 2):
        value = {"nested": value}
    deep = _write_descriptor(tmp_path / "deep.json", _descriptor(attributes={"deep": value}))
    with pytest.raises(RecordValidationError) as deep_error:
        load_record_descriptor(deep)
    assert deep_error.value.code == "record_attributes_invalid"

    too_many = _write_descriptor(
        tmp_path / "too_many.json",
        _descriptor(attributes={f"k{i}": i for i in range(MAX_RECORD_ATTRIBUTE_ITEMS + 1)}),
    )
    with pytest.raises(RecordValidationError) as item_error:
        load_record_descriptor(too_many)
    assert item_error.value.code == "record_attributes_invalid"

    changed = _write_descriptor(tmp_path / "changed.json")
    original_read_bytes = Path.read_bytes

    def mutate_during_read(path: Path) -> bytes:
        data = original_read_bytes(path)
        if path == changed:
            path.write_text(canonical_json_text(_descriptor(attributes={"changed": True})) + "\n", encoding="utf-8")
        return data

    monkeypatch.setattr(Path, "read_bytes", mutate_during_read)
    with pytest.raises(RecordValidationError) as changed_error:
        load_record_descriptor(changed)
    assert changed_error.value.code == "record_descriptor_changed"


def test_prove_records_manifest_and_identity_rules(tmp_path: Path) -> None:
    descriptor_a = _write_descriptor(tmp_path / "a.json", _descriptor(attributes={"name": "A"}, reference="ref-a"))
    descriptor_b = _write_descriptor(tmp_path / "b.json", _descriptor(attributes={"name": "B"}, reference="ref-b"))
    sample = tmp_path / "source.txt"
    sample.write_text("records identity\n", encoding="utf-8")
    sealed_at = "2026-07-13T00:00:00Z"

    first = tmp_path / "first"
    second = tmp_path / "second"
    changed = tmp_path / "changed"
    default = tmp_path / "default"
    create_proof_packet(sample, first, sealed_at_utc=sealed_at, concept_ids=["records"], record_descriptor_paths=[descriptor_a, descriptor_b])
    create_proof_packet(sample, second, sealed_at_utc=sealed_at, concept_ids=["records"], record_descriptor_paths=[descriptor_b, descriptor_a])
    changed_descriptor = _write_descriptor(tmp_path / "changed_record.json", _descriptor(attributes={"name": "C"}, reference="ref-a"))
    create_proof_packet(sample, changed, sealed_at_utc=sealed_at, concept_ids=["records"], record_descriptor_paths=[changed_descriptor])
    create_proof_packet(sample, default, sealed_at_utc=sealed_at)

    first_manifest = load_manifest(first / "manifest.json")
    second_manifest = load_manifest(second / "manifest.json")
    changed_manifest = load_manifest(changed / "manifest.json")
    default_manifest = load_manifest(default / "manifest.json")

    assert first_manifest["identifiers"] == second_manifest["identifiers"]
    assert first_manifest["identifiers"]["proof_id"] != changed_manifest["identifiers"]["proof_id"]
    assert "records" not in default_manifest
    assert default_manifest["proof_concepts"]["requested"] == ["existence", "integrity"]
    records = first_manifest["records"]
    assert records["schema_version"] == RECORDS_COLLECTION_SCHEMA_VERSION
    items = records["items"]
    assert [item["record_id"] for item in items] == sorted(item["record_id"] for item in items)
    assert all("a.json" not in canonical_json_text(item) for item in items)
    claim = first_manifest["proof_concepts"]["claims"][0]
    assert claim["concept_id"] == "records"
    assert claim["parameters"]["record_ids"] == [item["record_id"] for item in items]
    assert claim["parameters"]["records_schema_version"] == RECORDS_COLLECTION_SCHEMA_VERSION


def test_prove_records_argument_rules(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("records args\n", encoding="utf-8")
    descriptor = _write_descriptor(tmp_path / "record.json")

    missing_descriptor = run_cli("prove", str(sample), "--output", str(tmp_path / "missing"), "--concept", "records")
    assert missing_descriptor.returncode == 2
    without_concept = run_cli("prove", str(sample), "--output", str(tmp_path / "without"), "--record-json", str(descriptor))
    assert without_concept.returncode == 2
    duplicate = run_cli(
        "prove",
        str(sample),
        "--output",
        str(tmp_path / "duplicate"),
        "--concept",
        "records",
        "--record-json",
        str(descriptor),
        "--record-json",
        str(descriptor),
    )
    assert duplicate.returncode == 2


def test_valid_records_verify_audit_and_inspect(tmp_path: Path) -> None:
    descriptor = _write_descriptor(
        tmp_path / "record.json",
        _descriptor(attributes={"sensitive_note": "do-not-print-human"}, reference="internal-document-001"),
    )
    _sample, packet = _proof_with_records(tmp_path, descriptor)

    inspect_json = run_cli("record", "inspect", str(packet), "--json")
    assert inspect_json.returncode == 0, inspect_json.stderr
    inspect_data = json.loads(inspect_json.stdout)
    assert inspect_data["status"] == "pass"
    assert inspect_data["record_count"] == 1
    assert inspect_data["records"][0]["attributes"]["sensitive_note"] == "do-not-print-human"

    inspect_human = run_cli("record", "inspect", str(packet))
    assert inspect_human.returncode == 0
    assert "do-not-print-human" not in inspect_human.stdout
    assert "Record ID:" in inspect_human.stdout

    audit = run_cli("audit", str(packet), "--json")
    assert audit.returncode == 0, audit.stderr
    audit_data = json.loads(audit.stdout)
    records_result = audit_data["proof_concept_results"][0]
    assert records_result["concept_id"] == "records"
    assert records_result["status"] == "PASS"
    assert records_result["record_count"] == 1
    assert "truth" in records_result["limitations"][0]

    audit_human = run_cli("audit", str(packet))
    assert audit_human.returncode == 0
    assert "records: 1" in audit_human.stdout
    assert "do-not-print-human" not in audit_human.stdout


def _tampered_records_audit(tmp_path: Path, edit: object) -> dict[str, object]:
    descriptor = _write_descriptor(tmp_path / "record.json", _descriptor(attributes={"name": "A"}))
    _sample, packet = _proof_with_records(tmp_path, descriptor)
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    if callable(edit):
        edit(manifest)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    result = run_cli("audit", str(packet), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    records_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "records")
    assert records_result["status"] == "FAIL"
    assert data["proof_concept_summary"]["overall_status"] == "FAIL"
    return records_result


@pytest.mark.parametrize(
    ("name", "edit", "failure"),
    [
        ("missing_section", lambda manifest: manifest.pop("records"), "records_section_missing"),
        ("empty", lambda manifest: manifest["records"].update({"items": []}), "records_empty"),
        ("extra_collection_field", lambda manifest: manifest["records"].update({"verified": True}), "records_items_invalid"),
        ("unsupported_schema", lambda manifest: manifest["records"].update({"schema_version": "tohupono.records.v99"}), "records_schema_unsupported"),
        ("record_id_mismatch", lambda manifest: manifest["records"]["items"][0]["attributes"].update({"name": "B"}), "record_id_mismatch"),
        ("subject_mismatch", lambda manifest: manifest["records"]["items"][0]["subject"].update({"digest": "0" * 64}), "record_subject_digest_mismatch"),
        ("duplicate_record_id", lambda manifest: manifest["records"]["items"].append(dict(manifest["records"]["items"][0])), "record_duplicate_id"),
    ],
)
def test_tampered_records_fail_audit(tmp_path: Path, name: str, edit: object, failure: str) -> None:
    result = _tampered_records_audit(tmp_path / name, edit)
    assert failure in result["failures"]


def test_claim_and_record_mismatch_failures(tmp_path: Path) -> None:
    def extra_unclaimed(manifest: dict[str, object]) -> None:
        records = manifest["records"]
        assert isinstance(records, dict)
        items = records["items"]
        assert isinstance(items, list)
        extra = dict(items[0])
        body = {key: value for key, value in extra.items() if key != "record_id"}
        body["reference"] = "extra"
        extra.update(body)
        extra["record_id"] = record_id_for_body(body)
        items.append(extra)
        items.sort(key=lambda item: item["record_id"])

    extra = _tampered_records_audit(tmp_path / "extra", extra_unclaimed)
    assert "record_claim_undeclared" in extra["failures"]

    def missing_claimed(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        assert isinstance(declaration, dict)
        claim = declaration["claims"][0]
        assert isinstance(claim, dict)
        params = claim["parameters"]
        assert isinstance(params, dict)
        params["record_ids"] = ["rec_" + ("0" * 32)]
        claim["claim_id"] = make_claim_id("records", claim["subject"], params)

    missing = _tampered_records_audit(tmp_path / "missing_claim", missing_claimed)
    assert "record_claim_missing" in missing["failures"]

    def duplicate_claim(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        assert isinstance(declaration, dict)
        claim = declaration["claims"][0]
        assert isinstance(claim, dict)
        params = claim["parameters"]
        assert isinstance(params, dict)
        record_ids = params["record_ids"]
        assert isinstance(record_ids, list)
        params["record_ids"] = [record_ids[0], record_ids[0]]
        claim["claim_id"] = make_claim_id("records", claim["subject"], params)

    duplicate = _tampered_records_audit(tmp_path / "duplicate_claim", duplicate_claim)
    assert "record_claim_duplicate_id" in duplicate["failures"]


def test_records_claim_order_mismatch_fails(tmp_path: Path) -> None:
    descriptor_a = _write_descriptor(tmp_path / "a.json", _descriptor(reference="ref-a"))
    descriptor_b = _write_descriptor(tmp_path / "b.json", _descriptor(reference="ref-b"))
    _sample, packet = _proof_with_records(tmp_path, descriptor_a, descriptor_b)
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    claim = manifest["proof_concepts"]["claims"][0]
    params = claim["parameters"]
    params["record_ids"] = list(reversed(params["record_ids"]))
    claim["claim_id"] = make_claim_id("records", claim["subject"], params)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    result = run_cli("audit", str(packet), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    records_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "records")
    assert "record_claim_order_mismatch" in records_result["failures"]


def test_record_validate_cli_and_human_privacy(tmp_path: Path) -> None:
    descriptor = _write_descriptor(tmp_path / "record.json", _descriptor(attributes={"secret_value": "hidden"}))
    machine = run_cli("record", "validate", str(descriptor), "--json")
    assert machine.returncode == 0
    data = json.loads(machine.stdout)
    assert data["status"] == "ok"
    assert data["attribute_count"] == 1
    human = run_cli("record", "validate", str(descriptor))
    assert human.returncode == 0
    assert "hidden" not in human.stdout
    assert "Descriptor validation does not prove declared metadata is true" in human.stdout


def test_report_contains_records_section_without_full_attributes(tmp_path: Path) -> None:
    descriptor = _write_descriptor(
        tmp_path / "record.json",
        _descriptor(attributes={"private_detail": "do-not-render"}, namespace="local", reference="report-ref"),
    )
    _sample, packet = _proof_with_records(tmp_path, descriptor)
    report = tmp_path / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(packet / "manifest.json", report, key)
    text = report.read_bytes().decode("latin-1", errors="ignore")
    assert "Proof of Records Details" in text
    assert "report-ref" in text
    assert "do-not-render" not in text
    assert "does not independently establish that declared record metadata is true" in text
    assert report.with_suffix(".pdf.sig").exists()
