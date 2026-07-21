from __future__ import annotations

import json
from pathlib import Path

import pytest

from tohupono.concepts.execution import make_claim_id
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.proof import create_proof_packet, load_manifest
from tohupono.custody.validation import (
    CUSTODY_COLLECTION_SCHEMA_VERSION,
    CUSTODY_DESCRIPTOR_SCHEMA_VERSION,
    CUSTODY_EVENT_SCHEMA_VERSION,
    CustodyValidationError,
    build_custody_chain,
    custody_event_hash_for_body,
    load_custody_descriptor,
)
from tohupono.reporting.pro_report import generate_report
from tohupono.security.limits import MAX_CUSTODY_DESCRIPTOR_BYTES, MAX_RECORD_ATTRIBUTE_DEPTH

from tests.support import run_cli


def _descriptor(
    *,
    event_type: str = "received",
    actor: dict[str, object] | None = None,
    occurred_at: str | None = None,
    location: str | None = None,
    reference: str | None = None,
    attributes: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "actor": actor or {"namespace": "local", "identifier": "operator-1"},
        "attributes": attributes or {},
        "event_type": event_type,
        "location": location,
        "occurred_at": occurred_at,
        "reference": reference,
        "schema_version": CUSTODY_DESCRIPTOR_SCHEMA_VERSION,
    }


def _write_descriptor(path: Path, value: dict[str, object] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json_text(value or _descriptor()) + "\n", encoding="utf-8")
    return path


def _proof_with_custody(tmp_path: Path, *descriptors: Path) -> tuple[Path, Path]:
    sample = tmp_path / "source.txt"
    sample.write_text("custody subject\n", encoding="utf-8")
    packet = tmp_path / "packet"
    args = ["prove", str(sample), "--output", str(packet), "--concept", "custody"]
    for descriptor in descriptors:
        args.extend(["--custody-json", str(descriptor)])
    result = run_cli(*args)
    assert result.returncode == 0, result.stderr
    return sample, packet


@pytest.mark.parametrize("event_type", ["created", "received", "transferred", "copied", "verified", "stored", "released"])
def test_valid_descriptor_event_types(tmp_path: Path, event_type: str) -> None:
    descriptor = load_custody_descriptor(_write_descriptor(tmp_path / f"{event_type}.json", _descriptor(event_type=event_type)))
    assert descriptor.event_type == event_type


@pytest.mark.parametrize(
    ("name", "content", "code"),
    [
        ("duplicate.json", '{"schema_version":"tohupono.custody_descriptor.v1","schema_version":"x","event_type":"received","actor":{"namespace":"local","identifier":"op"},"attributes":{}}\n', "custody_json_duplicate_key"),
        ("float.json", '{"schema_version":"tohupono.custody_descriptor.v1","event_type":"received","actor":{"namespace":"local","identifier":"op"},"attributes":{"x":1.5}}\n', "custody_float_invalid"),
        ("nan.json", '{"schema_version":"tohupono.custody_descriptor.v1","event_type":"received","actor":{"namespace":"local","identifier":"op"},"attributes":{"x":NaN}}\n', "custody_non_finite_invalid"),
        ("control.json", '{"schema_version":"tohupono.custody_descriptor.v1","event_type":"received","actor":{"namespace":"local","identifier":"op"},"attributes":{"x":"bad\\u0001"}}\n', "custody_attributes_invalid"),
        ("bidi.json", '{"schema_version":"tohupono.custody_descriptor.v1","event_type":"received","actor":{"namespace":"local","identifier":"op"},"attributes":{"x":"bad\\u202e"}}\n', "custody_attributes_invalid"),
    ],
)
def test_descriptor_strict_json_rejections(tmp_path: Path, name: str, content: str, code: str) -> None:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    with pytest.raises(CustodyValidationError) as exc:
        load_custody_descriptor(path)
    assert exc.value.code == code


def test_descriptor_validation_rejections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(CustodyValidationError) as unsupported:
        load_custody_descriptor(_write_descriptor(tmp_path / "bad_type.json", _descriptor(event_type="seized")))
    assert unsupported.value.code == "custody_event_type_unsupported"

    with pytest.raises(CustodyValidationError) as actor:
        load_custody_descriptor(_write_descriptor(tmp_path / "bad_actor.json", _descriptor(actor={"namespace": "local"})))
    assert actor.value.code == "custody_actor_invalid"

    with pytest.raises(CustodyValidationError) as offset:
        load_custody_descriptor(_write_descriptor(tmp_path / "offset.json", _descriptor(occurred_at="2026-07-13T01:02:03+12:00")))
    assert offset.value.code == "custody_occurred_at_invalid"
    with pytest.raises(CustodyValidationError) as impossible:
        load_custody_descriptor(_write_descriptor(tmp_path / "impossible.json", _descriptor(occurred_at="2026-99-99T99:99:99Z")))
    assert impossible.value.code == "custody_occurred_at_invalid"

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(CustodyValidationError) as directory_error:
        load_custody_descriptor(directory)
    assert directory_error.value.code == "custody_descriptor_not_file"

    target = _write_descriptor(tmp_path / "target.json")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(CustodyValidationError):
        load_custody_descriptor(link)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + (b" " * MAX_CUSTODY_DESCRIPTOR_BYTES) + b"}")
    with pytest.raises(CustodyValidationError) as oversized_error:
        load_custody_descriptor(oversized)
    assert oversized_error.value.code == "custody_descriptor_too_large"

    value: object = "leaf"
    for _ in range(MAX_RECORD_ATTRIBUTE_DEPTH + 2):
        value = {"nested": value}
    with pytest.raises(CustodyValidationError):
        load_custody_descriptor(_write_descriptor(tmp_path / "deep.json", _descriptor(attributes={"deep": value})))

    changed = _write_descriptor(tmp_path / "changed.json")
    original_read_bytes = Path.read_bytes

    def mutate_during_read(path: Path) -> bytes:
        data = original_read_bytes(path)
        if path == changed:
            path.write_text(canonical_json_text(_descriptor(attributes={"changed": True})) + "\n", encoding="utf-8")
        return data

    monkeypatch.setattr(Path, "read_bytes", mutate_during_read)
    with pytest.raises(CustodyValidationError) as changed_error:
        load_custody_descriptor(changed)
    assert changed_error.value.code == "custody_descriptor_changed"


def test_event_identity_and_chain_are_deterministic(tmp_path: Path) -> None:
    first = load_custody_descriptor(
        _write_descriptor(tmp_path / "first.json", _descriptor(occurred_at="2026-07-13T00:00:00Z", attributes={"b": 2, "a": "one"}))
    )
    second = load_custody_descriptor(
        _write_descriptor(tmp_path / "nested" / "second.json", _descriptor(occurred_at="2026-07-13T00:00:00Z", attributes={"a": "one", "b": 2}))
    )
    subject = "a" * 64
    chain_a = build_custody_chain([first], subject_algorithm="sha256", subject_digest=subject)
    chain_b = build_custody_chain([second], subject_algorithm="sha256", subject_digest=subject)
    assert chain_a["events"][0]["event_id"] == chain_b["events"][0]["event_id"]
    assert str(chain_a["events"][0]["event_id"]).startswith("cue_")
    assert len(str(chain_a["events"][0]["event_id"])) == 36

    changed_actor = load_custody_descriptor(_write_descriptor(tmp_path / "actor.json", _descriptor(actor={"namespace": "local", "identifier": "operator-2"})))
    changed_type = load_custody_descriptor(_write_descriptor(tmp_path / "type.json", _descriptor(event_type="stored")))
    changed_time = load_custody_descriptor(_write_descriptor(tmp_path / "time.json", _descriptor(occurred_at="2026-07-13T01:00:00Z")))
    changed_location = load_custody_descriptor(_write_descriptor(tmp_path / "loc.json", _descriptor(location="vault")))
    changed_reference = load_custody_descriptor(_write_descriptor(tmp_path / "ref.json", _descriptor(reference="ref-2")))
    changed_attributes = load_custody_descriptor(_write_descriptor(tmp_path / "attr.json", _descriptor(attributes={"a": "two"})))
    ids = {
        build_custody_chain([item], subject_algorithm="sha256", subject_digest=subject)["events"][0]["event_id"]
        for item in [first, changed_actor, changed_type, changed_time, changed_location, changed_reference, changed_attributes]
    }
    ids.add(build_custody_chain([first], subject_algorithm="sha256", subject_digest="b" * 64)["events"][0]["event_id"])
    assert len(ids) == 8


def test_prove_custody_manifest_and_identity_rules(tmp_path: Path) -> None:
    created = _write_descriptor(tmp_path / "created.json", _descriptor(event_type="created", occurred_at="2026-07-13T00:00:00Z"))
    received = _write_descriptor(tmp_path / "received.json", _descriptor(event_type="received", occurred_at="2026-07-13T01:00:00Z"))
    sample = tmp_path / "source.txt"
    sample.write_text("custody identity\n", encoding="utf-8")
    sealed_at = "2026-07-13T02:00:00Z"

    first = tmp_path / "first"
    second = tmp_path / "second"
    changed = tmp_path / "changed"
    default = tmp_path / "default"
    create_proof_packet(sample, first, sealed_at_utc=sealed_at, concept_ids=["custody"], custody_descriptor_paths=[created, received])
    create_proof_packet(sample, second, sealed_at_utc=sealed_at, concept_ids=["custody"], custody_descriptor_paths=[received, created])
    changed_descriptor = _write_descriptor(tmp_path / "changed_event.json", _descriptor(event_type="stored", occurred_at="2026-07-13T00:00:00Z"))
    create_proof_packet(sample, changed, sealed_at_utc=sealed_at, concept_ids=["custody"], custody_descriptor_paths=[changed_descriptor])
    create_proof_packet(sample, default, sealed_at_utc=sealed_at)

    first_manifest = load_manifest(first / "manifest.json")
    second_manifest = load_manifest(second / "manifest.json")
    changed_manifest = load_manifest(changed / "manifest.json")
    default_manifest = load_manifest(default / "manifest.json")
    assert first_manifest["identifiers"] == second_manifest["identifiers"]
    assert first_manifest["identifiers"]["proof_id"] != changed_manifest["identifiers"]["proof_id"]
    assert "custody" not in default_manifest
    assert default_manifest["proof_concepts"]["requested"] == ["existence", "integrity"]
    custody = first_manifest["custody"]
    assert custody["schema_version"] == CUSTODY_COLLECTION_SCHEMA_VERSION
    assert custody["event_count"] == 2
    assert [event["sequence"] for event in custody["events"]] == [1, 2]
    assert custody["events"][0]["previous_event_hash"] == "GENESIS"
    assert custody["events"][1]["previous_event_hash"] == custody["events"][0]["event_hash"]
    assert custody["chain_head"] == custody["events"][-1]["event_hash"]
    assert all("created.json" not in canonical_json_text(event) for event in custody["events"])
    claim = first_manifest["proof_concepts"]["claims"][0]
    assert claim["concept_id"] == "custody"
    assert claim["parameters"]["event_ids"] == [event["event_id"] for event in custody["events"]]
    assert claim["parameters"]["chain_head"] == custody["chain_head"]


def test_prove_custody_argument_rules(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("custody args\n", encoding="utf-8")
    descriptor = _write_descriptor(tmp_path / "custody.json")
    missing = run_cli("prove", str(sample), "--output", str(tmp_path / "missing"), "--concept", "custody")
    assert missing.returncode == 2
    without_concept = run_cli("prove", str(sample), "--output", str(tmp_path / "without"), "--custody-json", str(descriptor))
    assert without_concept.returncode == 2
    duplicate = run_cli(
        "prove", str(sample), "--output", str(tmp_path / "dup"), "--concept", "custody", "--custody-json", str(descriptor), "--custody-json", str(descriptor)
    )
    assert duplicate.returncode == 2
    null_a = _write_descriptor(tmp_path / "null_a.json", _descriptor(event_type="created"))
    null_b = _write_descriptor(tmp_path / "null_b.json", _descriptor(event_type="received"))
    ambiguous = run_cli(
        "prove", str(sample), "--output", str(tmp_path / "ambiguous"), "--concept", "custody", "--custody-json", str(null_a), "--custody-json", str(null_b)
    )
    assert ambiguous.returncode == 2


def _tampered_custody_audit(tmp_path: Path, edit: object) -> dict[str, object]:
    descriptor = _write_descriptor(tmp_path / "custody.json", _descriptor())
    _sample, packet = _proof_with_custody(tmp_path, descriptor)
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    if callable(edit):
        edit(manifest)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    result = run_cli("audit", str(packet), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    custody_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "custody")
    assert custody_result["status"] == "FAIL"
    assert data["proof_concept_summary"]["overall_status"] == "FAIL"
    return custody_result


@pytest.mark.parametrize(
    ("name", "edit", "failure"),
    [
        ("missing_section", lambda manifest: manifest.pop("custody"), "custody_section_missing"),
        ("empty", lambda manifest: manifest["custody"].update({"events": [], "event_count": 0}), "custody_empty"),
        ("count", lambda manifest: manifest["custody"].update({"event_count": 99}), "custody_event_count_mismatch"),
        ("extra_collection_field", lambda manifest: manifest["custody"].update({"verified": True}), "custody_events_invalid"),
        ("schema", lambda manifest: manifest["custody"].update({"schema_version": "tohupono.custody.v99"}), "custody_schema_unsupported"),
        ("event_hash", lambda manifest: manifest["custody"]["events"][0].update({"event_hash": "0" * 64}), "custody_event_hash_mismatch"),
        ("event_id", lambda manifest: manifest["custody"]["events"][0].update({"event_id": "cue_" + "0" * 32}), "custody_event_id_mismatch"),
        ("subject", lambda manifest: manifest["custody"]["events"][0]["subject"].update({"digest": "0" * 64}), "custody_subject_digest_mismatch"),
        ("chain_head", lambda manifest: manifest["custody"].update({"chain_head": "0" * 64}), "custody_chain_head_mismatch"),
    ],
)
def test_tampered_custody_fail_audit(tmp_path: Path, name: str, edit: object, failure: str) -> None:
    result = _tampered_custody_audit(tmp_path / name, edit)
    assert failure in result["failures"]


def test_claim_and_chain_mismatch_failures(tmp_path: Path) -> None:
    def missing_claimed(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        claim = declaration["claims"][0]
        params = claim["parameters"]
        params["event_ids"] = ["cue_" + "0" * 32]
        claim["claim_id"] = make_claim_id("custody", claim["subject"], params)

    assert "custody_claim_event_missing" in _tampered_custody_audit(tmp_path / "missing_claim", missing_claimed)["failures"]

    def duplicate_claim(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        claim = declaration["claims"][0]
        params = claim["parameters"]
        event_ids = params["event_ids"]
        params["event_ids"] = [event_ids[0], event_ids[0]]
        claim["claim_id"] = make_claim_id("custody", claim["subject"], params)

    assert "custody_claim_event_duplicate" in _tampered_custody_audit(tmp_path / "duplicate_claim", duplicate_claim)["failures"]

    def claim_head(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        claim = declaration["claims"][0]
        params = claim["parameters"]
        params["chain_head"] = "0" * 64
        claim["claim_id"] = make_claim_id("custody", claim["subject"], params)

    assert "custody_claim_head_mismatch" in _tampered_custody_audit(tmp_path / "claim_head", claim_head)["failures"]

    def malformed_claim_head(manifest: dict[str, object]) -> None:
        declaration = manifest["proof_concepts"]
        claim = declaration["claims"][0]
        params = claim["parameters"]
        params["chain_head"] = None
        claim["claim_id"] = make_claim_id("custody", claim["subject"], params)

    assert "custody_claim_head_mismatch" in _tampered_custody_audit(tmp_path / "bad_claim_head", malformed_claim_head)["failures"]


def test_custody_cli_human_privacy_and_report(tmp_path: Path) -> None:
    descriptor = _write_descriptor(tmp_path / "custody.json", _descriptor(attributes={"private_note": "do-not-render"}, reference="custody-ref"))
    validate = run_cli("custody", "validate", str(descriptor), "--json")
    assert validate.returncode == 0
    assert json.loads(validate.stdout)["status"] == "ok"
    human_validate = run_cli("custody", "validate", str(descriptor))
    assert "do-not-render" not in human_validate.stdout
    assert "does not prove that a custody event occurred" in human_validate.stdout

    _sample, packet = _proof_with_custody(tmp_path, descriptor)
    inspect_json = run_cli("custody", "inspect", str(packet), "--json")
    assert inspect_json.returncode == 0
    assert json.loads(inspect_json.stdout)["event_count"] == 1
    inspect_human = run_cli("custody", "inspect", str(packet))
    assert "do-not-render" not in inspect_human.stdout
    assert "Event ID:" in inspect_human.stdout

    report = tmp_path / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(packet / "manifest.json", report, key)
    text = report.read_bytes().decode("latin-1", errors="ignore")
    assert "Proof of Custody Details" in text
    assert "do-not-render" not in text
    assert "does not independently prove physical possession" in text
    assert report.with_suffix(".pdf.sig").exists()


def test_records_and_custody_are_separate_concepts(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("combined concepts\n", encoding="utf-8")
    record = tmp_path / "record.json"
    record.write_text(
        '{"schema_version":"tohupono.record_descriptor.v1","record_type":"generic","namespace":"local","reference":null,"attributes":{}}\n',
        encoding="utf-8",
    )
    custody = _write_descriptor(tmp_path / "custody.json")
    packet = tmp_path / "packet"
    result = run_cli(
        "prove",
        str(sample),
        "--output",
        str(packet),
        "--concept",
        "records",
        "--concept",
        "custody",
        "--record-json",
        str(record),
        "--custody-json",
        str(custody),
    )
    assert result.returncode == 0, result.stderr
    audit = run_cli("audit", str(packet), "--json")
    data = json.loads(audit.stdout)
    statuses = {item["concept_id"]: item["status"] for item in data["proof_concept_results"]}
    assert statuses["records"] == "PASS"
    assert statuses["custody"] == "PASS"
