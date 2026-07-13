from __future__ import annotations

import json
from pathlib import Path

import pytest

from tohupono.concepts.execution import make_claim_id
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.proof import create_proof_packet, load_manifest
from tohupono.reporting.pro_report import generate_report
from tohupono.security.limits import MAX_RECORD_ATTRIBUTE_DEPTH, MAX_RECORD_ATTRIBUTE_ITEMS, MAX_TRANSACTION_DESCRIPTOR_BYTES
from tohupono.transaction.validation import (
    TRANSACTION_COLLECTION_SCHEMA_VERSION,
    TRANSACTION_DESCRIPTOR_SCHEMA_VERSION,
    TransactionValidationError,
    build_transaction_envelope,
    load_transaction_descriptor,
    transaction_id_for_body,
)

from tests.support import run_cli

SUBJECT = "c" * 64


def _participants() -> list[dict[str, str]]:
    return [
        {"role": "sender", "namespace": "local", "identifier": "party-a"},
        {"role": "receiver", "namespace": "local", "identifier": "party-b"},
    ]


def _descriptor(
    *,
    transaction_type: str = "transfer",
    participants: list[dict[str, str]] | None = None,
    occurred_at: str | None = None,
    reference: str | None = None,
    terms: dict[str, object] | None = None,
    attributes: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "attributes": attributes or {},
        "occurred_at": occurred_at,
        "participants": participants if participants is not None else _participants(),
        "reference": reference,
        "schema_version": TRANSACTION_DESCRIPTOR_SCHEMA_VERSION,
        "terms": terms or {},
        "transaction_type": transaction_type,
    }


def _write_descriptor(path: Path, value: dict[str, object] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json_text(value or _descriptor()) + "\n", encoding="utf-8")
    return path


def _proof_with_transaction(tmp_path: Path, *descriptors: Path) -> tuple[Path, Path]:
    sample = tmp_path / "source.txt"
    sample.write_text("transaction subject\n", encoding="utf-8")
    packet = tmp_path / "packet"
    args = ["prove", str(sample), "--output", str(packet), "--concept", "transaction"]
    for descriptor in descriptors:
        args.extend(["--transaction-json", str(descriptor)])
    result = run_cli(*args)
    assert result.returncode == 0, result.stderr
    return sample, packet


@pytest.mark.parametrize("transaction_type", ["transfer", "sale", "gift", "license", "assignment", "exchange", "receipt"])
def test_valid_descriptor_transaction_types(tmp_path: Path, transaction_type: str) -> None:
    participants = [{"role": "customer", "namespace": "local", "identifier": "party-a"}] if transaction_type == "receipt" else None
    descriptor = load_transaction_descriptor(_write_descriptor(tmp_path / f"{transaction_type}.json", _descriptor(transaction_type=transaction_type, participants=participants)))
    assert descriptor.transaction_type == transaction_type


@pytest.mark.parametrize(
    ("name", "content", "code"),
    [
        ("duplicate.json", '{"schema_version":"tohupono.transaction_descriptor.v1","schema_version":"x","transaction_type":"transfer","participants":[{"role":"sender","namespace":"local","identifier":"party-a"},{"role":"receiver","namespace":"local","identifier":"party-b"}],"terms":{},"attributes":{}}\n', "transaction_json_duplicate_key"),
        ("float.json", '{"schema_version":"tohupono.transaction_descriptor.v1","transaction_type":"transfer","participants":[{"role":"sender","namespace":"local","identifier":"party-a"},{"role":"receiver","namespace":"local","identifier":"party-b"}],"terms":{"x":1.5},"attributes":{}}\n', "transaction_float_invalid"),
        ("nan.json", '{"schema_version":"tohupono.transaction_descriptor.v1","transaction_type":"transfer","participants":[{"role":"sender","namespace":"local","identifier":"party-a"},{"role":"receiver","namespace":"local","identifier":"party-b"}],"terms":{"x":NaN},"attributes":{}}\n', "transaction_non_finite_invalid"),
        ("control.json", '{"schema_version":"tohupono.transaction_descriptor.v1","transaction_type":"transfer","participants":[{"role":"sender","namespace":"local","identifier":"party-a"},{"role":"receiver","namespace":"local","identifier":"party-b"}],"terms":{"x":"bad\\u0001"},"attributes":{}}\n', "transaction_terms_invalid"),
        ("bidi.json", '{"schema_version":"tohupono.transaction_descriptor.v1","transaction_type":"transfer","participants":[{"role":"sender","namespace":"local","identifier":"party-a"},{"role":"receiver","namespace":"local","identifier":"party-b"}],"terms":{},"attributes":{"x":"bad\\u202e"}}\n', "transaction_attributes_invalid"),
    ],
)
def test_descriptor_strict_json_rejections(tmp_path: Path, name: str, content: str, code: str) -> None:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    with pytest.raises(TransactionValidationError) as exc:
        load_transaction_descriptor(path)
    assert exc.value.code == code


def test_descriptor_validation_and_file_safety_rejections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(TransactionValidationError) as unsupported:
        load_transaction_descriptor(_write_descriptor(tmp_path / "bad_type.json", _descriptor(transaction_type="payment")))
    assert unsupported.value.code == "transaction_type_unsupported"

    with pytest.raises(TransactionValidationError) as schema:
        load_transaction_descriptor(_write_descriptor(tmp_path / "bad_schema.json", {**_descriptor(), "schema_version": "x"}))
    assert schema.value.code == "transaction_descriptor_schema_unsupported"

    with pytest.raises(TransactionValidationError) as missing:
        load_transaction_descriptor(_write_descriptor(tmp_path / "missing_participants.json", {key: value for key, value in _descriptor().items() if key != "participants"}))
    assert missing.value.code == "transaction_descriptor_invalid"

    with pytest.raises(TransactionValidationError) as empty:
        load_transaction_descriptor(_write_descriptor(tmp_path / "empty_participants.json", _descriptor(participants=[])))
    assert empty.value.code == "transaction_participants_invalid"

    with pytest.raises(TransactionValidationError) as malformed:
        load_transaction_descriptor(_write_descriptor(tmp_path / "malformed_participant.json", _descriptor(participants=[{"role": "sender"}])))  # type: ignore[list-item]
    assert malformed.value.code == "transaction_participants_invalid"

    with pytest.raises(TransactionValidationError) as role:
        load_transaction_descriptor(_write_descriptor(tmp_path / "role.json", _descriptor(participants=[{"role": "owner", "namespace": "local", "identifier": "party-a"}])))
    assert role.value.code == "transaction_participants_invalid"

    duplicate_participants = [_participants()[0], _participants()[0]]
    with pytest.raises(TransactionValidationError) as duplicate:
        load_transaction_descriptor(_write_descriptor(tmp_path / "duplicate_participant.json", _descriptor(participants=duplicate_participants)))
    assert duplicate.value.code == "transaction_participant_duplicate"

    with pytest.raises(TransactionValidationError) as insufficient:
        load_transaction_descriptor(_write_descriptor(tmp_path / "insufficient.json", _descriptor(participants=[_participants()[0]])))
    assert insufficient.value.code == "transaction_participants_invalid"

    for bad_time in ["2026-07-13T01:02:03+12:00", "2026-07-13T01:02:03.000Z", "2026-07-13 01:02:03"]:
        with pytest.raises(TransactionValidationError) as time_error:
            load_transaction_descriptor(_write_descriptor(tmp_path / f"{bad_time.replace(':', '_')}.json", _descriptor(occurred_at=bad_time)))
        assert time_error.value.code == "transaction_occurred_at_invalid"

    with pytest.raises(TransactionValidationError) as reference:
        load_transaction_descriptor(_write_descriptor(tmp_path / "reference.json", _descriptor(reference="bad\x01ref")))
    assert reference.value.code == "transaction_reference_invalid"

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(TransactionValidationError) as directory_error:
        load_transaction_descriptor(directory)
    assert directory_error.value.code == "transaction_descriptor_not_file"

    target = _write_descriptor(tmp_path / "target.json")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(TransactionValidationError):
        load_transaction_descriptor(link)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + (b" " * MAX_TRANSACTION_DESCRIPTOR_BYTES) + b"}")
    with pytest.raises(TransactionValidationError) as oversized_error:
        load_transaction_descriptor(oversized)
    assert oversized_error.value.code == "transaction_descriptor_too_large"

    value: object = "leaf"
    for _ in range(MAX_RECORD_ATTRIBUTE_DEPTH + 2):
        value = {"nested": value}
    with pytest.raises(TransactionValidationError):
        load_transaction_descriptor(_write_descriptor(tmp_path / "deep.json", _descriptor(terms={"deep": value})))

    too_many = _write_descriptor(tmp_path / "too_many.json", _descriptor(attributes={f"k{i}": i for i in range(MAX_RECORD_ATTRIBUTE_ITEMS + 1)}))
    with pytest.raises(TransactionValidationError):
        load_transaction_descriptor(too_many)

    changed = _write_descriptor(tmp_path / "changed.json")
    original_read_bytes = Path.read_bytes

    def mutate_during_read(path: Path) -> bytes:
        data = original_read_bytes(path)
        if path == changed:
            path.write_text(canonical_json_text(_descriptor(attributes={"changed": True})) + "\n", encoding="utf-8")
        return data

    monkeypatch.setattr(Path, "read_bytes", mutate_during_read)
    with pytest.raises(TransactionValidationError) as changed_error:
        load_transaction_descriptor(changed)
    assert changed_error.value.code == "transaction_descriptor_changed"


def test_transaction_id_is_deterministic_and_metadata_sensitive(tmp_path: Path) -> None:
    first = load_transaction_descriptor(_write_descriptor(tmp_path / "first.json", _descriptor(participants=list(reversed(_participants())), terms={"b": 2, "a": "one"})))
    second = load_transaction_descriptor(_write_descriptor(tmp_path / "nested" / "second.json", _descriptor(participants=_participants(), terms={"a": "one", "b": 2})))
    txn_a = build_transaction_envelope(first, subject_algorithm="sha256", subject_digest=SUBJECT)
    txn_b = build_transaction_envelope(second, subject_algorithm="sha256", subject_digest=SUBJECT)
    assert txn_a.transaction_id == txn_b.transaction_id
    assert txn_a.transaction_id.startswith("txn_")
    assert len(txn_a.transaction_id) == 36
    assert txn_a.transaction_id == transaction_id_for_body({k: v for k, v in txn_a.to_dict().items() if k != "transaction_id"})

    variants = [
        _descriptor(transaction_type="sale"),
        _descriptor(participants=[_participants()[0], {"role": "witness", "namespace": "local", "identifier": "party-c"}]),
        _descriptor(occurred_at="2026-07-13T00:00:00Z"),
        _descriptor(reference="ref-1"),
        _descriptor(terms={"price": 1}),
        _descriptor(attributes={"a": "two"}),
    ]
    ids = {txn_a.transaction_id}
    for index, value in enumerate(variants):
        descriptor = load_transaction_descriptor(_write_descriptor(tmp_path / f"variant_{index}.json", value))
        ids.add(build_transaction_envelope(descriptor, subject_algorithm="sha256", subject_digest=SUBJECT).transaction_id)
    ids.add(build_transaction_envelope(first, subject_algorithm="sha256", subject_digest="d" * 64).transaction_id)
    assert len(ids) == 8


def test_prove_transaction_manifest_and_identity_rules(tmp_path: Path) -> None:
    descriptor_a = _write_descriptor(tmp_path / "a.json", _descriptor(reference="a"))
    descriptor_b = _write_descriptor(tmp_path / "b.json", _descriptor(reference="b", participants=[{"role": "buyer", "namespace": "local", "identifier": "party-c"}, {"role": "seller", "namespace": "local", "identifier": "party-d"}], transaction_type="sale"))
    sample = tmp_path / "source.txt"
    sample.write_text("transaction identity\n", encoding="utf-8")
    sealed_at = "2026-07-13T00:00:00Z"

    first = tmp_path / "first"
    second = tmp_path / "second"
    changed = tmp_path / "changed"
    default = tmp_path / "default"
    create_proof_packet(sample, first, sealed_at_utc=sealed_at, concept_ids=["transaction"], transaction_descriptor_paths=[descriptor_a, descriptor_b])
    create_proof_packet(sample, second, sealed_at_utc=sealed_at, concept_ids=["transaction"], transaction_descriptor_paths=[descriptor_b, descriptor_a])
    changed_descriptor = _write_descriptor(tmp_path / "changed.json", _descriptor(reference="changed"))
    create_proof_packet(sample, changed, sealed_at_utc=sealed_at, concept_ids=["transaction"], transaction_descriptor_paths=[changed_descriptor])
    create_proof_packet(sample, default, sealed_at_utc=sealed_at)

    first_manifest = load_manifest(first / "manifest.json")
    second_manifest = load_manifest(second / "manifest.json")
    changed_manifest = load_manifest(changed / "manifest.json")
    default_manifest = load_manifest(default / "manifest.json")
    assert first_manifest["identifiers"] == second_manifest["identifiers"]
    assert first_manifest["identifiers"]["proof_id"] != changed_manifest["identifiers"]["proof_id"]
    assert "transactions" not in default_manifest
    assert default_manifest["proof_concepts"]["requested"] == ["existence", "integrity"]
    transactions = first_manifest["transactions"]
    assert transactions["schema_version"] == TRANSACTION_COLLECTION_SCHEMA_VERSION
    assert transactions["transaction_count"] == 2
    assert [item["transaction_id"] for item in transactions["items"]] == sorted(item["transaction_id"] for item in transactions["items"])
    assert all("a.json" not in canonical_json_text(item) for item in transactions["items"])
    claim = first_manifest["proof_concepts"]["claims"][0]
    assert claim["concept_id"] == "transaction"
    assert claim["parameters"]["transaction_ids"] == [item["transaction_id"] for item in transactions["items"]]
    assert claim["parameters"]["subject"] == {"algorithm": "sha256", "digest": first_manifest["file"]["sha256"]}


def test_prove_transaction_argument_rules(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("transaction args\n", encoding="utf-8")
    descriptor = _write_descriptor(tmp_path / "transaction.json")
    missing = run_cli("prove", str(sample), "--output", str(tmp_path / "missing"), "--concept", "transaction")
    assert missing.returncode == 2
    without_concept = run_cli("prove", str(sample), "--output", str(tmp_path / "without"), "--transaction-json", str(descriptor))
    assert without_concept.returncode == 2
    duplicate = run_cli(
        "prove", str(sample), "--output", str(tmp_path / "dup"), "--concept", "transaction", "--transaction-json", str(descriptor), "--transaction-json", str(descriptor)
    )
    assert duplicate.returncode == 2


def _tampered_transaction_audit(tmp_path: Path, edit: object) -> dict[str, object]:
    descriptor = _write_descriptor(tmp_path / "transaction.json")
    _sample, packet = _proof_with_transaction(tmp_path, descriptor)
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    if callable(edit):
        edit(manifest)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    result = run_cli("audit", str(packet), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    transaction_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "transaction")
    assert transaction_result["status"] == "FAIL"
    assert data["proof_concept_summary"]["overall_status"] == "FAIL"
    return transaction_result


@pytest.mark.parametrize(
    ("name", "edit", "failure"),
    [
        ("missing_section", lambda manifest: manifest.pop("transactions"), "transaction_section_missing"),
        ("empty", lambda manifest: manifest["transactions"].update({"items": [], "transaction_count": 0}), "transaction_empty"),
        ("count", lambda manifest: manifest["transactions"].update({"transaction_count": 99}), "transaction_count_mismatch"),
        ("schema", lambda manifest: manifest["transactions"].update({"schema_version": "tohupono.transactions.v99"}), "transaction_schema_unsupported"),
        ("id", lambda manifest: manifest["transactions"]["items"][0].update({"transaction_id": "txn_" + "0" * 32}), "transaction_id_mismatch"),
        ("subject", lambda manifest: manifest["transactions"]["items"][0]["subject"].update({"digest": "0" * 64}), "transaction_subject_digest_mismatch"),
        ("type", lambda manifest: manifest["transactions"]["items"][0].update({"transaction_type": "payment"}), "transaction_type_unsupported"),
        ("duplicate", lambda manifest: manifest["transactions"]["items"].append(dict(manifest["transactions"]["items"][0])), "transaction_count_mismatch"),
    ],
)
def test_tampered_transaction_fails_audit(tmp_path: Path, name: str, edit: object, failure: str) -> None:
    result = _tampered_transaction_audit(tmp_path / name, edit)
    assert failure in result["failures"]


def test_claim_and_transaction_mismatch_failures(tmp_path: Path) -> None:
    def extra_unclaimed(manifest: dict[str, object]) -> None:
        transactions = manifest["transactions"]
        items = transactions["items"]
        extra = dict(items[0])
        body = {key: value for key, value in extra.items() if key != "transaction_id"}
        body["reference"] = "extra"
        extra.update(body)
        extra["transaction_id"] = transaction_id_for_body(body)
        items.append(extra)
        transactions["transaction_count"] = len(items)
        items.sort(key=lambda item: item["transaction_id"])

    assert "transaction_claim_id_undeclared" in _tampered_transaction_audit(tmp_path / "extra", extra_unclaimed)["failures"]

    def missing_claimed(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        params["transaction_ids"] = ["txn_" + "0" * 32]
        claim["claim_id"] = make_claim_id("transaction", claim["subject"], params)

    assert "transaction_claim_id_missing" in _tampered_transaction_audit(tmp_path / "missing", missing_claimed)["failures"]

    def duplicate_claim(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        txn_ids = params["transaction_ids"]
        params["transaction_ids"] = [txn_ids[0], txn_ids[0]]
        claim["claim_id"] = make_claim_id("transaction", claim["subject"], params)

    assert "transaction_claim_id_duplicate" in _tampered_transaction_audit(tmp_path / "duplicate", duplicate_claim)["failures"]

    def subject_mismatch(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        params["subject"] = {"algorithm": "sha256", "digest": "0" * 64}
        claim["claim_id"] = make_claim_id("transaction", claim["subject"], params)

    assert "transaction_claim_subject_mismatch" in _tampered_transaction_audit(tmp_path / "subject", subject_mismatch)["failures"]


def test_transaction_cli_privacy_audit_and_report(tmp_path: Path) -> None:
    descriptor = _write_descriptor(tmp_path / "transaction.json", _descriptor(terms={"secret_term": "do-not-render"}, attributes={"private_note": "do-not-render"}, reference="txn-ref"))
    validate = run_cli("transaction", "validate", str(descriptor), "--json")
    assert validate.returncode == 0
    assert json.loads(validate.stdout)["status"] == "ok"
    human_validate = run_cli("transaction", "validate", str(descriptor))
    assert "do-not-render" not in human_validate.stdout
    assert "does not prove" in human_validate.stdout

    _sample, packet = _proof_with_transaction(tmp_path, descriptor)
    inspect_json = run_cli("transaction", "inspect", str(packet), "--json")
    assert inspect_json.returncode == 0
    assert json.loads(inspect_json.stdout)["transaction_count"] == 1
    inspect_human = run_cli("transaction", "inspect", str(packet))
    assert "do-not-render" not in inspect_human.stdout
    assert "Transaction ID:" in inspect_human.stdout

    audit = run_cli("audit", str(packet), "--json")
    assert audit.returncode == 0
    data = json.loads(audit.stdout)
    transaction_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "transaction")
    assert transaction_result["status"] == "PASS"
    assert "payment" in " ".join(transaction_result["limitations"]).lower()

    report = tmp_path / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(packet / "manifest.json", report, key)
    text = report.read_bytes().decode("latin-1", errors="ignore")
    assert "Proof of Transaction Details" in text
    assert "do-not-render" not in text
    assert "does not independently prove" in text
    assert report.with_suffix(".pdf.sig").exists()


def test_records_custody_provenance_and_transaction_are_separate(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("combined transaction concepts\n", encoding="utf-8")
    record = tmp_path / "record.json"
    record.write_text('{"schema_version":"tohupono.record_descriptor.v1","record_type":"generic","namespace":"local","reference":null,"attributes":{}}\n', encoding="utf-8")
    custody = tmp_path / "custody.json"
    custody.write_text('{"schema_version":"tohupono.custody_descriptor.v1","event_type":"received","actor":{"namespace":"local","identifier":"operator-1"},"occurred_at":null,"location":null,"reference":null,"attributes":{}}\n', encoding="utf-8")
    provenance = tmp_path / "provenance.json"
    provenance.write_text('{"schema_version":"tohupono.provenance_descriptor.v1","relation_type":"derived_from","parent":{"algorithm":"sha256","digest":"' + ("a" * 64) + '"},"operation":null,"occurred_at":null,"actor":null,"reference":null,"attributes":{}}\n', encoding="utf-8")
    transaction = _write_descriptor(tmp_path / "transaction.json")
    packet = tmp_path / "packet"
    result = run_cli(
        "prove", str(sample), "--output", str(packet),
        "--concept", "records", "--concept", "custody", "--concept", "provenance", "--concept", "transaction",
        "--record-json", str(record), "--custody-json", str(custody), "--provenance-json", str(provenance), "--transaction-json", str(transaction),
    )
    assert result.returncode == 0, result.stderr
    audit = run_cli("audit", str(packet), "--json")
    data = json.loads(audit.stdout)
    statuses = {item["concept_id"]: item["status"] for item in data["proof_concept_results"]}
    assert statuses["records"] == "PASS"
    assert statuses["custody"] == "PASS"
    assert statuses["provenance"] == "PASS"
    assert statuses["transaction"] == "PASS"

    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest["transactions"]["items"][0]["transaction_id"] = "txn_" + "0" * 32
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    tampered = run_cli("audit", str(packet), "--json")
    tampered_data = json.loads(tampered.stdout)
    tampered_statuses = {item["concept_id"]: item["status"] for item in tampered_data["proof_concept_results"]}
    assert tampered_statuses["transaction"] == "FAIL"
    assert tampered_statuses["records"] == "PASS"
    assert tampered_statuses["custody"] == "PASS"
    assert tampered_statuses["provenance"] == "PASS"


def test_legacy_packet_without_transaction_remains_valid(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("legacy transaction\n", encoding="utf-8")
    packet = tmp_path / "packet"
    create_proof_packet(sample, packet, sealed_at_utc="2026-07-13T00:00:00Z")
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest.pop("proof_concepts", None)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    audit = run_cli("audit", str(packet), "--json")
    data = json.loads(audit.stdout)
    assert "transaction" not in data["declared_proof_concepts"]
    assert data["proof_concept_summary"]["overall_status"] == "UNPROVEN"
