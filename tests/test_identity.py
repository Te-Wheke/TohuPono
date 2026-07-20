from __future__ import annotations

import json
from pathlib import Path

import pytest

from tohupono.concepts.execution import make_claim_id
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.proof import create_proof_packet, load_manifest
from tohupono.identity.validation import (
    IDENTITY_COLLECTION_SCHEMA_VERSION,
    IDENTITY_DESCRIPTOR_SCHEMA_VERSION,
    IdentityValidationError,
    build_identity_assertion,
    identity_assertion_id_for_body,
    load_identity_descriptor,
)
from tohupono.reporting.pro_report import generate_report
from tohupono.security.limits import MAX_IDENTITY_DESCRIPTOR_BYTES, MAX_RECORD_ATTRIBUTE_DEPTH, MAX_RECORD_ATTRIBUTE_ITEMS
from tohupono.trust.keys import DEFAULT_MANIFEST_KEY, DEFAULT_MANIFEST_PUBLIC_KEY

from tests.support import run_cli

SUBJECT = "d" * 64


def _descriptor(
    *,
    assertion_type: str = "associated_with",
    namespace: str = "local",
    identifier: str = "party-a",
    display_name: str | None = None,
    key_fingerprint: dict[str, str] | None = None,
    reference: str | None = None,
    attributes: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "assertion_type": assertion_type,
        "attributes": attributes or {},
        "identity": {"display_name": display_name, "identifier": identifier, "namespace": namespace},
        "key_fingerprint": key_fingerprint,
        "reference": reference,
        "schema_version": IDENTITY_DESCRIPTOR_SCHEMA_VERSION,
    }


def _write_descriptor(path: Path, value: dict[str, object] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json_text(value or _descriptor()) + "\n", encoding="utf-8")
    return path


def _proof_with_identity(tmp_path: Path, *descriptors: Path) -> tuple[Path, Path]:
    sample = tmp_path / "source.txt"
    sample.write_text("identity subject\n", encoding="utf-8")
    packet = tmp_path / "packet"
    args = ["prove", str(sample), "--output", str(packet), "--concept", "identity"]
    for descriptor in descriptors:
        args.extend(["--identity-json", str(descriptor)])
    result = run_cli(*args)
    assert result.returncode == 0, result.stderr
    return sample, packet


def test_valid_identity_descriptor_and_fingerprint(tmp_path: Path) -> None:
    descriptor = load_identity_descriptor(
        _write_descriptor(
            tmp_path / "identity.json",
            _descriptor(
                namespace="local.id",
                identifier="party-a",
                display_name="Party A",
                key_fingerprint={"algorithm": "sha256", "digest": "a" * 64},
            ),
        )
    )
    assert descriptor.assertion_type == "associated_with"
    assert descriptor.identity["namespace"] == "local.id"
    assert descriptor.key_fingerprint == {"algorithm": "sha256", "digest": "a" * 64}


def test_display_name_canonicalization_and_validation(tmp_path: Path) -> None:
    omitted_value = _descriptor()
    omitted_value["identity"] = {"namespace": "local", "identifier": "party-a"}
    explicit_null = _descriptor(display_name=None)

    omitted = load_identity_descriptor(_write_descriptor(tmp_path / "omitted.json", omitted_value))
    explicit = load_identity_descriptor(_write_descriptor(tmp_path / "explicit.json", explicit_null))
    omitted_assertion = build_identity_assertion(omitted, subject_algorithm="sha256", subject_digest=SUBJECT)
    explicit_assertion = build_identity_assertion(explicit, subject_algorithm="sha256", subject_digest=SUBJECT)

    assert omitted_assertion.identity == {"display_name": None, "identifier": "party-a", "namespace": "local"}
    assert omitted_assertion.assertion_id == explicit_assertion.assertion_id

    load_identity_descriptor(_write_descriptor(tmp_path / "string.json", _descriptor(display_name="Party A")))
    with pytest.raises(IdentityValidationError) as type_error:
        load_identity_descriptor(_write_descriptor(tmp_path / "type.json", {**_descriptor(), "identity": {"namespace": "local", "identifier": "party-a", "display_name": 7}}))
    assert type_error.value.code == "identity_display_name_invalid"
    with pytest.raises(IdentityValidationError) as oversized_error:
        load_identity_descriptor(_write_descriptor(tmp_path / "oversized_display.json", _descriptor(display_name="x" * 201)))
    assert oversized_error.value.code == "identity_display_name_invalid"


@pytest.mark.parametrize(
    ("name", "content", "code"),
    [
        ("duplicate.json", '{"schema_version":"tohupono.identity_descriptor.v1","schema_version":"x","assertion_type":"associated_with","identity":{"namespace":"local","identifier":"party-a"},"attributes":{}}\n', "identity_json_duplicate_key"),
        ("float.json", '{"schema_version":"tohupono.identity_descriptor.v1","assertion_type":"associated_with","identity":{"namespace":"local","identifier":"party-a"},"attributes":{"x":1.5}}\n', "identity_float_invalid"),
        ("nan.json", '{"schema_version":"tohupono.identity_descriptor.v1","assertion_type":"associated_with","identity":{"namespace":"local","identifier":"party-a"},"attributes":{"x":NaN}}\n', "identity_non_finite_invalid"),
        ("control.json", '{"schema_version":"tohupono.identity_descriptor.v1","assertion_type":"associated_with","identity":{"namespace":"local","identifier":"party-a"},"attributes":{"x":"bad\\u0001"}}\n', "identity_attributes_invalid"),
        ("bidi.json", '{"schema_version":"tohupono.identity_descriptor.v1","assertion_type":"associated_with","identity":{"namespace":"local","identifier":"party-a"},"attributes":{"x":"bad\\u202e"}}\n', "identity_attributes_invalid"),
    ],
)
def test_descriptor_strict_json_rejections(tmp_path: Path, name: str, content: str, code: str) -> None:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    with pytest.raises(IdentityValidationError) as exc:
        load_identity_descriptor(path)
    assert exc.value.code == code


def test_descriptor_validation_and_file_safety_rejections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cases = [
        (_descriptor(schema_version="x") if False else {**_descriptor(), "schema_version": "x"}, "identity_descriptor_schema_unsupported"),
        ({**_descriptor(), "assertion_type": "verified_by"}, "identity_assertion_type_unsupported"),
        ({key: value for key, value in _descriptor().items() if key != "identity"}, "identity_descriptor_invalid"),
        ({**_descriptor(), "identity": {"namespace": "Local", "identifier": "party-a"}}, "identity_namespace_invalid"),
        ({**_descriptor(), "identity": {"namespace": "local", "identifier": "bad\tid"}}, "identity_identifier_invalid"),
        (_descriptor(display_name="bad\x01name"), "identity_display_name_invalid"),
        (_descriptor(reference="bad\x01ref"), "identity_reference_invalid"),
        (_descriptor(key_fingerprint={"algorithm": "sha512", "digest": "a" * 64}), "identity_fingerprint_invalid"),
        (_descriptor(key_fingerprint={"algorithm": "sha256", "digest": "A" * 64}), "identity_fingerprint_invalid"),
        (_descriptor(key_fingerprint={"algorithm": "sha256", "digest": "a" * 63}), "identity_fingerprint_invalid"),
        ({**_descriptor(), "verified": True}, "identity_descriptor_invalid"),
    ]
    for index, (value, code) in enumerate(cases):
        with pytest.raises(IdentityValidationError) as exc:
            load_identity_descriptor(_write_descriptor(tmp_path / f"case_{index}.json", value))
        assert exc.value.code == code

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(IdentityValidationError) as directory_error:
        load_identity_descriptor(directory)
    assert directory_error.value.code == "identity_descriptor_not_file"

    target = _write_descriptor(tmp_path / "target.json")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(IdentityValidationError):
        load_identity_descriptor(link)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + (b" " * MAX_IDENTITY_DESCRIPTOR_BYTES) + b"}")
    with pytest.raises(IdentityValidationError) as oversized_error:
        load_identity_descriptor(oversized)
    assert oversized_error.value.code == "identity_descriptor_too_large"

    value: object = "leaf"
    for _ in range(MAX_RECORD_ATTRIBUTE_DEPTH + 2):
        value = {"nested": value}
    with pytest.raises(IdentityValidationError):
        load_identity_descriptor(_write_descriptor(tmp_path / "deep.json", _descriptor(attributes={"deep": value})))

    too_many = _write_descriptor(tmp_path / "too_many.json", _descriptor(attributes={f"k{i}": i for i in range(MAX_RECORD_ATTRIBUTE_ITEMS + 1)}))
    with pytest.raises(IdentityValidationError):
        load_identity_descriptor(too_many)

    changed = _write_descriptor(tmp_path / "changed.json")
    original_read_bytes = Path.read_bytes

    def mutate_during_read(path: Path) -> bytes:
        data = original_read_bytes(path)
        if path == changed:
            path.write_text(canonical_json_text(_descriptor(attributes={"changed": True})) + "\n", encoding="utf-8")
        return data

    monkeypatch.setattr(Path, "read_bytes", mutate_during_read)
    with pytest.raises(IdentityValidationError) as changed_error:
        load_identity_descriptor(changed)
    assert changed_error.value.code == "identity_descriptor_changed"


def test_identity_assertion_id_is_deterministic_and_metadata_sensitive(tmp_path: Path) -> None:
    first = load_identity_descriptor(_write_descriptor(tmp_path / "first.json", _descriptor(attributes={"b": 2, "a": "one"})))
    second = load_identity_descriptor(_write_descriptor(tmp_path / "nested" / "second.json", _descriptor(attributes={"a": "one", "b": 2})))
    assertion_a = build_identity_assertion(first, subject_algorithm="sha256", subject_digest=SUBJECT)
    assertion_b = build_identity_assertion(second, subject_algorithm="sha256", subject_digest=SUBJECT)
    assert assertion_a.assertion_id == assertion_b.assertion_id
    assert assertion_a.assertion_id.startswith("idn_")
    assert len(assertion_a.assertion_id) == 36
    assert assertion_a.assertion_id == identity_assertion_id_for_body({k: v for k, v in assertion_a.to_dict().items() if k != "assertion_id"})

    variants = [
        _descriptor(namespace="other"),
        _descriptor(identifier="party-b"),
        _descriptor(display_name="Party A"),
        _descriptor(key_fingerprint={"algorithm": "sha256", "digest": "a" * 64}),
        _descriptor(reference="ref-1"),
        _descriptor(attributes={"a": "two"}),
    ]
    ids = {assertion_a.assertion_id}
    for index, value in enumerate(variants):
        descriptor = load_identity_descriptor(_write_descriptor(tmp_path / f"variant_{index}.json", value))
        ids.add(build_identity_assertion(descriptor, subject_algorithm="sha256", subject_digest=SUBJECT).assertion_id)
    ids.add(build_identity_assertion(first, subject_algorithm="sha256", subject_digest="e" * 64).assertion_id)
    assert len(ids) == 8


def test_prove_identity_manifest_and_identity_rules(tmp_path: Path) -> None:
    descriptor_a = _write_descriptor(tmp_path / "a.json", _descriptor(identifier="party-a"))
    descriptor_b = _write_descriptor(tmp_path / "b.json", _descriptor(identifier="party-b"))
    sample = tmp_path / "source.txt"
    sample.write_text("identity deterministic\n", encoding="utf-8")
    sealed_at = "2026-07-13T00:00:00Z"
    first = tmp_path / "first"
    second = tmp_path / "second"
    changed = tmp_path / "changed"
    default = tmp_path / "default"
    create_proof_packet(sample, first, sealed_at_utc=sealed_at, concept_ids=["identity"], identity_descriptor_paths=[descriptor_a, descriptor_b])
    create_proof_packet(sample, second, sealed_at_utc=sealed_at, concept_ids=["identity"], identity_descriptor_paths=[descriptor_b, descriptor_a])
    changed_descriptor = _write_descriptor(tmp_path / "changed.json", _descriptor(reference="changed"))
    create_proof_packet(sample, changed, sealed_at_utc=sealed_at, concept_ids=["identity"], identity_descriptor_paths=[changed_descriptor])
    create_proof_packet(sample, default, sealed_at_utc=sealed_at)

    first_manifest = load_manifest(first / "manifest.json")
    second_manifest = load_manifest(second / "manifest.json")
    changed_manifest = load_manifest(changed / "manifest.json")
    default_manifest = load_manifest(default / "manifest.json")
    assert first_manifest["identifiers"] == second_manifest["identifiers"]
    assert first_manifest["identifiers"]["proof_id"] != changed_manifest["identifiers"]["proof_id"]
    assert "identities" not in default_manifest
    assert default_manifest["proof_concepts"]["requested"] == ["existence", "integrity"]
    identities = first_manifest["identities"]
    assert identities["schema_version"] == IDENTITY_COLLECTION_SCHEMA_VERSION
    assert identities["assertion_count"] == 2
    assert [item["assertion_id"] for item in identities["items"]] == sorted(item["assertion_id"] for item in identities["items"])
    assert all("a.json" not in canonical_json_text(item) for item in identities["items"])
    claim = first_manifest["proof_concepts"]["claims"][0]
    assert claim["concept_id"] == "identity"
    assert claim["parameters"]["assertion_ids"] == [item["assertion_id"] for item in identities["items"]]
    assert claim["parameters"]["subject"] == {"algorithm": "sha256", "digest": first_manifest["file"]["sha256"]}


def test_prove_identity_argument_rules(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("identity args\n", encoding="utf-8")
    descriptor = _write_descriptor(tmp_path / "identity.json")
    missing = run_cli("prove", str(sample), "--output", str(tmp_path / "missing"), "--concept", "identity")
    assert missing.returncode == 2
    without_concept = run_cli("prove", str(sample), "--output", str(tmp_path / "without"), "--identity-json", str(descriptor))
    assert without_concept.returncode == 2
    duplicate = run_cli("prove", str(sample), "--output", str(tmp_path / "dup"), "--concept", "identity", "--identity-json", str(descriptor), "--identity-json", str(descriptor))
    assert duplicate.returncode == 2


def test_create_proof_packet_preserves_existing_positional_descriptor_slots(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("positional descriptor compatibility\n", encoding="utf-8")
    provenance = tmp_path / "provenance.json"
    provenance.write_text('{"schema_version":"tohupono.provenance_descriptor.v1","relation_type":"derived_from","parent":{"algorithm":"sha256","digest":"' + ("a" * 64) + '"},"operation":null,"occurred_at":null,"actor":null,"reference":null,"attributes":{}}\n', encoding="utf-8")
    transaction = tmp_path / "transaction.json"
    transaction.write_text('{"schema_version":"tohupono.transaction_descriptor.v1","transaction_type":"transfer","participants":[{"role":"sender","namespace":"local","identifier":"party-a"},{"role":"receiver","namespace":"local","identifier":"party-b"}],"occurred_at":null,"reference":null,"terms":{},"attributes":{}}\n', encoding="utf-8")
    identity = _write_descriptor(tmp_path / "identity.json")

    create_proof_packet(
        sample,
        tmp_path / "provenance_packet",
        False,
        DEFAULT_MANIFEST_KEY,
        DEFAULT_MANIFEST_PUBLIC_KEY,
        "2026-07-13T00:00:00Z",
        ["provenance"],
        None,
        None,
        [provenance],
    )
    create_proof_packet(
        sample,
        tmp_path / "transaction_packet",
        False,
        DEFAULT_MANIFEST_KEY,
        DEFAULT_MANIFEST_PUBLIC_KEY,
        "2026-07-13T00:00:00Z",
        ["transaction"],
        None,
        None,
        None,
        [transaction],
    )
    create_proof_packet(
        sample,
        tmp_path / "identity_packet",
        False,
        DEFAULT_MANIFEST_KEY,
        DEFAULT_MANIFEST_PUBLIC_KEY,
        "2026-07-13T00:00:00Z",
        ["identity"],
        None,
        None,
        None,
        None,
        [identity],
    )

    provenance_manifest = load_manifest(tmp_path / "provenance_packet" / "manifest.json")
    transaction_manifest = load_manifest(tmp_path / "transaction_packet" / "manifest.json")
    identity_manifest = load_manifest(tmp_path / "identity_packet" / "manifest.json")
    assert "provenance" in provenance_manifest
    assert "identities" not in provenance_manifest
    assert "transactions" in transaction_manifest
    assert "identities" not in transaction_manifest
    assert "identities" in identity_manifest


def _tampered_identity_audit(tmp_path: Path, edit: object) -> dict[str, object]:
    descriptor = _write_descriptor(tmp_path / "identity.json")
    _sample, packet = _proof_with_identity(tmp_path, descriptor)
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    if callable(edit):
        edit(manifest)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    result = run_cli("audit", str(packet), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    identity_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "identity")
    assert identity_result["status"] == "FAIL"
    assert data["proof_concept_summary"]["overall_status"] == "FAIL"
    return identity_result


@pytest.mark.parametrize(
    ("name", "edit", "failure"),
    [
        ("missing_section", lambda manifest: manifest.pop("identities"), "identity_section_missing"),
        ("empty", lambda manifest: manifest["identities"].update({"items": [], "assertion_count": 0}), "identity_empty"),
        ("count", lambda manifest: manifest["identities"].update({"assertion_count": 99}), "identity_count_mismatch"),
        ("extra_collection_field", lambda manifest: manifest["identities"].update({"verified": True}), "identity_items_invalid"),
        ("schema", lambda manifest: manifest["identities"].update({"schema_version": "tohupono.identities.v99"}), "identity_schema_unsupported"),
        ("id", lambda manifest: manifest["identities"]["items"][0].update({"assertion_id": "idn_" + "0" * 32}), "identity_assertion_id_mismatch"),
        ("subject", lambda manifest: manifest["identities"]["items"][0]["subject"].update({"digest": "0" * 64}), "identity_subject_digest_mismatch"),
        ("type", lambda manifest: manifest["identities"]["items"][0].update({"assertion_type": "verified_by"}), "identity_assertion_type_unsupported"),
        ("duplicate", lambda manifest: manifest["identities"]["items"].append(dict(manifest["identities"]["items"][0])), "identity_count_mismatch"),
        (
            "duplicate_with_count",
            lambda manifest: (
                manifest["identities"]["items"].append(dict(manifest["identities"]["items"][0])),
                manifest["identities"].update({"assertion_count": 2}),
            ),
            "identity_duplicate_id",
        ),
    ],
)
def test_tampered_identity_fails_audit(tmp_path: Path, name: str, edit: object, failure: str) -> None:
    result = _tampered_identity_audit(tmp_path / name, edit)
    assert failure in result["failures"]


def test_claim_and_identity_mismatch_failures(tmp_path: Path) -> None:
    def noncanonical_identity_object(manifest: dict[str, object]) -> None:
        item = manifest["identities"]["items"][0]
        item["identity"].pop("display_name")
        body = {key: value for key, value in item.items() if key != "assertion_id"}
        item["assertion_id"] = identity_assertion_id_for_body(body)
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        params["assertion_ids"] = [item["assertion_id"]]
        claim["claim_id"] = make_claim_id("identity", claim["subject"], params)

    assert "identity_assertion_malformed" in _tampered_identity_audit(tmp_path / "noncanonical", noncanonical_identity_object)["failures"]

    def extra_unclaimed(manifest: dict[str, object]) -> None:
        identities = manifest["identities"]
        items = identities["items"]
        extra = dict(items[0])
        body = {key: value for key, value in extra.items() if key != "assertion_id"}
        body["reference"] = "extra"
        extra.update(body)
        extra["assertion_id"] = identity_assertion_id_for_body(body)
        items.append(extra)
        identities["assertion_count"] = len(items)
        items.sort(key=lambda item: item["assertion_id"])

    assert "identity_claim_id_undeclared" in _tampered_identity_audit(tmp_path / "extra", extra_unclaimed)["failures"]

    def missing_claimed(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        params["assertion_ids"] = ["idn_" + "0" * 32]
        claim["claim_id"] = make_claim_id("identity", claim["subject"], params)

    assert "identity_claim_id_missing" in _tampered_identity_audit(tmp_path / "missing", missing_claimed)["failures"]

    def duplicate_claim(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        ids = params["assertion_ids"]
        params["assertion_ids"] = [ids[0], ids[0]]
        claim["claim_id"] = make_claim_id("identity", claim["subject"], params)

    assert "identity_claim_id_duplicate" in _tampered_identity_audit(tmp_path / "duplicate", duplicate_claim)["failures"]

    def subject_mismatch(manifest: dict[str, object]) -> None:
        claim = manifest["proof_concepts"]["claims"][0]
        params = claim["parameters"]
        params["subject"] = {"algorithm": "sha256", "digest": "0" * 64}
        claim["claim_id"] = make_claim_id("identity", claim["subject"], params)

    assert "identity_claim_subject_mismatch" in _tampered_identity_audit(tmp_path / "subject", subject_mismatch)["failures"]


def test_identity_claim_order_mismatch_fails(tmp_path: Path) -> None:
    descriptor_a = _write_descriptor(tmp_path / "a.json", _descriptor(identifier="party-a"))
    descriptor_b = _write_descriptor(tmp_path / "b.json", _descriptor(identifier="party-b"))
    _sample, packet = _proof_with_identity(tmp_path, descriptor_a, descriptor_b)
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    claim = manifest["proof_concepts"]["claims"][0]
    params = claim["parameters"]
    params["assertion_ids"] = list(reversed(params["assertion_ids"]))
    claim["claim_id"] = make_claim_id("identity", claim["subject"], params)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")

    audit = run_cli("audit", str(packet), "--json")
    assert audit.returncode == 1
    data = json.loads(audit.stdout)
    identity_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "identity")
    assert "identity_claim_order_mismatch" in identity_result["failures"]


def test_identity_cli_privacy_audit_and_report(tmp_path: Path) -> None:
    descriptor = _write_descriptor(tmp_path / "identity.json", _descriptor(attributes={"private_note": "do-not-render"}, reference="id-ref"))
    validate = run_cli("identity", "validate", str(descriptor), "--json")
    assert validate.returncode == 0
    assert json.loads(validate.stdout)["status"] == "ok"
    human_validate = run_cli("identity", "validate", str(descriptor))
    assert "do-not-render" not in human_validate.stdout
    assert "does not prove" in human_validate.stdout

    _sample, packet = _proof_with_identity(tmp_path, descriptor)
    inspect_json = run_cli("identity", "inspect", str(packet), "--json")
    assert inspect_json.returncode == 0
    assert json.loads(inspect_json.stdout)["assertion_count"] == 1
    inspect_human = run_cli("identity", "inspect", str(packet))
    assert "do-not-render" not in inspect_human.stdout
    assert "Assertion ID:" in inspect_human.stdout
    assert "verified identity" not in inspect_human.stdout.lower()

    audit = run_cli("audit", str(packet), "--json")
    assert audit.returncode == 0
    data = json.loads(audit.stdout)
    identity_result = next(item for item in data["proof_concept_results"] if item["concept_id"] == "identity")
    assert identity_result["status"] == "PASS"
    assert "not externally verified" in " ".join(identity_result["limitations"]).lower()

    report = tmp_path / "verification_report.pdf"
    key = tmp_path / "keys" / "report_signing_key.pem"
    generate_report(packet / "manifest.json", report, key)
    text = report.read_bytes().decode("latin-1", errors="ignore")
    assert "Proof of Identity Details" in text
    assert "do-not-render" not in text
    assert report.with_suffix(".pdf.sig").exists()


def test_all_packet_internal_concepts_and_identity_are_separate(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("combined identity concepts\n", encoding="utf-8")
    record = tmp_path / "record.json"
    record.write_text('{"schema_version":"tohupono.record_descriptor.v1","record_type":"generic","namespace":"local","reference":null,"attributes":{}}\n', encoding="utf-8")
    custody = tmp_path / "custody.json"
    custody.write_text('{"schema_version":"tohupono.custody_descriptor.v1","event_type":"received","actor":{"namespace":"local","identifier":"operator-1"},"occurred_at":null,"location":null,"reference":null,"attributes":{}}\n', encoding="utf-8")
    provenance = tmp_path / "provenance.json"
    provenance.write_text('{"schema_version":"tohupono.provenance_descriptor.v1","relation_type":"derived_from","parent":{"algorithm":"sha256","digest":"' + ("a" * 64) + '"},"operation":null,"occurred_at":null,"actor":null,"reference":null,"attributes":{}}\n', encoding="utf-8")
    transaction = tmp_path / "transaction.json"
    transaction.write_text('{"schema_version":"tohupono.transaction_descriptor.v1","transaction_type":"transfer","participants":[{"role":"sender","namespace":"local","identifier":"party-a"},{"role":"receiver","namespace":"local","identifier":"party-b"}],"occurred_at":null,"reference":null,"terms":{},"attributes":{}}\n', encoding="utf-8")
    identity = _write_descriptor(tmp_path / "identity.json")
    packet = tmp_path / "packet"
    result = run_cli(
        "prove", str(sample), "--output", str(packet),
        "--concept", "records", "--concept", "custody", "--concept", "provenance", "--concept", "transaction", "--concept", "identity",
        "--record-json", str(record), "--custody-json", str(custody), "--provenance-json", str(provenance), "--transaction-json", str(transaction), "--identity-json", str(identity),
    )
    assert result.returncode == 0, result.stderr
    audit = run_cli("audit", str(packet), "--json")
    data = json.loads(audit.stdout)
    statuses = {item["concept_id"]: item["status"] for item in data["proof_concept_results"]}
    assert statuses["records"] == "PASS"
    assert statuses["custody"] == "PASS"
    assert statuses["provenance"] == "PASS"
    assert statuses["transaction"] == "PASS"
    assert statuses["identity"] == "PASS"

    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest["identities"]["items"][0]["assertion_id"] = "idn_" + "0" * 32
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    tampered = run_cli("audit", str(packet), "--json")
    tampered_data = json.loads(tampered.stdout)
    tampered_statuses = {item["concept_id"]: item["status"] for item in tampered_data["proof_concept_results"]}
    assert tampered_statuses["identity"] == "FAIL"
    assert tampered_statuses["records"] == "PASS"
    assert tampered_statuses["custody"] == "PASS"
    assert tampered_statuses["provenance"] == "PASS"
    assert tampered_statuses["transaction"] == "PASS"


def test_legacy_packet_without_identity_remains_valid(tmp_path: Path) -> None:
    sample = tmp_path / "source.txt"
    sample.write_text("legacy identity\n", encoding="utf-8")
    packet = tmp_path / "packet"
    create_proof_packet(sample, packet, sealed_at_utc="2026-07-13T00:00:00Z")
    manifest_path = packet / "manifest.json"
    manifest = load_manifest(manifest_path)
    manifest.pop("proof_concepts", None)
    manifest_path.write_text(canonical_json_text(manifest) + "\n", encoding="utf-8")
    audit = run_cli("audit", str(packet), "--json")
    data = json.loads(audit.stdout)
    assert "identity" not in data["declared_proof_concepts"]
    assert data["proof_concept_summary"]["overall_status"] == "UNPROVEN"
