from __future__ import annotations

import json
import os
from pathlib import Path

import tohupono
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.file_identity import Blake3UnavailableError, hash_file, inspect_file
from tohupono.core.proof import (
    GENESIS_EVENT_HASH,
    build_evidence_event,
    create_proof_packet,
    evidence_chain_diagnostics,
    event_hash,
    load_manifest,
    make_proof_id,
    packet_diagnostics,
    verify_evidence_chain,
)
from tohupono.reporting.pro_report import COMMUNITY_TEXT, FORBIDDEN_LANGUAGE, generate_report
from tohupono.trust.keys import export_public_key, verify_signature
from tohupono.verdicts.classifier import (
    ALTERED_AFTER_PROOF,
    PATH_DIFFERS_NOTE,
    PROVENANCE_CONFLICT,
    UNPROVEN,
    VERIFIED_INTEGRITY,
    verify_file,
)

from tests.support import run_cli


def test_hash_stability(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("evidence\n", encoding="utf-8")
    assert hash_file(sample, "sha256") == hash_file(sample, "sha256")
    assert hash_file(sample, "sha512") == hash_file(sample, "sha512")

def test_blake3_unavailable_is_clean(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("evidence\n", encoding="utf-8")
    try:
        digest = hash_file(sample, "blake3")
    except Blake3UnavailableError as exc:
        assert "BLAKE3 support is unavailable" in str(exc)
    else:
        assert len(digest) == 64

def test_v030_universal_file_object_fields(tmp_path: Path) -> None:
    sample = tmp_path / "photo_like.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\nnot really an image")
    proof_dir = tmp_path / "proof_packet"
    create_proof_packet(sample, proof_dir)
    manifest = load_manifest(proof_dir / "manifest.json")
    file_info = manifest["file"]
    assert file_info["file_id"] == file_info["sha256"]
    assert file_info["original_path"] == str(sample)
    assert file_info["filename"] == "photo_like.png"
    assert file_info["extension"] == ".png"
    assert file_info["metadata_trust_level"] == "untrusted_supporting_metadata"
    assert "os_created_time" in file_info
    assert "os_modified_time" in file_info
    assert "os_accessed_time" in file_info

def test_v030_empty_binary_video_and_unicode_names_prove(tmp_path: Path) -> None:
    cases = {
        "empty": b"",
        "binary.bin": bytes(range(32)),
        "clip.mp4": b"\x00\x00\x00\x18ftypmp42",
        "taonga_\u0101hua.dat": b"unicode filename bytes",
    }
    for name, payload in cases.items():
        sample = tmp_path / name
        sample.write_bytes(payload)
        proof_dir = tmp_path / f"{name}_proof"
        create_proof_packet(sample, proof_dir)
        result = verify_file(sample, proof_dir / "manifest.json")
        assert result.verdict == VERIFIED_INTEGRITY

def test_v030_compare_command_reports_match_and_difference(tmp_path: Path) -> None:
    one = tmp_path / "one.txt"
    copied = tmp_path / "copied.txt"
    changed = tmp_path / "changed.txt"
    one.write_bytes(b"same")
    copied.write_bytes(b"same")
    changed.write_bytes(b"different")
    match = run_cli("compare", str(one), str(copied), "--json")
    assert match.returncode == 0, match.stderr
    match_data = json.loads(match.stdout)
    assert match_data["status"] == "MATCH"
    assert match_data["file_id_same"] is True
    different = run_cli("compare", str(one), str(changed))
    assert different.returncode == 1
    assert "FAIL: files are not byte-identical." in different.stdout
