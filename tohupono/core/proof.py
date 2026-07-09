from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tohupono import __version__
from tohupono.core.canonical_json import canonical_json_bytes, canonical_json_text
from tohupono.core.file_identity import FileIdentity, inspect_file
from tohupono.trust.keys import DEFAULT_MANIFEST_KEY, DEFAULT_MANIFEST_PUBLIC_KEY, sign_manifest_bytes

SCHEMA_VERSION = "tohupono.proof_manifest.v0.1"


@dataclass(frozen=True)
class ProofManifest:
    schema_version: str
    proof_id: str
    sealed_at_utc: str
    tool: dict[str, str]
    file: dict[str, object]
    claims: list[dict[str, object]]
    evidence: dict[str, list[dict[str, object]]]
    trust_policy: dict[str, str]
    warnings: list[str]
    community: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_proof_id(identity: FileIdentity, sealed_at_utc: str) -> str:
    source = {
        "schema_version": SCHEMA_VERSION,
        "sha256": identity.sha256,
        "sealed_at_utc": sealed_at_utc,
        "tool_version": __version__,
    }
    digest = hashlib.sha256(canonical_json_bytes(source)).hexdigest()
    return f"tp_{digest[:32]}"


def build_manifest(identity: FileIdentity, sealed_at_utc: str) -> ProofManifest:
    warnings: list[str] = []
    if identity.blake3 is None:
        warnings.append("BLAKE3 unavailable; optional BLAKE3 digest was not recorded.")

    return ProofManifest(
        schema_version=SCHEMA_VERSION,
        proof_id=make_proof_id(identity, sealed_at_utc),
        sealed_at_utc=sealed_at_utc,
        tool={"name": "tohupono", "version": __version__},
        file=identity.to_dict(),
        claims=[
            {
                "claim_id": "claim_001",
                "type": "received_from_user",
                "statement": "User supplied file for proof sealing.",
                "issuer": "local_user",
                "evidence_refs": [],
            }
        ],
        evidence={
            "hashes": [],
            "timestamps": [],
            "signatures": [],
            "c2pa": [],
            "transparency_logs": [],
            "custody_events": [],
        },
        trust_policy={"policy_id": "local_default", "policy_digest": "unconfigured"},
        warnings=warnings,
        community=False,
    )


def write_json(path: Path, value: Any) -> None:
    path.write_text(canonical_json_text(value) + "\n", encoding="utf-8")


def create_proof_packet(
    source: Path,
    output: Path,
    include_payload: bool = False,
    manifest_key: Path = DEFAULT_MANIFEST_KEY,
    manifest_public_key: Path = DEFAULT_MANIFEST_PUBLIC_KEY,
) -> ProofManifest:
    identity = inspect_file(source)
    sealed_at = utc_now_iso()
    manifest = build_manifest(identity, sealed_at)
    output.mkdir(parents=True, exist_ok=True)

    manifest_path = output / "manifest.json"
    write_json(manifest_path, manifest.to_dict())
    signatures_dir = output / "signatures"
    signatures_dir.mkdir(exist_ok=True)
    signature, public_key = sign_manifest_bytes(
        manifest_path.read_bytes(),
        private_key=manifest_key,
        public_key=manifest_public_key,
    )
    (signatures_dir / "manifest.sig").write_bytes(signature)
    (signatures_dir / "manifest.pub").write_bytes(public_key)
    hashes = [
        f"sha256  {identity.sha256}",
        f"sha512  {identity.sha512}",
    ]
    if identity.blake3:
        hashes.append(f"blake3  {identity.blake3}")
    (output / "hashes.txt").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    write_json(output / "metadata.json", identity.to_dict())
    sealed_event = {
        "event_id": hashlib.sha256(
            canonical_json_bytes(
                {
                    "event_type": "sealed",
                    "proof_id": manifest.proof_id,
                    "sealed_at_utc": sealed_at,
                    "sha256": identity.sha256,
                }
            )
        ).hexdigest(),
        "event_type": "sealed",
        "proof_id": manifest.proof_id,
        "recorded_at_utc": sealed_at,
        "file_sha256": identity.sha256,
    }
    (output / "evidence_chain.jsonl").write_text(
        canonical_json_text(sealed_event) + "\n", encoding="utf-8"
    )
    write_json(output / "warnings.json", {"warnings": manifest.warnings})

    if include_payload:
        payload_dir = output / "payload"
        payload_dir.mkdir(exist_ok=True)
        shutil.copy2(source, payload_dir / source.name)

    return manifest


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
