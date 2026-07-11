from __future__ import annotations

import json
from pathlib import Path

from tohupono.concepts.model import MATURITY_VALUES
from tohupono.concepts.registry import concept_registry, get_concept
from tohupono.trust.keys import verify_lifecycle_chain

from tests.support import run_cli

def test_agents_operating_contract_mentions_proof_concepts_and_security_rules() -> None:
    text = Path("AGENTS.md").read_text(encoding="utf-8")
    assert "Proof Concepts" in text
    assert "Digest integrity does not automatically prove authenticity" in text
    assert "Possession does not automatically prove ownership" in text
    assert "never use shell command strings for OpenSSL" in text
    assert "Do not use macrons" in text
    assert "must not:" in text


def test_proof_concepts_use_declared_maturity_values_only() -> None:
    registry = concept_registry()
    assert {item["concept_id"] for item in registry} >= {
        "integrity",
        "existence",
        "records",
        "lineage",
        "authenticity",
        "ownership",
        "reality",
    }
    for item in registry:
        assert item["implementation_maturity"] in MATURITY_VALUES
        assert item["claim_boundary"]
        assert item["known_limitations"]


def test_initial_proof_concept_maturity_assignments() -> None:
    assert get_concept("integrity").implementation_maturity == "locally_supported"
    assert get_concept("existence").implementation_maturity == "locally_supported"
    assert get_concept("records").implementation_maturity == "locally_supported"
    assert get_concept("lineage").implementation_maturity == "locally_supported"
    assert get_concept("authenticity").implementation_maturity == "modelled"
    assert get_concept("ownership").implementation_maturity == "modelled"
    assert get_concept("reality").implementation_maturity == "modelled"


def test_concept_registry_output_is_deterministic() -> None:
    first = json.dumps(concept_registry(), sort_keys=True, separators=(",", ":"))
    second = json.dumps(concept_registry(), sort_keys=True, separators=(",", ":"))
    assert first == second
def test_lifecycle_chain_tampering_fails(tmp_path: Path) -> None:
    key_dir = tmp_path / "keys"
    assert run_cli("key", "create", "--purpose", "manifest", "--output-dir", str(key_dir), "--json").returncode == 0
    assert (
        run_cli(
            "key",
            "rotate",
            "--purpose",
            "manifest",
            "--reason",
            "chain tamper",
            "--output-dir",
            str(key_dir),
            "--json",
        ).returncode
        == 0
    )
    log_path = key_dir / "key_lifecycle_log.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[-1])
    event["reason"] = "edited"
    lines[-1] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify_lifecycle_chain(key_dir)
    assert result["status"] == "invalid"
    assert any("hash_mismatch" in failure for failure in result["failures"])
