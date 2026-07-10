from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from tohupono import __version__
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.file_identity import Blake3UnavailableError, TohuPonoError, hash_file, inspect_file
from tohupono.core.proof import create_proof_packet, evidence_chain_diagnostics, load_manifest
from tohupono.reporting.pro_report import generate_report
from tohupono.verdicts.classifier import manifest_signature_status, verify_file, write_markdown, write_verdict


def _print_json(value: object) -> None:
    print(canonical_json_text(value))


def _proof_artefacts(manifest: Path) -> list[str]:
    proof_dir = manifest.parent
    names = [
        "manifest.json",
        "hashes.txt",
        "metadata.json",
        "evidence_chain.jsonl",
        "warnings.json",
        "signatures/manifest.sig",
        "signatures/manifest.pub",
    ]
    return [name for name in names if (proof_dir / name).exists()]


def inspect_proof_manifest(manifest_path: Path) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    file_info = manifest.get("file", {})
    if not isinstance(file_info, dict):
        file_info = {}
    tool_info = manifest.get("tool", {})
    if not isinstance(tool_info, dict):
        tool_info = {}
    warnings = manifest.get("warnings", [])
    warnings_count = len(warnings) if isinstance(warnings, list) else 0
    chain_result = evidence_chain_diagnostics(manifest_path.parent / "evidence_chain.jsonl")
    return {
        "available_artefacts": _proof_artefacts(manifest_path),
        "boundary": "Proof manifest inspected. Source file was not verified in this command.",
        "evidence_chain_status": chain_result["status"],
        "file_sha256": file_info.get("sha256"),
        "file_size": file_info.get("size_bytes"),
        "manifest_signature_status": manifest_signature_status(manifest_path),
        "manifest_version": manifest.get("manifest_version"),
        "original_observed_file_path": file_info.get("path_observed"),
        "proof_id": manifest.get("proof_id"),
        "schema_version": manifest.get("schema_version"),
        "sealed_timestamp": manifest.get("sealed_at_utc"),
        "tool_version": tool_info.get("version"),
        "warnings_count": warnings_count,
    }


def _print_verify_chain_human(result: dict[str, object]) -> None:
    print(f"Evidence chain status: {result['status']}")
    print(f"Path: {result['path']}")
    print(f"Events: {result['event_count']}")
    errors = result.get("errors", [])
    if errors:
        print("Diagnostics:")
        for error in errors:
            print(f"- {error}")


def _print_inspect_proof_human(result: dict[str, object]) -> None:
    print("Proof manifest inspected. Source file was not verified in this command.")
    print(f"Proof ID: {result.get('proof_id') or 'unknown'}")
    print(f"Schema version: {result.get('schema_version') or 'unknown'}")
    print(f"Manifest version: {result.get('manifest_version') or 'unknown'}")
    print(f"Tool version: {result.get('tool_version') or 'unknown'}")
    print(f"Sealed timestamp: {result.get('sealed_timestamp') or 'unknown'}")
    print(f"Original observed file path: {result.get('original_observed_file_path') or 'unknown'}")
    print(f"File size: {result.get('file_size') if result.get('file_size') is not None else 'unknown'}")
    print(f"SHA-256: {result.get('file_sha256') or 'unknown'}")
    print(f"Manifest signature status: {result.get('manifest_signature_status') or 'unknown'}")
    print(f"Evidence chain status: {result.get('evidence_chain_status') or 'unknown'}")
    print(f"Warnings count: {result.get('warnings_count')}")
    print("Available proof packet artefacts:")
    for artefact in result.get("available_artefacts", []):
        print(f"- {artefact}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tohupono", description="Local-first file-origin proof tooling.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_cmd = sub.add_parser("inspect", help="Inspect observed file identity.")
    inspect_cmd.add_argument("file")

    hash_cmd = sub.add_parser("hash", help="Hash a file.")
    hash_cmd.add_argument("file")
    hash_cmd.add_argument("--algorithm", choices=["sha256", "sha512", "blake3"], default="sha256")

    prove_cmd = sub.add_parser("prove", help="Create a proof packet.")
    prove_cmd.add_argument("file")
    prove_cmd.add_argument("--output", required=True)
    prove_cmd.add_argument("--include-payload", action="store_true")

    verify_cmd = sub.add_parser("verify", help="Verify a file against a proof manifest.")
    verify_cmd.add_argument("file")
    verify_cmd.add_argument("--proof", required=True)
    verify_cmd.add_argument("--output")
    verify_cmd.add_argument("--json", action="store_true")

    verify_chain_cmd = sub.add_parser("verify-chain", help="Verify an evidence chain JSONL file.")
    verify_chain_cmd.add_argument("evidence_chain")
    verify_chain_cmd.add_argument("--json", action="store_true")

    inspect_proof_cmd = sub.add_parser("inspect-proof", help="Inspect a proof manifest without a source file.")
    inspect_proof_cmd.add_argument("manifest")
    inspect_proof_cmd.add_argument("--json", action="store_true")

    report_cmd = sub.add_parser("report", help="Generate a signed PDF report.")
    report_cmd.add_argument("--proof", required=True)
    report_cmd.add_argument("--format", choices=["pdf"], default="pdf")
    report_cmd.add_argument("--output", required=True)
    report_cmd.add_argument("--community", action="store_true")
    report_cmd.add_argument("--report-key", default="keys/report_signing_key.pem")

    return parser


def run(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            _print_json(inspect_file(Path(args.file)).to_dict())
        elif args.command == "hash":
            try:
                digest = hash_file(Path(args.file), args.algorithm)
            except Blake3UnavailableError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            print(digest)
        elif args.command == "prove":
            manifest = create_proof_packet(Path(args.file), Path(args.output), args.include_payload)
            _print_json({"proof_id": manifest.proof_id, "manifest": str(Path(args.output) / "manifest.json")})
        elif args.command == "verify":
            result = verify_file(Path(args.file), Path(args.proof))
            write_verdict(Path(args.proof), result)
            if args.output:
                write_markdown(Path(args.output), result)
            _print_json(result.to_cli_json() if args.json else result.to_dict())
        elif args.command == "verify-chain":
            result = evidence_chain_diagnostics(Path(args.evidence_chain))
            if args.json:
                _print_json(result)
            else:
                _print_verify_chain_human(result)
        elif args.command == "inspect-proof":
            result = inspect_proof_manifest(Path(args.manifest))
            if args.json:
                _print_json(result)
            else:
                _print_inspect_proof_human(result)
        elif args.command == "report":
            sig_path = generate_report(
                proof=Path(args.proof),
                output=Path(args.output),
                report_key=Path(args.report_key),
                community=args.community,
                fmt=args.format,
            )
            _print_json({"report": args.output, "signature": str(sig_path)})
        else:
            parser.error("Unknown command")
    except (FileNotFoundError, TohuPonoError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> None:
    raise SystemExit(run(argv))
