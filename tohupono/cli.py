from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from tohupono import __version__
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.file_identity import Blake3UnavailableError, TohuPonoError, hash_file, inspect_file
from tohupono.core.proof import (
    create_amendment,
    create_proof_packet,
    evidence_chain_diagnostics,
    load_manifest,
    packet_diagnostics,
    resolve_packet_manifest,
)
from tohupono.reporting.pro_report import generate_report
from tohupono.trust.keys import KeyErrorWithAction, check_keys, inspect_keys, key_purpose_names
from tohupono.verdicts.classifier import (
    VERIFIED_INTEGRITY,
    manifest_signature_status,
    verify_file,
    write_markdown,
    write_verdict,
)

EXIT_SUCCESS = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USER_ERROR = 2
EXIT_INTERNAL_ERROR = 3


def _print_json(value: object) -> None:
    print(canonical_json_text(value))


def _json_error(code: str, message: str) -> dict[str, object]:
    return {"error": {"code": code, "message": message}, "status": "error"}


def _emit_error(code: str, message: str, *, json_mode: bool, exit_code: int) -> int:
    if json_mode:
        _print_json(_json_error(code, message))
    else:
        print(f"error: {message}", file=sys.stderr)
    return exit_code


def _missing_path_code(command: str, path_arg: str) -> str:
    if command in {"verify", "verify-file", "report", "inspect-proof", "audit", "amend"} and (
        "manifest" in path_arg.lower() or "packet" in path_arg.lower()
    ):
        return "MISSING_PROOF"
    return "MISSING_FILE"


def _json_mode(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json", False))


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


def _print_packet_checks(result: dict[str, object]) -> None:
    for check in result.get("checks", []):
        if isinstance(check, dict):
            print(f"{check.get('status')}: {check.get('message')}")


def _print_verify_file_human(result: object) -> None:
    verdict = getattr(result, "verdict")
    if verdict == VERIFIED_INTEGRITY:
        print("PASS: file hash matches manifest.")
        print("PASS: file_id matches.")
        for warning in getattr(result, "warnings"):
            print(f"WARN: {warning}")
        for note in getattr(result, "notes"):
            if "path differs" in note.lower():
                print("WARN: current path differs from original recorded path.")
            print(f"NOTE: {note}")
        print("NOTE: copy or rename does not weaken byte-level proof.")
    else:
        for reason in getattr(result, "reasons"):
            print(f"FAIL: {reason}")
        print("FAIL: file hash does not match manifest.")
        print("FAIL: file_id mismatch.")


def _compare_files(file_a: Path, file_b: Path) -> dict[str, object]:
    a = inspect_file(file_a, include_blake3=False)
    b = inspect_file(file_b, include_blake3=False)
    same = a.sha256 == b.sha256
    return {
        "conclusion": "files are byte-identical" if same else "files are not byte-identical",
        "file_a": {"path": str(file_a), "sha256": a.sha256, "size_bytes": a.size_bytes},
        "file_b": {"path": str(file_b), "sha256": b.sha256, "size_bytes": b.size_bytes},
        "file_id_same": same,
        "paths_differ": str(file_a) != str(file_b),
        "status": "MATCH" if same else "DIFFERENT",
    }


def _print_compare_human(result: dict[str, object]) -> None:
    print(str(result["status"]))
    a = result["file_a"]
    b = result["file_b"]
    if isinstance(a, dict) and isinstance(b, dict):
        print(f"File A SHA-256: {a['sha256']}")
        print(f"File A size: {a['size_bytes']}")
        print(f"File B SHA-256: {b['sha256']}")
        print(f"File B size: {b['size_bytes']}")
    print(f"file_id same: {result['file_id_same']}")
    print(f"paths differ: {result['paths_differ']}")
    if result["file_id_same"]:
        print("PASS: files are byte-identical.")
        print("PASS: file_id matches.")
        print("NOTE: differing names or paths do not weaken byte-level integrity.")
    else:
        print("FAIL: files are not byte-identical.")
        print("FAIL: file_id differs.")
    print(f"Conclusion: {result['conclusion']}")


def _print_key_inspect_human(result: dict[str, object]) -> None:
    for item in result.get("keys", []):
        if not isinstance(item, dict):
            continue
        print(f"Purpose: {item['purpose']}")
        print(f"Private key path: {item['private_key_path']}")
        print(f"Private key exists: {'yes' if item['private_key_exists'] else 'no'}")
        print(f"Public key path: {item['public_key_path']}")
        print(f"Public key exists: {'yes' if item['public_key_exists'] else 'no'}")
        print(f"Allowed operations: {', '.join(item['allowed_operations'])}")
        print(f"Status: {item['status']}")
        warnings = item.get("warnings") or []
        if warnings:
            print("Warnings:")
            for warning in warnings:
                print(f"- {warning}")
        print("")


def _print_key_check_human(result: dict[str, object]) -> None:
    print(f"OpenSSL available: {'yes' if result.get('openssl_available') else 'no'}")
    print(f"Status: {result.get('status')}")
    for item in result.get("keys", []):
        if not isinstance(item, dict):
            continue
        print(f"Purpose: {item['purpose']}")
        print(f"Status: {item['status']}")
        for warning in item.get("warnings") or []:
            print(f"WARN: {warning}")
        for failure in item.get("failures") or []:
            print(f"FAIL: {failure}")
        print("")


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
    prove_cmd.add_argument("--output", default="proof_packet")
    prove_cmd.add_argument("--include-payload", action="store_true")

    verify_cmd = sub.add_parser("verify", help="Verify a packet, or verify a file with --proof.")
    verify_cmd.add_argument("target")
    verify_cmd.add_argument("--proof")
    verify_cmd.add_argument("--output")
    verify_cmd.add_argument("--json", action="store_true")

    verify_file_cmd = sub.add_parser("verify-file", help="Verify a file against a proof packet.")
    verify_file_cmd.add_argument("file")
    verify_file_cmd.add_argument("packet")
    verify_file_cmd.add_argument("--json", action="store_true")

    verify_chain_cmd = sub.add_parser("verify-chain", help="Verify an evidence chain JSONL file.")
    verify_chain_cmd.add_argument("evidence_chain")
    verify_chain_cmd.add_argument("--json", action="store_true")

    inspect_proof_cmd = sub.add_parser("inspect-proof", help="Inspect a proof manifest without a source file.")
    inspect_proof_cmd.add_argument("manifest")
    inspect_proof_cmd.add_argument("--json", action="store_true")

    compare_cmd = sub.add_parser("compare", help="Compare two files by byte digest.")
    compare_cmd.add_argument("file_a")
    compare_cmd.add_argument("file_b")
    compare_cmd.add_argument("--json", action="store_true")

    amend_cmd = sub.add_parser("amend", help="Create an amendment packet without mutating the original.")
    amend_cmd.add_argument("packet")
    amend_cmd.add_argument("--note", required=True)
    amend_cmd.add_argument("--json", action="store_true")

    audit_cmd = sub.add_parser("audit", help="Produce a technical proof packet audit.")
    audit_cmd.add_argument("packet")
    audit_cmd.add_argument("--json", action="store_true")

    key_cmd = sub.add_parser("key", help="Inspect and check local key purposes.")
    key_sub = key_cmd.add_subparsers(dest="key_command", required=True)
    key_inspect_cmd = key_sub.add_parser("inspect", help="Inspect configured key purposes.")
    key_inspect_cmd.add_argument("--purpose", choices=key_purpose_names())
    key_inspect_cmd.add_argument("--json", action="store_true")
    key_check_cmd = key_sub.add_parser("check", help="Check local key hygiene.")
    key_check_cmd.add_argument("--purpose", choices=key_purpose_names())
    key_check_cmd.add_argument("--json", action="store_true")

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
            return EXIT_SUCCESS
        elif args.command == "hash":
            try:
                digest = hash_file(Path(args.file), args.algorithm)
            except Blake3UnavailableError as exc:
                print(str(exc), file=sys.stderr)
                return EXIT_USER_ERROR
            print(digest)
            return EXIT_SUCCESS
        elif args.command == "prove":
            manifest = create_proof_packet(Path(args.file), Path(args.output), args.include_payload)
            _print_json({"proof_id": manifest.proof_id, "manifest": str(Path(args.output) / "manifest.json")})
            return EXIT_SUCCESS
        elif args.command == "verify":
            if args.proof:
                result = verify_file(Path(args.target), Path(args.proof))
                write_verdict(Path(args.proof), result)
                if args.output:
                    write_markdown(Path(args.output), result)
                _print_json(result.to_cli_json() if args.json else result.to_dict())
                return EXIT_SUCCESS if result.verdict == VERIFIED_INTEGRITY else EXIT_VERIFICATION_FAILED
            packet_result = packet_diagnostics(Path(args.target))
            if args.output:
                Path(args.output).write_text(canonical_json_text(packet_result) + "\n", encoding="utf-8")
            if args.json:
                _print_json(packet_result)
            else:
                _print_packet_checks(packet_result)
            return EXIT_SUCCESS if packet_result["status"] != "fail" else EXIT_VERIFICATION_FAILED
        elif args.command == "verify-file":
            manifest_path = resolve_packet_manifest(Path(args.packet))
            result = verify_file(Path(args.file), manifest_path)
            write_verdict(manifest_path, result)
            if args.json:
                _print_json(result.to_cli_json())
            else:
                _print_verify_file_human(result)
            return EXIT_SUCCESS if result.verdict == VERIFIED_INTEGRITY else EXIT_VERIFICATION_FAILED
        elif args.command == "compare":
            result = _compare_files(Path(args.file_a), Path(args.file_b))
            if args.json:
                _print_json(result)
            else:
                _print_compare_human(result)
            return EXIT_SUCCESS if result["file_id_same"] else EXIT_VERIFICATION_FAILED
        elif args.command == "verify-chain":
            result = evidence_chain_diagnostics(Path(args.evidence_chain))
            if args.json:
                _print_json(result)
            else:
                _print_verify_chain_human(result)
            status = result["status"]
            if status == "valid":
                return EXIT_SUCCESS
            if status == "missing":
                return EXIT_USER_ERROR
            if status == "error":
                return EXIT_INTERNAL_ERROR
            return EXIT_VERIFICATION_FAILED
        elif args.command == "inspect-proof":
            result = inspect_proof_manifest(Path(args.manifest))
            if args.json:
                _print_json(result)
            else:
                _print_inspect_proof_human(result)
            return EXIT_SUCCESS
        elif args.command == "amend":
            out = create_amendment(Path(args.packet), args.note)
            result = {"amendment": str(out), "status": "created"}
            if args.json:
                _print_json(result)
            else:
                print(f"PASS: amendment packet created at {out}")
                print("PASS: original packet was not modified.")
            return EXIT_SUCCESS
        elif args.command == "audit":
            result = packet_diagnostics(Path(args.packet))
            if args.json:
                _print_json(result)
            else:
                _print_packet_checks(result)
            return EXIT_SUCCESS if result["status"] != "fail" else EXIT_VERIFICATION_FAILED
        elif args.command == "key":
            if args.key_command == "inspect":
                result = inspect_keys(args.purpose)
                if args.json:
                    _print_json(result)
                else:
                    _print_key_inspect_human(result)
                return EXIT_SUCCESS
            if args.key_command == "check":
                result = check_keys(args.purpose)
                if args.json:
                    _print_json(result)
                else:
                    _print_key_check_human(result)
                return EXIT_VERIFICATION_FAILED if result["status"] == "fail" else EXIT_SUCCESS
            parser.error("Unknown key command")
        elif args.command == "report":
            sig_path = generate_report(
                proof=Path(args.proof),
                output=Path(args.output),
                report_key=Path(args.report_key),
                community=args.community,
                fmt=args.format,
            )
            _print_json({"report": args.output, "signature": str(sig_path)})
            return EXIT_SUCCESS
        else:
            parser.error("Unknown command")
    except FileNotFoundError as exc:
        missing_path = exc.filename or str(exc)
        return _emit_error(
            _missing_path_code(args.command, str(missing_path)),
            str(exc),
            json_mode=_json_mode(args),
            exit_code=EXIT_USER_ERROR,
        )
    except json.JSONDecodeError as exc:
        code = "INVALID_JSONL" if args.command == "verify-chain" else "INVALID_MANIFEST"
        return _emit_error(code, str(exc), json_mode=_json_mode(args), exit_code=EXIT_USER_ERROR)
    except TohuPonoError as exc:
        return _emit_error("INVALID_ARGUMENT", str(exc), json_mode=_json_mode(args), exit_code=EXIT_USER_ERROR)
    except ValueError as exc:
        return _emit_error("INVALID_ARGUMENT", str(exc), json_mode=_json_mode(args), exit_code=EXIT_USER_ERROR)
    except KeyErrorWithAction as exc:
        return _emit_error("SIGNATURE_ERROR", str(exc), json_mode=_json_mode(args), exit_code=EXIT_INTERNAL_ERROR)
    except Exception as exc:
        return _emit_error("INTERNAL_ERROR", str(exc), json_mode=_json_mode(args), exit_code=EXIT_INTERNAL_ERROR)
    return EXIT_SUCCESS


def main(argv: Sequence[str] | None = None) -> None:
    raise SystemExit(run(argv))
