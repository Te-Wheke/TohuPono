from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from tohupono import __version__
from tohupono.core.canonical_json import canonical_json_text
from tohupono.core.file_identity import Blake3UnavailableError, TohuPonoError, hash_file, inspect_file
from tohupono.core.proof import create_proof_packet
from tohupono.reporting.pro_report import generate_report
from tohupono.verdicts.classifier import verify_file, write_markdown, write_verdict


def _print_json(value: object) -> None:
    print(canonical_json_text(value))


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
            _print_json(result.to_dict())
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
