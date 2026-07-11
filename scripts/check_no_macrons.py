from __future__ import annotations

import sys
from pathlib import Path

MACRON_CODEPOINTS = {
    0x0100,
    0x0101,
    0x0112,
    0x0113,
    0x012A,
    0x012B,
    0x014C,
    0x014D,
    0x016A,
    0x016B,
}
SUFFIXES = {".py", ".md", ".toml", ".json", ".yaml", ".yml", ".txt"}
EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    ".venv",
    "venv",
    "build",
    "dist",
    "node_modules",
    "__pycache__",
    "timestamp_receipts",
    "keys",
}


def should_scan(path: Path) -> bool:
    if path.suffix not in SUFFIXES:
        return False
    if path.suffix == ".txt" and "proof_packet" in path.parts:
        return False
    if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in path.parts):
        return False
    return True


def scan(root: Path) -> list[tuple[Path, int]]:
    findings: list[tuple[Path, int]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or not should_scan(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if any(ord(char) in MACRON_CODEPOINTS for char in line):
                findings.append((path, line_number))
    return findings


def main() -> int:
    root = Path.cwd()
    findings = scan(root)
    for path, line_number in findings:
        print(f"macron detected: {path}:{line_number}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
