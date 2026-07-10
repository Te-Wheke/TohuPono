from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "tohupono", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
