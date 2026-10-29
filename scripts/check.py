"""Bounded checks for this small standalone project; no live service dependencies."""

import subprocess

for command in (
    ["uv", "run", "ruff", "check", "."],
    ["uv", "run", "ruff", "format", "--check", "."],
    ["uv", "run", "pyright"],
    ["uv", "run", "pytest", "-q", "tests"],
):
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, check=True, timeout=120)
