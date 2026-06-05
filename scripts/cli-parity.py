#!/usr/bin/env python3
"""Check implemented CLI syntax against the pinned upstream submodule."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUST_BIN = ROOT / "target" / "debug" / "detect-secrets-rs"

IMPLEMENTED_SCAN_FLAGS = [
    "--all-files",
    "--base64-limit",
    "--disable-plugin",
    "--exclude-files",
    "--exclude-lines",
    "--exclude-secrets",
    "--hex-limit",
    "--list-all-plugins",
    "--no-verify",
    "--only-allowlisted",
    "--slim",
    "--string",
]

SCAN_SMOKE_ARGS = [
    ["scan", "--string", "const aws = 'AKIA1234567890ABCDEF';"],
    ["scan", "--only-allowlisted", "--all-files", "fixtures/secrets"],
    ["scan", "--slim", "--all-files", "fixtures/secrets"],
    [
        "scan",
        "--base64-limit",
        "4.5",
        "--hex-limit",
        "3.0",
        "--disable-plugin",
        "AWSKeyDetector",
        "--all-files",
        "fixtures/secrets",
    ],
    [
        "scan",
        "--no-verify",
        "--exclude-lines",
        "github_token",
        "--exclude-files",
        "does-not-match",
        "--exclude-secrets",
        "ghp",
        "--all-files",
        "fixtures/secrets",
    ],
]


def main() -> int:
    run(["cargo", "build", "--quiet", "--locked"])

    rust_help = output([str(RUST_BIN), "scan", "--help"])
    upstream_help = output(upstream_command("scan", "--help"))

    missing = []
    for flag in IMPLEMENTED_SCAN_FLAGS:
        if flag not in rust_help:
            missing.append(f"rust help missing {flag}")
        if flag not in upstream_help:
            missing.append(f"upstream help missing {flag}")

    if missing:
        for item in missing:
            print(item, file=sys.stderr)
        return 1

    for args in SCAN_SMOKE_ARGS:
        run([str(RUST_BIN), *args], stdout=subprocess.DEVNULL)
        run(upstream_command(*args), stdout=subprocess.DEVNULL)

    print("cli parity ok")
    return 0


def upstream_command(*args: str) -> list[str]:
    return ["python3", "-m", "detect_secrets", *args]


def upstream_env() -> dict[str, str]:
    env = os.environ.copy()
    pythonpath = str(ROOT / "detect-secrets")
    if env.get("PYTHONPATH"):
        pythonpath = pythonpath + os.pathsep + env["PYTHONPATH"]
    env["PYTHONPATH"] = pythonpath
    return env


def run(
    command: list[str],
    *,
    stdout: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=upstream_env() if is_upstream_command(command) else None,
        stdout=stdout,
        check=True,
    )


def output(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=upstream_env() if is_upstream_command(command) else None,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def is_upstream_command(command: list[str]) -> bool:
    return len(command) >= 3 and command[:3] == ["python3", "-m", "detect_secrets"]


if __name__ == "__main__":
    raise SystemExit(main())
