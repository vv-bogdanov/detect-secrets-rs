#!/usr/bin/env python3
"""Compare Rust and upstream detect-secrets baselines without raw secrets."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: compare-baselines.py <rust.json> <upstream.json>", file=sys.stderr)
        return 2

    rust = read_json(Path(sys.argv[1]))
    upstream = read_json(Path(sys.argv[2]))

    rust_findings = flatten(rust)
    upstream_findings = flatten(upstream)
    rust_keys = {identity(finding) for finding in rust_findings}
    upstream_keys = {identity(finding) for finding in upstream_findings}

    missing = sorted(upstream_keys - rust_keys)
    extra = sorted(rust_keys - upstream_keys)

    print_metric("files", len(results(rust)), len(results(upstream)))
    print_metric("findings", len(rust_findings), len(upstream_findings))
    print_metric("missing", len(missing), 0)
    print_metric("extra", len(extra), 0)

    print_sample("missing upstream findings", missing)
    print_sample("extra rust findings", extra)

    strict = os.environ.get("STRICT", "missing")
    if strict in {"1", "missing", "coverage", "coverage-first"} and missing:
        print(f"compat comparison failed: missing upstream findings: {len(missing)}", file=sys.stderr)
        return 1

    return 0


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def results(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    value = report.get("results")
    return value if isinstance(value, dict) else {}


def flatten(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for filename, items in results(report).items():
        for item in items:
            if isinstance(item, dict):
                finding = dict(item)
                finding.setdefault("filename", filename)
                findings.append(finding)
    return findings


def identity(finding: dict[str, Any]) -> str:
    filename = normalize_filename(str(finding.get("filename", "")))
    secret_type = str(finding.get("type", ""))
    hashed_secret = str(finding.get("hashed_secret", ""))
    return f"{filename}\t{secret_type}\t{hashed_secret}"


def normalize_filename(filename: str) -> str:
    return filename.replace("\\", "/").lstrip("./")


def print_metric(name: str, rust: int, upstream: int) -> None:
    delta = rust - upstream
    print(f"{name:<10} rust={rust:>5} upstream={upstream:>5} delta={delta:>+5}")


def print_sample(label: str, values: list[str], limit: int = 10) -> None:
    if not values:
        return

    print(f"\n{label}:")
    for value in values[:limit]:
        filename, secret_type, hashed_secret = value.split("\t", 2)
        print(f"  {filename}: {secret_type} {hashed_secret[:12]}...")
    if len(values) > limit:
        print(f"  ... {len(values) - limit} more")


if __name__ == "__main__":
    raise SystemExit(main())
