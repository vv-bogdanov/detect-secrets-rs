#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

scripts/poc-gate.sh
cargo publish --dry-run --locked
npm run npm:smoke
scripts/python-smoke.sh

if [[ "${FULL:-0}" == "1" ]]; then
  REAL=1 scripts/compat-matrix.sh
  RUNS="${RUNS:-3}" scripts/public-bench-suite.sh
fi
