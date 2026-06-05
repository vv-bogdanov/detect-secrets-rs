#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
scripts/compat-matrix.sh
RUNS="${RUNS:-1}" scripts/bench.sh fixtures/secrets
