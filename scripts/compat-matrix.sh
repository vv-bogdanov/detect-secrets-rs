#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXCLUDE_PATTERN="${EXCLUDE_PATTERN:-(^|/)(\\.git|target|node_modules|dist|build|\\.next|__pycache__)/}"

cd "$ROOT"

run_case() {
  local name="$1"
  local target="$2"
  shift 2

  printf '\n== %s ==\n' "$name"
  scripts/compat.sh "$target" "$@"
}

run_case "seeded fixture" fixtures/secrets
run_case "upstream each_secret" detect-secrets/test_data/each_secret.py
run_case "seeded exclude-lines" fixtures/secrets --exclude-lines "github_token|gitlab_token"
run_case "seeded exclude-secrets" fixtures/secrets --exclude-secrets "ghp|glpat|xoxp"
run_case "seeded disable entropy" fixtures/secrets \
  --disable-plugin Base64HighEntropyString \
  --disable-plugin HexHighEntropyString
run_case "seeded exclude-files" fixtures/secrets --exclude-files "poc\\.py$"

if [[ "${REAL:-0}" == "1" ]]; then
  PREPARE_ONLY=1 scripts/public-bench-suite.sh >/dev/null
  run_case "real react" .bench/react --exclude-files "$EXCLUDE_PATTERN"
  run_case "real django" .bench/django --exclude-files "$EXCLUDE_PATTERN"
  run_case "real prometheus" .bench/prometheus --exclude-files "$EXCLUDE_PATTERN"
else
  printf '\nSkipping real repository compatibility. Run REAL=1 scripts/compat-matrix.sh to include pinned benchmark repos.\n'
fi
