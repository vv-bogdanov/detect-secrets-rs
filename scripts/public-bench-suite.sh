#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-3}"
EXCLUDE_PATTERN="${EXCLUDE_PATTERN:-(^|/)(\\.git|target|node_modules|dist|build|\\.next|__pycache__)/}"

REACT_SHA="${REACT_SHA:-43bcbf80065a4913b6a4eb69f4e001165974f11b}"
DJANGO_SHA="${DJANGO_SHA:-a2348c85fc6c20087935c74cd99340dd4ef2dcdc}"
PROMETHEUS_SHA="${PROMETHEUS_SHA:-afec04d3f547e8010608963993340ddfc5204e54}"

prepare_repo() {
  local url="$1"
  local dir="$2"
  local sha="$3"

  if [[ -d "$dir/.git" ]]; then
    printf 'using existing %s\n' "$dir"
  else
    git clone --depth 1 "$url" "$dir"
  fi

  if ! git -C "$dir" cat-file -e "$sha^{commit}" 2>/dev/null; then
    git -C "$dir" fetch --depth 1 origin "$sha"
  fi
  git -C "$dir" checkout --quiet --detach "$sha"
  printf '%s pinned to %s\n' "$dir" "$sha"
}

cd "$ROOT"
mkdir -p .bench

prepare_repo https://github.com/facebook/react.git .bench/react "$REACT_SHA"
prepare_repo https://github.com/django/django.git .bench/django "$DJANGO_SHA"
prepare_repo https://github.com/prometheus/prometheus.git .bench/prometheus "$PROMETHEUS_SHA"

if [[ "${PREPARE_ONLY:-0}" == "1" ]]; then
  exit 0
fi

RUNS="$RUNS" scripts/bench.sh .bench/react --exclude-files "$EXCLUDE_PATTERN"
RUNS="$RUNS" scripts/bench.sh .bench/django --exclude-files "$EXCLUDE_PATTERN"
RUNS="$RUNS" scripts/bench.sh .bench/prometheus --exclude-files "$EXCLUDE_PATTERN"
