#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_PATH="${1:-fixtures/secrets}"
RUNS="${RUNS:-5}"
if (($# > 0)); then
  shift
fi
EXTRA_ARGS=("$@")

DISABLE_UNSCOPED_PLUGINS=(
  ArtifactoryDetector
  AzureStorageKeyDetector
  BasicAuthDetector
  CloudantDetector
  DiscordBotTokenDetector
  IbmCloudIamDetector
  IbmCosHmacDetector
  IPPublicDetector
  MailchimpDetector
  OpenAIDetector
  PypiTokenDetector
  SendGridDetector
  SoftlayerDetector
  SquareOAuthDetector
  StripeDetector
  TelegramBotTokenDetector
  TwilioKeyDetector
)

common_args=(scan --all-files --no-verify)
for plugin in "${DISABLE_UNSCOPED_PLUGINS[@]}"; do
  common_args+=(--disable-plugin "$plugin")
done
common_args+=("${EXTRA_ARGS[@]}" "$TARGET_PATH")

cd "$ROOT"
cargo build --release --bin detect-secrets-rs >/dev/null

rust_cmd=("$ROOT/target/release/detect-secrets-rs" "${common_args[@]}")
upstream_cmd=(env "PYTHONPATH=$ROOT/detect-secrets" python3 -m detect_secrets "${common_args[@]}")

measure() {
  local label="$1"
  shift
  local total_ns=0
  local run start_ns end_ns elapsed_ns

  printf '%s\n' "$label"
  for run in $(seq 1 "$RUNS"); do
    start_ns="$(date +%s%N)"
    "$@" >/dev/null
    end_ns="$(date +%s%N)"
    elapsed_ns=$((end_ns - start_ns))
    total_ns=$((total_ns + elapsed_ns))
    awk -v run="$run" -v ns="$elapsed_ns" 'BEGIN { printf "  run %s: %.6fs\n", run, ns / 1000000000 }'
  done
  awk -v ns="$total_ns" -v runs="$RUNS" 'BEGIN { printf "%.9f\n", ns / runs / 1000000000 }'
}

printf 'target: %s\n' "$TARGET_PATH"
printf 'runs: %s\n\n' "$RUNS"

rust_avg="$(measure "rust" "${rust_cmd[@]}" | tee /dev/stderr | tail -n 1)"
printf '\n' >&2
upstream_avg="$(measure "upstream" "${upstream_cmd[@]}" | tee /dev/stderr | tail -n 1)"

awk -v rust="$rust_avg" -v upstream="$upstream_avg" \
  'BEGIN { printf "\nspeedup: %.2fx\n", upstream / rust }'
