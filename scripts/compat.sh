#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_PATH="${1:-fixtures/secrets}"
if (($# > 0)); then
  shift
fi
EXTRA_ARGS=("$@")
TMP_ROOT="${TMP_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/detect-secrets-rs-compat.XXXXXX")}"
RUST_OUT="$TMP_ROOT/rust.json"
UPSTREAM_OUT="$TMP_ROOT/upstream.json"

mkdir -p "$TMP_ROOT"

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    rm -rf "$TMP_ROOT"
  fi
}
trap cleanup EXIT

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

"$ROOT/target/release/detect-secrets-rs" "${common_args[@]}" >"$RUST_OUT"
PYTHONPATH="$ROOT/detect-secrets" python3 -m detect_secrets "${common_args[@]}" >"$UPSTREAM_OUT"

python3 "$ROOT/scripts/compare-baselines.py" "$RUST_OUT" "$UPSTREAM_OUT"

if [[ "${KEEP:-0}" == "1" ]]; then
  printf '\nrust report: %s\n' "$RUST_OUT"
  printf 'upstream report: %s\n' "$UPSTREAM_OUT"
fi
