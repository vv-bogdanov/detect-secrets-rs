#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT/target/python-smoke"
BUILD_VENV="$WORK_DIR/build-venv"
INSTALL_VENV="$WORK_DIR/install-venv"
WHEEL_DIR="$WORK_DIR/wheels"

if [[ -z "${PYTHON:-}" ]]; then
  for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
      "$candidate" -m ensurepip --version >/dev/null 2>&1; then
      PYTHON="$candidate"
      break
    fi
  done
fi

if [[ -z "${PYTHON:-}" ]]; then
  echo "python-smoke: no Python with ensurepip/venv support found" >&2
  exit 1
fi

rm -rf "$WORK_DIR"
mkdir -p "$WHEEL_DIR"

"$PYTHON" -m venv "$BUILD_VENV"
"$BUILD_VENV/bin/python" -m pip install --upgrade pip
"$BUILD_VENV/bin/python" -m pip install 'maturin>=1.9,<2'
"$BUILD_VENV/bin/python" -m maturin build --release --locked --out "$WHEEL_DIR"
"$BUILD_VENV/bin/python" -m maturin sdist --out "$WHEEL_DIR"

"$PYTHON" -m venv "$INSTALL_VENV"
"$INSTALL_VENV/bin/python" -m pip install --upgrade pip
"$INSTALL_VENV/bin/python" -m pip install "$WHEEL_DIR"/*.whl
"$INSTALL_VENV/bin/detect-secrets-rs" scan --list-all-plugins >/dev/null

echo "python smoke passed"
