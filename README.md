# detect-secrets-rs

Fast native Rust proof of concept for a practical clone of Yelp
[`detect-secrets`](https://github.com/Yelp/detect-secrets).

The current repository is intentionally in POC shape. The first target is the
scan hot path:

```bash
cargo run -- scan .
```

The implementation follows the project plan in `PLAN.md`: coverage-first
compatibility, no raw secrets in output, simple native detectors, deterministic
baseline-like JSON, and benchmark-driven scope decisions.

## Install

The first release is a `scan`-focused POC release, not full upstream
`detect-secrets` compatibility.

```bash
cargo install detect-secrets-rs --locked
npm install -g detect-secrets-rs
pip install detect-secrets-rs
```

The npm package is a small wrapper around platform-specific optional native
packages. The initial prebuilt package names are:

- `detect-secrets-rs-linux-x64`
- `detect-secrets-rs-linux-arm64`
- `detect-secrets-rs-darwin-x64`
- `detect-secrets-rs-darwin-arm64`
- `detect-secrets-rs-win`

Unsupported npm platforms should use the Cargo install path.

## POC Checks

Run the fast local POC gate:

```bash
scripts/poc-gate.sh
```

Run compatibility comparison against upstream `detect-secrets`:

```bash
scripts/compat.sh fixtures/secrets
scripts/compat.sh detect-secrets/test_data/each_secret.py
scripts/compat-matrix.sh
REAL=1 scripts/compat-matrix.sh
```

Run benchmark smoke checks:

```bash
RUNS=3 scripts/bench.sh fixtures/secrets
RUNS=3 scripts/bench.sh detect-secrets/detect_secrets
RUNS=1 scripts/bench.sh . --exclude-files '(^|/)(target|\.git|\.idea)/'
RUNS=3 scripts/public-bench-suite.sh
```

Local benchmarking tools are installed under `.tools/bin/`; for example,
`.tools/bin/hyperfine` is used for Rust-only optimization passes.

The upstream submodule in `detect-secrets/` is used as the executable
specification. Compatibility scripts disable upstream plugins outside the
current POC detector scope and fail on missing upstream findings; Rust-only
extra findings are reported separately.

`scripts/public-bench-suite.sh` pins its benchmark repositories to reviewed
commits and checks them out under `.bench/`.

## Release Checks

Run the local release gate before publishing:

```bash
scripts/release-gate.sh
FULL=1 scripts/release-gate.sh
```

`FULL=1` also runs the real compatibility matrix and public benchmark suite.
Release packaging is configured for:

- Cargo crate dry-run/publish;
- npm wrapper plus prebuilt optional packages;
- Python wheels via `maturin` binary bindings;
- GitHub Release binary archives and checksums.
