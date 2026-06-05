# detect-secrets-rs Plan

## Goal

Build a fast native Rust clone of Yelp
[`detect-secrets`](https://github.com/Yelp/detect-secrets).

The long-term goal is full practical compatibility with upstream
`detect-secrets`: baseline format, scan behavior, hook workflow, detector
coverage, filters, allowlisting, exit codes, and CI/pre-commit integration.

The first goal is smaller: build a performance POC and decide whether the Rust
clone is worth continuing.

## Phase 0: Performance POC

### Objective

Prove that a native Rust implementation can materially outperform upstream
`detect-secrets` on realistic repositories without missing common upstream
findings.

This phase is intentionally not a full MVP. It should answer one business
question:

> Is the performance improvement large enough to justify building the full
> compatible clone?

### POC Scope

Implement only the scan hot path needed for a fair benchmark:

- basic CLI entrypoint: `detect-secrets-rs scan [path ...]`
- recursive file discovery
- git-tracked file discovery where practical
- `--all-files`
- `--exclude-files`
- `--exclude-lines`
- `--exclude-secrets`
- `--disable-plugin`
- `--list-all-plugins`
- deterministic JSON baseline-like output
- no raw secret values in output
- enough baseline structure to compare against upstream results

Initial detectors:

- `KeywordDetector`
- `Base64HighEntropyString`
- `HexHighEntropyString`
- `AWSKeyDetector`
- `GitHubTokenDetector`
- `GitLabTokenDetector`
- `NpmDetector`
- `JwtTokenDetector`
- `PrivateKeyDetector`
- `SlackDetector`

Initial filters:

- binary/unreadable file skip
- file regex exclusions
- line regex exclusions
- secret regex exclusions
- inline allowlist:
  - `# pragma: allowlist secret`
  - `// pragma: allowlist secret`
  - `pragma: allowlist nextline secret`

### Explicit Non-Goals For POC

- no dynamic Python plugin loading
- no dynamic Python filter loading
- no interactive `audit`
- no online secret verification
- no full baseline upgrade logic
- no full `detect-secrets-hook` parity
- no git history scanning
- no custom plugin system
- no npm package or prebuilt binaries yet

These can matter later, but they should not block the speed decision.

## POC Compatibility Gate

Use upstream as the executable specification.

For the same repository and options:

- missing upstream findings are blockers;
- extra Rust findings are allowed during POC but must be reported separately;
- line-number differences are diagnostics unless they hide a missed secret;
- baseline JSON does not need to be byte-identical, but it must preserve the
  same meaningful finding identity.

Secret identity should be based on file path, secret type, hashed secret value,
and enough location context to debug differences. Do not use line number as the
only identity, because upstream explicitly treats line numbers as audit
navigation rather than stable identity.

## POC Benchmark Gate

Benchmark against upstream `detect-secrets` with pinned inputs.

Suggested benchmark cases:

- this repository itself;
- one large JavaScript/TypeScript repository;
- one large Python repository;
- one mixed-language repository with config files;
- one intentionally seeded fixture repository with known secrets.

Use `hyperfine` or an equivalent simple CLI-level benchmark.

Measure:

- upstream `detect-secrets scan`
- Rust `detect-secrets-rs scan`
- wall-clock time
- number of scanned files
- number of findings by type
- missing/extra finding counts

Continue to MVP only if:

- Rust is consistently and materially faster on realistic repositories;
- Rust does not miss common upstream findings in the POC detector set;
- the implementation remains small and understandable;
- no security concern appears around output, logging, or secret hashing.

As a rough decision threshold, aim for at least a 5x speedup on realistic scans.
If the speedup is closer to 1-2x, pause and re-evaluate before building more
compatibility.

## Recommended Rust Crates

Prefer mature crates and minimal custom code:

- CLI: `clap`
- JSON: `serde`, `serde_json`
- regex: `regex`; add `fancy-regex` only where upstream-compatible patterns
  require lookaround or backreferences
- keyword search: `aho-corasick`
- file walking: `ignore`, `globset`
- hashing: `sha2`
- parallelism: `rayon`
- git tracked files: start with `git ls-files -z` for KISS
- tests: `assert_cmd`, `assert_fs`, `tempfile`, `insta`
- benchmarks: `hyperfine`

## Implementation Shape

Keep the POC boring and direct:

1. parse CLI options;
2. resolve files;
3. compile detector/filter configuration once;
4. scan files in parallel;
5. collect findings;
6. sort deterministically;
7. emit baseline-like JSON;
8. compare against upstream in a separate harness.

Do not build abstractions for future plugin systems until the POC proves the
project is worth continuing.

## Security Rules

- Never print raw secrets unless an upstream-compatible command explicitly
  requires it.
- Never store raw secrets in generated baselines.
- Mask secret values in diagnostics.
- Keep verification/network checks out of the POC.
- Treat dynamic plugin/filter loading as security-sensitive and non-MVP.

## If POC Succeeds: MVP Direction

After the speed decision, move toward a real MVP:

- upstream `detect-secrets` submodule in `detect-secrets/`;
- full baseline-compatible output;
- `detect-secrets-hook` compatibility;
- baseline update with label preservation;
- common plugin/filter coverage;
- `--baseline`;
- `--slim`;
- `--string`;
- `--only-allowlisted`;
- `audit --stats`, `audit --report`, `audit --json`;
- public compatibility report;
- public benchmark report;
- Cargo/npm/PyPI install flow only after the CLI is stable.

## First Release Packaging Plan

The first public release should optimize for easy installation without adding
runtime compatibility promises beyond the documented `scan` scope.

Supported install paths:

- Cargo: `cargo install detect-secrets-rs --locked`.
- npm: `npm install -g detect-secrets-rs` / `npx detect-secrets-rs`.
- Python: `pip install detect-secrets-rs`, installing the CLI binary into the
  active environment path.
- GitHub Releases: archives and checksums for direct binary downloads.

### npm Package Layout

Follow the `jscpd-rs` prebuilt package pattern: one small main wrapper package
plus platform-specific optional packages. Do not use install-time native builds
or postinstall downloads for the default path.

Main package:

- `detect-secrets-rs`

Prebuilt optional packages:

- `detect-secrets-rs-linux-x64`
- `detect-secrets-rs-linux-arm64`
- `detect-secrets-rs-darwin-x64`
- `detect-secrets-rs-darwin-arm64`
- `detect-secrets-rs-win`

Keep npm package names short and simple enough to avoid registry/package spam
heuristics. In particular, do not publish a long Windows package name such as
`detect-secrets-rs-win32-x64-msvc`; use `detect-secrets-rs-win` and keep the
exact Rust target (`x86_64-pc-windows-msvc`) in package metadata and release
scripts.

Each prebuilt package should declare npm `os`, `cpu`, and, for Linux, `libc`
constraints. The main package should list all prebuilt packages in
`optionalDependencies`, select the matching package at runtime, and print a
clear Cargo fallback message on unsupported platforms.

The first Linux npm packages are glibc builds even though the package names omit
the `gnu` suffix. Keep the exact ABI in package metadata and release scripts; if
musl builds are added later, publish explicit `*-musl` packages.

Initial npm target matrix:

| Package | Rust target | Runner |
| --- | --- | --- |
| `detect-secrets-rs-linux-x64` | `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| `detect-secrets-rs-linux-arm64` | `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm` |
| `detect-secrets-rs-darwin-x64` | `x86_64-apple-darwin` | `macos-15-intel` |
| `detect-secrets-rs-darwin-arm64` | `aarch64-apple-darwin` | `macos-15` |
| `detect-secrets-rs-win` | `x86_64-pc-windows-msvc` | `windows-2025` |

Linux musl, Windows arm64, and extra package managers should wait for install
data or user reports.

### Python Package Layout

Use `maturin` with `bin` bindings for the first Python release. The Python
package should install the CLI binary, not expose a Python API yet. A native
Python API can be added later after the CLI and baseline contracts stabilize.

Build wheels for the same OS/architecture set as npm where practical. Linux
wheels must be manylinux/musllinux compatible. The source distribution should
build from Cargo for unsupported platforms.

### Release Gates

Before publishing `v0.1.0`:

- `scripts/poc-gate.sh` passes.
- `REAL=1 scripts/compat-matrix.sh` passes with `missing=0`.
- `RUNS=3 scripts/public-bench-suite.sh` shows no sustained speed regression.
- `cargo publish --dry-run --locked` passes.
- `npm pack` and `npm publish --dry-run --json` pass for the main package and
  every prebuilt optional package.
- Local npm install smoke passes for the main wrapper plus a generated platform
  package, with no install-time build scripts.
- `maturin build --release` produces installable wheels and `pip install`
  smoke passes from a clean virtual environment.
- GitHub Release archives, checksums, and package versions all match the same
  tag.

## Open Questions

- What exact detector set is enough for the first benchmark decision?
- Which public repositories should become the pinned benchmark suite?
- Should the binary be named only `detect-secrets-rs` first, or should it also
  expose `detect-secrets` after compatibility improves?
- How much baseline byte-level compatibility is necessary before publishing?
- Should online verification ever be implemented, or left to upstream/Python?
- Should prebuilt npm packages keep the full `detect-secrets-rs-*` prefix, or
  move to an even shorter prefix if npm registry checks flag the longer names?
