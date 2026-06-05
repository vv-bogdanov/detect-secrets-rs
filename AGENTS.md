# AGENTS.md

## Project Goal

This project is a high-performance Rust clone of
[`detect-secrets`](https://github.com/Yelp/detect-secrets).

The long-term goal is full practical compatibility with upstream
`detect-secrets`: command-line behavior, baseline formats, supported detectors,
filters, inline allowlisting, hook workflows, audit workflows, exit codes, and
CI/pre-commit integrations should match the reference implementation unless a
deliberate incompatibility is documented.

The immediate goal is a performance POC. Before building a full MVP, prove that
a native Rust implementation can materially outperform upstream on realistic
repositories while preserving the important finding coverage.

Follow `PLAN.md` for the current POC scope, non-goals, benchmark gate, and
MVP direction.

## Upstream Reference

Treat upstream `detect-secrets` as the executable specification.

When compatibility work begins, keep the upstream repository in `detect-secrets/`
as a git submodule and compare behavior against it for CLI flags, baseline
shape, detector output, filters, allowlisting, hook behavior, and audit
semantics.

## Compatibility Policy

The primary compatibility gate is coverage-first parity: on the same inputs and
options, this Rust clone must not miss secrets reported by upstream
`detect-secrets` for the detector/filter set currently in scope.

Additional findings reported only by the Rust implementation are allowed while
the project is converging, but they must remain visible in compatibility reports
as `extra` findings.

Exact byte-for-byte baseline parity is useful, but it is not the first blocking
gate. Missing upstream findings are blockers. Extra findings are follow-up
compatibility work unless they reveal a clear false-positive regression.

Secret identity must not depend only on line number. Line numbers are useful for
audit navigation, but code moves. Prefer file path, secret type, hashed secret
value, and stable context when comparing results.

## Security Policy

- Never print raw secrets unless a specific upstream-compatible command
  explicitly requires it.
- Never store raw secrets in generated baselines.
- Mask secret values in diagnostics, logs, and test failure output.
- Keep online verification opt-in, timeout-bound, and separate from the core
  scan path.
- Treat dynamic plugin/filter loading as security-sensitive. Do not implement
  dynamic Python loading in the POC.
- Do not send generic or unknown secrets to external services.

## Engineering Principles

- Optimize for business value: faster development, reliable releases, simpler
  maintenance, stronger security posture, and lower CI/compute cost. Code is a
  cost, not the product goal.
- Prefer the minimum sufficient change that solves the current problem and is
  easy to read, test, and change. Avoid future-proofing until a real workflow
  needs it.
- Build a fast Rust implementation first: performance is a core product goal,
  not an afterthought.
- Do not accept simplification, refactoring, or compatibility work that causes a
  sustained speed regression on the benchmark suite. If a change touches file
  discovery, filters, detectors, hashing, output, or hook behavior, rerun the
  relevant benchmark case.
- Prefer battle-tested crates over custom code. Keep project-specific logic as
  small as practical.
- Keep it simple. Use KISS: straightforward data flow, small modules, and
  minimal abstraction until real complexity requires it.
- Use SOTA libraries and algorithms where they materially improve correctness,
  performance, maintainability, security, or ecosystem compatibility.
- Match upstream behavior before improving it. Optimizations must not silently
  change user-visible semantics.
- Avoid rewriting mature infrastructure from scratch: prefer existing crates for
  CLI parsing, JSON, regex/search, globbing, ignore files, file discovery,
  serialization, concurrency, diagnostics, and testing.
- Keep dependencies intentional: choose widely used, maintained crates with
  clear APIs and acceptable compile-time/runtime costs.
- Before and after edits, check whether the diff can be smaller, simpler, or
  replaced by an existing mature tool without reducing clarity or safety.
- Add focused compatibility tests as features are ported. Prefer fixtures based
  on upstream behavior.
- Put black-box behavior tests that use the public CLI/API in `tests/`. Keep
  small private-helper tests next to the module they protect.
- Document intentional deviations from upstream in the relevant code, tests, or
  project documentation.

## POC Rules

During the POC, focus only on proving speed and basic finding coverage.

Do implement:

- `detect-secrets-rs scan [path ...]`
- recursive and git-tracked file discovery
- `--all-files`
- `--exclude-files`
- `--exclude-lines`
- `--exclude-secrets`
- `--disable-plugin`
- `--list-all-plugins`
- deterministic baseline-like JSON output
- a small high-value detector set
- inline allowlisting
- upstream-vs-Rust comparison harness
- CLI-level benchmarks

Do not implement yet:

- dynamic Python plugin loading
- dynamic Python filter loading
- interactive `audit`
- online verification
- full baseline upgrade logic
- full `detect-secrets-hook` parity
- package publication
- large extension/plugin architecture

If the POC does not show a meaningful speedup, pause and re-evaluate before
adding more compatibility surface.
