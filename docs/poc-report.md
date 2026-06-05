# POC Report

Date: 2026-06-05.

This is the current local performance POC baseline. It compares the native Rust
scan path against upstream `detect-secrets` from the `detect-secrets/`
submodule. Upstream is run with `--no-verify`, and plugins outside the current
POC detector scope are disabled.

## Compatibility

Default matrix:

```bash
scripts/compat-matrix.sh
```

The matrix covers:

- seeded fixture;
- upstream `test_data/each_secret.py`;
- `--exclude-lines`;
- `--exclude-secrets`;
- `--exclude-files`;
- `--disable-plugin` for entropy plugins.

Pinned real-repository compatibility can be included with:

```bash
REAL=1 scripts/compat-matrix.sh
```

Latest pinned real-repository matrix:

| Case | Rust findings | Upstream findings | Missing | Extra |
| --- | ---: | ---: | ---: | ---: |
| React | 172 | 9 | 0 | 87 |
| Django | 1593 | 259 | 0 | 486 |
| Prometheus | 14834 | 426 | 0 | 2357 |

```bash
scripts/compat.sh fixtures/secrets
```

Result:

- files: Rust 1, upstream 1
- findings: Rust 21, upstream 14
- missing upstream findings: 0
- extra Rust findings: 7

```bash
scripts/compat.sh detect-secrets/test_data/each_secret.py
```

Result:

- files: Rust 1, upstream 1
- findings: Rust 10, upstream 8
- missing upstream findings: 0
- extra Rust findings: 2

## Benchmark Smoke

| Case | Command | Rust avg | Upstream avg | Speedup |
| --- | --- | ---: | ---: | ---: |
| seeded fixture | `RUNS=3 scripts/bench.sh fixtures/secrets --exclude-files '(^|/)(\.git|target|node_modules|dist|build|\.next|__pycache__)/'` | 0.007185002s | 0.122396427s | 17.03x |
| React | `RUNS=3 scripts/bench.sh .bench/react --exclude-files '(^|/)(\.git|target|node_modules|dist|build|\.next|__pycache__)/'` | 0.073855916s | 4.386996701s | 59.40x |
| Django | `RUNS=3 scripts/bench.sh .bench/django --exclude-files '(^|/)(\.git|target|node_modules|dist|build|\.next|__pycache__)/'` | 0.094422353s | 5.503050590s | 58.28x |
| Prometheus | `RUNS=3 scripts/bench.sh .bench/prometheus --exclude-files '(^|/)(\.git|target|node_modules|dist|build|\.next|__pycache__)/'` | 0.109115900s | 18.790930492s | 172.21x |

Rust-only optimization trace from local `hyperfine`:

| Case | Before optimization | After optimization |
| --- | ---: | ---: |
| React | 86.7ms | 70.2ms |
| Django | 182.7ms | 94.6ms |
| Prometheus | 123.9ms | 106.8ms |

The public benchmark repositories can be reproduced with:

```bash
RUNS=3 scripts/public-bench-suite.sh
```

Pinned benchmark commits:

| Case | Repository | Commit |
| --- | --- | --- |
| React | `https://github.com/facebook/react.git` | `43bcbf80065a4913b6a4eb69f4e001165974f11b` |
| Django | `https://github.com/django/django.git` | `a2348c85fc6c20087935c74cd99340dd4ef2dcdc` |
| Prometheus | `https://github.com/prometheus/prometheus.git` | `afec04d3f547e8010608963993340ddfc5204e54` |

## Notes

This is still a local POC benchmark, not a publication-quality release report.
The next step is expanding the compatibility matrix with more upstream fixtures
and reducing Rust-only extra findings. The current result is enough to show
that the native scan path is materially faster on small, JavaScript/TypeScript,
Python, and mixed-language cases without missing upstream findings in the
current fixture and pinned real-repository scope.
