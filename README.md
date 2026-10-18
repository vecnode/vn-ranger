<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo/vn-ranger-white-512.png">
  <img src="assets/logo/vn-ranger-512.png" alt="vn-ranger" width="112">
</picture>

# vn-ranger

**A quiet ranger for your machine.**

[![License: MIT](https://img.shields.io/badge/license-MIT-3fb950.svg)](LICENSE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-dea584.svg?logo=rust&logoColor=white)](#build)
[![Edition 2024](https://img.shields.io/badge/edition-2024-dea584.svg)](#build)
[![egui 0.37](https://img.shields.io/badge/UI-egui%200.37-8b5cf6.svg)](https://github.com/emilk/egui)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-4c8dff.svg)](docs/PLAN.md#7-platform-matrix)
[![Telemetry: none](https://img.shields.io/badge/telemetry-none-f26a21.svg)](docs/PLAN.md#13-privacy-and-data)

</div>


## Build

The workspace uses the same commands as vn-launcher:

```bash
cargo run --release              # build and run the ranger
cargo build --release            # build it without running it

cargo run --release -- --report report.json   # scan without a window

cargo xtask ci                   # formatting, lints and tests — exactly what CI runs
cargo xtask fmt-fix              # apply formatting
cargo xtask lint                 # clippy over the workspace, warnings denied
cargo xtask test                 # the test suite
```

## Documentation

| Document | What it answers |
|---|---|
| [docs/PLAN.md](docs/PLAN.md) | The research, the scope, the architecture and the roadmap |
| [docs/PLAN-0.1.7.md](docs/PLAN-0.1.7.md) | The next release: four new evidence domains, the feature catalogue, the waves and the size budget |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | What was measured, and what is still owed |
| [docs/RELEASES.md](docs/RELEASES.md) | The release contract that makes ranger installable by vn-launcher |
| [SECURITY.md](SECURITY.md) | What ranger protects, what it cannot, and how to report a flaw |
| [AGENTS.md](AGENTS.md) | The rules a change to this repository has to keep |
| [assets/logo/README.md](assets/logo/README.md) | The mark and every file in the set |
| [assets/logo/BRAND.md](assets/logo/BRAND.md) | Construction, clear space, contrast and usage |

## Licence

MIT — see [LICENSE](LICENSE). The mark is original vecnode work.

The bundled typefaces are Inter and JetBrains Mono, both under the SIL Open Font
License 1.1; their licence texts and sources are in [assets/fonts](assets/fonts).
