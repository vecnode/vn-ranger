<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo/vn-ranger-white-512.png">
  <img src="assets/logo/vn-ranger-512.png" alt="vn-ranger" width="112">
</picture>

# vn-ranger

**A quiet ranger for your machine.**

[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-3fb950.svg)](LICENSE)
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
| [docs/PLAN-0.1.7.md](docs/PLAN-0.1.7.md) | The release: four new evidence domains, the feature catalogue, the waves and the size budget |
| [docs/NEXT.md](docs/NEXT.md) | The work order, and what is deliberately not in this release |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | What was measured, and what is still owed |
| [docs/RELEASES.md](docs/RELEASES.md) | The release contract that makes ranger installable by vn-launcher |
| [SECURITY.md](SECURITY.md) | What ranger protects, what it cannot, and how to report a flaw |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to send a change, the contributor licence agreement, and what a finished change has to prove |
| [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) | Every crate the build resolves, the licence each one keeps, and the typefaces embedded in the binary |
| [AGENTS.md](AGENTS.md) | The rules a change to this repository has to keep |
| [assets/logo/README.md](assets/logo/README.md) | The mark and every file in the set |
| [assets/logo/BRAND.md](assets/logo/BRAND.md) | Construction, clear space, contrast and usage |

## Security & license

- AGPL-3.0-only — see [LICENSE](LICENSE). Copyright (C) 2026 vecnode. The ranger is
  copyleft: you may run, study, change and share it, and a version you distribute or offer
  over a network must carry its source under the same license. That is deliberate —
  vn-ranger is not to become a closed product on somebody else's bench. A commercial
  exception is available on request; see [CONTRIBUTING.md](CONTRIBUTING.md) for the CLA
  that keeps that possible, and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for the
  crate tree and the typefaces that keep their own licenses (MIT, Apache-2.0, BSD, ISC,
  Zlib, Unicode-3.0, MPL-2.0, BSL-1.0, CC0-1.0 and OFL-1.1) and are not relicensed by this.
- [SECURITY.md](SECURITY.md): the threat model, the action path and the four refusals, the
  quarantine, the one-shot administrator scan, what the ranger deliberately does not do, and
  how `cargo xtask ci` keeps a network client out of the tree. Report a vulnerability
  privately, as described there.
- [docs/PLAN.md](docs/PLAN.md) is the deep dive; [docs/](docs/) holds the plan, the release
  contract, the rule vocabulary, the benchmarks and the per-release notes.

The mark is original vecnode work. The bundled typefaces are Inter and JetBrains Mono,
both under the SIL Open Font License 1.1; their licence texts and sources are in
[assets/fonts](assets/fonts), and every third-party term that travels with a build is in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
