<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/logo/vn-ranger-white-512.png">
  <img src="assets/logo/vn-ranger-512.png" alt="vn-ranger" width="112">
</picture>

# vn-ranger

**A quiet ranger for the machine.** See what runs, what persists, and what changed.

vn-ranger is a resident, local-only system ranger for Windows, macOS and Linux. It
inventories the processes, startup items, listeners and autonomous agents on a
computer, explains every finding with the evidence behind it, and keeps a baseline so
that a change is something you can see rather than something you have to guess at.

It is part of the vecnode/vn suite, built with the same Rust and egui stack as
[vn-launcher](https://github.com/vecnode/vn-launcher), released under the same
convention, and installable by it. The crystal is the suite's mark; the ember inside
it is ranger's.

[![License: MIT](https://img.shields.io/badge/license-MIT-3fb950.svg)](LICENSE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-dea584.svg?logo=rust&logoColor=white)](#build)
[![Edition 2024](https://img.shields.io/badge/edition-2024-dea584.svg)](#build)
[![egui 0.37](https://img.shields.io/badge/UI-egui%200.37-8b5cf6.svg)](https://github.com/emilk/egui)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-4c8dff.svg)](docs/PLAN.md#7-platform-matrix)
[![Telemetry: none](https://img.shields.io/badge/telemetry-none-f26a21.svg)](docs/PLAN.md#13-privacy-and-data)

</div>

---

> **Status — plan.** This repository contains the mark, the licence and the plan.
> There is no binary yet. The first release, v0.1.0, is the read-only inventory
> described in [docs/PLAN.md](docs/PLAN.md). The release contract follows
> vn-launcher's convention; the launcher's own install path is still landing, so
> ranger is built to the contract from day one. Nothing here claims a detection it
> cannot explain.

## What it is for

- **See.** Processes and their ancestry, what starts on its own, what is listening,
  what is installed — and the agents, MCP servers and local model runners that now sit
  in that list.
- **Explain.** Every finding carries its subject, the observation that produced it, the
  rule that fired, and what the finding does *not* mean. No score without a reason.
- **Remember.** A baseline of what was true on a good day. Later checks report the
  difference, not a vague "threat found".
- **Act.** Quarantine and cleanup arrive in v0.3.0: previewed first, journalled,
  reversible. Never in the background, never silently.

## What it will never do

- **No telemetry, no account, no network.** The v0.1 binary will link no HTTP client
  at all, and CI will fail if one appears in the dependency tree. Nothing about the
  machine leaves it.
- **No root, no kernel driver, no hidden service.** Ranger runs with the user's
  permissions and says what it cannot see without elevation instead of guessing.
- **No silent deletion, no registry cleaning, no "boost".** Every action is previewed
  and reversible; the snake-oil half of this category is out of scope on purpose.
- **No paywall, no ads, no upsell.** MIT, free forever.

## Build

The Rust workspace lands with v0.1.0. It will use the same commands as vn-launcher:

```bash
cargo run --release              # build and run the ranger
cargo build --release            # build it without running it

cargo xtask ci                   # formatting, lints and tests — exactly what CI runs
cargo xtask fmt-fix              # apply formatting
cargo xtask lint                 # clippy over the workspace, warnings denied
cargo xtask test                 # the test suite
```

There is nothing to build yet, and this README does not pretend otherwise.

## Repository layout

The workspace is planned; this is the shape it will take at v0.1.0.

```text
crates/
  core      vnr-core     pure: facts, findings, rules, diffs, evidence, reports
  native    vnr-native   desktop: collectors, storage, quarantine and cleanup
  ui        vnr-ui       egui: theme, fonts, icons, widgets, the five views
apps/
  vn-ranger              the eframe shell: worker, scheduler and tray
xtask/                   cargo xtask ci | fmt | lint | test | version
assets/
  logo/                  the mark, its rendered set and the colour rule
  rules/                 the built-in rules that ship (from v0.2.0)
docs/                    PLAN, RELEASES
```

## Documentation

| Document | What it answers |
|---|---|
| [docs/PLAN.md](docs/PLAN.md) | The research, the scope, the architecture and the roadmap |
| [docs/RELEASES.md](docs/RELEASES.md) | The release contract that makes ranger installable by vn-launcher |
| [SECURITY.md](SECURITY.md) | What ranger protects, what it cannot, and how to report a flaw |
| [AGENTS.md](AGENTS.md) | The rules a change to this repository has to keep |
| [assets/logo/README.md](assets/logo/README.md) | The mark, the suite's colour rule, and every file |

## Prior art

Ranger is not the first tool to do any of this, and it does not pretend to be. It takes
its shape from [osquery](https://github.com/osquery/osquery) (facts, not verdicts), its
caution from [ClamAV](https://github.com/Cisco-Talos/clamav) (signatures are a separate,
licensed layer), its interface lesson from [Czkawka](https://github.com/qarmin/czkawka)
(preview before you delete), its persistence model from
[Sysinternals Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns) and
[KnockKnock](https://github.com/objective-see/KnockKnock), and its confidence from
[Lynis](https://github.com/CISOfy/lynis) (an audit says what it checked). The full
comparison, with licences and what was deliberately not borrowed, is in
[docs/PLAN.md](docs/PLAN.md#3-prior-art).

## Licence

MIT — see [LICENSE](LICENSE). The mark is original vecnode work and shares the crystal
geometry of vn-launcher; the ember inlay is ranger's. No third-party fonts, images or
code are bundled.
