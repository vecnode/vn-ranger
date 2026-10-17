# Changelog

All notable changes to vn-ranger are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Release titles are `vn-ranger v<version>`. The published v0.1.1 release was retitled
  from `v0.1.1 — Professional interface` to `vn-ranger v0.1.1`, and the workflow now
  creates every release with that title.
- The roadmap is one theme per release: 0.1.2 watch, 0.1.3 explain, 0.1.4 act, 0.1.5
  resident, 0.1.6 rule packs, 0.2.0 distribution. `docs/PLAN.md` and `AGENTS.md` now
  agree on where signature verification and quarantine land.

## [0.1.1] - 2026-10-17

### Added

- Embedded Inter Regular, Inter SemiBold and JetBrains Mono; no system-font lookup.

### Changed

- Compact type scale: 13 px body, 21 px page title and 22 px maximum display number,
  with tighter chrome and full-width cards. Statistic and preview columns respond to
  the window width instead of overlapping.
- Processes, Startup and Listeners fill their tab with sticky-header tables, whole-row
  selection and a pinned, full-width detail footer for the selected process or startup
  item. Each view keeps its own scroll position.

## [0.1.0] - 2026-10-17

### Added

- The first working application: a Rust workspace with `vnr-core` (facts, signatures,
  reports), `vnr-native` (collectors, hashing, signatures, elevation), `vnr-ui`
  (egui 0.37) and the eframe shell.
- Read-only inventory on Windows, macOS and Linux: processes and ancestry, startup
  items, listening sockets (Windows and Linux) and installed packages. Every collector
  reports what it could not see.
- A clean-room ClamAV `.hdb` / `.hsb` hash-signature reader, MD5/SHA-1/SHA-256 matching,
  and an in-memory EICAR self-test that still works when another antivirus removes the
  test file.
- An opt-in, one-shot administrator scan on Windows: the unelevated window asks, the
  operating system prompts, a second copy writes one snapshot and exits.
- The interface: Overview, Processes, Startup, Listeners, Report and Settings; search;
  JSON and Markdown export; the suite mark in the title bar and rail; ink-on-ember
  buttons that meet WCAG AA.
- The designer record: `assets/logo/BRAND.md`, `MANIFEST.toml` with every digest, and
  the contact sheet.
- The plan, the release contract, the security policy, the agent guide and CI.

### Known limitations

- Read-only. No rules, findings, quarantine, cleaning or tray.
- Signature verification (WinVerifyTrust, `codesign`) is not implemented; ranger
  reports hashes, not trust.
- macOS listeners are unavailable without a C build dependency; scheduled tasks, macOS
  login items, MSIX, Snap and Flatpak packages are not listed yet.
- No code signing. `SHA256SUMS.txt` is the only integrity statement.
- vn-launcher cannot install the release until its own install path ships; ranger is
  built to the contract now.

[Unreleased]: https://github.com/vecnode/vn-ranger/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.1
[0.1.0]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.0
