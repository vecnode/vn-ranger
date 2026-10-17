# Changelog

All notable changes to vn-ranger are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5] - 2026-10-17

### Added

- A command palette with global search (Ctrl+K) over views, processes, startup items,
  findings and the common actions; the arrow keys move, Enter runs a row.
- Keyboard navigation: j/k and the arrow keys move the selected process or startup row,
  and Esc clears it.
- Filters and sorting on the process table (name, pid, user, started; listening, no
  path, temporary or download folders), startup (scope, disabled items), findings
  (severity, text, sort) and the Changes view (source, clear).
- A baseline card on the overview, findings in the Markdown report, and findings as
  JSON.
- Extra watched folders, with the watcher restarted when the list changes.
- Cancelling a scan between collectors.
- Preferences in settings.json, and a single-instance guard that refuses a second
  window and does not save from it.
- An error is a dismissible top-right notice instead of red text under every view.

### Changed

- An atomic save retries a transient access or sharing denial three times.
- The scan-completion message and the report's "What this report is not" card are gone.
## [0.1.4] - 2026-10-17

### Added

- Fifteen built-in rules over the collected facts: startup items in temporary, Downloads
  or Desktop folders, script startup entries, bare commands, shell interpreters,
  machine-wide entries pointing into a user folder, startup binaries that changed since
  the baseline, startup entries new since the baseline, processes running from temporary
  or download locations, processes whose parent exited, recently started public
  listeners, public sockets with no visible owner, persistent programs waiting for
  connections, and duplicate startup commands.
- A Findings view: every finding carries the evidence it fired on, why it matters, the
  most likely benign explanation and what to do. The overview summarises the counts, and
  a new finding appears in the session timeline.
- Suppressions: scoped to one rule and one subject, carrying a reason, expiring after 30
  days, saved in `suppressions.json`. Settings shows the count and can clear them.
- `Finding`, `Severity`, `Confidence`, `Suppression` and `evaluate` in `vnr-core`, with a
  positive and a negative fixture per rule.

### Not in this release

- Signature verification. No safe wrapper meets the dependency rules, so it waits for
  0.2.0 rather than breaking `unsafe_code = "forbid"`.
- Scheduled tasks, macOS login items, MSIX, Snap and Flatpak remain named gaps in the
  platform matrix.

## [0.1.3] - 2026-10-17

### Fixed

- Process identity on Linux and macOS. The start time was derived as `now - run_time`,
  which wobbles by a second between polls on those platforms, so the two-second poll
  reported every process as new and gone on every poll. It now uses the start time
  sysinfo stores when the process is first loaded. The v0.1.2 Windows build was not
  affected; the v0.1.2 release is superseded by this one on Linux and macOS.

## [0.1.2] - 2026-10-17

### Added

- A two-second process poll. New, gone and replaced processes are recorded; a reused pid
  with a different start time is a new process, not a changed one.
- File watchers on Downloads, Desktop, the temporary directory and the user's startup
  folders, with a 500 ms debounce and the existing 64 MB hash cap.
- An explicit baseline (`baseline.json`) that only a person accepts, and a diff of the
  latest scan against it.
- A Changes view: the session timeline and the baseline diff, with empty states that
  name what was checked.
- Switches for the poll and the watcher in Settings. They last for the session.
- A live poll indicator in the top bar that steps as each poll arrives; Settings can
  hide it.
- An About window from the circle in the top bar, showing the project page as selectable
  text. Ranger does not open a browser and fetches nothing.
- The interface, the window title and the About line report 0.1.2.

### Changed

- Release titles are `vn-ranger v<version>`. The published v0.1.1 release was retitled
  from `v0.1.1 — Professional interface` to `vn-ranger v0.1.1`, and the workflow now
  creates every release with that title.
- The roadmap is one theme per release: 0.1.2 watch, 0.1.3 explain, 0.1.4 act, 0.1.5
  resident, 0.1.6 rule packs, 0.2.0 distribution. `docs/PLAN.md` and `AGENTS.md` now
  agree on where signature verification and quarantine land.
- The dependency allowlist admits CC0-1.0 for `notify` alone, with the macOS build using
  kqueue rather than `fsevent-sys`.

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

[Unreleased]: https://github.com/vecnode/vn-ranger/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.5
[0.1.4]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.4
[0.1.3]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.3
[0.1.2]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.2
[0.1.1]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.1
[0.1.0]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.0
