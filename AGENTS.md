# AGENTS.md — guide for contributors and AI agents

vn-ranger is a resident, local-only system ranger: it inventories what runs on a
machine, explains what is unusual, remembers a baseline, and — later, and carefully —
quarantines and cleans. It is written in **Rust only**: a native egui/eframe
application, with **no Tauri, Electron, webview or JavaScript build step**.

**Status:** v0.1.6 is code-complete and its release candidate is published; v0.1.7 is the
next line, and its plan is [`docs/PLAN-0.1.7.md`](docs/PLAN-0.1.7.md), which supersedes the
M6 milestone in `docs/PLAN.md` §9. The read-only inventory, the local hash signature
engine, the one-shot administrator scan,
the two-second process poll, the file watchers, the accepted baseline, fifteen rules, the
Findings view, the command palette and keyboard navigation work, with preferences saved
and one window per data directory.

What 0.1.6 adds, and what this file is the contract for: the journal and the typed
action API, quarantine and allowlisted cleaning, the tray with opt-in autostart and a
scheduler, and signed rule packs with an optional content scan. Quarantine is the
project's first destructive capability, so §2 "Never delete" is written as an
architecture rather than as a promise.

**0.1.7 adds four evidence domains and no new privilege:** the bytes of a file (extended
body signatures, containers, structural and signature facts), the record of an event (the
operating system's own logs, read as files), the flow of a connection (the connection
table with process ownership, never a packet), and the configuration of an autonomous
agent (a capability matrix and provenance). It adds no network call, no kernel component
and no score, and every new destructive verb still goes through the one typed action path.

**0.1.7 also starts acting, in user scope.** The owner's decision of 2026-10-20 makes adding
and removing a startup entry the first destructive verb since quarantine: `HKCU` run keys
and the user's Startup folder, identified by the `AutorunFact` the scan produced rather than
by a path, journalled before the act, with the previous value kept so it can be put back. A
machine-scope entry is refused, because removing it needs an administrator and there is no
standing elevation — so "no new privilege" is still true, and the §2 order (journal, act,
result) is what makes the verb admissible at all.

`docs/PLAN.md` explains the research, the scope and the architecture.
`docs/RELEASES.md` is the distribution contract. `SECURITY.md` is the promise to the
person running it.

## 1. Workspace map

```text
crates/
  core      vnr-core     pure and IO-free: facts, snapshots, timelines, diffs, rules,
                         findings, hash signatures, reports, time arithmetic,
                         journal records, recovery verdicts, pack schema and matcher,
                         the allowlist table and its refusals (`action.rs`), the field
                         vocabulary and the pack schema (`fields.rs`, `pack/`),
                         schedule arithmetic
  native    vnr-native   the only crate that touches the world:
                         collect/{processes,autoruns,listeners,packages,tasks,agentstack},
                         hash, signatures, elevation, paths, store, watch, scan,
                         journal, act, action, quarantine, clean, pack, tray, autostart
  ui        vnr-ui       egui: theme, fonts, icons, widgets, the views, World/Action,
                         and the clean card's selection state
apps/
  vn-ranger              the eframe shell: owns the World, runs the worker,
                         scheduler and tray, carries out actions, and the headless
                         report and soak modes
xtask/                   cargo xtask ci | fmt-fix | lint | test | check | language | version
assets/
  logo/                  the mark, BRAND.md, MANIFEST.toml, contact sheet
  fonts/                 Inter and JetBrains Mono, OFL texts, type notes
  screenshots/           the picture the README uses
packs/                   the first-party rule pack, signed like any other (from 0.1.6)
docs/                    PLAN, PLAN-0.1.7, RELEASES, BENCHMARKS and RULES
```

**Layering is a rule, not a suggestion.**

- `vnr-core` depends on nothing in the workspace and must never gain a filesystem,
  network, clock or OS dependency. "Now" is a parameter; every decision is a pure
  function with a test beside it.
- `vnr-native` may use `vnr-core`. It is the only crate that reads the machine or
  writes to it.
- `vnr-ui` may use `vnr-core`. It must not do IO, read a config file or spawn a
  process — it draws a `World` and returns `Action`s.
- Only `apps/vn-ranger` opens a window, and only it knows about all three.

If a change makes `vnr-core` need to know what time it is, or makes `vnr-ui` want to
read a file, the change is in the wrong place.

## 2. Golden rules

### Never crash (this outranks feature work)

A missing OS API, a hand-edited signature line, a truncated plist, a process that exits
between enumeration and inspection, or a full disk must produce an outcome a person can
act on — never a panic.

- Non-test code never panics. No `unwrap()`, `expect()`, `panic!`, `unreachable!`,
  `todo!` or `unimplemented!`. The workspace lints deny all of them.
- Test builds stand those lints down at crate level with
  `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]`.
- **No `unsafe`.** The workspace sets `unsafe_code = "forbid"`.
- A panic inside the worker must not leave the window saying "Scanning…" for ever. A
  closed channel is visible, and the shell explains it.

### Never lie

- A finding without evidence is not a finding. Every one names the fact, the rule, the
  reason and the most likely benign explanation.
- "Not visible without elevation" is a state, not an empty list. An empty list is a
  claim that there was nothing to find.
- An empty state says what was checked, never "your PC is clean".
- There is no numeric threat score in v0.x. A number without its evidence is a lie with
  a decimal point.
- A hash match is a fact about a file, not a diagnosis of the machine.
- If a documented promise stops being true, the documentation changes in the same
  commit.

### Never delete

- Read-only is the default. There is no deletion API in v0.1.5, on purpose.
- From v0.1.6 every destructive act goes through `native/src/action.rs`, and the order
  is fixed: journal, then act, then result. Quarantine before delete, preview before
  action.
- **Nothing takes a path.** The API is `RootId` plus `EntryId`, resolved from an
  already-open `cap_std::fs::Dir`. A function that accepts a destination `Path` for a
  destructive act is a bug, not a style choice.
- **Four refusals, always:** outside the root, a link (symlink, junction, reparse
  point), a hard link (`nlink > 1`), and a file whose identity changed since it was
  inspected. Each is an outcome with a reason, each has a test, and deleting a refusal
  fails the suite.
- **The allowlist is a table** (`docs/PLAN.md` §6.10), not a heuristic. A new `Surface`
  needs a row in that table, an entry in the policy, and an adversarial test. A path
  that is not a child of a surface root cannot be reached.
- **A permanent delete exists only inside the quarantine**, only by id, and only after
  `DELETE` is typed. There is no delete-this-path anywhere in the program.
- **Every action is journalled before it happens**, with a `sync_data`, so a crash
  leaves a record rather than a mystery. An `intent` without a `result` is a named
  recovery state, never a silent guess.
- A change to the action path has **two reviewers**, and the second writes the traversal
  table from the specification without reading the first's tests.

### Never phone home

- No HTTP client, no telemetry, no account, no update ping. v0.x is offline by design.
- The enforcement is `xtask`: it bans network crates in `Cargo.lock` and greps the
  workspace for `TcpStream`, `TcpListener`, `UdpSocket` and `socket2`. Adding one is
  not a trade-off to be weighed; it is out of scope.
- Rule packs and signature databases are local files. They cannot fetch, and rules are
  data, not code.
- One local socket exists anywhere near the product, and it belongs to the tray's Linux
  backend: the status-item connection to the session bus, opened by `ksni` (pure-Rust
  `zbus`), which is reached through `tray-icon`'s `ksni` feature. No file in this tree
  opens a socket, `xtask` asserts that, and the dependency that does is the one named in
  §8 — so "local IPC" cannot quietly become something else.

### Never hide

- No kernel driver, no service, no persistent privileged helper, no silent elevation.
- Autostart is opt-in, names the exact OS entry (`docs/PLAN.md` §6.5), and is removable
  in one click. The entry is shown with its path, not described.
- The tray is an icon for a window that is still there. **Close-to-tray is off by
  default**, and where no tray exists the window is the only surface and closing quits.
- The data directory is documented and the user can open or delete it.
- A security tool that hides is indistinguishable from the thing it hunts.

### Elevation is one operation, not a mode

The one exception to "never elevate" is a named operation the person asks for:

- The window is unelevated. **Run an administrator scan** opens a consent screen.
- The operating system asks for consent (UAC on Windows). Nothing is bypassed.
- A second, short-lived copy runs `vn-ranger --elevated-scan <file>`, writes one
  snapshot and exits. No service, no driver, no standing privilege.
- The elevated copy cannot delete, quarantine or change configuration. If a future
  action needs that, it gets its own named operation, consent screen and journal entry.
- The unelevated process never hands an elevated helper an arbitrary path.

Never use a shell string for `sudo`, a UAC bypass, an elevated scheduled task, or a
helper that stays alive after its report is written.

### No `unsafe`

The workspace forbids it. If a platform API seems to need it, the binding belongs
behind a safe, reviewed crate — or the feature waits. The safe wrappers in use are
`winreg`, `netstat2`, `is_elevated`, `runas`, `cap-std` and `ksni`; each is a
dependency, not a licence to write `unsafe` here.

## 3. Commands

```bash
cargo xtask ci        # fmt --check, no-network, language, clippy -D warnings, tests
cargo xtask fmt-fix   # apply formatting
cargo xtask lint      # clippy alone
cargo xtask test      # tests alone
cargo xtask language  # the §5.5 language audit, as a check
cargo run --release   # the ranger
cargo run --release -- --report report.json   # scan without a window
cargo run --release -- --soak soak.ndjson     # sample a 24-hour run (from 0.1.6)
cargo run --release -- --diagnose             # where the files are, and whether this
                                              # program may write them
cargo run --release -- --sigma rule.yml       # import one Sigma rule as a pack to sign
```

The first build is the slow one: egui, wgpu and winit are most of the tree. After that,
`cargo xtask ci` is the loop. CI checks run in the `ci` profile: the same code with
dependencies unoptimised and no incremental state, so the three-OS matrix spends its
time on our code rather than on re-optimising wgpu. `cargo run` keeps the `dev`
profile, because a debug build of egui feels broken to use.

## 4. Adding a collector

A collector is how ranger learns a fact. Every one returns an outcome, never an
interpreted error:

```text
Outcome::Items(Vec<T>)
Outcome::Partial { items, reason }
Outcome::Unavailable { reason }
```

and `Outcome::into_parts(id, label)` turns it into facts plus the `CollectorStatus` the
interface shows. There is no separate `Capability` type yet; the status is the
capability report.

- One module per platform, under `native/src/collect/`.
- The parser is pure and fixture-tested; the syscall/API wrapper is thin.
- A collector that cannot see something says so. Silence is not an answer.
- Never invent a fact from a field that was absent. Optional means optional.
- Add a sanitised fixture for every parser and a test that runs on every host.
- A collector that needs privilege says so; it does not silently return an empty list.
- **Surfaces are a table, not a pile of functions.** Every Windows registry persistence
  surface is one `Surface` row read through one `KeyReader` trait, so a fixture for each
  runs on Linux. The same shape applies to launchd keys and systemd directives: a table
  of what to look for, and a parser that knows how to read one file.

## 5. Platform rules

CI builds on three platforms, and two of them will disagree with your machine. A push to
`main` checks Linux only; a pull request, the Monday run and the release gate check all
three. So a `#[cfg]` bug can live on `main` until the next Monday or until the cut, and
the target check below is how you find it on the day you write it rather than the day you
tag. An attribute on a **statement** deletes it on the other platforms, which can leave a
binding unused, a variable unread or a branch unreachable:

```rust
let mut out = vec![directory.join(command)];

#[cfg(windows)]
if Path::new(command).extension().is_none() {
    out.push(/* … */);       // on Linux this whole block does not exist
}

out                          // …so `mut` is unused, and CI denies warnings
```

An attribute on an **item** — a function, a `use`, a `struct` — cannot do that. When
behaviour genuinely differs per platform, write two functions of the same name under
`#[cfg(windows)]` and `#[cfg(not(windows))]`, each self-contained; when only a value
differs, use `cfg!`.

Before pushing anything with a `#[cfg]` in it, hold the file to a target you are not
on:

```bash
rustup target add x86_64-unknown-linux-gnu
cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
```

That may stop in a dependency rather than in our code. It is still worth running: if it
reaches our crates, it has checked them. `netstat2`'s Linux/macOS path uses `bindgen`,
which is why Windows is the only platform where listeners are compiled from it; Linux
reads `/proc` directly, and macOS reports the collector as unavailable.

## 6. Style

- British spelling in prose and identifiers (`colour`, `behaviour`, `licence` as a
  noun; `color` only where it is a field name a person might type).
- Comments explain *why*, never *what*. If a line needs a comment to say what it does,
  rewrite the line.
- A doc comment on every public item; `missing_docs` is a warning and CI denies
  warnings.
- Prefer a named constant over a literal, and a named type over a tuple.
- A long function that is a sequence of UI statements is fine. A long function that is
  a tangle of decisions is not.

## 7. Rules and findings

Fifteen rules shipped in v0.1.4 as Rust detectors. From v0.1.6 there are two engines and
one contract:

- **Rust detectors** stay for the rules that need computation: a hash compared with the
  baseline, a diff, a containment walk. They live in `core/src/rules.rs` with fixtures.
- **Pack rules** are data, in `packs/ranger.core.json` or an imported, signed pack. A
  pack is one JSON file plus a detached `.minisig` — never an archive, so there is no
  extraction.
- Both declare `id`, `title`, `severity`, `confidence`, `why`, `benign`, `remediation`
  and, where one applies, an ATT&CK `technique`. **A rule that cannot name a benign
  explanation may not ship as `attention`.**
- Rule ids are stable forever; changing one is a breaking change to suppressions. A pack
  id may not collide with a built-in, and the validator rejects it at load.
- **A pack rule is data and cannot act.** No code, no regular expressions, no file
  content, no socket. The vocabulary of subjects, fields and operators is closed and
  documented in `docs/RULES.md`; an unknown field is a load error, not a rule that never
  fires.
- **A pack is verified before it is parsed.** Unsigned, tampered, oversized or
  unknown-key packs are refused with a reason and a fingerprint, never partially loaded.
- `urgent` cannot come from a pack: the ceiling is `attention`. It requires an observed
  harm, and an observation is not a pack's to make. No rule uses it yet.
- Suppressions are scoped to one `(rule, subject)`, carry a reason, and expire after 30
  days. There is no ignore-everything switch.
- The language table in `docs/PLAN.md` §5.5 is part of the product, not a style guide,
  and `cargo xtask language` is now the check.

## 8. Dependencies

Every new dependency is a licence, a supply chain and a size decision.

- Allowed: MIT, Apache-2.0 (including the LLVM exception), BSD-2-Clause,
  BSD-3-Clause, ISC, Zlib, Unicode-3.0, MPL-2.0 (file-level, unmodified), and
  public-domain dedications for `notify` (CC0-1.0) and `ksni` (Unlicense) alone: no
  attribution, no copyleft, no burden. Another crate under either needs its own
  decision.
- Not allowed: GPL, AGPL, LGPL without a written exception, CDLA, SSPL, BUSL, or
  anything whose licence text has to be guessed.
- No network crate in v0.x: `reqwest`, `ureq`, `hyper`, `h2`, `curl`, `isahc`, `surf`,
  `attohttpc`, `socket2` and raw socket code are banned. The one local socket the tray
  needs is named in §2 and asserted by `xtask`.
- No C or C++ build dependency in the default build. A crate that needs one has to
  justify it; `netstat2` is Windows-only here for exactly that reason, and the Linux tray
  takes `tray-icon` with `default-features = false, features = ["ksni"]` precisely so that
  no GTK3 and no `libappindicator` is compiled in. Both halves of that are a decision:
  `tray-icon` (MIT OR Apache-2.0) for one menu API on three platforms, and its `ksni`
  backend, which speaks StatusNotifierItem through the pure-Rust `zbus` and needs no
  toolkit installed on the user's machine.
- OS access goes through a safe wrapper (`winreg`, `netstat2`, `is_elevated`, `runas`,
  `sysinfo`, `plist`, `cap-std`), never through a hand-written FFI block.
- **The action path's dependency is `cap-std`**, and it is not negotiable for
  convenience: it is what makes a traversal bug unrepresentable. **Signatures use
  `minisign-verify`**, one zero-dependency primitive for packs now and archives at 0.2.0.
- `yara-x` is an optional feature and never a default dependency; a default build that
  contains it fails `ci`.
- Prefer a crate the platform already justifies, and prefer `std` over a crate.
- Run `cargo xtask ci` after adding one, and say in the pull request what it bought.

## 9. Release

Follow `docs/RELEASES.md`. The short version:

- tag `vX.Y.Z`, release from the tag, non-draft;
- `vn-ranger-<version>-<os>-<arch>.<ext>`, one top-level directory;
- `SHA256SUMS.txt` generated after every build;
- never replace an asset on a published tag.

Ranger does not update itself. vn-launcher does.

## 10. Definition of done

A change is done when:

- the behaviour has a test, and the test fails without the change;
- a collector's parser has a fixture, and the fixture is sanitised;
- a rule has a positive and a negative case, and a benign explanation — a pack rule
  included, and a rule without one does not ship;
- a deletion path has two reviewers, and the §12 deletion matrix: traversal, links, hard
  links, TOCTOU, crash and restore;
- a new `Surface` has a row in the allowlist table and an adversarial test that fails
  without the refusal;
- a pack change has a signature test, and a tampered byte is refused;
- the docs and the UI language still tell the truth, and `cargo xtask language` passes;
- `cargo xtask ci` is green, including the cross-target clippy where it can run;
- no new dependency has escaped §8.

## 11. Where the tricky parts are

| Concern | File | Why it is subtle |
|---|---|---|
| Process identity | `native/src/collect/processes.rs` | Pids are reused; a parent may have exited; a path can change between listing and hashing. |
| Command parsing | `native/src/collect/winutil.rs` | Quoted paths with spaces, `\SystemRoot\`, registry values with arguments. |
| Signature checks | `native/src/signatures.rs` | A ClamAV `.hdb` / `.hsb` line can be malformed in a dozen ways; reject and count, never guess. |
| Hashing | `native/src/hash.rs` | One file can appear in several startup entries; hash once, cap the size, never return a partial digest. |
| Watching files | `native/src/watch.rs`, `apps/vn-ranger/src/worker.rs` | One editor save produces several events; the debounce is pure and tested, and the hash is capped and cached per path. |
| Rules and findings | `core/src/rules.rs` | A rule that cannot name a benign explanation is not ready; every finding carries the evidence it fired on and a stable subject for suppressions. |
| The action path | `native/src/action.rs`, `quarantine.rs`, `clean.rs` | The only code that can destroy data. `cap-std`, four refusals, a journal line before every act, and a test seam for TOCTOU — never a race. |
| The journal | `native/src/journal.rs`, `core/src/journal.rs` | Append-only, `sync_data`, a torn tail tolerated, a rotation that keeps seq monotone, and a recovery verdict for four on-disk states. |
| The allowlist | `native/src/clean.rs`, `core/src/action.rs` | A table, not a heuristic; the walk never follows a link or crosses a device, and a file changed since the preview is skipped. |
| Packs | `core/src/pack/`, `native/src/pack/` | Verified before parsed; a closed vocabulary; an unknown field is an error; activation and rollback are journal entries. |
| The Sigma reader | `core/src/sigma/` | YAML is user input: a restricted reader that refuses anchors, tags and multi-document files rather than guessing. |
| The tray | `native/src/tray.rs` | One crate for three desktops, so the subtlety is not a per-platform module: it is that the icon must be created on the frame's thread, that a click arrives on a channel this process has to wake the interface for, and that "no status area" is a state rather than an error. |
| Elevation | `native/src/elevation.rs`, `apps/vn-ranger/src/worker.rs` | The elevated copy is one-shot; the unelevated window must not hand it a path to act on. |
| Listener ownership | `native/src/collect/listeners/` | The socket table and the fd table are read at different times; other users' sockets need privilege. |
| Autorun parsing | `native/src/collect/autoruns/` | Registry views, 32/64-bit keys, quoted paths, binary plists, systemd user units, and a surface table read through one trait. |
| The worker | `apps/vn-ranger/src/app.rs` | A worker that sends `Done` and then closes is normal; a channel that closes without a terminal message is a failure. |
| egui 0.37 | `crates/ui/src/lib.rs` | Panels are built from the root `Ui`, not the `Context`; `Context::style` is per-theme now. |
| Tables | `crates/ui/src/views.rs` | `egui_extras::TableBuilder` columns are computed from the available width; a `remainder` column can expand past following columns. |
| The mark | `assets/logo/BRAND.md` | The geometry is a suite identifier; only the inlay changes. |
| Type | `crates/ui/src/fonts.rs`, `assets/fonts/` | Fonts are embedded with `include_bytes!` and installed before the first frame; Semibold is a real family, not synthesised. |

## 12. If in doubt

Choose the smaller, more explainable change. If a feature needs a new privilege, a new
network call, or a new way to delete a file, it needs a decision from the owner (the
decisions in `docs/PLAN.md` §14.2) before it needs code. The default answer to all
three is no.

One exception, and it is the reverse: a change that *removes* a way to delete is not a
smaller change, it is a better one. Take it.
