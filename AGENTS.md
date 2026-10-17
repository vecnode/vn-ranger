# AGENTS.md — guide for contributors and AI agents

vn-ranger is a resident, local-only system ranger: it inventories what runs on a
machine, explains what is unusual, remembers a baseline, and — later, and carefully —
quarantines and cleans. It is written in **Rust only**: a native egui/eframe
application, with **no Tauri, Electron, webview or JavaScript build step**.

**Status:** v0.1.0 is released; v0.1.1 interface work is in the repository. The
read-only inventory, the local hash signature engine and the one-shot administrator
scan work. Rules, cleaning, the real-time watcher and the tray are still ahead. This
file is the contract for all of it, written before the features that will need it.

`docs/PLAN.md` explains the research, the scope and the architecture.
`docs/RELEASES.md` is the distribution contract. `SECURITY.md` is the promise to the
person running it.

## 1. Workspace map

```text
crates/
  core      vnr-core     pure and IO-free: facts, snapshots, hash signatures,
                         reports, time arithmetic
  native    vnr-native   the only crate that touches the world:
                         collect/{processes,autoruns,listeners,packages},
                         hash, signatures, elevation, paths, store, scan
  ui        vnr-ui       egui: theme, fonts, icons, widgets, the six views, World/Action
apps/
  vn-ranger              the eframe shell: owns the World, runs the worker,
                         carries out actions, and the headless report mode
xtask/                   cargo xtask ci | fmt-fix | lint | test | check | version
assets/
  logo/                  the mark, BRAND.md, MANIFEST.toml, contact sheet
  fonts/                 Inter and JetBrains Mono, OFL texts, type notes
  screenshots/           the picture the README uses
docs/                    PLAN, RELEASES, BENCHMARKS
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

- Read-only is the default. There is no deletion API in v0.1.0, on purpose.
- When quarantine arrives in v0.3.0: quarantine before delete, preview before action,
  and an allowlist of cache, temporary and log locations. User documents are excluded
  by construction, not by a heuristic.
- The deletion API takes an **id**, not a path. It resolves under the quarantine or
  cleanup root, refuses `..`, refuses a separator in an id, and refuses links.
- Every action is journalled before it happens, so a crash leaves a record rather than
  a mystery.

### Never phone home

- No HTTP client, no telemetry, no account, no update ping. v0.x is offline by design.
- The enforcement is `xtask`: it bans network crates in `Cargo.lock` and greps the
  workspace for `TcpStream`, `TcpListener`, `UdpSocket` and `socket2`. Adding one is
  not a trade-off to be weighed; it is out of scope.
- Rule packs and signature databases are local files. They cannot fetch, and rules are
  data, not code.

### Never hide

- No kernel driver, no service, no persistent privileged helper, no silent elevation.
- Autostart, when it arrives, is opt-in, names the exact OS entry, and is removable in
  one click.
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
`winreg`, `netstat2`, `is_elevated` and `runas`; each is a dependency, not a licence to
write `unsafe` here.

## 3. Commands

```bash
cargo xtask ci        # fmt --check, no-network check, clippy -D warnings, tests
cargo xtask fmt-fix   # apply formatting
cargo xtask lint      # clippy alone
cargo xtask test      # tests alone
cargo run --release   # the ranger
cargo run --release -- --report report.json   # scan without a window
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

## 5. Platform rules

CI builds on three platforms, and two of them will disagree with your machine. An
attribute on a **statement** deletes it on the other platforms, which can leave a
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

Not shipped yet. The contract for v0.2.0:

- A rule declares `id`, `title`, `severity`, `confidence`, `why`, `benign` and
  `remediation`.
- **A rule that cannot name a benign explanation may not ship as `attention`.**
- Rule ids are stable forever; changing one is a breaking change to suppressions.
- Rules are data, not code. No shell, no unbounded regex, no network, no file path
  arithmetic that can escape an allowlist.
- `urgent` requires an observed harm, not a suspicious-looking path.
- Suppressions are scoped to one `(rule, subject)`, carry a reason, and expire.
- The language table in `docs/PLAN.md` §5.5 is part of the product, not a style guide.

## 8. Dependencies

Every new dependency is a licence, a supply chain and a size decision.

- Allowed: MIT, Apache-2.0 (including the LLVM exception), BSD-2-Clause,
  BSD-3-Clause, ISC, Zlib, Unicode-3.0, MPL-2.0 (file-level, unmodified).
- Not allowed: GPL, AGPL, LGPL without a written exception, CDLA, SSPL, BUSL, or
  anything whose licence text has to be guessed.
- No network crate in v0.x: `reqwest`, `ureq`, `hyper`, `h2`, `curl`, `isahc`, `surf`,
  `attohttpc`, `socket2` and raw socket code are banned.
- No C or C++ build dependency in the default build. A crate that needs one has to
  justify it; `netstat2` is Windows-only here for exactly that reason.
- OS access goes through a safe wrapper (`winreg`, `netstat2`, `is_elevated`,
  `runas`, `sysinfo`, `plist`), never through a hand-written FFI block.
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
- a rule has a positive and a negative case, and a benign explanation;
- a deletion path has two reviewers, and traversal, symlink and TOCTOU tests;
- the docs and the UI language still tell the truth;
- `cargo xtask ci` is green, including the cross-target clippy where it can run;
- no new dependency has escaped §8.

## 11. Where the tricky parts are

| Concern | File | Why it is subtle |
|---|---|---|
| Process identity | `native/src/collect/processes.rs` | Pids are reused; a parent may have exited; a path can change between listing and hashing. |
| Command parsing | `native/src/collect/winutil.rs` | Quoted paths with spaces, `\SystemRoot\`, registry values with arguments. |
| Signature checks | `native/src/signatures.rs` | A ClamAV `.hdb` / `.hsb` line can be malformed in a dozen ways; reject and count, never guess. |
| Hashing | `native/src/hash.rs` | One file can appear in several startup entries; hash once, cap the size, never return a partial digest. |
| Elevation | `native/src/elevation.rs`, `apps/vn-ranger/src/worker.rs` | The elevated copy is one-shot; the unelevated window must not hand it a path to act on. |
| Listener ownership | `native/src/collect/listeners/` | The socket table and the fd table are read at different times; other users' sockets need privilege. |
| Autorun parsing | `native/src/collect/autoruns/` | Registry views, 32/64-bit keys, quoted paths, binary plists, systemd user units. |
| The worker | `apps/vn-ranger/src/app.rs` | A worker that sends `Done` and then closes is normal; a channel that closes without a terminal message is a failure. |
| egui 0.37 | `crates/ui/src/lib.rs` | Panels are built from the root `Ui`, not the `Context`; `Context::style` is per-theme now. |
| The mark | `assets/logo/BRAND.md` | The geometry is a suite identifier; only the inlay changes. |
| Type | `crates/ui/src/fonts.rs`, `assets/fonts/` | Fonts are embedded with `include_bytes!` and installed before the first frame; Semibold is a real family, not synthesised. |

## 12. If in doubt

Choose the smaller, more explainable change. If a feature needs a new privilege, a new
network call, or a new way to delete a file, it needs a decision from the owner (the
decisions in `docs/PLAN.md` §14.2) before it needs code. The default answer to all
three is no.
