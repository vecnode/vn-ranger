# AGENTS.md — guide for contributors and AI agents

vn-ranger is a resident, local-only system ranger: it inventories what runs on a
machine, explains what is unusual, remembers a baseline, and — later, and carefully —
quarantines and cleans. It is written in **Rust only**: a native egui/eframe
application, with **no Tauri, Electron, webview or JavaScript build step**.

**Status:** plan. There is no application code yet. This file is the contract for the
code that follows; it is written first on purpose, because the safety rules are
cheaper to agree on before there is anything to defend.

`docs/PLAN.md` explains the research, the scope and the architecture.
`docs/RELEASES.md` is the distribution contract. Both are worth reading before a
change of any size.

## 1. Workspace map

```text
crates/
  core      vnr-core     pure and IO-free: facts, findings, rules, diffs, evidence,
                         reports
  native    vnr-native   desktop only: collectors, storage, quarantine, cleanup
  ui        vnr-ui       egui: theme, fonts, icons, widgets, views
apps/
  vn-ranger              the eframe shell: owns the World, runs the worker,
                         scheduler and tray
xtask/                   cargo xtask ci | fmt | lint | test | version
assets/
  logo/                  the mark and its rendered set
  rules/                 the built-in rules that ship (from v0.2.0)
docs/                    PLAN, RELEASES
```

**Layering is a rule, not a suggestion.**

- `vnr-core` depends on nothing in the workspace and must never gain a filesystem,
  network, clock or OS dependency. Its value is that every decision it makes is a pure
  function with a test beside it.
- `vnr-native` may use `vnr-core`. It is the only crate that touches the world.
- `vnr-ui` may use `vnr-core`. It must not do IO, read a config file or spawn a
  process — it draws a `World` and returns `Action`s.
- Only `apps/vn-ranger` opens a window, and only it knows about all three.

If a change makes `vnr-core` need to know what time it is, or makes `vnr-ui` want to
read a file, the change is in the wrong place.

## 2. Golden rules

### Never crash (this outranks feature work)

A missing OS API, a hand-edited rule, a truncated plist, a process that exits between
enumeration and inspection, or a full disk must produce an outcome a person can act
on — never a panic.

- Non-test code never panics. No `unwrap()`, `expect()`, `panic!`, `unreachable!`,
  `todo!` or `unimplemented!`. The workspace lints deny all of them.
- Test modules stand those lints down with an inner
  `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`.
- **No `unsafe`.** The workspace sets `unsafe_code = "forbid"`.
- A panic inside a library the worker calls must not leave the window saying
  "Checking…" for ever. A dead worker is visible; keep that property.

### Never lie

- A finding without evidence is not a finding. Every one names the fact, the rule, the
  reason and the most likely benign explanation.
- "Not visible without elevation" is a state, not an empty list. An empty list is a
  claim that there was nothing to find.
- An empty state says what was checked, never "your PC is clean".
- There is no numeric threat score in v0.x. A number without its evidence is a lie with
  a decimal point.
- If a documented promise stops being true, the documentation changes in the same
  commit.

### Never delete

- Read-only is the default. Quarantine before delete. Preview before action.
- Cleanup reaches only an allowlist of cache, temporary and log locations. User
  documents are excluded by construction, not by a heuristic.
- The deletion API takes an **id**, not a path. It resolves under the quarantine or
  cleanup root, refuses `..`, refuses a separator in an id, and refuses links.
- Every action is journalled before it happens, so a crash leaves a record rather than
  a mystery.

### Never phone home

- No HTTP client, no telemetry, no account, no update ping. v0.x is offline by design.
- The dependency graph is the enforcement: `cargo deny` bans network crates and CI
  greps `Cargo.lock`. Adding one is not a trade-off to be weighed; it is out of scope.
- Rule packs are local files. They cannot fetch, and they are data, not code.

### Never hide

- No kernel driver, no service, no privileged helper, no silent elevation.
- Autostart is opt-in, names the exact OS entry, and is removable in one click.
- The data directory is documented and the user can open or delete it.
- A security tool that hides is indistinguishable from the thing it hunts.

### No `unsafe`

The workspace forbids it. If a platform API seems to need it, the binding belongs
behind a safe, reviewed wrapper — or the feature waits.

## 3. Commands

```bash
cargo xtask ci        # fmt --check, clippy -D warnings, tests — exactly what CI runs
cargo xtask fmt-fix   # apply formatting
cargo xtask lint      # clippy alone
cargo xtask test      # tests alone
cargo run --release   # the ranger
```

The checks run in a `ci` profile that compiles dependencies faster, as in vn-launcher.
Tests that touch the real OS are fixture-driven and run everywhere; tests that need a
particular host are `#[ignore]`d and named.

## 4. Adding a collector

A collector is how ranger learns a fact. Every one returns an outcome, never an
interpreted error:

```text
Facts(Vec<Fact>) | Partial { facts, skipped } | Unavailable { reason }
```

and declares a `Capability` (`Available`, `NeedsElevation`, `Unsupported { why }`).

- One module per platform, under `native/src/collect/`.
- The parser is pure and fixture-tested; the syscall/API wrapper is thin.
- A collector that cannot see something says so. Silence is not an answer.
- Never invent a fact from a field that was absent. Optional means optional.
- Add a sanitised fixture for every parser and a test that runs on every host.

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

That may stop in a C dependency rather than in our code. It is still worth running: if
it reaches our crates, it has checked them.

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
- Prefer a crate the platform already justifies, and prefer `std` over a crate.
- Run `cargo deny check` after adding one, and say in the pull request what it bought.

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

## 11. Where the tricky parts will be

| Concern | File | Why it is subtle |
|---|---|---|
| Process identity | `native/src/collect/processes.rs` | Pids are reused; parent may have exited; a path can change between listing and hashing. |
| Signature checks | `native/src/collect/signature.rs` | WinVerifyTrust can reach the network for revocation; macOS assesses trust differently from `codesign -v`. Cache-only and offline by default. |
| Autorun parsing | `native/src/collect/autorun/` | Registry views, 32/64-bit keys, quoted paths with arguments, plists that are binary. |
| Listener ownership | `native/src/collect/listeners.rs` | The socket table and the fd table are read at different times; other users' sockets need privilege. |
| Rule evaluation | `core/src/rule.rs` | A rule that matches too much is a false-positive factory; bound the work and the matches. |
| Quarantine | `native/src/act/quarantine.rs` | It takes an id, not a path; links, junctions and `..` are how a safe API becomes a delete-anything API. |
| Scheduler | `apps/vn-ranger/src/scheduler.rs` | Sleep, wake, clock changes, and a worker that died must all be visible. |
| egui pass timing | `ui/src/fonts.rs` | `set_fonts` lands on the next pass; text drawn with an unbound family panics. Install fonts before the first frame. |
| Tray | `apps/vn-ranger/src/tray.rs` | Linux desktops differ; the tray is a convenience, never a requirement. |

## 12. If in doubt

Choose the smaller, more explainable change. If a feature needs a new privilege, a new
network call, or a new way to delete a file, it needs a decision from the owner (the
open questions in `docs/PLAN.md` §14.2) before it needs code.
