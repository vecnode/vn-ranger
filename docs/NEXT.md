# Next: the work order

Written 2026-10-19 at `62600a1` on `dev`, for whoever picks this up — including a session
with more working memory than the one that wrote it. The plan is
[`PLAN-0.1.7.md`](PLAN-0.1.7.md); this file is the order of work and the exact files, so
nothing has to be rediscovered.

**Rules that do not change:** `dev` is the only place work happens, `main` is only ever a
released commit, `cargo xtask ci` runs **before** the commit, and a capability that cannot
fire does not ship.

## 1. Close Wave 3 — the sampler gets a caller

**Done.** The poll feeds the sampler, a scan's flows are stamped from its answer, and
`flow.beaconing` fires with fixtures for a steady rhythm and for none. The steps are kept
below because they are the shape the next wave repeats.

Everything else in the flow wave is done: `Sampler::observe`, `beacon()`, `BeaconFact`,
`FlowFact::beacon`, and the `flow` fact fields (`beacon`, `beacon_interval`,
`beacon_jitter`). What was missing was the producer and the rule.

| Step | File | What to do |
|---|---|---|
| 1 | `apps/vn-ranger/src/worker.rs` | The poll loop already produces `Vec<ProcessFact>` every two seconds. Have it also call `collect::flows::collect(&process_names)`, and for each fact call `Sampler::observe(key, now_unix())` where `key` is `"{process}>{remote_addr}:{remote_port}"` — the same shape `flow_fact` uses for its subject. Hold one `Sampler` per `WatchService`. |
| 2 | `apps/vn-ranger/src/app.rs` | When a scan's snapshot arrives, take the sampler's answer for each flow and set `FlowFact::beacon`. The sampler lives in the worker, so this is one message on the existing channel — do not add a second one. |
| 3 | `crates/core/src/rules.rs` | The rule: `flow.beaconing`, `Notice`, `Likely`, technique **none** with the note "a rhythm is a channel; what it carries is not observed". Benign: "a client that polls on a fixed interval — an updater, a sync tool, a monitor". Evidence: the interval, the jitter in basis points, the number of contacts. Add the id to `RULE_IDS` and the const to `BUILTIN_RULES`, then `cargo xtask coverage`. |
| 4 | `crates/core/src/rules.rs` tests | Two fixtures in one test: a flow with `beacon: Some(BeaconFact { contacts: 8, interval_s: 60, jitter_bp: 300 })` fires; a flow with `beacon: None` does not. |
| 5 | `docs/RULES.md` | Regenerate the coverage table; the rule count goes to 32. |

**Done when:** a long-running process that talks to one address on a steady rhythm raises
`flow.beaconing`, and a process that talks to it at random does not.

## 2. Wave 4 — the agent collector

**Done.** The collector finds a `SKILL.md` in the folders a client keeps one, reads the
package's own files, and reports the five capabilities with the line that proved each, one
digest per folder, and `agent.skill-executes-networked`. The steps below are kept as the
record of what was decided.

`vnr_core::skills` already reads `SKILL.md` and reports the five capabilities. What was
missing was the collector that finds the skills and turns them into facts.

| Step | File | What to do |
|---|---|---|
| 1 | `crates/native/src/collect/agentstack/skills.rs` (new) | Look in the folders a skill lives in: `~/.claude/skills`, `~/.codex/skills`, and vn-code's plugins folder. One `AgentFact` per skill, id `skill:<folder name>`, with the `SKILL.md` path. |
| 2 | same | Read the frontmatter with `skills::read_meta`, list the files beside it, hash each script with `crate::hash`, and run `skills::capabilities` over the scripts' text. Keep the capability kinds and their evidence lines. |
| 3 | `crates/core/src/model.rs` | `AgentFact` gains `capabilities: Vec<(String, String)>` (kind, evidence) and `hash: Option<String>`, both `#[serde(default)]`. |
| 4 | `crates/core/src/fields.rs` + `pack/evaluate.rs` | `agent` fields gain `executes`, `network`, `writes`, `credentials`, `model` (all `bool`), and `agent_fact` fills them. |
| 5 | `crates/core/src/rules.rs` | One rule: `agent.skill-executes-networked` — a skill that both executes and reaches the network. `Attention`, `Observed`, benign: "a package manager, a formatter or a deployment helper that legitimately installs and fetches". |

## 3. Wave 2 — events (needs `evtx`)

`cargo add evtx` (MIT OR Apache-2.0, `unsafe` forbidden, ~200 KB). Then:

- `native/src/collect/events/windows.rs` — read `…\winevt\Logs\*.evtx`, a 24-hour window, 24
  fields per record, `Unavailable` for `Security.evtx` without elevation.
- `native/src/collect/events/linux.rs` — `journalctl --output=json` as a bounded child, file
  fallback; a fixture of NDJSON and one of `auth.log`.
- `native/src/collect/events/macos.rs` — `log show --style json`, 15 minutes, or a named state
  saying the capture is owed.
- `core/src/fields.rs` — the `event` subject; `packs/` — the twelve event rules.

## 4. Wave 1 — containers, then structural facts

`cargo add zip flate2 cfb`. One walker with a ratio cap, 256 MB total, 3 layers, and the
`.ndb` library run on what it extracts — never to disk. Then `goblin` **or** `object`
(measure both, keep one): sections and entropy, imports and imphash, the overlay, the
signature blob, and `authenticode` for the PE digest.

## 5. The owner's order, 2026-10-20 — ranger starts acting

These come before the rest of the waves: a program that only ever reads is a program
nobody can use to fix anything. The promise list does not change — journal first, a
preview before the act, a refusal with a reason, and the allowlist table.

### 5a. Processes: group by name

**Done.** One row per name with its count and the executable it shares, a `Group` dropdown
(`Name`, `None`, `Parent`), the tree for `Parent`, keyboard navigation over what is on
screen, and a selection made elsewhere opens its group. Tests: a name is one closed row and
opens to its pids, two executables under one name share no path, a tree nests and a parent
that has gone is a root, and a cycle costs a row its place but never its existence.

| Step | File | What to do |
|---|---|---|
| 1 | `crates/ui/src/views.rs` | Group rows by process name (case-insensitive), one row per group with the count, its pids nested under a disclosure triangle, and the exe path / signature / start time shown only where the group agrees. Keep the existing sort keys applied to the *groups*. |
| 2 | same | A "Group by" dropdown in the page header beside the filter: `Name` (default), `None`, and `Parent` for the tree. `Parent` indents by pid under its parent, and a parent that has gone is a root with a note. |
| 3 | `crates/ui/src/lib.rs` tests | A frame with two same-named processes draws once and counts two; expanding shows both pids; `None` shows two rows. |

### 5b. Startup: add and remove, through the typed path

This is the first new destructive verb since quarantine. `AGENTS.md` §2 applies in full:
two reviewers, the §12 matrix (traversal, links, hard links, TOCTOU, crash, restore), an
allowlist row per surface, and a journal `intent` before the act and a `result` after.

**Step 1 is done** in `core/src/action.rs`: `StartupSurface` is its own ten-row table
(three writable user surfaces, two machine surfaces refused for want of elevation, five read
and not yet written), `StartupChange::{Add, Remove}` carries the `AutorunFact` so an act can
re-read the entry it is about to change, and five refusals — `MachineScope`,
`UnsupportedSurface`, `NotAName`, `NotACommand`, `NotTheSameEntry` — each with a sentence a
person can read. Name and command rules are pure functions with tests: a name cannot look
like a key path, and a command must start with a program path, quoted or bare.

**Step 2 is done for the registry.** `crates/native/src/startup.rs` reads and writes the two
`HKCU` surfaces through a four-method `Key` trait: the registry is one implementation and a
`BTreeMap` is the other, so every refusal is proved on any host rather than on a machine
that will let a test binary write a real `Run` key. `Add` refuses a name that already exists
(`DestinationOccupied`) rather than replacing a command nobody saw; `Remove` re-reads the
value and refuses `Changed` when the command is not the one the scan reported, and
`SourceMissing` when it is gone. A read never creates the key it reads. The Startup folder
is still refused at the surface level — the `.lnk` move into the quarantine is step 2b.

**Steps 3 and 4 are done for the registry surfaces.** `vnr_native::act::startup` writes the
intent (synced) before the operating system is touched and the result after it, with the same
act id on both lines, and a refusal is journalled as a refusal rather than as silence — a test
proves the pair for a machine-scope removal without touching the registry at all. The Startup
card has **Remove from startup…**, which opens a card naming the surface, the location and the
command, shows the refusal sentence instead of a button where the surface needs an
administrator, and emits `Action::RemoveStartup { id }`. The shell looks that id up in the
snapshot it is showing, re-checks the change, and takes the row out of the table afterwards
rather than waiting for a scan to agree.

**Still owed:** (a) step 2b, the Startup folder's `.lnk` into the quarantine, which is what
makes the third writable row real; (b) the `Add…` half of the card, which needs a typed
command form; (c) **the second reviewer** — `AGENTS.md` §2 requires two on a change to the
action path, and the traversal table written from the specification by the reviewer who did
not write the tests. This commit is one reviewer's work and says so.

| Step | File | What to do |
|---|---|---|
| 1 | `core/src/action.rs` | A new `Action::StartupChange` with `Add`/`Remove`, one `Surface` row per writable startup surface (HKCU Run, HKCU RunOnce, machine Run needs elevation and is refused, the user Startup folder), each with its own refusal tests. **No path is accepted**: the identity is `AutorunFact.id`, resolved from the surface's own root. |
| 3 | `apps/vn-ranger/src/app.rs` | The confirmation names the key **and** the value (or the folder and the file), then journal, act, result. The card says what undo exists: a removal writes the previous value into the journal entry so it can be put back by hand, and a quarantine move can be restored. |
| 4 | `crates/ui/src/views.rs` | The Startup view's bottom card: `Open location`, `Remove…`, and `Add…` for a command a person types. Disabled, with the reason, where the entry is machine scope without elevation. |
| 5 | `docs/RULES.md`/`SECURITY.md`/`PLAN.md` §6.10 | The new surface rows, the second reviewer's traversal table, and the sentence "removal is an act on the operating system, not on a file ranger owns". |

### 5c. One window per data directory, without fighting development

Today a second launch asks the running window to come forward and exits, which leaves an
old build answering. Fix it for development without weakening the lock:

| Step | File | What to do |
|---|---|---|
| 1 | `native/src/instance.rs` | A `stop` file beside `wake`, and `InstanceGuard::ask_to_stop()` writing it. Same channel the wake file already uses. |
| 2 | `apps/vn-ranger/src/app.rs` | The frame that checks for a wake also checks for `stop`; when it is there, clear it and quit cleanly (journal the session stop). |
| 3 | `apps/vn-ranger/src/main.rs` | `--replace`: ask the running instance to stop, wait up to five seconds for the lock, then start. Without the flag nothing changes. |
| 4 | `docs/PLAN.md` §6.5 | The flag, and why it is a flag: an automatic takeover is a way to kill a window someone is reading. |

### 5d. Scan profiles

| Step | File | What to do |
|---|---|---|
| 1 | `native/src/scan.rs` | A `Profile` parameter: `Quick` (processes, startup, listeners — the table and what runs), `Standard` (today's scan), `Deep` (adds packages, agent stack, and the content engine over the startup targets). Each collector already reports its own status, so a profile is which ones run, not a different code path. |
| 2 | `crates/ui` | The scan button becomes a split button: `Quick scan`, `Standard scan`, `Deep scan…`, and the status line says which profile produced the snapshot. |
| 3 | `docs/report`/`Snapshot` | The profile is recorded in the snapshot, so a saved scan says how it was taken. |

### 5e. A Clean tab, for later

A placeholder that is honest rather than empty: the Clean view lists the known places —
temporary folders, browser caches, Windows Update leftovers, crash dumps, logs — with the
size it measured **when a person asks it to measure**, and no delete verb. Each place is a
`Surface` row, so the same walk that powers the dry run powers this. It ships disabled
until there is a removal verb scoped to a cleanable place and its own refusal tests.

## 6. The deep scan is a real anti-virus, and an honest one

The owner's decision of 2026-10-20: **`Standard` stays an inventory, `Deep` must be a
malware scan worth running instead of a consumer AV.** Offline, Rust only, no telemetry, no
upsell, no automatic deletion — and it must beat the commercial products on the two things
they are worst at: saying what was *not* checked, and never turning a guess into a verdict.

### What makes it credible, in the order evidence is worth

| Layer | What it means | Where |
|---|---|---|
| Signature match, whole file | A file whose bytes are a known sample: `.hdb`/`.hsb` (already), then `.ldb` logical signatures and the `flevel` they declare | `core/src/signature.rs`, `native/src/content/` |
| Signature match, body | A byte pattern at an offset, with the signature's own name and line as evidence (already) | `native/src/content/` |
| Container reach | The `.ndb` library run on what an archive or document holds, in memory, never to disk, with a ratio cap and a depth bound (item 4) | `native/src/content/containers.rs` |
| Structure | PE/ELF/Mach-O facts: sections and entropy, imports, imphash, overlay, signature blob, and whether the digest is Authenticode-valid (item 4, `object` or `goblin`) | `core/src/structs.rs` |
| Behaviour-adjacent statics | A section that is writable and executable, a PE with no imports, an overlay after a signed section, a script that decodes a blob and evaluates it — each one a **fact with evidence**, never a score | `core/src/structs.rs`, rules |
| The database | The person points ranger at a ClamAV database directory and/or a YARA rule set they chose; ranger reads it, never fetches it, and says which database and which version matched | `native/src/signatures.rs` |

**YARA-X stays optional** (`--features yara`, never default, and `ci` fails if the default
build contains it). It is the one place where a rule can describe a family instead of a
byte string, and it is also a large dependency: the person who wants it turns it on and
pays for it.

**What we will not claim.** Not "better detection than McAfee" — that is a claim nobody can
measure from inside this repository. What we will claim, and test, is: offline by
construction, no numeric score, no file ever deleted without the typed path, every finding
carries the evidence and the benign case, and every scan prints what it skipped — the size
cap, an unreadable file, a container dropped by the ratio cap, an extension it did not read.
"Nothing matched the database" is the only clean result this program will ever print.

### Done when

| Step | File | What to do |
|---|---|---|
| 1 | `native/src/content/scan.rs` | A profile-aware walk: `Deep` reads executables, scripts, documents and archives by extension first, then everything a person selected; bounded by bytes and wall clock, cancellable between files. |
| 2 | `native/src/content/cache.rs` | An incremental cache keyed by `(path, size, mtime)` → digest and verdict, so the second deep scan costs seconds, written under the data directory and pruned by age. |
| 3 | `core/src/structs.rs` | The structural facts as pure parsers over a byte slice, with fixtures: a PE with an RWX section, a PE with no imports, an ELF with an executable stack, a Mach-O fat binary. |
| 4 | `core/src/signature.rs` | `.ldb` parsing (logical signatures: sub-signatures, offsets, `flevel`), with a fixture of a real ClamAV line and a malformed one that is refused rather than guessed. |
| 5 | `crates/ui` Sources card | One place that says which database is loaded, its version, its rule count, and the self-test result — the EICAR test that already exists becomes the visible proof the pipeline works. |
| 6 | `docs/BENCHMARKS.md` | The deep scan measured on a synthetic 20 GB tree and on this repository: files/s, bytes/s, RSS, and the second-run (cached) numbers. |

**Performance is part of the product:** a deep scan that makes a laptop unusable is a failed
deep scan. One thread pool bounded to `cores - 1`, hashing and matching chunked, no file read
twice, and every limit visible in the status line.

## 7. Wave 5 — the payoff

- `core/src/journal.rs` is chained; the sweep reuses `content::scan` and the four fact
  domains, and offers quarantine through the existing typed path.
- Triage package: `<data>/exports/triage-<time>/` with a hashed manifest, `snapshot.json`,
  `findings.md`, `timeline.csv` (the exporter exists), `events-<channel>.jsonl`.
- `bodyfile` waits for filesystem timestamps — a bodyfile of events is not a bodyfile.

## What a session should verify before it stops

```bash
cargo xtask ci                 # the gate, before the commit
cargo run -q -- --report /tmp/r.json
git status --short             # clean
git log --oneline -1 main      # still the last release
```
