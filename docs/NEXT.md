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

| Step | File | What to do |
|---|---|---|
| 1 | `crates/ui/src/views.rs` | Group rows by process name (case-insensitive), one row per group with the count, its pids nested under a disclosure triangle, and the exe path / signature / start time shown only where the group agrees. Keep the existing sort keys applied to the *groups*. |
| 2 | same | A "Group by" dropdown in the page header beside the filter: `Name` (default), `None`, and `Parent` for the tree. `Parent` indents by pid under its parent, and a parent that has gone is a root with a note. |
| 3 | `crates/ui/src/lib.rs` tests | A frame with two same-named processes draws once and counts two; expanding shows both pids; `None` shows two rows. |

### 5b. Startup: add and remove, through the typed path

This is the first new destructive verb since quarantine. `AGENTS.md` §2 applies in full:
two reviewers, the §12 matrix (traversal, links, hard links, TOCTOU, crash, restore), an
allowlist row per surface, and a journal `intent` before the act and a `result` after.

| Step | File | What to do |
|---|---|---|
| 1 | `core/src/action.rs` | A new `Action::StartupChange` with `Add`/`Remove`, one `Surface` row per writable startup surface (HKCU Run, HKCU RunOnce, machine Run needs elevation and is refused, the user Startup folder), each with its own refusal tests. **No path is accepted**: the identity is `AutorunFact.id`, resolved from the surface's own root. |
| 2 | `native/src/act/startup.rs` (new) | Remove: delete the value by exact name under a `cap_std`-opened key (winreg on Windows, `key.DeleteValue`); the Startup folder: move the `.lnk` into the quarantine, never delete it. Add: write a value with the command a person typed and a preview that shows the exact data written. Refusals: machine scope without elevation, a value that changed since the scan (compare a re-read), a name that is not in the scan the interface showed, a `.lnk` that is a link or has `nlink > 1`. |
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

## 6. Wave 5 — the payoff

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
