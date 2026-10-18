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

**Containers are built.** `cargo add zip cfb` with `zip`'s default features off and only
`deflate` on: two new crates in `Cargo.lock` and no C toolchain. `content/containers.rs`
reads a zip-shaped container and an OLE (`cfb`) one **in memory**, and the content engine
scans each member as a file of its own: the fact's path is `outer.zip!inside/payload.txt`, its
`container` chain says where it came from, and a container inside a container is followed
three deep. Nothing is ever extracted, so there is no folder to clean and no path an archive
could write through.

Everything is bounded because an archive is attacker-controlled: 32 members, 16 MB a member,
64 MB a container, and a member that claims more than 200 bytes per byte it occupies is not
read — that is what a decompression bomb looks like. What was skipped goes into the report's
refused list with a reason, in words, rather than leaving an archive that looks empty.

`goblin` vs `object` and the structural facts (sections and entropy, imports and imphash, the
overlay, the signature blob, `authenticode`) are **built, except the digest**: `object` 0.40
is the choice (one new crate, features `read,std`, no C — `goblin` was not taken, so nothing
was measured against it), and `native/src/structs.rs` turns an executable's header into a
`Structure`: format and machine, section count, how many sections are writable *and*
executable, the highest section entropy in hundredths of a bit, import count, the import hash
(libraries and symbols in table order, lower-cased — the open-source family hash), bytes after
the last section, and whether an Authenticode blob is attached. The content engine records it
on every file and every container member, the `file` subject gains `sections`, `rwx`,
`entropy`, `imports`, `overlay` and `imphash` for pack rules, and
`file.writable-executable-section` reads them. **The `authenticode` digest is not built** — it
is in §8 with the reason and what it would take.

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

**The add half is done.** The Startup view has **Add a startup entry…**, which opens a form
with a name and a command and a check that is the core's own `StartupChange::Add::check`, so
the card cannot disagree with the action path about what may be written. The button is
disabled with the refusal sentence while the command is not a program path, and a test proves
an invalid command never reaches the shell. A successful add says in the notice that the entry
appears after the next scan: the table is not given a made-up row, because this scan predates
what was written.

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

**Done.** `native/src/instance.rs` writes a `stop` file beside `wake`; the frame that answers
a wake takes a stop request first and closes with a journalled reason; and `--replace` on the
command line asks, waits up to five seconds for the lock, clears a stale request and takes
over. A second launch without the flag is unchanged and still only raises the window. A test
holds the two files apart, because one path for two meanings would make an ordinary launch
end the window it was meant to raise.

Today a second launch asks the running window to come forward and exits, which leaves an
old build answering. Fix it for development without weakening the lock:

| Step | File | What to do |
|---|---|---|
| 1 | `native/src/instance.rs` | A `stop` file beside `wake`, and `InstanceGuard::ask_to_stop()` writing it. Same channel the wake file already uses. |
| 2 | `apps/vn-ranger/src/app.rs` | The frame that checks for a wake also checks for `stop`; when it is there, clear it and quit cleanly (journal the session stop). |
| 3 | `apps/vn-ranger/src/main.rs` | `--replace`: ask the running instance to stop, wait up to five seconds for the lock, then start. Without the flag nothing changes. |
| 4 | `docs/PLAN.md` §6.5 | The flag, and why it is a flag: an automatic takeover is a way to kill a window someone is reading. |

### 5d. Scan profiles

**Done.** `ScanProfile` is `Quick`, `Standard` or `Deep`, recorded in every snapshot (a
snapshot written before profiles existed loads as a standard scan, which is what it was).
`Quick` skips the package and agent-stack inventories and says so in the collector status
rather than reporting an empty list; `Deep` adds `content::scan_files` over the programs that
start on their own — 400 files and 256 MB of bounds — and its status says how many files were
read against how many body signatures. `scan()` is `scan_with(Standard)`, so every existing
caller means what it always did. The top bar's scan button gains a **Size** menu with the
three profiles and their one-line description, and the progress line says *"Starting a quick
scan…"* for the sizes that are not the default.

| Step | File | What to do |
|---|---|---|
| 1 | `native/src/scan.rs` | A `Profile` parameter: `Quick` (processes, startup, listeners — the table and what runs), `Standard` (today's scan), `Deep` (adds packages, agent stack, and the content engine over the startup targets). Each collector already reports its own status, so a profile is which ones run, not a different code path. |
| 2 | `crates/ui` | The scan button becomes a split button: `Quick scan`, `Standard scan`, `Deep scan…`, and the status line says which profile produced the snapshot. |
| 3 | `docs/report`/`Snapshot` | The profile is recorded in the snapshot, so a saved scan says how it was taken. |

### 5e. A Clean tab, for later

**Done, as a measuring view.** `View::Clean` lists every row of the cleaning allowlist — all
eleven surfaces, whatever the machine has — with the folders it resolved to, how many entries
are past the age that surface keeps, the size, and how many were left alone because they are
young, a link, or on another volume. Before the first dry run every row says *"not measured"*,
which is a different statement from "nothing here": a place that was measured and is absent
says **"none here"**. **Measure** runs the existing dry run, which reads names, sizes and
times and writes nothing. The view has **no delete verb**: the removal is the existing
allowlisted card in Actions, with its totals, its confirmation and its journal, because a
second removal path in a second view is how a security tool grows two answers to one question.

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

**Built:** the profile-aware, bounded, cancellable walk (steps 1 and 3 — though the structural
parsers live in `native/src/structs.rs` because `object` is a native dependency, and the pure
parts — entropy and the family hash — are tested there over built fixtures rather than over
captured binaries); containers; the `Deep` profile that reads the programs which start on
their own; and the visible self-test (step 5) in the Settings card.

**Not in this release, and named in §8 or here:** the incremental cache (step 2), `.ldb`
logical signatures (step 4), and the benchmark table (step 6). Without the cache a second deep
scan costs what the first did.

| Step | File | What to do |
|---|---|---|
| 1 | `native/src/content/scan.rs` | A profile-aware walk: `Deep` reads executables, scripts, documents and archives by extension first, then everything a person selected; bounded by bytes and wall clock, cancellable between files. |
| 2 | `native/src/content/cache.rs` | An incremental cache keyed by `(path, size, mtime)` → digest and verdict, so the second deep scan costs seconds, written under the data directory and pruned by age. **Not built.** |
| 3 | `core/src/structs.rs` | The structural facts as pure parsers over a byte slice, with fixtures: a PE with an RWX section, a PE with no imports, an ELF with an executable stack, a Mach-O fat binary. |
| 4 | `core/src/signature.rs` | `.ldb` parsing (logical signatures: sub-signatures, offsets, `flevel`), with a fixture of a real ClamAV line and a malformed one that is refused rather than guessed. **Not built.** |
| 5 | `crates/ui` Sources card | One place that says which database is loaded, its version, its rule count, and the self-test result — the EICAR test that already exists becomes the visible proof the pipeline works. |
| 6 | `docs/BENCHMARKS.md` | The deep scan measured on a synthetic 20 GB tree and on this repository: files/s, bytes/s, RSS, and the second-run (cached) numbers. **Not built**, and it waits for the cache to make the second run mean anything. |

**Performance is part of the product:** a deep scan that makes a laptop unusable is a failed
deep scan. One thread pool bounded to `cores - 1`, hashing and matching chunked, no file read
twice, and every limit visible in the status line.

## 7. Wave 5 — the payoff

**The triage package is built.** `native/src/export.rs` writes one folder,
`<data>/exports/triage-<utc>/`, with `snapshot.json`, `findings.md`, `timeline.csv`, a `README`
that says what the folder is and is not, and a `manifest.txt` written **last** so it covers
what is actually there: a SHA-256 and a size for every file. The README repeats every
collector's own status, so *"the logs were not enabled"* and *"nothing matched"* cannot look
alike; it says plainly that a clean result is a statement about a database, and that nothing
in the folder was sent anywhere. A second export in the same minute is refused rather than
merged, because two exports in one folder would make the manifest untrue. The Report view
writes it, the journal records that it happened, and the folder stays on this machine.

**Not built:** the sweep across the four domains (it needs the event domain, which is out of
this release — see §8) and the `events-<channel>.jsonl` file, which has no events to write.

- `core/src/journal.rs` is chained; the sweep reuses `content::scan` and the four fact
  domains, and offers quarantine through the existing typed path.
- Triage package: `<data>/exports/triage-<time>/` with a hashed manifest, `snapshot.json`,
  `findings.md`, `timeline.csv` (the exporter exists), `events-<channel>.jsonl`.
- `bodyfile` waits for filesystem timestamps — a bodyfile of events is not a bodyfile.

## 8. Not in this release, and why

Written down rather than left to be discovered. Each of these was in the plan; each has a
reason and a size.

| Not built | Why | What it would take |
|---|---|---|
| **Event records (§3)** | `evtx` with `--no-default-features` still resolves to **34 crates** — `error-chain` 0.12, five `encoding-*` crates from 2014, `skeptic`, and an `rkyv` + `sonic-rs` SIMD stack. That is a supply chain a 0.1.7 cannot absorb in the last round of a session, and the plan's "~200 KB" was wrong. | A dependency decision of its own, then `native/src/collect/events/{windows,linux,macos}.rs` and the `event` subject with its twelve rules. The refused alternative — `wevtutil qe /f:xml` behind a bounded child — is the cheaper path and needs one paragraph of the same decision. |
| **The Authenticode digest** | Reading the signature blob is built (`signature_blob`); validating the digest needs a PKCS#7 parser and a trust decision. | `authenticode` over `object`'s certificate table, or the platform's own verifier through a safe wrapper. |
| **The sweep (§7)** | It is a search across four domains, one of which (events) is not built; a sweep that searched two of four would have to say so in every result, and the honest version of that is worse than waiting. | The event domain first, then `native/src/sweep.rs` reusing `content::scan` and the existing typed quarantine path. |
| **The Startup folder's `.lnk`** | The move into the quarantine needs the one decision this release did not make: whether a `.lnk` move may take the source path the scan reported, the way quarantine-from-a-finding does. | One paragraph in `PLAN.md` §6.10, `quarantine` reused, and the surface flipped back to writable with its refusal tests. |
| **The action path's second reviewer** | `AGENTS.md` §2 requires two reviewers on a change to the action path. This session is one. | A review of `startup.rs`, `act::startup` and the Startup card against the specification, and the traversal table written by the reviewer who did not write the tests. |
| **`yara-x`** | Deliberately absent: an optional feature, never a default dependency, and `ci` fails if a default build contains it. | `--features yara`, and a person who chooses to pay for the dependency. |
| **`bodyfile`** | It waits for filesystem timestamps that the event domain would carry. | With §3. |


## What a session should verify before it stops

```bash
cargo xtask ci                 # the gate, before the commit
cargo run -q -- --report /tmp/r.json
git status --short             # clean
git log --oneline -1 main      # still the last release
```
