# The plan — vn-ranger

**Status:** v0.1.4 ships the rules and findings layer: fifteen built-in rules, the
Findings view, scoped suppressions and the session timeline. The process poll, file
watchers and accepted baseline arrived in 0.1.2/0.1.3; the read-only inventory, the local
hash-signature engine and the one-shot administrator scan remain in the repository. The
sections below that describe cleaning, residency and deeper platform access are the plan
for what follows.
**Audience:** the maintainer, future contributors, and anyone deciding whether to
trust this program with a machine.
**What this document is:** the research behind ranger, the scope it will and will not
take, the architecture that keeps it honest, and the order in which it gets built.

The short version is §1. Everything after it exists to justify that version.

**Contents:** [1. The short version](#1-the-short-version) ·
[2. Why ranger exists](#2-why-ranger-exists) · [3. Prior art](#3-prior-art) ·
[4. Principles](#4-principles) · [5. The product model](#5-the-product-model) ·
[6. Architecture](#6-architecture) · [7. Platform matrix](#7-platform-matrix) ·
[8. The mark and the suite](#8-the-mark-and-the-suite) · [9. Roadmap](#9-roadmap) ·
[10. Distribution](#10-distribution) · [11. Budgets](#11-budgets) ·
[12. Verification](#12-verification) · [13. Privacy and data](#13-privacy-and-data) ·
[14. Risks and open questions](#14-risks-and-open-questions) ·
[15. References](#15-references)

---

## 1. The short version

vn-ranger is a resident, local-only system ranger for Windows, macOS and Linux. It
answers four questions, in this order:

1. **See** — what is running, what starts on its own, what is listening, what is
   installed, and which autonomous agents are among them.
2. **Explain** — for anything unusual, what was observed, which rule fired, and what
   the finding does *not* mean.
3. **Remember** — a baseline of the machine on a good day, so later checks report a
   diff rather than a verdict.
4. **Act** — quarantine and cleanup, previewed, journalled and reversible.

It is a Rust and egui application, distributed as a small archive through GitHub
releases, installed and updated by
[vn-launcher](https://github.com/vecnode/vn-launcher). It has no model, no runtime, no
service, no account and — in the v0.x line — no network code at all. It is MIT and
free forever.

The first release, **v0.1.0**, is read-only. It collects and displays inventory,
matches binary hashes against a local ClamAV-format database, and can ask the operating
system for one administrator scan. It does not delete, quarantine or "fix" anything.
Every later capability has to earn its place (§9).

---

## 2. Why ranger exists

### 2.1 The category lost the plot

Consumer security software began with a good instinct: a program that watches the
machine so its owner does not have to. It then became a business model. The modern
category is full of upsells, scareware, opaque "scores", registry cleaning that fixes
nothing, "RAM boosters" that do nothing, and warnings designed to sell an upgrade
rather than explain a fact.

The result is predictable. People do not trust security software, so they ignore it;
or they trust it too much, so they believe a green tick means a clean machine.

Ranger keeps the instinct and drops the business model. The product is not a verdict.
It is **evidence a person can read**.

### 2.2 The new resident

A computer in 2026 runs more autonomous software than the security category was
designed for: coding agents, MCP servers, local model runners, sync daemons, browser
automation drivers, background "helpers" that hold a socket and a credential file.
They are not malware. Most are useful. But they act without a person in the loop, and
almost nobody can say what they are, who installed them, what they can reach, or
whether they were there last week.

Classic antivirus has no vocabulary for this. It asks "does this file match a
signature?" The useful question is "what is this thing allowed to do, and did that
change?"

Ranger's answer is an **agent inventory**: a plain, local list of the autonomous
processes on the machine, with provenance and reach, and a diff against the last time
the machine looked normal. No judgement of intent — just the facts a person needs to
make one.

### 2.3 Ablated models and the intent problem

The uncomfortable version of §2.2 is that capability and alignment are separable.
Research on safety ablation treats the removal of refusal behaviour as a utility-risk
frontier, not an "uncensoring recipe": refusal can be reduced while capability
remains, and unsafe compliance rises as a measurable cost
([David & Gervais, 2026](https://arxiv.org/abs/2605.17413)). The implication for a
defender is narrow and practical:

> A model's identity, vendor or model card cannot tell you what a process will do with
> a user's keys.

So ranger does not try to detect "an AI". It records what an agent can do: what
spawned it, whether it persists, which sockets it holds, what it shipped with, whether
its binary is signed, and what changed after it arrived. **The model is not the
evidence; the behaviour is.**

This is also why ranger itself contains no model. A detector that depends on a model
inherits the model's failure modes, its update cadence, its licence and its supply
chain. Deterministic rules can be read, tested and argued with. Model-assisted triage is
a possible later feature (§9, "deferred"), never a dependency.

### 2.4 The gap

The tools that do parts of this well are either large, server-shaped, copyleft, or
commercial:

- **osquery** models the machine as facts, but expects an operator and a fleet.
- **ClamAV** scans files, but is an engine, not an explanation.
- **Autoruns** and **KnockKnock** answer "what starts on its own", but are
  Windows-only / macOS-only and not designed as a quiet daily companion.
- **EDR platforms** do this at enterprise scale, with an agent, a server and a price.
- **Cleaners** delete things confidently and explain almost nothing.

There is no small, free, local, cross-platform app that says: *here is what runs, here
is what changed, here is why it matters, and here is the evidence*. That is the gap.

---

## 3. Prior art

The research was done against the live repositories, not against memory. Licences are
as reported by each repository in October 2026.

| Project | Licence | What it does | What ranger takes | What it leaves |
|---|---|---|---|---|
| [vn-launcher](https://github.com/vecnode/vn-launcher) | MIT | Installs, updates and opens the vecnode applications | The workspace shape, the worker model, the release contract, the mark | The catalogue domain: it launches apps, ranger inspects a machine |
| [osquery](https://github.com/osquery/osquery) | Apache-2.0 **or** GPL-2.0 | Exposes OS state as SQL tables | "Facts, not verdicts"; a cross-platform fact schema | The SQL surface, the agent/server model, the deployment weight |
| [ClamAV](https://github.com/Cisco-Talos/clamav) | GPL-2.0 | Signature antivirus engine | The idea that signatures are a separate, optional layer; signature-update discipline | The engine: copyleft, C, and far larger than this app |
| [YARA-X](https://github.com/VirusTotal/yara-x) | BSD-3-Clause | Rust pattern-matching rules for files | A linkable rule engine **if** it earns its place (v0.1.7, optional feature) | A default dependency; rules are a supply-chain surface |
| [Sigma](https://github.com/SigmaHQ/sigma) | DRL 1.1 (rules) | A portable detection-rule format | The idea of a reviewable rule document with a rationale | The rules themselves: DRL is not an OSI licence, so import-only and user-supplied |
| [Czkawka / Krokiet](https://github.com/qarmin/czkawka) | MIT (code), CC BY 4.0 (assets) | Fast cross-platform duplicate and junk finder | Preview → select → act; honest scope; no telemetry | Its scanning domain and its Slint interface |
| [BleachBit](https://github.com/bleachbit/bleachbit) | GPL-3.0 | Cleaner with per-application rules | The "cleaner list" concept, and the caution it demands | Code (copyleft), GTK, registry cleaning |
| [Lynis](https://github.com/CISOfy/lynis) | GPL-3.0 | Host hardening audit | Check IDs, "what was checked" reporting, remediation text | The shell implementation and copyleft code |
| [Loki](https://github.com/Neo23x0/Loki) | GPL-3.0 | Indicator-of-compromise scanner | The indicator model and match reporting | Python, copyleft, and network-fed IOC lists |
| [KnockKnock](https://github.com/objective-see/KnockKnock) | GPL-3.0 | macOS persistence inventory | The "what is installed that runs" question; signed/unsigned presentation | Objective-C code; macOS-only scope |
| [Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns) / Sigcheck | Proprietary freeware | Windows autorun and signature inventory | The feature bar: what "complete" means, and the category list | Code and redistribution; not open source |
| [Wazuh](https://github.com/wazuh/wazuh) | GPL-2.0 | SIEM/EDR at fleet scale | Event vocabulary and the shape of an audit trail | Server/agent architecture; copyleft |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | AGPL-3.0 | DFIR collection at fleet scale | The discipline of evidence and collection scope | Server architecture; AGPL |
| [zeroclaw](https://github.com/zeroclaw-labs/zeroclaw) | Apache-2.0 | Small autonomous assistant infrastructure | One binary, no runtime service, "deploy anywhere" packaging discipline | Its agent runtime and model plumbing: ranger has no model |
| [agent-bom](https://github.com/agent-bom/agent-bom) | Apache-2.0 | Scans agentic infrastructure (agents, MCP servers) | The agent/MCP inventory as a first-class object | Its Python/control-plane scope |
| [Microsoft Defender for AI agents](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection) | Proprietary (preview) | Commercial agent discovery and protection | Nothing reusable — it confirms the category is real | Everything else |

### 3.1 What the research changed

1. **Visibility first.** The most useful half of this category is inventory, not
   verdicts. osquery, Autoruns and KnockKnock are valuable because they show facts.
   Ranger therefore ships inventory before it ships rules, and rules before actions.
2. **Signatures are a separate layer.** ClamAV is GPL-2.0, so it cannot be linked into
   an MIT application; YARA-X is BSD-3-Clause and can be, later, behind a feature flag.
   Neither belongs in v0.1.
3. **Cleaning is a trust problem, not a scanning problem.** Czkawka earns trust by
   showing what it will delete before it deletes it. Ranger makes preview and
   reversibility the default, and refuses the "registry cleaner" category outright.
4. **Rule packs are attack surface.** Sigma's DRL is not an OSI licence, and a rule
   pack that can name arbitrary paths is a deletion vector. Ranger rules are data, not
   code; external packs arrive only with signatures (v0.1.7).
5. **Agent inventory is real and unowned.** Commercial EDR now sells agent discovery;
   the open-source options are server- or Python-shaped. A small local app can own this.
6. **Distribution is already solved.** vn-launcher's release convention gives ranger a
   channel from day one. Build to it rather than inventing an installer.

### 3.2 Licence compatibility

Ranger is MIT. That decides what can be linked:

- **Linkable:** YARA-X (BSD-3-Clause), osquery (Apache-2.0 option), `sysinfo` (MIT),
  `notify` (MIT/Apache-2.0), `aya` (Apache-2.0), `windows` (MIT/Apache-2.0),
  `objc2` (MIT).
- **Ideas only:** ClamAV, BleachBit, Lynis, Loki, KnockKnock, Wazuh, Velociraptor
  (GPL/AGPL). No code is copied from them.
- **Not vendored:** Sigma rules (DRL 1.1). If imported at all, the user supplies them
  and the licence travels with them.

### 3.3 The detection stack, and what was actually built

v0.1.0 ships the first layer of a stack whose layers are deliberately separate:

| Layer | Status | What it does | Licence boundary |
|---|---|---|---|
| Hash signatures | **shipped** | Reads ClamAV `.hdb` / `.hsb` (`hash:size:name`) and matches MD5, SHA-1 or SHA-256 of startup binaries and a self-test file. | A clean-room reader of a documented format. No ClamAV code, so the app stays MIT. |
| Pattern rules | v0.1.7, optional | YARA-X behind a feature flag, for string and byte patterns. | BSD-3-Clause, linkable. Not in the default build. |
| Behavioural rules | **shipped** (v0.1.4) | Ranger's own detectors over facts: a startup item in a temporary folder, a binary that changed since the baseline, a persistent process holding a socket. | Ranger's own code, MIT. |
| Sigma import | v0.1.7, user-supplied | A converter for the subset of Sigma that maps onto ranger facts. | Sigma rules are DRL 1.1, not OSI. Never vendored; the user brings the rules. |
| Cleanup patterns | v0.1.5 | File walking, preview and cancellation discipline learned from Czkawka. | Czkawka is MIT; if code is copied, attribution travels with it. |

**Why not port ClamAV itself.** ClamAV is GPL-2.0. Translating its code to Rust creates
a derivative work, so the translated engine — and the combined application — would have
to be GPL-2.0. That is a legitimate choice, but it is not the MIT choice this
repository made. The compatible path is the one taken: read the documented signature
formats, implement the matching, and say "ClamAV-compatible database" rather than
"ClamAV engine". If the owner later wants the actual engine, the licence decision comes
first and the code second.

**The EICAR self-test.** The only signature shipped is the EICAR test file, which is
not malware and is what every engine is expected to recognise. The self-test hashes it
in memory, so it still proves the parser and the matcher on a machine whose antivirus
removes the file the moment it is written. That is exactly what happened on the
development machine, and the test reports it rather than pretending otherwise.

**YARA-X is a crate, not a dependency.** It is pure Rust and BSD-3-Clause, and it is a
good fit for the pattern layer. It is not linked into v0.1 because rules are a
supply-chain surface, it adds size for a layer that has no rule pack yet, and the hash
layer already answers "is this known bad?" for the files ranger can hash. The v0.1.7
feature flag keeps the default build small and offline.

**"Pure Rust" has one boundary.** The application, its UI and its collectors are safe
Rust with `unsafe_code = "forbid"` in every workspace crate. The Windows registry,
socket table and elevation prompt come through `winreg`, `netstat2`, `is_elevated` and
`runas`: safe Rust APIs over OS calls made by someone else. There is no C or C++ build
dependency in the default build, and no webview. A crate that needs a C toolchain is not
automatically wrong, but it has to justify itself; `netstat2`'s macOS/Linux `bindgen`
path is why macOS listeners are marked unavailable rather than compiled in.

---

## 4. Principles

These are the constitution. A change that breaks one is the wrong change, however
useful it looks.

1. **Visible.** Ranger is a normal process with a normal window and a normal tray icon.
   It documents where it stores data and how to remove it. A security tool that hides
   is indistinguishable from the thing it hunts.
2. **Local.** No telemetry, no analytics, no account, no cloud, no network in v0.x.
   The promise is enforced by the dependency graph, not by a paragraph (§6.6).
3. **Honest.** A finding names its evidence and its limits. "I do not know" is a valid
   answer. "Your PC is clean" is not a sentence ranger says.
4. **Reversible.** Quarantine before delete. Preview before action. A journal entry for
   everything. Nothing outside an allowlist is ever touched.
5. **Least privilege.** No kernel driver, no standing root service, no silent
   elevation. Elevation is one operation, started by a person, approved by the
   operating system, and finished before the window asks for anything else. What cannot
   be seen without elevation is shown as unseen, not guessed.
6. **Small.** One binary, no runtime, no model server, no database engine. egui and
   `std`, not Electron and not a webview.
7. **Boring.** No scareware, no countdowns, no red badges for attention metrics, no
   "optimise" buttons that cannot explain themselves.
8. **Free.** MIT, no paywall, no ads, no "pro" tier. If it cannot be funded honestly,
   it stays small rather than becoming an upsell.

### 4.1 Ranger's own threat model

| Asset | Threat | Mitigation |
|---|---|---|
| The user's files | A bug or a malicious rule causes deletion | Read-only default; quarantine; allowlists; two-person review of deletion paths; tests for traversal, symlinks and TOCTOU |
| The user's privacy | Inventory is exfiltrated or over-collected | No network; no file contents; no secrets; local storage; export only on request |
| Trust in findings | False positives train the user to ignore the app | Evidence on every finding; a named benign explanation; expiring suppressions; no "urgent" without strong evidence |
| The release | A compromised maintainer or asset | SHA256SUMS; signed releases when certificates exist; branch protection; no asset replacement |
| The rule supply chain | A rule pack becomes a remote-delete primitive | Rules are data, not code; signed packs; no third-party packs before v0.1.7 |
| The app's own persistence | Ranger becomes the hidden thing it warns about | Autostart is opt-in, visible and removable; no service; no driver; Quit really quits |

**What ranger cannot do:** detect kernel rootkits, inspect firmware, scan memory,
guarantee that a machine is free of malware, or replace the operating system's own
security updates. The interface says so where it matters, and so does `SECURITY.md`.

---

## 5. The product model

### 5.1 Facts

A **fact** is a typed observation, not a judgement:

```text
Fact {
  kind:        process | autorun | listener | package | agent | signature | file
  id:          stable within a snapshot (pid:4242, hkcu-run:AcmeHelper, tcp:0.0.0.0:8080)
  fields:      the observation (path, hash, parent, user, start time, signer, ...)
  source:      the collector that produced it (windows.processes, macos.launchd, ...)
  collected_at
}
```

Facts can be shown raw in the **Inventory** view. They carry no severity and no score.
The raw view is the escape hatch that makes the interpreted view auditable.

### 5.2 Findings

A **finding** is what a rule says about one or more facts:

```text
Finding {
  id, rule_id, subject (a fact id or a small set),
  severity:    info | notice | attention | urgent
  confidence:  observed | likely | possible
  evidence:    [ what was seen, where it was seen, why it was collected ]
  why:         the plain-language rationale
  benign:      the most likely innocent explanation
  first_seen, last_seen, status: new | acknowledged | suppressed | resolved
}
```

- **observed** — the fact itself is certain; the interpretation may not be.
- **likely / possible** — inference from a pattern, with the pattern named.
- **Severity is about consequence, not confidence.** A certain fact can be `info`; an
  uncertain one is never `urgent`.
- **`urgent` is rare by design.** It requires an active, observed harm (for example, a
  binary that was quarantined has reappeared and is listening on a public interface),
  not a suspicious-looking path.
- **No numeric risk score in v0.x.** A single number hides the evidence. If a score is
  ever added, it must decompose into the findings that produced it.

### 5.3 Rules

Two kinds, one shape:

- **Built-in detectors** are Rust functions with fixtures. They are deterministic,
  bounded, and tested against both a positive and a negative case.
- **Data rules** are TOML: a subject kind, a small set of predicates, a rationale, a
  severity and a benign explanation. No scripting, no shell, no unbounded regex.

Every rule declares `id`, `title`, `severity`, `confidence`, `why`, `benign`, and
`remediation`. A rule that cannot name a benign explanation may not ship as
`attention`.

**Suppressions** are scoped to one `(rule, subject)` pair, carry a reason, and expire
(default 30 days, maximum 90). There is no "ignore everything" switch. A suppression is
visible in Settings and in the report.

### 5.4 The agent inventory

An **agent** is a process that acts without a person in the loop. Ranger detects them
by observable properties, not by brand:

| Axis | What is recorded |
|---|---|
| Provenance | install path, signer, package owner, hash, parent chain |
| Persistence | autorun entry, service, launch agent, scheduled task |
| Reach | listening sockets, owning user, whether it can open a public interface |
| Autonomy | long-running or scheduled, started by a person or by the system |
| Change | first seen, last seen, and whether it is new since the baseline |

Ranger does **not** read prompts, model files, browser content, messages or
credentials, and it does not try to classify "AI" by name. It shows capability and
provenance, and leaves intent to the person. That is the honest version of "a detector
of agents".

### 5.5 Language

Words are part of the safety model.

| Never | Instead |
|---|---|
| "Infected" | "An unexplained startup item" |
| "Virus found" | "This binary matches rule `startup.temp-directory`" |
| "Your PC is clean" | "No unexplained startup items in this check" |
| "Threat score 87" | The findings, with their evidence |
| "Fix" (for a finding) | "Quarantine", "remove the startup entry", "open the folder" |

Empty states say what was checked, not that the machine is safe.

### 5.6 What "clean" means

"Clean" is something done to a cache, not a verdict on a computer. In v0.1.5:

- **Quarantine** moves a user-selected file into app-managed storage, with its hash,
  original path and reason recorded. Restore is one click.
- **Cleanup** removes files only in an allowlist of cache, temporary and log
  locations, with a size preview and per-item selection. User documents are excluded
  by construction, not by a clever heuristic.
- **Registry cleaning, "junk" scoring, RAM boosting and secure-delete claims are out
  of scope.** They do not do what they say, and pretending otherwise is the behaviour
  this project exists to reject.

Ranger is not an antivirus. When a finding looks like malware, the honest next step is
to quarantine the file and point the user at the operating system's own protections,
not to promise a disinfection it cannot verify.

---

## 6. Architecture

### 6.1 Crates and layering

Same shape as vn-launcher, so the suite stays legible to one maintainer:

```text
crates/
  core      vnr-core     pure: facts, findings, rules, diffs, evidence, reports
  native    vnr-native   the only crate that touches the world:
                         collectors, storage, quarantine, cleanup
  ui        vnr-ui       egui: theme, fonts, icons, widgets, views
apps/
  vn-ranger              the eframe shell: owns the World, runs the worker,
                         scheduler and tray
xtask/                   cargo xtask ci | fmt | lint | test | version
```

The rules are the same rules:

- `vnr-core` depends on nothing in the workspace and never gains a filesystem,
  network, clock or OS dependency. "Now" is a parameter, so every decision is a pure
  function with a test.
- `vnr-native` may use `vnr-core`. It is the only crate that reads the machine or
  writes to it.
- `vnr-ui` may use `vnr-core`. It draws a `World` and returns `Action`s; it never reads
  a file or spawns a process.
- Only `apps/vn-ranger` opens a window and knows about all three.

### 6.2 Data flow

```text
  collectors (worker thread) ──▶ Facts ──▶ vnr-core (diff, rules) ──▶ Findings
        ▲                                                              │
        │ Request                                                      ▼
  apps/vn-ranger ◀──────────── Action ◀──────────── vnr-ui::show ◀── World
```

The worker exists for the same reason as in vn-launcher: an inventory can take
seconds, and the window must not freeze while it does. A dead worker is visible: the
channel closes, the shell says so, and the spinner is cleared.

### 6.3 Collectors and capability

Every collector returns an outcome, never an error a caller has to interpret:

```text
CollectorOutcome = Facts(Vec<Fact>)
                 | Partial { facts, skipped: Vec<Skip> }
                 | Unavailable { reason }
```

```text
trait Collector {
    fn id(&self) -> CollectorId;
    fn capability(&self) -> Capability;   // Available | NeedsElevation | Unsupported { why }
    fn collect(&self, ctx: &Context) -> CollectorOutcome;
}
```

A collector that cannot see something says so. An empty list is a claim that there was
nothing to find, and ranger is not allowed to make that claim on behalf of a permission
it did not have.

### 6.4 Storage

Everything lives under the platform data directory (`directories::ProjectDirs`), in
`vn-ranger/`:

```text
settings.toml          user choices; human-readable
baseline.json          the last accepted snapshot (compacted)
journal.ndjson         append-only findings, actions and errors
reports/               exported JSON and Markdown
quarantine/<id>/       the file plus manifest.json (from v0.1.5)
logs/                  local, rotated, no secrets
```

No database engine. JSON and NDJSON are inspectable with a text editor, survive a
decade, and add no C dependency. Writes are atomic: a temporary file, then a rename
(`tempfile::NamedTempFile::persist`, which is correct on Windows too). A crash leaves
the previous file intact.

On Unix the data directory is created `0700`. On Windows it inherits the user's
profile ACL. Nothing in it is secret, but paths contain usernames, so exports carry a
"this is personal data" note.

### 6.5 Scheduling and residency

- **Start:** a quick inventory (processes, autoruns, listeners) within a few seconds.
- **Resident:** every six hours, with jitter. A wake-from-sleep check is v0.1.6.
- **Heavy work:** user-initiated. v0.1.0 has no full-disk scan.
- **Budget:** idle CPU under 0.5% of one core, RSS under 120 MB, measured and
  published (§11).
- **Close to tray** is a choice; **Quit** ends the process. There is no daemon, no
  service, and no watchdog that restarts ranger behind the user's back.

Autostart, when it arrives, is opt-in and uses the least invasive mechanism per OS:

| OS | Mechanism | Never |
|---|---|---|
| Windows | `HKCU\...\Run` | HKLM, a service, Task Scheduler with SYSTEM |
| macOS | `~/Library/LaunchAgents` | `/Library/LaunchDaemons`, a privileged helper |
| Linux | `~/.config/autostart/*.desktop` | a systemd system unit |

Settings shows the exact entry, and one click removes it.

### 6.6 No network, enforced

The v0.x promise is "nothing leaves the machine". It is enforced, not asserted:

- No HTTP/TLS client in the dependency tree. `cargo deny` bans `reqwest`, `ureq`,
  `hyper`, `h2`, `curl`, `isahc`, `surf` and `attohttpc`; a CI step also greps
  `Cargo.lock` so a new transitive dependency cannot slip in.
- No socket code in the workspace: a review rule, plus a grep for `std::net`,
  `socket2` and raw `libc::socket` in CI.
- No auto-update inside ranger. vn-launcher updates it; a future self-updater would
  require signed manifests and an explicit opt-in.
- Rule packs are local files; they cannot fetch.

If a future feature needs the network (a hash lookup, for example), it is opt-in,
off by default, documented per feature, and visible in the UI while it runs. The
default build stays offline.

### 6.7 Failure policy

- No panics in non-test code: the workspace lints deny `unwrap`, `expect`, `panic`,
  `todo` and `unimplemented`; `unsafe_code = "forbid"`.
- Every failure is an outcome with a reason a person can act on: permission denied,
  file unreadable, OS API unavailable, disk full.
- A dead worker is visible; a collector that hangs is cancellable.
- A log is local and contains no secrets; there is no crash upload.

### 6.8 Real time without a kernel driver

"Real time" usually means a driver. Ranger does not have one, and will not pretend it
does. The honest version is event-driven where the OS offers an event, and polled where
it does not:

- **v0.1.0:** scans on launch and on demand. This is the inventory a person can read,
  not a daemon.
- **v0.1.2:** a process poll every two seconds, which is cheap because it reads the
  process table rather than the disk. A process that is new since the last check has
  its executable hashed and matched, and appears in the timeline.
- **v0.1.2:** `notify` watchers on Downloads, Desktop, the temporary directory and the
  user's startup folders. A file written and closed is queued, debounced and scanned.
  No file-open interception, no kernel hook.
- **v0.1.6:** the watcher and the poll run while the window is closed to the tray, under
  the same idle budget.
- **Later, and only with a written scope:** user-mode ETW on Windows, EndpointSecurity
  with an Apple entitlement on macOS, eBPF or fanotify on Linux. None of them is a
  kernel driver, and none is in v0.x.

What this cannot catch, and says it cannot: a file that is opened and executed entirely
in memory, a process that starts and exits between polls, and anything a rootkit hides
from the operating system's own process table. The interface names those limits rather
than implying that "real time" means "sees everything".

The cost matters as much as the coverage. A watch event is debounced, a file is hashed
once per scan, and a scan that would exceed the idle budget waits for the machine to be
idle. A security tool that heats a laptop is a security tool people uninstall.

### 6.9 Elevation: one operation at a time

The window is never elevated. Elevation is a separate, short-lived copy of the same
binary, started for one named operation:

1. A person chooses **Run an administrator scan**.
2. The interface explains what the elevated copy can read, and what it will not do.
3. The operating system asks for consent — UAC on Windows. Nothing is bypassed.
4. A second copy runs `vn-ranger --elevated-scan <file>`: the same `scan()` code, one
   snapshot written to the data directory, then exit.
5. The unelevated window reads the snapshot and marks it `elevated: true`.

There is no standing administrator process, no service, no driver and no persistent
helper. The elevated copy can do exactly one thing: scan and write one file. It cannot
delete, quarantine or change configuration.

macOS and Linux do not have this path yet; the interface reports `can_elevate = false`
and the button says so. When they arrive, the same shape applies: a named operation, a
consent prompt, a one-shot helper, a journal entry. An unprivileged process never gets
to hand an elevated helper an arbitrary path to delete.

Never: a shell string passed to `sudo`, a UAC bypass, an elevated service, a scheduled
task running as SYSTEM, or a helper that stays alive after its report is written.

---

## 7. Platform matrix

`●` shipped in v0.1.0, `◐` partial, `○` planned or unavailable. A `○` in this table is
a named gap, not a silent one.

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Processes, parent, command line | ● `sysinfo` | ● `sysinfo` | ● `sysinfo` |
| Binary hash | ● SHA-256 | ● SHA-256 | ● SHA-256 |
| Signature / provenance | ○ v0.2 (WinVerifyTrust, cache-only) | ○ v0.2 (`codesign` / Security framework) | ◐ package owner, later |
| Autoruns | ◐ HKCU/HKLM Run, Startup, services; tasks not yet | ◐ LaunchAgents/Daemons; login items and cron not yet | ◐ systemd units, system cron, XDG; user crontabs not yet |
| Listeners → process | ● IP helper via `netstat2` | ○ no safe, C-free path yet | ● `/proc/net` + fd inode |
| Installed packages | ◐ registry uninstall keys; MSIX not yet | ◐ Applications, Homebrew; receipts not yet | ◐ dpkg, pacman; Snap/Flatpak not yet |
| File-change watch (v0.1.2) | ○ ReadDirectoryChangesW | ○ FSEvents | ○ inotify |
| Runtime file access | ○ ETW (user-mode) later | ○ EndpointSecurity (entitlement) later | ○ eBPF/auditd (root) later |
| Kernel / rootkit | ○ | ○ | ○ |
| Memory scanning | ○ | ○ | ○ |

What v0.1.0 actually ships: processes, startup items, listeners (Windows and Linux),
installed packages, SHA-256 hashes of startup binaries, the hash-signature engine and
the one-shot administrator scan. Everything marked `○` is honest work for a later
release.

Notes that matter more than the ticks:

- **Windows:** no service, no driver, and no HKLM autostart for ranger itself. (It
  reads HKLM autoruns, because they are facts; it never writes one.) Signature checks,
  when they arrive, must use cached revocation data so that verifying a signature never
  becomes a network call.
- **macOS:** several collectors trigger TCC prompts, login items live in an opaque
  store, and EndpointSecurity requires an Apple entitlement. Ranger degrades and
  explains rather than asking for more access than it needs. It is not notarised until
  v0.2.0.
- **Linux:** `hidepid`, containers and sandboxed packages (Flatpak, Snap) reduce what
  is visible. The capability banner says which collector is degraded and why.
- **All three:** "not visible without elevation" is a first-class state, not an empty
  list. The administrator scan fills some of those gaps; it never fills them by
  guessing.

---

## 8. The mark and the suite

The crystal is shared with vn-launcher: the same 24-unit grid, the same 2.914-unit
stroke, the same six facets. What changes per application is the **inlay** — the colour
inside the crystal:

| Application | Inlay |
|---|---|
| vn-launcher | none (transparent) |
| vn-ranger | ember: `#F26A21`, gradient `#FFA45E → #F26A21 → #D14A0C` |

The suite rule is simple: **same crystal, one colour per app, no other variants.** The
application icon is the mark on the suite's black tile, with white ridges so it holds
on both a light and a dark taskbar. The construction, clear space, minimum sizes,
contrast and usage rules are in [`assets/logo/BRAND.md`](../assets/logo/BRAND.md); the
files and their digests are in [`assets/logo/MANIFEST.toml`](../assets/logo/MANIFEST.toml);
the contact sheet is [`assets/logo/contact-sheet.png`](../assets/logo/contact-sheet.png).

The launcher catalogue uses the same ember (`color = "#F26A21"`), so the card and the
icon agree.

---

## 9. Roadmap

Each milestone has an exit criterion. A milestone is not "done" because the code
compiles; it is done when the criterion is met and written down.

### M0 — Identity — **shipped** `5a4aa68`

- README, LICENSE, this plan, SECURITY, AGENTS, the release contract.
- The mark in every size, including the application tile and the raw RGBA.
- **Exit:** a reader can say what ranger is, what it refuses, and how it ships. No
  application code. **Met.**

### M1 — v0.1.0, Inventory — **shipped** `ab1d8d4`

- Workspace, three crates, app shell, CI, release workflow.
- Collectors: processes and ancestry, startup items, listeners (Windows and Linux),
  installed packages, on all three platforms.
- UI: Overview, Processes, Startup, Listeners, Report and Settings; search; capability
  reports; JSON and Markdown export; the application mark in the title bar and rail.
- A clean-room ClamAV `.hdb` / `.hsb` hash engine, the built-in EICAR self-test, and
  hash matching for every startup binary.
- A one-shot administrator scan on Windows (§6.9).
- **Exit:** runs on Windows, macOS and Linux; no panic on malformed or missing data;
  every collector names its gaps; tests for the parsers and the signature engine; a
  release that follows the contract and is parsed correctly by vn-launcher, with
  install and removal verified as soon as the launcher's install path ships.

**Named gaps in v0.1.0:** signature verification (WinVerifyTrust, `codesign`), scheduled
tasks, macOS login items and listeners, MSIX/Snap/Flatpak packages, the real-time
watcher, rules, cleaning. Each is a row in §7 or a milestone below, not a surprise.

### M1.1 — v0.1.1, interface pass — **shipped (UI scope)**

The first release a person can leave open all day without the interface getting in the
way. Detection work belongs to M2.

- **Type:** Inter Regular and SemiBold plus JetBrains Mono, embedded in the binary;
  13 px body, 21 px page title, 22 px largest display number, no system-font lookup.
  The type scale lives in `theme.rs`, the fonts in `assets/fonts/`.
- **Layout:** compact top bar and rail, full-width cards, responsive statistic and
  preview columns, tables that fill their tab with sticky headers and a pinned
  full-width detail footer, and a visible page scrollbar. The minimum window is
  920 × 600 logical points; the layout is checked at 920, 1380 and 1600.
- **Behaviour shipped:** scroll position per view and whole-row selection.
- **Still open, and not claimed by this tag:** window size/position and theme
  remembered, keyboard navigation for the rail, tables and dialog, visible focus,
  accessible labels, Escape closes a dialog, and first-run/empty states that say what
  was checked rather than "clean".
- **Feedback still open:** a scan progress line that names the current stage, an export
  action that says where the file went, and feedback on copy-path actions.
- **Exit for 0.1.1:** no overlapping rectangles at the minimum and wide layouts; the
  dense table views fill their tab and scroll long result sets; `cargo xtask ci` is
  green on three operating systems; the release archive stays below 10 MB; window
  appearance is measured (first painted frame is still owed).

The typography, responsive layout and full-tab tables shipped in v0.1.1. The open items
above are the next interface pass, not part of this release.

### M2 — v0.1.2, Watch — **shipped**

The machine stops being a snapshot and becomes a series with a diff. Nothing is judged:
no rules, no findings, no deletion, no journal and no tray. The release answers one
question — *what changed since the last time this machine looked normal?*

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | A two-second poll of the process table | `native/collect/processes.rs`, `apps/vn-ranger/src/worker.rs` | A diff fixture classifies new, gone and replaced; a reused pid with a different start time is new, not changed; the poll costs under 10 ms at 300 processes. |
| 2 | Watchers on Downloads, Desktop, temp and the user's startup folders | `native/src/watch.rs` (new) | A file written and closed once yields exactly one event after a 500 ms debounce; an unavailable watcher is `Outcome::Unavailable`, never an empty list. |
| 3 | A timeline of session events | `core/src/timeline.rs` (new) | Ordering is stable; every event names the collector that saw it; the timeline is in memory and writes no file. |
| 4 | An explicit baseline and a diff against it | `core/src/diff.rs` (new), `native/src/store.rs` | `baseline.json` is written only when a person accepts the current state; a schema mismatch says so and offers a re-baseline; no baseline says "no baseline yet", never "clean". |
| 5 | A Changes view | `ui/src/views.rs` | The empty state names what was checked; a long list scrolls; a collector that could not see something shows a capability banner above the list. |
| 6 | Budgets, and a switch for each background task | `apps/vn-ranger/src/app.rs`, Settings | Idle CPU under 0.5% and working set under 200 MB over 30 minutes, published in `docs/BENCHMARKS.md`; the poll and the watcher can each be turned off. |

**The watcher decision (taken).** `notify` 8.2 is **CC0-1.0**, a public-domain
dedication with no attribution or copyleft burden, and it joins the §8 allowlist for
this crate alone. Default features are off and the macOS build selects `macos_kqueue`,
so no `fsevent-sys` is linked. The alternative was per-platform watchers, which is more
code and more platform risk for the same result. The decision is recorded in §14.2.

**The journal stays in v0.1.5.** The 0.1.2 timeline lives in memory for the session,
so nothing is written that looks like a journal without its guarantees.

**Exit for 0.1.2:** the poll and the watcher are correct on a real machine and in
fixtures; a new file yields exactly one scan; no view says "nothing changed" when a
collector was unavailable; the idle budgets hold over 30 minutes and are published;
`cargo xtask ci` is green on three operating systems.

The poll and the watcher are in the tree, their unit tests pass, and the 30-minute idle
soak measured 0.387% of one core and a 173 MB working set with the window visible — both
inside the budgets in §11. The 300-process poll cost is the one measurement still owed:
this environment exposes 32 processes, so it cannot answer that row. It stays named in
`docs/BENCHMARKS.md` rather than being assumed.

### M2.1 — v0.1.3, process identity — **shipped**

The three-OS matrix caught this the day 0.1.2 was cut: `started_at_unix` was derived as
`now - run_time`, which moves by a second between polls on Linux and macOS. The poll's
identity is `(pid, started_at_unix)`, so every process was classified as new and gone on
every poll. It now uses the start time sysinfo stores when the process is first loaded.

- **Exit:** the two-poll identity test passes on all three platforms. The v0.1.2 matrix
  failed it on Linux and macOS; the Windows build was never affected.

### M3 — v0.1.4, Explain — **shipped**

Fifteen built-in rules over the facts the collectors already produce. Each declares a
severity, a confidence, the evidence it fired on, why it matters and a named benign
explanation; each has a positive and a negative fixture. A finding carries a stable
subject, and a suppression covers one `(rule, subject)` pair with a reason and a 30-day
expiry.

- **Rules:** Rust functions with fixtures, not data loaded at runtime. `startup.temp-path`,
  `startup.downloads-path`, `startup.script-extension`, `startup.bare-command`,
  `startup.shell-interpreter`, `startup.user-writable-system`, `startup.hash-changed`,
  `startup.new-since-baseline`, `process.temp-path`, `process.downloads-path`,
  `process.parent-exited`, `listener.public-new-process`, `listener.public-unknown-owner`,
  `agent.persistent-listening`, `startup.duplicate-command`.
- **Findings:** a Findings view with the evidence, the reason, the likely benign
  explanation and what to do; a summary on Overview; a new finding is written to the
  session timeline.
- **Suppressions:** scoped to one rule and one subject, carrying a reason and expiring
  after 30 days, saved in `suppressions.json`. Clearing them is one button in Settings.
- **Not in this release:** signature verification — the tree has no §8-safe wrapper, so
  it waits for 0.2.0 rather than breaking `unsafe_code = "forbid"` — and the collector
  gaps named in §7 (scheduled tasks, login items, MSIX, Snap/Flatpak) remain open and
  named rather than silently assumed.
- **Exit:** every rule has a positive and a negative fixture; no finding exists without
  evidence; the language audit in §5.5 passes. Met by reading every rule's text against
  that table by hand.

### M4 — v0.1.5, Act

- The action journal first: append-only, one entry written before the action, and a
  killed process leaves it consistent.
- Quarantine and restore with a manifest and a hash; allowlisted cleanup with preview,
  per-item selection and dry-run; typed confirmation for anything permanent.
- **Exit:** traversal, symlink, hard-link and TOCTOU tests pass; restore is verified;
  no path outside the allowlist can be reached; every deletion path has two reviewers;
  a crash mid-action leaves the journal consistent.

### M5 — v0.1.6, Resident

- Tray, opt-in autostart, scheduler, single instance, close-to-tray, wake handling.
- A 24-hour soak with the poll and the watcher running, so the budgets are measured on
  the configuration a person actually leaves open.
- **Exit:** budgets in §11 hold over the soak; autostart is visible and removable in
  one click; no service or driver; tray fallback works on a desktop without
  AppIndicator.

### M6 — v0.1.7, Rule packs

- Signed external rule packs, a rule-development guide, an optional `yara-x` feature,
  and an importer for a user-supplied subset of Sigma (licence respected).
- **Exit:** unsigned packs are refused; signature verification has tests; the default
  build contains no YARA-X; a bad pack can be rolled back without touching data.

### M7 — v0.2.0, Distribution (minor)

This is deliberately a minor release, not another 0.1.x. It is held until the 0.1.x
line has settled; it is not part of that line.

- Signed Windows binaries (Authenticode), Developer ID and notarisation on macOS, and
  a detached `minisign` signature over the archives on Linux.
- Launcher catalogue integration, install and removal verification, reproducible-build
  notes, and release notes that state exactly what is signed.
- **Exit:** all three archives are signed and verify; vn-launcher installs and removes
  the application; no unsigned asset is published; the keys and the release process are
  documented.

### M8 — v1.0.0, Deep and done

- External security audit, reproducible builds, accessibility pass, benchmarks, and
  complete documentation.
- **Exit:** an audit with no open high-severity findings; a first-run experience that
  never requests more privilege than it explains; a release a cautious person would
  install.

### Deferred, deliberately

- Model-assisted triage (local, optional, never required).
- Elevated "deep scan" helper.
- ETW, EndpointSecurity and eBPF collectors.
- A Windows service or a privileged helper.
- Self-update.
- Mobile, web, server, and fleet management.

The gates are order, not dates:

1. No cleaning before quarantine and the journal.
2. No external rules before signing.
3. No elevation before a threat model for the helper.
4. No model before deterministic rules are proven.
5. No self-update before signed manifests.
6. No network without an opt-in, a disclosure, and an off switch.

---

## 10. Distribution

Ranger follows the vecnode release convention, documented in
[vn-launcher/docs/RELEASES.md](https://github.com/vecnode/vn-launcher/blob/main/docs/RELEASES.md).
The concrete instantiation is in [`docs/RELEASES.md`](RELEASES.md). The checks are in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and the archives are built by
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

Summary:

- Tag `v<major>.<minor>.<patch>` and publish a GitHub Release from the tag.
- Assets named `vn-ranger-<version>-<os>-<arch>.zip` (Windows) or `.tar.gz`
  (macOS, Linux), plus `SHA256SUMS.txt` generated after every build finishes.
- One top-level directory in the archive: `vn-ranger-<version>/`, containing the
  binary, `README.md` and `LICENSE`.
- The binary is `vn-ranger`, never `ranger`: the latter collides with the well-known
  terminal file manager.
- macOS: universal binary once the build matrix allows it. Linux: build on
  Ubuntu 22.04 for the oldest glibc. Windows: MSVC with a static CRT.
- No installers (`.msi`, `.dmg`, `.deb`, `.rpm`, `.AppImage`): the launcher unpacks
  archives.
- Signing arrives with v0.2.0. Until then, `SHA256SUMS.txt` is the only integrity
  statement, and the release notes say so.

The vn-launcher catalogue entry:

```toml
[[app]]
id       = "vn-ranger"
name     = "vn-ranger"
tagline  = "Resident system ranger: what runs, what persists, what changed"
repo     = "vecnode/vn-ranger"
color    = "#F26A21"
order    = 2

[app.install]
stems      = ["vn-ranger"]
extensions = ["zip", "tar.gz"]
binary     = "vn-ranger"
docs       = "https://github.com/vecnode/vn-ranger#build"

[app.launch]
windows = ["{bin}"]
macos   = ["{bin}"]
linux   = ["{bin}"]

[app.detect]
command = "vn-ranger"
paths   = ["{install}/vn-ranger", "{install}/vn-ranger.exe"]
```

---

## 11. Budgets

Targets, not claims. v0.1.0 publishes measured numbers in
[`docs/BENCHMARKS.md`](BENCHMARKS.md); if a target is missed, the document says so and
the target is revised with a reason.

| Budget | Target | Why |
|---|---|---|
| Cold start to window | ≤ 500 ms (measured 30–116 ms; first frame not measured) | a resident app is opened often |
| Idle CPU, resident, no scan | < 0.5% of one core | "always open" must not cost a laptop |
| Idle working set | ≤ 200 MB in v0.1.x; 120 MB is the v1.0 goal | 166 MB was measured with the wgpu backend; glow is the next experiment |
| Release archive | ≤ 12 MB | measured 6.83 MB Windows, 8.77 MB Linux, 5.69 MB macOS |
| Installed footprint | ≤ 40 MB | no models, no runtime, no database; the Windows binary measured 15.64 MB |
| Inventory scan | ≤ 3 s typical | longer is allowed with progress; measured 1.2–1.8 s |
| Hashing | ≥ 200 MB/s single-thread SHA-256 on NVMe | bounded, visible work; not yet measured |
| Journal write | < 1 ms per event | no UI stalls; the journal arrives with v0.1.5 |

Measured on the development Windows machine: 287–291 processes, 131 startup items,
95–102 listeners, 128 packages, a 1.2–1.8 s scan, 166 MB idle working set, 0% idle CPU,
a 15.64 MB release binary, a window in 30–116 ms, and 6.83/8.77/5.69 MB archives for
Windows, Linux and macOS. `docs/BENCHMARKS.md` has the method and the numbers that are
still owed.

The one honest comparison to zeroclaw is shape, not bytes: one binary, no runtime, no
external service, nothing to install beside it.

---

## 12. Verification

- **Unit tests** in `vnr-core` for every pure decision; property tests for parsers and
  diffing.
- **Fixture tests** for each collector: sanitised real output captured on each OS,
  replayed on any host. The Linux rules are therefore tested by a Windows developer.
- **Golden reports:** a fixed fixture set produces a byte-stable JSON report.
- **No-network test:** `cargo deny` bans plus a `Cargo.lock` grep, as in §6.6.
- **Cross-target clippy:** the workspace is checked against Linux and macOS targets, as
  vn-launcher does, because a Windows machine cannot see what they see.
- **Fuzzing:** the TOML rule parser and the plist/registry parsers, from v0.1.4 as each
  parser lands.
- **Manual matrix:** Windows 10 and 11; macOS 13, 14 and 15; Ubuntu 22.04 and 24.04;
  Fedora; on VMs with known-clean snapshots.
- **Release check:** version bump, changelog, tag, checksums, the launcher's parser
  accepts the release, a clean VM unpacks it and smoke-tests the binary, and an
  uninstall leaves nothing behind. Install through the launcher is added to this list
  the day its install path ships.
- **Accessibility:** keyboard reachability, labels for custom-painted widgets, reduced
  motion, high contrast. egui has limits; they are documented rather than ignored.

---

## 13. Privacy and data

**Collected:** process metadata (name, path, pid, parent, user, start time), autorun
entries, the listener table, installed package names, signatures, hashes of startup
binaries, and hashes of files written to the watched folders (Downloads, Desktop, the
temporary directory and the startup folders). Host OS and version.

The timeline of what changed during a session is held in memory and is not written to
disk; only the baseline a person accepts is stored.

**Not collected:** file contents (only hashes), browser history, messages, documents,
credentials, keystrokes, screenshots, microphone or camera data, and anything sent off
the machine.

**Storage:** the platform data directory, readable by the user, exportable as JSON or
Markdown, deletable by removing one folder. Reports can contain usernames and paths, so
the export dialog says they are personal data.

**Retention:** the journal keeps 90 days or 10,000 entries by default. The baseline is
kept until replaced. Quarantine is kept until the user deletes it; automatic purge is
opt-in and off by default.

**Telemetry:** none. No analytics, no crash upload, no update ping. The only network
traffic associated with ranger is the one vn-launcher performs to download a release,
and that is the launcher's, not ranger's.

---

## 14. Risks and open questions

### 14.1 Risks

| Risk | Impact | Mitigation |
|---|---|---|
| False positives erode trust | High | Evidence, a benign explanation, expiring suppressions, no `urgent` without observed harm |
| Scope creep into AV/EDR | High | The constitution (§4) and the milestone gates |
| A deletion bug | Severe | Quarantine first, allowlists, two-person review, traversal and TOCTOU tests |
| Permission gaps look like bugs | Medium | Capability banners and "not visible" states |
| macOS TCC and entitlements | Medium | Degrade, document, avoid private APIs |
| Linux tray inconsistency | Low | Tray where available, window-only fallback, no hard dependency |
| Rule-pack supply chain | High | Signed packs, no code in rules, no third-party packs before v0.1.7 |
| egui accessibility | Medium | Keyboard and labels now; document what remains |
| Maintainer time and funding | High | Small scope, no server, no telemetry, MIT |

### 14.2 Decisions

**Taken**

1. **Licence:** MIT only, matching vn-launcher. ClamAV code is not copied; the app reads
   ClamAV's documented hash formats instead (§3.3). If the owner wants the actual
   ClamAV engine, the licence changes to GPL-2.0 first.
2. **Elevation:** yes, as one named operation. The unelevated window asks; the operating
   system prompts; a one-shot copy scans and writes one report; nothing stays elevated
   (§6.9). Windows ships this in v0.1.0; macOS and Linux say "not yet".
3. **Binary name:** `vn-ranger`, never `ranger`, which would collide with the terminal
   file manager.
4. **Cleaning:** quarantine and an allowlisted cache/temp cleanup in v0.1.5. Registry
   cleaning, "junk" scoring and RAM boosting are never.
5. **YARA-X:** an optional feature at v0.1.7, never the default dependency. It is pure
   Rust and BSD-3-Clause; rules are the supply-chain risk, not the crate.
6. **Sigma:** a user-supplied import at v0.1.7. The rules are DRL 1.1 and are not
   vendored; the converter reads what the user brings.
7. **Czkawka:** its MIT file-walking, preview and cancellation discipline informs the
   cleanup layer; its Slint interface is not used. Attribution travels with any copied
   code.
8. **Network:** none in v0.x. No HTTP client, no telemetry, no update ping.
9. **Model:** none in the application. Model-assisted triage is a possible post-1.0
   feature, local and optional, never a dependency.
10. **Watcher:** `notify` 8.2 with `default-features = false` and `macos_kqueue` on
    macOS. CC0-1.0 is a public-domain dedication, added to the §8 allowlist for this
    crate alone. It is the only way to read a file event without writing `unsafe` or a
    watcher per operating system, and the kqueue backend keeps the macOS build free of
    `fsevent-sys`.

**Still owed**

1. **Code signing:** Windows EV and Apple Developer ID certificates, and who holds them.
2. **Platform floor:** Windows 10 1809+, macOS 13+, glibc 2.35+ (Ubuntu 22.04)?
3. **Tray:** all three platforms at v0.1.6, or a window-only first release?
4. **Localisation:** English only until v1.0?
5. **Agent scope:** confirm the process, network and persistence boundary, with no
   prompt or content inspection.
6. **Funding:** donations only, or no funding at all. No paywall either way.

---

## 15. References

- vn-launcher — <https://github.com/vecnode/vn-launcher>
- vn-launcher release convention —
  <https://github.com/vecnode/vn-launcher/blob/main/docs/RELEASES.md>
- osquery — <https://github.com/osquery/osquery>
- ClamAV — <https://github.com/Cisco-Talos/clamav>
- ClamAV hash-signature formats —
  <https://docs.clamav.net/manual/Signatures/HashSignatures.html>
- YARA-X — <https://github.com/VirusTotal/yara-x>
- Sigma — <https://github.com/SigmaHQ/sigma>
- Sigma Detection Rule License 1.1 —
  <https://github.com/SigmaHQ/Detection-Rule-License>
- Czkawka — <https://github.com/qarmin/czkawka>
- BleachBit — <https://github.com/bleachbit/bleachbit>
- Lynis — <https://github.com/CISOfy/lynis>
- Loki — <https://github.com/Neo23x0/Loki>
- KnockKnock — <https://github.com/objective-see/KnockKnock>
- Sysinternals Autoruns — <https://learn.microsoft.com/sysinternals/downloads/autoruns>
- Wazuh — <https://github.com/wazuh/wazuh>
- Velociraptor — <https://github.com/Velocidex/velociraptor>
- zeroclaw — <https://github.com/zeroclaw-labs/zeroclaw>
- agent-bom — <https://github.com/agent-bom/agent-bom>
- Microsoft Defender for AI agents —
  <https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection>
- David, I. & Gervais, A. (2026). *Ablating Safety: Mechanisms for Removing Alignment
  in Language Models for Security Applications.* arXiv:2605.17413 —
  <https://arxiv.org/abs/2605.17413>
- egui — <https://github.com/emilk/egui>
- sysinfo — <https://github.com/GuillaumeGomez/sysinfo>
- netstat2 — <https://github.com/ohadravid/netstat2-rs>
- winreg — <https://crates.io/crates/winreg>
- runas — <https://crates.io/crates/runas>
- is_elevated — <https://crates.io/crates/is_elevated>
- notify — <https://github.com/notify-rs/notify>
- YARA-X crate — <https://crates.io/crates/yara-x>
- tray-icon — <https://crates.io/crates/tray-icon>
- single-instance — <https://crates.io/crates/single-instance>
