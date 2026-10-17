# The plan — vn-ranger

**Status:** v0.1.5 ships the interface layer on top of the rules: a command palette with
global search, keyboard navigation, filters and sorting, saved preferences, a
single-instance guard, watch roots and cancellation between collectors. The process poll, file
watchers and accepted baseline arrived in 0.1.2/0.1.3; the read-only inventory, the local
hash-signature engine and the one-shot administrator scan remain in the repository.

**v0.1.6 is one large release, not three small ones.** The owner compressed the act,
resident and rule-pack milestones into it, so it is the release that stops being
read-only: the journal and the typed action API, quarantine and allowlisted cleaning,
the tray and opt-in autostart, the scheduler, and signed first-party rule packs. It is
built in five waves inside one gate, and the sections below describe what each wave
must prove before the next one starts.
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
| [YARA-X](https://github.com/VirusTotal/yara-x) | BSD-3-Clause | Rust pattern-matching rules for files | A linkable rule engine **if** it earns its place (v0.1.6, optional feature, no rules bundled) | A default dependency; rules are a supply-chain surface |
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
   code; every pack is signed and verified before it is parsed (v0.1.6), and a pack can
   name a fact, never a path to delete.
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
| Behavioural rules | **shipped** (v0.1.4) | Ranger's own detectors over facts: a startup item in a temporary folder, a binary that changed since the baseline, a persistent process holding a socket. | Ranger's own code, MIT. |
| Signed rule packs | v0.1.6 | The behavioural layer expressed as signed data, with a closed vocabulary over facts, so a detection can ship without a rebuild. | Ranger's own format, MIT. The signature primitive is minisign. |
| Sigma import | v0.1.6, user-supplied | A converter for the subset of Sigma that maps onto ranger facts; the output is signed before it can be active. | Sigma rules are DRL 1.1, not OSI. Never vendored; the user brings the rules. |
| Pattern rules | v0.1.6, optional | YARA-X behind a build feature, for string and byte patterns, with its own consent screen. | BSD-3-Clause, linkable. Not in the default build, and no rules bundled. |
| Cleanup patterns | v0.1.6 | File walking, preview and cancellation discipline learned from Czkawka. | Czkawka is MIT; if code is copied, attribution travels with it. |

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
good fit for the pattern layer. It is not linked into the default build because rules
are a supply-chain surface and a matching engine that reads bytes changes the privacy
promise. v0.1.6 gives it a build feature and a consent screen of its own, so a person who
wants byte patterns can have them, and a person who does not is not carrying the code.

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
| The user's files | A bug or a malicious rule causes deletion | Read-only default; quarantine; the §6.10 allowlist; a type that cannot name a destination path; two-person review; tests for traversal, links and TOCTOU |
| The user's privacy | Inventory is exfiltrated or over-collected | No network; no file contents, except an opt-in content scan that stores none; no secrets; local storage; export only on request |
| Trust in findings | False positives train the user to ignore the app | Evidence on every finding; a named benign explanation; expiring suppressions; no "urgent" without strong evidence |
| The release | A compromised maintainer or asset | SHA256SUMS; signed releases when certificates exist; branch protection; no asset replacement |
| The rule supply chain | A rule pack becomes a remote-delete primitive | Rules are data and cannot name a path; every pack is signed and verified before parsing; a closed vocabulary with no regex and no content; `attention` is the ceiling; rollback touches no data |
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

"Clean" is something done to a cache, not a verdict on a computer. From v0.1.6:

- **Quarantine** moves a user-selected file into app-managed storage, with its hash,
  original path and reason recorded. Restore is one click, and is verified.
- **Cleanup** removes files only under the roots in the allowlist table (§6.10), with a
  size preview and per-item selection. User documents are excluded by construction, not
  by a clever heuristic: no entry in that table is a place a person keeps work.
- **Permanent delete** exists only inside the quarantine, only for an id, and only
  after a typed confirmation. There is no delete-this-path anywhere in the program.
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
  core      vnr-core     pure: facts, findings, rules, diffs, evidence, reports,
                         pack schema and matcher, journal record types, crash
                         recovery verdicts, clean policy, schedule arithmetic
  native    vnr-native   the only crate that touches the world:
                         collectors, storage, journal writer, action path,
                         quarantine, clean walk, packs and signatures, tray,
                         autostart
  ui        vnr-ui       egui: theme, fonts, icons, widgets, views, Action
apps/
  vn-ranger              the eframe shell: owns the World, runs the worker,
                         scheduler and tray, carries out actions
xtask/                   cargo xtask ci | fmt | lint | test | check | language | version
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
Outcome::Items(Vec<T>)
Outcome::Partial { items, reason }
Outcome::Unavailable { reason }
```

`into_parts(id, label)` turns an outcome into facts plus the `CollectorStatus` the
interface shows; the status is the capability report, and there is no separate
`Capability` type. A collector that cannot see something says so. An empty list is a
claim that there was nothing to find, and ranger is not allowed to make that claim on
behalf of a permission
it did not have.

### 6.4 Storage

Everything lives under the platform data directory (`directories::ProjectDirs`), in
`vn-ranger/`:

```text
settings.json          user choices; human-readable
baseline.json          the last accepted snapshot (compacted)
journal.ndjson         append-only actions, findings and errors (from v0.1.6)
journal-<seq>.ndjson   a rotated journal; the reader reads them in seq order
quarantine/<id>/       payload plus manifest.json (from v0.1.6)
packs/                 embedded core pack, imported packs, their .minisig files
packs/keys/            public keys you chose to trust; the local signing key
packs/active.json      which pack version is active, and its hash
reports/               exported JSON and Markdown
logs/                  local, rotated, no secrets
wake                   an activation request from a second launch (§6.5)
```

`VN_RANGER_DATA_DIR`, when it holds an absolute path, replaces the platform directory.
Two callers need it: the soak harness, which wants a disposable profile, and a person
who wants a second profile beside their daily one. A relative value is ignored, because
a data directory that moves with the working directory is how a "portable" tool ends up
writing into whatever folder launched it.

No database engine. JSON and NDJSON are inspectable with a text editor, survive a
decade, and add no C dependency. Writes are atomic: a temporary file, then a rename
(`tempfile::NamedTempFile::persist`, which is correct on Windows too). A crash leaves
the previous file intact. The journal is the one file that is appended rather than
replaced, and §6.10 is the protocol that makes an append safe to interrupt.

On Unix the data directory is created `0700`. On Windows it inherits the user's
profile ACL. Nothing in it is secret, but paths contain usernames, so exports carry a
"this is personal data" note.

### 6.5 Scheduling and residency

- **Start:** a quick inventory (processes, autoruns, listeners) within a few seconds.
- **Resident:** every six hours, with ±10% jitter. Paused for an hour from the tray or
  Settings. A full inventory is skipped while the machine is on battery if the person
  asked for that, and while an action dialog is open.
- **Wake from sleep:** detected from a gap in the two-second tick. A gap of three
  intervals or more means the machine slept; one scan runs on resume, and a backwards
  clock jump does not start a loop (§9, wave 3).
- **Heavy work:** user-initiated. There is no full-disk scan.
- **Budget:** idle CPU under 0.5% of one core and a working set under 200 MB, measured
  and published (§11).
- **Close to tray** is a choice, and it is **off** by default: a security tool that
  hides when you close it is indistinguishable from the thing it hunts. With it on, the
  first close says where the window went. **Quit** ends the process from the window and
  from the tray. There is no daemon, no service, and no watchdog that restarts ranger
  behind the user's back.
- **A second launch** touches one file, `wake`, in the data directory. The running
  instance sees it on its next tick and raises its window. A stale `wake` file is
  cleared at start, so a crash cannot make the window jump on the next launch.

Autostart is opt-in and uses the least invasive mechanism per OS:

| OS | Mechanism | Never |
|---|---|---|
| Windows | `HKCU\...\Run` | HKLM, a service, Task Scheduler with SYSTEM |
| macOS | `~/Library/LaunchAgents/dev.vecnode.ranger.plist` | `/Library/LaunchDaemons`, a privileged helper |
| Linux | `~/.config/autostart/dev.vecnode.ranger.desktop` | a systemd system unit |

Settings shows the exact key, plist or desktop file, with its path, and one click
removes it. Removal deletes ranger's own entry and nothing else: a hand-edited file
keeps every other line, and a missing file is a success, not an error. The login launch
uses `--background`, starts without focus, and shows the window only when a scan finds
something the baseline does not explain.

**The tray** is a menu, not a second interface: open, scan now, pause for an hour,
quit. Windows and macOS use `tray-icon` (no C dependency). Linux uses `ksni`, a pure
Rust implementation of the StatusNotifierItem protocol; the decision and its licence are
in §14.2. A desktop with no status-notifier host (GNOME without the extension, a bare
window manager) is a supported configuration: there is no icon, the setting says so, and
closing the window quits. The tray is never the only way to reach a feature.

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

### 6.10 The action path

This is the only code in ranger that can destroy something, so it is written as if the
filesystem were hostile — because between two syscalls, it is.

**Nothing takes a path.** A destructive act is named by two values:

```text
RootId  = Quarantine | Clean(Surface)      where the act may happen
EntryId([u8; 8])                            which entry, as 16 lowercase hex digits
```

`EntryId` is not a file name and not a path. The only strings the action layer ever hands
the filesystem are `<id>`, `<id>/manifest.json` and `<id>/payload`, each built from a
sixteen-character hex alphabet — so there is no user string on that path at all, and no
amount of `..`, `%2e%2e`, UNC prefix or Unicode trickery can produce one. The root is
opened once as a `cap_std::fs::Dir`, which resolves relative to the handle and does not
accept an absolute path or `..`; a test asserts that, because a guarantee nobody tested
is a rumour. That is what makes "no path outside the allowlist is reachable" a property
of the types rather than a property of a validator somebody has to remember to call.

The one `Path` that enters the action layer is the *source* of a quarantine: a file a
person selected, or a finding's subject, previewed and recorded before anything moves.
It is never used to compute a destination.

**Four refusals**, each an outcome with a reason, each with a test:

| Refusal | How it is recognised | Test |
|---|---|---|
| Outside the root | impossible to express through `RootId` + `EntryId` + `cap-std` | `..`, absolute, UNC, `\\?\`, drive-relative `C:x`, NUL, invalid UTF-8, trailing dot or space, a Unicode-normalised alias, a separator inside an id |
| A link | `symlink_metadata` on every component; never followed | file symlink, directory symlink, dangling link, a chain, a Windows junction, a reparse point |
| A hard link | `nlink > 1` on Unix, `number_of_links() > 1` on Windows | a second link to the same inode; the refusal names both paths |
| A changed file | open once, hash from the handle, re-stat the directory entry, compare device, file id, size and mtime | a deterministic seam: `ActionIo` is a trait and the test double swaps the file between the stat and the rename |

The identity check is the TOCTOU refusal. It is a seam rather than a race on purpose: a
test that has to win a race to fail is a test that passes in CI.

**The journal protocol**, in order, every time:

1. Resolve, validate and record the file's identity (device, file id, size, mtime, hash).
2. Append an `intent` line and `sync_data` it. Nothing has happened yet.
3. Act.
4. Append a `result` line — `ok`, `refused` or `failed` — and sync it.
5. The interface shows the outcome.

If step 3 fails, the partial state is removed and a `failed` result is written with the
OS error. If the process dies between 2 and 4, recovery reads the journal and the disk
together and says what probably happened. It never guesses silently:

| Payload in `<root>/<id>/` | Source at the manifest path | Verdict, and the one next step offered |
|---|---|---|
| absent | present | not started; nothing moved; retry or forget |
| present | absent | moved but unrecorded; verify the hash, then record or restore |
| present | present | copied, source not unlinked; verify, then finish the move |
| absent | absent | both gone; named as unexplained, with the manifest's expectation |

A torn final line — a crash in the middle of an append — is ignored and counted, so at
most one line is lost and the file stays readable. The reader parses line by line, keeps
whole entries, and never panics. The test truncates the file at every byte offset and
asserts both properties.

**Restore** verifies the payload's hash against the manifest, refuses a mismatch,
refuses an occupied destination, and moves without clobbering: `hard_link` then `unlink`
is the portable no-replace primitive, because `link` fails when the target exists. On
Linux, `renameat2(RENAME_NOREPLACE)` is used where the kernel has it. A cross-device
restore is copy → `sync_all` → verify → unlink, and a failure at any step leaves the
quarantine entry intact.

**The allowlist.** Cleanup is a table, not a heuristic. Each row is a `Surface` with a
root, an age threshold and a shape, and the walk only ever descends one of them.

| OS | Surface | What may be removed | What is never touched |
|---|---|---|---|
| Windows | `win.temp` | children of `%TEMP%` and `%LOCALAPPDATA%\Temp`, files only, older than 24 h | `%SYSTEMROOT%\Temp`, an open file, a directory a running program is using |
| Windows | `win.crashdumps` | children of `%LOCALAPPDATA%\CrashDumps` | the WER report queue |
| Windows | `win.inetcache` | children of `%LOCALAPPDATA%\Microsoft\Windows\INetCache` | cookies, history, `WebCache` |
| Windows | `win.gpu` | children of `%LOCALAPPDATA%\D3DSCache` | driver installers, shader caches of a running game |
| Windows | `win.pkgcache` | `%LOCALAPPDATA%\pip\Cache`, `npm-cache`, `Yarn\Cache`, `NuGet\v3-cache` | `node_modules`, `target`, a package's installed files |
| macOS | `mac.caches` | children of `~/Library/Caches` not named `com.apple.*`, older than 24 h | `~/Library/Application Support`, keychains |
| macOS | `mac.temp` | children of `$TMPDIR`, older than 24 h | `/tmp`, `/private/var/tmp` |
| macOS | `mac.logs` | children of `~/Library/Logs` older than 7 days — opt-in, off by default | system logs |
| Linux | `linux.cache` | children of `$XDG_CACHE_HOME` (`~/.cache`), files then empty directories, older than 24 h | `~/.config`, `~/.local/share` |
| Linux | `linux.temp` | children of `$TMPDIR`, older than 24 h | a recursive walk of `/tmp` |
| Linux | `linux.tmpfiles` | files directly in `/tmp` owned by the current uid, older than 24 h | another user's files, any directory, any file with a second link |

Never, on any platform: the home directory itself, Documents, Desktop, Downloads (it is
watched, not cleaned), Pictures, Music, Videos, `~/.ssh`, `~/.gnupg`, a password store,
keychains, browser profiles, `.git`, a trash or recycle bin, any path that is not a
child of a surface root, and any directory that still holds an ineligible entry.

The walk never follows a link, never crosses a device boundary, stops at depth 8, skips
anything modified inside the age threshold, removes files before pruning empty
directories bottom-up, and cancels between two items. The preview and the act use the
same iterator, and the act re-stats every item before removing it: a file that changed
since the preview is skipped and counted, not deleted.

**Confirmation is proportional to the act**, and the journal says which one it was:

| Act | Confirmation | Journal |
|---|---|---|
| Quarantine | preview with path, size, hash and signer; one click | `confirmed: preview` |
| Restore | one click | `confirmed: restore` |
| Clean | one dialog naming the surfaces and the total bytes | `confirmed: clean <bytes>` |
| Permanent delete | type `DELETE` | `confirmed: typed` |

Two reviewers read every change to this path, and the second one writes the traversal
table from this specification without reading the first one's tests. §12 says how that
is recorded.

### 6.11 Rule packs and content scanning

A rule pack is **one file**: UTF-8 JSON with schema version 1, plus a detached
`.minisig`. There is no archive, so there is no extraction, so there is no zip-slip, no
permission bit, and no path inside a pack. That is a security decision, not a
convenience.

```json
{
  "schema": 1,
  "pack": { "id": "ranger.core", "version": "2026.11.1", "title": "Ranger core detections" },
  "rules": [
    {
      "id": "startup.msix-package-root",
      "title": "A startup entry under a packaged app's local cache",
      "severity": "attention",
      "confidence": "medium",
      "technique": "T1547.001",
      "match": {
        "subject": "startup",
        "all": [
          { "field": "path", "op": "under", "value": "{LOCALAPPDATA}\\Packages\\" },
          { "field": "scope", "op": "eq", "value": "user" }
        ]
      },
      "why": "A package's cache is not a place an installer registers a login item.",
      "benign": "An application that registers its own updater at first launch.",
      "remediation": "Quarantine the binary, then remove the startup entry."
    }
  ]
}
```

The matcher is a **closed vocabulary**, evaluated by `vnr-core` as data:

- **Subjects:** `startup`, `process`, `listener`, `package`, `file-event`, `agent`.
- **Fields:** stable names from `core/src/fields.rs`, documented in `docs/RULES.md` and
  versioned. An unknown field is a load error, not a rule that never fires.
- **Operators:** `eq`, `ne`, `prefix`, `suffix`, `contains`, `glob`, `under`, `in`,
  `gt`, `lt`, `exists`. No regular expressions and no file content: a pack cannot make
  the machine do unbounded work, and it cannot read a document.

Four promises a pack cannot break: it holds no code, reads no file content, opens no
socket, and cannot produce `urgent` — the ceiling is `attention`, because only an
observed harm earns more, and an observation is not a pack's to make. A rule without a
`benign` explanation is rejected, exactly as a built-in would be.

Limits, enforced before anything is evaluated: 2 MB, 512 rules, 4 KB per string, 32
predicates per rule, unique ids matching `[a-z0-9]+(\.[a-z0-9-]+)+`, and no id that
collides with a built-in. Validation names the rule and the line.

**Signature.** Every pack is verified before it is parsed: minisign, Ed25519 over
BLAKE2b-512, one detached file, one key. The project's public key is compiled into the
binary; a pack signed by any other key is refused, and the refusal shows the fingerprint
and offers to add the key behind a typed confirmation. Removing a key unloads the packs
that depended on it. Keys are public data; the private half never exists on a user's
machine.

**Activation and rollback.** `packs/active.json` names the active id, version, SHA-256,
key fingerprint and time. Activation is a journal entry. The previous verified version
stays on disk, and rollback flips `active.json` back to it — it touches no fact, no
baseline, no quarantine entry and no journal line. A pack that fails validation at load
is not fatal: it is deactivated with a named reason, the built-ins keep working, and a
banner says which pack and why.

**Content scanning is a build feature and a named operation.** `--features content-scan`
compiles YARA-X in; the default build does not contain it, and `cargo xtask ci` proves
that with `cargo tree` rather than a promise. With the feature, **Scan file contents in a
folder** is its own consent screen: it states that file bytes will be read, it runs on
folders the person chooses, it keeps rule names and offsets in the report, and it stores
no content and no second hash. No YARA rules are bundled; the person brings `.yar`
files, and they are data like everything else here.

**Sigma is a producer, not a loader.** `core/src/sigma/` converts a user-supplied subset
onto the fact vocabulary and writes a pack candidate. Only rules whose `logsource` maps
onto something ranger observes are converted — `process_creation` and `registry_event`
on Windows, `file_event` on watched folders, `network_connection` on listeners — and
everything else is counted by reason in the import report. The output must then be
signed, with the local key, before it can be active; so importing untrusted rules cannot
skip the signature step.

---

## 7. Platform matrix

`●` shipped in the current release (v0.1.5), `◐` partial, `○` planned or unavailable. A
`○` in this table is a named gap, not a silent one. The `v0.1.6` rows are what the next
release turns into `●`; this table is rewritten at that tag, not before it.

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Processes, parent, command line | ● `sysinfo` | ● `sysinfo` | ● `sysinfo` |
| Binary hash | ● SHA-256 | ● SHA-256 | ● SHA-256 |
| Signature / provenance | ○ v0.2 (WinVerifyTrust, cache-only) | ○ v0.2 (`codesign` / Security framework) | ◐ package owner, later |
| Autoruns | ◐ HKCU/HKLM Run, Startup, services; tasks, WMI, IFEO, COM not yet | ◐ LaunchAgents/Daemons; login items, periodic and cron not yet | ◐ systemd units, system cron, XDG; user crontabs, rc files, `ld.so.preload` not yet |
| Listeners → process | ● IP helper via `netstat2` | ○ no safe, C-free path yet | ● `/proc/net` + fd inode |
| Installed packages | ◐ registry uninstall keys; MSIX not yet | ◐ Applications, Homebrew; receipts not yet | ◐ dpkg, pacman; Snap/Flatpak not yet |
| File-change watch | ● ReadDirectoryChangesW | ● kqueue | ● inotify |
| Journal and crash recovery | ○ v0.1.6 | ○ v0.1.6 | ○ v0.1.6 |
| Quarantine and verified restore | ○ v0.1.6 | ○ v0.1.6 | ○ v0.1.6 |
| Allowlisted cleaning | ○ v0.1.6 | ○ v0.1.6 | ○ v0.1.6 |
| Tray | ○ v0.1.6 (`tray-icon`) | ○ v0.1.6 (`tray-icon`) | ○ v0.1.6 (`ksni`; no icon without a host) |
| Opt-in autostart | ○ v0.1.6 (HKCU `Run`) | ○ v0.1.6 (LaunchAgent) | ○ v0.1.6 (`~/.config/autostart`) |
| Signed rule packs | ○ v0.1.6 | ○ v0.1.6 | ○ v0.1.6 |
| Content scan (YARA-X) | ○ v0.1.6, build feature | ○ v0.1.6, build feature | ○ v0.1.6, build feature |
| Runtime file access | ○ ETW (user-mode) later | ○ EndpointSecurity (entitlement) later | ○ eBPF/auditd (root) later |
| Kernel / rootkit | ○ | ○ | ○ |
| Memory scanning | ○ | ○ | ○ |

What v0.1.5 ships: processes, startup items, listeners (Windows and Linux), installed
packages, SHA-256 hashes of startup binaries, the hash-signature engine, fifteen rules,
the accepted baseline, the watch, and the one-shot administrator scan. Everything marked
`○` is honest work for a later release.

0.1.6 changes the shape of that table more than any release since 0.1.0: five rows move
from `○` to `●`, and the autoruns `◐` becomes considerably less partial (§9, wave 5).
What stays `○` after it matters as much — kernel, memory, runtime file access — and the
interface says so.

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
- **Tray:** on Linux there is no icon unless a status-notifier host is running, and that
  is a supported state rather than an error. On all three platforms the tray holds
  nothing the window cannot reach, and closing it is never the only way to quit.
- **Packs:** a rule pack is data. It cannot read a file, open a socket, run code or
  produce `urgent`, and the default build contains no YARA-X. Content scanning is a
  build feature and a named operation with its own consent screen.
- **Elevation:** 0.1.6 adds nothing to the elevated copy. It still scans, writes one
  snapshot and exits, and it cannot quarantine, clean or change a setting (§6.9).

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

**The journal stays in v0.1.6.** The 0.1.2 timeline lives in memory for the session,
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

### M4 — v0.1.5, Interface — **shipped**

The 0.1.5 line is the interface release: a command palette with global search (Ctrl+K),
keyboard navigation (j/k, arrows, Enter, Esc), sort and quick filters on the process
table, scope and disabled filters on startup, severity/text/sort controls on findings,
a source filter and clear button on the session timeline, per-suppression removal, a
baseline card on the overview, extra watched folders, cancellation between collectors,
findings in the Markdown report, findings as JSON, saved preferences, a single-instance
guard and a top-right error toast.

### M5 — v0.1.6, Act, Resident and Packs

The interface layer closed in 0.1.5. 0.1.6 is the release that stops being read-only,
and it is deliberately large: the action layer, the resident shell and signed rule packs
ship together, because a ranger that can act but must be restarted to notice, or that
stays open but needs a rebuild before it knows a new technique, is not the product
described in §1.

The owner chose bigger releases over a chain of small ones, and that is the owner's
scheduling decision to make. The order inside the release is not a scheduling decision:

```text
journal ──▶ typed action ──▶ quarantine ──▶ cleaning ──▶ resident ──▶ packs ──▶ coverage
```

Each step is a precondition for the next, and none of them moves to protect a date. A
release may take longer than planned. It may not take the shortcut.

Five waves and one gate. The tag is cut when all five wave exits hold; the changelog
names whatever a wave had to leave behind, and the plan is amended in the same commit.

#### Wave 1 — Ledger

The journal and the typed action API. Nothing acts in this wave: this is the wave that
makes acting safe to write.

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | The journal: append-only NDJSON, one line flushed and `sync_data`d **before** the act, carrying seq, time, kind, action, id, subject, path, hash, size, result and reason | `core/src/journal.rs` (records and reader, pure), `native/src/journal.rs` (writer) | Every field has a meaning and a test; seq is monotone across a rotation; a write costs < 1 ms at the median; a full disk refuses the act instead of performing it unrecorded |
| 2 | A reader that tolerates a torn tail | `core/src/journal.rs` | Truncating the file at every byte offset yields whole entries only, never a panic, and never loses a complete line |
| 3 | Crash recovery: an `intent` without a `result` becomes a named state with a verdict and one suggested next step | `core/src/recovery.rs` (new) | All four on-disk states in §6.10 have a fixture; startup shows the verdict instead of guessing |
| 4 | The typed action API: `RootId` + `EntryId`, resolved through `cap_std::fs::Dir`; no function takes a destination path | `native/src/action.rs` (new) | A path outside the root cannot be expressed; no `unwrap`, no `unsafe`, no `PathBuf` in a destructive signature |
| 5 | The four refusals: outside the root, a link, a hard link, a changed file | `native/src/action.rs` | Traversal, symlink, junction, hard-link and TOCTOU fixtures all pass, on all three platforms |
| 6 | A deterministic TOCTOU seam | `native/src/action/io.rs` | The test double swaps the file between the stat and the rename; deleting the identity check makes the test fail |
| 7 | Interrupted actions in the interface | `crates/ui/src/views.rs` | An interrupted action is visible in the journal, with the file, the reason and the one next step |

**Wave 1 exit:** the protocol in §6.10 is implemented, not described; a process killed
between the intent and the result leaves a journal a person can read and act on.

#### Wave 2 — Quarantine and cleaning

The destructive half. Everything here is reversible except a permanent delete that a
person typed.

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | Quarantine: `<data>/quarantine/<id>/` holds the payload and `manifest.json` (original path, hash, size, mode, reason, time, identity) | `native/src/quarantine.rs` (new) | A same-volume move is one rename; a cross-volume move is copy → `sync_all` → verify → unlink, and a failure removes the partial |
| 2 | Verified restore | `native/src/quarantine.rs` | Quarantine → restore returns byte-identical content; a hash mismatch is refused and journalled; an occupied destination is refused, never clobbered |
| 3 | Permanent delete, only of a quarantine entry, only by id, only after `DELETE` is typed | `native/src/action.rs`, UI | Not reachable for any path outside the quarantine root; the journal records `confirmed: typed` |
| 4 | The allowlist as data: a `Surface` table per OS (§6.10), age thresholds and shapes | `core/src/clean.rs` (policy, pure), `native/src/clean.rs` (walk) | A test enumerates adversarial inputs — `..`, absolute, UNC, drive-relative, junction, another user's file, the home directory — and every one is refused by construction |
| 5 | A cancellable preview and a dry run that touches nothing | `native/src/clean.rs` | 10,000 entries preview in under 2 s; cancellation lands within 100 ms; a dry run writes no journal and removes nothing; a file changed since the preview is skipped and counted |
| 6 | Confirmation proportional to the act (§6.10) | `crates/ui/src/views.rs` | A permanent action cannot be confirmed with one click; the journal says which confirmation was used |
| 7 | The Act surfaces: quarantine candidates with preview, the quarantine list with restore and purge, the clean preview, the journal newest first, and the data-directory size in Settings | `crates/ui/src/views.rs`, `icons.rs` | Every empty state says what was checked; every failure names the file and the OS error |
| 8 | `cargo xtask language`, part of `ci` | `xtask/src/main.rs` | It fails on "fix", "infected", "threat score" and "your PC is clean" in user-facing strings, and on an empty state that does not name what was checked |
| 9 | Two reviewers on every deletion path | process | Both reviewers and the commit are recorded; the second writes the traversal table from §6.10 without reading the first's tests |

**Wave 2 exit:** the owner's criterion for everything that can destroy data — two
reviewers, traversal, symlink, hard-link and TOCTOU tests, no reachable path outside the
allowlist, a crash-consistent journal, and a verified restore.

#### Wave 3 — Resident

The shell a person leaves open. It stays a window with an icon, never a service.

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | Tray: `tray-icon` on Windows and macOS, `ksni` on Linux; menu is open, scan now, pause an hour, quit; no icon is a supported state | `native/src/tray/` (new), `apps/vn-ranger/src/app.rs` | The icon appears on all three where a host exists; where none does, the setting says so and closing quits; the tray can do nothing the window cannot |
| 2 | Opt-in autostart, per OS (§6.5), removable in one click | `native/src/autostart/` (new) | Idempotent write; removal deletes only ranger's entry and succeeds when the file is already gone; the exact key, plist or desktop path is shown |
| 3 | The scheduler: every six hours ±10%, pause, battery preference | `apps/vn-ranger/src/worker.rs`, `core/src/schedule.rs` (new, pure) | Jitter is a pure function with a fixture; a paused scheduler runs nothing; a scan never starts while an action dialog is open |
| 4 | Wake handling from a tick gap | `core/src/schedule.rs` | A gap of three intervals is one scan on resume; a backwards clock jump does not loop; tested with a fake clock |
| 5 | Activation of a second launch through the `wake` file | `native/src/instance.rs`, `apps/vn-ranger/src/app.rs` | The running window is raised; a stale `wake` file is cleared at start and never raises the window |
| 6 | Close-to-tray, off by default | Settings | Closing quits when the setting is off; when on, the first close says where the window went |
| 7 | A soak harness and a 24-hour run | `apps/vn-ranger/src/main.rs` (`--soak`), `docs/BENCHMARKS.md` | The app samples itself every 60 s into NDJSON — CPU, working set, private bytes, handles, polls, events, journal writes — on the release candidate, with the configuration a person actually leaves open |

**Wave 3 exit:** the budgets in §11 hold over 24 hours, and the numbers are published
with the configuration and the build they were taken on.

#### Wave 4 — Packs

Detections become data with an author, and the author is verifiable offline.

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | The pack schema and its validator: closed vocabulary, no unknown fields, no unknown operator, `benign` required, severity at most `attention`, the limits in §6.11 | `core/src/pack/` (new) | Every rejection names the rule and the line; a test per limit; a pack that fails to load cannot stop the built-ins |
| 2 | The field vocabulary, versioned and documented | `core/src/fields.rs` (new), `docs/RULES.md` | Stable names; an unknown field is a load error, not a rule that never fires; the vocabulary is tested against the fact model |
| 3 | Signature verification: minisign, detached, before parsing | `native/src/pack/signature.rs` (new) | Flipping any single byte of a valid pack is refused; a pack from an unknown key is refused and its fingerprint shown |
| 4 | The trust store and the local signing key | `native/src/pack/keys.rs` (new) | Adding a key needs the fingerprint typed; the local key is `0600`; a key's removal unloads its packs |
| 5 | Activation, journaling and rollback | `native/src/pack/store.rs` (new) | Activating v2 and rolling back to v1 restores v1's findings with every other file byte-identical |
| 6 | The embedded first-party pack, validated in `ci` by the same validator | `packs/ranger.core.json`, `include_str!` | `cargo xtask ci` validates it; no rule id collides with a built-in; the pack is the catalogue wave 5 fills |
| 7 | `docs/RULES.md`: the authoring guide and the ATT&CK coverage table | `docs/` | A person can write, sign and import a rule without reading Rust; the coverage table is generated from the packs, not typed |
| 8 | An optional `content-scan` feature | `native/src/contentscan/` (new), `Cargo.toml` | The default build contains no YARA-X, proved by `cargo tree` in `ci`; the consent screen names the folders and says bytes are read; no content is stored |
| 9 | A Sigma importer for a user-supplied subset | `core/src/sigma/` (new) | A restricted YAML reader that refuses anchors, tags and multi-document files; unmapped rules counted by reason; the output must be signed before it can be active |

**Wave 4 exit:** unsigned packs are refused; signature verification has tests; the
default build contains no YARA-X; and rolling a bad pack back leaves every other file
byte-identical.

#### Wave 5 — Coverage

The wave that decides whether the release is worth installing. Every rule names the
technique it covers or says why it cannot, so a gap is a row in a table rather than a
surprise.

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | A table-driven Windows registry surface reader: Run/RunOnce/RunServices/RunServicesOnce (both views), Active Setup, Winlogon `Shell`, `Userinit` and `Notify`, AppInit_DLLs, IFEO `Debugger`, COM `InprocServer32`, shell extensions, the accessibility swap, Print Monitors, LSA packages, netsh helpers, the screensaver and the time providers | `native/src/collect/autoruns/windows/keys.rs` (new) | One `Surface` table and one `KeyReader` trait, so every surface has a fixture that runs on any host; each row carries its technique id |
| 2 | Windows scheduled tasks and WMI subscriptions | `native/src/collect/tasks/` (new) | Task XML is parsed from a fixture, including a hidden task and an `onlogon` trigger; a WMI subscription is reported as a fact with its consumer |
| 3 | Windows services, deepened: `ServiceDll`, svchost groups, unquoted paths | `native/src/collect/autoruns/windows.rs` | A `ServiceDll` under a user-writable directory is a fact; an unquoted path with a space is parsed, not guessed |
| 4 | macOS `periodic`, cron, `ScriptingAdditions`, Folder Actions | `native/src/collect/autoruns/macos.rs` | A fixture per source; a directory that cannot be read is `Unavailable`, not empty |
| 5 | Linux user crontabs, `at`, `/etc/cron.*`, shell startup files, `profile.d` | `native/src/collect/autoruns/linux.rs` | A fixture per source; a file that changed since the scan is hashed once |
| 6 | Linux preload and loader surfaces: `ld.so.preload`, `LD_PRELOAD` in a unit, `ld.so.conf.d`, `pam.d`, `udev` rules, `modprobe.d install` | `native/src/collect/autoruns/linux/loader.rs` (new) | Every line that names a library is a fact with the file that named it |
| 7 | SSH and agent-stack surfaces: `authorized_keys` with a forced command, `~/.ssh/rc`, MCP client configuration, an editor task with `runOn: folderOpen`, a package-manager lifecycle hook | `native/src/collect/agentstack/` (new) | Each is a fact, not a verdict; nothing outside the configuration files listed in `docs/RULES.md` is read |
| 8 | The first-party rules for all of the above, each with a positive and a negative fixture and a technique id | `packs/ranger.core.json`, `docs/RULES.md` | A rule without a fixture does not ship; a rule without a benign explanation does not ship; the coverage table is generated |
| 9 | The language audit of every new string | `cargo xtask language` | The release notes can say "quarantine", "remove the startup entry" and "open the folder", and cannot say "fix" |

**Wave 5 exit:** the pack covers the techniques in the coverage table, every rule has
both fixtures, and the release notes restate what is still not seen — kernel, memory,
runtime file access, macOS login items (§7).

**What is not claimed by wave 5:** macOS login items need an `objc2` wrapper and wait;
`/tmp` is never walked recursively; browser profiles are never cleaned; a running
executable is never quarantined on Windows, and the interface says the file is in use
rather than pretending the move failed for no reason.

#### How the release is cut

1. `0.1.6-rc.1` is tagged when all five waves are code-complete. It is published as a
   pre-release, so the soak runs on a binary a person can download, not on a local build.
2. The 24-hour soak and the manual matrix (§12) run on that binary. Findings are fixed in
   `0.1.6-rc.2`; a release candidate takes fixes, not features.
3. `v0.1.6` is cut from the last candidate that passed everything. `Cargo.toml`, this
   plan and the changelog move to the version in the same commit.
4. If a wave cannot reach its exit, it is named in the release notes and in §7, and the
   version still ships — because what shipped is true. What does not happen is a wave
   shipping with its tests written after its apology.

**Exit for 0.1.6** — the owner's criterion, unchanged:

> every deletion path has two reviewers and traversal, symlink, hard-link and TOCTOU
> tests; no path outside the allowlist is reachable; a crash mid-action leaves the
> journal consistent; restore is verified; the language audit says "quarantine", never
> "fix"; `cargo xtask ci` is green on three platforms.

Added by this plan, because a five-wave release needs its own proof:

- Wave 3: the §11 budgets hold over a 24-hour soak on the release candidate, published in
  `docs/BENCHMARKS.md` with the configuration and the build.
- Wave 4: unsigned packs are refused; signature verification has tests; the default build
  contains no YARA-X; a bad pack rolls back without touching data.
- Wave 5: every shipped rule has a positive and a negative fixture and a technique id or
  a written reason for none.
- `cargo xtask language` is part of `ci`, so the language audit is a check rather than a
  reading.
- The manual matrix (§12) is run on the candidate binary, not on a developer build.

**Deliberately not in 0.1.6** — the owner's list, unchanged:

> registry cleaning, "junk" scoring, secure-delete claims, a service, and any elevated
> deletion. The elevated copy stays a one-shot scan.

And, added here because a bigger release attracts them: browser-profile caches and
history, the Recycle Bin and the Trash, `/tmp` walked recursively, cleaning anything not
in the §6.10 table, deleting a file the running system holds mapped, automatic purge of
quarantine, macOS login items (needs a new Objective-C wrapper), a network lookup, a
model, and self-update.

### M6 — v0.2.0, Distribution (minor)

This is deliberately a minor release, not another 0.1.x. It is held until the 0.1.x line
has settled; it is not part of that line.

- Signed Windows binaries (Authenticode), Developer ID and notarisation on macOS, and a
  detached `minisign` signature over the archives on Linux — the same primitive the rule
  packs already use, which is why the packs ship it first.
- Launcher catalogue integration, install and removal verification, reproducible-build
  notes, and release notes that state exactly what is signed.
- **Exit:** all three archives are signed and verify; vn-launcher installs and removes
  the application; no unsigned asset is published; the keys and the release process are
  documented.

### M7 — v1.0.0, Deep and done

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
- macOS login items through an Objective-C wrapper, and a Linux tray that does not need
  a status-notifier host. Both are named gaps in §7, not accidents.

The gates are order, not dates:

1. No cleaning before quarantine and the journal.
2. No external rules before signing — which is why 0.1.6 ships the signature before the
   catalogue that needs it, in that order, inside one release.
3. No YARA-X in the default build, and no content reading without its own consent
   screen.
4. No elevation before a threat model for the helper.
5. No model before deterministic rules are proven.
6. No self-update before signed manifests.
7. No network without an opt-in, a disclosure, and an off switch.
8. No rule without a benign explanation, and no `urgent` from data.

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
| Journal write | < 1 ms median, < 10 ms at p99, including `sync_data` | no UI stalls, and the record exists before the act (§6.10) |
| Quarantine move, same volume | < 10 ms for a 1 GB file | one rename; the number is about directory work, not bytes |
| Quarantine move, cross volume | bounded by 200 MB/s, verified, cancellable | copy → sync → verify → unlink |
| Clean preview | 10,000 entries in ≤ 2 s; cancel within 100 ms | the walk is visible work a person can stop |
| Rule pack load | ≤ 30 ms for 512 rules | startup must not wait on a pack |
| Rule evaluation | ≤ 20 ms for 512 rules over 1,000 facts | a pack cannot make the interface feel broken |
| Tray overhead | 0% idle CPU, ≤ 8 MB working set | an icon is not a runtime |
| 24-hour soak, tray and poll running | CPU < 0.5%, working set ≤ 200 MB, growth ≤ +10 MB, zero errors | the configuration a person actually leaves open |

Measured on the development Windows machine: 287–291 processes, 131 startup items,
95–102 listeners, 128 packages, a 1.2–1.8 s scan, 166 MB idle working set, 0% idle CPU,
a 15.64 MB release binary, a window in 30–116 ms, and 6.83/8.77/5.69 MB archives for
Windows, Linux and macOS. `docs/BENCHMARKS.md` has the method and the numbers that are
still owed.

The 0.1.6 rows are targets until the release candidate is soaked, and then they are
numbers with a date and a configuration beside them. A missed target is reported and
revised, as the 120 MB working set was, never quietly dropped.

The one honest comparison to zeroclaw is shape, not bytes: one binary, no runtime, no
external service, nothing to install beside it.

---

## 12. Verification

- **Unit tests** in `vnr-core` for every pure decision; property tests for parsers and
  diffing.
- **Fixture tests** for each collector: sanitised real output captured on each OS,
  replayed on any host. The Linux rules are therefore tested by a Windows developer. A
  registry surface table is tested through its `KeyReader` seam, so fifteen Windows
  surfaces have fixtures that run on Linux.
- **The deletion matrix**, from v0.1.6, on all three platforms:

  | Family | Inputs |
  |---|---|
  | Traversal | `..`, `../..`, an absolute path, a UNC path, `\\?\`, a drive-relative `C:x`, an embedded NUL, invalid UTF-8, a trailing dot or space, a Unicode-normalised alias, a separator inside an id |
  | Links | a file symlink, a directory symlink, a dangling link, a link chain, a Windows junction, a reparse point, a link swapped after the preview |
  | Hard links | a second link to the same inode, a link created between the preview and the act |
  | TOCTOU | the file replaced between stat and rename, replaced between hash and rename, and truncated mid-hash, each through the `ActionIo` seam |
  | Crash | the process killed between the intent and the result, at every phase; the reader must produce a verdict from the four states in §6.10 |
  | Restore | a hash mismatch, an occupied destination, a cross-device move, a full disk, a quarantined entry that was edited |

  Every row is a test that fails when its refusal is deleted. That is the whole point of
  the row.
- **Two reviewers.** A change to `native/src/action.rs`, `quarantine.rs`, `clean.rs`,
  `journal.rs` or the §6.10 protocol needs two people. The second reviewer writes the
  traversal table from the specification, without reading the first reviewer's tests, and
  both names go in the pull request. A tool cannot enforce that; a reviewer can, and the
  checklist is the artifact.
- **Pack tests:** a valid pack, a single flipped byte, a wrong key, an unknown field, an
  unknown operator, a rule without `benign`, `urgent` in a pack, an id that collides with
  a built-in, an oversized pack, a truncated JSON document, and a rule whose field does
  not belong to its subject. Each is a named rejection.
- **Golden reports:** a fixed fixture set produces a byte-stable JSON report.
- **No-network test:** `cargo deny` bans plus a `Cargo.lock` grep, as in §6.6. From
  v0.1.6 it also asserts the only local socket in the tree is the Linux tray's D-Bus
  connection, in one file.
- **No YARA-X by default:** `cargo tree -e features` proves the default build has no
  `yara-x`, and that the feature builds it in when asked.
- **Language:** `cargo xtask language` fails on "fix", "infected", "threat score" and
  "your PC is clean" in user-facing strings, and on an empty state that does not name
  what was checked.
- **Cross-target clippy:** the workspace is checked against Linux and macOS targets, as
  vn-launcher does, because a Windows machine cannot see what they see.
- **Fuzzing:** the pack JSON, the journal reader, the plist/registry parsers and the
  restricted Sigma YAML reader, as each parser lands.
- **The soak:** 24 hours with the tray, the poll, the watcher and the scheduler running,
  sampling every 60 s into NDJSON, on the release candidate. The numbers go in
  `docs/BENCHMARKS.md` with the build and the configuration; a soak on a developer build
  is not evidence about the binary a person downloads.
- **Manual matrix:** Windows 10 and 11; macOS 13, 14 and 15; Ubuntu 22.04 and 24.04;
  Fedora; on VMs with known-clean snapshots. From 0.1.6 it also covers a desktop with no
  status-notifier host, a machine that suspends and resumes, and an autostart entry
  removed by hand.
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
disk; only the baseline a person accepts is stored. From v0.1.6 the journal is on disk,
because a record that exists only in memory cannot survive the crash it exists to
explain.

**Not collected:** file contents (only hashes), browser history, messages, documents,
credentials, keystrokes, screenshots, microphone or camera data, and anything sent off
the machine.

**The two exceptions, both explicit, both new in 0.1.6:**

- **Quarantine stores the file.** That is the point of it. The file sits in the data
  directory with a manifest, is never uploaded, and is removable in one click. The
  interface says where it is.
- **Content scanning reads bytes**, only with the `content-scan` build feature, only for
  folders a person names, only on the consent screen that says so. It keeps rule names
  and offsets, never the content, and never a second hash.

A rule pack carries rules, not data: it cannot read a file, and no fact from a pack is
collected. The trust store holds public keys.

**Storage:** the platform data directory, readable by the user, exportable as JSON or
Markdown, deletable by removing one folder. Reports, the journal and quarantine manifests
can contain usernames and paths, so the export dialog says they are personal data.

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
| A deletion bug | Severe | Quarantine first, allowlists, two-person review, traversal and TOCTOU tests, and a type that cannot name a path |
| A five-wave release hides a regression | High | Five wave exits, a release candidate, a 24-hour soak on the candidate, and a changelog that names what slipped |
| Permission gaps look like bugs | Medium | Capability banners and "not visible" states |
| macOS TCC and entitlements | Medium | Degrade, document, avoid private APIs |
| Linux tray inconsistency | Low | `ksni` where a status-notifier host exists, window-only fallback, no hard dependency |
| Rule-pack supply chain | High | Signed packs over a one-file format, no code, no regex, no file content, `attention` as the ceiling, rollback without touching data |
| A pack with a wide match floods the Findings view | Medium | Limits and validation; every first-party rule has a negative fixture; suppressions stay per `(rule, subject)` |
| Content scan reads private files | High | Off by default and absent from the default build; per-folder consent; nothing stored |
| One machine's 24-hour soak is not three | Medium | The soak runs on a release candidate on each platform before the tag, and the numbers carry their configuration |
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
4. **Cleaning:** quarantine and the allowlisted cleanup in v0.1.6, with the table in
   §6.10 as the whole of the allowlist. Registry cleaning, "junk" scoring and RAM
   boosting are never. Browser profiles and trash containers are never a surface.
5. **YARA-X:** an optional feature in v0.1.6, never the default dependency. It is pure
   Rust and BSD-3-Clause; rules are the supply-chain risk, not the crate, which is why
   no rules are bundled.
6. **Sigma:** a user-supplied import in v0.1.6. The rules are DRL 1.1 and are not
   vendored; the converter reads what the user brings and its output must be signed
   before it can be active.
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
11. **The action path is capability-based:** `cap-std` (Apache-2.0 WITH LLVM-exception OR
    MIT, pure Rust) resolves every destructive path from an already-open directory
    handle. It is the only dependency in the tree whose whole purpose is to make a
    traversal bug unrepresentable rather than unlikely, and it behaves the same on
    Windows, where `std` cannot open with `FILE_FLAG_OPEN_REPARSE_POINT`.
12. **Signatures are minisign:** `minisign-verify` (MIT, zero dependencies) verifies packs
    in v0.1.6 and the archives in v0.2.0. One primitive, one format, one public key
    story for both, and no crypto dependency tree to audit.
13. **The tray:** `tray-icon` (Apache-2.0/MIT) on Windows and macOS; `ksni` on Linux,
    which is **Unlicense**. Unlicense is a public-domain dedication with no attribution
    or copyleft burden — the same class as the CC0-1.0 admitted for `notify` — and it is
    admitted here for this crate alone. The alternative, `tray-icon` on Linux, needs GTK3
    and `libappindicator` at build time, which §8 forbids in the default build. `ksni`
    reaches the session bus over one local socket, in one file, with no network
    capability, and the no-network check is narrowed to assert exactly that.
14. **One file per pack:** a pack is JSON plus a detached signature, never an archive.
    Refusing to extract anything removes zip-slip, permission bits and symlink entries
    from the attack surface by construction.
15. **Close-to-tray is off by default.** A resident security tool that hides on close is
    the behaviour §4 exists to reject. The tray is an icon for a window that is still
    there, not a replacement for it.
16. **The first-party catalogue ships inside the binary** as `packs/ranger.core.json`,
    validated by the same validator an imported pack meets. It is the catalogue, not a
    download: v0.x has no way to fetch one.
17. **A rule names its technique.** First-party rules carry an ATT&CK id where one
    applies, and `docs/RULES.md` renders the coverage by tactic. A public taxonomy is
    what makes "we know attacks" a table with rows instead of an adjective.
18. **Release candidates before the tag.** `0.1.6-rc.N` is published as a pre-release so
    the soak and the manual matrix run on the binary a person downloads.

**Still owed**

1. **Code signing:** Windows EV and Apple Developer ID certificates, and who holds them.
2. **Platform floor:** Windows 10 1809+, macOS 13+, glibc 2.35+ (Ubuntu 22.04)?
3. **Localisation:** English only until v1.0?
4. **Agent scope:** confirm the process, network and persistence boundary, with no
   prompt or content inspection. The 0.1.6 answer is narrower than the question: ranger
   reads configuration files that name a program to run, and never a prompt, a model or
   a conversation.
5. **Funding:** donations only, or no funding at all. No paywall either way.
6. **The second reviewer:** who holds the review for the action path when the maintainer
   is the author. This is the one process item 0.1.6 cannot solve with code.

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
- ksni — <https://github.com/iovxw/ksni>
- StatusNotifierItem — <https://www.freedesktop.org/wiki/Specifications/StatusNotifierItem/>
- cap-std — <https://github.com/bytecodealliance/cap-std>
- minisign — <https://jedisct1.github.io/minisign/>
- minisign-verify — <https://github.com/jedisct1/rust-minisign-verify>
- MITRE ATT&CK — <https://attack.mitre.org/>
- ATT&CK on boot or logon autostart — <https://attack.mitre.org/tactics/TA0003/>
- systemd unit and timer semantics — <https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html>
- launchd.plist — <https://www.manpagez.com/man/5/launchd.plist/>
- Task Scheduler schema — <https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema>
- single-instance — <https://crates.io/crates/single-instance>
