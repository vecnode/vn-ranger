# The plan — v0.1.7, *Inside*

**Status:** a proposal for the release after 0.1.6. It supersedes the M6 milestone in
[`PLAN.md`](PLAN.md) §9, which was written as a coverage patch before this scope was
asked for; M6's rows are carried into §8's Wave 0 rather than dropped.

**Audience:** the owner, who has to take the seven decisions in §14; a contributor who
has to write one of the waves; and anyone deciding whether this program should be
allowed to look inside their files, their logs and their connections.

**What this document is:** the audit that says where the application actually stands, the
reconciliation that says what should be merged rather than added, the research behind
four new evidence domains, the feature catalogue with a verdict on every row, and the
order in which the work gets built.

**What it is not:** a promise that all of it ships in one release. §9 names what a wave
may leave behind, and the changelog will name it again.

---

## 1. The short version

0.1.6 made ranger able to act, stay resident, and learn a technique without a rebuild.
It still sees the machine from the outside: names, paths, hashes, sockets, and what
starts on its own.

**0.1.7 makes it see inside four things it currently treats as opaque** — the bytes of a
file, the record of an event, the flow of a connection, and the configuration of an
autonomous agent — and it does so **without a network call, a kernel driver, a model or a
score**.

| Domain | Today | In 0.1.7 |
|---|---|---|
| Bytes | A hash, and (behind a feature flag) YARA-X over named folders | Hash, extended body signatures, container walking, structural facts, signature facts |
| Events | Nothing | Windows event logs, the Linux journal, the macOS unified log — read as files and as bounded child processes |
| Flows | Listening sockets only | The connection table with process ownership, per-process byte counters where the platform gives them, and beaconing as a pure function |
| Agents | Process heuristics and a config reader | A capability matrix and provenance: what an agent can reach, who installed it, and what changed |
| Evidence | A journal and a report | A hash-chained journal, one merged timeline, one triage package, one sweep |

The sentence the release should be able to say:

> Ranger now reads the bytes, the logs, the connections and the agent configuration on
> your machine, and tells you what it found with the evidence beside it — offline, in one
> binary whose archive is under 10 MB, and without a single packet it did not observe
> locally.

**What it is still not:** an engine, a service, a fleet agent, a sandbox, a cloud lookup,
or a number that calls itself a threat score. The constitution in
[`AGENTS.md`](../AGENTS.md) §2 is unchanged and every wave below is judged by it.

---

## 2. Where the application stands

### 2.1 The inventory of capability

Measured against the tree on 2026-10-18 (`main` at `3353974`, version 0.1.6, tag
`v0.1.6-rc.1`). 90 Rust files, 27,559 lines, 374 tests, three crates and one shell.

| Capability | Where | State |
|---|---|---|
| Processes and ancestry | `native/src/collect/processes.rs` | Shipped, 2 s poll, identity is `(pid, start time)` |
| Autoruns, 21 Windows surfaces through one `KeyReader` | `collect/autoruns/` | Shipped, each surface has a fixture that runs on any host |
| launchd, systemd, the Linux loader surfaces | `collect/autoruns/{macos,linux}` | Shipped; Linux captured from a real Ubuntu, **macOS captures owed** |
| Listening sockets | `collect/listeners/` | Shipped on Windows and Linux; macOS reports unavailable |
| Scheduled tasks | `collect/tasks/` | Shipped, XML parsed from fixtures, needs elevation for the system folder |
| Packages | `collect/packages/` | Shipped, four sources |
| Agent stack (SSH, MCP config) | `collect/agentstack/` | Shipped, the `agent` subject is matchable |
| Hash signatures (`.hdb`, `.hsb`) | `native/src/signatures.rs` | Shipped, 3 algorithms, rejects malformed lines by count |
| 15 built-in detectors | `core/src/rules.rs` | Shipped, each with a positive and a negative fixture |
| 12 signed pack rules, 11 techniques | `packs/ranger.core.json` | Shipped, embedded with `include_str!`, coverage table generated |
| Quarantine, verified restore, typed delete | `native/src/quarantine.rs`, `action.rs` | Shipped, four refusals, journal before the act |
| Allowlisted cleaning | `native/src/clean.rs`, `core/src/clean.rs` | Shipped, dry run off the frame's thread |
| Tray, scheduler, autostart, wake | `native/src/{tray,autostart}.rs`, `core/src/schedule.rs` | Shipped |
| Nine views | `crates/ui/src/views.rs` | Overview, Findings, Processes, Startup, Listeners, Changes, Actions, Report, Settings |
| Content scan (YARA-X) | `native/src/contentscan/` | Feature-gated, consent sentence and button exist, no rules bundled |

That is a real product, and §3 exists to stop 0.1.7 from rebuilding it.

### 2.2 What is measured, and what is only claimed

| Measure | Number | Source |
|---|---|---|
| Inventory scan | 1.2–1.8 s | `BENCHMARKS.md`, Windows 11, 287–291 processes |
| Idle working set | 166 MB (0.1.1), 171.6–173.0 MB (0.1.2) | measured, wgpu backend |
| Idle CPU with poll and watcher | 0.387% of one core over 30 min | measured |
| Release archive | 6.83 MB Windows, 8.77 MB Linux, 5.69 MB macOS | measured, 0.1.1 |
| **Release binary, Windows** | **18,856,960 bytes (18.0 MB)**, built 2026-10-18 | measured in this tree |
| 24-hour soak | not run | owed since 0.1.6 |
| Journal write, quarantine move, clean preview | not measured | promised targets in `PLAN.md` §11 |

Two of those rows disagree with the project's own public claim. The repository
description says *"single Rust binary ~6–9Mb"*, and the plan's budget says the archive is
≤ 12 MB. Both are true of the **archive** and neither is true of the **binary**, which is
18 MB. §10 fixes the vocabulary: an archive budget, a binary budget, an installed
footprint budget, and a rule that a claim names which one it is about.

### 2.3 The truth gaps

Six things are currently untrue, vague or split, and Wave 0 exists for them.

1. **The status lines are one release stale.** `AGENTS.md` says 0.1.5 is released and
   0.1.6 is next; `PLAN.md`'s header says the same; `Cargo.toml` says 0.1.6 and the
   changelog is dated. Three documents, two answers.
2. **The coverage table counts half the rules.** `cargo xtask coverage` builds the table
   from the pack only, so the 15 built-in detectors do not appear in the one document
   that claims to say what ranger detects. 12 of 27 rules are visible.
3. **There are two rule engines and no shared registry.** Both are good; both carry the
   same eight fields; nothing enumerates them together.
4. **The size claim names the wrong artifact** (§2.2).
5. **0.1.6's own debts are open**: the second reviewer on the deletion paths, the
   24-hour soak on a candidate, the macOS captures, WMI subscriptions, Linux user
   `crontab`/`at`, and the data-folder size in Settings (the folder is shown; its size
   is not).
6. **The suite has drifted**: vn-launcher is on egui 0.36 and ranger on 0.37, and nothing
   in either repository says which one wins.

### 2.4 What must not be rebuilt

The bones are good and this plan spends its budget on capability rather than on
reorganisation. Specifically:

- The **typed action path** (`RootId` + `EntryId`, four refusals, `cap-std`) is the only
  way anything destructive happens, and every new response in §4.6 goes through it.
- The **journal protocol** — intent synced before the act, result after — is what makes
  a new destructive verb safe to add. §4.6 adds a hash chain to it; it does not replace it.
- The **pack pipeline** — verify before parse, closed vocabulary, `benign` required,
  `attention` as the ceiling — is extended with new subjects, never bypassed.
- The **`Outcome` contract** for collectors (`Items` / `Partial` / `Unavailable`) is the
  reason an empty list is never read as "nothing found". Every new reader in this release
  returns one.
- The **language audit** is part of the product. It gains words in §9 rather than losing
  them.

---

## 3. What should be merged

"Merged" here means two different things, and both matter: the release history has to be
reconciled, and the product has several pairs of things that answer the same question
twice.

### 3.1 The release history

| Fact | Today | Action |
|---|---|---|
| `main` | `3353974` "v0.1.6 — act, resident and packs" | — |
| `release/0.1.6` | `0352014`, one commit behind `main` | Fast-forward to `main` |
| `release/0.1.7` | `3353974`, identical to `main` | Keep; it is the branch 0.1.7 is cut from |
| Tags | `v0.1.0`…`v0.1.5`, `v0.1.6-rc.1` | Cut `v0.1.6` at `3353974` (the owner's decision: 0.1.6 ships as it stands), non-draft, per `docs/RELEASES.md` |
| Changelog | `[0.1.6] — 2026-10-18` | Open `[0.1.7] — Unreleased` in the same commit as the version bump |

`v0.1.6-rc.1` is an annotated tag that peels to `3353974`, the same commit as `main`, so
the release is cut from the candidate that passed rather than from a new build. The release
notes say exactly that.

### 3.2 The product

| Pair | Why it is two things | Merge into | Why it pays |
|---|---|---|---|
| 15 built-ins + 12 pack rules | Built-ins are Rust functions; packs are data | One `RuleRegistry` in `vnr-core` that both register into, with the same `RuleMeta` | `cargo xtask coverage` counts 27 rules; "what do we detect" has one answer; a new subject is added in one place |
| Three scanning paths (the inventory hash pass, the watcher's hash, the content walk) | They grew at different times, each with its own loop and its own cancellation | One `evidence::pipeline` with one budget, one cancellation token and one progress channel | The new content engine cannot become a fourth; §10's budgets are measured in one place |
| Changes view + Actions journal | Changes is in memory, Actions is on disk | One **Timeline** view with source filters (`session`, `journal`, `event`, `flow`, `agent`) | The forensics payoff in §4.6 is a timeline; two half-timelines is how a blue team loses an hour |
| Two agent concepts (process heuristics, `agentstack` config) | One is behavioural, one is configuration | One `agent` subject with `origin` and `capability` fields | §2.3 of `PLAN.md` — the model is not the evidence, the behaviour is — and the behaviour now has an owner |
| Provenance, four ways | package manager, vn-launcher, skill install, download | One `origin` field on every fact that can have one | "Who installed this" is the first question in triage and the current answer is a guess from the path |
| Size vocabulary, three ways (archive, binary, installed) | §2.2 | Three named budgets in §10, and every claim in README, PLAN and the release notes names which one it is | A claim that cannot be checked is a claim that will be wrong |
| egui, two versions in one suite | vn-launcher 0.36, ranger 0.37 | One version across the suite, decided once, in the launcher's favour if the launcher ships first | Two audits of one dependency for cosmetic reasons |

The `RuleRegistry` merge is the only one that touches code in more than one crate, and it
is deliberately behaviour-preserving: the same 27 rules, the same severities, the same
subjects. A merge that changes findings is a feature wearing a merge's clothes.

---

## 4. What should be developed

Four evidence domains and one evidence product. Each subsection states the fact, the
engine, the rule vocabulary it needs, the consent it requires and what it refuses.

The architectural rule that keeps this from becoming four products:

> **The join happens in the fact builder, not in the rule language.** A pack rule still
> matches one subject with a closed vocabulary. When a rule needs to know that a process
> is unsigned *and* autostarted *and* holds a connection, the fact builder publishes
> `process.signed`, `process.autostart` and `process.remote_count`, and the rule reads
> three fields of one subject. There is no correlation language, no SQL, and no place for
> a rule to walk the machine.

### 4.1 Content — the bytes

**The fact.** A file has bytes, a type, a structure, and possibly a second file inside it.
Today ranger knows a hash and a name.

**The signature layer**, in the order it pays for itself (full ladder in §6):

1. **Extended body signatures** (`.ndb`): `name:target:offset:hex` with `??` wildcards,
   `{n-m}` gaps, `(aa|bb)` alternation, and the `EP`, `SL`, `EOF` offsets. This is a
   documented format, it is data, and a reader is a few hundred lines with a fuzz target.
   It is the single largest detection win per line of code in this plan.
2. **Containers**: zip, tar, gzip, OLE2 (Word/Excel macro storage), 7z, and an embedded
   PE/Mach-O found at an offset in an arbitrary file. Bounded by layers (3), streams
   (100), bytes per stream (64 MB), total bytes (256 MB), and a compression-ratio cap that
   stops a zip bomb before it is read.
3. **Structural facts** for PE, ELF and Mach-O: sections and their entropy, imports and
   the import hash, the overlay, the linker and timestamp, whether a signature is present.
   Facts, not verdicts: "this binary has a 7.94-bit section and no imports" is a sentence
   a person can act on; "packed: 87%" is not.
4. **Signature facts**: for PE, the Authenticode blob parsed and its digest compared to
   the file's; for Mach-O, the code-signature blob and its identifier; for ELF, whether a
   build-id exists at all. The fact is *"carries a signature and the digest matches"* —
   not *"Windows trusts it"* — because evaluating a certificate chain needs a platform API
   this workspace will not call without a safe wrapper, and saying "trusted" when the
   chain was never evaluated is the exact lie `AGENTS.md` forbids.

**What it refuses.** Bytecode signatures (`.cbc`) are a C-like VM distributed as data.
Loading one means executing attacker-authored logic inside the scanner: it is a second
engine, it is not safe Rust, and it is the opposite of "rules are data, not code". Ranger
reads the format's *documentation* and refuses the format. PCRE subsignatures are refused
for the same release on size and denial-of-service grounds (a regex engine over
attacker-chosen bytes is a worse trade than a hex matcher). No unpacker that needs C
(`unrar`), and nothing that extracts to disk.

**The signature database is a separate file from a rule pack**, with the same detached
`minisign` signature, because they are different things: a signature answers *"is this
byte string here"*, a rule answers *"does this machine's state mean something"*. One file
per kind, one format each, both verified before parsed.

**Consent.** Bytes are not read without a person asking. The existing
`content-scan` feature's consent sentence is the model: it names the folders, the file
cap, the depth and the fact that bytes are read. 0.1.7 adds: exclusions, a per-run budget,
a progress line with a cancel, and a scheduler rule that a deep check never runs
unattended unless the person turned it on.

### 4.2 Time — the events

**The fact.** Something happened at a time, and the operating system wrote it down.

The design decision that keeps this inside the constitution: **ranger reads the logs as
files, not as a subscriber**. There is no ETW consumer, no `auditd` plugin, no
EndpointSecurity client, no eBPF program — each of those needs a privileged component, and
`unsafe` or a kernel driver to reach. Reading the artefact is what a forensic tool does,
it needs no privilege ranger does not already have, and it works on a machine that has
already been rebooted and on a log copied from another one.

| Platform | Source | Method | Honest limit |
|---|---|---|---|
| Windows | `…\winevt\Logs\*.evtx` | Pure-Rust `evtx` parser (MIT OR Apache-2.0, `unsafe` forbidden) | `Security.evtx` needs elevation; the collector says so rather than returning nothing |
| Linux | journald, then `/var/log/auth.log` | `journalctl --output=json` as a bounded child process; file parse as fallback | A machine without journald gets the file reader and a named state |
| macOS | the unified log | `log show --style json` as a bounded child process | Slow and noisy; a 15-minute window, not a day, and it says which |

The `event` subject carries channel, provider, event id, time, user, and a bounded field
map (the top 24 fields, never the whole record). Rules match on fields the same closed
vocabulary already uses.

**Two of those three readers are external programs, and the plan treats them as such.**
`journalctl` and `log show` may be absent, may be shadowed by something else on `PATH`, and
their output is untrusted text like any other input. So: an absolute path and an argument
array (never a shell string, as §2 requires), a timeout, a record cap, a parser with a
fixture from a real machine, and a missing program reported as `Unavailable { reason }` that
names it. The Windows reader needs no program at all, which is why it is the one that ships
first.

**The first-party event rules** are the twelve that are high-signal on a single host, each
with a positive and a negative fixture: log cleared (1102/104), a service installed with
its binary outside `System32` (7045), a scheduled task created (4698), a process started
from a temporary or download folder with a shell parent (4688/Sysmon 1), an encoded
PowerShell command (4104), a Sysmon network event from a temporary binary (3), a local
account created (4720), an audit policy changed (4719), a Defender exclusion added
(5007), a driver loaded from a user-writable folder, a PowerShell download cradle, and a
RDP logon from a new address. Eleven of the twelve require logging the machine may not
have enabled; the release notes say which, because **"we saw nothing" and "the log was
off" must not look the same**.

### 4.3 Flows — the connections

**The fact.** A process holds a socket to somewhere, for a while, at a rhythm.

This is the domain where the honest scope is narrowest, and narrowing it is what makes it
shippable:

- **Flow-level, not packet-level.** There is no pcap capture in the default build. Capture
  needs `libpcap`/`Npcap` on Windows (a C dependency and a driver install), root or BPF
  access on macOS, and `CAP_NET_RAW` on Linux — three privilege stories and a C toolchain
  for a feature the plan can approximate with the connection table it already reads.
- **No DNS resolution.** ranger never sends a query. A remote address is shown as an
  address; a name is shown only if the operating system already cached it and the platform
  exposes that cache without a privileged call.
- **Sampled, not subscribed.** Every 4 s the connection table is read and diffed into
  flows: `(pid, protocol, local, remote, state, first_seen, last_seen, bytes)`.
  `bytes` is `null` where the platform cannot give it per connection without an FFI call
  this workspace will not make, and a `null` is printed as unknown, never as zero.

**Beaconing** is the one analytic here and it is a pure function with fixtures: for a
`(process, remote)` series with at least six contacts, compute the intervals, require a
median inside 20 s–2 h and a coefficient of variation under 0.15, and report *the
intervals and the jitter as evidence* — "18 connections to 203.0.113.9 at 60 s ± 2 s" —
never as a score. A CI runner polling an API looks exactly like this, which is why the
finding names the benign explanation (a scheduled client) before it names anything else.

**The export** is a Zeek `conn.log`-shaped TSV, because every blue team already has a
parser for it.

### 4.4 Autonomy — the agents

**The fact.** A thing on this machine acts without a person in the loop, and something
installed it.

0.1.6 reads SSH configuration and MCP client configuration. 0.1.7 makes the agent a
first-class object with two things a person cannot currently get anywhere for free:

- **A capability matrix, not a verdict.** For each agent, skill, MCP server and plugin:
  can it execute (does it ship scripts, does its configuration name a command), can it
  reach the network (a URL in a script or a config), can it write files (a path in a
  script), does it hold credentials (reads `~/.ssh`, `.env`, a keychain path), can it call
  a model (an endpoint in a config). Five booleans and the line that produced each.
- **Provenance.** Which launcher, package manager, skill marketplace or manual copy put it
  there, when, and with which hash — read from what the suite already records locally.

The skills model is not hypothetical. VirusTotal reported in February 2026 that of 3,016
OpenClaw skills analysed, hundreds were malicious — droppers, backdoors, infostealers and
remote access tools disguised as automation, distributed through a public skill
marketplace called ClawHub, and structured as a `SKILL.md` plus scripts
([VirusTotal, 2026](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html)).
The same shape exists inside this suite: vn-code bundles plugins, skills and interfaces,
and vn-launcher installs it. **Ranger is the program in the suite that can say what those
packages are allowed to do.**

It refuses: reading a prompt, a conversation, a model, or a completion. The agent's
*configuration* is a fact about the machine; its conversation is not ranger's to read, and
`PLAN.md` §14.2 decision 4 is unchanged.

### 4.5 The rule vocabulary, version 2

Four new subjects, one new join, no new language.

| Subject | Key fields | Kind |
|---|---|---|
| `file` | `path`, `name`, `extension`, `size`, `entropy`, `type`, `signed`, `signer`, `in_container`, `container_depth` | text/number/bool |
| `event` | `channel`, `provider`, `id`, `time`, `user`, `image`, `command`, `parent`, `target`, `remote`, `port` | text/number |
| `flow` | `process`, `pid`, `remote`, `port`, `protocol`, `state`, `first_seen`, `last_seen`, `bytes`, `beacon_interval`, `beacon_jitter`, `contacts` | mixed |
| `agent` | existing, plus `origin`, `installed_at`, `hash`, `executes`, `network`, `writes`, `credentials`, `model` | mixed |
| `process` joins | new fields `signed`, `autostart`, `remote_count`, `beaconing`, `file_written` | mixed |

A pack declares `vocabulary: 2`. A 0.1.6 binary refuses a v2 pack with a reason rather
than loading half of it; a 0.1.7 binary loads a v1 pack unchanged. The coverage table
counts both engines (§3.2) and the refusal a rule with no fixture gets is a build error.

### 4.6 Acting, from 0.1.7

The four domains are read-only, and a program that only reads cannot fix what it finds. The
owner's decision of 2026-10-20 adds the first destructive verb since quarantine, in the
same release: **add and remove a startup entry**, user scope, through the typed action path
and nothing else.

- **No new privilege.** `HKCU\…\Run`, `HKCU\…\RunOnce` and the user's Startup folder are
  writable by the account ranger already runs as. A machine-scope entry is refused with a
  reason, because removing it needs an administrator and there is no standing elevation.
- **Nothing takes a path.** The identity is the `AutorunFact` id the scan produced, resolved
  from the surface's own root; a path a person types is not a way to reach the registry.
- **Journal, then act, then result.** A removal writes the previous value into the journal
  entry, so what was removed can be put back by hand, and a `.lnk` is moved into the
  quarantine rather than deleted.
- **The four refusals still apply**, and each has a test: a machine-scope surface, a link or
  a hard link, a value that changed between the scan and the act, and a name that was not in
  the scan the interface showed.

Wave 4 of [`NEXT.md`](NEXT.md) carries the steps; the deletion matrix in `AGENTS.md` §12 and
the second reviewer are required before it ships.

### 4.7 Evidence — the product

The four domains are only worth what a person can hand to somebody else.

- **The journal gains a hash chain.** Every entry carries
  `hash = sha256(prev_hash ‖ canonical_json(entry))`, with a fixed genesis. On startup and
  on demand the chain is verified; a mismatch is a named state — *"the record does not
  verify after entry 1,842"* — and never a silent pass. It costs microseconds and it turns
  an append-only file into evidence that tampering is visible.
- **One timeline.** Session events, journal entries, log events and flow observations, in
  UTC, source-tagged, exportable as CSV and as a `bodyfile` for Plaso/`mactime`. The
  Timeline view is the merge in §3.2.
- **One triage package.** An opt-in export to `<data>/exports/triage-<time>/`: a manifest
  with the version, host, time and the SHA-256 of every file inside; `snapshot.json`;
  `findings.md`; `timeline.csv`; `bodyfile.txt`; `events-<channel>.jsonl`; and a `README`
  that says what it is and what it is not. Zipped, journalled, and never uploaded.
- **One sweep.** Given a set of indicators — hashes, paths, domains, addresses, rule ids —
  ranger looks in all four domains, previews what it matched, and offers quarantine for
  the files through the **existing** typed path. It is the closest thing to a "scan now
  find everything" button that stays honest: the sweep reports what it did *not* search.

---

## 5. Prior art, 2026

Read from the repositories and documentation in October 2026. Licences marked † were
confirmed this session; the rest are as recorded in `PLAN.md` §3.

| Project | Licence | What it does | What ranger takes | What it leaves |
|---|---|---|---|---|
| [ClamAV](https://docs.clamav.net/) | GPL-2.0 | Signature engine, 1.5.4 current, signature formats documented in detail | The **formats** (`.hdb`/`.hsb`/`.ndb`/`.ldb`), the container discipline, the FLEVEL idea that a signature declares what it needs | The engine, the bytecode VM, the copyleft |
| [YARA-X](https://virustotal.github.io/yara-x/) | BSD-3-Clause † | Rust pattern engine, 1.0 stable June 2025, 5–10× faster than YARA on heavy rules, ~99% rule compatibility | The optional content engine ranger already has, behind its consent screen | A default dependency; bundled rules |
| [evtx](https://github.com/omerbenamram/evtx) | MIT OR Apache-2.0 † | Pure-Rust Windows event log parser, `unsafe` forbidden, ~20 ms for 30 MB at 8 threads | The parser for §4.2, and the evidence that a forensic reader can be safe Rust | Nothing |
| [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) | GPL-3.0 † | Rust DFIR triage: EVTX + Sigma, Shimcache/Amcache/SRUM/MFT, record-gap detection | The artefact list, the "first response" framing, the gap idea | The code (copyleft), the hunting-style rules |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | AGPL-3.0 †, rules DRL 1.1 | Windows event-log timeline generator with full Sigma support | The timeline output discipline and the rule-status vocabulary | Code and rules |
| [Sigma](https://github.com/SigmaHQ/sigma) | DRL 1.1 | Portable detection rules | The import path that already exists; the field naming it uses | The rules themselves — never vendored |
| [osquery](https://github.com/osquery/osquery) | Apache-2.0 **or** GPL-2.0 | Machine state as SQL tables | "Facts, not verdicts"; the column naming a forensic reader expects | The SQL surface and the fleet |
| [Zeek](https://zeek.org/) | BSD-3-Clause | Network security monitor with a canonical `conn.log` | The **export schema** for §4.3, so ranger's flows are readable by tools people already run | Any capture, any packet |
| [libpnet](https://github.com/libpnet/libpnet) | Apache-2.0 † | Cross-platform packet capture and parsing | Nothing yet — it is the dependency a future capture mode would need, and Windows still means Npcap | A C toolchain and a driver in the default build |
| [Sniffnet](https://github.com/GyulyVGC/sniffnet) / [bandwhich](https://github.com/imsnif/bandwhich) | MIT | Network monitors that show traffic per process | The presentation idea: a process, a remote, a number | Their capture stack |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | AGPL-3.0 | DFIR collection at fleet scale | The triage-package shape and the "collection scope is stated" discipline | The server, the VQL |
| [Loki](https://github.com/Neo23x0/Loki) | GPL-3.0 | Indicator-of-compromise sweep | The sweep in §4.6 and the IOC file shapes | Python, network-fed lists |
| [Plaso](https://github.com/log2timeline/plaso) | Apache-2.0 | Super-timeline tooling | The `bodyfile` export target | The Python |
| [KnockKnock](https://objective-see.org/products/knockknock.html) / [Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns) | GPL-3.0 / proprietary | Persistence inventory | The surface list, which 0.1.6 already read | Code |
| [OpenClaw skill abuse](https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html) | — | 3,016 skills analysed, hundreds malicious, delivered through a marketplace | The `SKILL.md` + scripts shape that §4.4 inventories | Trusting a marketplace |
| [MCP: Landscape, Security Threats](https://dl.acm.org/doi/10.1145/3796519) | — | Research on tool poisoning: malicious logic behind a legitimate interface | The capability-matrix framing for MCP servers | Model-based detection |
| [Microsoft Defender for AI agents](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection) | proprietary | Commercial agent discovery | Confirmation the category is real | Everything else |

### 5.1 What the research changed

1. **The gap is not signatures — it is time and context.** Every strong open-source
   project above is a *reader* (evtx, Chainsaw, Hayabusa, Zeek). Ranger's advantage is
   that it is already resident, already has a baseline, and already knows what starts on
   its own. Adding readers to a resident fact model is cheaper than adding a fact model to
   a reader.
2. **ClamAV is a format, not a program, for an MIT project.** Its signature families are
   documented well enough to implement cleanly; its engine and bytecode are not linkable
   and would be the wrong dependency even if they were.
3. **Bytecode is the line.** ClamAV's `.cbc` is a C-like VM. A scanner that loads
   attacker-authored programs to decide whether a file is malicious has imported the
   problem it was hired to solve.
4. **The agent supply chain is now a malware channel, and it is a suite problem.** A
   marketplace of skills that run shell commands is a soft target; the program that can
   inventory and quarantine them should be in the same suite that installs them.
5. **Flow-level is enough to be useful and small.** Zeek exists because packets are rich;
   the connection table exists because they are expensive. A resident app that samples it
   and reports a rhythm catches beaconing, which is most of what a single host needs.

---

## 6. The detection ladder

The claim "as good as a modern ClamAV" is not a size or a count; it is a set of layers
with a decision on each. This table is the whole claim.

| L | Layer | What it answers | 0.1.7 | Cost and licence |
|---|---|---|---|---|
| L0 | Hash (MD5/SHA-1/SHA-256) | is *this exact file* known bad | shipped | ours, free |
| L1 | Extended body signatures (`.ndb`) | is this byte pattern here, with wildcards and gaps | **develop** | ours, a few hundred lines |
| L2 | Logical signatures (`.ldb`) | do these patterns co-occur with these counts | 0.1.8 — it needs per-subsig counts, negation and a bounded matcher | ours |
| L2′ | PCRE / macro / byte-compare subsigs | regex and arithmetic inside a signature | **refused in 0.1.7**: a regex engine over hostile bytes is a denial-of-service surface and a size cost the release cannot pay | — |
| L3 | Pattern rules (YARA-X) | a full rule language over content | stays optional, consent-gated, no rules bundled | BSD-3, ~3 MB when enabled |
| L4 | Structural facts (PE/ELF/Mach-O) | what kind of file is this, really | **develop**: sections, entropy, imports, imphash, overlay, signature presence | `goblin` or `object`, small |
| L5 | Fuzzy (TLSH, icon pHash) | is this a variant of something | 0.1.8 | TLSH crate, small |
| L6 | Containers | what is inside this file | **develop**: zip, tar, gz, OLE2, 7z, embedded PE, PDF streams | `zip`, `flate2`, `cfb`, pure Rust |
| L7 | Reputation / cloud / MultiAV | what does the internet think | **never** | a network call |
| L8 | Bytecode VM (`.cbc`) | run this program to decide | **never** | code execution in the scanner |
| L9 | Emulation / sandbox | what does it do when run | **never** | a hypervisor, a kernel driver, a fleet |

**What a scan actually does** when a person presses *Deep check* on a folder:

```text
walk (bounded, no link, cancel) ─▶ hash ─┬─▶ L0 match?  ── finding
                                         ├─▶ L1 match?  ── finding (offset, rule)
                                         ├─▶ L4 facts  ──▶ rule over `file` subject
                                         └─▶ L6 container ─▶ recurse (3 layers, capped)
                                                              └─▶ L3 if enabled
```

Every arrow is cancellable, every stage has a byte budget, and the report says which
stages ran, which were skipped for size, and which engine was not built in. A scan that
cannot say that is a green tick, and this project does not ship green ticks.

---

## 7. The feature catalogue

Every row has a verdict. The first table is the release; the second is the line after it;
the third is the list that keeps the project honest.

### 7.1 In 0.1.7

| # | Feature | Why it is worth it | Effort |
|---|---|---|---|
| F1 | Extended body signatures (`.ndb`) | Turns ranger from "matches the hashes in one local file" into "can consume a real signature corpus" | M |
| F2 | Container walking with a bomb guard | Most malware arrives inside something | M |
| F3 | Structural file facts (PE/ELF/Mach-O) | "Packed, no imports, entry point in the last section" is a sentence a person can act on | M |
| F4 | Signature facts (Authenticode, Mach-O, ELF build-id) | Unsigned-and-user-writable is the highest-value rule in the pack and currently unprovable | S |
| F5 | Deep check with exclusions, budget, progress, cancel | Bytes are only read with consent and only for as long as a person allows | S |
| F6 | Event readers: `evtx`, `journalctl`, `log show` | The single biggest forensics unlock available to a resident app | M |
| F7 | Twelve first-party event rules | Makes the reader useful on day one, with the log-off case stated | M |
| F8 | Flow facts with process ownership + Zeek export | "Which process is talking to what" is the question people actually ask | M |
| F9 | Beaconing as a pure function | Catches a class of C2 no signature will | S |
| F10 | IOC lists in a signed pack, and one sweep across all four domains | The "check everything I know" button, offline | M |
| F11 | Agent and skill inventory with a capability matrix | The differentiator nobody else has, and the suite makes it concrete | M |
| F12 | Hash-chained journal with a verification verdict | Evidence that survives being handed to someone else | S |
| F13 | One timeline, CSV + `bodyfile` | Interoperates with the tools an analyst already has | S |
| F14 | Triage package export with a hashed manifest | The thing a blue team asks for first | M |
| F15 | The size programme (§10) | Pays for F1–F14 out of the renderer change | M |
| F16 | Lineage: what started this process, what it started | Cheap, and unique among free tools | S |
| F17 | Ransomware burst detection over the existing watcher | A write-rate spike with extension changes is a real, honest alarm | S |
| F18 | Signature and rule age, on the overview | "Your last signature file is 412 days old" is a fact that changes behaviour | XS |
| F19 | A hash allowlist for developer machines | Cuts the noise that makes people stop reading findings | S |
| F20 | Driver inventory with signature facts, and a vulnerable-driver list as pack data | BYOVD is the standard way past a signed-only policy | M |
| F21 | Removable-media inventory and diff | Cheap, and the oldest delivery route there is | S |
| F22 | Agent, MCP and skill diff against the baseline | "A new MCP server appeared on Tuesday" is the alarm this suite needs | S |
| F23 | Finding correlation on one subject (§4.5 joins) | One finding that says four things beats four that say one | M |

### 7.2 The line after it (0.1.8, named now so it is not smuggled in)

| # | Feature | Why it waits |
|---|---|---|
| G1 | Logical signatures (`.ldb`) | Needs a matcher with counts and negation; do L1 properly first |
| G2 | TLSH and icon fuzzy hashing | Needs L1 and L4 to have something to cluster |
| G3 | Reversible autorun disable | A new destructive verb needs its own consent screen and two reviewers, exactly as quarantine did |
| G4 | An elevated event scan (Security log) | Extends the one-shot elevated copy to a second named operation |
| G5 | Linux user `crontab`/`at`, with elevation | Carried from 0.1.6; needs a fixture from a machine this project does not have |
| G6 | macOS login items | Needs an `objc2` wrapper and the same review as any new safe binding |
| G7 | Browser extension inventory (metadata only) | Privacy-adjacent; needs its own decision |
| G8 | Sigma correlation and aggregation | Sigma v2 correlation is a second language; the importer stays a subset |
| G9 | WMI subscriptions | Carried from 0.1.6; still needs a machine that can prove it |
| G10 | Scan profiles and a schedule editor | The scheduler exists; the interface for it is a week nobody has spent |

### 7.3 Refused, with the reason attached

| Feature | Why not |
|---|---|
| Cloud reputation, multi-engine upload, "check this hash online" | One network call turns the privacy claim into a promise about a server. It is also the feature that makes a program need an account |
| Bytecode signatures (`.cbc`) | A VM for attacker-authored code inside the tool that inspects attackers |
| Kernel driver, minifilter, ETW consumer, eBPF, EndpointSecurity client | Privilege plus `unsafe` plus a component that outlives the window: §2 of `AGENTS.md` |
| Packet capture in the default build | A C dependency, a driver install on Windows and root on macOS for a fraction of what the connection table already says |
| Memory scanning, process dumps, injected-code detection | Needs a privileged reader and reads things a person did not consent to |
| Reading prompts, conversations, model inputs | The agent's configuration is a fact; its conversation is not ranger's to read |
| A model in the product | `PLAN.md` §14.2 decision 9, unchanged |
| A numeric threat score | A number without its evidence is a lie with a decimal point |
| Registry cleaning, "junk" scores, RAM boosting | The category's original sin |
| Browser history, downloads history, cookies | Not a security fact; a privacy liability |
| Auto-quarantine without a person | The first false positive that removes a work file ends the product's credibility |
| Self-update, signature pull, telemetry | vn-launcher's job, with consent, and not ranger's |

### 7.4 The ten that would make someone switch

In rough order of how much they would move a person from "I have a scanner" to "I have a
ranger":

1. **It tells you what is talking to the internet, per process, with evidence.**
2. **It reads the logs the system already wrote and explains them in sentences.**
3. **It knows what the autonomous things on the machine can do — before they do it.**
4. **It shows what changed since Tuesday, in persistence, in skills, in connections.**
5. **It quarantines a skill or a binary with a revert that works.**
6. **It hands an analyst one folder with a manifest, a timeline and the evidence.**
7. **It never uploads anything, and the number under 10 MB is the proof of how little is
   in it.**
8. **It tells you when its own signatures are stale instead of pretending.**
9. **It says "the log was off" instead of "nothing found".**
10. **It is MIT, one binary, no service, and it does not hide.**

---

## 8. The waves

**Progress, 2026-10-20.** Built on `dev`, in order, each with its tests and a green
`cargo xtask ci`:

| Wave | Built | Commit |
|---|---|---|
| 0 | One rule table (`Rule` public, technique or written reason, coverage counts both engines); version and size truth | `910c5bd` |
| 1 | `.ndb` reader and matcher with a budget; the bounded, cancellable deep check; `file` and `file-match` subjects; two content rules; the Settings card | `00d7bbe` |
| 3 | The connection table with process ownership (Windows, Linux); the `flow` subject and its join; one rule; the Zeek export; the beaconing analytic and its bounded sampler; the poll that feeds it and `flow.beaconing` | `54265cb`, `8066811`, `c5a2e7c`, `d3f3027` |
| 5 | The journal hash chain with its three-state verdict and the Actions-view line; the timeline CSV export | `9d76250`, `4457935` |
| 4 | The skill reader: `SKILL.md` frontmatter (an unclosed header is body, not metadata) and the five capability kinds with the line that proved each; the collector that finds the folders, the package digest, the matrix as five booleans, and `agent.skill-executes-networked` | `0a2135a`, `9127da8` |
| 1 | Containers read in memory (zip and OLE, three deep, ratio-capped) and the structural facts from `object` (sections, entropy, imports, family hash, overlay, signature blob) with `file.writable-executable-section` | `0f60858`, `53362ac`, `ecdf6d2` |
| 5 | The triage folder: snapshot, findings, timeline, a README that repeats every collector's status, and a manifest written last | `ecdf6d2` |
| — | The owner's order of 2026-10-20: grouped processes, the startup verb (add and remove through the typed path), `--replace`, three scan sizes and the Clean view | `685f72b`, `c609496`, `e144797`, `d814ef5`, `310cd41`, `89b07e5`, `3f372f4`, `c348911` |

**Not started, and named in [`NEXT.md`](NEXT.md) §8 with its reason:** event records
(Wave 2 — `evtx` measured at 34 crates with default features off), the Authenticode digest,
the sweep, the Startup folder's `.lnk`, the action path's second reviewer, `yara-x` and the
`bodyfile`. The rest of agents (Wave 4: suite provenance and the baseline diff) is also
unbuilt and listed there.
**Beaconing is closed:** the two-second poll calls `Sampler::observe` for every connection it
reads, the scan's flows are stamped with what the sampler saw, and `flow.beaconing` fires on
a steady rhythm. Without a series there is nothing to stamp, so a one-shot scan reports no
rhythm rather than guessing one — `FlowFact::beacon` is never set by a single photograph.
**The skill inventory is built:** the agent-stack collector finds a `SKILL.md` wherever a
client keeps one, reads the package's own files, hashes them into one digest, and reports the
five capabilities with the line that proved each. `agent.skill-executes-networked` is the
first finding that reads that matrix. What is not built is item 3's provenance record and
item 5's baseline diff.

Six waves, one gate, in order. A wave is done when its exit holds, and the release may
take longer than a plan, but it may not take the shortcut.

### Wave 0 — Truth, size and the carried rows

No new capability. The wave that makes the rest measurable.

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | The remaining version truth: the `CHANGELOG` `[0.1.7] — Unreleased` section, the size vocabulary in `README.md` and `BENCHMARKS.md` (§10.1), and a check that no document names a different version (the `AGENTS.md` status, the `PLAN.md` header and M6 are already corrected by the commit that adds this plan) | docs | One version, named the same way, in every document a person reads first |
| 2 | Cut `v0.1.6` at `3353974`, fast-forward `release/0.1.6` | process | The release verifies, the launcher parses it, and `release/0.1.7` is where the work lands |
| 3 | `RuleRegistry`: built-ins and packs enumerate together, coverage counts 27 | `core/src/rules.rs`, `core/src/pack/`, `xtask` | `cargo xtask coverage` lists every rule that can fire, and a test fails if a built-in has no technique or no benign explanation |
| 4 | The size measurement: `cargo bloat` top 20 by crate, recorded in `BENCHMARKS.md` | `docs/BENCHMARKS.md` | The table exists with the build it came from, and the biggest three contributors are named |
| 5 | The renderer experiment: `glow` behind a feature, measured binary and working set on all three platforms | `apps/vn-ranger/Cargo.toml` | Either the numbers justify the switch or the experiment is written down as a negative result |
| 6 | The carried 0.1.6 rows: macOS captures, WMI decision, `crontab`/`at`, data-folder size in Settings, the 24-hour soak on the candidate | as listed in `PLAN.md` M5/M6 | Each row is either fixed, or named in §9's "not in this release" with a reason |
| 7 | The second reviewer on the deletion paths | process | Two names on the pull request, and the traversal table written from the specification |

**Wave 0 exit:** the number the release will be judged by exists before the features that
will move it; the docs say one version; coverage counts every rule.

### Wave 1 — Bytes

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | A bounded reader: one chunked stream, a rolling window, cancellation, a byte budget | `native/src/content/read.rs` | A 2 GB file is hashed and scanned without allocating more than 8 MB; cancel lands in ≤ 100 ms |
| 2 | The `.ndb` parser (pure) and its matcher | `core/src/sig/ndb.rs` | Every malformed line in a 40-line fixture set is refused with a reason and a count; a fuzz target runs for 60 s clean |
| 3 | Wildcards, gaps and the `EP`/`SL`/`EOF` offsets | same | Positive and negative fixtures per construct; a gap of 1 MB does not scan 1 MB |
| 4 | Containers with a bomb guard | `native/src/content/container.rs` | A 42-byte zip bomb is refused by ratio and counted, not expanded; a nested archive stops at layer 3 |
| 5 | Structural facts for PE/ELF/Mach-O | `native/src/content/format.rs` | A fixture per format; a truncated header is `Unavailable { reason }`, never a guess |
| 6 | Signature facts | `native/src/content/signed.rs` | A signed fixture, a tampered one and an unsigned one each produce a different, named fact |
| 7 | The `file` subject in the vocabulary, and the first file rules | `core/src/fields.rs`, `packs/` | A rule that names a field the builder cannot fill is a load error |
| 8 | Deep check in the interface: folders, exclusions, budget, progress, cancel | `crates/ui`, `apps/vn-ranger` | A second click while a walk runs is ignored; the sentence names the cap before it starts |
| 9 | A generated test corpus: EICAR, a keyword-stuffed PE, a container-with-container | `crates/native/fixtures/content/` | The suite proves detection without shipping live malware, and the repository's own signature file still cannot match its own source |

**Wave 1 exit:** a folder walk finds a signature, a structural fact and a container, and
the report says which of the three engines ran and which were not built in.

### Wave 2 — Time

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | The `evtx` reader with a bounded window and a field cap | `native/src/collect/events/windows.rs` | A sanitised `.evtx` fixture yields records with the 24 fields the rules name; an unreadable file is `Unavailable` |
| 2 | The Linux reader: `journalctl` as a child, then a file fallback | `native/src/collect/events/linux.rs` | A fixture of NDJSON and a fixture of `auth.log` produce the same fact shape; a machine without journald says so |
| 3 | The macOS reader with a 15-minute window | `native/src/collect/events/macos.rs` | A captured fixture, or a named state saying the capture is owed — never an invented one |
| 4 | The `event` subject and its typed fields | `core/src/fields.rs` | An operator that cannot hold for a field is refused at load |
| 5 | Twelve event rules with a positive and a negative each | `packs/`, `docs/RULES.md` | The coverage table gains twelve rows, each with a technique or a written reason for none; a rule without a benign explanation fails the build |
| 6 | The Timeline view merges session, journal and events | `crates/ui/src/views.rs` | One list, source filter, UTC, and an empty state that names which sources were read |
| 7 | CSV and `bodyfile` export | `core/src/report.rs` | A 100,000-row timeline exports in ≤ 3 s and round-trips through a fixture parser |

**Wave 2 exit:** on a machine with logging on, ranger shows a logon, a service install and
a cleared log as three findings with their evidence, and says which channels were off.

### Wave 3 — Flows

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | The sampler: connection table → flows, diffed across samples | `native/src/collect/flows/` | 500 connections cost ≤ 20 ms; a page of `/proc/net/tcp` and a `netstat2` table produce the same fact shape |
| 2 | Byte counters where the platform gives them, `null` where it does not | same | A `null` renders as unknown, and a test fails if a zero is used instead |
| 3 | Beaconing: a pure function with fixtures | `core/src/rules.rs` or `core/src/beacon.rs` | A 60 s ± 2 s series is found; a 60 s ± 30 s series is not; six contacts is the floor |
| 4 | The `flow` subject and the joined `process` fields | `core/src/fields.rs` | A rule can say "this process is unsigned, autostarted, and beaconing" in one finding |
| 5 | The Zeek-shaped export | `core/src/report.rs` | The header matches `conn.log`, and a fixture row parses |
| 6 | IOC matching for addresses and CIDRs | `core/src/pack/` | A CIDR field is validated at load; a malformed prefix is a load error |

**Wave 3 exit:** a long-lived connection and a beaconing one are different findings, and
both name the process, the remote and the observation window.

### Wave 4 — Autonomy

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | The skill reader: `SKILL.md` frontmatter, referenced files, hashes | `native/src/collect/agentstack/skills.rs` | A fixture skill with a script and a URL yields three facts, not a verdict |
| 2 | The capability matrix: five booleans with the line that produced each | `core/src/model.rs`, `native/` | Every boolean names its evidence; an absent file is a `null`, not a `false` |
| 3 | Suite provenance: vn-launcher's catalogue and vn-code's install record, read locally | `native/src/collect/agentstack/` | An installed skill shows its origin and time, or says the record is absent |
| 4 | The `agent` subject v2 and six first-party rules | `core/src/fields.rs`, `packs/` | A skill that runs shell at install time is a finding; a skill that merely documents is not |
| 5 | The diff against the baseline | `core/src/diff.rs` | A new MCP server or skill since the baseline is a finding with the date it appeared |

**Wave 4 exit:** a person can see every autonomous thing on the machine, what each can
reach, and which one is new — without ranger reading a single prompt.

### Wave 5 — Evidence and response

| # | Work | Where | Done when |
|---|---|---|---|
| 1 | The journal hash chain and its verification | `core/src/journal.rs`, `native/src/journal.rs` | A flipped byte at any offset is reported at the entry it breaks; an intact chain verifies in ≤ 50 ms for 10,000 entries |
| 2 | The triage package export | `native/src/export.rs` | The manifest hashes every file it lists; the export is journalled; removing one file makes verification fail |
| 3 | The sweep across four domains | `native/src/sweep.rs` | It reports what it searched and what it could not; quarantine from a sweep goes through the existing typed path |
| 4 | Quarantine from a content finding, with the container path shown | `crates/ui` | The preview names the file, the offset and the container chain before anything moves |
| 5 | A report that reads like an incident, not a table | `core/src/report.rs` | Markdown: what was found, what it means, what was not checked, what to do next |

**Wave 5 exit:** one folder, one manifest, one timeline, one sentence per finding, and a
journal that says whether it verifies.

---

## 9. Gates, exit and cut

**The gate is the constitution, unchanged.** Every wave is judged by `AGENTS.md` §2:
never crash, never lie, never delete outside the typed path, never phone home, never hide,
no `unsafe`, no new privilege without an owner decision.

**Exit for 0.1.7** — the owner's criterion, extended:

> every new reader returns an `Outcome` and names what it could not see; every new rule
> has a positive and a negative fixture and a benign explanation; every destructive path
> still goes through one typed API with its four refusals; the hash chain verifies; the
> content engine refuses a byte it was not given consent for; `cargo xtask ci` is green on
> three platforms.

Added by this plan, because a release this wide needs its own proof:

- **The refusal table is tested.** A `.ndb` rule with a PCRE, a container that nests four
  deep, a log path outside the allowlist, a flow export with a domain ranger resolved
  itself: each is a test that fails if the refusal is deleted.
- **The consent rule is tested.** With consent off, a deep check reads zero bytes —
  asserted by a test that counts reads through the seam.
- **The log-off rule is tested.** A machine with no Sysmon produces a finding that says
  the channel was absent, not a clean bill of health.
- **The size gate:** archive ≤ 10 MB and binary ≤ 13 MB on Windows, or the release notes
  carry the number and the reason it missed. The archive budget is the one the user
  sees; the binary budget is the one that grows silently.
- **`cargo xtask language` gains** the words this release makes tempting: "malware found",
  "infected", "threat detected", "your machine is protected" — and keeps the existing bans.
- **The 24-hour soak runs on the candidate** with the poll, the watcher, the flow sampler
  and one event read, and the numbers go in `BENCHMARKS.md`.
- **A macOS capture exists** for every macOS parser that ships a rule, or the parser ships
  without a rule and says so.

**How the release is cut.** `0.1.7-rc.1` when the six waves are code-complete and
published as a pre-release; the soak and the manual matrix on that binary; fixes in
`rc.2`; `v0.1.7` from the last candidate that passed. A wave that cannot reach its exit is
named in the release notes and in §7.2 — the version still ships, because what ships is
true.

**Deliberately not in 0.1.7:**

> packet capture, bytecode signatures, logical signatures, PCRE, TLSH, a kernel driver,
> ETW, eBPF, EndpointSecurity, memory scanning, model-assisted triage, cloud reputation,
> autorun disable, browser inventory, a second elevated operation, a scan-schedule editor,
> and auto-quarantine.

---

## 10. Size and performance budget

### 10.1 The vocabulary

Four numbers, always named:

| Budget | Target | What it is |
|---|---|---|
| **Archive** | ≤ 10 MB | what a person downloads; measured 5.69–8.77 MB in 0.1.1 |
| **Binary** | ≤ 13 MB Windows, ≤ 16 MB Linux | what is on disk; measured **18.0 MB** on 2026-10-18 |
| **Working set** | ≤ 200 MB resident | 166–173 MB measured on wgpu; the `glow` goal is ≤ 120 MB |
| **Installed footprint** | ≤ 40 MB | binary plus data directory |

The README, the plan and the release notes each say which of the four they mean.

### 10.2 The programme, in the order it pays

| Lever | Expected direction | Risk | Where |
|---|---|---|---|
| `strip = "symbols"` instead of `"debuginfo"` | −1 to −2 MB | none; symbols are not shipped | `Cargo.toml` |
| Drop eframe's `default_fonts` | −1 to −1.5 MB | egui's fallback glyphs disappear; the app already embeds Inter and JetBrains Mono (1.09 MB), so the visual delta must be checked at 920 px and 1600 px | `apps/vn-ranger/Cargo.toml` |
| Subset the three embedded faces to Latin + the icons used | −0.5 MB | a glyph outside the subset falls back | `assets/fonts/` |
| `panic = "abort"` | −0.3 to −0.8 MB | a panic aborts instead of unwinding. The lints already deny panics in non-test code; the cost is a worse message if one escapes a dependency | `Cargo.toml` |
| `opt-level = "s"` (measure `"z"` too) | −1 to −3 MB, some speed | the scan budgets in §10.3 must hold | `Cargo.toml` |
| `lto = "fat"` | −0.5 to −1.5 MB | build time | `Cargo.toml` |
| **`glow` instead of `wgpu`** | **−4 to −6 MB and −40 to −60 MB working set** | a renderer change on three platforms; needs the manual matrix and a feature flag for one candidate | `apps/vn-ranger` |
| The new engines: `evtx`, `zip`, `cfb`, `goblin`, `authenticode` | **+1.5 to +2.5 MB** | the price of §4; each is measured before it is merged | `crates/native` |
| YARA-X | +3 MB when enabled | stays a feature, never default | feature |

The arithmetic the release has to show: **18.0 MB − (strip + fonts + abort + opt + lto +
renderer) + (four engines) ≤ 13 MB.** If the renderer is not switched, the four engines
do not fit, and the plan says so rather than shipping at 21 MB and calling it small.

### 10.3 New budgets

| Measure | Target | Why |
|---|---|---|
| Deep check throughput | ≥ 60 MB/s for hashing+`.ndb` on NVMe, one core | a 1 GB folder in under 20 s |
| Deep check memory | ≤ 8 MB over the baseline | chunked, never mapped whole |
| Container expansion | ratio cap 100:1, 256 MB total, layer cap 3 | a zip bomb is a refusal, not a crash |
| Event read | 100,000 records in ≤ 2 s; ≤ 200 MB read | a day of System log, not a month |
| Flow sample | ≤ 20 ms for 500 connections at a 4 s cadence | under 0.2 % of a core |
| Beacon evaluation | 1,000 series in ≤ 50 ms | it runs on the poll |
| Journal chain | +20 µs per entry, verify 10,000 in ≤ 50 ms | evidence is not a tax on the act |
| Timeline export | 100,000 rows in ≤ 3 s | the number a triage package is judged on |
| Triage package | ≤ 200 MB or it refuses and says why | it is meant to be handed over |

### 10.4 The dependency rule

A dependency that adds more than **300 KB** to the binary names what it buys, in the pull
request, with the measurement. A dependency that adds a C toolchain is refused in the
default build, as `netstat2` already is on anything but Windows. A crate that cannot be
built with `unsafe_code = "forbid"` in our tree is judged on whether its own `unsafe` is
auditable and small; `evtx` advertises a safety-dance badge, `authenticode` is 542 lines
of `no_std` parsing, and both are the kind of dependency this repository has accepted
before.

---

## 11. Dependencies and licences

Every row is a decision, not a shopping list. "Adopt" means the wave may add it; "candidate"
means the wave must justify it with a measurement and a licence check first.

| Crate | Licence | Size | What it buys | Status |
|---|---|---|---|---|
| `evtx` | MIT OR Apache-2.0 | ~200 KB | Windows event log parsing, safe Rust | **adopt** (Wave 2) |
| `zip` | MIT | ~150 KB | container walking | **adopt** (Wave 1) |
| `flate2` (miniz_oxide backend) | MIT OR Apache-2.0 | ~100 KB | gzip/zlib inside containers | **adopt** (Wave 1) |
| `cfb` | MIT | ~60 KB | OLE2 compound files (macro storage) | **adopt** (Wave 1) |
| `goblin` **or** `object` | MIT (goblin) / MIT OR Apache-2.0 (object) | ~250 KB | PE/ELF/Mach-O structural facts | **candidate** — pick one, measure both |
| `authenticode` | MIT OR Apache-2.0 | ~30 KB | Authenticode blob and digest | **adopt** (Wave 1) |
| `aho-corasick` | Unlicense OR MIT | ~120 KB | multi-pattern matching for the signature set | **candidate** — a hex matcher may not need it |
| `sevenz-rust` | Apache-2.0 | ~200 KB | 7z containers | **candidate** — only if measured as needed |
| `quick-xml` | MIT | already in the tree | event and task XML | shipped |
| `yara-x` | BSD-3-Clause | ~3 MB | the optional content engine | shipped, feature-gated |
| `pnet` | Apache-2.0 | ~300 KB | packet capture, if it ever ships | **refused in 0.1.7** |
| `notatin` / `ntfs` | MIT | ~300 KB each | offline hive and MFT reading | **0.1.8**, and only if the triage package needs it |
| `tlsh` | Apache-2.0 | ~100 KB | fuzzy hashing | **0.1.8** |
| Any GPL/AGPL crate, Chainsaw's code, ClamAV's engine, Hayabusa's code | — | — | — | **refused**: the licences are incompatible with MIT distribution |

The sizes are estimates to size the budget, not measurements. A licence marked † in §5 was
read from the project's own metadata in this session; the rest are as recorded in
`PLAN.md` §3 or in the crate's own metadata, and prose is not where a licence is settled.
`AGENTS.md` §8 makes the licence text part of the pull request, so a row that is wrong here
is caught there rather than shipped. The rows marked **adopt** are the ones §14 asks the
owner to decide.

---

## 12. Privacy and consent

0.1.7 reads three kinds of thing that 0.1.6 did not, and each gets a sentence in the
interface and a row in `PLAN.md` §13.

| New read | When | What is kept | What is never done |
|---|---|---|---|
| File bytes | Only inside a person-initiated deep check, with a consent sentence naming folders, depth and cap | A match: signature name, path, offset, container chain. No content, no second hash | Never uploaded, never kept, never read outside the named folders |
| Event logs | On a scan, from the paths the collector names | The bounded field map of the records a rule matched, plus counts | Never modified, never cleared, never read outside the allowlist |
| Connection table | Sampled every 4 s while the window is open or the schedule says so | Remote address, port, process, timestamps, byte counts | Never resolved, never captured, never sent |

**Still never collected:** prompts, conversations, model inputs, file contents outside a
consented walk, browser history, messages, credentials, keystrokes, screenshots, and
anything off the machine. The journal and the triage package *do* contain paths and
usernames, so both say so before they are written.

---

## 13. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Four engines, four half-finished products | High | §4's one-fact-model rule, Wave 0's registry merge, and a wave that may ship a reader without a rule but never a rule without a fixture |
| False positives from content signatures | High | `attention` is the ceiling for a signature hit, every finding names the benign explanation, and the first-party corpus is generated, not borrowed |
| A false positive quarantines a work file | Severe | Nothing auto-quarantines; the preview names the file, the offset and the container; restore is verified |
| Zip bombs, deeply nested archives, a hostile `.ndb` | Medium | Ratio, size, depth and time caps; a fuzz target per parser; cancellation |
| Reading logs costs more than it finds | Medium | Event reads are windowed and capped, and the interface says how long it took |
| Beaconing finds a scheduled client on every machine | Medium | The finding leads with the benign explanation and the interval, and suppression is per subject |
| A renderer change breaks one platform | High | Feature flag for a candidate, the manual matrix, and the working-set number published |
| The size programme does not pay for the engines | Medium | §10.2's arithmetic is a gate, and the fallback is a feature gate on content scanning rather than a 21 MB binary |
| Scope creep into EDR | High | §7.3's refusal table and the owner's decisions in §14 |
| The macOS surface stays untested | High | Wave 0's captures are an exit criterion, not a wish; a parser without a capture ships without a rule |

---

## 14. Decisions the owner must take

Each is a question with a recommendation; none is a detail a contributor can settle.

1. **Content scanning default.** Recommendation: **off by default, one button, consent per
   run**, and a scheduler option the person turns on explicitly. The alternative —
   scanning Downloads automatically — is what makes a security tool feel like a tax.
2. **Event logs and elevation.** Recommendation: **unelevated channels in 0.1.7**, with the
   Security log named as not read, and the elevated event scan in 0.1.8 as its own named
   operation. The alternative doubles the elevation surface in a release that already has
   four new readers.
3. **Packet capture.** Recommendation: **no**, for the reasons in §4.3. If the owner wants
   it, it is a separate build with a C toolchain and a driver, and the archive-under-10 MB
   claim goes with it.
4. **The new dependencies.** Recommendation: adopt `evtx`, `zip`, `flate2`, `cfb` and
   `authenticode`; choose `goblin` or `object` on measurement; refuse `pnet`.
5. **The binary budget.** Recommendation: **13 MB as a gate**, with the renderer change as
   the way to meet it. The alternative is a 21 MB binary and a claim that no longer
   matches the repository description.
6. **Response scope.** Recommendation: **sweep, timeline, triage package in 0.1.7; the
   reversible autorun disable in 0.1.8.** A new destructive verb needs the same two
   reviewers and the same refusal matrix that quarantine needed, and quarantine took a
   wave.
7. **The second reviewer.** Unchanged from 0.1.6 and still the one thing code cannot
   provide. The recommendation is that a release that adds four readers and a sweep does
   not ship without it.

---

## 15. References

- `AGENTS.md` — the constitution this plan is judged by
- [`PLAN.md`](PLAN.md) — the research, the architecture and the roadmap this supersedes (M6)
- ClamAV documentation — <https://docs.clamav.net/>; versions and FLEVELs —
  <https://docs.clamav.net/appendix/FunctionalityLevels.html>; logical signatures —
  <https://docs.clamav.net/manual/Signatures/LogicalSignatures.html>; bytecode signatures —
  <https://docs.clamav.net/manual/Signatures/BytecodeSignatures.html>
- YARA-X 1.0 — <https://blog.virustotal.com/2025/06/yara-x-100-stable-release-and-its.html>
- From Automation to Infection: How OpenClaw AI Agent Skills Are Being Weaponized —
  <https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html>
- MCP: Landscape, Security Threats, and Future Research Directions —
  <https://dl.acm.org/doi/10.1145/3796519>
- evtx — <https://github.com/omerbenamram/evtx>
- Chainsaw — <https://github.com/WithSecureOpenSource/chainsaw>
- Hayabusa — <https://github.com/Yamato-Security/hayabusa>
- Sigma — <https://github.com/SigmaHQ/sigma>; Detection Rule License 1.1 —
  <https://github.com/SigmaHQ/Detection-Rule-License>
- osquery — <https://github.com/osquery/osquery>
- Zeek — <https://zeek.org/>
- libpnet — <https://github.com/libpnet/libpnet>
- Sniffnet — <https://github.com/GyulyVGC/sniffnet>; bandwhich —
  <https://github.com/imsnif/bandwhich>
- Velociraptor — <https://github.com/Velocidex/velociraptor>
- Loki — <https://github.com/Neo23x0/Loki>
- Plaso — <https://github.com/log2timeline/plaso>
- Sysinternals Autoruns — <https://learn.microsoft.com/sysinternals/downloads/autoruns> /
  Sigcheck — <https://learn.microsoft.com/sysinternals/downloads/sigcheck>
- KnockKnock — <https://objective-see.org/products/knockknock.html>
- authenticode-rs — <https://github.com/google/authenticode-rs>
- Microsoft Defender for AI agents —
  <https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection>
- vn-launcher — <https://github.com/vecnode/vn-launcher>; vn-code —
  <https://github.com/vecnode/vn-code>
- MITRE ATT&CK — <https://attack.mitre.org/>
