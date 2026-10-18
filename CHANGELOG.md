# Changelog

All notable changes to vn-ranger are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.7] - 2026-10-20

The release that stops treating a file, a log, a connection and an agent as opaque. Its
plan is [`docs/PLAN-0.1.7.md`](docs/PLAN-0.1.7.md): four evidence domains, one rule
vocabulary, one evidence ledger, and a size budget that pays for them.

### Added

- **The content engine's signature vocabulary** (`vnr_core::content`): a clean-room reader
  for ClamAV extended body signatures (`.ndb`) — name, target type, offset and a hex
  pattern with `??` wildcards, `{n-m}` gaps, `*`, `(aa|bb)` choices and the `EP`/`SL`/`SX`/
  `EOF` offsets — with a matcher that is anchored on the first literal run, jumps to the
  literal after a gap instead of walking it, and spends from a budget so a hostile
  signature set cannot hang a scan. Every malformed line is refused with its number and the
  field at fault; a scan that runs out of budget says so rather than reporting a clean file.
- **One rule table.** `Rule` is public, every built-in rule carries the ATT&CK technique it
  covers or the written reason it covers none, and `cargo xtask coverage` now counts both
  engines: **30 rules over 14 techniques, 18 built in and 12 from the pack**, where it used
  to list 12. `docs/RULES.md` lists the rules with no technique and why.
- **The deep check** (`vnr_native::content`): a bounded, cancellable walk over Downloads, the
  Desktop and the temporary folder that hashes every file, identifies what the bytes are
  (PE, ELF, Mach-O, PDF, OLE2, zip, gzip, 7z, rar), matches hash signatures by digest *and*
  size, and runs the body signatures over the whole file. At most 20,000 files, eight folders
  deep, 64 MB per file read, 2 GB per run — and a file over the cap is still hashed, because
  a digest is a fact and "not read" is not "clean". It never runs on its own, it is stoppable
  between files, and it stores no content.
- **Connections** (`vnr_native::collect::flows`): the machine's TCP table with the process
  that owns each socket — Windows through `netstat2`, Linux through `/proc/net/tcp{,6}` and
  the same inode-to-pid reader the listener collector uses, macOS a named state rather than
  an empty list. Deduplicated, ordered by process and remote end, capped at 2,000 with the
  cap reported as a partial collector rather than a silent cut. No packet is captured and no
  name is resolved.
- **The `flow` subject for pack authors**, with the join done in the fact builder:
  `process_path`, `from_temp` and `from_downloads` are looked up from the scan's process
  table, so a rule can ask "is the program talking to that address running from a temporary
  folder" without a join language.
- **`flow.temp-process-remote`**, the rule that uses it: a connection held by a process
  running from a temporary folder, with the path, the remote end and the state as evidence.
- **A Zeek `conn.log` export** (`vnr_core::flows`): the real 21-column header, `-` where a
  sample cannot fill a column, and the state mapped to Zeek's abbreviation only when the
  mapping is known.
- **A hash chain over the journal.** Every line now carries a digest over the previous
  line's digest and its own facts, computed before the line is written. Reading the record
  back verifies it, and the Actions view says one of three true things: the chain verifies,
  it does not verify at entry *N* (a fact changed, or a line was inserted, removed or
  reordered), or the chain starts at *N* because earlier lines were written before it
  existed. The record is still append-only, still synced before an act, and still readable
  by a build that has never heard of the field.
- **Two rules that make a deep check say something without a pack**: `file.hash-match` (the
  whole file is the file a signature names) and `file.content-match` (a pattern is at an
  offset inside it), each naming the file, the signature and the offset.
- **Two new subjects for pack authors**: `file` (one fact per file read: shape, digest,
  kind, signature, container chain) and `file-match` (one fact per signature hit: name,
  offset, line, plus the file's fields so one rule can read both). A rule about a file's
  shape cannot fire once per signature, because the two questions are two subjects.
- **A Settings card for it**: what would be read, the folders, the caps, a run button, a
  stop button, and what the last check did — including a sentence when a limit stopped it or
  a person cancelled it, because a partial check is not a clean folder.
- **A rhythm in a connection**: the two-second poll reads the connection table and remembers
  when each process was seen talking to each peer; a scan is stamped with what the sampler
  saw, and `flow.beaconing` reports the interval, the spread in basis points and the number of
  contacts. **One rhythm is one finding**, however many sockets a client holds to that peer,
  and a poll that stops forgets, because a rhythm is a claim about now.
- **The skill inventory** (`vnr_native::collect::agentstack::skills`): a `SKILL.md` found in
  the folders a client keeps one is one fact — the package's own files, the five capabilities
  with the file and line that proved each, and one digest of the whole folder (the
  `sha256sum` text, hashed again). `agent.skill-executes-networked` reads that matrix; the
  `agent` subject gains the five booleans, present only where a file proved them.
- **Containers, read without unpacking** (`vnr_native::content::containers`): zip-shaped and
  OLE containers are opened in memory and each member is scanned as a file of its own
  (`outer.zip!inside/payload.txt`, with its container chain), three deep. Bounded at 32
  members, 16 MB a member, 64 MB a container, and a member claiming more than 200 bytes per
  byte it occupies is not read — a decompression bomb has that shape.
- **Structural facts** (`vnr_native::structs`): section count, writable-and-executable
  sections, the highest section entropy, import count, the import (family) hash, bytes after
  the last section, and whether an Authenticode blob is attached — recorded on every file and
  every container member, and exposed to pack rules as `sections`, `rwx`, `entropy`,
  `imports`, `overlay` and `imphash` on the `file` subject.
- **`file.writable-executable-section`**: an executable whose header says a section can be
  written to and run, with the JIT compiler and the self-extracting installer named as the
  benign case. 34 rules in total.
- **The triage folder** (`vnr_native::export`): `<data>/exports/triage-<utc>/` with
  `snapshot.json`, `findings.md`, `timeline.csv`, a README that repeats every collector's own
  status, and a `manifest.txt` written last so it names the hash and size of every file that
  is there.
- **Three scan sizes**: `Quick` (what is running and what starts), `Standard` (everything the
  read-only collectors reach), and `Deep` (and then the bytes of the programs that start on
  their own). The profile is recorded in every snapshot, and a profile chooses which
  collectors run rather than how honestly each reports.
- **Processes grouped by name**, with a `Group` dropdown offering `Name`, `None` and `Parent`;
  the keyboard walks what is on screen, and a selection made elsewhere opens its own group.
- **A startup entry can be removed and added** (`vnr_native::startup`): `HKCU`'s `Run` and
  `RunOnce`, identified by the scan's entry rather than by a path, journalled before the act,
  with the previous value kept so it can be put back. A machine-wide entry is refused with the
  reason, because changing it needs an administrator and there is no standing elevation.
- **A Clean view** that measures the allowlisted places and offers nothing to delete: "not
  measured", "none here" and a number are three different answers, and the removal stays where
  it was, in the Actions card with its totals and its journal.
- **`--replace`**: ask a running window to stop, wait for the instance lock, and take over —
  a flag rather than the default, because ending a window somebody is reading is not
  something a shortcut should do quietly.

### Changed

- `builtin_ids` in `xtask` reads the published list from `vnr-core` instead of scraping
  string literals out of `rules.rs`, so the pack validator and the engine cannot disagree.
- `signatures::load` no longer reports `.ndb` as "an extended format this build does not
  read": the content engine reads it, and the note now covers the logical formats it does
  not.
- A status sentence is a message in the corner that goes away by itself, not a line under
  the page header that stays for the session. A message card wraps, and takes at most half
  the window's height with a scrollbar past that.
- The data directory falls back to the local application folder when the roaming one refuses
  a create, and says which folder it is using rather than leaving a person to find out.

### Notes

- The release is in progress. Bytes, connections and agents are readable end to end; event
  records are **not** in this release, and `docs/NEXT.md` §8 says why and what each one would
  take — together with the Authenticode digest, the sweep, the Startup folder's `.lnk`, and
  the second reviewer the action path requires. A file's Authenticode signature is still
  `not_checked`: the fact is recorded as such rather than guessed at.

## [0.1.6] - 2026-10-18

### Added

- The action journal: append-only NDJSON, one entry synced before an action that changes
  something, a reader that tolerates a torn tail, rotation at 10,000 entries and 90-day
  retention. The window records a session start, every observed event, every new finding,
  each scan, watcher failures and the session stop, and says once when the journal cannot
  be written. `--report` records its scan; `--elevated-scan` deliberately does not.
- Crash-recovery verdicts for the four states a half-finished action can leave on disk,
  with one suggested next step each.
- `VN_RANGER_DATA_DIR`, absolute paths only, for a disposable profile beside the daily
  one; the soak harness needs it.
- Quarantine: one directory per entry, holding a manifest written and synced before the
  bytes move and the payload itself. Restore verifies the hash, refuses to overwrite, and
  puts the file back with a hard link; a permanent delete is reachable only through the
  word `DELETE`.
- A typed action path in which nothing takes a path: an entry id under an open directory
  handle, four refusals (outside the root, a link, a hard link, a changed file) and a
  deterministic seam for the test that proves the last one.
- All four acts share one journaled facade — intent synced before the act, result after —
  and a clean that selected nothing is not journalled.
- Allowlisted cleaning: a walk that never follows a link, never enters another filesystem,
  stops at depth 8, skips anything younger than the surface's threshold, and re-checks
  every item before removing it.
- `cargo xtask language`: the §5.5 audit as a check, reading the interface's string
  literals for the words that turn a fact into a verdict.
- An Actions view listing the quarantine (with verified restore and the typed delete) and
  the journal newest-first, with an interrupted intent marked.
- A quarantine entry point in the Startup detail panel, which is the preview.
- A resident schedule: six hours ±10 % from a seeded jitter, and a scan when the machine
  wakes from sleep.

### Added — rule packs

- **A pack now fires.** `vnr_core::pack::evaluate` takes a rule and a fact view and returns a
  `Finding`: `all` and `any`, text compared case-insensitively, an absent field matching
  nothing, `glob` as a two-pointer walk instead of a regular expression, and evidence that
  names the value the fact actually had. Before this, a pack could be proved valid and could
  never say anything.
- **The field vocabulary is typed.** Every field of every subject is text, a number or
  true/false, and the validator refuses an operator that cannot hold for it (`gt` on a path,
  `prefix` on a port) at load time, with the operators that would work in the refusal.
- **Places instead of paths.** A rule may name `{TEMP}`, `{HOME}`, `{DOWNLOADS}`,
  `{DESKTOP}`, `{APPDATA}`, `{LOCALAPPDATA}`, `{PROGRAMDATA}` or `{STARTUP}`; the core resolves
  none of them, so the caller hands the paths in and a build on a machine that cannot name a
  place does not guess at one.
- **Activation and rollback.** `packs/active.json` names the pack, its digest and the key that
  signed it; the pair of writes is journalled with an intent before and a result after, and
  `previous.json` is written first so a crash leaves a way back. Rolling back swaps the two
  records and touches nothing else.
- **The first-party pack is compiled in** with `include_str!`, so the catalogue travels with
  the build rather than with a file a person could swap.
- **The Rule packs page**: what is loaded and who signed it, every pack in the folder with
  what verification says about it, keys added only when the typed fingerprint is the key's
  own, and a key removed by fingerprint — which unloads the packs it signed, because the
  record is verified again every time it is read.
- **The Sigma importer** (`--sigma rule.yml`): a restricted YAML reader that refuses anchors,
  aliases, tags and multi-document files by line; `Image`, `CommandLine` and `User` map with
  three modifiers; everything else is counted with a reason that names the field or the
  condition. The output is a pack that still has to be signed.
- **The optional content scan** (`--features content-scan`): `yara-x`, behind a flag, off in
  the default build, with the walk bounded by files, depth and size, no link followed, and
  nothing but a rule name and a path kept. `cargo xtask ci` proves the default build contains
  no YARA-X with `cargo tree`.

### Changed — the interface

- The overview opens with a line of counts rather than four tiles, and says how long the last
  scan ago was, how long it took and how many collectors answered, where a person reads about
  the scan.
- "No network. No telemetry." moved from the overview to Settings, with the data folder beside
  it, because it is a statement about the program rather than a fact about the machine.
- Dialogs have one header size and one padding: a dialog titled at a page's size reads as a
  page in a box, and the margin now comes from the theme rather than from each dialog.
- The controls above every table are chips and a 24-pixel search field, sized with the table
  header, instead of links at body size.
- The journal's failure sentence now names the folder and the two things that cause it —
  a security program, or a policy — and the variable that moves it.

### Fixed

- A journal that could not be opened said `Access is denied` and nothing a person could act
  on. It now says which of the three problems it is: this program may not write in the folder
  (a security program, a folder policy or a sandbox all look like this, and
  `VN_RANGER_DATA_DIR` moves the folder), the journal file itself cannot be opened (it is
  moved aside as `journal.kept-<time>.ndjson` and a new one starts, so the session is recorded
  after all), or something else, reported as it came.
- `--diagnose` prints the folder, whether this program can write in it, whether the journal
  opens, which pack is loaded and how many keys are trusted — facts that were checked at that
  moment, so a refusal can be quoted rather than described.
- **The clean dry run no longer freezes the window.** The walk moved to its own thread: the
  button reads "Counting…", a spinner turns beside it, and the rest of the window keeps
  drawing while a cache with ten thousand files in it is counted. A second click while a
  walk is running is ignored rather than queued.
- **The clean list says what would go, more precisely**: each surface row now reads "1,204
  files · 3.2 GB in 4 folders · 6 empty folders · Kept 40 too new, 3 links", with the
  Show/Hide control beside the name it opens instead of floating to the right, and the
  "off by default" badge on the right where a badge belongs.
- The live indicator toggled once per poll, which reads as a metronome and keeps looking
  alive after the thread that feeds it has stopped. It now flashes for 220 ms as each
  poll arrives, stays quietly lit in between, and turns amber after three missed beats.
- A quoted startup command with spaces was tokenised into `C:\Program`, so a duplicated
  startup group was labelled "program". The tokeniser honours the closing quote, and an
  ambiguous command is labelled with its entry name.

### Changed

- The roadmap compresses the act, resident and rule-pack milestones into a single
  **v0.1.6**, built in five waves with one gate and cut through release candidates.
  `0.2.0` is distribution and signing; `1.0.0` is the audited release.
- `docs/PLAN.md` now specifies the action path — the journal protocol, the typed action
  API, the four refusals, the cleanup allowlist table and crash recovery — the rule-pack
  format (one signed JSON file, a closed vocabulary, no code, no file content, an
  optional and separately consented content scan), and the resident shell (tray, opt-in
  autostart, scheduler, close-to-tray off by default).
- `docs/BENCHMARKS.md` carries the 0.1.6 budgets and the 24-hour soak that must hold
  before the tag, and `AGENTS.md` carries the deletion and pack contracts those waves
  have to obey.

### Added — coverage, the first half of wave 5

- **The Windows registry is a table now.** Nineteen persistence surfaces — `Run`, `RunOnce`
  and the legacy `RunServices` in both registry views, Winlogon `Shell`, `Userinit` and
  `Notify`, `AppInit_DLLs`, the IFEO `Debugger`, Active Setup's `StubPath`, a service's
  `ServiceDll`, print monitors, both LSA package lists, netsh helpers, the screensaver and
  time-provider DLLs — are rows read through one `KeyReader` trait and parsed by one
  function, so a fixture for each runs on a machine that has never seen Windows. A key that
  is not there is an absence rather than an error, and the fixtures that capture an absence
  say so. A `REG_MULTI_SZ` is a list, so each string in it is its own entry.
- **A service in a user-writable folder is a finding**: `startup.service-dll-user-writable`
  fires on a `ServiceDll` under `ProgramData`, `LocalAppData`, `AppData` or a temporary
  folder, with a positive and a negative case against the shipped pack itself.
- A scan now reads 429 startup entries on the maintainer's machine where it read 132, and the
  collector's status line names the techniques the table covers rather than only the count.
- **Scheduled tasks**: every task file is parsed by a pure, fixture-tested reader (URI, action,
  account, enabled, hidden, triggers), read with `quick-xml`, which the plist reader already
  brought in. The task folder needs administrative rights to list, so a standard scan reports
  the collector as unavailable with that reason instead of reporting no tasks.
- **`hidden` is a fact**, so "a hidden scheduled task runs a program from a folder a user can
  write" is a shipped rule with a positive and a negative case.
- **The agent stack**: the collector reads four configuration surfaces — `authorized_keys`
  lines with a forced command or a supplied environment, `~/.ssh/rc`, `ProxyCommand` and
  `LocalCommand` in `~/.ssh/config`, and an MCP client's `mcpServers` — and says what each
  would run. A private key, a known-hosts file and every browser profile are never read, and
  the status line names which files were read and which were not there.
- **The content scan has a consent screen.** Settings says whether this build has one, names
  the folders, the file and depth limits and what is kept, and runs it on a thread of its own
  so the window keeps drawing. The default build says it was not compiled with one, which is
  a state rather than an error. The journal records the counts, never the content.
- **Two more detections**: `startup.accessibility-swap` fires on a debugger registered for a
  program Windows starts before sign-in (`sethc.exe`, `utilman.exe` and the rest), and
  `service.unquoted-path` is a built-in rule for a service image path with a space and no
  quotes, which Windows resolves one folder at a time.
- **The Linux loader surfaces**: `/etc/ld.so.preload`, `modprobe.d` `install` lines, `udev`
  rules with `RUN+=`/`PROGRAM=`, and login scripts, each parsed by a pure reader and each
  tested against a file **captured inside Ubuntu on WSL2** — including the absences, which are
  the ordinary case: no `ld.so.preload`, no `install` line, an empty `/etc/udev/rules.d`.
  `crates/native/fixtures/README.md` records where every capture came from.
- **The coverage table is generated** from the pack by `cargo xtask coverage`, and `ci` fails
  when a rule exists and the table does not mention it.
- **A cross-target check in CI**: the Windows runner type-checks the whole workspace for
  `x86_64-unknown-linux-gnu`. It found two real bugs on its first run — a path that only
  resolved on Unix, and a helper only Windows called — which is the failure mode `AGENTS.md`
  §5 describes.
- **A rule about a subject nothing collects is now a load error.** `agent` and `file-event`
  are in the vocabulary and not in a collector, so the one rule that named `agent` was
  removed rather than left in the catalogue looking like coverage.

### Fixed — the binary no longer contains the antivirus test file

- The EICAR test string was a byte literal in the product, so **`vn-ranger.exe` contained a
  complete antivirus test file** — Defender refused to execute this project's own test build
  with `ERROR_VIRUS_INFECTED`, which is what a browser would do to a download. The bytes are
  stored masked and decoded at run time, with `black_box` holding the optimiser off.
- Measured rather than assumed: a byte search finds **no complete test file** in either
  profile, and the release binary runs. A *prefix* of it can survive the optimiser in an
  optimised build, which is not a whole file and is not what an engine matches.
- `cargo xtask signature` reads whichever binaries are built and **fails the build** if a
  complete test file ever comes back, so the claim is checked rather than remembered.
### Changed — the interface

- The overview opens with a line of counts rather than four tiles, and says how long the last
  scan ago was, how long it took and how many collectors answered, where a person reads about
  the scan.
- "No network. No telemetry." moved from the overview to Settings, with the data folder beside
  it, because it is a statement about the program rather than a fact about the machine.
- Dialogs have one header size and one padding: a dialog titled at a page's size reads as a
  page in a box, and the margin now comes from the theme rather than from each dialog.
- The controls above every table are chips and a 24-pixel search field, sized with the table
  header, instead of links at body size.
- The journal's failure sentence now names the folder and the two things that cause it —
  a security program, or a policy — and the variable that moves it.

### Fixed

- A journal that could not be opened said `Access is denied` and nothing a person could act
  on. It now says which of the three problems it is: this program may not write in the folder
  (a security program, a folder policy or a sandbox all look like this, and
  `VN_RANGER_DATA_DIR` moves the folder), the journal file itself cannot be opened (it is
  moved aside as `journal.kept-<time>.ndjson` and a new one starts, so the session is recorded
  after all), or something else, reported as it came.
- `--diagnose` prints the folder, whether this program can write in it, whether the journal
  opens, which pack is loaded and how many keys are trusted — facts that were checked at that
  moment, so a refusal can be quoted rather than described.
- **The clean dry run no longer freezes the window.** The walk moved to its own thread: the
  button reads "Counting…", a spinner turns beside it, and the rest of the window keeps
  drawing while a cache with ten thousand files in it is counted. A second click while a
  walk is running is ignored rather than queued.
- **The clean list says what would go, more precisely**: each surface row now reads "1,204
  files · 3.2 GB in 4 folders · 6 empty folders · Kept 40 too new, 3 links", with the
  Show/Hide control beside the name it opens instead of floating to the right, and the
  "off by default" badge on the right where a badge belongs.
- The live indicator toggled once per poll, which reads as a metronome and keeps looking
  alive after the thread that feeds it has stopped. It now flashes for 220 ms as each
  poll arrives, stays quietly lit in between, and turns amber after three missed beats.
- A quoted startup command with spaces was tokenised into `C:\Program`, so a duplicated
  startup group was labelled "program". The tokeniser honours the closing quote, and an
  ambiguous command is labelled with its entry name.

### Changed

- The roadmap compresses the act, resident and rule-pack milestones into a single
  **v0.1.6**, built in five waves with one gate and cut through release candidates.
  `0.2.0` is distribution and signing; `1.0.0` is the audited release.
- `docs/PLAN.md` now specifies the action path — the journal protocol, the typed action
  API, the four refusals, the cleanup allowlist table and crash recovery — the rule-pack
  format (one signed JSON file, a closed vocabulary, no code, no file content, an
  optional and separately consented content scan), and the resident shell (tray, opt-in
  autostart, scheduler, close-to-tray off by default).
- `docs/BENCHMARKS.md` carries the 0.1.6 budgets and the 24-hour soak that must hold
  before the tag, and `AGENTS.md` carries the deletion and pack contracts those waves
  have to obey.

### Added — coverage, the first half of wave 5

- **The Windows registry is a table now.** Nineteen persistence surfaces — `Run`, `RunOnce`
  and the legacy `RunServices` in both registry views, Winlogon `Shell`, `Userinit` and
  `Notify`, `AppInit_DLLs`, the IFEO `Debugger`, Active Setup's `StubPath`, a service's
  `ServiceDll`, print monitors, both LSA package lists, netsh helpers, the screensaver and
  time-provider DLLs — are rows read through one `KeyReader` trait and parsed by one
  function, so a fixture for each runs on a machine that has never seen Windows. A key that
  is not there is an absence rather than an error, and the fixtures that capture an absence
  say so. A `REG_MULTI_SZ` is a list, so each string in it is its own entry.
- **A service in a user-writable folder is a finding**: `startup.service-dll-user-writable`
  fires on a `ServiceDll` under `ProgramData`, `LocalAppData`, `AppData` or a temporary
  folder, with a positive and a negative case against the shipped pack itself.
- A scan now reads 429 startup entries on the maintainer's machine where it read 132, and the
  collector's status line names the techniques the table covers rather than only the count.
- **Scheduled tasks**: every task file is parsed by a pure, fixture-tested reader (URI, action,
  account, enabled, hidden, triggers), read with `quick-xml`, which the plist reader already
  brought in. The task folder needs administrative rights to list, so a standard scan reports
  the collector as unavailable with that reason instead of reporting no tasks.
- **`hidden` is a fact**, so "a hidden scheduled task runs a program from a folder a user can
  write" is a shipped rule with a positive and a negative case.
- **The agent stack**: the collector reads four configuration surfaces — `authorized_keys`
  lines with a forced command or a supplied environment, `~/.ssh/rc`, `ProxyCommand` and
  `LocalCommand` in `~/.ssh/config`, and an MCP client's `mcpServers` — and says what each
  would run. A private key, a known-hosts file and every browser profile are never read, and
  the status line names which files were read and which were not there.
- **The content scan has a consent screen.** Settings says whether this build has one, names
  the folders, the file and depth limits and what is kept, and runs it on a thread of its own
  so the window keeps drawing. The default build says it was not compiled with one, which is
  a state rather than an error. The journal records the counts, never the content.
- **Two more detections**: `startup.accessibility-swap` fires on a debugger registered for a
  program Windows starts before sign-in (`sethc.exe`, `utilman.exe` and the rest), and
  `service.unquoted-path` is a built-in rule for a service image path with a space and no
  quotes, which Windows resolves one folder at a time.
- **The Linux loader surfaces**: `/etc/ld.so.preload`, `modprobe.d` `install` lines, `udev`
  rules with `RUN+=`/`PROGRAM=`, and login scripts, each parsed by a pure reader and each
  tested against a file **captured inside Ubuntu on WSL2** — including the absences, which are
  the ordinary case: no `ld.so.preload`, no `install` line, an empty `/etc/udev/rules.d`.
  `crates/native/fixtures/README.md` records where every capture came from.
- **The coverage table is generated** from the pack by `cargo xtask coverage`, and `ci` fails
  when a rule exists and the table does not mention it.
- **A cross-target check in CI**: the Windows runner type-checks the whole workspace for
  `x86_64-unknown-linux-gnu`. It found two real bugs on its first run — a path that only
  resolved on Unix, and a helper only Windows called — which is the failure mode `AGENTS.md`
  §5 describes.
- **A rule about a subject nothing collects is now a load error.** `agent` and `file-event`
  are in the vocabulary and not in a collector, so the one rule that named `agent` was
  removed rather than left in the catalogue looking like coverage.

### Fixed — the binary no longer contains a virus signature

- The EICAR test string was a byte literal in the product, so **every antivirus engine
  quarantines `vn-ranger.exe`** — Defender refused to execute this project's own test build
  with `ERROR_VIRUS_INFECTED`. The bytes are stored encoded and decoded at run time — shorter
  literals do not help, because they sit back to back in the read-only section and the
  signature survives the joins. The self-test still writes a real EICAR file, which is what it
  is for, and the binary no longer looks like the thing it hunts.

### Not in this release

- **WMI subscriptions.** The owner dropped the row: it needs COM and administrator rights to
  read `root\subscription`, and it could not be tested on the machine this release was built
  on. An untested collector that reports facts about someone's machine is worse than a named
  gap, so it is carried into 0.1.7 (`docs/PLAN.md` §14.2, M6 row 1).
- **Captured macOS fixtures.** The macOS collectors — `periodic`, the system crontab,
  `ScriptingAdditions`, Folder Actions and the launchd plists — are written and are
  **compile-checked for `x86_64-apple-darwin` in `ci`**, but no Mac was available to capture
  against, so their tests assert the documented shapes rather than a machine. The collector's
  status says so on a Mac, and the Linux ones are genuine captures from Ubuntu on WSL2.
- **The macOS and Linux user-level sources that need elevation**: user `crontab` tabs, `at`
  jobs. The collector reports the gap rather than an empty list.
- The 24-hour soak on the candidate binary and the manual matrix in `docs/PLAN.md` §12 are
  process rows and are still owed; so are the two reviewers on the deletion paths.
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
[0.1.7]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.7
[0.1.6]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.6
[0.1.5]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.5
[0.1.4]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.4
[0.1.3]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.3
[0.1.2]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.2
[0.1.1]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.1
[0.1.0]: https://github.com/vecnode/vn-ranger/releases/tag/v0.1.0
