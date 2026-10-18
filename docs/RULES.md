# Writing a rule pack

A pack is how a detection becomes data with an author. This is the authoring guide: what a
pack may say, what it may not, and what ranger does with it. The machine-readable half of
this document is `crates/core/src/fields.rs` (the field table) and
`crates/core/src/pack/` (the validator); if the two ever disagree, the validator wins and
this file is the bug.

## What a pack is

**One UTF-8 JSON file plus a detached `.minisig`.** No archive, no folder of rules, no
extraction step — which means no path inside a pack, no permission bit, and no zip-slip.
That is a security decision rather than a convenience: a format that cannot carry a path
cannot be made to write one.

A pack that fails validation is refused **whole**. Half a pack is a set of rules whose
absence nobody can see, which is worse than none.

## The file

```json
{
  "schema": 1,
  "pack": { "id": "ranger.core", "version": "2026.11.1", "title": "Ranger core detections" },
  "rules": [
    {
      "id": "startup.under-temp",
      "title": "A startup entry that runs something out of a temporary folder",
      "severity": "attention",
      "confidence": "likely",
      "technique": "T1547.001",
      "match": {
        "subject": "startup",
        "all": [
          { "field": "path", "op": "under", "value": "{TEMP}" },
          { "field": "scope", "op": "eq", "value": "user" }
        ]
      },
      "why": "A temporary folder is emptied by the system and by cleaners, so an entry there is one that expects to be re-created rather than installed.",
      "benign": "An installer that registers a temporary shim and removes it when it finishes.",
      "remediation": "Quarantine the binary, then remove the startup entry."
    }
  ]
}
```

`schema` is `1` and there is no other version. `pack.id` is the author's namespace and
`pack.version` is theirs to move.

## A rule, field by field

| Field | Required | What it is |
|---|---|---|
| `id` | yes | Stable forever. Lowercase, dot-separated, `[a-z0-9]+(\.[a-z0-9-]+)+`. |
| `title` | yes | What the rule says happened, in one sentence. |
| `severity` | yes | `attention`, `notice` or `info`. **`urgent` is refused** — the ceiling for a pack is `attention`. |
| `confidence` | yes | `observed`, `likely` or `possible` — how sure the rule is of its own reading. |
| `technique` | no | An ATT&CK id: `T` and four digits, optionally `.` and three more (`T1547.001`). |
| `match` | yes | The subject and the predicates. See below. |
| `why` | yes | The reasoning a person reads. |
| `benign` | yes | The most likely innocent explanation. **A rule without one is refused**, exactly as a built-in would be. |
| `remediation` | yes | What a person can do about it, in one or two steps. |

## The match

`match.subject` names what the rule is about; `match.all` holds predicates that must all
hold, and `match.any` holds predicates of which at least one must. A rule needs at least one
predicate and may hold at most 32 across both.

A subject that this build collects nothing for is a **load error**, for the same reason an
unknown field is: `file-event` and `agent` are in the vocabulary and not in a collector, so a
rule about either would load, look like coverage, and never fire. When a collector lands, the
subject becomes loadable and the rule that was waiting starts working.

A predicate is `{ "field": …, "op": …, "value": … }`, and the field must belong to the
subject. An unknown subject, an unknown field or an unknown operator is a **load error**,
not a rule that never fires: a rule that silently matches nothing looks like coverage.

### Subjects and their fields

Every field has a kind, and the kind decides which operators can hold for it. That is not a
style rule: `gt` on a path and `prefix` on a port can never be true, so a pack that writes one
is refused rather than loaded as a rule that never fires.

| Subject | Field | Kind |
|---|---|---|
| `startup` | `command`, `hash`, `kind`, `location`, `name`, `path`, `scope`, `signed` | text |
| `startup` | `enabled`, `hidden` | true/false |
| `process` | `command`, `name`, `path`, `user` | text |
| `process` | `parent`, `pid`, `started_at` | number |
| `listener` | `address`, `process`, `protocol`, `state` | text |
| `listener` | `port` | number |
| `listener` | `public` | true/false |
| `package` | `name`, `publisher`, `source`, `version` | text |
| `file-event` | `kind`, `path`, `source` | text |
| `agent` | `command`, `name`, `path`, `tool` | text |
| `file` | `container`, `digest`, `extension`, `kind`, `name`, `path`, `signed`, `signer` | text |
| `file` | `depth`, `size` | number |
| `file-match` | `container`, `kind`, `name`, `path`, `signed`, `signer` | text |
| `file-match` | `at`, `line` | number |
| `flow` | `process`, `process_path`, `protocol`, `remote_addr`, `state` | text |
| `flow` | `beacon_interval`, `beacon_jitter`, `bytes`, `local_port`, `pid`, `remote_port` | number |
| `flow` | `beacon`, `from_downloads`, `from_temp` | true/false |

The content engine produces two subjects. **`file`** is one fact per file it read: its shape,
its digest, and what its signature says. **`file-match`** is one fact per signature that hit
a file: `name` is the **signature's** name there (it is the file's name on `file`), `at` is
the offset it matched at, and `line` is where the signature came from in the signature file.
A match repeats the file's `path`, `kind`, `signed`, `signer` and `container`, so a rule can
say "this signature, in an executable, in a user folder" and read all of it from one fact.
The two subjects never answer each other's questions, which is why a rule about a file's
shape cannot fire once per signature.

`container` is the chain of containers a file was found inside, outermost first, joined with
` > `; `depth` is how many links it has. A file that was hashed but not read has a `digest`
and no match, which is a different statement from a file that was read and held nothing.

**`flow`** is one fact per connection the machine is holding, with the process that holds it.
`remote_addr` is an address and never a resolved name, because ranger sends no query. The
three joined fields answer a question the socket table cannot: `process_path` is the holding
process's binary, and `from_temp`/`from_downloads` say whether it runs from a folder the
system clears or a folder files arrive in.

The beacon fields are the one part of this subject that a single scan cannot fill. A rhythm
is read from a series of samples taken by the two-second poll, so `beacon` is true only when
the poll has watched this process and this peer often enough (six contacts) closely enough
(20 s to 2 h, under 15% spread) to call it a schedule. `beacon_interval` is the middle
interval in seconds and `beacon_jitter` is the spread in basis points: 300 means 3%. A
`--report` run has no poll behind it, so it carries no rhythm — a rule that matches
`beacon` is quiet there rather than guessing.


The values a text field takes, where the machine has a fixed set:

| Field | Values |
|---|---|
| `scope` | `user`, `system` |
| `signed` | `valid`, `invalid`, `unsigned`, `unknown`, `not_checked` |
| `kind` | `run_key`, `startup_folder`, `service`, `scheduled_task`, `netsh_helper`, `print_monitor`, `time_provider`, `screensaver`, `shell_extension`, `launch_agent`, `launch_daemon`, `systemd_unit`, `cron`, `xdg_autostart`, `debugger`, `preload`, `shell_startup`, `kernel_module`, `udev_rule`, `other` |
| `protocol` | `TCP`, `UDP` |

A field is absent when the fact does not carry it — a startup entry with no resolvable path has
no `path` — and an absent field matches nothing. `exists` is what asks whether it is there.

### Places, instead of paths

A rule cannot know where a person's temporary folder is, so it may name a place and ranger
resolves it. The closed list is:

`{TEMP}`, `{HOME}`, `{DOWNLOADS}`, `{DESKTOP}`, `{APPDATA}`, `{LOCALAPPDATA}`,
`{PROGRAMDATA}`, `{STARTUP}`

Anything else in braces is a refusal, not a literal. A place this machine cannot name is a
place the comparison cannot hold, so the rule does not fire rather than firing against a guess.

### Operators

| Operator | Takes a value | Means |
|---|---|---|
| `eq` | yes | Equal, case-insensitively. |
| `ne` | yes | Not equal. |
| `prefix` | yes | Starts with. |
| `suffix` | yes | Ends with. |
| `contains` | yes | Contains. |
| `glob` | yes | A pattern with `*` and `?` only. |
| `under` | yes | Is a path under a directory. |
| `in` | yes | Is one of a list. |
| `gt` | yes | Greater than, for a number. |
| `lt` | yes | Less than. |
| `exists` | **no** | The field is present. Giving it a value is refused. |

Text operators accept text (`eq`, `ne`, `prefix`, `suffix`, `contains`, `glob`, `under`, `in`,
`exists`); numbers accept `eq`, `ne`, `gt`, `lt`, `in` and `exists`; a true/false field accepts
`eq`, `ne` and `exists`. A value that is not the field's kind is refused, and `in` takes a
non-empty list of the right kind. Text comparisons are case-insensitive, because `C:\Users` and
`c:\users` are the same folder.

There is no regular expression operator and no operator that reads a file's contents. A pack
cannot make the machine do unbounded work and cannot read a document.

## Limits

Enforced before anything is evaluated:

| Limit | Value |
|---|---|
| Pack size | 2 MB |
| Rules per pack | 512 |
| A string in the pack | 4 KB |
| Predicates per rule | 32 |
| Rule ids | unique within the pack, and no id may shadow a built-in |

A rule id is forever: changing one is a breaking change to every suppression that names it,
because a suppression is scoped to `(rule, subject)`.

## When a pack is refused

Every refusal names the rule and the line, and says what to write instead. Two real ones:

```text
rule startup.under-temp at line 12: `registry_hive` is not a field of `startup`; docs/RULES.md lists the ones that are
rule startup.under-temp at line 15: `regex` is not an operator; use eq, ne, prefix, suffix, contains, glob, under, in, gt, lt or exists
```

A pack that is not valid JSON reports the line the parser stopped on. The first-party pack is
checked by the same validator in `cargo xtask ci`, so a rule that would be refused for a
third party is refused for ranger's own.

## Signing, and what is not built yet

A pack is verified **before it is parsed**: minisign, Ed25519 over BLAKE2b-512, one detached
`.minisig` beside the JSON, one public key per author. A pack signed by a key ranger has not
been given is refused, and so is a pack with one changed byte.

The trust store is `packs/keys.json` in ranger's data folder, and the interface is the **Rule
packs** page. Adding a key needs two things pasted: the key, and the fingerprint its author
read out. Ranger computes the fingerprint from the key and refuses the two if they disagree,
because a form that trusts whatever was pasted is not a check. Removing a key unloads the packs
it signed on the next read.

Activation is `active.json`, beside the packs: the id, the version, the SHA-256 of the bytes
and the key that signed them. It is written only after the signature and the validator have
both passed, and the intent and the result are journalled, like every other act. **Roll back**
swaps that record with `previous.json` and touches nothing else — not a fact, not a baseline,
not a pack file — so returning to a pack that worked is one click and one journal line.

The pack compiled into the binary (`packs/ranger.core.json`) needs no signature at run time,
because the bytes travel with the build rather than with a file a person could swap.

## What the Windows collector reads

The startup subject is filled by one table of registry surfaces, read in both views where a
32-bit program would see a different key. A rule about `startup` can match `location` to say
which one it came from:

| Surface id | Key | What is one entry |
|---|---|---|
| `run` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | every value |
| `run-machine` | the same, in `HKLM` | every value |
| `run-once`, `run-once-machine` | `...\RunOnce` | every value |
| `run-services`, `run-services-once` | `...\RunServices[Once]` | every value |
| `winlogon-shell` | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | the `Shell` value |
| `winlogon-userinit` | the same key | the `Userinit` value |
| `winlogon-notify` | `...\Winlogon\Notify` | every value |
| `appinit` | `...\CurrentVersion\Windows` | the `AppInit_DLLs` value |
| `ifeo-debugger` | `...\Image File Execution Options\<program>` | the `Debugger` value |
| `active-setup` | `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\<id>` | the `StubPath` value |
| `service-dll` | `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters` | the `ServiceDll` value |
| `print-monitor` | `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>` | the `Driver` value |
| `lsa-notification` | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | each `Notification Packages` string |
| `lsa-authentication` | the same key | each `Authentication Packages` string |
| `netsh-helper` | `HKLM\SOFTWARE\Microsoft\NetSh` | every value |
| `screensaver` | `HKCU\Control Panel\Desktop` | the `SCRNSAVE.EXE` value |
| `time-provider` | `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\<name>` | the `DllName` value |

A value written as `REG_MULTI_SZ` is a list, and each string in it is its own entry: `LSA
Notification Packages` is one DLL per entry, named `Notification Packages (1)`, `(2)`, and so
on. A `REG_DWORD` in a `Run` key is not a command and is not an entry, because guessing at its
bytes would invent a fact.

The agent-stack collector fills the `agent` subject from four kinds of configuration, each
named in the finding by its file:

| File | What is one fact |
|---|---|
| `~/.ssh/authorized_keys` | a key line with `command=` or `environment=` |
| `~/.ssh/rc` | the script itself, which runs when a session opens |
| `~/.ssh/config` | a `ProxyCommand`, `LocalCommand` or `Match exec` naming a program |
| an MCP client's configuration (`mcpServers`) | a server, with the command it starts |

A private key, a known-hosts file and everything under a browser profile are never read.
`file-event` is still the one subject nothing collects, and a rule about it is a load error.

Scheduled tasks are the twentieth source and they are not a registry key: each task file is
parsed by a reader with its own captured fixture, and the facts carry `kind eq
"scheduled_task"`, the account the task runs as in `scope`, whether it hides itself in
`hidden`, and its action in `command` and `path`. The task folder needs administrative rights
to list, so a standard scan reports that collector as unavailable rather than as empty.

On Linux the startup subject is filled by systemd units, XDG autostart entries, system cron,
and the four surfaces that load code before anything a person clicks: `/etc/ld.so.preload`
(one library per line, mapped into every process), `modprobe.d` `install` lines (a module's
load replaced by a command), `udev` rules with `RUN+=` or `PROGRAM=`, and login scripts
(`/etc/profile.d`, `~/.profile`, `~/.bashrc`, `~/.zshrc`). Each is a fact with the file that
named it; none of them is a verdict.

A key that is not there produces no entries, and that is the ordinary case: `RunOnce`,
`RunServices` and `Notify` do not exist on a clean machine. The fixture that proves it is a
capture of exactly that absence.

## The four promises no pack can break

1. **No code.** Rules are data. Nothing in a pack is executed, parsed as a program, or
   compiled.
2. **No file content.** A rule matches facts ranger already collected; no operator reads
   bytes inside a document.
3. **No socket.** Nothing in a pack can reach the network, because nothing in a pack runs.
4. **No `urgent`.** The ceiling is `attention`. Only an observed harm earns more, and an
   observation is not a pack's to make.

## Coverage

Two engines produce findings and one table lists them. The **built-in** rules are Rust
functions with fixtures in `crates/core/src/rules.rs`; the **pack** rules are data in
`packs/ranger.core.json`, which is the catalogue that grows without a rebuild. The table
below is generated from both by `cargo xtask coverage`, and `cargo xtask ci` fails when a
rule from either engine is missing from it: a coverage table that is typed by hand is a
claim that drifts, and this is the one place a reader looks to find out what the release
actually covers. A rule that cannot name a single ATT&CK technique says why underneath the
table instead of leaving a blank.

<!-- coverage:start -->
<!-- generated by `cargo xtask coverage`: do not edit by hand -->

| Technique | Rule | Severity | Source | What it says |
|---|---|---|---|---|
| `T1053.005` | `task.hidden-user-writable` | Attention | pack | A hidden scheduled task runs a program from a user-writable folder |
| `T1059` | `agent.config-names-a-command` | Notice | pack | A configuration file names a program to run |
| `T1059` | `startup.shell-interpreter` | Notice | built-in | A startup item launches a shell or script host |
| `T1204.002` | `process.downloads-path` | Notice | built-in | A running process is in Downloads or on the Desktop |
| `T1204.002` | `process.from-temp` | Notice | pack | A process running from a temporary folder |
| `T1543.003` | `startup.service-dll-user-writable` | Attention | pack | A service's DLL is in a folder a user can write |
| `T1546.002` | `startup.screensaver-user-writable` | Notice | pack | The screensaver runs a program from a user-writable folder |
| `T1546.007` | `startup.netsh-helper-user-writable` | Attention | pack | A netsh helper DLL is named by a full path in a user-writable folder |
| `T1546.008` | `startup.accessibility-swap` | Attention | pack | An accessibility program is replaced by another program |
| `T1547` | `agent.persistent-listening` | Notice | built-in | A persistent program is waiting for connections |
| `T1547` | `startup.downloads-path` | Attention | built-in | A startup item runs from Downloads or the Desktop |
| `T1547` | `startup.new-since-baseline` | Notice | built-in | A startup item is new since the baseline |
| `T1547` | `startup.script-extension` | Notice | built-in | A startup item runs a script |
| `T1547` | `startup.temp-path` | Attention | built-in | A startup item runs from a temporary folder |
| `T1547` | `startup.user-writable-system` | Attention | built-in | A machine-wide startup item points into a user folder |
| `T1547.001` | `startup.under-temp` | Attention | pack | A startup entry that runs something out of a temporary folder |
| `T1547.001` | `startup.unsigned-user-scope` | Notice | pack | An unsigned startup entry in the user's own scope |
| `T1547.003` | `startup.time-provider-user-writable` | Attention | pack | A time provider DLL is in a user-writable folder |
| `T1547.012` | `startup.print-monitor-user-writable` | Attention | pack | A print monitor DLL is named by a full path in a user-writable folder |
| `T1554` | `startup.hash-changed` | Attention | built-in | A startup binary changed since the baseline |
| `T1574.008` | `service.unquoted-path` | Notice | built-in | A service path has a space in it and no quotes |
| `T1611` | `listener.every-interface` | Notice | pack | A socket waiting for a connection on every interface |
| `—` | `file.content-match` | Attention | built-in | A file holds the bytes a signature describes |
| `—` | `file.hash-match` | Attention | built-in | A file matched a signature by hash |
| `—` | `flow.beaconing` | Notice | built-in | A program is contacting the same address on a steady rhythm |
| `—` | `flow.temp-process-remote` | Notice | built-in | A program in a temporary folder is talking to another machine |
| `—` | `listener.public-new-process` | Notice | built-in | A recently started process listens beyond loopback |
| `—` | `listener.public-unknown-owner` | Info | built-in | A public socket has no visible owner |
| `—` | `process.parent-exited` | Info | built-in | A process outlived the process that started it |
| `—` | `process.temp-path` | Notice | built-in | A running process is in a temporary folder |
| `—` | `startup.bare-command` | Notice | built-in | A startup command does not name a full path |
| `—` | `startup.duplicate-command` | Info | built-in | One command is registered as several startup items |

32 rules covering 14 technique(s): 20 built in and 12 from `packs/ranger.core.json`.

No technique, and why — a rule that cannot name one says so:

- `startup.bare-command` — a startup command that is not a full path is how an entry is written, not an action an adversary takes; the same entry is covered as T1547 by the rule above
- `process.temp-path` — where a process runs is a location; it names a technique only when the execution context is known, and this rule does not know it
- `process.parent-exited` — a parent exiting is normal, and the rule exists so the ancestry stays honest rather than to describe an adversary
- `listener.public-new-process` — reachability is a fact about a socket; which technique it serves depends on the program holding it
- `listener.public-unknown-owner` — the rule reports a gap in this program's view, not an adversary action
- `startup.duplicate-command` — duplicates are a hygiene fact; no adversary needs two identical startup entries
- `file.hash-match` — a hash names a file; which technique that file serves is the signature author's knowledge, and a rule cannot inherit it
- `file.content-match` — the pattern is a fact; a technique is an interpretation of what the file does, which this rule does not observe
- `flow.temp-process-remote` — a connection is a channel; which technique it serves depends on what is said over it, which this rule does not observe
- `flow.beaconing` — a rhythm is a channel; what it carries is not observed
<!-- coverage:end -->

## Importing a Sigma rule

```sh
vn-ranger --sigma rule.yml
```

writes `rule.pack.json` beside the rule and prints what mapped and what did not. The mapping is
small on purpose: `Image` → `process.path`, `CommandLine` → `process.command`, `User` →
`process.user`, with `|contains`, `|startswith` and `|endswith` carried across. Everything else
is skipped with a reason naming the field, the modifier or the condition — a Sigma rule about
a registry key is not expressible as a fact about a process, and saying so is more useful than
a rule that would never fire.

`level: critical` and `level: high` become `attention`, which is the pack ceiling.
`falsepositives` becomes `benign`, and a rule without one is skipped for the same reason a
hand-written rule without one is refused. The output is not active: it has no `.minisig`, so
the Rule packs page lists it as refused until its author signs it. Ranger never signs anything.

## Working on a pack

```sh
cargo xtask packs   # validate the first-party pack with the product's validator
cargo xtask ci      # everything, including that check
```

A pack you are writing is checked the same way: parse it with `vnr_core::pack::parse` and
read the refusals. They are written to be the thing that tells you what to change.
