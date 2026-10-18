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


The values a text field takes, where the machine has a fixed set:

| Field | Values |
|---|---|
| `scope` | `user`, `system` |
| `signed` | `valid`, `invalid`, `unsigned`, `unknown`, `not_checked` |
| `kind` | `run_key`, `startup_folder`, `service`, `scheduled_task`, `netsh_helper`, `print_monitor`, `time_provider`, `screensaver`, `shell_extension`, `launch_agent`, `launch_daemon`, `systemd_unit`, `cron`, `xdg_autostart`, `debugger`, `other` |
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

The pack that ships is `packs/ranger.core.json`, and it is the catalogue that grows. The
table below is generated from it by `cargo xtask coverage`, and `cargo xtask ci` fails when a
rule exists in the pack and not in the table: a coverage table that is typed by hand is a
claim that drifts, and this is the one place a reader looks to find out what the release
actually covers.

<!-- coverage:start -->
<!-- generated by `cargo xtask coverage`: do not edit by hand -->

| Technique | Rule | Severity | What it says |
|---|---|---|---|
| `T1053.005` | `task.hidden-user-writable` | Attention | A hidden scheduled task runs a program from a user-writable folder |
| `T1059` | `agent.config-names-a-command` | Notice | A configuration file names a program to run |
| `T1204.002` | `process.from-temp` | Notice | A process running from a temporary folder |
| `T1543.003` | `startup.service-dll-user-writable` | Attention | A service's DLL is in a folder a user can write |
| `T1546.002` | `startup.screensaver-user-writable` | Notice | The screensaver runs a program from a user-writable folder |
| `T1546.007` | `startup.netsh-helper-user-writable` | Attention | A netsh helper DLL is named by a full path in a user-writable folder |
| `T1546.008` | `startup.accessibility-swap` | Attention | An accessibility program is replaced by another program |
| `T1547.001` | `startup.under-temp` | Attention | A startup entry that runs something out of a temporary folder |
| `T1547.001` | `startup.unsigned-user-scope` | Notice | An unsigned startup entry in the user's own scope |
| `T1547.003` | `startup.time-provider-user-writable` | Attention | A time provider DLL is in a user-writable folder |
| `T1547.012` | `startup.print-monitor-user-writable` | Attention | A print monitor DLL is named by a full path in a user-writable folder |
| `T1611` | `listener.every-interface` | Notice | A socket waiting for a connection on every interface |

12 rules covering 11 technique(s), from `packs/ranger.core.json`.
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
