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

A predicate is `{ "field": …, "op": …, "value": … }`, and the field must belong to the
subject. An unknown subject, an unknown field or an unknown operator is a **load error**,
not a rule that never fires: a rule that silently matches nothing looks like coverage.

### Subjects and their fields

| Subject | Fields |
|---|---|
| `startup` | `command`, `hash`, `name`, `path`, `scope`, `signed`, `user` |
| `process` | `command`, `name`, `parent`, `path`, `pid`, `started_at`, `user` |
| `listener` | `address`, `port`, `process`, `protocol`, `public` |
| `package` | `name`, `path`, `publisher`, `version` |
| `file-event` | `kind`, `path`, `source` |
| `agent` | `config`, `name`, `path`, `tool` |

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

Be clear about the state of this: the signature check exists and is tested
(`native/src/pack/signature.rs`), and the validator exists (`crates/core/src/pack/`). The
**trust store, activation and rollback are not built yet** — so there is no way, in this
build, to install a third-party pack and have it loaded. When they land, adding a key will
require typing its fingerprint, and removing a key will unload the packs that depended on it.

## The four promises no pack can break

1. **No code.** Rules are data. Nothing in a pack is executed, parsed as a program, or
   compiled.
2. **No file content.** A rule matches facts ranger already collected; no operator reads
   bytes inside a document.
3. **No socket.** Nothing in a pack can reach the network, because nothing in a pack runs.
4. **No `urgent`.** The ceiling is `attention`. Only an observed harm earns more, and an
   observation is not a pack's to make.

## Coverage

The pack that ships is `packs/ranger.core.json`, and it is the catalogue that grows. A
coverage table — which techniques the shipped rules reach, and which they cannot — is owed:
today the technique ids are on the rules, but the table that makes a gap visible is not
generated yet. The plan asks for it generated from the packs rather than typed, so it will
arrive with the generator rather than as a list that drifts.

## Working on a pack

```sh
cargo xtask packs   # validate the first-party pack with the product's validator
cargo xtask ci      # everything, including that check
```

A pack you are writing is checked the same way: parse it with `vnr_core::pack::parse` and
read the refusals. They are written to be the thing that tells you what to change.
