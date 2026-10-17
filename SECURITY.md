# Security policy

Ranger is a security tool, so it is held to the standard it asks of other software.
This document says what it protects, what it cannot, how to report a flaw, and which
promises are enforced rather than merely intended.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

<https://github.com/vecnode/vn-ranger/security/advisories/new>

Do not open a public issue for a vulnerability, and do not attach live malware samples
to a public thread. If a sample is necessary to reproduce the problem, say so in the
private report and a channel will be arranged.

A useful report includes:

- the ranger version and how it was installed;
- the operating system and version;
- the smallest sequence of steps that reproduces the problem;
- what happened, and what should have happened;
- the impact you believe it has (data loss, privilege, privacy, false verdict);
- logs or a report export with personal paths redacted.

## Supported versions

Before v1.0.0, only the latest release of the current minor line is supported. There
are no backports to older 0.x lines.

## What is in scope

- The ranger binary and its collectors.
- The hash-signature engine, its ClamAV-format reader, and the databases it loads.
- The rule engine and the rules that ship with it.
- The rule-pack loader, its signature verification and the trust store (from v0.1.6).
- The action path: the journal, quarantine, restore and the cleanup allowlist (from
  v0.1.6). A vulnerability here is a data-loss vulnerability, and it is treated as
  high severity.
- The release pipeline, checksums and (from v0.2.0) signatures.
- A documentation claim that is false about the software's behaviour.
- A finding that is dangerous to act on, or a recommended action that is not
  reversible.

## What is out of scope

- Vulnerabilities in the operating system, in egui/winit/wgpu, or in another
  dependency. Report those upstream; tell us if ranger's use of them makes the impact
  worse.
- A machine that was already compromised by an administrator. Ranger does not claim
  to survive a local administrator, and says so below.
- Social engineering, physical access, and firmware or kernel rootkits.

## What ranger promises, and how it is enforced

| Promise | Enforcement |
|---|---|
| No telemetry, no account, no network in v0.x | No HTTP client in the dependency tree; `cargo xtask ci` bans network crates and greps the workspace for socket code, and asserts that the Linux tray's local session-bus socket is the only one |
| No standing elevation | The window is unelevated; an administrator scan is a separate one-shot copy that the OS asks you to approve, writes one report and exits; no service and no driver |
| No silent deletion | Quarantine before delete; preview; the allowlist table; an action journal written before the act; a typed confirmation for a permanent delete; two-person review of deletion paths |
| No path outside the allowlist is reachable | A destructive act is named by an id, never a path, and resolved through an open directory handle (`cap-std`); `..`, absolute, UNC, links and hard links are refused by construction |
| No rule can act | A pack is signed data with a closed vocabulary: no code, no regular expressions, no file content, no socket, and `attention` is the ceiling |
| No hidden autostart | Opt-in only; the exact registry key, plist or `.desktop` file is shown with its path, and one click removes it |
| No hidden window | Close-to-tray is off by default; where no tray exists, closing quits |
| No content reading by default | The default build has no YARA-X; a content scan is a separate build feature with its own consent screen, and it stores nothing it reads |
| No asset replacement | The release checklist and a protected tag history |
| No numeric "threat score" | The finding model has no score field |

## Threat model

### What ranger can see

Process metadata, startup entries, listening sockets, installed package names, hashes of
startup binaries and of files written to the watched folders (Downloads, Desktop, the
temporary directory and the startup folders), and, once signature verification lands in
v0.2, signatures. It does not read file contents apart from hashing, except when a person
built the optional content scan and pointed it at a folder, and then it keeps rule names
and offsets and nothing else. It does not read credentials, messages, browser data or
keystrokes, and it does not read a prompt, a model file or a conversation.

### Adversaries considered

- **Unprivileged local software** that persists and hides in the ordinary places
  ranger inventories.
- **An agent with more permission than its owner intended** — the agent inventory
  exists for this case.
- **A malicious or mistaken rule pack.** Rules are data and cannot execute code or name
  a path. From v0.1.6 a pack is signed and verified before it is parsed, its vocabulary
  is closed, it holds no regular expression, and its severity ceiling is `attention`.
  A pack that fails to load cannot stop the built-ins, and a bad import rolls back
  without touching a fact, a baseline or a quarantine entry.
- **A compromised release.** Checksums now, signatures at v0.2.0.
- **A local administrator.** Out of scope for integrity: an administrator can change
  ranger's binary, its data and the operating system. Ranger does not pretend
  otherwise.

### The elevated copy

On Windows, **Run an administrator scan** starts `vn-ranger --elevated-scan <file>`
after the operating system's own consent prompt. The copy:

- is a separate process, not a service, driver or persistent helper;
- runs the same `scan()` and writes one snapshot under the data directory;
- exits as soon as the snapshot is written;
- cannot delete, quarantine or change configuration.

The elevated copy sees more of the machine, so a vulnerability in a collector is worse
there. Treat a crash, a path traversal or a surprising file write in that mode as a
high-severity report. The unelevated window never hands the elevated copy an arbitrary
path to act on.

### What ranger cannot do

- Detect kernel rootkits, firmware implants or memory-only malware.
- Certify a machine as free of malware.
- Verify a binary's signature yet; v0.1.0 reports hashes, not trust.
- Replace operating-system updates or an antivirus engine.
- Recover a file that was deleted outside ranger's quarantine.
- Recover a file deleted permanently from inside the quarantine. That is the one
  irreversible act in the program: it needs an id, a typed `DELETE`, and a journal.
- Clean anything outside the allowlist table, whatever a rule or a person suggests. The
  table is the product decision, not a suggestion.

These limits are stated in the interface where they affect a finding, not buried in a
footer.

### The action path

From v0.1.6 ranger can move a file into quarantine, restore it, delete it permanently,
and remove files under an allowlisted set of cache and temporary roots. This is the most
dangerous code in the program, and it is written as if the filesystem were hostile:

- a destructive act is named by an `EntryId`, never by a path, and resolved from an
  already-open `cap_std::fs::Dir`, so `..`, an absolute path and an escaping symlink are
  unrepresentable rather than merely rejected;
- a link, a hard link, and a file whose identity changed since it was inspected are
  refused with a reason;
- an `intent` line is written and `sync_data`d before the act, so a crash leaves a
  record;
- restore verifies the hash and refuses to overwrite;
- cleaning is a table of roots with age thresholds, never a heuristic about "junk".

If you find a way to make ranger move or delete something outside those rules, that is a
high-severity report. Include the platform, the filesystem type and whether the file was
reachable through a link, a junction, a reparse point or a rename race.

## Data handling

Everything is local. The data directory is documented in the plan (§6.4) and removable
as a folder. It holds `last-scan.json`, `signatures/` (local `.hdb`/`.hsb` databases),
`reports/`, the one-shot `elevated-scan.json`, and, from v0.1.6, `journal.ndjson`, the
`quarantine/` folder, and `packs/` with their public keys. Reports, journal entries and
quarantine manifests can contain usernames and file paths, so exports are treated as
personal data and carry a warning. Logs contain no secrets and are rotated locally.

**Quarantine holds the file.** That is what quarantine is; the file sits under the data
directory with a manifest, is never uploaded, and is removed when the person removes it.
The journal holds paths, hashes and reasons, not content. The trust store holds public
keys and the local signing key; a private key never leaves the machine, and the project's
private key never exists on a user's machine at all.

The signature self-test writes the EICAR test file to a temporary directory. EICAR is
not malware, but another antivirus product may remove it immediately; ranger hashes the
same bytes in memory so the self-test still proves the parser and matcher. That
behaviour is reported, not hidden.

There is no crash upload. If ranger crashes, the log is on disk and the user decides
whether to share it.

## False positives and false negatives

A false positive is a security defect in the product, not a cost of doing business.
Report one with the evidence ranger showed and the benign explanation it missed. A
false negative is harder to report honestly; if you can show a technique ranger should
have surfaced and did not, that is a useful report, not an embarrassment.

A hash match is only as good as the database that produced it. If a local `.hdb` or
`.hsb` line names a benign file, report the database and the line; ranger does not
silently mark a match as a detection. Quarantine exists from v0.1.6, and a match is
evidence for a person to read — not a verdict, and not an instruction to act.

## Disclosure

- Acknowledgement within 72 hours.
- An assessment and a mitigation plan within 30 days for a high-severity issue; the
  fix follows as soon as it is safe to ship.
- Coordinated disclosure at 90 days, or sooner by agreement.
- Credit in the release notes unless you ask otherwise.

## No warranty

Ranger is MIT-licensed and provided as is. It is a tool for seeing a machine more
clearly, not a guarantee that the machine is safe.
