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
- The rule engine and the rules that ship with it.
- The release pipeline, checksums and (from v1.0) signatures.
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
| No telemetry, no account, no network in v0.x | No HTTP client in the dependency tree; `cargo deny` bans and a CI lockfile check |
| No elevation by default | No installer, no service, no driver; a collector that needs privilege reports "not visible" |
| No silent deletion | Quarantine before delete; preview; allowlists; an action journal; two-person review of deletion paths |
| No hidden autostart | Opt-in only; the exact registry key, plist or `.desktop` file is shown, and one click removes it |
| No asset replacement | The release checklist and a protected tag history |
| No numeric "threat score" | The finding model has no score field |

## Threat model

### What ranger can see

Process metadata, startup entries, listening sockets, installed package names, binary
signatures and hashes, and the first/last-seen time of those facts. It does not read
file contents apart from hashing, and it does not read credentials, messages, browser
data or keystrokes.

### Adversaries considered

- **Unprivileged local software** that persists and hides in the ordinary places
  ranger inventories.
- **An agent with more permission than its owner intended** — the agent inventory
  exists for this case.
- **A malicious or mistaken rule pack.** Rules are data and cannot execute code;
  third-party packs require a signature from v0.5.
- **A compromised release.** Checksums now, signatures at v1.0.
- **A local administrator.** Out of scope for integrity: an administrator can change
  ranger's binary, its data and the operating system. Ranger does not pretend
  otherwise.

### What ranger cannot do

- Detect kernel rootkits, firmware implants or memory-only malware.
- Certify a machine as free of malware.
- Replace operating-system updates or an antivirus engine.
- Recover a file that was deleted outside ranger's quarantine.

These limits are stated in the interface where they affect a finding, not buried in a
footer.

## Data handling

Everything is local. The data directory is documented in the plan (§6.4) and removable
as a folder. Reports can contain usernames and file paths, so exports are treated as
personal data and carry a warning. Logs contain no secrets and are rotated locally.

There is no crash upload. If ranger crashes, the log is on disk and the user decides
whether to share it.

## False positives and false negatives

A false positive is a security defect in the product, not a cost of doing business.
Report one with the evidence ranger showed and the benign explanation it missed. A
false negative is harder to report honestly; if you can show a technique ranger should
have surfaced and did not, that is a useful report, not an embarrassment.

## Disclosure

- Acknowledgement within 72 hours.
- An assessment and a mitigation plan within 30 days for a high-severity issue; the
  fix follows as soon as it is safe to ship.
- Coordinated disclosure at 90 days, or sooner by agreement.
- Credit in the release notes unless you ask otherwise.

## No warranty

Ranger is MIT-licensed and provided as is. It is a tool for seeing a machine more
clearly, not a guarantee that the machine is safe.
