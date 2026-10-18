# Releases

**Status:** v0.1.6 is cut from this tree; v0.1.7 (*Inside*) is in development on `dev`. The
release workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml).
**Audience:** whoever cuts a vn-ranger release, and the launcher that installs it.

Ranger follows the vecnode release convention documented in
[vn-launcher/docs/RELEASES.md](https://github.com/vecnode/vn-launcher/blob/main/docs/RELEASES.md).
That document is the agreement; this one is ranger's instantiation of it. Where the
two disagree, the launcher's document wins, because it is the code that has to read
the result.

## 0. Branches: `main` is a release, `dev` is the work

| Branch | Holds | Moves |
|---|---|---|
| `main` | **Exactly the last cut release.** Its tip is the commit the `vX.Y.Z` tag points at. | Only when a version is cut: `dev` is merged into it, the tag is placed on `main`, and nothing else lands there. |
| `dev` | Every change in progress, however many waves it spans. | Every commit. This is where work happens and where `cargo xtask ci` has to be green. |
| Tags | The releases themselves. | Never moved, never re-pointed (`AGENTS.md` §9). |

There is no per-release branch. A release is cut by merging `dev` into `main`, tagging that
commit, and pushing both -- in that order, so the tag never names a commit `main` does not
have. `main` is therefore always shippable and always *shipped*: a person who clones this
repository and checks out `main` gets the last release, not a half-finished wave.
## 1. The contract in one table

| Question | Ranger's answer |
|---|---|
| Tag | `v<major>.<minor>.<patch>`, e.g. `v0.1.0` |
| Release title | `vn-ranger v<version>`, e.g. `vn-ranger v0.1.1` |
| Release | A published, non-draft GitHub Release for the tag |
| Asset stem | `vn-ranger` |
| Asset names | `vn-ranger-<version>-<os>-<arch>.<ext>` |
| `os` | `windows`, `macos`, `linux` |
| `arch` | `x86_64`, `aarch64` |
| `ext` | `zip` on Windows, `tar.gz` elsewhere |
| Archive root | Exactly one directory: `vn-ranger-<version>/` |
| Inside | `vn-ranger` (or `vn-ranger.exe`), `README.md`, `LICENSE` |
| Checksums | `SHA256SUMS.txt`, generated after every build finishes |
| Trigger | `on: push: tags: ['v*']` |
| Pre-release | `vn-ranger v0.1.6-rc.1`, published with the pre-release flag, for the soak |
| Update mechanism | vn-launcher. Ranger does not update itself. |

The release title is the product and the version, and nothing else. What shipped is
described in the milestone and the changelog; a description never becomes the title.
The workflow creates every release with that title, so renaming one is a correction,
not a step in the process.

So a full set looks like:

```text
vn-ranger-0.1.0-windows-x86_64.zip
vn-ranger-0.1.0-linux-x86_64.tar.gz
vn-ranger-0.1.0-macos-aarch64.tar.gz
SHA256SUMS.txt
```

The binary is **`vn-ranger`**, never `ranger`. A binary called `ranger` collides with
the well-known terminal file manager on Linux and macOS, and a security tool that
shadows another program is not a small mistake.

### What v0.1.5 is

- Read-only inventory: processes, startup items, listeners (Windows and Linux),
  installed packages, SHA-256 hashes of startup binaries.
- A clean-room hash-signature engine for local `.hdb` / `.hsb` databases, with the
  built-in EICAR self-test.
- Fifteen rules and a Findings view, each finding carrying its evidence, its reason and
  a named benign explanation; suppressions scoped to one `(rule, subject)` pair.
- The accepted baseline and the diff against it, a two-second process poll and file
  watchers.
- An interface layer: command palette, keyboard navigation, filters, saved preferences.
- An opt-in, one-shot administrator scan on Windows.
- No quarantine, no cleaning, no tray, no autostart, no external rules, no network.

The release notes must repeat those limitations. A release that implies antivirus
coverage it does not have is the behaviour this project exists to reject.

### What v0.1.6 adds, and what it still is not

One release, five waves (`docs/PLAN.md` §9): an action journal and a typed action API,
quarantine with verified restore, allowlisted cleaning, a tray with opt-in autostart and
a scheduler, signed rule packs with an optional content scan, and a catalogue of rules
that name their technique.

The release notes for it must say, in the same breath:

- **Cleanup is an allowlist, not a cleaner.** The table in `docs/PLAN.md` §6.10 is the
  whole of it. Browser profiles, trash containers and everything outside it are not
  cleaned, and the interface says so.
- **Quarantine is reversible; deletion is not.** A permanent delete exists only inside
  the quarantine, only by id, and only after `DELETE` is typed.
- **No elevation was added.** The administrator scan is still one operation that writes
  one snapshot and exits; it cannot quarantine, clean or change a setting.
- **Still not an antivirus**, still no kernel driver, no service, no rootkit detection,
  no memory scanning, and no claim that a machine is clean.
- **A signed rule pack is not a signed release.** The archives are verified with
  `SHA256SUMS.txt` and nothing else until v0.2.0; the pack signature proves who wrote a
  rule file, not who built the binary.
- **macOS login items**, and a Linux tray that works with **no status-notifier host**,
  remain named gaps in `docs/PLAN.md` §7.

## 2. The archive

```text
vn-ranger-0.1.0/
  vn-ranger.exe        (or vn-ranger on Unix)
  README.md
  LICENSE
```

No absolute paths, no `..`, no symlinks that escape the root. The launcher rejects
those entries, but a rejected archive is a failed install, not a security incident
avoided quietly.

## 3. Checksums

`SHA256SUMS.txt` covers every other asset, in the format `sha256sum` produces:

```text
a4a9447b09e37a417c0fb90e7c826c46801c6b32eaf49497b78bbf1842a6b990  vn-ranger-0.1.0-linux-x86_64.tar.gz
```

It is generated in a job that runs **after** every build uploads its archive. A
checksum file computed before the last upload is a lie.

The launcher uses, in order: `SHA256SUMS.txt`, then GitHub's own asset `digest`, then
record-and-warn. Ranger publishes the first, so the first is what will be used.

## 4. Builds

| Target | Runner | Notes |
|---|---|---|
| `x86_64-pc-windows-msvc` | `windows-latest` | Static CRT (`-C target-feature=+crt-static`) |
| `x86_64-unknown-linux-gnu` | `ubuntu-22.04` | Oldest glibc we support; not `ubuntu-latest` |
| `aarch64-apple-darwin` | `macos-latest` | Universal binary once both macOS targets build in one job |
| `aarch64-unknown-linux-gnu` | cross or native | Added only when a runner and a test exist |

The workflow builds `-p vn-ranger` with `--locked`, so only the application is
packaged and the dependency graph is the one in `Cargo.lock`. The checksum job runs
after every build has uploaded, and re-downloads the assets rather than trusting the
build directories.

A platform that is not built publishes nothing for that platform. "There is no build
for this system" is a useful answer; a Linux binary named `macos` is not.

## 5. Versioning

- Start at `v0.1.0`.
- Patch releases fix defects; the `0.1.x` line also carries the interface polish and the
  watch, explain and act milestones. **v0.1.6 is one large release, not three:** act,
  resident and rule packs ship together, in five waves with one gate
  (`docs/PLAN.md` §9). The `0.2.0` minor is distribution and signing; `v1.0.0` is the
  audited release.
- A release of this size is cut through release candidates. `v0.1.6-rc.N` carries the
  pre-release flag, and the 24-hour soak and the manual matrix run on that binary, not
  on a developer build. A candidate takes fixes, not features. The final tag comes from
  the last candidate that passed everything.
- **Never replace an asset on an existing tag.** A checksum is a statement about a
  file; replacing the file invalidates every verification already made. Cut a patch.
  This applies to pre-release tags too: `rc.2` is a new tag, never a replaced asset.

## 6. Signing

v0.1.0 through v0.1.x ship with `SHA256SUMS.txt` only. The README and the release notes
say so.

From v0.1.6 the **rule packs** are signed (minisign, detached, verified before parsing),
and that is a different claim from a signed release: the pack signature says who wrote a
rule file. It says nothing about who built the binary, and the release notes must not let
the two blur.

v0.2.0 targets:

- Windows: Authenticode, with a certificate the project owns.
- macOS: Developer ID, hardened runtime, notarisation.
- Linux: a detached `minisign` signature over the archives and the checksum file.

A checksum protects against a truncated download and a corrupted mirror. It does not
protect against a compromised maintainer account, because whoever can replace the
archive can replace the checksum in the same release. Signing is the answer to that,
and it is a v0.2.0 requirement, not a v0.1 claim. The signature primitive is the one the
rule packs already use, so it is exercised for a release before it protects one.

## 7. Checklist before tagging

- [ ] `cargo xtask ci` is green on all three runners. The release workflow calls that
  same check as its gate, so a tag on a red commit publishes nothing: the matrix runs at
  the cut rather than on every commit, which is why the cut is the one place it cannot be
  skipped.
- [ ] The version in `Cargo.toml` matches the tag.
- [ ] `CHANGELOG.md` has the entry.
- [ ] `README.md` and `docs/PLAN.md` still describe what the binary does.
- [ ] The archive unpacks to exactly one directory and contains the binary.
- [ ] `SHA256SUMS.txt` is generated after the last build.
- [ ] A clean VM runs the archived binary, and install through vn-launcher is verified
      as soon as the launcher's install path ships.
- [ ] No new dependency brings a network client (`cargo xtask ci` checks it).
- [ ] The release notes name the known limitations, including the ones in this file.
- [ ] From `v0.1.6`: every deletion path has two named reviewers, and the traversal
      table was written by the second one from the specification.
- [ ] From `v0.1.6`: the 24-hour soak numbers are in `docs/BENCHMARKS.md`, with the build
      and the configuration they were taken on.
- [ ] From `v0.1.6`: the default build contains no YARA-X, and `cargo tree` proves it.
- [ ] From `v0.1.6`: the manual matrix includes a desktop with no status-notifier host,
      a suspend and resume, and an autostart entry removed by hand.

## 8. What is never published

- `.msi`, `.dmg`, `.deb`, `.rpm` or `.AppImage` installers. The launcher unpacks
  archives and never runs installers.
- A build that was not produced from the tagged commit.
- An archive without the licence and the README.
- A "portable" asset with a different stem, however convenient it looks today.
