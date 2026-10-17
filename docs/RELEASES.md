# Releases

**Status:** v0.1.0 is cut from this tree. The release workflow is
[`.github/workflows/release.yml`](../.github/workflows/release.yml).
**Audience:** whoever cuts a vn-ranger release, and the launcher that installs it.

Ranger follows the vecnode release convention documented in
[vn-launcher/docs/RELEASES.md](https://github.com/vecnode/vn-launcher/blob/main/docs/RELEASES.md).
That document is the agreement; this one is ranger's instantiation of it. Where the
two disagree, the launcher's document wins, because it is the code that has to read
the result.

## 1. The contract in one table

| Question | Ranger's answer |
|---|---|
| Tag | `v<major>.<minor>.<patch>`, e.g. `v0.1.0` |
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
| Update mechanism | vn-launcher. Ranger does not update itself. |

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

### What v0.1.0 actually is

- Read-only inventory: processes, startup items, listeners (Windows and Linux),
  installed packages, SHA-256 hashes of startup binaries.
- A clean-room hash-signature engine for local `.hdb` / `.hsb` databases, with the
  built-in EICAR self-test.
- An opt-in, one-shot administrator scan on Windows.
- No rules, no findings, no quarantine, no cleaning, no tray, no network.

The release notes must repeat those limitations. A release that implies antivirus
coverage it does not have is the behaviour this project exists to reject.

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
- Patch releases fix defects; the `0.1.x` line also carries interface polish and the
  watch, act, resident and rule-pack milestones. The `0.2.0` minor is distribution and
  signing; `v1.0.0` is the audited release.
- Pre-releases carry a semver suffix and the GitHub pre-release flag.
- **Never replace an asset on an existing tag.** A checksum is a statement about a
  file; replacing the file invalidates every verification already made. Cut a patch.

## 6. Signing

v0.1.0 through v0.1.x ship with `SHA256SUMS.txt` only. The README and the release notes
say so.

v0.2.0 targets:

- Windows: Authenticode, with a certificate the project owns.
- macOS: Developer ID, hardened runtime, notarisation.
- Linux: a detached `minisign` signature over the archives and the checksum file.

A checksum protects against a truncated download and a corrupted mirror. It does not
protect against a compromised maintainer account, because whoever can replace the
archive can replace the checksum in the same release. Signing is the answer to that,
and it is a v0.2.0 requirement, not a v0.1 claim.

## 7. Checklist before tagging

- [ ] `cargo xtask ci` is green on all three runners.
- [ ] The version in `Cargo.toml` matches the tag.
- [ ] `CHANGELOG.md` has the entry.
- [ ] `README.md` and `docs/PLAN.md` still describe what the binary does.
- [ ] The archive unpacks to exactly one directory and contains the binary.
- [ ] `SHA256SUMS.txt` is generated after the last build.
- [ ] A clean VM runs the archived binary, and install through vn-launcher is verified
      as soon as the launcher's install path ships.
- [ ] No new dependency brings a network client (`cargo xtask ci` checks it).
- [ ] The release notes name the known limitations, including the ones in this file.

## 8. What is never published

- `.msi`, `.dmg`, `.deb`, `.rpm` or `.AppImage` installers. The launcher unpacks
  archives and never runs installers.
- A build that was not produced from the tagged commit.
- An archive without the licence and the README.
- A "portable" asset with a different stem, however convenient it looks today.
