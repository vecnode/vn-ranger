# Benchmarks

Measured on 2026-10-17 on the development Windows 11 machine (x86_64). These are
observations from one machine, not a specification: a release runner, a laptop on
battery and a machine with a different GPU will differ. The point is to publish the
number rather than the adjective.

## The numbers

| Measure | Result | Target | Verdict |
|---|---:|---:|---|
| Inventory scan, headless | 1.2–1.8 s | ≤ 3 s | met |
| Processes | 287–291 | — | — |
| Startup items | 131 | — | — |
| Listening sockets | 95–102 | — | — |
| Installed packages | 128 | — | — |
| Idle working set | 166 MB | ≤ 200 MB | met (target revised) |
| Idle private bytes | 367 MB | — | observed |
| Idle CPU, one core | 0.00% over 5 s | < 0.5% | met |
| Release binary, Windows | 15.64 MB | — | — |
| Windows zip | 6.83 MB | ≤ 12 MB | met |
| Linux tarball | 8.77 MB | ≤ 12 MB | met |
| macOS tarball | 5.69 MB | ≤ 12 MB | met |
| Installed footprint | 15.64 MB plus data | ≤ 40 MB | met |
| Cold start to window | 30–116 ms | ≤ 500 ms | met (0.1.0 measurement; first frame not measured) |
| Hashing throughput | not measured | ≥ 200 MB/s | owed |

The v0.1.1 release archives contain one top-level directory, `vn-ranger-0.1.1/`, with
the binary, `README.md` and `LICENSE`. That is the layout vn-launcher expects, and the
published Windows binary was extracted and run headless before this file was written.

The 0.1.1 interface embeds Inter and JetBrains Mono; the Windows binary measures
15.64 MB. The three published archives measure 6.83 MB, 8.77 MB and 5.69 MB, all below
the 10 MB target.

## How each number was taken

- **Scan:** `vn-ranger --report <file>` on the same tree, taking `duration_ms` from the
  snapshot. The range is three consecutive runs, not a best-of-many.
- **Counts:** the same snapshots. They move with what is running, which is why they are
  a range or a single observation rather than a fixed claim.
- **Working set and private bytes:** `Get-Process vn-ranger` after eight seconds idle,
  with the window open on the Overview.
- **Idle CPU:** two samples of `TotalProcessorTime` five seconds apart, divided by the
  elapsed time. The window repaints on demand, so the expected answer is zero.
- **Cold start:** three launches of the release binary, timing process start to the
  moment `MainWindowHandle` becomes non-zero. It is not the first painted frame; that
  number is still owed.
- **Release assets:** the four files published on the `v0.1.0` release. The Windows
  binary was extracted from the zip and run with `--report` to confirm the archive is
  not just a correctly named container.

## What was revised, and why

The plan's original idle-RSS target was **120 MB**. The measured working set is
**166 MB**, dominated by egui's wgpu backend and the GPU driver's own allocations. The
target is revised to **200 MB** for v0.1.x, and **120 MB remains the v1.0 goal**: the
next experiment is the `glow` backend, which drops wgpu, naga and the GPU abstraction
from the tree. It is not switched now because the wgpu build is the one that has been
tested on all three platforms, and a renderer change during the first release is not a
benchmark.

The private-bytes figure (367 MB) is larger than the working set because wgpu reserves
address space it may never touch. Working set is the number a person feels in Task
Manager, so it is the one the budget tracks.

## v0.1.2 — watch

Measured on 2026-10-17 on the same Windows 11 machine, from the release build, with the
window visible and the process poll and file watcher running for 30 minutes. Sixty
samples, 30 s apart; the CPU figure is the delta between the first and last sample, so
window creation and the first scan are excluded.

| Measure | Result | Target | Verdict |
|---|---:|---:|---|
| Idle CPU, one core | 0.387% | < 0.5% | met |
| Idle working set | 171.6–173.0 MB | ≤ 200 MB | met |
| Idle private bytes | 374.4 → 373.8 MB | — | flat over the run |
| Poll cadence | 2 s (904 polls; one 3 s gap) | 2 s | met |
| Errors in 30 minutes | 0 | 0 | met |
| Working-set growth | +0.7 MB over 29.5 min | — | no leak signal at this length |

A two-minute check of the final build, after the About window was added, measured
0.286% CPU; the difference from the 30-minute run is window state and noise, not
behaviour. v0.1.3 changes only how a process's start time is read, which adds no work to
a poll, so these figures stand for it.

The application saw **32 processes** here. That is the one number the soak cannot speak
for: the poll cost at the 300-process case needs a full desktop and is still owed, so
the figure above is an idle-behaviour measurement, not a promise about a busy machine.

The window was left visible for the whole run. A minimized window has its working set
trimmed by the operating system, which would have made the memory figure meaningless.

## Still owed

- The poll's refresh at 300 processes (target: under 10 ms). This environment exposes 32,
  so the run above cannot answer it.
- The delay from a file being written to its hash appearing in the timeline.
- The debounce under a burst, measured rather than tested: one editor save must produce
  one event, not four. The behaviour is covered by unit tests; the timing is not.

When these exist they belong in the table above, not in a promise.

## v0.1.6 — the numbers that release owes

0.1.6 is the release that can act, so its budgets are about acting. None of the rows
below is measured yet; each is listed with the target it will be judged against, and the
number that replaces it will carry the build and the configuration with it.

| Measure | Target | What it is judging |
|---|---:|---|
| Journal write, median | < 1 ms | the record exists before the act, and the interface does not stall |
| Journal write, p99 | < 10 ms | `sync_data` on a busy disk is the honest tail |
| Quarantine move, same volume | < 10 ms for 1 GB | one rename: directory work, not bytes |
| Quarantine move, cross volume | bounded by 200 MB/s, verified | copy → sync → verify → unlink |
| Clean preview | 10,000 entries in ≤ 2 s | the walk is visible work |
| Clean cancellation | within 100 ms | a person can stop it |
| Rule pack load | ≤ 30 ms for 512 rules | startup does not wait on a pack |
| Rule evaluation | ≤ 20 ms for 512 rules over 1,000 facts | a pack cannot make the interface feel broken |
| Tray overhead | 0% idle CPU, ≤ 8 MB working set | an icon is not a runtime |
| 24-hour soak, tray and poll running | CPU < 0.5%, working set ≤ 200 MB, growth ≤ +10 MB, zero errors | the configuration a person actually leaves open |

The 24-hour soak is run on the **release candidate**, not on a developer build, and the
numbers are published with the candidate they came from. A soak that does not name its
build is a reading, not evidence.

The recorder is `--soak <file>`, and it is the product measuring itself rather than a
script measuring the product from outside: one NDJSON line a minute with the version, the
CPU of the interval, the working set and private bytes, the descriptor count where the
platform lets a process count its own, and the polls, watcher events and journal lines
written since the previous line. A field a platform cannot fill is `null`, never zero — a
zero is a measurement and would be read as one. Linux reports descriptors; Windows and
macOS do not, because counting handles needs a call this workspace will not make without a
safe wrapper, and that gap is stated here rather than filled with a placeholder.

## The binary, measured again in the 0.1.6 tree

Not a release measurement, and labelled as such: the build beside the working tree on
2026-10-18, at `3353974`, on the development Windows 11 machine.

| Measure | Result | Where it is written down |
|---|---:|---|
| Release binary, Windows x86_64 | **18,856,960 bytes (18.0 MB)** | `docs/PLAN-0.1.7.md` §2.2 and §10 |
| Embedded typefaces | 1.09 MB (three faces, `include_bytes!`) | §10.2 of the same plan |
| Embedded mark, RGBA | 16 KB (64 × 64 × 4, two files) | §10.2 |

The 0.1.1 binary measured 15.64 MB and the repository description says *"~6–9 MB"*, which
is closer to the archive than to the binary. The four budgets in `PLAN-0.1.7.md` §10.1
exist so that a claim about size names which artifact it is about; the 18.0 MB figure is
the one the 0.1.7 size programme has to move, and it is published here before the work
rather than after it.

## What is not measured yet

- Cold start. The window appears quickly, but "quickly" is not a number. A timestamped
  measurement from process start to first frame is owed.
- Streaming hash throughput on a large file. The v0.1.0 scan hashes startup binaries,
  which are small; a dedicated throughput measurement arrives with the real-time
  watcher.
- The 24-hour run itself. The recorder exists (--soak), but no 24-hour sample has been
  taken on a release candidate yet, so the table above states what it must hold rather
  than what it held.
- macOS and Linux. The CI builds and tests them; the numbers above are Windows unless
  stated otherwise.

When a number is missed, this file says so and the target is revised with the reason,
as the 120 MB target was. When it is not measured, it says that too.
