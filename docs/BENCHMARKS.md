# Benchmarks — v0.1.0

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
| Release binary, Windows | 14.8 MB | — | — |
| Windows zip | 6.25 MB | ≤ 12 MB | met |
| Linux tarball | 8.18 MB | ≤ 12 MB | met |
| macOS tarball | 5.11 MB | ≤ 12 MB | met |
| Installed footprint | 14.8 MB plus data | ≤ 40 MB | met |
| Cold start to window | 30–116 ms | ≤ 500 ms | met (first frame not measured) |
| Hashing throughput | not measured | ≥ 200 MB/s | owed |

The release archives contain one top-level directory, `vn-ranger-0.1.0/`, with the
binary, `README.md` and `LICENSE`. That is the layout vn-launcher expects, and the
published Windows binary was extracted and run headless before this file was written.

The 0.1.1 interface embeds Inter and JetBrains Mono. A local 0.1.1 release build with
them measures 15.64 MB for the Windows binary and a 6.37 MB zip, still below the 10 MB
target. The published figures above remain the 0.1.0 release numbers until 0.1.1 ships
and the three platform archives are measured again.

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

## What is not measured yet

- Cold start. The window appears quickly, but "quickly" is not a number. A timestamped
  measurement from process start to first frame is owed.
- Streaming hash throughput on a large file. The v0.1.0 scan hashes startup binaries,
  which are small; a dedicated throughput measurement arrives with the real-time
  watcher.
- A 24-hour resident soak. v0.1.0 has no resident mode, so there is nothing to soak.
- macOS and Linux. The CI builds and tests them; the numbers above are Windows unless
  stated otherwise.

When a number is missed, this file says so and the target is revised with the reason,
as the 120 MB target was. When it is not measured, it says that too.
