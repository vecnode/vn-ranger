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
| Release binary | 14.55 MB | — | — |
| Windows zip | 5.85 MB | ≤ 12 MB | met |
| Installed footprint | 14.55 MB plus data | ≤ 40 MB | met |
| Cold start to first frame | not measured | ≤ 500 ms | owed |
| Hashing throughput | not measured | ≥ 200 MB/s | owed |

The Windows zip contains `vn-ranger-0.1.0/` with the binary, `README.md` and `LICENSE`,
which is the layout vn-launcher expects.

## How each number was taken

- **Scan:** `vn-ranger --report <file>` on the same tree, taking `duration_ms` from the
  snapshot. The range is three consecutive runs, not a best-of-many.
- **Counts:** the same snapshots. They move with what is running, which is why they are
  a range or a single observation rather than a fixed claim.
- **Working set and private bytes:** `Get-Process vn-ranger` after eight seconds idle,
  with the window open on the Overview.
- **Idle CPU:** two samples of `TotalProcessorTime` five seconds apart, divided by the
  elapsed time. The window repaints on demand, so the expected answer is zero.
- **Binary and zip:** `target/release/vn-ranger.exe`, and a zip of the binary with the
  README and licence in one top-level directory.

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
