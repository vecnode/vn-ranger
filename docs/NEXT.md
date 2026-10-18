# Next: the work order

Written 2026-10-19 at `62600a1` on `dev`, for whoever picks this up — including a session
with more working memory than the one that wrote it. The plan is
[`PLAN-0.1.7.md`](PLAN-0.1.7.md); this file is the order of work and the exact files, so
nothing has to be rediscovered.

**Rules that do not change:** `dev` is the only place work happens, `main` is only ever a
released commit, `cargo xtask ci` runs **before** the commit, and a capability that cannot
fire does not ship.

## 1. Close Wave 3 — the sampler gets a caller

Everything else in the flow wave is done: `Sampler::observe`, `beacon()`, `BeaconFact`,
`FlowFact::beacon`, and the `flow` fact fields (`beacon`, `beacon_interval`,
`beacon_jitter`). What is missing is the producer and the rule.

| Step | File | What to do |
|---|---|---|
| 1 | `apps/vn-ranger/src/worker.rs` | The poll loop already produces `Vec<ProcessFact>` every two seconds. Have it also call `collect::flows::collect(&process_names)`, and for each fact call `Sampler::observe(key, now_unix())` where `key` is `"{process}>{remote_addr}:{remote_port}"` — the same shape `flow_fact` uses for its subject. Hold one `Sampler` per `WatchService`. |
| 2 | `apps/vn-ranger/src/app.rs` | When a scan's snapshot arrives, take the sampler's answer for each flow and set `FlowFact::beacon`. The sampler lives in the worker, so this is one message on the existing channel — do not add a second one. |
| 3 | `crates/core/src/rules.rs` | The rule: `flow.beaconing`, `Notice`, `Likely`, technique **none** with the note "a rhythm is a channel; what it carries is not observed". Benign: "a client that polls on a fixed interval — an updater, a sync tool, a monitor". Evidence: the interval, the jitter in basis points, the number of contacts. Add the id to `RULE_IDS` and the const to `BUILTIN_RULES`, then `cargo xtask coverage`. |
| 4 | `crates/core/src/rules.rs` tests | Two fixtures in one test: a flow with `beacon: Some(BeaconFact { contacts: 8, interval_s: 60, jitter_bp: 300 })` fires; a flow with `beacon: None` does not. |
| 5 | `docs/RULES.md` | Regenerate the coverage table; the rule count goes to 32. |

**Done when:** a long-running process that talks to one address on a steady rhythm raises
`flow.beaconing`, and a process that talks to it at random does not.

## 2. Wave 4 — the agent collector

`vnr_core::skills` already reads `SKILL.md` and reports the five capabilities. What is
missing is the collector that finds the skills and turns them into facts.

| Step | File | What to do |
|---|---|---|
| 1 | `crates/native/src/collect/agentstack/skills.rs` (new) | Look in the folders a skill lives in: `~/.claude/skills`, `~/.codex/skills`, and vn-code's plugins folder. One `AgentFact` per skill, id `skill:<folder name>`, with the `SKILL.md` path. |
| 2 | same | Read the frontmatter with `skills::read_meta`, list the files beside it, hash each script with `crate::hash`, and run `skills::capabilities` over the scripts' text. Keep the capability kinds and their evidence lines. |
| 3 | `crates/core/src/model.rs` | `AgentFact` gains `capabilities: Vec<(String, String)>` (kind, evidence) and `hash: Option<String>`, both `#[serde(default)]`. |
| 4 | `crates/core/src/fields.rs` + `pack/evaluate.rs` | `agent` fields gain `executes`, `network`, `writes`, `credentials`, `model` (all `bool`), and `agent_fact` fills them. |
| 5 | `crates/core/src/rules.rs` | One rule: `agent.skill-executes-networked` — a skill that both executes and reaches the network. `Attention`, `Observed`, benign: "a package manager, a formatter or a deployment helper that legitimately installs and fetches". |

## 3. Wave 2 — events (needs `evtx`)

`cargo add evtx` (MIT OR Apache-2.0, `unsafe` forbidden, ~200 KB). Then:

- `native/src/collect/events/windows.rs` — read `…\winevt\Logs\*.evtx`, a 24-hour window, 24
  fields per record, `Unavailable` for `Security.evtx` without elevation.
- `native/src/collect/events/linux.rs` — `journalctl --output=json` as a bounded child, file
  fallback; a fixture of NDJSON and one of `auth.log`.
- `native/src/collect/events/macos.rs` — `log show --style json`, 15 minutes, or a named state
  saying the capture is owed.
- `core/src/fields.rs` — the `event` subject; `packs/` — the twelve event rules.

## 4. Wave 1 — containers, then structural facts

`cargo add zip flate2 cfb`. One walker with a ratio cap, 256 MB total, 3 layers, and the
`.ndb` library run on what it extracts — never to disk. Then `goblin` **or** `object`
(measure both, keep one): sections and entropy, imports and imphash, the overlay, the
signature blob, and `authenticode` for the PE digest.

## 5. Wave 5 — the payoff

- `core/src/journal.rs` is chained; the sweep reuses `content::scan` and the four fact
  domains, and offers quarantine through the existing typed path.
- Triage package: `<data>/exports/triage-<time>/` with a hashed manifest, `snapshot.json`,
  `findings.md`, `timeline.csv` (the exporter exists), `events-<channel>.jsonl`.
- `bodyfile` waits for filesystem timestamps — a bodyfile of events is not a bodyfile.

## What a session should verify before it stops

```bash
cargo xtask ci                 # the gate, before the commit
cargo run -q -- --report /tmp/r.json
git status --short             # clean
git log --oneline -1 main      # still the last release
```
