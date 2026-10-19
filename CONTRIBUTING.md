# Contributing to vn-ranger

vn-ranger is a local-only system ranger: it inventories what runs on a machine, explains
what is unusual, remembers a baseline, and — carefully, and only through one typed action
path — quarantines and cleans. It is Rust and egui, it opens no socket that talks to the
network, and it does not hide.

Contributions are welcome, including a bug report with no patch attached. This document
says how a change gets in, and what it has to prove first.

## 1. Read two documents before you write code

| Document | Why |
|---|---|
| [AGENTS.md](AGENTS.md) | The contract. §2 is the golden rules: never crash, never lie, never delete, never phone home, never hide. A patch that breaks one of them is rejected on principle, not on style |
| [docs/PLAN.md](docs/PLAN.md) | The research and the scope. It is long; §1 is the short version, §4 the principles, §13 what is done with a machine's data |

`docs/PLAN-0.1.7.md`, `docs/NEXT.md` and `docs/RULES.md` are the release this tree cut, the
work order, and the closed vocabulary a rule may use. `SECURITY.md` is the promise to the
person running the program, and a change that quietly weakens one of its rows is a defect.

## 2. The contributor licence agreement

The project is **AGPL-3.0-only** ([LICENSE](LICENSE)), and it also offers a **commercial
exception on request**. Both remain possible only if the project holds enough rights in
every contribution to license it again. That is what this agreement buys, and it is why it
is a condition of merge rather than a courtesy.

By opening a pull request and stating in its description that you agree to this section,
you agree, for the contribution in that pull request, that:

1. **The work is yours to give.** You hold the copyright, or you have the copyright
   holder's permission — an employer's, typically — to make this agreement. If your
   employer holds the rights in work you do, say so in the pull request and, if asked,
   provide a letter from them.
2. **You grant a licence, not the copyright.** You grant vecnode a perpetual, worldwide,
   non-exclusive, royalty-free, irrevocable copyright licence to reproduce, prepare
   derivative works of, publicly display, publicly perform, sublicense and distribute your
   contribution and works derived from it, under any licence terms — including the
   AGPL-3.0-only everyone else receives it under, and a commercial licence — and to
   relicense it on those terms. You keep your copyright, and you may use your own
   contribution anywhere else.
3. **Patents come with it.** You grant vecnode and every recipient of the software a
   perpetual, worldwide, non-exclusive, royalty-free, irrevocable patent licence to make,
   use, sell, offer to sell, import and otherwise transfer your contribution, limited to
   the claims you own or control that the contribution necessarily infringes.
4. **There is nothing hidden in it.** To your knowledge the contribution carries no third
   party's copyright, patent or licence term that would prevent the grants above. If part
   of it is not entirely yours, name that part and its licence at the top of the pull
   request, and add it to [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
5. **No warranty.** You provide the contribution as it is, without warranty of any kind,
   and you are not liable for the project's use of it.
6. **It is public from the moment you send it.** The contribution is not confidential.
   It lives in the pull request and then in the repository history.

If a clause is unenforceable where you are, the rest stand. This is not an assignment of
copyright; it is a licence, and it survives a change of maintainer. It cannot be withdrawn
for work already merged, which is what makes it a licence record rather than a promise.

**How to agree.** Put this line in the pull request description, with your name and the
address you want the record kept under:

```text
CLA: I have read CONTRIBUTING.md and I agree to the contributor licence agreement.
```

The pull request is the record: public, dated, permanent. A pull request without that line
is not merged — not as a slight, but because merging it would make the project's licence
claim about that file a claim it cannot keep.

**If you cannot agree to it,** an issue that describes a defect is still worth a great deal
and needs no agreement at all. So does a review, a reproduction, or a corrected sentence in
these documents.

## 3. What a change has to prove

`AGENTS.md` §10 is the full definition of done. Distilled:

- **The behaviour has a test, and the test fails without the change.** A test that passes
  before the patch proves nothing.
- **A parser has a fixture, and the fixture is sanitised.** No real username, hostname or
  path from a real machine; `crates/native/fixtures/` is the precedent.
- **A rule has a positive and a negative case, and a benign explanation.** A rule that
  cannot say what the innocent version of the fact looks like does not ship — that is
  §7 of `AGENTS.md`, and it is the rule that keeps a finding from becoming a verdict.
- **No `unwrap`, `expect`, `panic!`, `todo!` or `unimplemented!` outside a test.** The
  workspace denies them; a missing API, a truncated file or a process that exits mid-read
  is an outcome a person can act on, never a crash.
- **No `unsafe`.** It is forbidden at workspace level. A platform call belongs behind a
  safe crate, or the feature waits.
- **No new dependency without §8.** Every crate is a licence, a supply chain and a size
  decision, and a GPL, AGPL or LGPL dependency is refused. Say in the pull request what the
  crate bought.
- **No network.** `cargo xtask ci` bans the network crates by name and greps the tree for a
  socket. v0.x is offline by design, and that is a product feature rather than an
  implementation detail.
- **The documents and the interface still tell the truth.** If a promise in `SECURITY.md`,
  `docs/PLAN.md` or the interface language stops being true, it changes in the same pull
  request. `cargo xtask language` is the check for the interface half of that sentence.
- **`cargo xtask ci` is green**, including the cross-target clippy where it can run.

## 4. The one path that needs a second reviewer

`crates/native/src/action.rs`, `quarantine.rs` and `clean.rs` are the only code that can
destroy data. A change there needs two reviewers, and the second writes the traversal table
from the specification without reading the first one's tests — so that two people have
independently asked "can this leave its root?" and got the same answer.

The order in that path is fixed and is not a style preference: **journal, then act, then
result**. A destructive verb is named by an id, never by a path, and is resolved through an
already-open `cap_std::fs::Dir`. Links, hard links, a file whose identity changed since it
was inspected, and anything outside the root are refused with a reason. Present a pull
request that removes one of those refusals and it will be rejected whatever else it fixes.

## 5. Building and checking

```bash
cargo run --release       # the ranger
cargo xtask ci            # everything CI runs, in the order CI runs it
cargo xtask test          # tests alone
cargo xtask lint          # clippy alone
```

`ci` is `fmt --check`, the no-network audit, the language audit, pack validation, the
coverage table in `docs/RULES.md`, the signature test, the "no content engine in the
default build" check, clippy with warnings denied, and then the tests.

The first build is the slow one: egui, wgpu and winit are most of the tree. After that,
`cargo xtask ci` is the loop, and it is exactly what CI runs — there is no separate CI
recipe to discover.

Three platforms are built in CI, and two of them will disagree with your machine. If your
change contains a `#[cfg]`, hold it to a target you are not on; `AGENTS.md` §5 has the
command and the reason an attribute on a statement deletes it elsewhere.

## 6. Commits and pull requests

- A commit subject is imperative and capitalised: *Say what an executable is*, not
  *Fixed the executable thing*.
- The body says **why**, because the diff already says what. A comment in the code follows
  the same rule.
- One concern per pull request. A licence change, a refactor and a bug fix are three.
- Say what you verified, and say what you did not. "Tested on Windows 11 only" is a useful
  sentence; silence reads as "tested everywhere".
- A dependency change is its own pull request, with the licence, the size and the reason.

## 7. Reporting a defect

- A **defect** is a GitHub issue: what you expected, what happened, the version, the
  platform, and the smallest sequence that reproduces it.
- A **vulnerability** is not an issue. Use
  [SECURITY.md](SECURITY.md) and GitHub's private reporting. Do not open a public thread,
  and do not attach a live sample to one.
- A **false positive** is a security defect in this product, not a cost of doing business.
  Report it with the evidence the interface showed and the benign explanation it missed.

## 8. Style

British spelling in prose and identifiers — `colour`, `behaviour`, `licence` as a noun —
and `color` only where it is a field name a person might type. A doc comment on every
public item. A named constant over a literal, and a named type over a tuple. A long
function that is a sequence of interface statements is fine; a long function that is a
tangle of decisions is not.

## 9. Licence of what you add

- Everything you add is distributed under **AGPL-3.0-only**. There is no per-file header to
  copy; `LICENSE` at the root covers the tree, and a header duplicated 400 times goes stale
  the first time it is edited.
- **Do not paste code from another project** unless its licence permits it here and you
  name it in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). The default answer is no: a
  copied file is a licence this repository cannot relicense, which is the same reason
  `AGENTS.md` §8 refuses a copyleft crate.
- Reading a **documented format** is not copying code. The ClamAV signature readers
  (`.hdb`, `.hsb`, `.ndb`) are the standing example: the format is implemented here from
  its documentation, no ClamAV source is in the tree, and the notices say exactly that.
- A **new dependency** changes the notices, so `cargo metadata --format-version 1` and the
  regeneration described in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) belong in the
  same pull request. A stale notices page is a licence claim that is no longer true.
