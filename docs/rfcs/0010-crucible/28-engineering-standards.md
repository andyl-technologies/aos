# 28 — Engineering Standards

This file states the **engineering standards** every `crucible-*` crate is held
to: the Rust quality bar, the documentation bar, the harness-determinism lint
that makes [INV-9] real, the `unsafe` discipline, the per-layer testing
standards, file/module hygiene, and the **determinism review checklist** a
reviewer applies to any PR touching the engine, scheduler, or transport.

It is the engineering-side companion to two other files. The *crate structure*
and the layer map (L0–L4) are owned by
[`27-crate-structure.md`](27-crate-structure.md); this file does not redefine
them, it defines how the code inside them is written. The *gate catalog* and the
*test strategy* are owned by [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md);
this file binds those gates to concrete coding rules. The three gates this file
leans on most are canonical there: `gate:harness-lint` (§9 of 24),
`gate:abi-conformance` (§8 of 24), and `gate:replay-oracle` (§6 of 24).

Crucible code is a determinism artifact, not ordinary application code. A bug in
ordinary code produces a wrong answer; a determinism bug here produces a *flaky*
answer, which is worse, because it is the exact failure mode the whole system
exists to abolish ([G-1], [INV-1]). The standards below are therefore stricter
than general "good Rust": they ban, at compile time, the constructs that leak
nondeterminism, and they treat every determinism-relevant boundary as a tested,
versioned data contract.

Requirement IDs here use the prefix **`STD`**. (The `CRATE` prefix is reserved by
[`27-crate-structure.md`](27-crate-structure.md); both files share the area
column in [`00-conventions.md`](00-conventions.md) §"Area prefixes" but this file
numbers its requirements `STD-n`.) These standards align with the repository's
root `CLAUDE.md` (the AOS Rust code style and documentation standard) exactly,
and add the Crucible-specific determinism rules on top.

The spine of this file is one sentence:

> **The compiler, the linter, and the reviewer each refuse a class of
> nondeterminism the next one would miss** — the lint bans it at compile time
> (`gate:harness-lint`), the runtime gates detect what the lint misses
> (`gate:layer0-determinism`, `gate:adversarial-determinism`), bisection
> localizes what slips through ([INV-10], `gate:divergence-bisect`), and the
> review checklist (§6) is the human backstop on every engine PR.

---

## 1. Rust quality

These requirements restate the root `CLAUDE.md` Rust code style as normative
Crucible requirements so the implementation plan can cover them and a reviewer
can cite them. Where `CLAUDE.md` and this file appear to differ, `CLAUDE.md`
wins and the discrepancy is a defect in this file.

### 1.1 Documentation (docs.rs quality)

- **[STD-1]** Every `crucible-*` crate MUST carry docs.rs-quality rustdoc to the
  bar defined in the root `CLAUDE.md` "Rust documentation standard". Concretely:
  each crate's `lib.rs`/`main.rs` MUST carry a `//!` crate overview (what the
  crate does, a map of its modules, how the pieces fit); every module file MUST
  carry a `//!` header naming what the module owns and its key concepts; and a
  module that owns an on-disk or wire format (the shmem layout, the protocol
  framing, the RPC schema, the reproduction-artifact format, the event-log
  segment format) MUST show that format in a fenced example block. *Gate:* the
  doc build is part of the workspace build; `cargo doc` MUST succeed with no
  warnings. *Spec:* §1.1.

- **[STD-2]** Every public item MUST have a `///` rustdoc comment: a
  one-sentence, third-person summary line, then detail only where behavior is
  non-obvious. Public struct fields whose meaning is not self-evident MUST be
  documented; schema/config/ABI structs are data contracts and their field docs
  are mandatory (the shmem region, `FrameEntry`, `Decision`, `Checkpoint`,
  `ReproArtifact`, the RPC message types). *Spec:* §1.1.

- **[STD-3]** Every public function returning `Result` MUST carry an `# Errors`
  section describing the conditions that produce each error variant; every item
  with a reachable panic MUST carry a `# Panics` section. Because Crucible's
  errors are mostly *determinism-relevant* (a divergence, a hash mismatch, an
  ABI-version mismatch), the `# Errors` text MUST name the invariant or gate the
  error defends where one applies (e.g. "returns [`Error::AbiVersion`] when the
  peer's ABI version does not match; see `gate:abi-conformance`"). *Spec:* §1.1.

- **[STD-4]** Every fenced code block in rustdoc MUST be tagged (` ```text `,
  ` ```rust `, ` ```toml `, ` ```no_run `, or ` ```ignore `). An untagged fence
  becomes a compiled doctest in the hermetic AOS build and an untagged *format*
  example is therefore a build failure (consistent with `CLAUDE.md` and the AOS
  `pkgs.aos`/`pkgs.crucible` doc build). Runnable `# Examples` are added only
  when they compile against the public API alone; prefer `no_run`. *Spec:* §4.5.

- **[STD-5]** The clap-derive caveat from `CLAUDE.md` applies to the `crucible`
  CLI ([`23-cli.md`](23-cli.md)): doc comments on `#[derive(Parser/Subcommand/Args)]`
  containers and their fields become `--help` output. Container `///` docs MUST
  NOT be added (document the surrounding module instead); a field doc edit is a
  user-facing CLI change and MUST be short, imperative, and accurate. *Spec:*
  §1.1.

- **[STD-6]** Intra-doc links (`` [`Item`] ``) MUST resolve to items visible
  from the linking item; a public-doc link to a private item is a warning and
  warnings fail the doc build ([STD-1]). Comments and docs MUST use ASCII
  punctuation. *Spec:* §1.1.

### 1.2 Error handling and logging

- **[STD-7]** Production code MUST NOT use `.unwrap()` or `.expect()`. Errors
  MUST be propagated with `?`, returned as `Result`, and modeled with proper
  types. The single exception is a panic that is the *intended* signal: a
  determinism-invariant violation that MUST fail loudly per [INV-10] (e.g. a
  replay-oracle hash mismatch detected at runtime) MAY `panic!`/`assert!` with a
  message that names the invariant — but it MUST do so explicitly, never via a
  bare `.unwrap()`. Tests and `# Examples` MAY use `.unwrap()`/`.expect()` where
  a panic is the intended test signal. *Gate:* `gate:harness-lint` flags
  `.unwrap()`/`.expect()` in non-test engine code (§2). *Spec:* §1.2.

- **[STD-8]** Library crates (every `crucible-*` crate that is not the binary)
  MUST model errors with **typed errors** (`thiserror`-style enums with one
  variant per failure mode), never `anyhow`. `anyhow` (or equivalent erased
  errors) MAY be used **only at the binary boundary** — the `crucible` CLI's
  `main` and its top-level command handlers — to attach context to a typed error
  on its way to the user. An engine or transport crate that returns `anyhow`
  from a public API is a defect. *Spec:* §1.2.

- **[STD-9]** Library crates MUST NOT write to `stdout`/`stderr` directly:
  diagnostics MUST go through `tracing` (spans + structured events), never
  `println!`/`eprintln!`/`print!`. The CLI/daemon binary owns the `tracing`
  subscriber and is the only place output is rendered for a human. Because
  wall-clock and ordering may legitimately appear in *logs* but never in
  *state*, all `tracing` output is **observational** ([INV-1],
  [`19-observability-event-log.md`](19-observability-event-log.md)) and MUST NOT
  feed back into `State` — a `tracing` field is never read by engine logic.
  *Spec:* §1.2, §2.

---

## 2. The harness-determinism lint (`gate:harness-lint`, INV-9)

The cheapest, broadest determinism defense is a static lint that bans the
constructs that introduce ordering nondeterminism before they reach a runtime
test (§9 of [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md),
which owns `gate:harness-lint` via [HARN-24]..[HARN-26]). This section pins the
**concrete banned-pattern set** and **how it is enforced** so the lint is a
buildable spec, not a slogan.

### 2.1 The banned-pattern set

- **[STD-10]** In every **engine and scheduler crate** (L0 `crucible-sim`,
  `crucible-assert`; L1 `crucible-shmem`, `crucible-protocol`, `crucible-device`;
  L3 `crucible`; and any host code on an ordering-significant path), the
  following patterns are **banned** and a single occurrence fails
  `gate:harness-lint`:

  1. **Unordered hash-container iteration on an ordering-significant path.**
     Iterating a `HashMap`, `HashSet`, or any hash-ordered container (including
     `.iter()`, `.values()`, `.keys()`, `.drain()`, `into_iter()`, and `for`
     loops over them) where the iteration order affects `State`, the `Schedule`,
     the canonical event log, a content hash, or any decision. Ordered
     containers — `BTreeMap`/`BTreeSet`, or `IndexMap` with a fixed insertion
     order, or an explicitly **sorted** `Vec` — MUST be used instead. Building a
     hash map and iterating it sorted (`collect` into `BTreeMap`, or
     `sort_unstable_by_key` before iterating) is the sanctioned escape; the lint
     accepts a sorted-before-iterate pattern.

  2. **Host wall-clock on a state path.** `std::time::Instant::now`,
     `SystemTime::now`, `Instant::elapsed`, `Duration` arithmetic derived from a
     real clock, or any equivalent on a path that influences `State`. Virtual
     time is icount-derived ([INV-4], [`09-virtual-time-icount.md`](09-virtual-time-icount.md));
     wall-clock is permitted only for **observational** logging behind a type
     that cannot feed canonical state ([STD-9]).

  3. **Thread/global RNG or host entropy.** `rand::thread_rng`, `rand::rng`,
     `rand::random`, `getrandom`, `/dev/urandom` reads, `RandomState`'s default
     hasher seeding where the seed escapes into ordering, or any equivalent. All
     randomness MUST come from the **seeded decision RNG** ([`04-determinism-contract.md`](04-determinism-contract.md),
     [`08-scheduling.md`](08-scheduling.md)), whose per-entity streams are forked
     by entity name-hash so adding a node does not perturb others ([HARN-31]).

  4. **Unordered `select`.** A `select!`/`select` (futures, tokio, crossbeam)
     whose branch choice on simultaneous readiness is nondeterministic, on any
     ordering-significant path. A **deterministic, priority-ordered** selection
     (e.g. `biased;` ordering, or an explicit poll order) MUST be used so the
     branch taken on a tie is a pure function of branch priority.

  5. **Floating point on a decision path.** `f32`/`f64` arithmetic where the
     result feeds `State`, a `Decision`, a probability comparison (does this
     fault fire?), a content hash, or the canonical log. Decision-path
     quantities that look fractional — loss probability, latency jitter weight,
     fault firing thresholds — MUST be expressed as **integer basis points**
     (or another fixed-point integer scale) so the comparison is exact and
     host-FPU-independent. `f64` is permitted only for *observational* metrics
     ([STD-9]) that never feed `State`.

- **[STD-11]** The default `HashMap`/`HashSet` hasher (`RandomState`) is
  additionally banned across **all** `crucible-*` crates, even off the
  ordering-significant path, because its per-process random seed makes accidental
  order-leaks irreproducible across runs. Where a hash map is genuinely needed
  (a pure-lookup cache whose order never escapes), it MUST use a **fixed-seed
  deterministic hasher** and MUST carry the [STD-13] annotation. This makes
  every hash map in the workspace either ordered, or fixed-seeded-and-annotated —
  never accidentally random.

### 2.2 How the lint is enforced

- **[STD-12]** `gate:harness-lint` MUST enforce the [STD-10]/[STD-11] set with a
  **two-tier** mechanism, both required to pass:

  1. **Clippy/dylint tier.** A curated `clippy` lint configuration plus custom
     `dylint` lints, denied (not warned), covering the mechanically-detectable
     patterns: `clippy::disallowed_methods` and `clippy::disallowed_types`
     populated with the banned APIs and types (`std::time::Instant::now`,
     `std::time::SystemTime::now`, `rand::thread_rng`, `rand::rng`,
     `rand::random`, `getrandom::getrandom`, `std::collections::hash_map::RandomState`,
     `HashMap`/`HashSet` without an explicit deterministic hasher), plus the
     workspace `#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used,
     clippy::float_arithmetic_on_decision_path)]`-style deny set. The
     disallowed-list is checked into the workspace `clippy.toml`/`Cargo.toml` and
     is part of the spec surface ([STD-14]).

  2. **Custom static-analysis / grep tier.** A custom analysis pass (preferred:
     a `dylint` driver with type/path awareness; minimum acceptable: a scoped,
     reviewed `grep`-gate) catches what clippy cannot express: unordered
     iteration of a hash container on a path the analysis marks
     ordering-significant, and an unordered `select` on such a path. The pass
     MUST run over exactly the `crucible-*` crates, MUST be deterministic itself
     ([HARN-2] — same tree ⇒ same verdict), and MUST emit a finding with file,
     line, and the rule violated.

  The gate fails on **zero tolerance**: a single finding from either tier fails
  it. The combined run MUST complete on every PR before any other gate
  ([HARN-24], Phase 0). *Gate:* `gate:harness-lint`. *Spec:* §9 of 24.

- **[STD-13]** Where a banned construct is *legitimately safe* (a `HashMap`
  whose iteration order provably never escapes into `State`/`Schedule`/log/hash),
  the exception MUST be **explicit and annotated**: a documented `#[allow(...)]`
  (or a sanctioned `// crucible-lint: allow <rule> — <rationale>` marker the
  custom tier recognizes) carrying a one-line rationale and, where non-obvious, a
  back-reference to why the order does not escape. An un-annotated allow is itself
  a finding. The result is that **every** use of a banned construct in the
  workspace is either rejected by the gate or justified in place — never silently
  tolerated ([HARN-25]). *Spec:* §2.1.

- **[STD-14]** The banned-API/type list and the custom-pass rule set are a
  **versioned part of the spec**: changing them (adding a banned API, granting a
  new exception class) MUST be a reviewed change to the workspace lint config in
  the same PR, and the determinism review checklist (§6) MUST be applied. The
  lint config is the executable form of [INV-9]; it MUST NOT be weakened to make
  a PR green — a finding is fixed at its root ("prefer root-cause over
  workaround"), never suppressed to pass. *Spec:* §2.2.

- **[STD-15]** The lint is the *first* line of defense, not the only one
  ([HARN-26]): a determinism leak it misses MUST still be caught at runtime by
  `gate:layer0-determinism` / `gate:adversarial-determinism` and localized by
  bisection (`gate:divergence-bisect`, [INV-10]). A reviewer MUST NOT treat a
  green `gate:harness-lint` as sufficient for an engine PR — the review checklist
  (§6) is still applied. *Spec:* §9 of 24.

---

## 3. `unsafe` discipline

Crucible needs `unsafe` in a small, sharply-bounded set of places — the shared
memory mapping, the lock-free SPSC ring, the FFI to the QEMU plugin C ABI, and
atomics with explicit orderings — and nowhere else. The root `CLAUDE.md` rule
("avoid `unsafe` at all costs; justify and document the invariants with a
`// SAFETY:` comment") is tightened here into a crate-level fence.

- **[STD-16]** `unsafe` is **forbidden by a crate-level fence** in every
  `crucible-*` crate except the explicitly enumerated FFI/mmap/atomics crates.
  Crates that contain no `unsafe` MUST declare `#![forbid(unsafe_code)]` at the
  crate root; the [`27-crate-structure.md`](27-crate-structure.md) crate table is
  the source of truth for which crates carry the fence and which are exempt. The
  set of `unsafe`-permitted crates is limited to those that genuinely need it:
  the shmem/transport crate(s) (`crucible-shmem` for the mmap'd `#[repr(C)]`
  region and the SPSC ring's atomics), and the QEMU-plugin crate
  (`crucible-qemu-plugin`, the in-VM `cdylib` that crosses the C plugin ABI).
  Adding `unsafe` to any other crate requires removing its `forbid` fence, which
  is a reviewed change gated by the §6 checklist. *Spec:* §3.

- **[STD-17]** In an `unsafe`-permitted crate, every `unsafe` block MUST be
  preceded by a `// SAFETY:` comment that states the invariants the block relies
  on and why they hold here (the pointer is valid and aligned for the lifetime of
  the access; the atomic ordering is sufficient for the producer/consumer
  protocol; the FFI contract upheld by the plugin host). A bare `unsafe` block
  with no `// SAFETY:` comment is a `gate:harness-lint` finding (the custom tier
  checks for it). *Spec:* §3.

- **[STD-18]** `unsafe` MUST be confined to the smallest possible scope and
  wrapped in a safe abstraction whose *safe* surface upholds the invariants, so
  that callers cannot violate them. The SPSC ring exposes safe `push`/`pop`; the
  shmem region exposes safe typed accessors; the plugin FFI is wrapped in safe
  Rust shims. No `unsafe` detail leaks into the engine (L3) or control plane
  (L4), which remain `#![forbid(unsafe_code)]`. The SPSC ring's `unsafe` MUST be
  validated by the exhaustive ordering model and trace-property corpus of
  [STD-22] before it is relied on.
  *Spec:* §3, §4.

---

## 4. Testing standards

Testing is owned by [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
(the gate catalog and the layered strategy); this section states the **coding
standards for tests** that the implementation plan holds each crate to. The
guiding rule is **per-layer**: a layer's determinism property is owned by that
layer's gate and MUST NOT be "covered" from a higher layer ([HARN-3]).

- **[STD-19]** Each crate MUST carry tests whose primary determinism property is
  its layer's gate ([HARN-3], §2 of 24): L0 → `gate:layer0-determinism`; L1 →
  `gate:layer1-injection`, `gate:abi-conformance`, `gate:content-address`; L2 →
  `gate:single-vm-fingerprint`, `gate:any-guest`, `gate:qemu-inert`; L3 →
  `gate:replay-oracle`, `gate:scheduler-liveness`, `gate:content-address`; L4 →
  `gate:control-responsive`. A higher-layer test MUST NOT be the *only* coverage
  of a lower layer's determinism property. *Spec:* §2 of 24.

- **[STD-20]** Determinism tests MUST follow the **twice-reduce, compare-by-hash**
  shape: drive the unit through a fixed decision sequence (or a fixed
  `(image, cmdline, seed, injected-input)` for real-QEMU tests) **twice** and
  assert the canonical digests are byte-identical, never asserting on a
  human-formatted dump. The canonical digest excludes observational entries
  ([INV-1], [`19-observability-event-log.md`](19-observability-event-log.md)).
  Test fixtures MUST be deterministic under [HARN-2]: a test that is flaky is
  treated as a *failing determinism test*, and its flake is root-caused as a
  residual nondeterminism, never retried or `#[ignore]`d to pass. *Spec:* §2 of
  24.

- **[STD-21]** The bulk of L1/L3/L4 determinism tests MUST run against the
  **in-process QEMU double** (`SimDouble`, §3 of 24) so they execute in
  milliseconds without booting a guest; only the three intrinsic-QEMU properties
  (Contract A instruction determinism, guest non-mutation, patch inertness)
  require real QEMU. The double MUST use the *shared* shmem/queue/codec crates,
  never a re-implementation ([HARN-15]), and participates in `gate:harness-lint`
  like any engine code ([HARN-17]). *Spec:* §3 of 24.

- **[STD-22]** Every concurrent primitive — the SPSC frame ring and any other
  lock-free or atomics-based structure ([`13-shmem-abi.md`](13-shmem-abi.md)) —
  MUST be covered by **(a)** a hermetic exhaustive memory-ordering model that
  enumerates all producer/consumer interleavings under the declared atomic
  orderings and **(b)** a deterministic exhaustive operation-trace corpus
  asserting no lost frame, no duplicated frame, FIFO order, correct full/empty
  behavior, and correct wraparound ([HARN-33]). At least one deliberately
  weakened ordering MUST fail as a negative control. These run in-process, are
  part of the L1 gate set, and MUST pass before any `unsafe` in the ring is
  relied on ([STD-18]). *Gate:* `gate:layer1-injection`. *Spec:* §8.2 of 24.

- **[STD-23]** Each of the three boundary ABIs — the shmem layout, the
  guest↔host protocol framing, and the control-plane RPC schema — MUST have a
  **frozen golden-vector** corpus checked into the repo and a round-trip
  property `decode(encode(x)) == x` for all well-formed inputs ([HARN-32],
  [HARN-34]). `gate:abi-conformance` compares the live encoding byte-for-byte
  against the golden vectors and verifies the version field; an intentional ABI
  change MUST bump the version and regenerate the vectors **in the same PR**, so
  a silent layout drift fails CI. The codec and the 9p/blk wire handlers MUST be
  **fuzzed** (structure-aware; never panics, never reads out of bounds, decodes
  deterministically or rejects cleanly), with findings added to the regression
  corpus. *Gate:* `gate:abi-conformance`. *Spec:* §8.1, §8.3 of 24.

- **[STD-24]** Every rustdoc fenced block that is *not* tagged `text`/`toml`/
  `no_run`/`ignore` is a compiled **doctest** and MUST compile and pass in the
  hermetic AOS doc build ([STD-4]). Doctests are part of the test surface, not a
  separate concern: a PR that breaks a doctest is failing CI the same as a unit
  test. *Spec:* §1.1, §4.5.

- **[STD-25]** The **replay-oracle test** (`gate:replay-oracle`, [INV-2]) is the
  load-bearing structural test and MUST be exercised two ways: deterministically
  over a fixed checkpoint corpus in CI, and **randomly during state-space
  search/fuzzing** at a configurable sampling rate, so each materialized fat
  checkpoint is also reconstructed thin and compared by canonical hash
  ([HARN-12], [HARN-13]). A mismatch is a hard failure that triggers bisection
  (§5 of 24). Most of the corpus runs against the `SimDouble` so the oracle is
  exercised in milliseconds. *Gate:* `gate:replay-oracle`. *Spec:* §6 of 24.

- **[STD-26]** **Coverage expectations.** Determinism-critical code — the
  scheduler quantum loop and ordering keys, the decision RNG and its per-entity
  forking, the content-addressed digest helpers, the SPSC ring, the protocol
  codec, the replay-oracle path, and the reproduction-artifact (de)serializer —
  MUST be covered such that every banned-pattern-adjacent branch and every error
  variant is exercised by a test. Coverage is a *floor on the determinism core*,
  not a blanket percentage target across the workspace: a green coverage report
  with an uncovered ordering branch in the scheduler is a defect; uncovered
  trivial getters are not. Coverage MUST be measured deterministically and MUST
  NOT itself perturb determinism (instrumentation runs in a separate test build).
  *Spec:* §4 of this file.

---

## 5. File, module, and commit hygiene

- **[STD-27]** **File and module size.** A source file SHOULD stay under **~600
  lines** and MUST stay under **1000**; a file that exceeds the soft limit MUST
  be split along a module boundary, not left as a monolith. Every `.rs` file is a
  module with a `//!` header ([STD-1]); a module owns one coherent concern (one
  ABI format, one scheduler concern, one fault family). A function on a
  determinism-significant path (the quantum loop, the ordering comparator, the
  codec) SHOULD be small enough to review for nondeterminism in one sitting;
  where it cannot be, it MUST be decomposed so each ordering decision is
  individually reviewable against the §6 checklist. *Spec:* §5.

- **[STD-28]** **Module boundaries follow the layer map.** A crate MUST NOT
  depend on a higher layer or sideways across a peer boundary that
  [`27-crate-structure.md`](27-crate-structure.md) forbids; the host's node
  abstraction MUST be defined against the ABI/protocol boundary, never against a
  QEMU-specific type, so the `SimDouble` is a drop-in ([HARN-14]). A dependency
  edge that violates the layer DAG is a build-graph defect caught by the crate
  structure's own check. *Spec:* §27.

- **[STD-29]** **Commit hygiene.** Commits MUST be focused and atomic (one
  logical change), with an imperative summary line and a body explaining *why*
  where it is not obvious. A change to a versioned ABI, a golden-vector
  regeneration, and an engine logic change that depends on it MUST land
  together, never split across PRs in a way that leaves CI red or the ABI
  unversioned ([STD-23]). A commit MUST NOT mix a determinism-relevant change
  with unrelated formatting churn, so the §6 reviewer can see exactly what
  changed on an ordering-significant path. Per the AOS workflow, commit and push
  only when explicitly requested. *Spec:* §5.

- **[STD-30]** **Documenting existing code is comments-only.** A docs pass MUST
  NOT reorder, rename, or reformat code (root `CLAUDE.md`): it adds `//!`/`///`
  and `// SAFETY:` comments only. If a doc claim contradicts the code, the doc is
  fixed to match the *observed* behavior and the discrepancy is flagged in the PR
  for separate resolution — the code is never changed in a docs pass. This keeps
  a determinism-relevant code change from hiding inside a documentation diff.
  *Spec:* §5.

- **[STD-31]** **Doc-lint and the gate catalog.** A documentation lint MUST keep
  the RFC and the code honest: every gate referenced anywhere in the RFC MUST
  appear verbatim in the §1.1 gate catalog of
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md), and
  every catalog gate MUST be wired into the phase plan ([HARN-1]); every topic
  file's **Implementation checklist** MUST match the master plan's task inventory,
  file ownership, phase-order projection, and ordered-text digest ([PLAN-3]). A
  referenced-but-undefined gate, a defined-but-unreferenced gate, or a drifted
  per-file checklist is a doc-lint failure. *Spec:* §1 of 24,
  [`00-conventions.md`](00-conventions.md).

---

## 6. The determinism review checklist

Every PR that touches an **engine, scheduler, or transport** crate (L0
`crucible-sim`/`crucible-assert`; L1 `crucible-shmem`/`crucible-protocol`/
`crucible-device`; L3 `crucible`), or any host code on an ordering-significant
path, MUST have this checklist applied by the reviewer before merge. It is the
human backstop behind the lint ([STD-15]) and the runtime gates: the lint catches
the mechanical cases, the gates catch what runs, and this checklist catches the
*design-level* leaks neither can see.

- **[STD-32]** A reviewer MUST apply the following determinism review checklist to
  any PR touching an engine/scheduler/transport crate, and MUST block the PR on
  any unchecked item. The checklist is recorded in the PR (a template). *Gate:*
  enforced by review on top of `gate:harness-lint`. *Spec:* §6.

The checklist:

```text
DETERMINISM REVIEW CHECKLIST (apply to any engine/scheduler/transport PR)

Ordering
[ ] Every collection on an ordering-significant path is ordered (BTree*/IndexMap/
    sorted Vec) or carries a justified [STD-13] allow. No HashMap/HashSet
    iteration leaks order into State / Schedule / canonical log / a hash.
[ ] Any sort uses a TOTAL, stable key — the cross-node order key is
    (virtual_time, consumer node_id, producer node_id, sequence) [INV-3]; ties cannot resolve by address,
    pointer, allocation order, or insertion-into-a-hash order.
[ ] Any select/poll over simultaneous readiness is biased/priority-ordered;
    the branch taken on a tie is a pure function of declared priority.

Time, randomness, numerics
[ ] No host wall-clock (Instant::now/SystemTime::now/elapsed) feeds State;
    virtual time is icount-derived [INV-4]. Wall-clock appears only in
    observational tracing that never feeds back.
[ ] No thread_rng/getrandom/host entropy; all randomness is the seeded decision
    RNG, forked per-entity by name-hash so adding/renaming a node doesn't
    perturb others [HARN-31].
[ ] No f32/f64 on a decision path; fractional decision quantities are integer
    basis points (or fixed-point) so comparisons are exact and FPU-independent.

State purity & content addressing
[ ] State is still a pure function of (ScenarioDef, Schedule) [INV-1]; no new
    uncontrolled input (env var, file mtime, host core count, address) reaches it.
[ ] Anything newly added to the canonical log/hash is canonical, not
    observational; anything that may vary between equivalent runs is
    observational by schema, not by a side flag [OBS schema].
[ ] Content addressing holds: equal content ⇒ equal id; the (de)serializer is
    canonical (stable field order, no map-order dependence) [INV-6].

ABI, unsafe, errors
[ ] If a boundary ABI changed: version bumped AND golden vectors regenerated in
    THIS PR; round-trip property still holds [STD-23], gate:abi-conformance.
[ ] If unsafe was added/touched: the crate is an enumerated unsafe-permitted
    crate [STD-16]; every block has a // SAFETY: comment [STD-17]; the safe
    wrapper upholds the invariant; SPSC changes are covered by the exhaustive
    ordering model and its negative controls [STD-22].
[ ] No .unwrap()/.expect() in production; library errors are typed (thiserror),
    anyhow only at the binary boundary; a loud-failure panic names the invariant
    it defends [STD-7, STD-8, INV-10].

Tests & gates
[ ] The relevant layer gate covers the change (not a higher layer) [HARN-3];
    a new determinism property has a test that FAILS when it is violated.
[ ] If the change could introduce nondeterminism the lint can't express, it is
    exercised under gate:adversarial-determinism and localizable by bisection
    [INV-10].
[ ] gate:harness-lint config was not weakened to make this PR green; any new
    [STD-13] allow has a written rationale.
```

- **[STD-33]** When the checklist surfaces a leak, the fix MUST be at the
  **source** of the nondeterminism, never a workaround that smooths it over
  (retry, jitter tolerance, "compare with a fudge factor") — consistent with
  [INV-10] ("localize, never smooth over") and the AOS "prefer root-cause over
  workaround" principle. A PR that papers over a determinism leak rather than
  eliminating it MUST be blocked even if CI is green, because the gates only
  prove the *tested* interleavings, and the leak will resurface. *Spec:* §6,
  [INV-10].

---

## 7. How these standards thread into the plan

Each `STD-n` is satisfied by a `T-STD-n` task below (verbatim copy of the
master-plan task for this file, per [PLAN-3]). These are **Phase-0 foundation
tasks**: the lint, the unsafe fences, the typed-error and `tracing` conventions,
and the review-checklist template come *before* feature code, because they are
the conditions under which feature code can be trusted to stay deterministic
([G-5]). `gate:harness-lint` runs on every PR from Phase 0 onward (§13 of 24).

---

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is this file, tracked by [PLAN-3]. They are
> **Phase-0 foundation tasks** — the engineering standards are in force before
> feature code is written.

- [x] **T-STD-1** Establish the workspace rustdoc bar: crate `//!` overviews,
  module `//!` headers (format blocks for ABI/wire/on-disk modules), `///` on
  every public item and data-contract field, `# Errors`/`# Panics` sections, and
  a warning-free `cargo doc` as part of the build. — satisfies [STD-1], [STD-2],
  [STD-3], [STD-6]; spec §1.1.
- [x] **T-STD-2** Enforce tagged-fence doctests (untagged fence = build failure),
  apply the clap-derive caveat to the `crucible` CLI, and wire doctests into the
  hermetic AOS doc build. — satisfies [STD-4], [STD-5], [STD-24]; spec §1.1, §4.5.
- [x] **T-STD-3** Establish the error/logging conventions: deny
  `.unwrap()`/`.expect()` in production, typed (`thiserror`) errors in every
  library crate, `anyhow` only at the binary boundary, and `tracing`-only
  diagnostics from libraries (no `println!`/`eprintln!`). — satisfies [STD-7],
  [STD-8], [STD-9]; spec §1.2.
- [x] **T-STD-4** Implement the `gate:harness-lint` clippy/dylint tier: the
  checked-in `disallowed_methods`/`disallowed_types` list (wall-clock,
  thread/global RNG, `RandomState`, raw `HashMap`/`HashSet`) and the workspace
  deny set (incl. `unwrap_used`/`expect_used` and decision-path float
  arithmetic). — satisfies [STD-10] (1–3, 5), [STD-11], [STD-12]; spec §2.
- [x] **T-STD-5** Implement the `gate:harness-lint` custom static-analysis tier:
  ordering-significant-path tracking that flags unordered hash-container
  iteration and unordered `select`, plus bare-`unsafe`-without-`// SAFETY:`
  detection; deterministic, file/line/rule findings, zero-tolerance. — satisfies
  [STD-10] (1, 4), [STD-12], [STD-17]; spec §2.2.
- [x] **T-STD-6** Implement the annotated-exception mechanism (`#[allow]` /
  `// crucible-lint: allow` with mandatory rationale) and the rule that an
  un-annotated allow is itself a finding; treat the lint config as versioned spec
  surface that is never weakened to pass. — satisfies [STD-13], [STD-14],
  [STD-15]; spec §2.
- [x] **T-STD-7** Apply the `unsafe` fences: `#![forbid(unsafe_code)]` on every
  crate except the enumerated FFI/mmap/atomics crates (per the crate table),
  with the safe-wrapper requirement and `// SAFETY:` on every block. — satisfies
  [STD-16], [STD-17], [STD-18]; spec §3.
- [x] **T-STD-8** Establish the per-layer testing standards: each crate's tests
  own its layer gate ([HARN-3]); the twice-reduce/compare-by-hash shape;
  flaky-is-failing; the `SimDouble` carries the bulk of L1/L3/L4 determinism
  tests. — satisfies [STD-19], [STD-20], [STD-21]; spec §4.
- [x] **T-STD-9** Establish the concurrency-, ABI-, and oracle-test standards:
  an exhaustive ordering model and deterministic exhaustive trace corpus on the
  SPSC ring (before its `unsafe` is relied on), golden vectors + round-trip +
  fuzzing for the three ABIs, and the replay-oracle test run both fixed-corpus
  and in-search. — satisfies [STD-22], [STD-23], [STD-25]; spec §4, §8 of 24,
  §6 of 24.
- [x] **T-STD-10** Define and measure the determinism-core coverage floor (every
  ordering branch and error variant in the scheduler/RNG/digest/ring/codec/
  oracle/artifact paths exercised), measured deterministically in a separate
  instrumentation build. — satisfies [STD-26]; spec §4.
- [x] **T-STD-11** Establish file/module size limits, layer-boundary dependency
  rules, and commit hygiene (atomic commits; ABI + golden-vector + dependent
  logic land together; no determinism change buried in formatting churn). —
  satisfies [STD-27], [STD-28], [STD-29]; spec §5.
- [x] **T-STD-12** Enforce "documenting existing code is comments-only" and the
  doc-lint that keeps the gate catalog and per-file Implementation checklists in
  sync with the master plan. — satisfies [STD-30], [STD-31]; spec §5, §1 of 24.
- [x] **T-STD-13** Author the determinism review checklist as a PR template,
  require it on any engine/scheduler/transport PR, and codify the
  root-cause-not-workaround rule for surfaced leaks. — satisfies [STD-32],
  [STD-33]; spec §6.
- [x] **T-STD-14** Reconcile the concurrency-oracle standard with what the
  workspace can hermetically build: either vendor `loom` and `proptest` as AOS
  packages and use them on the SPSC ring, or narrow [STD-22]/[STD-23] to the
  bespoke exhaustive model checker actually in use — and make the emitted gate
  marker name the mechanism truthfully either way.
  — satisfies [STD-22], [STD-23]; spec §4.
  - Defect (audit 2026-07-28): [T-STD-9] requires "loom + proptest on the SPSC
    ring", but neither crate appears in any `Cargo.toml` in the workspace and
    `crucible-shmem` declares no `[dev-dependencies]` at all. The actual
    implementation, `assert_spsc_ring_loom_model` in
    `crucible-shmem/tests/gate_layer1_injection.rs`, is a hand-rolled exhaustive
    checker over the RFC 13.6 orderings with genuine negative controls proving
    that relaxed orderings admit torn frames — substantive work, but not loom and
    not property-based. `checks.crucible.phase1.concurrencyAbiOracleStandards`
    nonetheless emits `spsc=loom,proptest`.
  - Plan: prefer narrowing. The hermetic-build rule (no upstream nixpkgs, all
    dependencies built from source) makes vendoring two proc-macro-heavy crates a
    disproportionate cost against a checker that already enumerates the ordering
    space exhaustively. Restate [STD-22]/[STD-23] in terms of "an exhaustive
    ordering model with negative controls", rename the marker to
    `spsc=exhaustive-ordering-model`, and record the decision in
    [`31-decision-register.md`](31-decision-register.md). If vendoring is chosen
    instead, the marker and this task's text move with it.
  - Gate: `checks.crucible.phase1.concurrencyAbiOracleStandards` MUST assert the
    marker matches the mechanism actually linked into the test binary.
  Completed by `checks.crucible.phase1.concurrencyAbiOracleStandards`: the
  production gate and its Rust mirror require
  `assert_spsc_ring_exhaustive_ordering_model` plus
  `assert_spsc_ring_exhaustive_trace_properties`, preserve weakened-ordering
  negative controls, and emit `spsc=exhaustive-ordering-model`. D-37 records
  the hermetic mechanism choice.
