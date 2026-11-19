# Engineering standards

Crucible code is a determinism artifact. A bug in ordinary code produces a
wrong answer; a determinism bug produces a flaky answer, which is the exact
failure the system exists to remove. The standards on this page add
Crucible-specific rules on top of the repository-wide Rust and documentation
standard in the root `AGENTS.md` and [`docs/engineering/code-style.md`](../code-style.md).
Where they appear to differ, the root guidance wins.

The standards form layered defenses, each refusing a class of nondeterminism
the next would miss:

```text
compile time   gate:harness-lint             bans the constructs that leak order
run time       gate:layer0-determinism,      detect leaks the lint cannot see
               gate:adversarial-determinism
diagnosis      gate:divergence-bisect        localizes what slips through
review         determinism review checklist  catches design-level leaks
```

Almost every rule here is an integration test in
`crates/crucible/crucible-test-support/tests/` with a Nix mirror under
`checks.crucible.phase1`. Where existing code predates a rule, the debt is
recorded in a capped baseline file under `tests/crucible/`; baseline counts
may shrink but never grow, and a stale entry is itself a failure. The gate
catalog and test layering are in [testing-and-gates.md](testing-and-gates.md);
crate layering, the unsafe fence, and feature rules are in
[crate-structure.md](crate-structure.md).

| Standard | Rust test | Nix check | Baseline |
| --- | --- | --- | --- |
| Harness lint | `harness_lint.rs`, `harness_lint_annotations.rs` | `checks.crucible.phase1.gates.harnessLint` | `harness-lint-baseline.txt` |
| Rustdoc bar | `rustdoc_bar.rs` | `checks.crucible.phase1.rustdocBar` | `rustdoc-bar-baseline.txt` |
| Testing standards | `testing_standards.rs` | `checks.crucible.phase1.testingStandards` | `testing-standards-baseline.txt` |
| Concurrency, ABI, and oracle tests | `concurrency_abi_oracle_standards.rs` | `checks.crucible.phase1.concurrencyAbiOracleStandards` | |
| Determinism-core coverage | `determinism_core_coverage.rs` | `checks.crucible.phase1.determinismCoreCoverage` | |
| Engineering hygiene | `engineering_hygiene.rs` | `checks.crucible.phase1.engineeringHygiene` | `engineering-hygiene-baseline.txt` |
| Documentation hygiene | `documentation_hygiene.rs`, `gate_catalog.rs` | `checks.crucible.phase1.documentationHygiene`, `checks.crucible.phase1.gateCatalog` | |
| Determinism review | `determinism_review.rs` | `checks.crucible.phase1.determinismReview` | |
| License boundary | `gate_license_boundary.rs` | `checks.crucible.phase1.gates.licenseBoundary` | |

## Rustdoc bar

Every Crucible crate meets the docs.rs-quality bar of the root `AGENTS.md`.
Rustdoc's own lints cover missing public docs and broken intra-doc links: crate
roots set `#![deny(missing_docs)]` (all but `crucible-store-s3` today), and
`cargo doc` is part of the build. `tests/rustdoc_bar.rs` checks the source
shape that rustdoc does not model:

- Every `.rs` file starts with a `//!` module header, and every crate root has
  a `Module map:` paragraph naming its modules.
- A module that owns an on-disk or wire format shows it in a tagged format
  sketch. The checked format owners are the shared-memory ABI
  (`crucible-qemu-shmem/src/lib.rs`), the wire protocol
  (`crucible-qemu-protocol/src/lib.rs`), and the golden-vector records
  (`crucible-test-support/src/abi.rs`). Other format-owning modules, such as
  the reproduction-artifact format, follow the same convention.
- Every rustdoc fence is tagged `text`, `rust`, `toml`, `no_run`, or `ignore`.
  An untagged fence becomes a doctest in the hermetic build, so an untagged
  format example is a build failure. `crucible-cli` and `crucible-qemu-plugin`
  are not covered by `cargo test --doc`, so a `rust` or `no_run` fence there is
  a finding. Prefer `no_run` for examples, and add runnable examples only when
  they compile against public API alone.
- Public functions returning `Result` carry `# Errors`; items with a reachable
  panic carry `# Panics`. Because Crucible errors are usually
  determinism-relevant (a divergence, a hash mismatch, an ABI version
  mismatch), the `# Errors` text names the invariant or gate the error defends
  where one applies.
- `#[derive(Parser)]`, `#[derive(Subcommand)]`, and `#[derive(Args)]`
  containers carry no `///` docs, because clap turns them into `--help` text.
  Field docs are user-facing CLI text: short, imperative, accurate.
- Comments and docs use ASCII punctuation.

## Error handling and logging

The harness lint's error and logging pass (`error_logging.rs` under
`tests/support/harness_lint/`) applies to production sources of every Crucible
crate; `#[cfg(test)]` code and test-only sources are exempt.

- `.unwrap()` and `.expect()` are findings (`panic-shortcut`). A
  determinism-invariant violation that must fail loudly does so with an
  explicit `panic!` or `assert!` whose message names the invariant, never a
  bare unwrap.
- Library crates model errors with typed enums: the manifest declares
  `thiserror` or the crate defines its own typed error. Erased error crates
  (`anyhow`, `eyre`, `miette`) and `bail!` are findings (`erased-error`) in a
  library manifest or source, and `Result<_, String>` is a finding
  (`stringly-error`).
- Libraries never write to stdout or stderr: `println!`, `eprintln!`, and
  `print!` are findings (`direct-diagnostic`). Diagnostics go through
  `tracing`, which is observational: a `tracing` field never feeds back into
  run state.
- The binary boundary is exempt from the erased-error and direct-output
  rules: all of `crucible-cli/src`, the `src/main.rs` or `src/main/` entry of
  `crucible-qemu-debug-gateway` and `crucible-guest`, and any `src/bin/`
  target.

## Harness lint

`gate:harness-lint` is the cheapest, broadest determinism defense: a static
lint that bans constructs that introduce ordering nondeterminism before any
runtime test sees them. It is zero-tolerance; a single finding fails the gate.

### Banned patterns

| Rule | Banned construct | Use instead |
| --- | --- | --- |
| `host-wall-clock` | `SystemTime`, `UNIX_EPOCH` | Virtual time derived from icount |
| `host-monotonic-time` | `Instant` | Virtual time; wall clock only in observational logging |
| `thread-global-rng` | `thread_rng`, `rand::rng`, `StdRng::from_entropy`, `SmallRng::from_entropy` | The seeded decision RNG |
| `host-rng` | `OsRng`, `getrandom` | The seeded decision RNG |
| `unordered-map-set` | `HashMap`, `HashSet` types | `BTreeMap`, `BTreeSet`, or a sorted `Vec` |
| `default-random-hasher` | `DefaultHasher`, `RandomState` | A fixed-seed hasher with an annotated exception |
| `nondeterministic-select` | An unbiased `select!` | A biased, priority-ordered selection |
| `hash-iteration` | Iterating a hash container binding | Sort before iterating, or an ordered container |
| `unordered-select` | Unordered selection over simultaneous readiness | Explicit poll order |
| `distribution-metadata-flow` | Host, lease, claim, or fleet metadata flowing into identity paths | Keep coordination metadata out of `State`, `Decision`, `ContentHash`, and artifacts |
| `guidance-ordering-float` | `f32`/`f64` in guidance and adaptive-ordering sources | Integer or fixed-point scores |

Randomness comes only from the seeded decision RNG, whose per-entity streams
are forked by name hash so adding or renaming a node does not perturb other
streams. Decision-path quantities that look fractional (loss probability,
jitter weight, firing thresholds) are integer basis points or another
fixed-point scale, so comparisons are exact and independent of the host FPU.

The rules apply with different strength by crate, as described in
[crate-structure.md](crate-structure.md): reduction-path crates may not
contain the constructs at all, host-nondeterminism boundary crates may use
them only in supervision and diagnostics code that never reaches run state,
and other crates carry capped baseline debt.

### Enforcement tiers

The lint has two tiers, and both must pass.

1. **Clippy tier.** The workspace denies `all`, `disallowed_methods`,
   `disallowed_types`, `expect_used`, `float_arithmetic`, and `unwrap_used`
   (`[workspace.lints.clippy]` in `crates/Cargo.toml`), and every Crucible
   package inherits them with `[lints] workspace = true`. `crates/clippy.toml`
   disallows the methods `std::time::Instant::now`,
   `std::time::Instant::elapsed`, `std::time::SystemTime::now`,
   `rand::thread_rng`, `rand::rng`, `rand::random`, and
   `getrandom::getrandom`, and the types `std::collections::HashMap`,
   `std::collections::HashSet`, `std::collections::hash_map::DefaultHasher`,
   and `std::collections::hash_map::RandomState`. The package build in
   `pkgs/tools/crucible/crucible.nix` runs `cargo clippy --all-targets` with
   `-D warnings`. `clippy_tier_is_checked_in_and_wired` checks all of this.
2. **Custom static-analysis tier.** A comment- and string-aware token scanner
   over every Crucible crate's sources catches what clippy cannot express:
   hash-container iteration, default hashers, unordered selection, bare
   `unsafe` blocks, distribution-metadata flow, guidance floats, and malformed
   or missing lint annotations. Findings carry file, line, and rule.

The same gate also runs the check-reference integrity lint
(`gate_evidence_references_are_integral`): every source path a Nix check reads
with `failuresFor` must exist, and no check may prove itself by asserting
checklist state.

### Annotated exceptions

A construct that is provably safe (for example a hash map used as a pure
lookup cache whose order never escapes) needs an explicit annotation on the
line before it:

```rust
// crucible-lint: allow unordered-map-set -- lookup-only cache; iteration order never escapes
```

The marker is `crucible-lint: allow <rule> -- <rationale>`, and `<rule>` must
be one of `LINT_RULES`: `host-wall-clock`, `host-monotonic-time`,
`thread-global-rng`, `host-rng`, `unordered-map-set`, `default-random-hasher`,
`nondeterministic-select`, `hash-iteration`, `unordered-select`,
`clippy-disallowed-method`, `clippy-disallowed-type`, `rust-allow`,
`panic-shortcut`, `erased-error`, `direct-diagnostic`, `stringly-error`,
`host-nondeterminism-state`, and `distribution-metadata-flow`. A malformed
marker is a finding, and every `#[allow(...)]` attribute needs a marker for
its rule in the comment block above it; an unannotated allow is a finding. So
every use of a banned construct is either rejected or justified in place.

The banned list and rule set are versioned with the code. Changing them is a
reviewed change under the determinism review checklist, and the lint is never
weakened to make a change pass: a finding is fixed at its root.

## Unsafe discipline

`unsafe` appears only in the enumerated boundary crates, for shared-memory
mapping, the lock-free SPSC ring, the QEMU plugin C ABI, descriptor handover,
and the guest doorbell. Every other crate forbids it at the crate root. In a
boundary crate, every `unsafe` block or impl carries an adjacent
`// SAFETY:` comment stating the invariant it relies on, every unsafe callable
item carries a `# Safety` doc section, and the `unsafe` sits behind a safe
wrapper whose safe surface upholds the invariant. The SPSC ring's `unsafe` is
relied on only after the exhaustive ordering model passes. The fence lists and
the per-crate safe-wrapper contracts are in
[crate-structure.md](crate-structure.md).

## Testing standards

A layer's determinism property is owned by that layer's gate and is never
covered only from a higher layer. `tests/testing_standards.rs` encodes this as
a `GateTestingStandard` per gate (owner packages, layers, test shape, and
backend) and checks it against `GATE_TARGETS`:

- The set of packages with a target for a gate must equal the standard's owner
  set, and each crate must keep a target for each gate it owns.
- A real-QEMU-only gate must be owned by an L2 crate; a double-backed gate may
  not be owned by an L2 crate, and an engine double-backed target must require
  the `test-double` feature.
- `gate:replay-oracle` and `gate:content-address` targets use the
  twice-reduce, compare-by-hash shape: they call
  `assert_twice_reduce_canonical_digest(` to drive the unit twice through a
  fixed decision sequence and compare canonical digests. Comparing a
  human-formatted dump (`human_formatted_dump`, `formatted_dump`, `dump()`)
  is a finding. Canonical digests exclude observational entries.
- Flaky is failing. Gate test sources may not contain `flaky`, `retry`,
  `rerun`, `thread::sleep`, or `std::thread::sleep` as whole words; a flake is
  a residual nondeterminism to fix, never something to retry or `#[ignore]`.
  The few legitimate domain uses (for example a modeled retry inside a
  scenario) are capped per target in `tests/crucible/testing-standards-baseline.txt`.

The bulk of L1, L3, and L4 determinism tests run against the in-process double
so they finish in milliseconds; only per-VM instruction determinism, guest
non-mutation, and patch inertness need real QEMU (see
[testing-and-gates.md](testing-and-gates.md)).

### Concurrency, ABI, and oracle tests

`tests/concurrency_abi_oracle_standards.rs` requires:

- the SPSC ring tests to call `assert_spsc_ring_exhaustive_ordering_model(`
  and `assert_spsc_ring_exhaustive_trace_properties(`, covering every
  producer and consumer interleaving under the declared orderings and the
  no-loss, no-duplication, FIFO, full and empty, and wraparound properties,
  with weakened-ordering negative controls;
- golden-vector, version, and round-trip coverage for the shmem layout, the
  protocol framing, and the RPC schema, with fuzzing of the codec and the
  block and 9p wire handlers;
- the replay-oracle targets to materialize fat checkpoints and replay schedule
  deltas (`materialize_fat_checkpoint`, `schedule_delta`, `replay_schedule`).

The exhaustive model is used instead of an external model-checking crate
because it is built entirely from the workspace and covers the same bounded
state space; its gate marker is `spsc=exhaustive-ordering-model`.

### Determinism-core coverage floor

Coverage is a floor on the determinism core, not a workspace-wide percentage.
`tests/determinism_core_coverage.rs` lists the surfaces whose ordering
branches and error variants must each be exercised by a named test:

```text
scheduler-quantum-loop         scheduler-ordering-keys
error-variant-floor            instantiate-recursion
sim-backend-error-variants     content-addressed-digest
replay-oracle-path             decision-rng-and-forking
spsc-ring                      protocol-codec
reproduction-artifact-serializer
```

Coverage is measured in a separate deterministic instrumentation build
(profile `crucible-determinism-core-coverage`), so instrumentation never
perturbs the determinism tests themselves.

## File, module, and commit hygiene

`tests/engineering_hygiene.rs` (`checks.crucible.phase1.engineeringHygiene`)
owns the source-shape and review-policy rules.

**Size.** Authors reconsider a hand-written module's responsibilities when its
implementation or its test section grows beyond 1000 lines, and a section
beyond 1500 lines needs a cohesion argument. `#[cfg(test)]` modules count
separately from the implementation, and a test-only source counts wholly as
tests. Exactly 1000 or 1500 lines does not cross a boundary. Each section above
1000 lines is recorded in `tests/crucible/engineering-hygiene-baseline.txt`
as a content-bound review:

```text
shape-review|path|sha256:digest|implementation-or-tests|section-lines|responsibilities|cohesion
```

The SHA-256 digest is over the whole source file, so any later change to the
file invalidates the review. Sections of 1500 lines or fewer record
`threshold-not-reached` as their cohesion; a record is stale once its section
returns to 1000 lines or fewer. Older `shape-line|path|cap` rows are a frozen
inventory from an earlier, stricter limit: a file at or below its cap stays
grandfathered, growth above the cap needs a `shape-review`, and caps are never
raised.

**Modules.** Every `.rs` file is a module with a `//!` header and owns one
coherent concern: one ABI format, one scheduler concern, one fault family. A
function on a determinism-significant path (the quantum loop, an ordering
comparator, a codec) is small enough to review for nondeterminism in one
sitting, or is decomposed so each ordering decision is reviewable on its own.
Module boundaries follow the layer map; the dependency rules and the QEMU
token boundary are in [crate-structure.md](crate-structure.md).

**Commits.** Commits are focused and atomic: one logical change per commit,
with an imperative summary line and a body explaining why when it is not
obvious. A change to a versioned ABI, its golden-vector regeneration, and the
engine logic that depends on it land together, never split in a way that
leaves CI red or the ABI unversioned. A determinism-relevant change never
shares a commit with unrelated formatting churn, so a reviewer can see exactly
what changed on an ordering-significant path. The hygiene check publishes the
rules as `atomic-logical-change`, `imperative-summary`,
`abi-golden-engine-together`, and `no-determinism-format-churn`.

## Documentation hygiene

**Documenting existing code is comments-only.** A documentation pass does
NOT reorder, rename, or reformat code; it adds `//!`, `///`, and `// SAFETY:`
comments only. If a doc claim contradicts the code, the doc is fixed to match
the observed behavior and the discrepancy is flagged in the PR for separate
resolution. This keeps a determinism-relevant code change from hiding inside a
documentation diff. `tests/documentation_hygiene.rs` checks that the root
`AGENTS.md` carries the same rule.

**Doc-lint and the gate catalog.** Gate names are checked between the code and
the documentation. The gate catalog table in
[testing-and-gates.md](testing-and-gates.md) must list exactly the names in
`canonical_gates()`, and every `gate:` name used in the Crucible engineering
documentation must be a catalog name. A referenced-but-undefined gate, a
defined-but-unreferenced gate, or a drifted catalog table fails
`tests/gate_catalog.rs`. Every catalog gate must also have a CI target in
`tests/crucible/phase1-phase-gate-wiring.nix`.

## License-boundary review

Code and documentation that touch QEMU integration, `crucible-qemu-plugin`,
`crucible-qemu-protocol`, `crucible-qemu-shmem`, packaging, or guest doorbells
preserve the component, dependency, and public-protocol rules in
[../../legal/licensing.md](../../legal/licensing.md). The `Always` gate
`gate:license-boundary`, owned by `crucible-test-support`, fails closed on any
dependency, license-scope, protocol-shape, package-source, or
corresponding-source violation.

## Determinism review checklist

The lint catches mechanical cases and the runtime gates catch what runs; the
review checklist catches design-level leaks neither can see. It applies to
every change to an engine, scheduler, or transport crate
(`crucible-determinism`, `crucible-qemu-shmem`, `crucible-qemu-protocol`,
`crucible-device`, `crucible-engine`) and to host code on an
ordering-significant path. A green `gate:harness-lint` is not sufficient for
such a change.

A reviewer MUST apply the checklist below to any PR touching an engine/scheduler/transport crate,
and MUST block the PR on any unchecked item. The
completed checklist is recorded in the PR description or review.

```text
DETERMINISM REVIEW CHECKLIST (apply to any engine/scheduler/transport PR)

Ordering
[ ] Every collection on an ordering-significant path is ordered (BTree*,
    IndexMap with fixed order, sorted Vec) or carries an annotated
    crucible-lint allow. No HashMap/HashSet iteration leaks order into State,
    the Schedule, the canonical log, or a hash.
[ ] Any sort uses a total, stable key; the cross-node order key is
    (virtual_time, consumer node_id, producer node_id, sequence). Ties never
    resolve by address, pointer, allocation order, or hash order.
[ ] Any select/poll over simultaneous readiness is biased/priority-ordered;
    the branch taken on a tie is a pure function of declared priority.

Time, randomness, numerics
[ ] No host wall-clock (Instant::now, SystemTime::now, elapsed) feeds State;
    virtual time is icount-derived. Wall-clock appears only in observational
    tracing that never feeds back.
[ ] No thread_rng, getrandom, or host entropy; all randomness is the seeded
    decision RNG, forked per entity by name hash so adding or renaming a node
    does not perturb others.
[ ] No f32/f64 on a decision path; fractional decision quantities are integer
    basis points (or fixed-point) so comparisons are exact and FPU-independent.

State purity and content addressing
[ ] State is still a pure function of (ScenarioDef, Schedule); no new
    uncontrolled input (env var, file mtime, host core count, address)
    reaches it.
[ ] Anything newly added to the canonical log or hash is canonical, not
    observational; anything that may vary between equivalent runs is
    observational by schema, not by a side flag.
[ ] Content addressing holds: equal content gives an equal id; the
    (de)serializer is canonical (stable field order, no map-order dependence).

ABI, unsafe, errors
[ ] If a boundary ABI changed: version bumped AND golden vectors regenerated
    in THIS change; the round-trip property still holds; gate:abi-conformance
    passes.
[ ] If unsafe was added or touched: the crate is an enumerated unsafe-boundary
    crate; every block has a // SAFETY: comment; the safe wrapper upholds the
    invariant; SPSC changes are covered by the exhaustive ordering model and
    its negative controls.
[ ] No .unwrap()/.expect() in production; library errors are typed
    (thiserror); erased errors only at the binary boundary; a loud-failure
    panic names the invariant it defends.

Tests and gates
[ ] The relevant layer gate covers the change (not a higher layer); a new
    determinism property has a test that FAILS when it is violated.
[ ] If the change could introduce nondeterminism the lint cannot express, it
    is exercised under gate:adversarial-determinism and localizable by
    bisection.
[ ] The gate:harness-lint configuration was not weakened to make this change
    green; any new crucible-lint allow has a written rationale.
```

When the checklist surfaces a leak, the fix MUST be at the
source of the nondeterminism, never a workaround that smooths it over: no retry, no
jitter tolerance, no comparison with a fudge factor. A change that papers over a determinism leak
rather than eliminating it is blocked even if CI is green, because the gates
prove only the interleavings they test and the leak will resurface. This is
the same localize-never-smooth-over rule that divergence bisection serves.
