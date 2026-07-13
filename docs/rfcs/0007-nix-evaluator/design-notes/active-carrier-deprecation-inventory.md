# Active (two-word) carrier deprecation — inventory & decision packet

Status: REPORT-ONLY (zero code changes). Prep for the user-surfaced question
*"should we delete the two-word Active value carrier now that Candidate-C is the
shipped carrier?"* — NOT the deletion itself. Measurements taken at HEAD after the
S5 promotion flip (5c22a8bab), which builds hermetic `pkgs.aos` with
`native-eval,candidate_c_value`. The `candidate_c_value` cargo feature stays
opt-in, so the two-word carrier remains the **cargo default** (dev/test builds
without the feature) through the deprecation window even though Candidate-C is
what ships.

## 0. TL;DR

- The two-word carrier's footprint is **638 `#[cfg(not(feature =
  "candidate_c_value"))]` blocks** plus ~1,200–1,500 LOC of carrier-core (the
  two-word regions of `ratchet-value/src/value.rs` — a mixed facade — plus
  `value/tag.rs`). **76% of the cfg footprint (485 of 638 blocks) is in test
  files**, not production.
- Deleting it is large but mostly mechanical: rough **~12k–20k LOC, dominated by
  tests**. The safety allowlists barely move (the reviewed FFI/JIT boundaries are
  carrier-neutral); only the separate **candidate-B** bridge, if bundled, shrinks
  them by ~16 pinned entries.
- The real cross-check is the **byte-identical `.drv` parity gate against C++
  Nix**, which runs on the shipped carrier. The two-word carrier's value as an
  independent second implementation was highest *during* the cutover (done); it
  is now a frozen parallel codepath that itself costs maintenance.
- **Recommendation:** keep the two-word carrier through a bounded deprecation
  window (opt-in buildable for rollback), and during that window **port the
  "gated-for-readiness" baseline-only tests onto Candidate-C** so coverage does
  not regress on deletion. Delete only the two-word-*inherent* tests. Gate the
  deletion on a full-corpus parity green + user approval.

## 1. cfg surface (measured at HEAD)

`#[cfg(feature = "candidate_c_value")]` = variant-only code that becomes
**unconditional** on deletion. `#[cfg(not(feature = "candidate_c_value"))]` =
two-word-only code that **dies**.

| crate | variant-only (unconditional) | baseline-only (dies) |
|---|---|---|
| ratchet-oracle | 12 | **513** |
| ratchet-jit | 19 | 75 |
| ratchet-runtime-ffi | 3 | 30 |
| aos-nix | 7 | 11 |
| ratchet-value | 13 | 6 |
| ratchet-core | 3 | 3 |
| aos-core / aos | 0 | 0 |
| **total** | **57** | **638** |

Of the 638 baseline-only blocks: **485 in test files, 153 in production.**

## 2. What dies

### 2.1 Carrier core (the two-word representation)
- `ratchet-value/src/value.rs` (955) is the value-module **facade**, not a
  wholly-two-word file: its `#[cfg(not(feature = "candidate_c_value"))]` regions
  hold the two-word `struct Value { tag, payload }` + its constructors/accessors
  (the bulk of the file, under a handful of large cfg blocks — 6 cfg sites) and
  **die**; the facade, `pub mod compressed`, and the
  `#[cfg(candidate_c_value)] pub use candidate_c_carrier::Value` re-export **stay**
  (and the re-export becomes unconditional). So a large chunk of value.rs
  deletes, not the whole file.
- `ratchet-value/src/value/tag.rs` (653) — `TaggedValueWord` / `TaggedHeapAddress`
  two-word encoding; audit for symbols shared with the Candidate-C path, but
  largely dies.
- Candidate-C's `value/candidate_c_carrier.rs` (513) + `value/compressed.rs`
  (1000) **stay** and lose their `#[cfg]` gating.
- Exact carrier-core LOC needs a precise per-block audit (value.rs is mixed);
  estimate ~1,200–1,500 LOC across value.rs (two-word regions) + tag.rs.

### 2.2 Production two-word codepaths (153 baseline-only blocks), concentrated in:
- ratchet-jit `lower/`: `lambda_rec.rs` (23), `lambda_chain.rs` (16),
  `arith_tree.rs` (16), `lambda_chain/fold_gen.rs` (8), `value_words.rs` (6),
  `extract.rs` (4) — the two-word tier-2 emitters (each already has a one-word
  `compressed/` sibling that stays).
- ratchet-oracle: `tree_walk/outcome.rs` (15), `eval/heap/flat_values/active_values.rs`
  (6), `cache/cutoff.rs` (4), `eval/whnf_tag.rs` (3) — two-word evaluator paths
  (the `active_values.rs` boxing seam collapses to the Candidate-C funnel).
- ratchet-runtime-ffi: `apply.rs` (8), `native_call/value_abi.rs` (4),
  `env.rs` (3) — two-word by-value FFI ABI (the tri-width return path collapses
  to one width).

### 2.3 Test population (485 blocks) — DIES vs PORT
Two distinct classes, and telling them apart is the load-bearing pre-deletion work:

- **Two-word-INHERENT → delete.** Assert the two-word shape itself and are
  meaningless under one word: 16-byte layout / `[Value; 2]` stack-map geometry,
  `TaggedValueWord` encode/decode round-trips, two-word `AtomicValueCell`
  store/load, the "frozen two-word `Value` return / two CLIF results" `aos_deopt`
  ABI asserts (ratchet-jit `arith_tree.rs`, `cranelift/tier2.rs`), and the
  candidate-B bridge tests. Concentrated in the big `heap/tests/part_*` and
  `tree_walk/tests/{options,safepoint_roots}/part_*` files.
- **Gated-for-READINESS → port, don't delete.** Baseline-only *only* because the
  one-word emitter/carrier wasn't ready or boxed wide/float at the time — the
  computation is carrier-agnostic. Precedent: `nested_dependent_lets_fold_natively`
  (tier2_fold) was `cfg(not(candidate_c_value))` until #32's decoded-i64 loop, then
  un-gated to run on both. Every such test should be re-examined: un-gate onto
  Candidate-C (often needs a decode-and-compare instead of `raw_eq`, because
  boxed wide/float words carry an evaluator-specific arena domain), or delete if
  two-word-inherent. **Deleting these without porting would silently drop
  coverage** — this is the main correctness risk of a naive deletion.

### 2.4 candidate-B (related but a SEPARATE decision)
The tagged-word Candidate-B bridge is **654 LOC** across 5 files
(`ratchet-jit/src/cranelift/candidate_b.rs`, `lower/candidate_b.rs` +
3 test files) and **16 pinned safety-allowlist entries** (10 in
ratchet-jit/safety.rs, 6 in ratchet-runtime-ffi/safety.rs). It is **not**
feature-gated (always compiled; exercised only in tests) — an inactive
alternative experiment. Once Candidate-C is the sole carrier it is dead weight,
but its removal is a distinct ruling from the two-word Active-carrier deletion and
is the only part of this cleanup that meaningfully shrinks the safety allowlists.

## 3. Deletion diff scale (rough)

| component | ~LOC | notes |
|---|---|---|
| two-word carrier core (value.rs two-word regions + tag.rs) | ~1,200–1,500 | value.rs is a mixed facade — per-block audit needed |
| production baseline-only blocks (153) | ~2k–4k | emitters/eval/FFI two-word paths |
| test baseline-only blocks (485) | ~8k–15k | the bulk; port-vs-delete triage first |
| candidate-B (if bundled) | +654 + 16 safety pins | separate decision |
| **total** | **~12k–20k, mostly tests** | large but mechanical |

Also: 57 `#[cfg(feature = "candidate_c_value")]` blocks lose their gate (code
stays, becomes unconditional). Safety allowlists: **~0 change** from the two-word
deletion (reviewed boundaries are carrier-neutral); ~16-entry shrink only if
candidate-B goes too. The file-size gate (#9) benefits: several
`heap/tests/part_*` / `tree_walk/tests/*/part_*` offenders shrink as their
baseline-only halves delete.

## 4. Keep the two-word carrier alive? (both sides)

**Arguments to KEEP (for a window, or longer):**
- *Differential testing.* Two-word is an independent second implementation of the
  value ABI; disagreement between carriers on the same program is a strong
  carrier-bug signal that a single carrier + the C++ gate can miss for
  Nix-valid-but-C++-untested expressions.
- *Debuggability.* A two-word `(tag, payload)` value is trivially inspectable; the
  one-word compressed word is bit-packed (kind/domain/forced/index) and needs a
  decoder to read in a debugger.
- *Rollback.* If a one-word-only bug surfaces post-deletion there is no in-tree
  fallback carrier.

**Arguments to DELETE:**
- *Maintenance tax.* 638 cfg blocks + ~1,600 core LOC means every value-touching
  change must reason about (and test) both carriers — a permanent drag on an
  actively evolving evaluator.
- *The differential value has mostly been realized.* Its peak utility was
  *during* the cutover (complete). The durable cross-check is the byte-identical
  `.drv` parity gate vs C++ Nix, which runs on the shipped carrier and does not
  need a second in-tree carrier.
- *Test/CI drag.* 485 baseline-only test blocks inflate CI time and the file-size
  gate; a frozen second carrier still needs its tests maintained.
- *candidate-B* is pure dead weight regardless.

## 5. Recommended deprecation-window exit criteria

1. **Shipped + validated:** Candidate-C is the default hermetic `pkgs.aos` build
   (done, 5c22a8bab) AND a full-corpus byte-parity run is green on the builder.
2. **Bounded opt-in window:** keep `--features candidate_c_value` opt-out
   (two-word buildable) for a fixed window (proposal: through the next release
   train) as a rollback path; no new two-word-only code lands during it.
3. **Coverage-preserving triage (the gating work):** before deletion, port every
   "gated-for-readiness" baseline-only test (§2.3) onto Candidate-C; delete only
   two-word-inherent tests. Land this as its own reviewed pass so the deletion PR
   is a pure mechanical `#[cfg]` sweep.
4. **Deletion is user-approved and staged:** (a) delete two-word production +
   inherent tests and un-gate the 57 variant blocks; (b) optionally, a separate PR
   removes candidate-B (with its 16 safety-allowlist entries). Both are
   user-surfaced rulings, not scheduled here.
5. **Optional residue:** decide whether to retain a *minimal* always-compiled
   differential harness (a handful of exprs evaluated on both a reference decoder
   and the compressed carrier) to keep some second-implementation cross-check, or
   to rely solely on the C++ parity gate. Recommend the latter unless a concrete
   carrier-bug class is identified that the C++ gate cannot catch.
