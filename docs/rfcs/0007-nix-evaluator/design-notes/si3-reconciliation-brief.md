# RFC-0007 SI-3 — Candidate-C carrier flip: reconciliation brief

> Handoff for a fresh-context agent completing the SI-3 8-byte `Value` carrier
> flip. The flip is built and **byte-parity-correct on both carriers** (20/20
> legs); what remains is reconciling the crate **test suite** under the variant
> and the deref-cost / RSS rider, then merging to the shared branch. This brief
> gives the failure taxonomy, the per-class disposition rule, the soundness razor
> for triage, and the completion checklist. It lives with the WIP on branch
> `si3-carrier-flip-wip` (base commit `761e81fc5`).

## 0. State at handoff

- **Landed on `worktree-rfc-0007-nix-evaluator`** (shared branch, pushed, both
  carriers green): the full registry substrate — SI-1-completion `135a9d165`,
  SI-2 forward registry `2f73234aa`, reverse lookup `b98c25677`.
- **On `si3-carrier-flip-wip` (`761e81fc5`)**: the carrier flip. `Value` is the
  8-byte `CompressedValueWord` under the `candidate_c_value` cargo feature
  (`ratchet-value/src/value/candidate_c_carrier.rs`); the baseline 16-byte
  carrier is `cfg(not(feature = "candidate_c_value"))`. Both carriers compile the
  whole `aos` binary.
- **Proven correct.** Byte-parity is green on **20/20** legs:
  - variant 12/12 — `pkgs.zlib` / `pkgs.openssl` / `stdenv.bash` /
    `stdenv.coreutils` × {serial, `AOS_NIX_PARALLEL=4`, `AOS_NIX_GC=sweep`};
  - default 8/8 — same four attrs × {serial, `AOS_NIX_JIT=1`}.
  The 8-byte carrier emits byte-identical `.drv` to C++ Nix across serial,
  parallel, and threshold-0 moving-GC modes.
- **What blocks landing:** the variant crate-test suite has **491 failures**
  (`cargo test -p ratchet-value -p ratchet-core -p ratchet-oracle --features
  candidate_c_value`, run against `761e81fc5`). None are core bugs (the parity
  battery exercises the real eval + parallel + moving-GC paths and is green);
  they are baseline-ABI-assumption tests that legitimately differ under an 8-byte
  word. This brief classifies them and gives the disposition rule per class.

## 1. Why the failures are reconciliation, not bugs

The battery is the correctness oracle: it drives complete real-package
evaluations through the exact production code path (reservation-backed heap,
K=4 workers, sweep GC) and compares `.drv` bytes to C++ Nix. It is green. The
491 failures are **unit tests** that reach into representation internals the
8-byte carrier changes: they construct `Value`s from fake pointers, force heap
geometries production never uses, or assert baseline byte counts / layouts /
error kinds. The task is to re-express each test's intent under the new carrier
(or gate it), **without** silencing a test that is actually catching a defect.

## 2. Failure classes and disposition rules

### Class A — fake-pointer `Value` constructions

**Symptom.** `ValueError::UnregisteredReservation { address: 8 }` (or another
tiny/synthetic address). `8` is `NonNull::<HeapObject>::dangling()` — the type
alignment.

**Root cause (by design).** A Candidate-C heap `Value` is a `(domain, index)`
into a live reservation; `Value::string(ptr)` / `Value::heap(tag, ptr)` resolve
`ptr` through the registry's reverse lookup. A dangling or hand-built pointer is
not inside any registered reservation, so construction fails. On the baseline
16-byte carrier the same call just stored the raw pointer, so these tests passed.

**Example.** `ratchet-oracle/src/eval/whnf_tag.rs`
`whnf_tags_return_by_inspection_without_heap_lookup` builds `Value::string(ptr)`
etc. from `NonNull::dangling()`; `ratchet-value/src/value.rs`'s ABI tests do the
same (already `cfg(not(...))`-gated at the flip).

**Disposition.** `#[cfg(not(feature = "candidate_c_value"))]` the test (or the
specific fake-pointer assertions) with a one-line rationale comment. The
behavior these tests pin (WHNF classification, tag predicates) is exercised on
the variant by the parity battery, which builds real heap values.

### Class B — chunked-geometry / GC-stress heap configs

**Symptom.** `ValueError::UnregisteredReservation { address: <real high
address> }` from an actual evaluation (e.g. `builtins.map f [ 1 2 3 ]`,
`{ b = 2; a = [ 1 true null ]; }`) inside a `gc_audit` / `gc_conformance` /
`gc_measurement` / `shared_arena` test.

**Root cause (design constraint).** Candidate-C requires **every heap object to
live in the single 4 GiB reservation** (doc 30 §3.6: Candidate-C is
"conditional on the single-reservation arena landing cleanly"). Tests that force
the **chunked fallback** geometry (`EvalHeap::with_initial_chunk_bytes`, or a
GC-stress option that selects chunked allocation) place objects outside the
reservation, so their addresses cannot be encoded as `(domain, index)`.
Production never falls back — the reservation maps successfully on every
supported target (Linux/macOS x86_64/aarch64) — which is why the battery is
green.

**Disposition.** `#[cfg(not(feature = "candidate_c_value"))]` the chunked-config
test with a comment citing the single-reservation constraint. Where a test's
*intent* is GC correctness (not the chunked geometry per se), prefer converting
it to the reservation-backed heap (`EvalHeap::new()`) so it keeps running on the
variant; gate only if the test is specifically about the chunked path. Do **not**
"fix" this by silently making Candidate-C tolerate chunked objects — that would
reintroduce a non-encodable pointer and is a design regression.

### Class C — baseline byte-count / layout / error-kind assertions

**Symptom.** `assertion left == right failed  left: 8  right: 16` (or a scalar
error variant mismatch), from a test asserting a representation-specific fact.

**Root cause (expected).** The 8-byte word changes value mass, the ABI layout
descriptor, and the scalar decode error type. Examples:
- `ratchet-core/src/runtime_abi/value_layout.rs`
  `active_and_candidate_layouts_are_distinct_and_self_consistent` and
  `runtime_abi::tests::runtime_call_metadata_pins_value_layout_and_convention` —
  assert the active layout is 16/2/8 and *distinct* from Candidate-C's 8/1/8. On
  the variant the active layout *is* 8/1/8, so "distinct" inverts.
- `active_values` scalar-boundary tests assert `decode_int_value(Value::bool)`
  yields `ValueError::Type`; on the variant it routes through the scalar store
  and yields `EvalHeapError::CandidateCScalar`.
- GC / heap tests asserting exact resident-byte or published-payload-byte counts
  (e.g. `published_payload_bytes() == 16` for two 8-byte cells).

**Disposition — prefer a *dual-carrier assertion*, not a gate, when the test's
intent survives the flip.** Pattern:

```rust
#[cfg(not(feature = "candidate_c_value"))]
assert_eq!(mem::size_of::<Value>(), 16);
#[cfg(feature = "candidate_c_value")]
assert_eq!(mem::size_of::<Value>(), 8);
```

For layout distinctness, invert the expectation under the variant (active ==
Candidate-C) rather than deleting coverage. For the scalar-boundary error kind,
assert the variant's `CandidateCScalar`/`BoxedScalarRequiresHeap` path. Gate the
whole test only when the assertion has no meaningful variant analogue.

## 3. The triage soundness razor (what DISQUALIFIES a failure from its class)

Before dispositioning a failure into a class, apply this razor. If any check
trips, **stop — it may be a real bug**, not a baseline-assertion:

1. **The failing input is a real evaluation and the heap is the default
   reservation-backed `EvalHeap::new()` (no chunked/`with_initial_chunk_bytes`
   config).** Class B only covers *forced* non-reservation geometries. A real
   eval on a default heap failing with `UnregisteredReservation` is a **bug**
   (an allocation escaped the reservation, or registration/reverse-lookup is
   wrong) — investigate, do not gate. Cross-check: does the same expression
   evaluate correctly through `crates/target/release/aos ... nix-diff`? If the
   release binary is byte-correct on it, it is config; if it also fails, it is a
   bug.
2. **A byte-count/layout assertion is off by something *other than the expected
   16→8 (or 2→1 word, or a clean halving of value mass)*.** Class C expects
   changes that track the word shrink. An unexpected magnitude (e.g. a count that
   should be carrier-independent, like element *count* rather than *bytes*, or a
   hash that should be canonical) means the flip perturbed something it
   shouldn't — investigate.
3. **The test is about laziness / observability / thunk forcing / string
   context, and it now returns a *different value* (not a different
   representation).** The carrier must not change *which* values are produced or
   *when* thunks force. A semantic-value divergence here is a bug (suspect the
   forced-bit path or `AtomicValueCell` collapse).
4. **A parallel (K=4) or GC-stress test fails with a data race, torn value, or
   use-after-free (not a byte-count assertion).** The registry drop-ordering
   (unregister-before-unmap) and the one-word `AtomicValueCell` are the load-
   bearing concurrency changes; a real tear here is a bug, not an assertion.

Everything that passes the razor is safe to disposition per §2. When in doubt on
a specific test, reproduce the expression through the release binary's
`nix-diff` (byte mode) — agreement there is decisive evidence of "config, not
bug."

## 4. Remaining tail checklist

1. **491 variant test failures** — reconcile per §2/§3. Re-run to zero (minus the
   pre-existing `no_source_file_exceeds_line_cap` gate and the
   `heap_cheap_memory_advice` concurrency flake, which are ignored on both
   carriers per the task frontier).
2. **26 dead-code warnings** — helpers used only by gated tests
   (`inline_hash`, the `eval` test helpers, etc.). Gate the helper with the same
   `cfg` as its callers, or `#[cfg_attr(feature = "candidate_c_value",
   allow(dead_code))]`. Also sweep the inert baseline-only imports under the
   variant (`TaggedValueWord`/`CandidateBValueError` in `runtime_values.rs`,
   `ACTIVE_VALUE_LAYOUT`, `mem`/`NonNull` in `value.rs`).
3. **Deref-cost gate (rider).** Measure `native_mean` on the 4-attr suite:
   variant must **not** regress the default carrier — the 8-byte carrier should
   *win* via cache density. If it loses, the hot heap-access/construct path is
   still routing through the registry instead of the arena's cached base — add
   the arena fast-path at the hot sites (the accessor already resolves via the
   registry for the cold/context-free path; hot arena-internal code should use
   `pointer_for_index` / `index_for_pointer` on the heap's own base). Harness:
   `nix-bench native_mean`, both release binaries.
4. **RSS scoreboard (the memory-prize number).** Measure `bench.wide` (and
   `bench.wide-eval` if runnable) resident-set cold + warm on the variant vs the
   default carrier, and write the doc-30 §5.4 scoreboard line. The 16→8B flip is
   the single biggest expected step toward the user target (wide-eval RSS ≤ half
   of C++). Report the delta.
5. **Merge-to-shared-branch criteria** (all at the merge commit):
   - variant crate suites green (`ratchet-value`/`-core`/`-oracle`/`-jit`/
     `-runtime-ffi`/`aos-nix`, minus the two pre-existing ignored failures);
   - default crate suites green;
   - both byte-parity batteries re-green (variant 12/12 serial+K4+sweep, default
     8/8 serial+JIT) at the merge commit;
   - deref-cost non-regression + the RSS scoreboard line recorded;
   - `pull --rebase` the shared branch first (other agents push to it), then
     merge/rebase `si3-carrier-flip-wip` onto it and land. Land the JIT re-enable
     (S4b) separately after S3's one-word stack-map geometry (§6.1 condition 2);
     under this variant the JIT stays off by construction.

## 5. How to run the gates (copy-paste)

Build (variant adds the feature):

```text
OPENSSL_DIR=/opt/homebrew/opt/openssl@3 cargo build --release \
  --manifest-path crates/Cargo.toml --bin aos \
  --features native-eval[,candidate_c_value]
```

Byte-parity leg (per attr/mode). Env short-circuits to the warm system store
(the clone-local store hits the task-#19 fetchTarball drift):

```text
AOS_NIX_STORE_DIR=/nix/store AOS_NIX_STATE_DIR=/nix/var/nix NIX_REMOTE=daemon \
AOS_NIX_ORACLE=/nix/var/nix/profiles/default/bin/nix-instantiate AOS_NIX_NATIVE=1 \
[AOS_NIX_PARALLEL=4 | AOS_NIX_GC=sweep | AOS_NIX_JIT=1] \
  crates/target/release/aos --eval-system x86_64-linux \
  nix-diff --attr=<pkgs.zlib|pkgs.openssl|stdenv.bash|stdenv.coreutils> --mode byte
```

Expect `drv diff matched`. Attrs are `pkgs.`-prefixed for packages,
`stdenv.`-prefixed for stdenv tools (bare `zlib` 404s against repo `default.nix`).

Variant crate tests:

```text
OPENSSL_DIR=/opt/homebrew/opt/openssl@3 cargo test --no-fail-fast \
  --manifest-path crates/Cargo.toml \
  -p ratchet-value -p ratchet-core -p ratchet-oracle \
  -p ratchet-jit -p ratchet-runtime-ffi -p aos-nix \
  --features candidate_c_value
```
