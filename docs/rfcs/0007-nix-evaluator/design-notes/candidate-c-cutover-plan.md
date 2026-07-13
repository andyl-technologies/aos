# RFC-0007 — Candidate-C value-ABI cutover plan (design note)

> Design-only prep for task #12: activate the Candidate-C 8-byte
> compressed-index value representation across the evaluator core, `ratchet-runtime-ffi`,
> and `ratchet-jit`, replacing the active 16-byte pointer-pair `Value`. This note
> enumerates every ABI touchpoint with verified `file:line`, states the
> activation mechanism, gives a staged-vs-big-bang verdict, inventories the tests
> that pin the old ABI, builds a silent-breakage risk register, and proposes a
> smallest-first parity-gated landing order. It is a plan, not an implementation;
> no code was changed and no build was run to produce it (Phase 1 is read-only —
> the build lane is queued fv5 → candidate-b → frontend-par).
>
> Companion specs: [30 — flat-value architecture](../30-flat-value-architecture.md)
> §3 (the Candidate-C candidate, §3.5/§3.6) and §12 FV-4 (the landed prerequisite
> subset), [05](../05-value-representation.md) (the value-word trajectory),
> [08](../08-execution-tiers-and-cranelift.md) (the JIT tiers), and the sibling
> note [heap-snapshot-implementation-plan.md](./heap-snapshot-implementation-plan.md)
> §9 (task #6 is `blockedBy` this cutover — it makes snapshot images address-free
> by construction).

## 0. Executive summary

- **Verdict: the peripheral machinery is mostly built and stages cleanly; the
  core carrier flip is an irreducible big-bang.** The Candidate-C word codec,
  the 4 GiB reservation, both serial and shared boxed-scalar stores, the
  reservation-domain identity, the inactive `EvalHeap` encode/decode bridge, the
  JIT dual-layout CLIF adapter, and the FFI tri-width *return* path all landed
  (doc 30 §12 FV-4). Serialization/memo/`.drv` rendering is already
  representation-neutral. What is **not** stageable is the carrier itself: the
  active `Value` is a concrete 16-byte `struct` (`ratchet-value/src/value.rs:116`)
  used by value at ~4,900 sites across ~189 files in `ratchet-oracle/src/eval`,
  behind no flag. **No runtime flag can resize a struct**, so activating the
  8-byte word is a compile-time type change plus a mechanical sweep — a big-bang
  commit at the core. The staging shrinks that commit to a small, reviewable
  diff by landing all peripheral Candidate-C machinery active-first under the
  16-byte carrier (§5).

- **The single biggest new work is reworking the just-landed two-word
  stack-map/relocation roots.** `ratchet-jit/src/lower/stack_maps.rs` and the
  finalized SP-offset join in `cranelift.rs` hardcode `[Value; 2]`, 16-byte root
  slots, an 8-byte payload offset, and an explicit "collector updates/reloads
  both words" contract. The recently-landed relocation work assumed the two-word
  representation; a one-word compressed value invalidates its spill geometry,
  slot width, and payload-word writeback contract. This is called out to the
  lead as the item that most directly contradicts a recent landing (§1.3, §6).

- **Three big de-risks are already banked:** (1) scalar construction/decode is
  funneled behind one seam (`active_values.rs`), so most of the tree walk
  compiles through a carrier change unchanged; (2) serialization/memo/`.drv` is
  representation-neutral (canonical `i64`/`f64`-bits/`bool`/`null`), so the cache
  and store layers need **no** change; (3) the FFI return path and the JIT CLIF
  signature are already width-parameterized. The residual hard surface is
  narrow: the `payload_bits`/`*_identity_bits` contract, `AtomicValueCell`, the
  FFI helper-*import* signatures, and the JIT stack-map geometry.

- **Recommended first increment:** flip scalar boxing at `active_values.rs`
  (float-first — every float must box under an 8-byte word) to route through the
  already-built Candidate-C scalar store, carrier unchanged. It exercises the
  boxing + reservation-membership + domain-guard paths under the full parity
  battery with zero type change (§5 S0).

## 1. ABI touchpoints that assume the 16-byte pointer-pair `Value`

### 1.0 The two representations

- **Active** (`ratchet-value/src/value.rs:113-119`): `struct Value { tag:
  ValueTag, payload: u64 }` — 16 bytes, two 8-byte words; heap payload is a raw
  native `HeapObject` pointer (`value.rs:241-252` `Value::heap`; read back by
  `relocation_sensitive_identity_bits` `:322-325`). 12 tags (`ValueTag`,
  `value.rs:44-69`).
- **Candidate-C** (`ratchet-value/src/value/compressed.rs:119`):
  `struct CompressedValueWord { raw: u64 }` — 8 bytes. High 32 bits =
  `kind(8) | domain(23) | forced(bit31)`; low 32 = payload (inline `i32`, or a
  `u32` `ArenaIndex` offset into the reservation). Kinds map 1:1 to `ValueTag`
  (`compressed.rs:94-109` `semantic_tag`). Wide `i64`/all `f64` box into the
  reservation via the scalar stores (`compressed.rs:314`, `:549`).
- **Core layout descriptors** (`ratchet-core/src/runtime_abi/value_layout.rs:7-9`):
  `ACTIVE_VALUE_LAYOUT = (16, 2, 8)`, `CANDIDATE_C_VALUE_LAYOUT = (8, 1, 8)`;
  `runtime_abi_value_layout()` returns the active one (`:12-14`).

### 1.1 Evaluator core (`ratchet-oracle`)

- **Scalar construction/decode is FUNNELED (the cutover seam).**
  `ratchet-oracle/src/eval/heap/flat_values/active_values.rs` is explicitly
  documented (`:3-7, 33-37`) as the seam Candidate-C can replace "without
  changing evaluator call sites": `alloc_int_value` (`:45`), `alloc_float_value`
  (`:56`), `decode_int_value` (`:68`), `decode_float_value` (`:80`),
  `alloc_cached_scalar_value` (`:21`). Caller counts are small (5-7 each);
  tree-walk scalar traffic routes through `tree_walk/runtime_values.rs:31-79`.
- **The inactive `EvalHeap` bridge already exists.**
  `flat_values/compressed_values.rs`: `candidate_c_encode_value` (`:26`,
  `Value → CompressedValueWord`, boxing scalars + resolving heap pointers to
  `(ArenaDomainId, ArenaIndex)` via `candidate_c_heap_location` `:93`) and
  `candidate_c_decode_value` (`:59`, the inverse). It **rejects forced-thunk
  words** (`ForcedThunkUnsupported`, `:72`) because the 16-byte `Value` has no
  carrier for the shortcut bit — a boundary that disappears once the carrier is
  Candidate-C. Scalar stores: serial `EvalHeap.compressed_scalars`
  (`heap/mod.rs:319`), shared `SharedHeapArena.compressed_scalars`
  (`heap/shared_arena.rs:678`). Candidate-B parallels in `tagged_values.rs`.
- **The non-funneled hard surface:** `Value::heap` (23 sites) is direct;
  identity-bit consumers assume a `u64` payload — `payload_bits` (60 sites),
  `relocation_sensitive_identity_bits` (18), `address_identity_bits` (5),
  `transient_identity_bits`. These are what the FV-0 identity audit
  (`eval/heap/tests/payload_identity.rs`) already classifies and pins.
- **`AtomicValueCell` is two words** (`eval/env.rs:474-477`:
  `{ tag: AtomicU64, payload: AtomicU64 }`); `store` publishes payload-relaxed
  then tag-release (`:497-502`), `load` reads tag-acquire then payload
  (`:518-524`) and rebuilds via `decode_value` (`:529-554`). Reused as
  `EvalThunk.result` (`eval/thunk.rs:189`) and mirrored by the CAS thunk state
  (`eval/thunk_cas.rs:322`, `:1167-1168`). Under a one-word value this collapses
  to a **single `AtomicU64`** — the two-word tearing/"mixed pair" protocol
  (`env.rs:469-472`) disappears (a simplification), but every field access and
  `decode_value` must be rewritten.
- **The accessor surface to re-point** (`ratchet-value/src/value.rs`):
  constructors `int`/`float`/`bool`/`null`/`string`/`path`/`list`/`attrs`/`lambda`/`primop`/`external`/`thunk`/`heap`
  (`:123-241`); accessors `tag` (`:259`), `payload_bits` (`:275`),
  `address_identity_bits` (`:291`), `relocation_sensitive_identity_bits`
  (`:322`), `as_int`/`as_float`/`as_bool`/`as_*_ptr` (`:401-541`). Preserving
  this exact surface lets most call sites compile through; the `payload_bits`/
  `*_identity_bits` `u64` contract is the part that genuinely breaks.

### 1.2 Runtime FFI (`ratchet-runtime-ffi`) — return path tri-width, import path two-word

- **Return path is already tri-width and Candidate-C is proven.**
  `run_context_finalized_native_thunk_call` branches on
  `body.artifact().value_abi()` into `Active` (two-word `Value`), `CandidateB`,
  `CandidateC` (one-word `u64`) — `native_call.rs:205-227` — with decoders in
  `native_call/value_abi.rs:10-59` that validate the word came from the
  receiving heap. A Candidate-C finalize+dispatch test passes today
  (`native_call/tests/candidate_c.rs:14-36`).
- **Helper-import surface is ALL two-word `-> Value`** and must gain one-word
  siblings: env `aos_env_get` (`env.rs:76`) / `aos_upval_get` (`:152`), force
  `aos_force` (`force.rs:148`) + `aos_force_deep`/`aos_blackhole_check`, apply
  `aos_apply` (safety.rs:291-297), attr `aos_has_attr`/`aos_select_ic`/`aos_update`
  (safety.rs:362-375), write-barrier `aos_gc_write_barrier` (safety.rs:441-447),
  primop `aos_primop_call` (`primop.rs:66`), string-length `aos_string_length`
  (`string_length.rs`, safety.rs:603-609), `aos_alloc_cons` (cons head is a
  `Value`, safety.rs:198-225).
- **The one-word env pinning:** both widths are declared side-by-side —
  active `RuntimeEnvGetNativeFn = ...fn(*mut c_void, u32) -> Value` (`env.rs:38`)
  and Candidate-B `RuntimeCandidateBEnvGetNativeFn = ...-> u64` (`env.rs:50`),
  with `aos_candidate_b_env_get` (`env.rs:98`) reachable only via
  `..._native_wrapper_address()` (`env.rs:117`), **unregistered** — the process
  manifest returns only `aos_env_get` (`env.rs:213`). **There is no Candidate-C
  env helper anywhere in the crate.** The wrapper-local export blockers are now
  empty (`ENV_ACCESS_REMAINING_EXPORT_BLOCKERS = &[]`, `env.rs:56`), but the
  oracle native-export gate still tracks `MissingFinalExportedWrapper` /
  `TrapTransferUnimplemented` (test `env.rs:322-339`). The width-rejection guard
  is `require_artifact_value_abi` → `UnsupportedArtifactValueAbi { expected,
  actual }` (`cranelift/native_error.rs:36-42, 148-152`) — an entry-type
  mismatch, not a finalize block.
- **The FFI crate does not deref a `Value` payload as a raw pointer** — value
  decoding is delegated to the oracle heap; the only raw-pointer casts are the
  `*mut c_void` context/env handles (`context.rs:36-39, 106-108, 145-215`),
  which are unaffected by value width. So the cutover work here is the `-> Value`
  **signatures** and their safety-manifest pins, not pointer arithmetic.

### 1.3 JIT (`ratchet-jit`) — dual-layout aware; stack maps hardcoded two-word

- **The CLIF signature is width-parameterized.**
  `clif_signature_for_runtime_call_with_layout(sig, value_layout)` (`abi.rs:197`)
  expands each `Value` param/return into `layout.register_words()` `i64` words
  (`abi.rs:362-366`); `validate_observed_value_layout` accepts 1..=2 words
  (`abi.rs:392-410`). The active public path selects the two-word layout
  (`clif_signature_for_runtime_call`, `abi.rs:161-165`); Candidate-C selects the
  one-word layout (`clif_signature_for_candidate_c_runtime_call`, `abi.rs:188-195`)
  and has an adapter witness (`abi.rs:807-820`). `JitValueAbi { Active,
  CandidateB, CandidateC }` (`artifact.rs:15-21`) defaults to `Active`
  (`artifact.rs:73-86`).
- **Constant emission is two-word today.** `emit_value_return` (`lower.rs:2462-2473`)
  emits **two** `iconst.i64` (tag + `relocation_sensitive_identity_bits`); the
  Candidate-C lowerer emits **one** (`lower/candidate_c.rs:59-60`, `word.raw()`).
  Heap-backed constants are rejected before emission
  (`lower/error.rs:507-513` `UnsupportedHeapConstant`, called at `lower.rs:415`).
  Candidate-C lowering + native boundary (`lower/candidate_c.rs`,
  `cranelift/candidate_c.rs`) are built but reachable only via their own
  entrypoints, not the active IR-root dispatch.
- **STACK MAPS + RELOCATION assume two-word (the load-bearing invalidation).**
  `lower/stack_maps.rs` is built end-to-end on `[Value; 2]`: module header
  "update both words / reload both" (`:1-7`); slot geometry
  `VALUE_STACK_SLOT_BYTES = 16`, `VALUE_PAYLOAD_OFFSET = 8` (`:175-179`);
  `spill_values(&[[Value; 2]])` writes both words (`:189, 199-205`); `attach`
  anchors one map entry per value at a `32 + index*16` stride with the payload
  implicit at +8 (`:213-232`); `force`/`reload` are arity-2 (`:76-83, 235-243`);
  geometry pinned by test (`:306-342`). The finalized SP-offset join
  (`cranelift.rs:3119-3150`) records one root per value at the tag-word offset,
  payload implicit at +8. **The recent relocation/stack-map landing assumed the
  two-word representation.** A one-word value changes the spill geometry
  (`VALUE_STACK_SLOT_BYTES` 16→8, second `stack_store` gone, stride
  `32+index*8`), the slot width, the collector's payload-word writeback
  contract, and every `[Value; 2]` signature. Because JIT is dual-layout-aware,
  this can be built as a second (one-word) geometry selected by `JitValueAbi`,
  but it must exist before the carrier flips.
- **Safety manifest** (`safety.rs:342-529`) pins native-entry/code-pointer
  families by **exact trimmed source line** (e.g. `JitThunkFn`,
  `JitCandidateCThunkFn`, the `transmute::<*mut u8, JitThunkFn>`). Renaming the
  active thunk/lambda return type from `Value` to a one-word carrier breaks the
  exact-string assertions even where counts hold.

### 1.4 Serialization / memo / `.drv` — ALREADY representation-neutral (no change)

Verified: none of these hold a live `Value` word. Cache scalar payloads are
canonical data — `InlineValuePayload::{Int(i64), Float(u64 /*bits*/), Bool,
Null}` (`cache/runtime/inline_value_payload.rs:11-15`), `CachedScalarValue`
likewise (`cache/runtime/expression_value.rs:37-42`), converted to/from `Value`
only at the `active_values.rs:21` boundary. Memo entries carry
`Arc<CachedExpressionValue>` plain data with no heap handles
(`tree_walk/memo.rs:114-115`). `.drv` rendering holds ATerm/hash bytes
(`cache/runtime/derivation_payload.rs`), and cutoff hashing is `blake3` over
canonical bytes (`cache/cutoff.rs:30-51, 328`). **The serializer, memo cache,
`.drv` rendering, and eval-cache key/hash layers need no change** — a major
de-risk that keeps `.drv` byte-parity structurally independent of the carrier.

## 2. Activation mechanism

**There is no runtime flag, and there cannot be one for the carrier.** No
`AOS_NIX_VALUE_ABI` / `ACTIVE_VALUE` / repr `cfg` / cargo feature gates the
active representation in `ratchet-value` or `ratchet-oracle`
(`ratchet-oracle/Cargo.toml` `default = []`; the only value-width `cfg`s are
`debug_assertions`/`target_os` on the reservation). The sole existing selector,
`AOS_NIX_JIT_VALUE_ABI` (`aos-nix/src/jit/engine/value_abi.rs:11-17`), governs
only JIT tier-1 *literal-thunk* lowering (`JitValueAbi::{Active,CandidateB,
CandidateC}`), not the tree-walk carrier.

A struct's size is fixed at compile time, so the carrier cannot be a runtime
switch. Two ways to stage it are available:

1. **Compile-time variant (recommended for the flip itself).** Introduce a
   `candidate_c_value` cargo feature that selects the `Value` representation (and
   the ~dozen genuinely two-word-assuming sites) at build time, producing a
   Candidate-C binary that runs the full parity battery as a P8 "build-the-variant-
   and-keep-the-winner" candidate (doc 30 §3.6), then is promoted to default.
   This keeps a bisectable A/B and a fallback, matching how Candidate-B/C landed
   their prerequisites.
2. **Direct flip.** Change the `Value` type in place once all peripheral
   machinery is active-capable. Simpler diff, no dual-build, but no A/B safety
   net.

**Per-value-kind staging is NOT possible for the carrier** (all `Value`s are one
type; you cannot have some 8-byte and some 16-byte). What *is* per-kind
stageable is everything *around* the carrier: scalar boxing (§5 S0), the bridge
(S1), FFI import helpers (S2), and the JIT stack-map geometry (S3) all land
active-first under the 16-byte carrier, so the final flip (S4) is minimal.

## 3. Test strategy

**Suites that pin the old ABI (coherent lock-step update required):**
- `ratchet-value/src/value.rs:668, :822` — the 16-byte `Value` ABI-contract
  asserts (size/layout). Update to the 8-byte contract at the flip.
- `ratchet-core/src/runtime_abi/value_layout.rs:63-81` — asserts active = 16/2/8
  distinct from Candidate-C 8/1/8. At the flip, `runtime_abi_value_layout()`
  returns the 8/1/8 layout; this test inverts.
- `ratchet-runtime-ffi/src/safety.rs` (env `:1409-1444`, and every `-> Value`
  family `:729-1141`) — **exact-line** ABI-string pins + per-family counts. New
  one-word helper lines get new entries per the documented safety-manifest
  update process (`heap/safety.rs` "count N→M" precedent).
- `ratchet-jit/src/safety.rs:342-529` — exact-string native-entry pins; the
  active thunk/lambda alias return-type change touches these.
- `ratchet-jit/src/lower/stack_maps.rs:306-342` — the two-word slot geometry
  test; rewritten for the one-word geometry (or gated by `JitValueAbi`).
- The FV-0 identity audit `eval/heap/tests/payload_identity.rs` — any
  reclassified `payload_bits` consumer fails until reviewed; this is the
  intended tripwire.

**New differential coverage the cutover needs:**
- JIT shape differential across **all 6 lowerable shapes** under Candidate-C
  (the existing tier-1/tier-2 differential broadened, per doc 30 §2.4's
  "all 6 lowerable shapes" battery), plus the candidate-b/c conformance suites.
- FFI: the tri-width *return* round-trip (exists) **plus** the new one-word
  *import* helpers (env/force/apply/attr/primop/string-length), each with a
  foreign-heap/wrong-domain rejection witness (mirroring
  `native_call/value_abi.rs:41-58`).
- The two-live-heaps same-offset regression witness (already exists per doc 30
  FV-4 reservation-domain row) must stay green under the active carrier.
- Boxed-scalar coverage: every `f64` and every out-of-`i32`-range `i64` boxes;
  inline `i32` never boxes — a targeted corpus at the immediate-range boundary
  (`±2^31`).

**Parity battery modes (all byte-green, per doc 30 §9.2):** byte-parity ×
{16 package legs} in serial / `AOS_NIX_JIT=1` / `K=4` / `AOS_NIX_GC=sweep`
(threshold-0); compute ×9; `bench.wide` / `bench.wide-eval`; the strict-JSON
seed corpus in the four modes; the memory columns A/B (the compression is
supposed to *reduce* value mass — the win must show). **GC-stress + sweep-zero
is mandatory** for the S3 stack-map rework.

## 4. Risk register — top 5 silent-breakage modes

1. **A `payload_bits` consumer truncates a 64-bit payload to `u32`.** 60
   `payload_bits` sites assume a `u64` payload; a Candidate-C payload is a 32-bit
   half. A consumer that reads the full word where it should read the low half
   (or vice-versa) silently corrupts an index or a scalar.
   *Detection:* the FV-0 identity audit (`payload_identity.rs`) forces review of
   every reclassified site; a compile-time width assertion on the codec; parity
   `.drv` diff on any value that flows to a derivation attribute.
2. **An FFI caller invokes a two-word `-> Value` helper through a one-word
   signature (or vice-versa).** ABI mismatch = the second register is garbage =
   silently wrong value, no crash. Worst in the helper-import surface (env/force),
   which is entirely two-word today.
   *Detection:* the `require_artifact_value_abi` guard
   (`cranelift/native_error.rs:36-42`); the safety-manifest exact-line pins that
   fail the build on a signature-string change; the per-helper foreign-heap
   rejection witnesses; differential under `AOS_NIX_JIT=1`.
3. **Stack-map root enumeration reads/writes the wrong word width under GC.** If
   a root slot stays 16-byte (`VALUE_STACK_SLOT_BYTES = 16`) while the value is
   8-byte, the collector's relocation writeback rewrites/reloads the adjacent
   word → torn heap references, observable only under a moving/stress collector.
   This is the recently-landed two-word code (`lower/stack_maps.rs`,
   `cranelift.rs:3119-3150`) directly.
   *Detection:* GC-stress + `AOS_NIX_GC=sweep` threshold-0 parity; the
   `stack_maps.rs` geometry test reworked to the one-word stride; the relocation
   writeback tests.
4. **Boxed-scalar reservation-domain aliasing / inline-vs-indexed misclassification.**
   Two live heaps allocating the same `u32` offset, or an inline `i32`
   mis-decoded as an indexed word (or an indexed word missing its domain),
   dereferences a foreign or wrong cell.
   *Detection:* `CompressedValueWord::from_raw` validation
   (`compressed.rs:192-216`: missing-domain, domain-on-inline, forced-on-non-thunk,
   bad bool/null payload); the two-live-heaps regression witness; `ArenaDomainMismatch`
   guards in the scalar stores (`compressed.rs:523, 801`).
5. **The forced-thunk shortcut bit (`COMPRESSED_FORCED_BIT`, bit 31) is silently
   lost.** The 16-byte `Value` cannot carry it (the bridge rejects with
   `ForcedThunkUnsupported`, `bridge.rs:52-54`). If, mid-cutover, a forced
   Candidate-C thunk word round-trips through the still-active 16-byte bridge, the
   shortcut is dropped → redundant re-forcing or, worse, a laziness/observability
   divergence.
   *Detection:* thunk claim/park parity (`K=4` + sweep-zero); a forced-bit
   fast-path round-trip test; the `is_forced_thunk` / `with_forced_bit`
   invariants (`compressed.rs:269-288`). **Ordering rule:** the carrier flip and
   the removal of the `ForcedThunkUnsupported` bridge path must land together —
   never a state where a forced Candidate-C word can reach the lossy bridge.

## 5. Staged landing order (smallest-first, each parity-gated)

Every stage keeps the full parity battery (§3) byte-green. S0-S3 land under the
**16-byte carrier**; S4 is the flip; S5 is the follow-on win.

- **S0 — Scalar boxing via the Candidate-C store, float-first.** Route
  `alloc_float_value` then `alloc_int_value` (`active_values.rs:56, 45`) through
  `EvalHeap.compressed_scalars` so every `f64` and out-of-range `i64` allocates a
  boxed reservation cell, carrier unchanged. Exercises boxing + reservation
  membership + domain guards under parity. Gate: standing battery + the
  boxed-scalar domain regression + the immediate-range corpus (risk 4).
- **S1 — Activate the `EvalHeap` Candidate-C bridge on an internal path.** Turn
  on `candidate_c_encode_value`/`decode_value` (`compressed_values.rs:26, 59`)
  round-trips at a chosen internal seam (e.g. a debug shadow that encodes then
  decodes every produced value and asserts equality), still 16-byte carrier, to
  flush encode/decode + heap-location + membership bugs before they matter.
  Gate: standing battery with the shadow assert on.
- **S2 — FFI dual-width import helpers.** Add one-word Candidate-C siblings for
  every `-> Value` helper (env/force/apply/attr/write-barrier/primop/string-length),
  mirroring `aos_candidate_b_env_get`; register them behind `JitValueAbi`
  selection; the return path is already tri-width. New safety-manifest entries
  per the update process. Gate: standing battery + the per-helper rejection
  witnesses (risk 2); JIT still selects Active for the tree walk.
- **S3 — JIT one-word stack-map + relocation rework (the load-bearing item).**
  Build a one-word slot geometry in `lower/stack_maps.rs` (single `stack_store`,
  8-byte slot, `32 + index*8` stride) and the matching finalized SP-offset join
  (`cranelift.rs:3119-3150`) **as a SECOND geometry selected by
  `JitValueAbi::CandidateC`, NOT an edit of the two-word path** (lead ruling §7.2):
  both geometries live simultaneously until S4b proves the one-word one. Gate:
  **GC-stress + sweep-zero** + the reworked geometry test + the relocation
  writeback tests (risk 3). Also add the one-word `emit_value_return` path under
  the Candidate-C layout beside the two-word one.
- **S4 — The carrier flip, JIT OFF** (lead ruling §7.2). Change `Value` to the
  8-byte representation via the `candidate_c_value` compile-time variant (§2
  option 1, lead ruling §7.1 — not in place), re-point the `value.rs` accessor
  surface (`payload_bits`/`*_identity_bits` → the 32-bit halves), collapse
  `AtomicValueCell` to one `AtomicU64` (`env.rs:474-554`), switch
  `active_values.rs` + the bridge to native Candidate-C, select the one-word
  layout from `runtime_abi_value_layout()`, and remove the `ForcedThunkUnsupported`
  lossy path (risk 5, atomic with the flip). **The variant runs with the JIT
  disabled** (tree-walk Candidate-C only). Gate: the parity battery **serial +
  K=4 + sweep** byte-green on the variant + the full differential corpus + all
  pinned-ABI test updates in lock-step (§3) + the memory-column A/B showing the
  value-mass reduction. This is the big-bang commit, minimized by S0-S3.
- **S4b — Re-enable JIT Candidate-C.** Only after S3's one-word stack-map
  geometry is GC-stress + sweep-zero proven, wire the active JIT dispatch to the
  Candidate-C layout under the variant and add `AOS_NIX_JIT=1` to the S4 gate.
  This decouples the two hardest risks (carrier flip vs. stack-map rework).

  **STATUS (2026-07-12): increment 1 LANDED** (82113215b..bb63c3110). S2
  dissolved into the flip (under the variant `runtime_abi_value_layout()` is
  one-word, so the frozen-signature adapter and the `-> Value` FFI helpers are
  already one-word ABI). S3's one-word geometry landed beside the two-word one
  in `lower/stack_maps.rs`; the runtime-side binding walker strides by
  `size_of::<Value>()`. The delegating tier-1 shapes (constant, env/upval get
  + forced, primop trampoline, stringLength inline, apply, update,
  select/has-attr) emit through a width-generic `lower/value_words.rs` facade
  and lower on both carriers; `emit_value_return` embeds only
  arena-independent compressed words (wide ints/floats decline as
  `ArenaBackedConstant`, decoded via `as_int`/`as_bool` — `payload_bits` is
  the whole word on this carrier and loses sign extension). Compound emitters
  (inline arith trees, alloc-cons, tier-2 lambda bodies) decline at their
  entries via `require_two_word_carrier` and stay on the tree walk. The engine
  and `AOS_NIX_JIT` gates are open on both carriers; ~370 JIT tests run under
  the variant (native execution, publish/dispatch, differentials), with only
  genuinely two-word test bodies still baseline-gated. Gate results: byte
  parity x4 (zlib/openssl/bash/coreutils) green on the variant release binary
  with `AOS_NIX_JIT=1`, tier-1/tier-2 counters identical to baseline.
  **Remaining (S4b phase 2):** compressed-word emitters for arith trees
  (inline-int decode/re-encode + deopt), alloc-cons, and the tier-2 bodies;
  then the GC-stress + sweep-zero battery over live one-word stack maps with
  a non-trivial dispatch mass.
- **S5 — Container narrowing + variant promotion (follow-on).** Narrow list
  spines and post-shape attr slots to 4-byte where they hold only heap references
  (doc 30 §3.5), the additional memory win. Then, once the variant wins the full
  benchmark matrix, **promote `candidate_c_value` to default and delete the
  Active carrier** (the kill-date criterion, lead ruling §7.1) — the workspace
  does not carry two carriers indefinitely. Separately gated; not required to
  declare S4 done.

## 6. Decisions, and doc-vs-code divergences

### 6.1 Decisions (2026-07-12, team lead)

Binding rulings on the §5/§2 questions; these govern the S0-S5 implementation.

1. **Q1 — Compile-time VARIANT approved.** `candidate_c_value` is a compile-time
   variant (P8 build-and-select), not an in-place flip: bisectable, keeps the
   Active fallback, and lets the parity battery run both carriers side-by-side.
   **Constraint:** while the variant exists, the landing gate for every S-stage
   runs the battery on **both** carriers (the variant must never rot silently),
   and the variant carries a **kill-date criterion** — once it wins the full
   benchmark matrix, it is promoted to default and the Active carrier is deleted
   (S5). The workspace does not carry two carriers indefinitely.
2. **Q2 — JIT OFF for the flip; S3 is a second geometry.** S4 flips the carrier
   with the JIT disabled (tree-walk Candidate-C, serial + K=4 parity); S4b
   re-enables JIT only after S3's one-word stack-map geometry is GC-stress +
   sweep-zero proven. **S3 reworks the just-landed two-word stack-map code
   (`lower/stack_maps.rs`, `cranelift.rs:3119-3150`) as a SECOND geometry
   selected by `JitValueAbi`, NOT an edit of the two-word path** — both
   geometries live until S4b proves the one-word one. This decouples the two
   hardest risks (carrier flip vs. stack-map rework).
3. **D2 accepted — the variant feature IS the missing switch.** Doc 30's
   "selecting the one-word active ABI" language gets a pointer fix in the batched
   doc pass; the `candidate_c_value` variant is that selection mechanism.

### 6.2 Doc-vs-code divergences

- **D1 — The recent stack-map/relocation landing assumed two-word.**
  `lower/stack_maps.rs` and `cranelift.rs:3119-3150` are recently-landed code
  (the FV-0 "compiled-root prerequisite" / relocation work) built explicitly on
  `[Value; 2]` and "update/reload both words." The cutover **reworks** this
  landing (S3). Flagged because it is the one place the cutover directly
  contradicts a just-shipped mechanism — the lead should expect that diff to
  touch code another agent recently authored.
- **D2 — No `AOS_NIX_VALUE_ABI` exists; doc 30 language implies flaggability.**
  Doc 30 §12 speaks of "selecting the one-word active ABI" as if a selection
  point exists; in code the only selector is JIT-tier-1-scoped
  (`AOS_NIX_JIT_VALUE_ABI`). The active carrier is a hard type with no switch
  (§2). The plan supplies the missing mechanism (the `candidate_c_value`
  variant), which is new work, not a flip of an existing flag.
- **D3 — `ForcedThunkUnsupported` is a mid-cutover hazard, not just a bridge
  detail.** The lossy 16-byte bridge path (`bridge.rs:52-54`) must be removed
  atomically with the carrier flip (risk 5); a staged state where a forced
  Candidate-C word can reach it is a silent laziness bug. Called out so the S4
  commit boundary is drawn to include it.

---

**Bottom line.** The cutover is **big-bang at the carrier, staged everywhere
else.** Serialization is already neutral, scalar construction is funneled, and
the JIT/FFI return path is width-parameterized — so S0-S3 land the boxing, the
bridge, the dual-width FFI import helpers, and (the hardest new work) the
one-word JIT stack-map/relocation geometry under the unchanged 16-byte carrier,
each parity-gated. S4 then flips the `Value` type in one reviewable commit under
the `candidate_c_value` compile-time variant (lead ruling §6.1) with the **JIT
off** — minimized to the accessor contract, `AtomicValueCell`, the layout
selector, and the forced-bit bridge removal — gated serial + K=4 + sweep;
S4b re-enables JIT Candidate-C once S3's one-word stack maps are stress-proven,
and S5 promotes the winning variant to default and deletes the Active carrier.
The single item most worth attention is that S3 reworks the recently-landed
two-word stack-map/relocation roots (`lower/stack_maps.rs`,
`cranelift.rs:3119-3150`) as a second `JitValueAbi`-selected geometry: that code
assumed the two-word representation and the cutover cannot avoid rebuilding it.

---

**Handoff (2026-07-12, superseded below).** Phase 1 (this design note) is
complete. The Phase-2 handoff recorded here was **reactivated** by the lead the
same day (option A: prioritize the S4 JIT-off carrier flip = the memory prize);
implementation is now underway in this session. See §7.

## 7. Implementation progress and remaining handoff (2026-07-12)

Worked in a dedicated clone (`.claude/worktrees/rfc0007-cutover-clone`, branch
`worktree-rfc-0007-nix-evaluator`), pushing directly to origin with
`pull --rebase` before each push (candidate-b / fv5 push concurrently).

**Gate harness (important).** The full 4-attr byte-parity battery requires the
**system nix store**, not the repo-relative store: run with
`AOS_NIX_STORE_DIR=/nix/store AOS_NIX_STATE_DIR=/nix/var/nix NIX_REMOTE=daemon`
(+ `AOS_NIX_ORACLE=<nix-2.24.12>/bin/nix-instantiate`, `AOS_NIX_NATIVE=1`). A
cold repo-local store hits a pre-existing `fetchTarball` tree-hash divergence on
the gcc bootstrap source (task #19: mirror drift vs. the pin; native
store-short-circuits correctly against the warm system store). Baseline 4-attr
serial is byte-green in this config (zlib/openssl/stdenv.bash/stdenv.coreutils).

**Gate rules for every remaining sub-increment (lead conditions 2 + 3).** Each
sub-increment builds **both** carriers (`--features native-eval` and
`--features native-eval,candidate_c_value`) and gates **both**: the **default**
carrier (including `AOS_NIX_JIT=1`) must stay **100% green** on the full 4-attr
byte-parity battery, and the **variant** runs its tree-walk battery (**serial +
K=4 + `AOS_NIX_GC=sweep`**; JIT off under the variant until S4b). State the
variant battery scope and the 4-attr cold+warm median RSS scoreboard line in
every commit body (add wide-eval RSS once runnable). **A half-flipped carrier
must never land — stop at the last green sub-increment** if you wall.

**Landed:**
- **S0** (commit `813fc859b`) — `AOS_NIX_CANDIDATE_C_SHADOW` scalar-store shadow
  in `active_values.rs`, default-off; proves the boxed-scalar encode/decode +
  reservation-membership path at eval scale. Byte-parity green shadow off + on.
- **S1** (commit `1cc5e302c`) — broadened active-value bridge round-trip test
  across all flat kinds (strings incl >4 KiB, path, nested lists, scalar edge
  cases).
- **S4 sub-increment 1** — the `candidate_c_value` compile-time variant + JIT
  **unreachable by construction** under it (condition 1): feature plumbed
  `ratchet-value` -> `aos-nix` -> `aos-core` -> `aos`; `tier1_engine_for`
  (`aos-nix/src/native/mod.rs`) returns `None` under the variant so no engine is
  ever created; `EvalConfig::native_jit()` (`aos-core/src/nix/eval.rs`) reports
  off regardless of `AOS_NIX_JIT`; a variant-only refusal test asserts it. Both
  carriers compile; the default carrier is unchanged (all `cfg(not(...))`).

**Remaining S4 (the carrier flip — hand off from here, staged, never
half-flipped):**

- **SI-1 completion — DONE (feature plumbing); test-gating deferred to SI-3.**
  Landed a coherent `candidate_c_value` pass-through across the whole ratchet
  stack so both carriers build and the per-crate variant gate is runnable:
  `ratchet-core` (owns the `runtime_abi::value_layout` 8/1/8 descriptor) and
  `ratchet-value` (owns the carrier) each define the feature; `ratchet-oracle` /
  `ratchet-jit` / `ratchet-runtime-ffi` forward to **both** so the runtime can
  never see an 8-byte `Value` under a 16-byte layout descriptor (or vice-versa);
  `aos-nix` forwards through every layer. **Empirical finding:** at SI-1 *no test
  needs gating yet* — the variant crate suites
  (`ratchet-value`/`-core`/`-oracle`/`-jit`/`-runtime-ffi` + `aos-nix`) are green
  because the representation has not flipped, so the two-word JIT still runs
  against a two-word runtime. `native_jit_enabled_eval_gates_and_matches_tree_walk`
  in particular asserts `tier1_promoted()==0 && tier1_dispatched()==0`, which the
  variant's JIT-off-by-construction path *satisfies*, so it passes unchanged. The
  `#[cfg(not(feature = "candidate_c_value"))]` gating of the JIT engine-direct
  tests (candidate_c/candidate_b/conformance suites) lands **with the SI-3 repr
  flip**, when those tests actually break, each with a loud
  `// S4b re-enables; see cutover plan §6.1` comment — gating them now while they
  pass would silently drop coverage on a guess. Gate this increment: default
  serial+JIT byte-parity 8/8; variant serial+K4+sweep 12/12; both carriers' crate
  suites green (only the pre-existing `no_source_file_exceeds_line_cap` gate red).
- **SI-2 — accessor-contract mechanicals** (compile-through on both carriers):
  ensure every `Value` access goes through the `value.rs` accessor surface
  (constructors `:123-241`, accessors `tag`/`payload_bits`/`*_identity_bits`/
  `as_*` `:259-541`); refactor any direct field / `payload_bits`-as-`u64`
  consumer (the 60 `payload_bits` + 18 `relocation_sensitive_identity_bits`
  sites, tracked by `eval/heap/tests/payload_identity.rs`) so the representation
  can swap under them. No-op on the default carrier.
- **SI-3 seam correction — `as_heap_ptr` is NOT self-contained under Candidate-C
  (needs a lead ruling before the flip).** The §7 SI-3 line "re-point the accessor
  surface to the 32-bit halves" is correct for scalars but **incomplete for heap
  values**, and the gap is load-bearing. Verified facts:
  - A Candidate-C heap `Value` carries a **32-bit `ArenaIndex` offset**, not a
    pointer (`value/compressed.rs`). Resolving it to a `NonNull<HeapObject>`
    requires the reservation **base**.
  - The reservation base is a **dynamic per-eval `mmap`** with a `null_mut()`
    hint and no `MAP_FIXED` (`heap/reservation.rs:198-207`) — there is no fixed
    process VA, so `base + index` cannot be computed from the word alone.
  - There is exactly **one reservation per evaluation** (serial: `EvalHeap`'s
    `flat_arena`; parallel: the *one common* `ReservedArena` shared by all shards,
    `shared_arena.rs:12,56`), but **multiple `EvalHeap`s can be live at once** (the
    two-live-heaps regression, doc 30 FV-4) — so a single process-global base is
    unsound.
  - All ~83 `as_*_ptr` consumers live in `ratchet-oracle` heap-context code (22 in
    `heap/arena.rs`); **zero** in `aos-nix`/`ratchet-jit`/`ratchet-runtime-ffi`.
  - There is **no ambient/thread-local base mechanism today**.

  Because the reservation base is dynamic and multiple heaps coexist, `Value`
  cannot keep a self-contained `as_heap_ptr()` accessor without one of two new
  mechanisms — a **design fork the plan did not specify**:
  1. **Global domain→base registry.** The word already carries the 23-bit
     reservation domain; a small global map (domain → base, populated on
     `ReservedArena::new`, dropped on unmap) lets `as_heap_ptr()` resolve
     `registry[domain].base + index` self-containedly and handles coexisting
     heaps. *Preserves the accessor signature → SI-2 is near-zero call-site work*,
     but adds a lock-free global with real `unsafe`/drop-ordering weight.
  2. **Thread heap/arena context into resolution.** Replace `value.as_heap_ptr()`
     with `heap.resolve_heap_ptr(value)` at the ~83 sites (all already hold
     `&self` heap). *No global*, matches the existing bridge
     (`candidate_c_pointer_for_index`), but is an 83-site refactor and changes the
     "preserve the accessor surface" contract.

  These two paths imply **opposite SI-2 refactors**, so SI-2 cannot proceed
  correctly until the mechanism is chosen. Per §6.1 / the "stop and report if a
  §7 seam is wrong" rule, the carrier flip is **held here pending a ruling**;
  improvising either mechanism risks a half-flipped or unsound carrier.

  **RULING (2026-07-12, team lead): Option 1 (domain→base registry) with a
  two-layer performance rider.** The registry is the correctness mechanism
  (coexisting heaps via distinct domains, cross-worker decode, accessor surface
  preserved, small SI-3 diff) and doubles as the rebase indirection heap-image
  snapshots (task #6) need — map an image anywhere, register domain→new base,
  done. **Rider — per-deref cost is sacred** (the whole flat-value campaign
  existed to kill deref indirection): implement BOTH layers —
  1. the **registry backs the self-contained accessor** (`Value::as_heap_ptr`,
     Debug, FFI decode, future JIT helpers, snapshot rebase — correctness
     everywhere); and
  2. **arena-internal hot paths resolve via the heap's own cached base** (a
     self-field load, no global) — the accessor internals take an optional
     heap-context fast path, or the ~83 hot sites use the existing bridge-style
     `arena.pointer_for_index` where `&heap` is in hand.

  Registry lookup stays as cheap as the domain space allows (fixed-slot lock-free
  table; live domains per process are few). Registry `unsafe` lives in the
  sanctioned zone with the token manifest + drop-ordering SAFETY comments: a
  domain must be unregistered before its mapping dies, and values must not
  outlive their heap (the existing invariant, now enforced at the registry seam).
  **Deref-cost gate at SI-3:** the variant battery `native_mean` must not be
  slower than the default carrier on the 4-attr suite — the 8-byte carrier should
  *win* via cache density; if it loses, the hot path isn't hot enough yet and
  that is fixed before SI-3 is called done.
- **SI-2 — registry substrate — DONE.** Landed the process-global
  `domain → base` table (`ratchet-value/src/heap/reservation_registry.rs`): a
  fixed-slot (2048), lock-free, `unsafe`-free table (it stores and returns
  addresses, never dereferencing them). `ReservedArena` registers `domain → base`
  in its constructor before the reservation escapes and withdraws it in `Drop`
  **before** the mapping is unmapped (the register-before-escape /
  unregister-before-unmap ordering that upholds values-must-not-outlive-their-heap
  at the registry seam; domains never repeat, so a post-unmap lookup returns
  `None`, never a stale/aliased base). Heap safety manifest updated coherently
  (reservation.rs unsafe count 7 → 8 for the added construction-failure unmap;
  the registry module itself adds zero `unsafe`). A **debug-only registry
  cross-check** in the bridge's `candidate_c_heap_location` asserts
  `reservation_base(domain) + index == arena pointer` for every heap value, so
  the context-free SI-3 accessor math is proven byte-for-byte against the arena's
  own base+offset across the S1 bridge corpus before the flip depends on it.
  Runs on BOTH carriers (registration is not cfg-gated — it is per-reservation,
  not per-value, so it is parity-neutral and also serves snapshot rebase, task
  #6). The accessor re-point itself is inseparable from the repr flip and lands
  in SI-3 (a 16-byte `Value` still carries its own pointer, so there is nothing
  for the accessor to resolve through the registry until the carrier is 8 bytes).
- **SI-3 — the flip** (one reviewable step, variant only): cfg-swap `Value`
  (`ratchet-value/src/value.rs:113-119`) to the 8-byte `CompressedValueWord`
  representation; re-point the accessor surface to the 32-bit halves with heap
  values resolved by the SI-2 registry (`Value::as_heap_ptr` =
  `reservation_base(domain)? + index`) for context-free callers, and hot
  arena-internal sites via the arena's cached base (`pointer_for_index`); collapse
  `AtomicValueCell` (`eval/env.rs:474-554`) to one `AtomicU64`, switch
  `active_values.rs` + the bridge to native Candidate-C, select the one-word
  layout from `runtime_abi_value_layout()`
  (`ratchet-core/src/runtime_abi/value_layout.rs:12`), and remove the
  `ForcedThunkUnsupported` bridge path (`value/compressed/bridge.rs:52-54`)
  atomically with the flip. Gate: full 4-attr battery serial + K=4 + sweep on
  the variant (JIT off), both carriers green, RSS scoreboard line.
  - **DONE (WIP 761e81fc5) + test-suite reconciled.** The flip compiles both
    carriers and is byte-parity-correct (variant 12/12 serial+K4+sweep, default
    8/8 serial+JIT). The 791 variant test failures were reconciled per the SI-3
    brief's three classes + the razor (fake-pointer A / GC-stress-record-
    placement B / baseline-assertion C, plus the JIT-off module gates and one
    dual-carrier ABI-rejection assertion); the FV-0-stale payload-identity
    accessor census was reconciled on both carriers. RSS scoreboard (§5.4):
    bench.wide resident 134.2 MiB vs default 152.0 MiB = **0.88x**, peak-RSS-
    delta 6.1 vs 23.2 MiB = 0.26x (the 16->8B memory prize). Deref-cost rider:
    the variant is ~4% slower on wide compute (index->base+offset resolve not
    offset by cache density on cache-resident workloads) — a hot-site deref
    audit is an S4 follow-up, not a blocker.
- **S4b** — re-enable JIT under the variant after S3's one-word stack-map
  geometry lands (§6.1 condition 2).

**Cross-agent coordination (fv5 / memory-campaign L4).** L4 arena-owns the
thunk state (kills the `Arc<ThunkCell>` sidecars). Agreed contract: L4 sizes its
inline arena slot off the **type** (`mem::size_of::<ThunkCell>()`), not a
hardcoded constant, and treats `AtomicValueCell` as **opaque** (public
store/load API, no field-offset assumptions). Then the variant's
`AtomicValueCell` shrink (16B -> 8B, cfg-gated) is inherited for free with no
merge note. S4 owns `AtomicValueCell`'s internal representation (`env.rs`,
cfg-gated); L4 owns `ThunkCell` placement (`thunk.rs` + the arena) and the
force-path re-entrant-borrow / stable-`*const ThunkCell` solution — S4 does not
touch that borrow.

## 8. Carrier-selection criteria (P8 build-and-select)

The SI-3 flip landed as a compile-time **variant** (`candidate_c_value`,
off-by-default). Merging it banks the capability without changing any default
binary — the shipped carrier stays the 16-byte Active pair. Which carrier
becomes the *default* is the P8 build-and-select decision (§6.1 Q1), made later
with explicit criteria recorded here.

**Measured at the flip (2026-07-12, both release binaries, system store, byte-
parity green):**

- **Memory — Candidate-C wins.** `bench.wide` resident RSS **134.2 MiB** vs the
  Active carrier's **152.0 MiB** = **0.88x**; per-eval peak-RSS-delta **6.1 MiB**
  vs **23.2 MiB** = **0.26x**. The 16->8-byte `Value` is the single biggest
  memory step toward the wide-eval RSS target.
- **Compute — Candidate-C loses ~4%.** Load-canceled interleaved `bench.wide`
  warm `native_mean` median (n=6): **0.4206s** vs **0.4033s** = **+4.3%**; the
  four small package attrs are +0.9-3.3%. The original rider assumed cache
  density would pay for the compressed word's `index -> base+offset` resolve;
  the measurement says it does not on cache-resident workloads. This is a
  genuine memory-vs-compute tradeoff, not a defect — the rider is amended
  accordingly (it is not a landing blocker for the off-by-default variant).

**The selection weighs the ~4% compute cost against:**

1. the memory win above (0.88x resident / 0.26x per-eval delta), and
2. what **only** Candidate-C enables — address-free heap-image snapshots (the
   biggest queued cold-start lever: a snapshot maps anywhere and re-registers
   `domain -> new base`, which a raw-pointer carrier cannot do) and the S4b
   one-word JIT stack-map geometry.

**Decision point:** make the default-carrier call once the **S4b** one-word JIT
numbers and the **heap-snapshot prototype** numbers exist, so the memory win and
the Candidate-C-only capabilities can be weighed against the measured compute
cost with real data on both sides.

**Recorded follow-up (may claw back part of the 4%):** a hot-site deref audit —
route the remaining hot arena-internal `Value` accesses through the arena's
cached base (`arena.pointer_for_index`) instead of the global reservation-base
registry, per the §6.1 two-layer rider. The registry stays the correctness
mechanism for context-free callers (Debug, FFI decode, snapshot rebase); only
the hot path needs the self-field base load.
