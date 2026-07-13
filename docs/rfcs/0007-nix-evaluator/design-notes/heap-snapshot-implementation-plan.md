# RFC-0007 — Heap-image snapshot implementation plan (design note)

> Design-only prep for the doc-31 §1 evaluator heap-image snapshot (task #6,
> doc 22 "Tier 3"). This note audits what actually exists at HEAD against the
> assumptions in [31 — substrate optimizations](../31-substrate-optimizations.md)
> §1, cites the code seams by `file:line`, proposes a concrete snapshot
> boundary and image format, and gives a staged, parity-gated landing order.
> It is a plan, not an implementation; no code was changed and no build was run
> to produce it (per the task's design-only, read-and-one-file constraint).
>
> Companion specs: [31](../31-substrate-optimizations.md) §1 (the technique),
> [30](../30-flat-value-architecture.md) (the flat-value + reservation
> substrate this rides on), [29](../29-tiered-content-keyed-memoization.md)
> §3.1/§7.1 (fingerprint keys; CHECK-mode pattern), [06](../06-memory-management-and-gc.md)
> §4 (the B1 sweep / B2 moving collector), [13](../13-parallel-evaluation.md)
> (the shared-graph parallel substrate), and the sibling note
> [simplifier-implementation-plan.md](./simplifier-implementation-plan.md) §8
> (the `PASS_SET_VERSION` decision that this note's invalidation key must fold
> in).

## 0. Executive summary

- **Prerequisite verdict: the flat-object substrate exists and is
  reservation-backed, but the image is NOT address-free today.** All six FV
  stages have landed ([30](../30-flat-value-architecture.md) §12): strings,
  paths, lists, attrsets, thunks, lambdas, and primops are flat objects, and
  a real demand-paged 4 GiB Candidate-C reservation with checked `u32`
  offsets is live (`ratchet-value/src/heap/reservation.rs`). **But the active
  `Value` is still a 16-byte tag+payload pair whose heap payload is a raw
  native `HeapObject` pointer** (`ratchet-value/src/value.rs:113-119`,
  `:241-252`), not a compressed index. The Candidate-C one-word index codec
  is built and passes its own tests but is *inactive* — the evaluator / FFI /
  JIT value ABI switch is an explicit open FV-4 row
  (`value/compressed.rs` module doc; [30](../30-flat-value-architecture.md)
  §12 FV-4 `[ ]` rows). Doc 31 §1's phrase "compressed 32-bit indices from
  doc 30 §2, which make the image address-free by construction" describes a
  capability that is **built but not switched on**. This is the single most
  important finding and it forks the whole design (§1, §3).

- **Recommended boundary: force a designated prelude root set, do not
  snapshot at the natural import boundary.** The natural boundary
  (`ratchet-oracle/.../eval/tree_walk/api.rs:322`, right after `eval_root()`
  returns and before the attr-path walk at `:324`) yields a WHNF attrset
  shell in which `lib`, `stdenv`, and the entire `pkgs` fixpoint are *still
  unforced thunks* (`eval_core.rs:680-686`; forcing is driven lazily,
  one attr-path segment at a time, only in `eval_numeric.rs:26-58`). A
  snapshot there captures almost no forced work and is worthless (§2). The
  boundary must be a deliberately over-forced prelude root set (§2.3).

- **Image realization: RULED — wait for the Candidate-C ABI, build
  address-free (no throwaway rebase machinery).** Live `Value`s and
  `AtomicValueCell` slots carry raw native pointers today (`eval/env.rs:474-547`),
  so an image built now would need a rebase-on-load pass. The team lead has
  ruled (2026-07-12, §9) that we will **not** build that throwaway machinery:
  the Candidate-C ABI cutover (8-byte compressed-index `Value`) is an already
  -open FV-4 checklist row, is independently valuable, and was the prior
  engineer's direction — tracked as **task #12**. Snapshots build address-free
  *after* that cutover, when heap references are base-relative `u32` offsets and
  the image maps with no rebase pass at all. The rebase-on-load variant is
  documented in §3.3 as the rejected interim, not the plan.

- **The persisted JIT and parse caches already survive a snapshot;** the
  fragile handles are live-runtime only (`EvalModuleId`, raw pointers). The
  tier-2 compiled-body cache is content-keyed (`LoweredIrFingerprint` + IR
  node ids), not module-id-keyed (`ratchet-oracle/.../cache/hashing.rs:447`),
  so it composes cleanly (§6).

- **Gate: RULED — implementation does not start until a measurement lands
  (§9).** The team lead has ruled (2026-07-12) that the item is measure-first
  gated on **the fraction of cold-eval wall spent forcing the `lib`+`stdenv`
  prelude scaffolding that is identical across packages** — folded into the
  same `AOS_NIX_EVAL_STATS` increment as the parallel-front-end S0 parse/lower
  timers (one eval-stats landing). If that number comes back small, the item is
  re-scoped honestly: the parse cache + import memo may already own most of the
  prelude win (§2.2). Implementation is blocked on both this metric and the
  Candidate-C cutover (task #12).

- **Staged landing (post-gate):** in-process serialize+reload byte-equality of
  a trivial eval first, then a forced-prelude snapshot behind `AOS_NIX_SNAPSHOT`,
  then CHECK-mode re-eval parity, then default-on — parity gate at every stage
  (§7). This is the largest single item in doc 31 and rides after the
  Candidate-C ABI cutover.

## 1. Prerequisite audit (doc 31 §1's assumptions vs. HEAD)

Doc 31 §1 asserts its prerequisites are "largely already being built" —
"position-independent flat values (doc 30) and the relocation work landed
alongside them … are exactly the substrate a dumpable, rebasable heap needs."
Here is what is actually true, component by component.

### 1.1 The flat-value heap — READY as bytes, NOT address-free as words

- **Flat objects exist and hold their payload inline.** FV-1..FV-3 landed:
  string/path bytes, list spines, attrset slots, and thunk/lambda/primop
  handles live in flat objects in a bump/reservation arena, resolved by one
  membership-checked load with no record-table probe
  ([30](../30-flat-value-architecture.md) §12 FV-1/FV-2/FV-3 `[x]`;
  `ratchet-oracle/src/eval/heap/flat_values/{lists,attrs,closures}.rs`). The
  arena's allocation order is traversal order, so a segment dump is a coherent
  contiguous graph. **This is the good news: the heap graph is dumpable.**

- **The value word is a native pointer, not an index.**
  `ratchet-value/src/value.rs:113-119` — `struct Value { tag: ValueTag,
  payload: u64 }`; for a heap tag the payload is set from the raw address
  (`value.rs:241-252`, `Value::heap`) and read back as a raw address
  (`value.rs:322-325`, `relocation_sensitive_identity_bits`, whose very name
  flags it). So the reachable graph is full of absolute addresses. A snapshot
  mapped at a different base is invalid until those words are rewritten.

- **The Candidate-C index substrate is built but inactive.**
  `heap/reservation.rs` maps the 4 GiB demand-paged reservation, defines
  `ArenaIndex(u32)` byte offsets and 23-bit reservation `ArenaDomainId`s, and
  checks every pointer/index conversion. `value/compressed.rs` seals the
  one-word codec (`COMPRESSED_FORCED_BIT`, inline `i32`, boxed-scalar/heap
  indices). But its module doc states plainly: "The active evaluator still
  uses `Value`; switching the runtime and JIT ABI is a later, separately
  gated step." Doc 30 §12's FV-4 tail confirms the reservation, codec,
  shared-mode adoption, both serial lanes, boxed-scalar populations,
  arena-domain identity, and an inactive checked conversion bridge are all
  `[x]`, while **"Candidate C: … selecting the one-word active ABI and
  narrowing containers remain"** is `[ ]`.

  **Conclusion:** value words are 64-bit native pointers today. The
  address-free-by-construction property doc 31 §1 leans on is one ABI cutover
  away, not present.

### 1.2 Relocation machinery — PRESENT, built for a moving collector, reusable

The FV-0 relocation audit is real and is exactly the writeback machinery a
rebase pass needs:

- The executable identity audit classifies every payload-address use into
  raw-scalar / address-only / relocation-sensitive families and pins per-file
  counts (`ratchet-oracle/src/eval/heap/tests/payload_identity.rs`;
  [30](../30-flat-value-architecture.md) §2.4). Production has 29/5/18 sites
  across 22 files.
- The live writeback path (`relocation_identity.rs`) stages a survivor
  mapping and rekeys the lazy-identity/fold and tier-1 publish tables,
  enumerates `AtomicValueCell` payloads as writable roots, and defers heap
  field stores to an allocation-free commit — for the B2 *moving* collector.
- Compiled roots: finalized Cranelift SP offsets are joined to live frame
  bindings with a transactional two-word slot writeback
  ([30](../30-flat-value-architecture.md) §12 FV-0 compiled-root row).

**A snapshot rebase is a strictly simpler special case of this pass:** it is a
one-shot, whole-graph, single-threaded relocation with a *known constant
delta* (new base − old base), run once at load with no concurrent mutator.
The moving collector's transactional multi-root writeback under a live mutator
is harder than what rebase needs. This machinery is the strongest prerequisite
doc 31 §1 is right about — but note it was built to rewrite roots into a
*freshly allocated* destination in the same process, not to rebase a mapped
foreign segment; the delta-add form is new code, even if the root enumeration
is reused.

### 1.3 GC copying/moving support — B1 non-moving is production; B2 moving is proving-ground only

- **B1 sweep is non-moving and retire-in-place.** Retirement swaps the flat
  payload for a `FlatClosurePayload::Retired(tag)` tombstone; the header and
  address remain and **addresses are never reissued**
  (`flat_values/closures.rs:70-85`; [30](../30-flat-value-architecture.md)
  §12 FV-3 sweep row). Region pops reclaim LIFO by rewinding the arena.
- **B2 (copying/moving) is not in the production path.** Worker-closure
  placement is `WorkerClosurePlacement::{Flat, Record}`; production always
  allocates flat, and only heaps under an installed `GcStressPolicy` or the
  explicit scaffolding option keep the record layout so the B2 relocation
  proving ground stays green ([30](../30-flat-value-architecture.md) §12 FV-3
  closure row). `heap/concurrent_gc.rs` is a *daemon* moving-barrier contract,
  not an active production collector.

**Implication for snapshots:** the production heap never moves objects, so
within a single process a snapshot's mapped segment can be treated as a
**permanent, immortal generation** that the sweep does not scan and does not
reclaim (§6.3). This is the natural and safe integration — it matches how the
permanent-shared domain is already immortal in one-shot mode.

### 1.4 Residual state outside the arena — a snapshot must include, rebuild, or reference each

A snapshot of the arena alone is insufficient. The reachable prelude graph
references several structures that do not live in the dumpable arena:

| Out-of-arena state | Where | Snapshot disposition |
|---|---|---|
| **Global symbol table** — attribute names are `Symbol(u32)` (`ratchet-core/src/ir/mod.rs:553`) indexing one process-global table `self.symbols`, redirected from per-module `ir.symbols` via `mem::take` (`eval/tree_walk/eval_load.rs:130,184`). | `SymbolTable` (`ratchet-core/src/ir/mod.rs:276`). | **Include** in the image (or its stable serialization). Symbol ids are table-position-dependent; a snapshot must reload the exact table so `Symbol(u32)`s in flat attrsets still resolve. |
| **Thunk force-state sidecars** — `FlatClosurePayload::Thunk(EvalThunk)` still carries an interior `Arc<ThunkCell>` (serial) plus optional parallel-cell `Arc` (`flat_values/closures.rs:74-85`; [30](../30-flat-value-architecture.md) §12 FV-6: 691k thunk-state sidecar clones remain on wide). | Interior to the flat closure payload; `Arc`-owned, outside the arena bytes. | **Rebuild.** A forced prelude thunk's *result* is a flat `Value`; its `ThunkCell` state (Forced/…) must be re-materialized on load, or the prelude must be snapshotted in a canonicalized "all forced, cells collapsed" form (§3.2). This is the hardest residual. |
| **String-context elements** — kept `Arc`-backed deliberately (`38da57c37`; [30](../30-flat-value-architecture.md) §5). | Interior to string values. | **Include** (serialize the context set) or intern into the image; store-path-bearing strings dominate derivation output, so context must round-trip byte-exactly or `.drv` parity breaks. |
| **Per-module lowered IR** — captures reference `(EvalModuleId, node)`; `EvalModuleId(u32)` is a process-local sequential module-table index (`eval/module.rs:11`; `eval_core/module_env.rs:202-211`). | The module table + each module's `Ir`. | **Reference via a stable key, not the live id.** The live `EvalModuleId` will not survive reload with a different load order; the image must record modules by content key (parse-cache `LoweredIrFingerprint`) and rebuild the id↔module mapping (§6.2). |
| **Parse-cache handles / JIT code** | `ratchet-oracle/src/cache/parse/`; `aos-nix/src/jit/`. | **Reference / recompute.** Parse artifacts are content-addressed on disk and reload verbatim; JIT native code is never persisted and is always recompiled (`compiled_body_cache.rs:1-8`). Neither needs to be in the image. |

**Net prerequisite verdict.** Doc 31 §1 is directionally correct that the flat
layout + relocation audit are the substrate — but it overstates readiness in
two specific ways this plan must design around: **(1)** value words are native
pointers, so the image is not address-free and needs a rebase pass (or the
Candidate-C ABI first); **(2)** the reachable graph is not self-contained in
the arena — the symbol table, string contexts, thunk-cell state, and the
module table are out-of-arena state a snapshot must handle explicitly. Neither
is fatal; both are unmentioned in doc 31 §1 and are the real work.

## 2. The snapshot boundary

### 2.1 Where the prelude ends in eval code (verified)

- Entry: `aos build pkgs.<pkg>` / `aos nix-diff` →
  `NixRunner::instantiate` (`aos-core/src/nix/runner.rs:325-334`) →
  `NativeEvaluator::instantiate` (`aos-nix/src/native/mod.rs:204-206`) →
  `eval_file_attr_derivation_closure_with_stats`
  (`aos-nix/src/native/mod.rs:543`), which reads `<repo>/default.nix`
  bytes, checks the durable root cutoff (`:568-585`), and on a cold miss
  descends into the oracle.
- **The one well-defined boundary:**
  `ratchet-oracle/src/eval/tree_walk/api.rs:322` calls `evaluator.eval_root()`
  (the top-level value), and `:324` then walks `pkgs.<pkg>` via
  `eval_instantiation_attr_path`. **Between `:322` and `:324`** the prelude
  (`default.nix`, which imports `lib` and builds the `pkgs` fixpoint) has been
  evaluated to a value, but no package-specific segment has been forced.

### 2.2 What is forced there — almost nothing (the decisive fact)

`eval_root()` (`eval_core.rs:680-686`) evaluates only to **WHNF**. For a
`default.nix` whose root is an attrset, WHNF is the attrset *shell with every
attribute left as an unforced thunk* — `lib`, `stdenv`, and the whole `pkgs`
fixpoint are unforced. Nothing on this path eagerly forces the scaffolding;
forcing happens lazily, one attr-path segment at a time, only when the
attr-path walk descends into the requested package (`eval_numeric.rs:26-58`,
`force_value` per segment). The pure-import-root force cache only memoizes
*scalar* roots and explicitly declines an attrset-valued root
(`eval_import_root_cache.rs:52-105`).

**Therefore a snapshot at the natural boundary is worthless:** it captures a
handful of WHNF attrset shells and no forced prelude values. The parse/lower
of the prelude *is* already covered — cheaply and durably — by the
content-addressed parse cache (`cache/parse/`, verbatim `ir.bin` reload) and
the in-process import-value memo keyed by realpath (`eval_import.rs:637`,
`import_cache` at `tree_walk.rs:1245`). **The parse/lower fraction the doc
imagines the snapshot saving is already saved elsewhere.** The only thing a
heap image can add over the existing caches is *forced values* — and at the
natural boundary there are none.

### 2.3 The boundary must be a deliberately over-forced prelude root set

Since laziness means little is forced at any natural point, the snapshot
build step must **eagerly force a designated prelude root set** and snapshot
after that:

- **Root set candidates** (force at snapshot-build time, accept over-forcing):
  `lib` in full (it is pure, terminating, and shared by every package —
  the tier-up census found `lib/strings.nix` bodies bit-identical across all
  probe packages, [30](../30-flat-value-architecture.md) §7.1), plus the
  `stdenv` scaffolding attrsets (`mkDerivation`, the setup-hook wiring, the
  default builder) up to but not through any concrete package's
  `derivationStrict`. The forcing must **stop before** `derivationStrict`
  (`NIX_OP_DERIVATION_STRICT`) so the image contains no package `.drv`s —
  those are per-demand and belong past the boundary, served by doc 29's memo
  records.
- **Impurity guard.** Forcing the root set must record its impure
  observations (the trace of §4) and must **refuse to bake any
  CLI/system-sensitive value** — the same hazard the simplifier note flags
  (D3): `builtins.currentSystem` / eval-system must be part of the
  *invalidation key* (§4), never silently forced into a snapshotted value
  that a cross-`--eval-system` eval would then reuse wrongly.
- **Honest tradeoff.** Over-forcing `lib`+`stdenv` risks forcing values a
  given eval would never demand (wasted snapshot-build work, larger image)
  and — worse — risks forcing a thunk whose forcing *observes impurity or
  diverges* on some path. Mitigation: restrict the root set to a
  statically-fixed, reviewed list of provably-pure prelude attributes, grown
  by measurement, never a blanket deep-force of the top-level set. The
  snapshot-build eval runs with the same options as a normal eval so its
  observations are captured identically.

**Recommendation:** boundary = "after forcing the fixed prelude root set,
before any `derivationStrict`," snapshot taken at that instant. Reported to
the lead as the load-bearing design decision (doc 31 §1 leaves "what
constitutes the prelude" open; this is the concrete answer, and it is *not*
the natural import boundary the doc's parenthetical suggests).

## 3. Image format and loading

### 3.1 Layout

A single-file image, mmap-able, with a manifest header, arena segments, a root
table, and the out-of-arena side structures of §1.4:

```text
heap-image v1 (all offsets are image-relative u64; segments 4 KiB-aligned):

  ┌───────────────────────────────────────────────────────────────┐
  │ header: magic "AOSNIXHI", format version, PASS_SET_VERSION,    │
  │   PARSE_CACHE_SCHEMA_VERSION, arena-base-at-dump, total len     │
  │ invalidation key (§4): 32-byte blake3                          │
  │ integrity: blake3 of each segment + whole-image digest         │
  ├───────────────────────────────────────────────────────────────┤
  │ segment: symbol table (serialized SymbolTable)                 │
  │ segment: string-context pool (interned context elements)       │
  │ segment: module manifest — [ (LoweredIrFingerprint, role) ]    │
  │   in load order, so EvalModuleIds can be rebuilt deterministically │
  ├───────────────────────────────────────────────────────────────┤
  │ segment: flat arena bytes (the dumped reservation prefix)      │
  │ segment: relocation-root table — offsets of every              │
  │   relocation-sensitive pointer word within the arena segment   │
  │   (only present in the rebase-on-load variant; empty when the  │
  │   arena is index-addressed)                                    │
  ├───────────────────────────────────────────────────────────────┤
  │ root table: named prelude roots → arena offsets                │
  │   ("lib" → off, "stdenv" → off, top-level attrset → off)       │
  └───────────────────────────────────────────────────────────────┘
```

The arena segment is exactly the used prefix of the serial permanent lane's
reservation (`SharedFlatStoreArena`, `heap/flat/backing.rs`), which already
charges only the used prefix, not 4 GiB ([30](../30-flat-value-architecture.md)
§12 FV-4 serial-permanent row). Dumping it is a `write(2)` of a contiguous
byte range; loading it is `mmap(2)` of that range.

### 3.2 The thunk-state problem — canonicalize to "forced, cells collapsed"

The residual thunk-cell `Arc`s (§1.4) do not serialize. The image must store
the prelude in a canonical form where every root-set value is **already forced
and its `ThunkCell` state collapsed to the forced result**. Concretely: the
snapshot walk visits the forced root set, and for any `Value` that is a
forced thunk it records the *result* value (the flat WHNF object), not the
thunk wrapper. Unforced thunks reachable from the root set (values the eager
force did not demand) are a real question: either (a) exclude them from the
snapshotted graph and re-thunk them lazily on demand from `(module, node)`
after load — which requires the module manifest (§3.1) so `(EvalModuleId,
node)` can be rebuilt — or (b) forbid them by making the root-set force deep
enough that the snapshotted graph is thunk-free. **Recommendation: (a)** —
a snapshot of *forced* values plus a thin re-thunking shim for the unforced
frontier, because a fully thunk-free deep force over-forces badly and risks
divergence (§2.3). This is the subtlest part of the format and should be
prototyped in the FV-style smallest-first increment (§7.1) before the prelude
scale.

### 3.3 Address-free vs. rebase — the fork from §1.1

- **Rebase-on-load (first shippable, given native-pointer words).** On load,
  after `mmap`, walk the relocation-root table (§3.1) and add `(new_base −
  base_at_dump)` to every relocation-sensitive pointer word, then rekey the
  identity side-tables exactly as `relocation_identity.rs` does for the moving
  collector (§1.2). Cost: one O(reachable pointer words) pass at load,
  defeating some of the lazy-page-fault benefit (rebase touches every pointer
  word's page). Mitigation: try to `mmap` at the same base as the dump
  (`MAP_FIXED` hint) so the delta is zero and the pass is skipped — feasible
  because a one-shot `aos` process controls its own address space early.
- **Address-free (end state, needs Candidate-C active).** Once the value word
  is a `u32` arena offset (`ArenaIndex`, `value/compressed.rs`), heap
  references are base-relative by construction and **no rebase pass runs at
  all** — the image maps and is immediately usable, pages faulted lazily, the
  doc-31 §1 ideal. The reservation-domain identity already encoded in
  Candidate-C words (`heap/reservation.rs`, 23-bit domain) is exactly what
  lets a loaded image's offsets be distinguished from a live heap's.

**Ruling (2026-07-12, team lead; §9).** Do **not** build the rebase-on-load
variant. It is throwaway machinery that a moving-collector-shaped rebase would
duplicate, and the address-free endpoint is reachable directly via the
Candidate-C ABI cutover (task #12, an already-open FV-4 row that is independently
valuable). The snapshot builds address-free only, *after* that cutover: the
relocation-root table shrinks to empty and no per-pointer pass runs at load. The
rebase-on-load design above is retained here as the documented rejected interim
so the reasoning is not re-derived; it is not the plan.

### 3.4 Integrity and loading semantics

- **Integrity:** blake3 per segment + a whole-image digest in the header;
  verified before the arena is trusted (matches the root-cutoff record's
  byte-exact discipline, `root_cutoff.rs`).
- **Lazy loading:** `mmap` with demand paging; the reservation is already
  demand-paged so only touched prelude pages fault in. The rebase pass (when
  present) is the one thing that forces eager touching — another reason to
  prefer same-base mapping / the address-free variant.
- **Arc-free reachable graph requirement:** the mapped segment must contain no
  `Arc`/`Rc`/`Box` — any owned pointer in a mapped read-only segment is a
  use-after-free/double-free waiting to happen. This is why §1.4's residuals
  (thunk cells, contexts) must be collapsed/interned into segments (§3.2), and
  why FV-6's remaining thunk-state `Arc` is the gating obstacle: the
  snapshotted values must be the fully-owned-by-arena kinds (lambda/primop
  snapshots already carry no payload `Arc` after FV-6;
  [30](../30-flat-value-architecture.md) §12 FV-6), with thunk results
  collapsed to their flat WHNF objects.

## 4. Invalidation key

The image is valid for a re-eval iff every input it observed is unchanged. The
key is a blake3 over:

1. **Parse-cache fingerprints of every module the snapshot observed** — the
   `LoweredIrFingerprint` (`cache/parse/mod.rs:137-150`, salted with
   `PARSE_CACHE_SCHEMA_VERSION = 11`, `:50`) of each file in the module
   manifest (§3.1). This is the "every file the snapshot observed" set doc 31
   §1 names; the module manifest *is* that set.
2. **`PASS_SET_VERSION`** — the simplifier's pass-set version
   ([simplifier-implementation-plan.md](./simplifier-implementation-plan.md)
   §8 decision 2): the simplifier rewrites IR and therefore moves
   `LoweredIrFingerprint`s and any snapshotted values derived from them. The
   snapshot key must fold it in so a pass-set change is a clean snapshot miss.
   (At the time of writing the simplifier is not yet landed; the key must
   reserve this field from day one so enabling it later invalidates cleanly.)
3. **The result-affecting fingerprint** — `result_affecting_fingerprint`
   (`eval/tree_walk/options/result_fingerprint.rs:20`), which already folds in
   `current_system`/eval-system (`:54-57`), `nix_path` (`:80-86`), store dir,
   path-literal base, eval mode, allowed paths, etc. This is the eval-relevant
   env/config slice doc 29 §2.3 and doc 31 §1 both require, and it is exactly
   the component the root-cutoff key already uses (`root_cutoff.rs:89`).
4. **The canonicalized cacheable impure-input trace** — the observed
   filesystem/env slice (`readFile`/`getEnv`/`import`/`pathExists`/`readDir`),
   canonicalized by `canonicalize_cacheable_input_trace`
   (`eval_impure_inputs.rs:137`) and re-checked on load by
   `revalidate_cacheable_input_trace` (`:103`). The snapshot reuses the
   root-cutoff record's two-part structure verbatim: a key (items 1-3) plus a
   revalidation slice (item 4) checked against the live world before the image
   is trusted.
5. **Binary identity** — `ACTIVE_CRANELIFT_CODEGEN_VERSION` is irrelevant
   (no code in the image), but the `aos-nix` build identity and the image
   `format version` guard against a value-representation change (e.g. the
   Candidate-C cutover) silently reusing an incompatible arena layout.

This mirrors, and should share code with, the root-cutoff record
(`root_cutoff.rs:64` key + `:222` trace validation) — the snapshot is
effectively a *cold-path* sibling of the root-cutoff *warm-path* record, one
level lower (values, not the finished closure).

## 5. CHECK mode

Per the doc 29 §7.1 pattern and the existing root-cutoff shadow check
(`AOS_NIX_ROOT_CUTOFF_CHECK` → `verify_root_cutoff_closure`,
`root_cutoff.rs:341`, requiring byte-identical closures):

- **`AOS_NIX_SNAPSHOT_CHECK`** re-evaluates the prelude root set from scratch
  (parse → lower → force the same root set) *and* maps the image, then
  byte-compares the two forced graphs value-by-value: same tags, same flat
  payload bytes, same string contexts, same attrset shapes and iteration
  order, same forced results. Any divergence fails loud with the first
  differing root path.
- Where it slots in: the snapshot loader (§3) gains a check arm that, instead
  of trusting the mapped image, runs the cold force in parallel and diffs. The
  diff harness is the same structural value-equality the differential battery
  already uses (`aos-nix-harness/src/diff.rs`), extended from `.drv` bytes to
  forced-value graphs.
- Because the ultimate gate is still **byte-identical `.drv` output**, the
  snapshot's real acceptance is: the whole parity battery
  ([30](../30-flat-value-architecture.md) §9.2 — byte-parity ×4 serial/K=4/JIT,
  compute ×9, `bench.wide`) run twice, snapshot-off and snapshot-on, both
  green. `AOS_NIX_SNAPSHOT_CHECK` is the cheaper always-on-in-CI inner guard;
  the parity battery is the outer proof.

## 6. Interaction audit

### 6.1 Parallel eval (shared graph, `AOS_NIX_PARALLEL`)

- Parallel mode uses a different heap: `SharedHeapArena` with per-worker
  shards over the common reservation (`eval/heap/shared_arena.rs:21`), and
  cross-worker handles are **raw `usize`/`NonNull<HeapObject>` addresses**
  (`shared_arena.rs:179-189`, `shared_backend.rs:141`). `AtomicValueCell`
  stores the raw pointer word (`eval/env.rs:474-547`, storing
  `relocation_sensitive_identity_bits`).
- **Implication:** a snapshot restored into a parallel eval is subject to the
  same rebase requirement (§3.3) as serial, and the flat objects' base-relative
  `u32` offset (already tracked, `shared_arena.rs:38-39,57,68`) is the seam the
  address-free variant would use. First cut: **build the snapshot in and for
  serial mode only**; the prelude is identical across modes, and serial is the
  simpler relocation story. Parallel restore is a follow-on gated on the same
  rebase pass proving out serially.

### 6.2 JIT compiled-body cache (module ids)

- The tier-2 compiled-body cache key is **content-derived, not module-id
  keyed**: `CompiledBodyRecordHash::for_unary_tier2`
  (`ratchet-oracle/src/cache/hashing.rs:447`) folds `LoweredIrFingerprint` +
  the `pattern`/`body` IR node ids + budget + `ACTIVE_CRANELIFT_CODEGEN_VERSION`
  + target triple (`compiled_body_cache.rs:413-429`). No `EvalModuleId`
  appears. Native code is never persisted; only address-free lowerings are,
  re-codegen'd on load (`compiled_body_cache.rs:1-8`). **So the JIT cache
  survives a snapshot untouched.**
- The fragile handle is `EvalModuleId` (`eval/module.rs:11`), a process-local
  sequential module-table index (`module_env.rs:202-211`). Live thunks embed
  `(EvalModuleId, node)`. The snapshot must **not** persist raw
  `EvalModuleId`s; it persists the module manifest by content fingerprint
  (§3.1) and rebuilds the id↔module mapping on load in the same order, so the
  restored `EvalModuleId`s match what a cold eval would assign. Any snapshotted
  `(module, node)` reference is stored as `(LoweredIrFingerprint, node)` and
  re-resolved.
- Note: **JIT is disabled under `AOS_NIX_PARALLEL`** (`aos-core/src/nix/eval.rs:1575`;
  tier-1 is worker-affine), so the JIT-snapshot interaction only exists in
  serial mode — which is where §6.1 already scopes the first cut.

### 6.3 GC (sweep over a mapped read-only segment)

- The mapped image must be treated as a **permanent, immortal generation**:
  the B1 sweep must not scan it and must not attempt to reclaim it (it is
  read-only; a retire-in-place write would fault). This matches the existing
  permanent-shared domain, which is immortal in one-shot mode
  ([30](../30-flat-value-architecture.md) §7.4). The sweep already segregates
  by allocation domain; the image is a new immortal domain the sweep skips.
- **Cross-domain references** are one-directional and safe: post-boundary
  worker values (packages) reference into the immortal prelude image, never
  the reverse (the prelude was forced before any package existed). So the
  sweep over the worker domain never needs to write into the image; it only
  needs to *not* mistake an image address for a dead worker object — the
  header magic/kind check already fails loud on foreign addresses
  (`flat_values/closures.rs` retirement/`unknown` path), and the Candidate-C
  reservation-domain id (§3.3) makes this exact at the word level once active.

### 6.4 Root-cutoff warm path (no double-answering)

- Root cutoff is a *warm* path that returns the finished closure before any
  eval (`aos-nix/src/native/mod.rs:568-584`, returning at `:583` without
  calling `eval_file_attr_closure_full`). The snapshot is a *cold* path
  optimization that only runs in the cold arm (`mod.rs:587`).
- **No double-answering as long as snapshot restore is gated strictly inside
  the cutoff-miss branch** (`mod.rs:587`): the order is root-cutoff hit →
  return closure; else snapshot-restore prelude → force only the demanded
  package → (write both a root-cutoff record and, if absent, refresh the
  snapshot). The two share the invalidation vocabulary (§4) but answer at
  different granularities (finished `.drv` closure vs. forced prelude values),
  so they compose as warm-then-cold, never both.

## 7. Staged landing order (parity gate at every stage)

Each stage is a small, parity-gated commit; every stage keeps the
snapshot-off battery byte-green, and a stage that *enables* snapshotting adds
its snapshot-on parity evidence (the twice-run battery of §5).

1. **In-process serialize+reload of a trivial eval, byte-equality test.**
   Serialize the flat arena of a tiny eval (e.g. `let x = { a = 1; b = [1 2];
   }; in x`), reload it into a fresh heap in the same process, and assert the
   reloaded graph is value-equal to the original. No boundary, no prelude — this
   proves the arena-dump + relocation-root-table + rebase pass (§3.3) and the
   symbol-table/context segment round-trips (§1.4) in isolation. Smallest
   possible surface; no parity-battery interaction yet.
2. **Thunk-collapse canonicalization (§3.2), still in-process.** Extend stage 1
   to a graph containing forced thunks; prove the "forced, cells collapsed"
   form reloads value-equal, and that the unforced frontier re-thunks correctly
   from `(fingerprint, node)`. This is the subtle correctness core; invest test
   effort here (adversarial: `rec` sets, `__overrides`, string-context unions).
3. **Prelude snapshot build behind `AOS_NIX_SNAPSHOT_BUILD`.** Force the fixed
   prelude root set (§2.3), dump the image with the invalidation key (§4).
   No restore yet; just prove the build is deterministic (same image bytes
   across runs, per the reproducibility discipline) and the impurity guard
   refuses to bake `currentSystem`.
4. **Prelude snapshot restore behind `AOS_NIX_SNAPSHOT`, serial only.** Cold
   eval maps the image, rebuilds the module id mapping (§6.2), rebases (§3.3),
   and continues into the demanded package. Gate: `AOS_NIX_SNAPSHOT_CHECK`
   (§5) green, then the full byte-parity battery snapshot-on vs snapshot-off
   (×4 serial + `bench.wide`), plus a `nix-bench` cold-eval delta showing the
   prelude force cost moved into page faults.
5. **Invalidation hardening.** Prove every key component (§4) actually
   invalidates: mutate a prelude file (fingerprint moves → miss), change
   `--eval-system` (result fingerprint moves → miss), touch an observed
   `getEnv`/`readFile` (trace revalidation → miss). Each is a targeted test.
6. **Default-on, serial.** Flip `AOS_NIX_SNAPSHOT` default-on behind its own
   parity-green gate across the full closure + fuzz corpus; keep the env knob
   as an escape hatch and `AOS_NIX_SNAPSHOT_CHECK` as an always-on CI inner
   guard.
7. **(Deferred) Address-free variant + parallel restore.** After the
   Candidate-C ABI cutover (FV-4 open rows) lands, drop the rebase pass (§3.3)
   and extend restore to parallel mode (§6.1). Separately gated; not on the
   critical path to a first shippable cold-eval win.

Sizing: stages 1-2 are pure substrate proving (no parity-battery coupling);
stage 3-4 are where the real integration risk lives; stages 5-6 are hardening.
The whole item is doc-31 §1's "campaign-scale effort in its own right"
(§9 ordering) and should not be undertaken before the Candidate-C ABI question
is resolved with the lead (§8).

### 7.1 Anchors re-verified against HEAD (post-#12, 2026-07-13) + stage-1/2 spec

Increment-0 recon after the Candidate-C carrier flip (task #12) landed
(`ef2360f46`). The plan predates the flip; the seams are re-anchored here so a
fresh implementation agent starts from verified line references, not the
now-stale §8.2 D1.

**What the flip changed (in our favor):**

- **D1 is resolved.** The address-free words are live under the
  `candidate_c_value` cargo variant: a `Value` is one `CompressedValueWord`
  (`ratchet-value/src/value/compressed.rs:119`) = `kind | 23-bit domain |
  forced` high word + a `u32` `ArenaIndex` low word, resolved to a native
  pointer only through the process-global reservation registry
  (`ratchet-value/src/heap/reservation_registry.rs`, `domain -> base`). **Build
  the snapshot under this variant: the image is address-free by construction and
  no rebase pass runs** (§3.3 end state, §9 decision 1). The registry is the
  load-time rebind seam — map the image, register `domain -> new_base`, done.

**What already exists (stage-1 substrate, not greenfield):**

- Arena backing + used-region enumeration: `ReservedArena`
  (`ratchet-value/src/heap/reservation.rs:144`) with `high_mark()`, plus
  `SharedFlatStoreArena::snapshot_chunk_regions()`
  (`ratchet-value/src/heap/flat/backing.rs:360`) and `mapped_bytes`
  (`backing.rs:421`). Stage-1's arena dump is a thin serializer over these.

**The live gating obstacle (D3 is CURRENT, not stale — FV-6 did not remove it):**

- `EvalThunk` (`ratchet-oracle/src/eval/heap/mod.rs:200`) still holds
  `cell: Arc<ThunkCell>` (`:202`) and `parallel_cell:
  Option<Arc<TreeWalkParallelThunkCell>>` (`:210`). A mapped read-only segment
  MUST be `Arc`-free (§3.4), so **a live thunk cannot be snapshotted**. This is
  exactly why the §3.2 thunk-collapse canonicalization is the stage-2
  correctness core, not an optimization.

**Residuals (§1.4) are current:** the authoritative global symbol table
(`ratchet-oracle/src/eval/tree_walk/parallel_demand.rs:138`), the process-local
module table, and `Arc`-backed string contexts live outside the arena and take
the **rebuild-from-manifest** posture (do not map them; reconstruct from a
manifest segment and re-intern).

**Stage 1 (in-process serialize+reload, byte/value-equality) — build spec:**

1. Under `candidate_c_value`, evaluate a **fully-forced** trivial value (no
   thunks at the frontier — e.g. force `let x = { a = 1; b = [ 1 2 ]; }; in x`
   to WHNF *and* deep-force its elements so the arena holds only flat WHNF
   objects). Thunks are deliberately out of scope until stage 2.
2. Serialize the arena's used regions (`snapshot_chunk_regions` + `mapped_bytes`)
   into an image segment, plus a manifest segment for the symbol ids the values
   reference.
3. Reload into a fresh `EvalHeap` in the same process: allocate a new
   reservation, `register(domain -> new_base)` via the registry, copy the image
   bytes into the reservation, re-intern the manifest symbols.
4. Assert the reloaded root is value-equal to the original (`raw_eq` on the flat
   WHNF graph). No parity-battery coupling. Gate stays green on BOTH carriers
   (the snapshot module is `#[cfg(feature = "candidate_c_value")]`; the default
   carrier compiles it out).

**Stage 2 (thunk-collapse canonicalization) — the correctness core:**

- Extend to a graph with forced thunks. Snapshot **only the forced WHNF result**
  (drop the `Arc<ThunkCell>`), and re-thunk the **unforced frontier** from its
  `(LoweredIrFingerprint, IrId node)` pair on load — do NOT deep-force
  everything (over-forcing risks divergence, §8.1 Q3). Invest adversarial test
  effort here: `rec` sets, `__overrides`, string-context unions (the same
  slot-rewrite shapes that AtomicValueCell handles). This is the subtle core;
  everything after it (stages 3-6) is prelude-root-set + invalidation +
  hardening on top of a proven collapse.

**Handoff note:** #12 (address-free words) and #13 (force-share GATE=GO) are both
landed; stages 1-6 are unblocked. A fresh snapshot-impl agent should take stage 1
from this spec.

## 8. Open questions and doc-vs-code divergences

### 8.1 Open questions for the lead

- **Q1 — Sequence against the Candidate-C ABI cutover. RULED (§9): wait for
  C, build address-free only.** No interim rebase-on-load machinery. See §9
  decision 1 and §3.3.
- **Q2 — Is the forced-prelude root set worth it at all? RULED (§9):
  measure-first, implementation gated.** The named metric — the fraction of
  cold-eval wall spent forcing `lib`+`stdenv` scaffolding identical across
  packages — must land (folded into the parallel-front-end S0 `AOS_NIX_EVAL_STATS`
  increment) before implementation begins; a small number re-scopes the item
  honestly, since the parse cache + import memo may already own most of the
  prelude win (§2.2). See §9 decision 2.
- **Q3 — Thunk-frontier policy (§3.2).** Confirm the "snapshot forced values +
  re-thunk the unforced frontier from `(fingerprint, node)`" approach vs. a
  deep-force-everything image. Recommend the former; the latter risks
  divergence and over-forcing.
- **Q4 — Root-set definition ownership.** The fixed prelude root set (§2.3) is
  a reviewed, hand-maintained list. Where does it live and who owns keeping it
  in sync as `lib`/`stdenv` evolve? Recommend a single declared constant in
  the aos-nix native entry, changes to which bump the image `format version`.

### 8.2 Doc-vs-code divergences (doc 31 §1's assumptions vs. HEAD)

- **D1 — "compressed 32-bit indices … make the image address-free by
  construction" is not true today.** The Candidate-C index substrate is built
  but inactive; the active `Value` is a 16-byte native-pointer pair
  (`value.rs:113-119`). The address-free property is one ABI cutover away
  (FV-4 open rows). A first shippable image needs a rebase pass, which doc 31
  §1 does not mention. (§1.1, §3.3)
- **D2 — "the prelude fixpoint already forced into flat values" overstates
  what is forced.** At the natural post-`default.nix` boundary, `lib`, `stdenv`,
  and the `pkgs` fixpoint are *unforced thunks* (`eval_core.rs:680-686`;
  `eval_numeric.rs:26-58`). The snapshot must *eagerly force* a root set to
  have anything worth snapshotting; the doc's parenthetical "likely the
  post-import fixpoint before any package-specific demand" is exactly the
  worthless boundary. (§2)
- **D3 — the reachable graph is not self-contained in the arena.** Doc 31 §1
  treats the heap as the dumpable object. In code the reachable prelude graph
  references out-of-arena state: the global symbol table (`ir/mod.rs:276`,
  `eval_load.rs:130,184`), `Arc`-backed string contexts
  ([30](../30-flat-value-architecture.md) §5), interior thunk-cell `Arc`s
  (`flat_values/closures.rs:74-85`; FV-6 residual), and the process-local
  module table (`module.rs:11`). Each needs an include/rebuild/reference
  decision (§1.4); none is in doc 31 §1. The thunk-cell `Arc` in particular
  (FV-6 left it in place) is the concrete obstacle to an `Arc`-free mapped
  segment (§3.4).
- **D4 — relocation machinery is for a moving collector into a fresh
  in-process destination, not for rebasing a foreign mapped segment.** The
  FV-0 relocation audit and `relocation_identity.rs` writeback are real and
  reusable (root enumeration, side-table rekey), but the delta-add-over-mapped
  -segment form is new code; doc 31 §1's "exactly the substrate a rebasable
  heap needs" is true for the root *enumeration* and false for the *rebase
  operation itself*. (§1.2)
- **D5 — no heap-image snapshot code exists yet.** The "snapshot" symbols in
  the tree (`heap/gc.rs:344`, `heap/flat.rs:787`) are GC card-table / edge
  snapshots, unrelated. This is greenfield.

## 9. Decisions (2026-07-12, team lead)

Binding rulings on §8.1's open questions; where a decision refines a question,
the decision text supersedes it.

1. **Wait for the Candidate-C ABI cutover; build address-free only (Q1).** No
   throwaway rebase-on-load machinery. The Candidate-C one-word compressed-index
   `Value` is an already-open FV-4 checklist row, is independently valuable
   (8-byte values, the memory ladder), and was the prior engineer's direction —
   tracked as **task #12**. The snapshot image is address-free by construction
   once that lands (§3.3), with no per-pointer rebase pass. The rebase-on-load
   design (§3.3) is retained only as the documented rejected interim.
2. **Measure-first; implementation is gated on the metric (Q2).** The gating
   number — the fraction of cold-eval wall spent forcing the `lib`+`stdenv`
   prelude scaffolding identical across packages — is folded into the same
   `AOS_NIX_EVAL_STATS` increment as the parallel-front-end (task #3) S0
   parse/lower timers (one eval-stats landing, one lane slot). Snapshot
   implementation does **not** start until that number exists. If it comes back
   small, the item is re-scoped honestly: the content-addressed parse cache +
   the realpath import memo may already own most of the prelude win (§2.2).

   **MEASURED — gate PASSES (task #13, S0 commit `c3a02187d`, native, JIT off).**
   The prelude-*force* share is substantial, not small: zlib
   `prelude_thunks_forced/thunks_forced` = 62.9% (count) / 38.8% (inclusive
   nanos); openjdk = 85.0% / 44.8%. True wall share sits between the
   inclusive-nanos floor (~39-45%) and the count ceiling (~63-85%) — count
   overstates (prelude thunks are numerous but individually cheaper),
   inclusive-nanos double-counts nesting — and it **grows with eval size**
   (openjdk > zlib), which is exactly the snapshot's value case. Per §2.2 this
   is the snapshot's *unique* contribution: the prelude *parse* share (measured
   24.6%/22.4% of cold, and already amortized by the parse cache) is **not** the
   snapshot's win; the prelude *force* share above is. Net: **GO** — the item is
   justified and is **not** re-scoped. Sizing caveat (§5): this share is the
   *ceiling* on payoff; subtract image load/map cost, and take the authoritative
   single wall number from a sampling profile with module attribution before the
   final go/no-go on absolute speedup.
3. **Invalidation key approved as scoped (§4).** The two-part root-cutoff
   structure — key = per-module `LoweredIrFingerprint`s + `PASS_SET_VERSION` +
   `result_affecting_fingerprint` (eval-system, `nix_path`, …); revalidation
   slice = the canonicalized cacheable impure trace — stands as written.
4. **Rebuild-from-manifest is the default posture for out-of-arena state
   (§1.4).** For the symbol table, the module table, and `Arc`-backed string
   contexts, "rebuild on load from the image manifest" is the default wherever
   the structure is cheap to rebuild; include-in-image or reference-by-key are
   used only where rebuild is not cheap. The per-structure decisions of §1.4
   stand under this posture.

**Task-board effect.** Task #6 was gated `blockedBy` task #12 (Candidate-C
cutover) and task #13 (the S0 prelude-wall-share measurement). **Task #13 is now
complete and the gate PASSES (GO, above).** Task #12 (address-free carrier via
the Candidate-C cutover) is the **sole remaining blocker**; #6 begins
implementation from §7 once #12 lands.

---

**Bottom line.** The flat-object substrate genuinely exists and the heap graph
is dumpable, so the item is buildable — but two doc-31 §1 assumptions are
optimistic in ways that shape the whole design: the image is **not** address-free
today (native-pointer value words), and the natural boundary forces **nothing**
worth snapshotting. Per the lead's rulings (§9), the path is: **wait for the
Candidate-C ABI cutover (task #12)** so the image is address-free with no rebase
machinery, and **gate the whole item on measuring the forced-`lib`/`stdenv` wall
share** (folded into the task-#3 S0 instrumentation) — that number decides
whether this campaign-scale item earns its cost, or whether the parse cache +
import memo already own the prelude win. Once past the gate, the staged landing
(§7) is a serial, forced-prelude, address-free snapshot behind `AOS_NIX_SNAPSHOT`,
gated by `AOS_NIX_SNAPSHOT_CHECK` re-eval and the twice-run parity battery.
