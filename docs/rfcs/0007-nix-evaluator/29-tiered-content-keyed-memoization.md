# RFC-0007 - Tiered content-keyed memoization

> The fastest evaluator is one that does not evaluate ([12](12-incremental-evaluation-cache.md));
> the second-fastest is one that never evaluates the same subtree twice —
> not in this thread, not in this process, not on this disk, and not on
> this network.

This document records the **unified tiered content-keyed memoization
architecture** (approved 2026-07-07), a later addition to the RFC-0007
set in the same manner as [25](25-intermediate-representation.md)–[28](28-generalization-and-language-dialects.md).
It unifies the memoization mechanisms that have shipped or been approved
since the original design round — the demand/force cache, root-level
early cutoff, the parse cache, and the deferred JIT compiled-body cache
— under **one record abstraction**, and adds a **tiered placement
policy** (in-thread, in-process shared, multi-location disk, network)
driven by measured recompute economics.

Where [12](12-incremental-evaluation-cache.md) specified the incremental
cache as a design, enough of it now exists as code that this document is
written against the shipped vocabulary (`DemandCacheKey`,
`ForceCacheSubject`, `RootInstantiationRecord`, `LoweredIrFingerprint`)
and states explicitly where the approved theses and the code disagree
(§13). Nothing here weakens the byte-parity contract of
[02](02-compatibility-constraints.md): every tier is advisory, every hit
is revalidated against its impure-observation slice, and every tier has
a CHECK mode that re-evaluates and asserts byte identity.

---

## 1. One memo abstraction

### 1.1 Thesis

Today the evaluator carries what look like four separate caches:

1. the **demand/force cache** — per-node memoization of forced results,
   keyed by expression identity plus captured free-variable value
   hashes, with a persistent node layer under `AOS_NIX_CACHE`;
2. **root cutoff** — a warm `instantiate(file, attr)` answered from a
   durable root record with no eval at all (warm native instantiate
   7.8–28 ms, 5–18x faster than a warm C++ `nix` flake-eval-cache hit);
3. the **parse cache** — per-file lowered-IR artifacts keyed by realpath
   plus content hash, carrying the post-remap `LoweredIrFingerprint`;
4. the approved-but-deferred **JIT persistent compiled-body cache** —
   compiled CLIF artifacts keyed by `(LoweredIrFingerprint, pattern IrId)`.

These are the same object at different granularities and with different
payload kinds. Each one is a **content-keyed record**: a key derived
from *what is being computed* (a stable fingerprint of lowered code) and
*what it can observe* (captured values, impure inputs), mapping to a
payload (a forced value, a `.drv` closure, a lowered-IR artifact, a
compiled body) that is legal to reuse exactly when the key still
describes the world. The unification thesis:

> **There is one memo abstraction — a content-keyed record store — and
> every cache in the evaluator is an instance of it at some granularity,
> holding some payload kind, resident in some tier.**

This is the concrete realization of the unified demand graph
([03](03-architecture-overview.md) §3.4, decisions C-19/C-20): if
lex/parse/resolve/compile/force are all node kinds in one graph, their
memo records belong in one keyspace with one revalidation contract, not
in four bespoke sidecar formats.

### 1.2 What exists today (grounding)

The abstraction is **not green-field**. The shipped code already
implements most of the record model at two granularities; the work is
unification and tiering, not invention:

| Mechanism | Granularity | Key today | Payload | Residency today |
| --- | --- | --- | --- | --- |
| Demand/force cache | per lowered node | `DemandCacheKey::for_free_vars(CacheExprIdentity{source_hash, node: IrId}, [ValueHash])` (`ratchet-oracle/src/cache/key.rs`, ordered length-prefixed combiner per decision C-1) | forced value payloads (`CachedExpressionPayloadValueHash`, derivation side records) | in-process maps + `nodes/` persist layer (`metadata.index`, `traces.log`) |
| Root cutoff | whole root (largest subtree) | blake3(domain ‖ format-v2 ‖ crate version ‖ entry realpath ‖ entry content ‖ attr ‖ `TreeWalkOptions::result_affecting_fingerprint()`) (`aos-nix/src/native/root_cutoff.rs`) | `RootInstantiationRecord` = root drv + closure blob refs + canonicalized input trace | `roots/instantiations.index` + `files/` pack, tag 6 |
| Parse cache | per source file | realpath + content hash (`ParseFileContentHash`); artifact carries post-remap `LoweredIrFingerprint` | lowered IR + symbol table + facts | `nodes/parse-artifacts.index` + packs |
| JIT body cache (approved, deferred) | per def-site | `(LoweredIrFingerprint, pattern IrId)` | lowering decision + serialized `JitClifArtifact` | new sidecar under `AOS_NIX_CACHE` (design) |

Shared machinery already in place: the hash-domain type system
(`cache/hashing.rs` — hot xxh3 never crosses into durable addresses),
the `LatestIndex` append-only sidecar index with tail-reload
(`ratchet-cache/src/sidecar_index.rs`), content-addressed `values/` and
`files/` packs with `ensure_blob_indexed` CAS dedup, and the
canonicalized impure-input trace (§2.3).

**FV-5 status boundary (2026-07-09).** Hybrid closure capture changes the
runtime representation, not this memo contract. `facts.bin` analysis version
5 now persists an ordered per-site `CapturePlan` and constant
`FlatCaptureAccess` indices; serial closures with at most two free values keep
those words in their flat object, while conservative/shared sites retain one
persistent-frame-chain head. Existing force-cache key construction still
observes the same ordered lexical coordinates and produces the same
`DemandCacheKey` bytes — the cold/warm shadow gate is byte-clean. This does
*not* make arbitrary closures durably hashable, does not implement recursive
thunk keys, and does not close any MEMO-1/MEMO-2 acceptance item by itself;
those rows remain governed by §10. It does remove frame-array-copy cost from
the future per-subtree slice path and gives the closure-hashcons extension in
[30](30-flat-value-architecture.md) a bounded canonical capture vector.

### 1.3 What unification adds

Three things the four instances do **not** share today, and should:

1. **One key-derivation module.** Root cutoff hashes raw entry bytes
   and options; the force cache combines expression identity with value
   hashes; the JIT design keys on `(LoweredIrFingerprint, IrId)`. §3
   defines a single composite-key grammar all four reduce to, so a
   record written by one mechanism is addressable by the others (e.g. a
   root record is a force-cache record whose node is the root and whose
   payload kind is a drv closure).
2. **One record envelope.** Every record carries the same validity
   metadata — impure-observation slice, options identity, format
   versions — regardless of payload kind (§2). Today the root record
   carries a trace, node records carry trace-log references, and the
   parse cache relies on content-keying alone; the envelope makes the
   revalidation contract uniform and lets CHECK mode be implemented
   once.
3. **Tiered placement** (§5). Today residency is binary: an in-process
   map or the single `AOS_NIX_CACHE` directory. The unified store
   places records in L0 (in-thread), L1 (in-process shared), L2 (disk,
   multiple locations with latency classes), or L3 (network) by a
   tunable economics heuristic, with promotion on repeat hits and
   demotion under size pressure.

---

## 2. The record

### 2.1 Record anatomy

```text
MemoRecord
├── key                  : MemoKey                     (§3; content-derived, never positional)
├── payload
│   ├── kind             : Value | RootClosure | FrontEndArtifact | CompiledBody
│   └── body             : tier-dependent representation (§6)
│         memory tiers   : Value handle(s) into the eval heap (may reference thunks)
│         disk/network   : canonical serialized bytes in a content-addressed pack
├── impure_slice         : [CacheableInputFingerprint]  (§2.3; canonicalized, order-independent)
├── validity
│   ├── options_identity : result-affecting options fingerprint (store_dir, nix_path,
│   │                      search-path bases, corepkgs, home, eval mode, pinned currentTime, ...)
│   ├── format_version   : per-payload-kind format constant + crate version salt
│   └── complete         : bool — record was written from a complete observation trace
└── stats
    ├── est_recompute    : static cost estimate units (§5.7)
    ├── entry_bytes      : serialized size (disk tiers) / retained bytes (memory tiers)
    └── hits, last_hit   : promotion/demotion inputs (per-tier, not persisted across format bumps)
```

A **hit** is legal iff: the key matches by content, the options identity
matches, the format versions match, and every entry in `impure_slice`
revalidates (§7.3). Everything else — which tier answered, how the
payload is represented — is a performance detail that must not be
observable in eval output.

### 2.2 Payload kinds: the existing features as instances

- **`Value`** — a fully or partially forced result. In memory tiers the
  body is a heap `Value` handle; on disk it is the canonical value
  serialization already used by the `values/` pack. This is the force
  cache's payload today.
- **`RootClosure`** — the largest-subtree case: the root `.drv` path
  plus the closure as `(path, files-blob-hash)` pairs. This is
  `RootInstantiationRecord` verbatim; root cutoff becomes "a memo hit
  on the root node whose payload kind is `RootClosure`".
- **`FrontEndArtifact`** — lowered IR + symbols + facts. The parse
  cache becomes the front-end instance; its key is the degenerate case
  where the "environment" component is empty and the code component is
  the file content itself.
- **`CompiledBody`** — the deferred JIT artifact: the lowering decision
  plus a serializable `JitClifArtifact`, recompiled into the batched
  `JitModuleContext` on load (never relocated code pages). Same
  keyspace, different payload kind; its records never carry an impure
  slice because a compiled body is a pure function of IR shape.

### 2.3 The impure-observation slice

Every record that can observe the world carries its **per-subtree slice
of impure observations**: the same `CacheableInputFingerprint` contract
root cutoff enforces per-root, applied at record granularity. The
fingerprints cover `Import`, `ReadFile`, `HashFile`, `ReadDir`,
`ReadFileType`, `PathExists` (including `FindFileCandidate` mode for
search-path probes), and `GetEnv`, each as `(identity, observation
blake3)` (`ratchet-oracle/src/eval/tree_walk/eval_impure_inputs.rs`).

Since commit `51d504800` the trace is **canonicalized at the record
boundary**: stable-sorted by kind/mode/subject/hash, exact duplicates
collapsed, and a trace that observed the same identity with two
different results (a file changed mid-eval) **refuses to record** — such
a record could never revalidate and, under parallel evaluation
([13](13-parallel-evaluation.md)), force order is nondeterministic, so
order-independence is a correctness requirement, not a nicety. Two
completeness rules:

- **Incomplete latches.** If any observation could not be captured
  (allocation failure, disallowed path, symlink resolution failure,
  unpinned `currentTime` or any uncacheable impure input per the keying
  table in [21](21-builtins-conformance.md)), the trace latches
  incomplete and the subtree is **never recorded** at any tier. Root
  cutoff already enforces this (`impure_input_trace_complete()`); the
  unified store inherits it per record.
- **Attribution is new machinery.** Today the evaluator accumulates one
  trace per eval; the root record snapshots all of it. Per-subtree
  slices require attributing each observation to the records being
  written while it was observed (a stack of open record scopes, each
  collecting the observations forced beneath it, with child slices
  folded into parents). This is the largest new correctness surface in
  MEMO-1 and gets its own CHECK leverage (§7.1). The force cache's
  existing per-node pure/impure observation identities
  (`ForceCacheSubject`) are the seed of this, but slice capture for
  arbitrary admitted subtrees does not exist yet.

### 2.4 Validity context

The root-cutoff key already folds in
`TreeWalkOptions::result_affecting_fingerprint()` — including
`nix_path`/search-path bases, store dir, home, corepkgs — because a
search-path config change can redirect a lookup to a *different file*,
which replaying recorded per-path observations would not catch. It
excludes `env_vars` because `getEnv` observations live in the trace and
revalidate per-name. The unified record adopts exactly this split:
**config that redirects resolution goes in the validity context; config
that is observed goes in the slice.** The force cache's
`ForceCacheOptionsIdentity` (per-module options identity including
pinned `currentTime` and eval mode) is the same idea and folds into the
same envelope field.

---

## 3. Key derivation

### 3.1 The code component: post-remap fingerprints, never raw node hashes

The stable identity of "what code is this" is the pair:

```text
code_id = (file_fp : LoweredIrFingerprint, node : IrId)
```

`LoweredIrFingerprint` is the **per-file, post-symbol-remap** blake3
fingerprint the parse cache already computes and persists
(`ratchet-oracle/src/cache/parse/mod.rs`: blake3 over a domain constant,
the parse-cache schema version, the encoded lowered IR bytes, and the
encoded symbol table). It is stable across evals because the encoded
IR + symbol table are serialized in the artifact's own namespace.

Raw in-heap node hashes are **not** usable as durable keys: they embed
global `Symbol` ids, which are assigned in eval order (import order,
force order) and differ across runs — the same instability class that
produced the foldl lazy-accumulator regression. The `IrId` node
discriminator *within* a fingerprinted artifact is stable because it is
part of the serialized artifact itself. This is the identical keying
resolution the compiled-body cache design reached, and it is already
what the force cache's `CacheExprIdentity { source_hash:
CacheExprSourceHash, node: IrId }` encodes. Keying is solved by data
the parse cache already writes; no new front-end work.

### 3.2 The environment component: ordered per-slot value hashes

The environment component fingerprints *what the subtree can see*: the
values captured in the slots the node's body actually references (its
free variables in scope-resolved form, [25](25-intermediate-representation.md)).

Two corrections to the approved thesis, both grounded in shipped code
and both flagged in §13:

1. **Not a fold — an ordered, length-prefixed combiner.** Decision C-1
   ([12](12-incremental-evaluation-cache.md) §3.2) rejected
   order/multiplicity-blind combining (XOR/fold) precisely because it
   conflates distinct environments. `DemandCacheKey::for_free_vars`
   already implements the correct form: canonical slot order, each
   `ValueHash` length-prefixed, hashed once into a hot xxh3 probe plus
   a blake3 confirmation digest. The unified key keeps this.
2. **Value hashes are not a free byproduct of hash-consing.** The
   hash-cons tables ([05](05-value-representation.md)) key on
   `HotXxh3Hash` structural hashes — per-eval, non-durable, explicitly
   fenced from durable use by the type system in `cache/hashing.rs`.
   The durable per-value hash is `ValueHash` =
   blake3(canonical(value)) (`cache/cutoff.rs`), computed on demand
   with per-tag domain constants (int/float/bool/null, context-free and
   context strings, paths, lists, attrsets, derivation ATerm) and
   **memoized per heap record** in the cold value-hash side table
   (`heap/record_table.rs::{cold_value_hash, set_cold_value_hash}`;
   `SharedHeapBackend::cold_value_hashes` in shared mode). What
   hash-consing buys is that the memoization is effective — shared
   substructure is hashed once — not that the hash pre-exists.

**The thunk rule.** `ValueHash::from_inline_value` rejects heap tags,
and thunks are never hashed (S-15/C-15: hashing an unforced thunk by
its future value is unsound; forcing it to hash it defeats laziness).
A candidate subtree whose free variables include an unforced thunk has
two sound options:

- **Decline admission** (today's behavior — the force cache admits
  subjects whose free variables are inline-hashable or closed
  composites, `ForceCacheMemoizationAdmission`); or
- **Key the thunk by its own memo key**: a captured unforced thunk is
  itself `(code_id, env)` — recursively derivable without forcing.
  This is the Adapton-style extension that widens admission to
  thunk-capturing subtrees, at the cost of key derivation recursing
  through the captured environment graph. It is sound (two thunks with
  equal recursive keys denote the same computation in the same world)
  but its cost must obey the same economics gate as everything else
  (§5.7). MEMO-1 ships with declined admission; recursive thunk keying
  is a measured follow-up.

### 3.3 Key derivation pseudocode

```rust
/// Composite memo key. `hot` accelerates probes; `confirmation` is the
/// authority (and the only component durable tiers may store).
struct MemoKey {
    hot: DemandKeyHotHash,                 // xxh3, in-process only
    confirmation: DemandKeyConfirmationHash, // blake3, durable
}

fn memo_key(node: NodeRef, env: &EvalEnv, opts: &ValidityContext) -> Option<MemoKey> {
    // 1. Code component: stable across evals (post-remap artifact fp + node id).
    let code_id = CacheExprIdentity::new(
        CacheExprSourceHash::from(module_lowered_ir_fingerprint(node.module)),
        node.ir_id,
    );

    // 2. Environment component: ordered per-slot durable value hashes.
    let mut env_hashes = Vec::new();
    for slot in free_variable_slots(node) {          // canonical slot order (C-1)
        let value = env.slot(slot);
        match durable_value_hash(value)? {           // cold side-table memoized
            Hashed(h) => env_hashes.push(h),
            UnforcedThunk => return None,            // MEMO-1: decline admission
            // Follow-up: UnforcedThunk => push memo_key(thunk.code, thunk.env)?
        }
    }

    // 3. Combine: domain ‖ format version ‖ code_id ‖ len-prefixed hashes ‖
    //    validity-context fingerprint. Hot xxh3 + blake3 confirmation over
    //    the identical byte stream.
    Some(DemandCacheKey::for_free_vars_with_context(code_id, env_hashes, opts.fingerprint()))
}
```

Special cases reduce onto this: the root-cutoff key is `memo_key` where
the "node" is the entry expression (whose code component degenerates to
realpath + content bytes, since the entry file is read directly rather
than through the fingerprinted import path), the environment is empty,
and the validity context is `result_affecting_fingerprint()`. The parse
cache is the key with an empty environment and the file content as the
code component. The compiled-body key is the code component alone.

### 3.4 Hash domains per tier

The hashing split (S-15, [12](12-incremental-evaluation-cache.md) §5) is
unchanged and load-bearing: **xxh3** for L0/L1 probes (never persisted,
never authoritative), **blake3** for record confirmation and all L2/L3
addresses, **SHA-256** only where Nix observes hashes. The existing
typed-hash fence in `cache/hashing.rs` is what makes a four-tier store
safe to build without a hot hash leaking into a durable address; the
unified store adds no new hash algorithms and no new domains beyond one
domain constant per new record kind.

---

## 4. Implied refactors

Declaring the unification is cheap; these are the concrete convergence
tasks it implies:

1. **Shared key derivation** — one module (today: `cache/key.rs`) owns
   the composite grammar of §3.3; `native/root_cutoff.rs` key assembly
   and the compiled-body design re-express their keys through it. Key
   format changes become one version bump site.
2. **Shared record envelope** — `RootInstantiationRecord` and the
   node-trace payloads already share the `PersistNodeTracePayload`
   codec for slices; the envelope (§2.1) extends this so validity
   context and completeness are uniform fields rather than per-format
   conventions.
3. **Shared sidecar plumbing in `ratchet-cache`** — the `LatestIndex`
   tail-reload index, tag allocation, `.locks/` discipline, blob-pack
   CAS, and the reaper are already shared; what is missing is (a) a
   registry of record kinds → tags → payload codecs so new kinds stop
   hand-rolling index formats, and (b) blob-liveness integration —
   the known root-record caveat where `maintain_storage` can trim
   `files/` blobs referenced by root records (miss + safe fallthrough
   today) becomes a general requirement: **every record kind must
   enumerate its blob references to the reaper.**
4. **Per-subtree slice capture** (§2.3) — the observation-attribution
   stack in the tree walk; the only piece with eval-loop footprint.
5. **Multi-location disk layout** (§5.4) — the persist cache learns to
   open an ordered list of roots instead of exactly one.

---

## 5. Tiers

### 5.1 Architecture

```text
                        force(node, env)
                              │
                    ┌─────────▼──────────┐   miss
                    │ admission gate      │──────────────► evaluate
                    │ (est_recompute ≥    │                    │
                    │  min-cost knob)     │                    │ record (if slice
                    └─────────┬──────────┘                    │  complete + eligible)
                              │ admitted                       ▼
   ┌──────────────────────────▼──────────────────────────────────────────┐
   │  L0  in-thread map            plain HashMap, no sync                │
   │      key: MemoKey.hot         payload: Value handles                │
   ├──────────────────────────────────────────────────────────────────────┤
   │  L1  in-process shared        sharded map over the L2-parallel      │
   │      cross-worker reuse       shared-heap substrate (§5.3)          │
   │      key: MemoKey             payload: published Value handles      │
   ├──────────────────────────────────────────────────────────────────────┤
   │  L2  disk (AOS_NIX_CACHE)     LatestIndex sidecars + blob packs     │
   │      location classes:        [nvme:...][ssd:...][hdd:...]          │
   │      key: confirmation blake3 payload: canonical serialized bytes   │
   ├──────────────────────────────────────────────────────────────────────┤
   │  L3  network                  registry / redis-class, advisory,     │
   │      largest + most stable    validation-not-authority (§11)        │
   │      key: confirmation blake3 payload: canonical serialized bytes   │
   └──────────────────────────────────────────────────────────────────────┘
        ▲ promotion: repeat hits at tier N publish to tier N-1 residency
        ▼ demotion: size pressure evicts memory tiers; disk demotes
          nvme→hdd by (entry_bytes / hit rate); L3 is publish-only
          from CI/trusted writers
```

Lookup descends L0→L3 and stops at the first legal hit; a hit at tier N
optionally installs the record at tiers above it (promotion). Recording
ascends: a newly evaluated eligible subtree records at the tier its
economics select (§5.7), not at every tier.

### 5.2 L0 — in-thread

A plain per-worker `HashMap<MemoKey, Value>` probed by `hot` and
confirmed by `confirmation`. No synchronization, no serialization; the
payload is a heap handle in the worker's own arena/shard. L0 exists
because under parallel evaluation L1 probes pay shard/atomic costs and
under serial evaluation L1 is pure overhead. Bounded by entry count;
cleared per eval (L0 never outlives the heap its handles point into).

### 5.3 L1 — in-process shared

The cross-worker tier, and deliberately **the same substrate as L2
parallel evaluation** (P1–P3a landings: `SharedHeapArena` per-worker
shards, append-only `OnceLock` chunks, stable-slot-address handles,
Release/Acquire publication, cross-shard resolve). Facts that shape it:

- A worker may reference a `Value` allocated by another worker's shard
  iff the slot was **published** (Acquire-visible); `SharedHeapBackend`
  resolution already does exactly this. So an L1 memo payload can be a
  handle into whichever shard evaluated it first — no copying.
- Hash-consing is per-worker in shared mode (dedup loss accepted;
  pointer-equality falls through to content comparison), so **the L1
  memo table is what restores cross-worker dedup**, at memo granularity
  instead of per-allocation granularity.
- There is **no existing shared writable map** in the parallel design —
  it is deliberately append-only chunks plus insert-only per-shard
  indexes. The L1 memo table is the first shared mutation surface, and
  must be built as a sharded map with the same discipline (publish via
  Release, probe via Acquire; never a global lock on the force path).
- **A memo hit and a claim-protocol foreign-forced thunk are the same
  event.** The thunk CAS protocol
  (`Suspended → Pending{owner} → Awaited{owner} → Forced/Failed`, with
  `ParallelForceCycleRegistry` publish-purge linearization) already
  gives every parallel force a "someone else computed this; adopt their
  published result" path — keyed by thunk *address*. L1 memoization is
  the same adoption keyed by *content*: where the claim protocol
  collapses two forces of one thunk, the memo collapses two forces of
  two distinct thunks with identical `(code, env)` keys. Concretely: on
  L1 hit, install the published value into the local thunk cell through
  the same terminal-publication path a foreign force uses, so cycle
  bookkeeping, error propagation (`Failed` payloads), and stats see one
  mechanism. An in-flight L1 entry (claimed, not yet forced) may
  optionally park arrivals exactly like an `Awaited` thunk — that
  single extension turns the memo table into a cross-worker
  computation-deduplicator, not just a result cache.

### 5.4 L2 — disk, multiple locations with latency classes

Today `AOS_NIX_CACHE` names exactly one root. L2 generalizes to an
**ordered list of locations, each with a latency class**:

```text
AOS_NIX_CACHE=/fast/aos-nix-cache                      # primary (class nvme, default)
AOS_NIX_MEMO_DISK=hdd:/bulk/aos-nix-cache-cold        # secondary, colder class
```

Each location is a full persist-cache layout (schema, `.locks/`,
sidecar indexes, packs) — the existing `LatestIndex` + pack machinery,
instantiated N times, not a new format. Reads probe in order; writes
target the class selected by economics (small hot records → nvme; large
cold records — full root closures, bulk value payloads — may be written
directly to a colder class). Demotion moves records between locations
by `(entry_bytes, hit recency)`; promotion copies upward on repeat
hits. The primary keeps its current role (root cutoff and the force
cache activate when it is set, and it stays byte-compatible with the
existing layout); secondaries are additive and safe to lose — the cache
is advisory end to end (C-13's relaxed-sync stance extends to whole
locations).

### 5.5 L3 — network

A registry/redis-class remote holding only the **largest, most stable**
records: root closures and whole-package value/drv subtrees whose keys
are dominated by source fingerprints (stable across machines) rather
than machine-local paths. Requirements that fall out of the correctness
regime rather than being optional hardening:

- **Content-addressed fetch by confirmation hash**; the fetched bytes
  re-hash to the key before use (self-validating, same property the
  `files/` pack relies on).
- **The remote is a validation-shaped catalog, never an authority** —
  the RFC-0006 principle (the registry is a validation catalog, never a
  signer) applied to eval caching: an L3 hit never bypasses slice
  revalidation, options-identity matching, or (when enabled) CHECK
  mode. A poisoned or stale remote can cause misses and wasted fetches,
  never wrong output, because a record whose payload disagrees with its
  own key fails the re-hash and a record whose slice does not
  revalidate is ignored (§11 for the residual risks).
- **Machine-relative validity**: records whose validity context or
  slice embeds absolute local paths (store dir differences, home-dir
  observations) simply miss on foreign machines — correct by
  construction, but it bounds what is worth publishing. The publishable
  sweet spot is the same corpus the JIT measurements identified: the
  shared-library scaffolding evaluated identically by every package and
  every machine with the same source tree.
- **Write policy**: publish-only from CI/trusted builders
  (`AOS_NIX_MEMO_NET_MODE=ro` default); interactive evals read.

### 5.6 Tier state machine

Per record (residency is a set of tiers, not a single position; the
state machine governs transitions):

```text
                 evaluate + eligible + slice complete
                                │
                                ▼
                     ┌─── record at tier T ───┐      T chosen by placement
                     │      (RESIDENT@T)      │      heuristic (§5.7)
                     └───────────┬────────────┘
             hit at T            │                      size pressure /
        ┌────────────────────────┤                      reaper / format bump
        ▼                        │                            │
  hits@T ≥ promote-threshold     │                            ▼
        │                        │                    ┌───────────────┐
        ▼                        │                    │ DEMOTED@T+1   │  (memory→gone;
  ┌───────────────┐              │                    │ or EVICTED    │   nvme→hdd;
  │ ALSO-RESIDENT │              │                    └───────┬───────┘   disk→gone)
  │     @T-1      │              │                            │ hit again
  └───────────────┘              │                            ▼
        (promotion copies; lower tier remains          re-promote per
         the durable home for serializable kinds)      heuristic
```

Invariant: transitions never affect legality — a record is equally
valid at any tier; tiers only trade lookup latency against capacity.
Memory-tier eviction is silent (recompute); disk demotion is a move;
L3 never demotes (remote retention is the remote's policy).

### 5.7 Placement economics

The placement heuristic scores `est_recompute / entry_bytes` — recompute
cost bought per byte held:

- **`est_recompute`**: there is **no per-node timing today** —
  `EvalStats` (`AOS_NIX_EVAL_STATS=1`) carries aggregate counters
  (thunks forced, force-cache hits/misses/admits, materialization
  decisions) but no per-force clocks, and adding always-on clocks to
  the force path is exactly the per-force hook tax the JIT rounds
  measured at 1.5–2.8 ms per eval. So `est_recompute` is a **static
  estimate** in the `Tier1BodyCost`/`native_insts` mold (`ratchet-jit`
  cost model): a lowered-IR walk summing per-node-kind unit costs,
  computed once per def-site at parse-artifact build time and stored in
  facts — plus optional *sampled* wall-time refinement gated behind
  `AOS_NIX_MEMO_STATS`, never on the default force path.
- **`entry_bytes`**: exact for serialized payloads; retained-size
  estimate (the existing `payload_size_estimate`) for memory tiers.
- **Admission floor**: no record below `AOS_NIX_MEMO_MIN_COST`
  regardless of tier (§8 — the decisive JIT lesson).
- **Tier selection**: memory tiers take anything admitted (they hold
  handles, cost ≈ a map entry); disk tiers additionally require the
  C-14 materialization rule (`eval_cost > hash + serialize + IO`, and
  re-demanded — the existing
  `force_cache_materialization_{materializes,keeps_in_memory}` decision
  generalized per location class); L3 additionally requires stability
  (no machine-local paths) and size dominance (closure-sized records).

---

## 6. Serializability and eligibility

Residency is constrained by payload representation:

| Tier | May hold | Constraint |
| --- | --- | --- |
| L0/L1 | any `Value` handle, including values that transitively reference unforced thunks or closures | handles die with the eval heap; L1 handles must be published shard slots |
| L2/L3 | only **fully-forced, closure-free** canonical serializations | must round-trip through the canonical value codec with byte-stable output |

**Eligibility classification** for disk/network, decided at record time
by a payload walk (memoized on the heap record alongside the cold value
hash so repeated classification is O(1)):

- *Eligible*: scalars; context-free and context-bearing strings (with
  canonical context serialization); paths; lists/attrsets whose
  elements are transitively eligible and forced. This covers exactly
  the payloads that matter at coarse granularity — drv attrsets,
  realized config trees, string/path closures — which is why "big
  subtrees" and "serializable subtrees" coincide in practice.
- *Ineligible*: anything transitively containing an unforced thunk
  (forcing it to serialize would change demand — unsound laziness-wise
  and a semantic risk if forcing throws where the program never
  demanded it), a lambda/closure or primop-partial (no canonical
  serialization; environments capture arbitrary graphs), or a value
  whose canonical form is not yet specified by the codec. Ineligible
  records live in memory tiers only — that is a *feature* of the
  tiering, not a failure: L0/L1 are precisely the tiers where
  closure-bearing mid-size subtrees can still be memoized.

Deep-forcing a *root* payload is legal at the root boundary (a `.drv`
closure is fully demanded by definition — root cutoff already exploits
this); the rule above is about never *introducing* forcing to make an
interior record eligible.

---

## 7. Correctness regime

### 7.1 CHECK mode per tier

`AOS_NIX_ROOT_CUTOFF_CHECK=1` set the pattern: take the hit, *also*
re-evaluate, assert byte-identical results, and fail loudly on
divergence. The unified store generalizes this to
`AOS_NIX_MEMO_CHECK=<tier list>`: every hit at a checked tier is
shadowed by a real evaluation and compared — value payloads by
canonical bytes (or deep structural equality for memory-tier
closure-bearing payloads), root closures byte-for-byte, compiled bodies
by output equivalence (the existing JIT differential). CHECK is the
primary weapon against the two novel risk surfaces: per-subtree slice
attribution (§2.3) and environment-key admission (§3.2) — a
wrongly-scoped slice or an over-eager admission shows up as a CHECK
divergence on the first corpus run, not as a wrong `.drv` in CI.

### 7.2 Byte-parity gate supremacy

The differential harness ([15](15-differential-testing-and-benchmarking.md))
outranks everything: the x4 package byte-parity gate (and on Linux, the
full-corpus `.drv` gate) must be green with the memo store off, on,
CHECK-on, and in parallel mode, before any phase ships. A memo tier
that wins benchmarks and loses parity does not exist.

### 7.3 Slice revalidation and completeness

A hit revalidates its slice through the existing seam
(`revalidate_cacheable_input_trace(options, &[CacheableInputFingerprint])`)
— per-observation replay against the current world, comparing
observation hashes. All-or-nothing: any mismatch is a miss (no partial
reuse). Completeness rules are §2.3's: incomplete traces never record;
conflicting observations never record; `currentTime` and friends latch
incomplete unless pinned into the options identity. The canonicalized
(order-independent) trace form is what makes one revalidation
implementation serve every granularity and both serial and parallel
recording.

### 7.4 Invalidation is content miss, never mtime

There is no invalidation walk and no timestamp anywhere in the design.
A changed source file produces a new `LoweredIrFingerprint` → every key
derived from it is simply never constructed again; a changed captured
value produces different `ValueHash`es → a different key; a changed
observed file fails slice revalidation. Stale records become
unreachable garbage for the reaper (the compiled-body design's
"invalidation: automatic" stance, generalized). Format evolution is the
same mechanism: bump the per-kind format constant and old records miss
safely (the `ROOT_CUTOFF_KEY_FORMAT_VERSION` 1→2 bump is the
precedent).

### 7.5 Parallel evaluation

Beyond §5.3's identification of memo-hit with foreign-force: recording
under parallelism relies on (a) canonicalized slices (P0 landed
precisely to make record bytes force-order-independent), (b)
per-worker slice capture merging like `EvalStats::merge_from`, and (c)
publication ordering — a record must not become probe-visible before
its payload's shard slots are published (payload Release-publish
happens-before table insert; probe Acquire on the table entry).
Duplicate concurrent recording of the same key is benign (idempotent
content; first-publish-wins CAS, mirroring `ensure_blob_indexed`).

### 7.6 GC interaction

Memory-tier payloads are heap handles. In shared/parallel mode GC is
quiesced, so L1 handles are stable for the eval's lifetime. In serial
mode the minor GC forwards records (`minor_gc_forwarding`); the L0
table must either register as a GC root set (keeping memoized subtrees
alive — which is also what makes repeat hits possible) or be swept for
forwarded/dead entries at collection points. Registering as a root is
the simple, correct default; its retention cost is exactly the memory
growth accounted in §11 and bounded by the L0/L1 budgets.

---

## 8. Cold-eval content memoization

The in-memory tiers are not only a warm-eval feature: they are a
**cold-eval optimization**, and this is the genuinely new performance
thesis (the disk tiers mostly re-house wins that exist today).

**The opportunity.** A single cold eval of one package set evaluates
distinct-but-content-identical subtrees repeatedly: the same library
lambdas applied to the same argument values through different import
instances, the same `mkDerivation` scaffolding attrsets, the same
stdenv fragments. Today hash-consing dedups the *allocations* after
the fact, and the claim protocol dedups forces of *one* thunk — but two
distinct thunk allocations with identical `(code, env)` both evaluate.
With stable code fingerprints and environment value hashes, the memo
collapses the second evaluation into a hit.

**Measured basis (honest extrapolation).** The JIT sizing rounds
measured the *code-level* duplication directly: ~889 per-module-instance
lambda def-sites in one zlib eval collapse to ~375 source-keyed
def-sites — **~2.4x intra-eval duplication of lambda identity within a
single cold eval**, and 296 of 375 sites shared across all five
measured packages (99–100% cross-eval overlap). Code duplication is the
*precondition* for value-level duplication, not proof of it: two
instances of the same def-site memo-hit only when their captured
environments also hash equal. How much of the 2.4x survives the
environment component is **unmeasured and is the first thing MEMO-1
must measure** (a counting instrumentation run — potential hits =
admitted keys seen ≥ 2 — before any table is built). The library-
scaffolding evidence (top hot bodies bit-identical across packages,
same lib attrsets flowing through them) suggests a real mass; the
honest statement is that the ceiling is bounded by eval-time share of
duplicated subtrees, and per-eval JIT arithmetic (hot sites = 74% of
calls but 24% of body time) warns that duplicated ≠ expensive.

**The cost side (the decisive JIT lesson).** The tier-1 rounds proved,
by construction, that a per-force fixed cost dominates small bodies:
the ~3 µs dispatch harness made every tiny-body promotion net-negative
(one-op bodies save less than the harness costs), and even the ~1.5–2.8
ms per-eval hook tax of *probing on every force* was measurable against
a ~110 ms eval. The memo probe is subject to the identical arithmetic,
with hashing on top: an L0 probe is a hash + map lookup (sub-µs), an L1
probe adds shard/atomic traffic, and *key derivation* adds per-slot
value-hash lookups (cold side-table hit) or computations (blake3 over
canonical bytes — potentially large for big captured values, though
paid once per value, then memoized). Consequences, stated as design
rules:

1. **Never probe on the bare force path.** Admission is decided per
   def-site (static cost estimate ≥ `AOS_NIX_MEMO_MIN_COST`), marked on
   the lowered node at parse-artifact time, so non-admitted forces pay
   zero — the same shape as the has-tier1-slot flag proposed to kill
   the JIT hook tax. A memo that probes every force re-creates the
   hook tax and loses before it begins.
2. **Gate by minimum estimated subtree cost.** Sub-µs subtrees are
   unmemoizable at any tier by arithmetic, exactly as sub-µs bodies
   were unJITable. The floor is a knob, but its existence is not.
3. **Hash once, reuse everywhere.** The cold value-hash side table is
   the load-bearing amortizer: env-component derivation must be lookups
   dominated, not blake3-dominated, or the key costs more than an L0
   hit saves. `AOS_NIX_MEMO_STATS` must decompose probe/key/hit/record
   time so a regression here is visible as a number, not a vibe.

**Expected shape of the win.** Given the floor, L0/L1 hits concentrate
in mid-size subtrees (config-tree fragments, attrset scaffolding,
library-function applications over shared values) — individually
10s–100s of µs, collectively meaningful only if the duplicated mass
measurement (above) says so. This phase is explicitly
**measure-gated** (M-11's granularity question, answered empirically):
if potential-hit mass times mean subtree cost does not clear the
instrumentation-measured probe+key tax with margin, MEMO-1 ships as
counters-only and the effort moves to the disk unification, which does
not depend on intra-eval duplication.

---

## 9. Knobs

Existing knobs (unchanged semantics, listed for the composed picture):

| Knob | Default | Meaning |
| --- | --- | --- |
| `AOS_NIX_CACHE` | unset (all durable caching off) | primary persist-cache root; enables parse cache, force-cache persist layer, root cutoff |
| `AOS_NIX_CACHE_VERIFY` | `0` | defensive pack verification on read |
| `AOS_NIX_ROOT_CUTOFF` | `1` when `AOS_NIX_CACHE` set | root-record cutoff kill switch |
| `AOS_NIX_ROOT_CUTOFF_CHECK` | `0` | shadow re-eval + byte-identical assert on every taken cutoff |
| `AOS_NIX_EVAL_STATS` | `0` | JSON counters to stderr |
| `AOS_NIX_PARALLEL` | off | worker count for shared-graph forcing (JIT refused when set) |

New knobs (defaults are initial values, measure-gated like every other
constant in this RFC):

| Knob | Default | Meaning |
| --- | --- | --- |
| `AOS_NIX_MEMO` | `1` | master switch for the unified memo store (subsumes, does not replace, the switches above during migration) |
| `AOS_NIX_MEMO_L0` | `1` | in-thread tier |
| `AOS_NIX_MEMO_L1` | `1` when `AOS_NIX_PARALLEL` set, else `0` | in-process shared tier (pointless serial; L0 covers it) |
| `AOS_NIX_MEMO_L2` | `1` when `AOS_NIX_CACHE` set | disk tier(s) |
| `AOS_NIX_MEMO_L3` | `0` | network tier |
| `AOS_NIX_MEMO_CHECK` | unset | comma list of tiers to shadow-check (`l0,l1,l2,l3` or `all`); every hit re-evaluated + byte/structurally asserted |
| `AOS_NIX_MEMO_MIN_COST` | `64` estimate units | admission floor on static recompute estimate (§5.7, §8) |
| `AOS_NIX_MEMO_L0_ENTRIES` | `65536` | per-worker L0 entry cap (evict LRU-ish, silent) |
| `AOS_NIX_MEMO_L1_BYTES` | `256MiB` | L1 retained-bytes budget (counts against `AOS_NIX_MAX_RSS` accounting) |
| `AOS_NIX_MEMO_DISK` | unset | secondary disk locations: `class:path[,class:path...]`, classes `nvme`/`ssd`/`hdd`; primary `AOS_NIX_CACHE` is implicitly class `nvme` |
| `AOS_NIX_MEMO_PROMOTE_HITS` | `2` | hits at tier N before also-installing at N-1 |
| `AOS_NIX_MEMO_NET` | unset | L3 endpoint URL |
| `AOS_NIX_MEMO_NET_MODE` | `ro` | `ro` (fetch only) / `rw` (CI/trusted publishers) |
| `AOS_NIX_MEMO_STATS` | `0` | probe/key/hit/record timing decomposition + potential-hit counters (adds sampled clocks; not for parity runs) |

Every boolean parses like the existing knobs (`0`/`false`/`off`/`no` =
off); invalid values disable the feature with a `tracing` warning,
never an error — the store is advisory.

---

## 10. Phasing and acceptance gates

### 10.1 MEMO-1 — in-process cold memo (L0/L1) + economics + CHECK

Scope: shared key derivation module (§3.3) expressed over the existing
`DemandCacheKey`/`CacheExprIdentity`; per-subtree slice attribution
(§2.3); static recompute estimates in parse facts; L0 table + admission
flags on lowered nodes; L1 sharded table integrated with the claim
protocol (parallel mode only); `AOS_NIX_MEMO_CHECK` for l0/l1;
`AOS_NIX_MEMO_STATS` decomposition, including the **potential-hit-mass
counting run before the tables are built** (§8).

Acceptance gates:

- Byte-parity x4 (zlib/openssl/coreutils/bash) green in **serial and
  parallel** modes, memo on, off, and CHECK-on; Linux full-corpus
  `.drv` gate before any default flips.
- CHECK-clean corpus runs (zero divergences) with `l0,l1` checked.
- **Perf non-regression serial**: memo-on cold eval within noise of
  memo-off on the 4-package bench (the admission-flag design makes
  "off for non-admitted forces" structural; this gate proves it).
- **Win demonstration**: measured cold-eval improvement on at least one
  real corpus attr, or an explicit counters-backed negative result and
  MEMO-1 ships counters-only (§8's exit ramp).

### 10.2 MEMO-2 — durable unification + tiers

Scope: record envelope (§2.1) adopted by root records and force-cache
persist records (format-version bump, old records miss safely); root
cutoff and parse cache re-expressed as instances (behavior-preserving —
same keys, same bytes on the primary location); blob-liveness
enumeration to the reaper (closes the known root-record trim caveat);
multi-location L2 with latency classes + promotion/demotion; L3
read-side with re-hash validation + `rw` publish from CI; compiled-body
records join the keyspace when the JIT profit-promotion round lands
(that design is approved separately and unchanged).

Acceptance gates:

- Byte-parity x4 serial + parallel across: primary-only, primary +
  secondary, secondary-lost (delete a location mid-corpus — must be
  miss-and-recompute, never error), L3-poisoned (corrupt remote record
  — must fail re-hash and miss).
- Root-cutoff behavior identical pre/post unification
  (`AOS_NIX_ROOT_CUTOFF_CHECK` clean; warm-instantiate latency within
  noise of the current 7.8–28 ms).
- Win demonstration on **repeat-heavy corpora**: warm re-eval of the
  package set and a CI-shaped run (many roots, shared closure) showing
  L2/L3 hit mass; L3 demonstrated across two machines with a shared
  source tree.

---

## 11. Risks

- **Hashing and probe overhead (the headline risk).** §8's arithmetic
  is the mitigation *policy*, but the measurement can still come back
  negative: if value-hash derivation for admitted environments is
  blake3-dominated (large captured attrsets hashed once but hit rarely)
  the key tax exceeds the hit mass. Mitigations: admission floor,
  hash-once side table, per-def-site (not per-force) admission, stats
  decomposition, and the counters-only exit ramp. Residual: accepted —
  this is what measure-gating means.
- **Memory growth.** L0/L1 tables are GC roots; memoized subtrees stop
  dying. A pathological corpus (huge distinct-but-admitted subtrees)
  converts the memo into a leak. Mitigations: entry/byte budgets with
  silent eviction, retained-size accounting against `AOS_NIX_MAX_RSS`,
  and the admission floor biasing toward small-key/large-win records.
- **Environment-hash instability across module instances.** The win in
  §8 assumes two instances of one def-site capture value-hash-equal
  environments. Real hazards: attrsets differing only in string
  *context* (context is in the canonical hash — correct, but it makes
  "looks identical" environments miss), positional salts
  (`AttrPositionSourceHash` exists precisely because position can be
  result-affecting), and floats hashed by IEEE bit pattern
  (over-conservative by design). These cause *misses*, never wrong
  hits — the risk is economic (hit mass evaporates), and the
  potential-hit counting run detects it before build-out.
- **Slice-attribution bugs.** A record whose slice under-captures its
  subtree's observations revalidates when it should not — a genuine
  wrong-output class. Mitigations: CHECK mode as the first-class
  development gate (§7.1), conflict-refusal and incompleteness latching
  inherited from the root-cutoff contract, all-or-nothing revalidation,
  and parity-gate supremacy as the backstop.
- **Network-tier consistency and poisoning.** L3 records are fetched
  bytes from a remote. Content-addressing (re-hash before use) makes
  substitution attacks equivalent to a miss; slice revalidation makes
  stale-world records inert; the RFC-0006 stance — the remote is a
  validation catalog, never an authority/signer — means no L3 record is
  ever trusted *because* the remote served it. Residual risks are
  availability-shaped (a hostile remote can serve misses or slow
  fetches — bounded by timeouts and `ro` default) and key-derivation
  bugs (a wrong key maps a valid payload to the wrong computation —
  covered by CHECK and the differential harness, and why L3 stays off
  by default until MEMO-2's poisoned-remote gate is green).
- **First shared writable map under parallelism.** L1 breaks the
  parallel design's "append-only or insert-only" purity; a sloppy
  implementation reintroduces the coordination costs P3a measured (+4.5%
  single-worker shared-backend tax) or deadlocks against the claim
  registry's lock order. Mitigation: sharded map, publish/probe
  ordering specified in §7.5, `loom` coverage like the thunk protocol,
  and L1 default-off outside parallel mode.

---

## 12. Non-goals

- **Replacing the demand-graph design of [12](12-incremental-evaluation-cache.md).**
  This document unifies and tiers its record layer; the three-layer
  trace model, early-cutoff decision (`cutoff.rs::decide`), and hashing
  policy stand.
- **Caching impure results beyond the slice contract.** Nothing here
  caches `currentTime`-tainted results, IFD build outputs, or
  fetcher network results; uncacheable inputs latch incompleteness
  exactly as today ([21](21-builtins-conformance.md) keying table).
- **A general-purpose distributed cache service.** L3 is a dumb
  content-addressed record catalog with a publish policy — not a
  coherence protocol, not a lease system, not Attic (RFC-0005/Attic
  integration for *store paths* is a separate, existing concern).
- **Cross-machine reuse of machine-relative records.** Records keyed by
  local absolute paths miss remotely by design; no path-rewriting layer.
- **Serialized machine code.** `CompiledBody` payloads are CLIF
  artifacts recompiled on load, per the approved compiled-body design;
  shipping finalized code pages stays out of scope.
- **Changing eval semantics or the parity contract.** No memo hit may
  be observable in `.drv` bytes, error classes, or trace output; the
  store is a pure performance layer with a kill switch at every level.

---

## 13. Divergences between the approved theses and the code

Recorded per the flag-don't-resolve rule; each was folded into the
design above with the code as ground truth:

1. **"Environment content hash is available because values are
   hash-consed" — not as stated.** Hash-cons tables key ephemeral
   `HotXxh3Hash` structural hashes, per-eval and type-fenced away from
   durable use. The durable `ValueHash` (blake3 canonical) exists but
   is computed on demand and memoized in the cold side table — and is
   defined only for forced, non-closure values; thunks are explicitly
   unsupported (S-15). Hash-consing amortizes the hashing; it does not
   provide it. §3.2 restates the thesis accordingly.
2. **"A fold over captured slot values" — rejected by C-1.** The
   shipped combiner is ordered and length-prefixed
   (`DemandCacheKey::for_free_vars`), and doc [12](12-incremental-evaluation-cache.md)
   §3.2 explicitly rules out order/multiplicity-blind folds. The design
   keeps per-slot ordered hashes.
3. **"The post-remap node IR fingerprint the parse cache already
   produces" — the parse cache produces a per-*file* fingerprint.**
   The per-node identity is the composite
   `(LoweredIrFingerprint, IrId)` — already how `CacheExprIdentity`
   and the compiled-body key are built. Substantively the thesis
   holds; the granularity attribution was imprecise.
4. **"Today's separate caches" undersells what exists.** A per-node,
   persist-backed force cache with admission
   (`ForceCacheMemoizationAdmission`), free-variable value-hash keying,
   options identity, and materialization economics counters is already
   live — the unified abstraction is one-quarter built and this
   document is partly *recognition*, not proposal. The genuinely new
   pieces: per-subtree slice attribution, the L0/L1 content tables,
   admission cost flags, multi-location L2, L3, and
   promotion/demotion.
5. **"Recompute cost from force-time stats — the `AOS_NIX_EVAL_STATS`
   machinery exists" — counters exist, per-node timing does not.**
   `EvalStats` is aggregate; per-force clocks would be a hook tax.
   §5.7 substitutes static estimates (the `ratchet-jit` cost-model
   precedent) plus sampled timing behind `AOS_NIX_MEMO_STATS`.
6. **"The memo table rides the L2-parallel shared structures" — with a
   caveat.** The parallel substrate is deliberately free of shared
   writable maps; the memo table is the *first*, and must import the
   claim/park discipline rather than inherit it for free (§5.3, §11).
7. **Root-record blobs and the reaper.** The existing `files/`-pack GC
   does not treat root-record blob references as live (miss + safe
   fallthrough today); the unified store makes blob-liveness
   enumeration a record-kind obligation (§4), which MEMO-2 must close
   rather than inherit.
