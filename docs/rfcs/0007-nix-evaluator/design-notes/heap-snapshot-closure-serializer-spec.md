# Heap-image snapshot: lambda/env serializer spec (doc 31 §1 step 3)

**Status: IMPLEMENTED. All five increments landed (increments 1-3:
74845a66b/95d2bdac8/f947a0d24, increment 4: 435bc4e87, acceptance-surfaced
restore fixes: ae2edfaca, increment 5 acceptance: 90763e2d6). The real forced
stdenv prelude captures with zero refused objects, restores into a fresh
mapping, and re-derives the stdenv `.drv` path byte-identical to a cold
evaluation. See the implementation-outcome section at the end for the probe
numbers, the three acceptance-surfaced bugs, and the recorded boundaries.**

Step 2 landed primop capture as builtin-registry references. Step 3 captures the
genuine closure residual the refusal census bounded: **980 lambdas + 1,667
suspended thunks (which live inside lambda envs) + the forced-thunk collapse
prefix**, ~444 KB total. This is the last blocker to snapshotting the real forced
lib+stdenv prelude.

## The two hard parts

A lambda is `EvalLambda { module: EvalModuleId, pattern: IrId, body: IrId,
frame: FrameId, env: EvalEnv, with_env, scoped_globals }`
(`eval/heap/mod.rs`). Two things do not survive a remap or the source heap's
drop:

1. **Code identity.** `module`/`pattern`/`body` reference the `TreeWalk` module
   table, which is not on the `EvalHeap`. The in-process module id is stable
   (shared table), but a durable/cross-process image must key code by content,
   not by a per-process index — otherwise a restored lambda silently binds to
   drifted IR, which is the `.drv`-divergence failure in a new costume.
2. **Captured environment.** `env`/`with_env`/`scoped_globals` are `Arc`-shared
   `EvalFrame` slot-array chains allocated outside the arena. They hold the
   evaluation state that forcing produced — it cannot be rebuilt without
   re-forcing (the thing the snapshot exists to skip), so it must be serialized.
   The 1,667 residual suspended thunks live in these frames; the env serializer
   subsumes them.

## Code-identity keying (the lead's up-front constraint)

Per the persistent-code-cache design, a code reference serializes as
`(module_source_fingerprint, IrId)`, **never** a raw `EvalModuleId`:

- `module_source_fingerprint` = the parse-cache source hash
  (`CacheExprSourceHash`, a content hash over `ModuleSource { name, bytes }`).
- Restore resolves the fingerprint back to a live `EvalModuleId` via a
  code-identity resolver and **refuses on mismatch** (no module with that
  fingerprint, or an ambiguous/drifted one). A lambda whose code fingerprint is
  absent is a hard `LambdaCodeDrift` refusal, not a silent rebind.

This requires extending the capture/restore API — the pattern primops set up — to
take a **code-identity context** the `EvalHeap` does not itself hold:

- Capture: `EvalModuleId -> CacheExprSourceHash` (fingerprint each referenced
  module's source).
- Restore: `CacheExprSourceHash -> Option<EvalModuleId>` (re-link, or refuse).

The context is supplied by the `TreeWalk` (which owns the module table) at the
capture/restore call site; the existing data-only `capture_heap_image` keeps
working (empty context) for heaps with no closures.

## Environment serialization

`EvalEnv` is a parent-linked chain of `Arc<EvalFrame>` slot arrays. Serialize as
an **index-keyed frame table**, generalizing the list-payload pattern to a shared
DAG:

- Dedup frames by `Arc` identity at capture (pointer-keyed), assigning each a
  dense frame id. The census shows 8,059 env-capturing closures over far fewer
  distinct frames — sharing is the whole point, so the table is much smaller than
  the closure count.
- Each frame payload = `parent_frame_id (or none) | slot_count | slot_value_word*`
  (`Value` words are address-free) `| with/scoped-global refs`.
- A closure's `env`/`with_env`/`scoped_globals` become frame-id references into
  the table. Restore rebuilds the `Arc<EvalFrame>` graph bottom-up (parents
  first) and re-shares.
- Slot values that reference suspended thunks are captured transitively: those
  thunks get their own code-ref + env, recursively. This is where the 1,667
  suspended thunks are handled.

## Forced-thunk collapse (mutating, lands here)

The read-only projection (step 1) confirmed the collapse is clean (0 chains, 0
unknowns, 89% to data). The **mutating** collapse — rewrite every `Value` word in
attrs entries, list elements, and env slots that points at a forced thunk to the
thunk's cached value — lands in this step as a capture-time pre-pass (off the
normal eval path). It is new arena-write `unsafe` (in `ratchet-value`, under the
heap-safety pin-map review protocol), and its byte-parity is verified on the
builder (the 4-package battery, both carriers) since it touches forced-thunk
representation adjacent to the eval path.

## Increment map

1. **Code-identity keying infra.** `CodeRef = (CacheExprSourceHash, IrId)`;
   extend capture/restore to take a code-identity context; a lambda's
   `module`+`pattern`+`body` round-trips as code refs with `LambdaCodeDrift`
   refuse-on-mismatch. First test: a single lambda's code refs survive
   capture/restore in-process (fingerprint matches) and a forged fingerprint
   refuses. **(This is increment 1 — build immediately after this spec.)**
2. **Env-frame graph serializer.** Dedup + serialize the `Arc<EvalFrame>` DAG as
   an index-keyed frame table; restore rebuilds and re-shares it.
3. **Lambda capture/restore.** Tie code ref + env + with_env + scoped_globals
   through `restore_payload`; capture stops refusing lambdas.
4. **Mutating forced-thunk collapse** pre-pass (pin-map `unsafe`, builder
   byte-parity); capture stops refusing forced thunks; suspended thunks captured
   via the env serializer.
5. **Acceptance.** The real forced lib+stdenv prelude captures and restores;
   re-census shows zero refused; a restored prelude image is byte-parity-equal to
   a fresh force on the builder.

## Stop conditions (honest gates)

- If increment 2's env serializer shows the distinct-frame count or retained mass
  is far larger than the census proxy implied (the `Arc<EvalFrame>` graph the
  census could not size), stop and re-evaluate — the ROI math changes.
- If the mutating collapse breaks byte-parity anywhere on the builder, stop and
  report; "defer, bank data-residual completeness" remains a live outcome.

## Symbols and cross-process images (in-process assumption, made explicit)

Every current segment reuses raw interned symbol ids on the assumption that the
symbol table is shared in-process (stage 1): attrset entry keys are `Symbol`s,
step 2's primop payloads reused the symbol id directly, and a lambda's captured
env references symbols through its `with`-scopes and scoped globals. In-process
restore is correct because the id space is identical. A **cross-process / durable
(L3) image is not** — the loader's symbol table assigns different ids, so raw ids
would silently rebind keys and scopes.

Making an image portable therefore needs a **serialized symbol-name table plus a
re-intern pass** applied across *all* segments (attrs keys, primop symbols, lambda
env scopes), keyed the same content-first way as code identity. That is a distinct
workstream from step 3 and is **out of scope here**, but it is recorded so the
in-process assumption is a deliberate, documented boundary rather than a latent
correctness gap: step 3 keeps reusing symbol ids in-process and does not close the
cross-process symbol hole. The `LambdaCodeDrift`/registry refuse-on-mismatch guards
protect *code* identity; symbol identity across processes is the parallel
unclosed axis.

## Wire format

Grows from v5: add a code-ref-keyed lambda-payload segment, a frame table, and a
provenance/fingerprint block. Each new segment reuses the index-keyed
`write_indexed_payload`/`read_indexed_payload` helpers where the shape fits;
opaque bytes keep `ratchet-value` value-agnostic, as for lists/contexts/primops.

## Implementation outcome (increments 1-5, 2026-07-13/14)

All five increments landed per the map; the wire format ended at **v8**
(v6 frame table, v7 closure payloads, v8 owned-data payloads — see below).
The mutating collapse landed with one reviewed unsafe surface
(`FlatSlice::as_mut_slice` + its single `FlatAttrs::rewrite_entry_values`
caller, pin-mapped in `heap/safety.rs`, second-reviewer-approved before push).

### Acceptance numbers (real prelude, darwin-via-cargo, candidate_c_value)

Driven by the ignored `snapshot_prelude_probe` harness
(`AOS_NIX_SNAPSHOT_EXPR`, usage in its doc comment; `heap_snapshot/closures.rs`):

- **stdenv prelude** (`pkgs.stdenv.stdenv.drvPath` forced — the census
  target): collapse shed **6,389 forced thunks** (census measured 6,386 —
  the distribution held) and rewrote 146 frame slots / 1,270 list elements /
  6,286 attrs entries / 294 closure fields / 5,809 tail values; capture
  emitted 6,877 relocations, 544 lists, 862 contexts, 497 primops, 54
  distinct frames, 9,037 closures; serialized image **4,829,364 bytes**;
  the restored function **re-derived the stdenv `.drv` path byte-identical**
  to a cold evaluation.
- **lib prelude** (deep-forced `import ./lib`): 423 thunks collapsed; image
  190,192 bytes; all 190 lib attrs enumerable post-restore; byte-identical.
- Hermetic CI acceptance: the mini-prelude round trip
  (`mini_prelude_round_trips_byte_identical_after_collapse`) drives restored
  curried lambdas, `with` scopes, a restored partially-applied builtin, and
  suspended-thunk forcing through a restored heap on both carriers.

### Acceptance-surfaced bugs (why the real-prelude gate was specified)

The increment-5 run found three restore bugs invisible to every small
fixture:

1. **Owned-storage data restored dangling** (the serious one). Attrsets above
   the flat-inline element threshold (~128 entries) and strings above the
   4096-byte threshold keep their *moved owned `Vec`s* behind the arena
   payload (the doc 30 FV-4 churn-workload decision), so the dumped lanes
   carry only `Vec` headers pointing at process-heap memory freed with the
   source heap. Symptom on the real lib prelude: the restored 190-entry lib
   attrset read as **empty** through its dangling permutation arrays
   (`attrNames = []`) while selects appeared to work — silent wrong answers
   over reads of freed memory. Fixed by the v8 **owned-attrs / owned-string
   payload segments** (entries + both permutations with positions; byte
   buffer + context), with untrusted-input validation (permutation bounds,
   strict entry sort order) and no-drop payload overwrite. **The
   `AOS_NIX_SNAPSHOT_VERIFY` completeness audit is structurally blind to
   this class**: it scans dumped words for uncovered pointers *into* the
   reservation, and owned `Vec` pointers point *out* of it. The default-deny
   storage-kind guard (below) is the standing defense.
2. **Tail sanity check ran before the registry finalize.** The dumped-header
   /declared-extent agreement check binary-searches the flat-closure
   registry, which is only address-sorted after
   `finalize_restored_registry`; with primop and closure segments
   interleaved (any real heap) the pre-sort search missed and refused
   well-formed images. The checks now queue and run after the sort,
   alongside flat-capture handle re-signing.
3. **Duplicate module fingerprints over-refused.** The same file loaded
   again (e.g. under a scoped import) yields two live modules with one
   identity hash; marking those ambiguous made restore refuse with
   `ClosureCodeDrift` on the stdenv prelude. Ruling (lead-endorsed):
   an equal content-keyed identity hash *is* the parse-cache key domain —
   equal source identity implies equal deterministic lowered IR, so binding
   the first such module is never a rebind to different code. **First-wins
   resolution; refusal remains for absent fingerprints (genuine drift), which
   is the case the constraint exists for.**

### Deliberate boundaries that remain (recorded, not latent)

- **In-process symbol ids** across all segments (attrs keys, primop symbols,
  builtin-attr symbols, lambda env scopes): the cross-process / durable L3
  image needs the serialized symbol-name table + re-intern pass described in
  the symbols section above — the recorded follow-on workstream.
- **Primop-arg and attr-position module ids are raw** (`EvalModuleId` words):
  these predate step 3's code-ref keying and share the same in-process
  boundary; upgrading them to `CodeNodeRef`s is mechanical when the
  cross-process workstream lands.
- **Post-collapse heaps are capture-only**: the mutating pass leaves
  hash-cons buckets keyed by pre-collapse hashes (raw-equality confirmation
  keeps them correct; dedup may miss) and sheds the collapsed wrappers'
  deferred work.
