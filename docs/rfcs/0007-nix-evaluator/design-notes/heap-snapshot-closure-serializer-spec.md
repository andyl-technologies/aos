# Heap-image snapshot: lambda/env serializer spec (doc 31 §1 step 3)

**Status: SPEC. Increment map for the closure serializer; implementation lands
per this map, gated by the lead's ruling on step 3 (already GO).**

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
