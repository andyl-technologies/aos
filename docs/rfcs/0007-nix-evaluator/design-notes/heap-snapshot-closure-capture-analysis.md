# Heap-image snapshot: closure/thunk capture analysis (doc 31 §1)

**Status: DESIGN-ONLY. No implementation without a ruling.**

This note is the feasibility probe the campaign needs before the next
heap-image snapshot increment. The compound **data** class (strings, paths,
attrsets, lists, and — as of the stage-2 context collapse — context-bearing
strings) now round-trips through `capture_heap_image` / `from_restored_heap_image`.
The open question is whether we can snapshot the **real forced lib+stdenv
prelude**, whose heap is dominated by objects capture still refuses: worker
closures (thunks, lambdas, primops) and record-table objects.

## 1. Method

`EvalHeap::refusal_census` (test-gated diagnostic, `eval/heap/census.rs`) walks a
forced heap and tallies the accepted vs refused object mass by kind. It is driven
by the ignored `census_probe` harness with `AOS_NIX_CENSUS_EXPR` pointing at the
real prelude via absolute-path imports.

Caveats on the numbers:

- **Byte mass is *inline* flat-allocation size only** (`size_bytes()`): header +
  inline payload + inline recursive-binding capture tail. It does **not** count a
  closure's captured `EvalEnv`, whose frames are `Arc`-shared outside the arena.
  So closure retention is **undercounted** — the true closure cost is higher than
  the inline bytes below. The census reports how many closures capture an
  environment as a proxy.
- **Source attribution** (prelude vs package, top-level vs nested) needs the
  `TreeWalk` module registry, which the `EvalOutcome` does not retain. Only the
  count of distinct referenced code modules is reported.
- Measured on this clone's `lib`/`stdenv` at `--eval-system x86_64-linux`, forced
  via `stdenv.stdenv.drvPath`, darwin-via-cargo. Absolute counts will drift with
  the tree; the *distribution* is the load-bearing result.

## 2. Census

`import ./lib { system = "x86_64-linux"; }` deep-forced:

| class | kind | count | inline bytes |
|---|---|---:|---:|
| accepted | strings+paths | 97 | 10,544 |
| accepted | attrs | 53 | 26,064 |
| accepted | lists | 6 | 288 |
| refused | thunks (suspended) | 63 | 8,768 |
| refused | thunks (forced) | 419 | 58,840 |
| refused | lambdas | 186 | 26,128 |
| refused | primops | 40 | 5,440 |
| refused | records | 0 | 0 |

`stdenv.stdenv.drvPath` forced (the real prelude the campaign targets):

| class | kind | count | inline bytes | share of refused |
|---|---|---:|---:|---:|
| accepted | strings+paths | 3,672 | 1,148,904 | — |
| accepted | attrs | 3,256 | 1,019,936 | — |
| accepted | lists | 544 | 26,112 | — |
| **accepted total** | | **7,472** | **2,194,952** | — |
| refused | thunks (suspended) | 1,667 | 236,504 | 17% |
| refused | thunks (forced) | 6,386 | 912,352 | **67%** |
| refused | lambdas | 980 | 140,256 | 10% |
| refused | primops | 497 | 67,592 | 5% |
| refused | records | 0 | 0 | 0% |
| **refused total** | | **9,530** | **1,356,704** | 100% |

Distinct code modules referenced by closures: **465**. Closures capturing an
environment: **8,059 / 9,530**.

## 3. Findings

1. **Refused closure mass is ~38% of the heap's inline bytes** (1.36 MB of
   3.55 MB). Snapshotting the real prelude is impossible without handling it.
2. **Thunks are ~85% of the refused mass** (forced 67% + suspended 17%).
   Genuine lambdas + primops are only **~15%** (208 KB).
3. **Forced thunks dominate** (6,386 objects, 912 KB). A *forced* thunk already
   holds its computed value in its cell; the thunk object is a wrapper. Collapsing
   it to its value produces a value the snapshot already handles — cheap, and
   semantically a no-op (a forced thunk *is* its value).
4. **Records are zero** in production (worker closures default to the flat store;
   the record table only fills under a GC-stress policy). The record refusal is
   not a real blocker.
5. **Lambdas are essential and not droppable.** The prelude's *value* is its
   functions (`mkDerivation`, the `lib.*` helpers). A snapshot that omitted
   lambdas would restore a heap you cannot call into. So the 980 lambdas must be
   captured, not skipped.
6. **A lambda's captured environment cannot be re-created without re-forcing** —
   it *is* the evaluation state we are trying to avoid recomputing. So the env
   must be serialized, not rebuilt from IR. The good news: an env is mostly
   `Value` words (address-free under Candidate-C, already trivially snapshottable)
   plus frame structure, and frames are `Arc`-shared, so the *distinct* frame
   count is far below 8,059. The IR-code half of a lambda (module + body `IrId`)
   is re-linkable to the already-cached parse/lower output.

## 4. Options for the next increment

**A. Full closure serialization.** Serialize every closure: thunk cells, lambda
(module + body `IrId` + captured `EvalEnv` frame graph), primop (builtin symbol +
applied args). Handles the whole refused set directly. Cost: the `EvalEnv`
frame-graph serializer is the hard part (shared `Arc` frames, cycle-free but
deep), plus a re-link pass against 465 code modules. Largest surface.

**B. Force-then-collapse hybrid (recommended core).** Before capture: (1) force
the prelude to normal form so suspended thunks become forced; (2) collapse forced
thunks to their values (drops ~85% of the refused mass into the data class we
already handle). Then only the residual lambdas + primops (~15%, 1,477 objects)
need genuine serialization — the bounded version of Option A. Aligns with the
stage-2 thunk-collapse idea and turns the big number small.

**C. Re-scope doc 31 §1.** Snapshot only the closure-free data and re-force
closures on load, or snapshot only a closure-free sublibrary. Cheapest to build,
but per finding 5 a data-only prelude image is not callable, so this only makes
sense if the restored image is a *seed* that still re-forces the function layer —
which recovers little of the prelude-force wall. Likely a non-starter for the
stated goal; listed for completeness.

## 5. ROI framing (honest)

The snapshot's win is skipping the **prelude-force wall** on cold start (task #13
measured prelude-force at a large share of cold; S0 instrumentation saw
39–85% depending on corpus). Restoring a ~3.5 MB image (mmap + rebase, µs–ms) is
far cheaper than re-forcing, so if the whole forced prelude can be captured, the
restore saves nearly the entire prelude-force wall.

Counterweight: we **already beat C++ cold everywhere** (0.77–0.89x) after S0 +
parse-cache, which captured much of the parse/lower share. The snapshot's
*marginal* win is the remaining force-wall share on top of that. Whether it
justifies the Option-B closure work depends on the **current** prelude-force
share post-S0 — a number the lead holds from task #13. If that share is already
small, the honest recommendation is to **defer** the closure increment and bank
the data-residual completeness as the natural stopping point; recommending
against is a valid outcome of this probe.

## 6. Recommendation

If the current prelude-force share justifies further cold investment (toward the
10x goal), pursue **Option B**, sequenced:

1. **Force-to-normal-form + forced-thunk collapse before capture** (behind the
   snapshot dev flag). Measure the residual refusal census after collapse — expect
   ~1,477 lambda+primop objects. This step alone is a large, mostly-mechanical
   reduction and de-risks the rest.
2. **Primop capture** (497 objects): builtin symbol + already-applied arg Values
   (address-free) — small, no env graph.
3. **Lambda capture** (980 objects): module + body `IrId` (re-link to cached IR)
   + captured `EvalEnv`. Design the env serializer as index-keyed frame payloads
   holding `Value`-word arrays (the list-payload pattern generalizes), exploiting
   `Arc` frame sharing to keep distinct-frame count low.

Do **not** start any of this without a ruling. The measurement in step 1 (residual
census after collapse) is itself worth capturing before committing to the lambda
serializer, since it sets the real size of the hard part.

## 7. Open measurements before implementation

- Current prelude-force share of cold post-S0 (task #13 number) — the ROI gate.
- Distinct `Arc<EvalFrame>` count and total slot mass across the 8,059
  env-capturing closures (the census undercounts this; a frame-graph walk would
  size the true lambda-env cost).
- Post-collapse residual census (how many lambdas/primops actually survive forcing
  + forced-thunk collapse) — the real size of Option B's hard part.
