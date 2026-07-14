# JIT Fuse-Shapes Economics: Shape Census, Grammar Gap, and Ceiling

Status: **RESOLVED — KILL CRITERION FIRED. JIT-for-toplevel-parity is CLOSED.**
The census ran on the builder (tip `6fd6cce70`, cache-off cold toplevel, serial +
JIT legs); §7 is the formal verdict. Increment-0's kill criterion
(`F_addressable < 0.68`) fired even under a pro-JIT measurement bias, and the
genuinely-fusible anchor population caps the JIT at ≤1.5x — nowhere near the 3.14x
target. **Tier-2 compute-shape wins (fold/filter/all/any, 20-25x) are unaffected;
this ruling is only about compiling the system-toplevel shape.** Instrumentation
was the only code (no compiler changes); both feature configs green; byte-parity
unaffected (diagnostic records to stderr, never perturbs evaluation).

Context: RFC-0007's current top target is **parity-or-faster on cache-off cold
system-toplevel eval vs C++ Nix** (pinned 2.24.12). Today native is **2.53 s vs
oracle 0.57 s = 4.4x slower**, with **identical work counts** (~3.2M function
calls both). Every interpreter-surgery lever has been measured to exhaustion
(micro-opts wall-neutral; env-flattening closed by histogram; parallel fan-out
closed by Amdahl; profile is a flat long tail, no entry >8.1%). The two
structural levers in flight (arena-owned payloads, capture-on-demand) have an
honest combined ceiling of **~1.4x**. To reach 4.4x, the JIT must therefore
supply the remaining **4.4 / 1.4 ≈ 3.14x**. This note decides whether it can.

---

## 0. TL;DR — the verdict, and the number that settles it

The JIT reaching ~3x on the toplevel requires **two independent things to both
be true**, and the second is very likely false:

1. **Coverage** — ≥75-85% of *total evaluation wall* must live in bodies a fused
   tier-2 grammar could compile (§4 ceiling table). The census (§2) measures
   this.
2. **Per-covered speedup** — those bodies must compile at **≥5x each**. This
   requires the compiled body to cover **enough operations per native dispatch
   to amortize the ~1 µs per-dispatch tax** (§4). The tax is the wall of a
   context pin + trap scope + environment clone, paid *once per dispatched
   body*, and it is measured in `tier2_filter.rs` at **~1 µs/call**.

The structural problem: the toplevel's 4.4x gap is **613 ns/call of interpreter
overhead spread across 3.2M sub-microsecond operations** (native 791 ns/call,
C++ 178 ns/call). If the per-force self-time of the dominant shapes is *below the
~1 µs dispatch tax* — which the flat-long-tail profile strongly implies — then
compiling those bodies **per force is net-negative** (you replace a 300-800 ns
interpreted force with a >1 µs dispatched one), and there is **no loop structure**
(unlike `fold`/`filter`/`all`/`any`, which amortize the tax over N elements) to
rescue it. Tonight's toplevel JIT stats confirm the compiler already contributes
nothing here: `tier2_promoted=3, tier2_dispatched=0, tier2_deopted=86152,
tier2_blacklisted=492`.

**The one number that settles it** (from the new `self_ns_buckets` histogram,
§2): the **fraction of total self-nanos that lives in forces whose exclusive
self-time exceeds the per-force dispatch break-even threshold**. Call it
`F_addressable`.

**RESOLVED (§7): the census ran and `F_addressable` is below the line.** The
genuinely-fusible (`w ≫ τ`) mass is ≤40.5% *even under a pro-JIT measurement
bias* — below the 0.68 floor — and the anchor honest-ceiling caps the JIT at
≤1.7x at `s = ∞`. JIT-for-toplevel-parity is **CLOSED**; tier-2 compute-shape
wins are unaffected. The original decision rule and its two branches, preserved:

- If `F_addressable` is small (long tail below the tax) → **JIT cannot reach
  ~3x at any coverage** (§4 proves `s < 1` for the mass). **← this is the
  measured outcome.**
- If `F_addressable` is large **and concentrated in few, large boundary bodies**
  (high self-ns/force `AttrSet`/`Let` forces — the `callPackage` /
  module-fixpoint bodies) → there is exactly one viable increment: compile
  **those** (few, large, high-amortization), not the tail (§5, Increment 1).
  **← not the measured outcome; the large-body mass is mostly overhead artifact
  (§7.1).**

Either way the census was the falsifiable test, and it was a one-command builder
run. The rest of this note is the framework that turns its output into a
go/no-go.

---

## 1. Why the existing histograms cannot answer the wall question

`aos_nix_tier1_gated_histogram` (JIT engine, `gated_histogram()`) is a **static
def-site census**: it counts each distinct def-site the engine declined to
promote **at most once**, because a gated def-site is dropped from the force hook
after its *first* consulted force (`engine.rs`
`count_and_maybe_promote` → `PromotionOutcome::gated()`). It reports shape
*variety*, not dynamic call frequency, and carries **no wall**. The lead's brief
reads it as "the 3.2M calls classified by shape" — it is not; it is the *number
of syntactically-distinct bodies* of each shape. `aos_nix_tier1_gated_cost_...`
adds a static native-instruction estimate per lowerable def-site, still per
def-site, still no wall and no dynamic count.

To rank shape classes by *wall a compiler could remove*, we need the **dynamic
per-force** distribution with **exclusive self-time**. That is what §2 adds.

---

## 2. The new instrumentation — force-shape wall census

`crates/ratchet-oracle/src/eval/tree_walk/force_shape_census.rs`
(+ classifier in `eval_stats.rs`, wired at the `eval_thunk_body` seam via the
existing `begin/end_force_accounting` pair).

**What it measures.** On **every thunk force** (not just the first — this hooks
the tree-walk force path, below the JIT gating), it classifies the forced body
into a **shape class matching the gated histogram's vocabulary** (`AttrSet`,
`Select`, `Interp`, `BinOp:Update`, `LocalVar`, `PrimOp`, `apply`, …) and
attributes:

- **dynamic force count** per class — the population a compiler would cover;
- **exclusive self-nanos** per class — inclusive wall minus nested child-force
  wall, computed with a per-thread children-nanos accumulator (reuses the single
  `Instant` `begin_force_accounting` already captures, so **zero extra clock
  reads**); and
- a **self-ns break-even bucket histogram** (`self_ns_buckets`) partitioning
  every force's self-time into power-of-two nanos buckets.

**Why exclusive self-time is the right metric.** Compiling a thunk body removes
its *own* interpreter dispatch/setup/alloc overhead, not the wall of the child
thunks it forces (those are separately-forced, separately-compilable bodies).
Inclusive time would over-credit the outer driver shapes (`Let`, `apply`,
`AttrSet`). The sum of all classes' self-time is the total top-level inclusive
wall, partitioned without double-counting.

**Critical granularity caveat (measured locally on darwin).** The census counts
**thunk forces**, and the evaluator evaluates many nodes **inline** within an
enclosing thunk rather than as separate forces. Verified: evaluating
`let m = { x = 1; } // { y = 2; }; in toString (m.x + m.y)` records **only** a
`BinOp:Update` force and a `BinOp:Add` force — the `AttrSet` literals and the
`.x`/`.y` `Select`s fold into those forces' self-time; they are **not** separate
forces. So:

- `total_forces` in the census is the `thunks_forced` population, **not** the
  3.2M `function_calls`. Do not expect them to match.
- Inline sub-evaluation is correctly attributed to the enclosing compilable body
  — which is exactly the granularity the JIT compiles at, so this is a feature,
  not a loss. A compiled `BinOp:Update` body would inline those same attrset
  builds and selects.
- `apply`/`apply2` classes count only **thunked** applies; inline applies fold
  into their caller. The census under-counts raw apply frequency by design.

**How to read it into the ceiling.** For each shape: `mean_self_ns =
self_ns / forces`. A shape whose `mean_self_ns` is well above the per-force
dispatch tax is a fusion candidate; one below it is net-negative to dispatch.
`F_addressable = (Σ self_ns in buckets ≥ tax_bucket) / total_self_ns` is the
coverage ceiling for a per-force strategy (§0).

Output line (one greppable JSON, on the `AOS_NIX_EVAL_STATS` stderr path):

```text
aos_nix_force_shape_census {"total_forces":N,"total_self_ns":T,
  "shapes":{"AttrSet":{"forces":..,"self_ns":..,"incl_ns":..}, ...},
  "self_ns_buckets":{"128":{"forces":..,"self_ns":..},"256":{...}, ...}}
```

Tests (bare `cargo`, darwin-runnable): exclusive-time subtraction math,
power-of-two bucket indexing, and an end-to-end classification assertion under a
real stats-dump eval.

---

## 3. Grammar gap list — the #41 requirements, made concrete

What the tier-2 compiler accepts **today** (`lower_body_artifact` +
`lower_force_aware_tier1_ir_thunk_body` + the strict-iteration seams):

- One-word **literals** (`value_abi::lower_literal`).
- **Arithmetic / comparison `BinOp`s** via the force-aware lowerer (the decoded
  i64-accumulator fold path, §i64-acc).
- A hot **`PrimOp` inline** (`stringLength`) and a **delegating trampoline** for
  every other primop — delegation is measured to cap at NEUTRAL.
- **Strict-iteration loops** that amortize the tax over N elements: `foldl'`,
  `filter`, `all`/`any`, genlist-fold, curried chains. These are the only
  net-positive tier-2 wins today, and they win **only because the ~1 µs pin is
  paid once per loop, not per element.**

What it **refuses** (the toplevel's mass — rank these by census `self_ns`, then
attack the top wall-owner first). Each row lists the runtime-FFI/grammar addition
required. Existing runtime-FFI helpers (`aos_alloc_*`, `aos_env_get`,
`aos_apply`, `aos_select_ic`, `aos_has_attr`, `aos_update`, `aos_gc_write_barrier`)
are the building blocks; "missing" marks a helper that does not yet exist.

| Shape class | Refusal today | Requirement to compile | FFI status |
|---|---|---|---|
| `AttrSet` (attrs-building bodies) | not lowerable | attrs-alloc FFI: build a hidden-class-keyed attrset from N (symbol, thunk-value) pairs in one out-call; write-barrier the result | `aos_alloc_*` exists; **attrs-build-from-shape helper missing** |
| `BinOp:Update` (`//` merge chains) | not lowerable | update-fusion: fold a `//`-chain into one merge over the base hidden class | `aos_update` exists; **chain-fusion lowering missing** |
| `Select` (attr access, incl. `.a.b.c` paths) | partial | select-with-IC lowering against a forced receiver + path | `aos_select_ic`/`aos_has_attr` exist; **path lowering missing** |
| `Interp` (string interpolation) | classifier only | interp-concat FFI over the fusable child grammar (`classify_interp_thunk_body` already partitions `Fusable{n}` / `ComplexChild` / `PathFragment`) | **string-concat/coerce FFI missing** |
| `Let` / `apply` (driver bodies) | not lowerable | frame-alloc + env-write + inline-apply; the fusion *anchor* — this is where a body covers many child ops per dispatch | `aos_env_get`/`aos_apply` exist; **frame-build + fused-body lowering missing** |
| `LocalVar`/`UpvalVar` (env reads) | lowerable but trivial | already cheap; not worth a dedicated dispatch (self-ns ≪ tax) | n/a |
| `PrimOp` (non-inlined) | delegates | selective **inline** of pure hot builtins only (delegation is NEUTRAL) | histogram-ranked; `stringLength` done |

The **fusion anchor** is `Let`/`apply`/`AttrSet` bodies that *contain* the
`Select`/`Interp`/`BinOp` work as inline children. Compiling the anchor is what
lets one native dispatch cover dozens of operations — the only structure with
tax-amortization headroom outside the iteration seams. Ranking by census
`self_ns` tells us which anchor bodies carry the wall.

---

## 4. Profit model and the honest ceiling

**Constants** (measured, cited):

- Per-dispatch tax `τ ≈ 1 µs` (context pin + trap scope + env clone), from
  `tier2_filter.rs` module docs. The tier-1 def-site dispatch (`dispatch_env`
  env-clone + bare native call + result decode) is *lighter* than the tier-2
  seam but **unmeasured** — see §6 for the microbench that pins it. Call it
  `τ1`; the analysis below uses `τ` and is monotonic in it.
- Compile cost: **tens of µs** per body (`tier2_filter.rs`), amortized only over
  repeated forces of the same def-site.
- Per-call wall today: native **791 ns/call**, C++ **178 ns/call**, gap **613
  ns/call** (2.53 s and 0.57 s over 3.2M calls).

**Amdahl on self-time.** Let `f` = fraction of total wall in covered
(compilable) bodies, `s` = per-covered speedup (compiled self-time vs
interpreted, net of residual FFI out-calls **and the amortized dispatch tax**).
Overall speedup:

```text
speedup = 1 / ( (1 - f) + f/s )
```

To hit the required **3.14x** (JIT's share of the 4.4x stack, other levers at
1.4x), we need `(1 - f) + f/s = 0.318`:

| per-covered speedup `s` | coverage `f` needed for 3.14x |
|---|---|
| ∞ (free compiled bodies) | **0.68** |
| 10x | **0.76** |
| 5x | **0.85** |
| 3x | **1.02 → impossible** |
| ≤1x (dispatch tax ≥ interp self-time) | **impossible at any f** |

**Two brutal facts fall out:**

1. Even with *infinitely fast* compiled bodies you must cover **68% of all
   evaluation wall**. At a realistic `s = 3` (allocation/select still cost an FFI
   out-call), **3.14x is unreachable at 100% coverage.** You need `s ≥ 5`, i.e.
   `f ≥ 0.85`.
2. `s` itself is bounded by the tax. For a body whose interpreted self-time is
   `w`, the compiled+dispatched cost is `τ + w/g` (native code `g×` faster than
   interpreted, plus the tax). So
   `s = w / (τ + w/g) < w/τ`. **If `w < τ`, `s < 1` — dispatching is slower.**
   The toplevel's mean per-call wall is 791 ns and the tax is ~1000 ns, so for
   the *average* body `w < τ` and **per-force dispatch loses**. Only bodies with
   `w ≫ τ` (few, large, high self-ns/force) can have `s ≥ 5`, and only if they
   *also* fuse enough inline work that `g` is high.

**Conclusion of the model.** A per-force JIT strategy over the toplevel's flat
long tail has `s < 1` and **cannot** contribute positively, let alone 3x. The
*only* path to `s ≥ 5` at meaningful `f` is **fusing large anchor bodies**
(`callPackage`/module-fixpoint `Let`/`AttrSet` bodies) where one dispatch covers
enough inline ops that `w ≫ τ`. Whether such bodies carry ≥68-85% of the wall is
**exactly `F_addressable`**, which the census (§2) measures. Given the flat
long-tail profile (no entry >8.1%; identical 3.2M work counts; 613 ns/call
constant-factor gap), the **prior probability that `F_addressable ≥ 0.68` is
low**. State this to Dylan as the likely outcome, pending the census run.

---

## 5. Campaign plan — ordered, byte-parity-gated increments

Each increment is gated by `aos nix-diff --all --mode byte` on the Linux builder,
**serial + JIT legs**, and carries an explicit kill criterion. **Increment 0 is
mandatory and gates the entire program** — do not write any compiler code before
it.

**Increment 0 — Census run + verdict (this note's instrumentation).**
Run §6 on the builder toplevel. Compute `F_addressable` and the per-shape
`mean_self_ns`.
- **Kill criterion (program-level):** if `F_addressable < 0.68` (self-time not
  concentrated above the dispatch tax), **stop the JIT-for-parity program** and
  redirect the 3x hunt away from tier-2 (the 4.4x is a per-op interpreter
  constant, not a compilable-body concentration). Report to Dylan.
- **Proceed only if** self-time concentrates in few large `AttrSet`/`Let`/anchor
  bodies with `mean_self_ns ≫ τ`.

**Increment 1 — Attrs-build FFI + single-anchor fusion (highest coverage).**
The census's top wall-owning shape is almost certainly `AttrSet`/`Let` anchor
bodies. Add the attrs-alloc-from-shape runtime-FFI helper (§3 row 1) and lower a
*single* anchor body class end-to-end: build the attrset + inline its
`Select`/`LocalVar`/literal children in one native dispatch. Measure the realized
`s` on that class.
- **Size:** one FFI helper + one lowering path + promotion gate tuned to
  `self_ns ≥ k·τ` (only promote bodies above break-even).
- **Kill criterion:** if realized `s < 3` on the covered class (dispatch tax not
  amortized), **abandon** — the anchor bodies are not large enough, and §4 says
  nothing below `s=5` reaches parity.

**Increment 2 — Update-chain fusion + Select-path lowering.**
Only if Increment 1 clears `s ≥ 3`. Fold `//`-chains (`aos_update`) and lower
multi-segment `Select` paths (`aos_select_ic`) inside the anchor bodies to raise
`g` (more inline ops per dispatch → higher `s`).
- **Kill criterion:** cumulative toplevel wall improvement < 1.3x after
  Increments 1+2 → the coverage ceiling from §4 is binding; stop.

**Increment 3 — Interp-concat FFI.**
Only if the census shows `Interp` self-time material. `classify_interp_thunk_body`
already partitions the fusable grammar; add the string-concat/coerce FFI for
`Fusable{n}` shapes. Lowest priority (interpolation is typically a small wall
share).

**Do not** pursue: per-force dispatch of the long tail (`LocalVar`, small
`PrimOp`, sub-τ bodies) — §4 proves `s < 1`. Delegation-only lowering — ruled
NEUTRAL. Cheap-builtin inline for net-positive — ruled impossible.

---

## 6. Builder run commands (lead runs these; darwin is IFD-blocked on toplevel)

Census on the system toplevel, cache-off cold, **both legs**. `AOS_NIX_EVAL_STATS=1`
turns on the census (and the other stderr probes); grep the `force_shape_census`
line. Use the global `--eval-system`/`--impure-eval` flags (darwin/toplevel
gotcha from prior sessions).

```text
# Serial leg (default features):
AOS_NIX_EVAL_STATS=1 <toplevel nix-bench/nix-measure invocation, cache off, cold> \
  2>&1 | grep aos_nix_force_shape_census

# JIT leg (candidate_c_value + JIT on):
AOS_NIX_EVAL_STATS=1 AOS_NIX_JIT=1 <same invocation, --features candidate_c_value> \
  2>&1 | grep aos_nix_force_shape_census
```

Then compute, from the single JSON line:

- `mean_self_ns[shape] = self_ns / forces` per shape (rank fusion candidates);
- `F_addressable = Σ self_ns over buckets ≥ τ_bucket / total_self_ns`
  (τ ≈ 1024 ns → bucket key `"1024"` and above; use the tier-1 microbench τ1 if
  measured);
- feed `F_addressable` and the realized per-shape means into §4's table to read
  the go/no-go.

**Tier-1 dispatch-tax microbench (needed to pin `τ1`).** The ~1 µs figure is the
tier-2 seam; the tier-1 def-site dispatch is lighter. A tight microbench that
force-promotes a trivial def-site (`AOS_NIX_JIT_FORCE_PROMOTE`) and times
dispatched vs interpreted forces of the same body pins `τ1`, which sets the true
break-even bucket. Until measured, use `τ = 1 µs` as a conservative upper bound
(it makes the ceiling *optimistic* to lower τ, so `τ = 1 µs` is the charitable
assumption for the JIT).

---

## 7. Formal verdict — census ran, kill criterion fired

Census executed on the builder (tip `6fd6cce70`, cache-off cold system-toplevel,
serial + JIT legs; JIT leg within ~3% of serial everywhere, so the shape
distribution is engine-independent). Serial-leg essentials:

- `total_forces = 8,827,365`, `total_self_ns = 9.053e9` ns.
- Top shapes by self-ns (mean = self_ns / forces): `apply` 4.02M forces / 3.167e9
  (787 ns), `PrimOp` 1.29M / 1.864e9 (1445 ns), `Let` 220,890 / 1.648e9
  (**7462 ns**), `Apply` 170,877 / 1.028e9 (**6019 ns**), `AttrSet` 104,883 /
  2.525e8, `BinOp:Concat` 283,077 / 2.322e8, `Select` 579,531 / 2.040e8,
  `LocalVar` 1.07M / 1.676e8.
- Self-ns bucket masses (verified to sum to `total_self_ns`): ≥τ (1024 ns) =
  6.514e9 = **72.0%**; ≥2τ (2048 ns) = 5.593e9 = **61.8%**; ≥16τ (16 µs) =
  3.669e9 = **40.5%**; ≥16 ms = 1.310e9 = **14.5%** (a handful of giant forces —
  the module fixpoint itself).

### 7.1 The measurement is contaminated, and the bias is pro-JIT

`total_self_ns = 9.053e9` against the **clean stats-off wall of 2.50e9** — the
census adds **6.55e9 ns of overhead**, i.e. **742 ns/force** across 8.83M forces
(this independently confirms the ~0.7 µs/force estimate). That overhead is the
census's own per-force cost (begin-classify's IR-arena lookup + close's lock and
map update), and it lands in **ancestor self-time**: each force's timed region
encloses its direct children's begin-classify and close-bookkeeping, which occur
inside the parent's clock but outside any child's measured `elapsed`, so they are
never subtracted as child time. The overhead therefore piles onto exactly the
large **driver** bodies (`apply`, `Let`, `Apply`, the fixpoint root) — the same
bodies that constitute the "addressable" large-`w` population.

**Consequence: the census overstates the fusible large-body mass.** Concretely,
`apply`'s 787 ns nominal mean is dominated by the overhead of the children it
drives; its true self-time is ~50-100 ns, so **~85-90% of `apply`'s 3.167e9 (≈35%
of all nominal self-time) is measurement artifact, not addressable work.** A
negative result obtained under a pro-JIT bias is therefore **robust**: the true
numbers are worse than the nominal ones below.

### 7.2 Two independent kill conditions, both fire

**(A) Coverage at break-even.** Reaching the required 3.14x needs `f ≥ 0.68` of
wall in bodies whose per-covered speedup `s` is large, and `s ≥ 5` requires
`w ≫ τ` (§4). The mass with `w ≫ τ` (≥16τ = 16 µs) is **40.5% nominal < 0.68**.
The broader `w > τ` mass (72.0%) nominally clears 0.68, but those marginal bodies
sit at `w ≈ τ`, where `s = w/(τ + w/g) ≈ 1` — **no speedup** — so they do not
count toward coverage. The kill line fires on nominal, pro-JIT-biased numbers;
true coverage is lower still.

**(B) Anchor honest-ceiling.** Compile the *entire* genuinely-large population
(≤40.5% nominal) at an unattainable `s = ∞`: `speedup = 1/(1 − 0.405) = 1.68x`.
On the lead's tighter anchor cut (`Let` + the ≥16 ms tail, ~33%): `1.49x`. At a
realistic `s = 5`: `1.48x`. **Every honest cut caps the JIT at ≤1.7x — nowhere
near the 3.14x it must supply**, and each of these is an over-estimate because the
large-body mass is inflated by §7.1's overhead.

The two conditions are independent (one is a coverage floor, one is a ceiling on
the achievable multiple) and both reject the target by a wide margin. There is no
`(f, s)` combination consistent with this census that reaches 3.14x.

### 7.3 Program disposition

- **JIT-for-toplevel-parity is CLOSED.** No fuse-shapes compiler increment
  (attrs-alloc FFI, update-chain fusion, select-path lowering, interp-concat) can
  move the toplevel to parity: the wall is a flat long tail of sub-τ thunk forces
  with no fusible concentration, and the interpreter's own per-force cost is the
  same order as a JIT dispatch. Increments 1-3 of §5 are **not started and should
  not be**.
- **Tier-2 compute-shape wins are UNAFFECTED.** The strict-iteration seams
  (`foldl'`/`filter`/`all`/`any`/genlist-fold, curried chains) still beat C++
  20-25x on compute shapes — they amortize `τ` over N elements, a structure the
  toplevel lacks. This ruling narrows, and does not retract, the JIT's role.
- **The 4.4x toplevel gap is a per-op interpreter constant**, distributed over
  ~3.2M sub-microsecond operations with no hot concentration — confirmed by the
  flat-long-tail profile *and* now by the self-ns bucket distribution. It is not
  a compilable-body-coverage problem, so it is not a JIT problem.
- **Re-entry conditions (Dylan's call, not a JIT increment):** (1) a *changed
  workload shape* — a future toplevel dominated by compute or wide strict
  iteration rather than module-fixpoint attrs-building would move mass into the
  tier-2-favorable regime; or (2) an *AOT / persistent-compiled-code posture* that
  pays the compile cost once, out of band, and amortizes native bodies across many
  evaluations — this changes the cost model entirely (no per-eval dispatch tax on
  the hot path) and is an architecture decision, not a tier-2 promotion tweak.
  Neither is actionable as an incremental JIT change today.
