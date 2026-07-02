# RFC-0007 - Execution Tiers and the Cranelift JIT

This document specifies the *execution engine* of `aos-nix`: the layered set of
mechanisms that turn the compact arena IR from [the frontend](04-frontend-parser-and-ir.md)
into running code that produces [values](05-value-representation.md), forces
[thunks](07-laziness-and-whole-program-analyses.md), and ultimately drives
[`derivationStrict`](11-derivation-and-store-compatibility.md) to byte-identical
`.drv` output. It covers the three execution tiers (tree-walk oracle, Cranelift
baseline, Cranelift optimized), the speculation/deoptimization/on-stack-replacement
machinery that makes tier 2 safe, the runtime ABI that compiled code uses to call
back into the host, and the explicit rationale for choosing Cranelift over LLVM,
WASM, and a copy-and-patch baseline.

It is deliberately a *design record*: every mechanism is justified by naming the
production system it descends from (HotSpot, V8, LuaJIT, GHC, Cranelift/Wasmtime)
and by arguing why Nix's purity and whole-program batch nature make that mechanism
*more* effective here than in its source system. Where a claim is research-grade
or unverified against `aos-nix`'s own workload, it is marked as an open question.

> Scope note. This document is about *how code runs*, not *what gets allocated*
> ([memory and GC](06-memory-management-and-gc.md)), *how attrsets are laid out*
> ([hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)),
> or *how primops are dispatched* ([primops and runtime ABI](10-primops-and-runtime-abi.md)).
> Those touch the engine and are cross-referenced, but their detail lives in their
> own documents. Critically, this document is also downstream of the
> [measure-first characterization](01-motivation-and-goals.md): tiers 1 and 2
> are ordered after the tree-walk oracle plus the differential harness have
> produced a baseline eval-time number and counter breakdown. Under the budget
> mandate, the JIT tiers remain in scope; the characterization decides priority
> and validation targets, not whether the tiers exist.

---

## 1. Why tier at all

### 1.1 The shape of the workload

The defining quantitative property of Nix evaluation, and the one that dictates the
entire execution model, is the (large, expected) ratio between **expressions** and
**thunk activations**. The order-of-magnitude figures below are estimates the
measure-first characterization must confirm on the AOS package set before JIT
work is prioritized; their *ratio*, not their absolute values, is what the design
leans on.

- The number of distinct *expressions* in the AOS package set — every lambda body,
  every `let` binding, every attrset literal, every `if`, across all of nixpkgs-scale
  Nix — is bounded. It is in the **tens of thousands** range and grows only when
  source files change.
- The number of *thunk activations* — each time a suspended computation is forced
  during a single evaluation — is in the **billions**. A `genList` over a large
  range, a `foldl'` over an attrset, an `import` that fans out across the
  package-set expression closure: each multiplies activations without adding
  expressions.

This ratio is the single most important number in the design. It says: **compile
per-expression, exactly once; never compile per-activation.** A thunk activation is
a *call* into already-compiled code, not a fresh compilation. C++ Nix is a pure
tree-walking interpreter and therefore pays interpretation overhead on every one of
those billions of activations; the entire premise of a JIT here is to pay a bounded
compilation cost (tens of thousands of compilations) to remove a per-activation
cost paid billions of times.

This is structurally identical to the justification HotSpot gives for JIT-compiling
*methods* rather than *bytecodes*, and to V8 compiling *functions* rather than
*expressions evaluated*. The unit of compilation is the static program unit; the
unit of speedup is the dynamic invocation count.

```text
            STATIC (bounded, ~10^4)          DYNAMIC (unbounded, ~10^9)
            ----------------------           --------------------------
  C++ Nix:  parse once                       interpret AST node every activation
  aos-nix:  parse + compile once per expr    call compiled code every activation
                                             (force = state check + indirect call)
```

### 1.2 The execution unit: thunk and lambda

The runtime objects the tiers manipulate are fixed by the
[value representation](05-value-representation.md) and repeated here only as the
contract the engine relies on:

- A **thunk** is `(code_ptr, captured_env, state)`. `state` is one of
  `Suspended`, `Blackhole`, `Forced`.
- A **lambda** is `(code_ptr, captured_env)`. Application binds the argument into a
  frame over `captured_env` and jumps to `code_ptr`.
- **Forcing** a thunk is: read `state`; if `Forced`, return the cached value; if
  `Suspended`, transition to `Blackhole`, call `code_ptr(runtime, env)`, store the
  result, transition to `Forced`, return; if `Blackhole`, raise *infinite recursion
  encountered* (the same error class C++ Nix raises, required for
  [compatibility](02-compatibility-constraints.md)).

The `Blackhole` state is the standard self-reference detector from the
STG machine / lazy-evaluation literature (GHC calls the analogous object a
"black hole"). It is mandatory: Nix programs legitimately rely on the *error* when
a binding refers to itself through strict demand, and the harness diffs that error.

The crucial property for tiering is that **`code_ptr` is the only thing that
changes between tiers.** A thunk forced by the tree-walk oracle and the same thunk
forced by tier-2 native code differ only in which function pointer sits in
`code_ptr`. Promotion is a pointer swap, not a representation change. This is what
makes the tiers composable: a value produced by one tier is indistinguishable from
a value produced by another, because the value *representation* is tier-invariant
and all allocation goes through the same [runtime symbols](#7-the-runtime-abi).

All three tiers consume **one Core IR** ([generalization and language dialects](28-generalization-and-language-dialects.md)):
the oracle (`ratchet-oracle`) and the JITs (`ratchet-jit`) walk and lower the same
generic Core (`ratchet-core`) nodes, and the Nix-specific ops (`DerivationStrict`,
`WithVar`) reach them via the same indexed `PrimOp` escape hatch the dialect
registers — so the one-IR-for-all-tiers invariant is, more precisely, one *Core* IR
for all tiers, extended by the dialect through that single seam.

---

## 2. The three tiers

`aos-nix` adopts the **HotSpot tiered-compilation model**: a slow, simple,
always-correct interpreter at the bottom; progressively faster, more speculative
compiled tiers above; profile-guided promotion between them; and deoptimization to
fall back down when a speculation is invalidated.

| Tier | Name | Mechanism | Role | When |
|------|------|-----------|------|------|
| 0 | Tree-walk oracle | AST/IR interpreter in safe Rust | Correctness reference; cold and run-once code; debugging | Always available; default for everything until profiled hot |
| 1 | Baseline JIT | Cranelift, no speculation | Remove interpretation overhead on hot thunks fast | Thunk/lambda crosses a hotness threshold |
| 2 | Optimized JIT | Cranelift + speculation, deopt, OSR | Peak throughput on the hottest, most stable code | Tier-1 code stays hot and type-stable |

HotSpot's analogous structure is interpreter -> C1 (client) -> C2 (server), with
the interpreter as the correctness baseline and C1/C2 as the two compiled tiers
([Microsoft, "How Tiered Compilation works in OpenJDK"](https://devblogs.microsoft.com/java/how-tiered-compilation-works-in-openjdk/)).
We collapse C1/C2 into "Cranelift baseline" and "Cranelift optimized" because both
of our compiled tiers use the *same* backend (Cranelift) at different optimization
levels and with speculation on/off — we are not maintaining two separate compilers.

### 2.1 Tier 0 — the tree-walk oracle

Tier 0 is a straightforward recursive evaluator over the IR, written in **safe
Rust** (no `unsafe`, no JIT, no raw function pointers). It is the first thing built
(phase 1 of the [roadmap](17-roadmap-and-risks.md)) and it is never removed. It
serves four distinct purposes, each of which independently justifies its permanent
existence:

1. **Correctness oracle.** The differential harness
   ([15-differential-testing-and-benchmarking.md](15-differential-testing-and-benchmarking.md))
   can diff tier-0 output against `nix-instantiate` *and* against the compiled
   tiers. Any disagreement between tier 0 and tier 1/2 is a JIT bug, localized
   immediately, without involving C++ Nix. The oracle is the ground truth the JIT
   is validated against.
2. **Cold / run-once code.** Most expressions in a Nix evaluation are forced *once*
   (the cardinality analysis in
   [07-laziness-and-whole-program-analyses.md](07-laziness-and-whole-program-analyses.md)
   makes this precise). Compiling a thunk that runs once is pure loss: you pay
   compile time and never amortize it. Tier 0 runs these directly. This mirrors
   HotSpot, where the interpreter — not the JIT — runs methods until they prove
   themselves hot.
3. **Debuggability.** A JIT is opaque; a tree-walker can carry source spans, print
   evaluation traces, and step. When a `.drv` diverges, debugging happens in tier 0.
4. **The safe island for `unsafe` policy.** Per the canon and AOS's
   [unsafe policy](14-integration-with-aos.md), the JIT tiers are necessarily heavy
   on `unsafe` (raw function-pointer calls, NaN-boxing, raw heap). Tier 0 is kept
   in the safe subset so that **miri and sanitizer CI run against the oracle**,
   giving a memory-safe reference implementation that exercises the same value
   representation, primops, and store logic as the JIT.

Tier 0 must be *fast enough to be the baseline number*. The measure-first
characterization is satisfied by tier 0 alone: if tier 0 plus the incremental
cache ([12-incremental-evaluation-cache.md](12-incremental-evaluation-cache.md)) already
beats `nix-instantiate` wall-clock on the AOS package set, the JIT no longer
carries near-term workload urgency. The roadmap explicitly ranks the incremental
early-cutoff cache and the bump-arena heap *above* the JIT for exactly this
reason.

### 2.2 Tier 1 — the Cranelift baseline JIT

Tier 1 compiles a single expression (a lambda body or a thunk's suspended
computation) to native code with **Cranelift**, at low optimization, with **no
speculation**. Every operation is fully general:

- Every value access goes through the boxed/tagged representation.
- Every attrset `select` calls the generic [inline-cache](09-attribute-sets-hidden-classes-and-inline-caches.md)
  runtime helper (the IC may still be monomorphic, but tier 1 does not *bake in* a
  shape assumption).
- Every arithmetic op type-checks its operands at runtime and raises the
  Nix-compatible error on mismatch.
- Every force is a call to the `aos_force` runtime symbol.

Tier 1 buys exactly one thing over tier 0: it removes the *interpreter dispatch
overhead* — the giant `match` on IR node kind, the recursion through `Box<Expr>`,
the repeated environment-slot lookups — replacing it with straight-line native code
that still calls the same runtime helpers. This is precisely the role of HotSpot's
C1: "fast to compile, modest code quality, no aggressive speculation." Cranelift is
an exceptionally good fit for this role because its compile speed is roughly an
order of magnitude faster than LLVM
([Wasmtime `compare-llvm.md`](https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/docs/compare-llvm.md);
[cranelift.dev](https://cranelift.dev/)), so the compile cost amortizes quickly even
for moderately hot thunks.

Tier 1 emits **safepoints and user stack maps** from the start (see
[§6](#6-cranelift-the-gc-and-stack-maps)), even though tier-1 code does no
speculation, because the precise generational GC in daemon mode
([06-memory-management-and-gc.md](06-memory-management-and-gc.md)) needs to find
live references on the stack of *any* compiled frame. This is a frontend obligation
in modern Cranelift and is cheap; it must not be deferred.

### 2.3 Tier 2 — the Cranelift optimized JIT

Tier 2 recompiles a thunk/lambda that stays hot under tier 1, this time **baking in
profile-guided speculations**:

- **Shape speculation.** If the profile shows a `select` site has always seen one
  [hidden class](09-attribute-sets-hidden-classes-and-inline-caches.md), tier 2
  emits a *guard* (shape == expected?) followed by a constant-offset load, with a
  **deopt** on guard failure. This is V8's monomorphic inline-cache idea promoted
  into the compiled code itself, exactly as TurboFan does.
- **Type speculation.** If an arithmetic site has only ever seen `int`, tier 2
  emits an unboxed `i64` add guarded by a tag check, deopting to the boxed path on
  the first `float`/`string` it ever sees.
- **Strictness baking.** Bindings that the
  [strictness/demand analysis](07-laziness-and-whole-program-analyses.md) proved
  always-forced are compiled **eagerly with zero thunk allocation** via the
  worker-wrapper split — tier 2 can inline the worker directly, eliminating the
  thunk object entirely.
- **Escape-analyzed scalar replacement.** Non-escaping attrsets/thunks
  ([07](07-laziness-and-whole-program-analyses.md)) have their allocation removed
  and their fields kept in Cranelift SSA values / stack slots, the HotSpot escape
  analysis trick.
- **Inlining and join points.** Small lambdas (especially the partial applications
  that `map`/`foldl'` create) are inlined, with unboxed multi-returns and join
  points to avoid re-boxing at merge points (a GHC STG technique).

Tier 2 is where the laziness-elimination and shape-specialization work from the
other documents actually *cashes out as machine code*. Tier 0 and tier 1 can use
the *analyses* (e.g. skip allocating a known-dead thunk), but only tier 2 can fully
specialize the generated code around them. The cost is that every speculation needs
a *guard* and a *deopt path*, which is the subject of [§3](#3-speculation-deoptimization-and-osr).

> **Why Nix makes tier-2 speculation pay off more than in Java or JavaScript.**
> In V8, a hidden-class guard can fail because objects are mutable and the program
> may add a property at any time; in HotSpot, a class-hierarchy speculation can be
> invalidated by dynamic class loading. In Nix, **values are immutable** and there
> is **no dynamic loading of new code at evaluation time** (the whole program is
> the closure of `import`s, fixed once parsed). A shape, once observed for a value,
> *cannot change for that value*. So the empirical stability that V8/HotSpot must
> defend against adversarial mutation is, in Nix, a structural guarantee for the
> lifetime of each value. Speculations still fail across *different* values reaching
> a site (a polymorphic call site genuinely sees two shapes), but they never fail
> due to mutation. This makes guards cheaper to reason about and deopt rarer.

---

## 3. Speculation, deoptimization, and OSR

Speculation is the only way tier 2 gets its speedup, and **deoptimization is the
mechanism that keeps speculation correct.** This is the central HotSpot insight: do
not prove the assumption; *assume* it, *guard* it, and have a *correct fallback*
when the guard fails ([OpenJDK `deoptimization.cpp`](https://github.com/openjdk/jdk/blob/master/src/hotspot/share/runtime/deoptimization.cpp)).

### 3.1 Uncommon traps / deopt points

Each speculation in tier-2 code is paired with a guard whose failure edge leads to
an **uncommon trap** (HotSpot's term). When the guard fails:

1. Execution of the tier-2 native frame is abandoned at the trap point.
2. The abstract evaluation state (which IR node we were at, the values of live
   variables, the partially-built environment) is **reconstructed** from the
   tier-2 frame using a side table the compiler emitted, and
3. execution **resumes in the tree-walk oracle (tier 0)** from the equivalent IR
   position, with the reconstructed state.

This is deoptimization: "switch execution from compiled code back to the
interpreter when an optimistic assumption is proven wrong"
([w3computing, "JVM JIT Compiler Deep Dive"](https://www.w3computing.com/articles/jvm-jit-compiler-deep-dive-c1-c2-tiered-compilation/)).
The reason tier 0 is the deopt target (rather than tier 1) is that tier 0 is the
*oracle*: it is total, it carries full source position information, and it cannot
itself deopt. A deopt is therefore always a one-hop fall to bedrock, never a
multi-hop cascade.

```text
   tier-2 native frame
   ┌───────────────────────────┐
   │ guard: shape == #C42 ?     │── pass ──► constant-offset load (fast path)
   │                            │
   │            fail            │
   └─────────────┘──────────────
                 │
                 ▼   reconstruct abstract state from deopt metadata
   ┌───────────────────────────┐
   │ tier-0 tree-walk oracle    │  resume at IR node N with live vars {x,y,env}
   │  (total, no speculation)   │  — produces the correct value, no divergence
   └───────────────────────────┘
```

The hard correctness requirement is that **deopt must be value-identical to never
having speculated.** Because Nix is pure, this is dramatically simpler than in
HotSpot: there are *no side effects* to have partially performed and to roll back.
A failed guard in `aos-nix` cannot have mutated the heap (the heap is immutable
values plus thunk-state transitions, and a guard sits *before* the speculative work
commits a thunk to `Forced`). Deopt therefore reduces to "reconstruct the
environment and re-enter the oracle," with no rollback of effects — the entire
class of HotSpot deopt bugs around partially-completed stores does not exist here.

### 3.2 Deopt metadata

For each deopt point the tier-2 compiler emits a record mapping the native frame to
the abstract state:

```text
DeoptPoint {
  ir_node:       NodeId,        // where in the IR to resume in tier 0
  live_slots:    [ (EnvSlot, ValueLocation) ],   // reg / stack-slot / constant
  scalar_repl:   [ (EnvSlot, Reconstruction) ],  // rebuild escape-eliminated objs
  guard_kind:    ShapeGuard | TagGuard | ArityGuard | ...,
}
```

The `scalar_repl` field is what makes escape-analysis-based scalar replacement
sound under deopt: if tier 2 *eliminated* an attrset allocation by keeping its
fields in registers, and we then deopt into tier 0 which expects a real heap
attrset, the deopt path must **materialize** the object from those registers before
resuming. This is exactly HotSpot's "reallocation of scalar-replaced objects during
deoptimization," and it is the single subtlest piece of the tier-2 design. It is
flagged as an [open question](#10-open-questions) for the first implementation:
the conservative initial policy is **do not scalar-replace any object that is live
across a deopt point** until the materialization path is proven against the harness.

### 3.3 On-stack replacement (OSR)

OSR is the dual of deopt: it lets us *enter* compiled code in the middle of a
long-running activation that started in a lower tier, rather than waiting for the
next call. The canonical trigger is a long loop whose body became hot *while the
loop was already running* ([the "osr_bci" mechanism in HotSpot](https://devblogs.microsoft.com/java/how-tiered-compilation-works-in-openjdk/)).

In Nix there are no source-level loops, but their dynamic equivalents exist and are
exactly the hot spots: a deep `foldl'` accumulation, a long `genList`, a recursive
`fix`-point that iterates many times, a `builtins.foldl'`-driven attrset merge over
a large package set. These manifest as a recursive thunk-forcing chain or a primop
internal loop that is already on the stack when it crosses the hotness threshold.
Without OSR, we could only promote them on the *next* top-level evaluation; with
OSR, we can swap the running activation to tier-2 code mid-flight.

OSR is **explicitly an advanced measured variant, not a phase-1 requirement.** It is the
most mechanically delicate tier-2 feature (it requires entering a compiled function
at a non-entry point with a tier-0 frame's state), and its benefit is bounded to a
small number of genuinely long-running single activations. The roadmap places it
after deopt and shape-specialization. The first cut promotes on the *next*
activation and accepts the missed speedup on the in-flight one. Whether OSR ever
earns its complexity on the AOS workload is itself an open question to be answered
by profiling, not assumed.

### 3.4 Promotion policy

Promotion between tiers is profile-guided, counter-based, in the HotSpot style:

- Each thunk/lambda carries an **invocation counter** (and, for OSR candidates, a
  **back-edge counter**). Counters live next to the `code_ptr` so the check is a
  cheap increment in the prologue.
- Tier 0 -> tier 1 when invocation count crosses `T1` (low, since tier-1 compile
  is cheap — Cranelift baseline).
- Tier 1 -> tier 2 when invocation count crosses `T2` *and* the site's collected
  type/shape profile is **stable** (e.g. monomorphic, or a small fixed polymorphic
  set). An unstable site stays in tier 1 to avoid thrashing deopts.
- A site that deopts more than `D` times is **blacklisted** from re-speculating
  that particular guard and recompiled in a more conservative shape, exactly as
  HotSpot tracks per-bci deopt counts to avoid recompilation loops.

Thresholds are tunables, not constants of the design, and must be chosen by
measurement against the package set. Given the bounded expression count, a
defensible *initial* policy is even simpler: **eagerly compile to tier 1 any
expression the profile or the [cardinality analysis](07-laziness-and-whole-program-analyses.md)
marks as multi-use, and reserve tier 2 for the small set of genuinely hot inner
loops.** The expression budget (~10^4) is small enough that we can afford to be
generous with tier 1.

---

## 4. The compilation pipeline

```text
  .nix source
      │  (04-frontend: lexer → recursive-descent parser → compact arena AST)
      ▼
  scope-resolved IR  ──── content-addressed parse cache (per file hash) ────┐
      │                                                                      │
      │  (07: whole-program strictness / cardinality / full-laziness /       │
      │       escape analysis annotate the IR)                               │
      ▼                                                                      │
  annotated IR ──────────────────────────────────────────────────────────► (12: incremental cache key)
      │
      ├─► TIER 0: walk the IR directly (always available)
      │
      ├─► TIER 1: lower IR → Cranelift CLIF (generic) → JITModule → code_ptr
      │
      └─► TIER 2: lower IR + profile → CLIF (speculative, guards, deopt edges)
                  → JITModule → code_ptr, + DeoptPoint side tables
```

Lowering IR to Cranelift CLIF is a tree-directed translation: each IR node kind
emits a small CLIF sequence. Most nodes emit a **call to a runtime symbol** rather
than open-coded logic — `aos_force`, `aos_alloc_thunk`, `aos_select_ic`,
`aos_apply`, `nix.builtin.<name>` — so that the *engine* stays thin and the *semantics*
live in Rust. This is the single most important structural decision in the JIT and
is detailed in [§7](#7-the-runtime-abi). Tier 2 differs from tier 1 only in that it
*inlines* and *specializes* some of those calls (turning an `aos_select_ic` call
into a guarded constant-offset load, an `aos_force` into an inline tag-test, etc.)
when the profile licenses it.

### 4.1 A worked lowering sketch

Consider the Nix expression `x.y + 1` in a context where `x` is in env slot 3.

Tier 1 (generic) emits, in CLIF-flavored pseudo-assembly:

```text
function %thunk_42(i64 rt, i64 env) -> i64 {
block0(v_rt: i64, v_env: i64):
    v_x   = call aos_env_get(v_env, 3)          ; load slot 3 (a thunk or value)
    v_xf  = call aos_force(v_rt, v_x)            ; force x to WHNF (an attrset)
    v_y   = call aos_select_ic(v_rt, v_xf, %sym_y, %ic_site_7)  ; x.y via inline cache
    v_yf  = call aos_force(v_rt, v_y)            ; force x.y
    v_sum = call nix.builtin.add(v_rt, v_yf, %int_1); generic add (type-checks)
    return v_sum
}
```

Tier 2, given a profile saying `%ic_site_7` is monomorphic on shape `#C42` (which
puts `y` at byte offset 16) and `nix.builtin.add` has only seen `int + int`:

```text
function %thunk_42_opt(i64 rt, i64 env) -> i64 {
block0(v_rt: i64, v_env: i64):
    v_x   = call aos_env_get(v_env, 3)
    v_xf  = call aos_force(v_rt, v_x)
    v_shape = load.i64 v_xf+0                    ; read hidden-class pointer
    v_ok  = icmp eq v_shape, %shape_C42
    brif v_ok, block1, block_deopt(N_select, [v_xf])   ; guard → deopt on miss
block1:
    v_y   = load.i64 v_xf+16                     ; constant-offset load, no IC call
    v_yf  = call aos_force(v_rt, v_y)
    v_ytag = ... ; tag check: is v_yf a small int?
    brif v_is_int, block2, block_deopt(N_add, [v_yf])
block2:
    v_yint = ... ; unbox i64
    v_sum  = iadd v_yint, 1                       ; unboxed native add
    v_res  = ... ; rebox as tagged int value
    return v_res
}
```

Two guards, two deopt edges, otherwise straight-line native code. Every place a
guard fails, control transfers to `block_deopt(<ir_node>, <live values>)`, whose
generated stub writes the deopt record and tail-calls `aos_deopt`, which re-enters
the tier-0 oracle at the named IR node with the named live values. This is the
entire speculation/deopt contract, made concrete.

---

## 5. Why Cranelift (and not LLVM, WASM, or copy-and-patch)

The backend choice is load-bearing and is justified explicitly against the three
serious alternatives.

One reframe to keep in view ([generalization and language dialects](28-generalization-and-language-dialects.md)
§2): **CLIF is the low-level universal target — the real LLVM-analog** — while the
Core IR is the higher-level, lazy-functional generic IR (the GHC-Core-analog). The
two live at different altitudes: Core unifies the pure lazy-functional language
family and lowers *to* CLIF, which in turn unifies the von-Neumann backends. The
question below is therefore narrowly "which low-level codegen do we lower Core to,"
not "which IR is generic" — that layer is already settled by Core above and CLIF
here.

### 5.1 Cranelift: the chosen backend

Cranelift is a pure-Rust code generator developed for Wasmtime
([cranelift.dev](https://cranelift.dev/)), used both as Wasmtime's baseline Wasm
compiler and as an alternative rustc backend
([`rustc_codegen_cranelift`](https://github.com/rust-lang/rust/blob/main/compiler/rustc_codegen_cranelift/src/driver/jit.rs)).
It is chosen for four reasons, in priority order:

1. **Fast compilation / warmup.** Cranelift's design explicitly trades a few percent
   of generated-code quality for roughly an order-of-magnitude faster compilation
   than LLVM
   ([Wasmtime `compare-llvm.md`](https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/docs/compare-llvm.md)).
   In a JIT whose total compile budget is bounded (~10^4 expressions) but whose
   *wall-clock* matters (eval is the thing we are trying to make faster), fast
   compile is worth far more than a 2-14% codegen edge that LLVM would buy. The
   whole project exists to reduce eval latency; a backend that spends that latency
   in the compiler defeats the purpose.
2. **Pure Rust, hermetic.** `aos-nix` is a Rust crate in a hermetic, build-from-source
   distro. Cranelift is a Rust dependency with no C++ toolchain, no external
   `libLLVM`, no version-skew surface against the host. This fits the AOS ethos
   ([CLAUDE.md hermetic-build principles](14-integration-with-aos.md)) far better
   than vendoring and building LLVM.
3. **First-class JIT story.** `cranelift-jit` provides `JITBuilder`/`JITModule` with
   exactly the host-symbol-resolution mechanism the runtime ABI needs:
   `JITBuilder::symbol` registers a host function under a name, and the JIT resolves
   declared-but-undefined names (our `aos_*` runtime functions) against that symbol
   table
   ([`cranelift_jit::JITBuilder` docs](https://docs.wasmtime.dev/api/cranelift_jit/struct.JITBuilder.html);
   [`JITModule` docs](https://docs.rs/cranelift-jit/latest/cranelift_jit/struct.JITModule.html)).
   This is precisely the [§7](#7-the-runtime-abi) substrate.
4. **GC stack-map support that fits a precise GC.** Cranelift's "user stack maps"
   let the frontend declare safepoints and the live GC references spilled at them,
   so an *external* precise collector can find roots in compiled frames
   ([Fitzgerald, "New Stack Maps for Wasmtime and Cranelift"](https://fitzgen.com/2024/09/10/new-stack-maps-for-wasmtime.html);
   [Bytecode Alliance, "New Stack Maps for Wasmtime and Cranelift"](https://bytecodealliance.org/articles/new-stack-maps-for-wasmtime)).
   This is exactly what the daemon-mode generational collector
   ([06](06-memory-management-and-gc.md)) requires. See [§6](#6-cranelift-the-gc-and-stack-maps).

**Executable-memory portability (Linux + macOS).** aos-nix targets both Linux
and macOS ([scope and platform](23-scope-platform-and-modes.md) §3.5), and
writing-then-executing JIT code is the one place the OS shows through. On Linux
the JIT maps a buffer, writes code, and `mprotect`s it executable. On Apple
Silicon (`aarch64-darwin`) the hardened runtime enforces W^X, so executable
pages must be mapped with `MAP_JIT` and the writer must toggle protection
per-thread via `pthread_jit_write_protect_np()` around code emission — macOS-only
plumbing behind `#[cfg(all(target_os = "macos", target_arch = "aarch64"))]`.
`cranelift-jit`'s memory manager encapsulates most of this, but the requirement
is called out because it is the JIT's one genuinely OS-divergent path; it changes
*how* code is installed, never *what* the code computes, so it has no bearing on
`.drv` output.

### 5.2 Not LLVM

LLVM produces better code (Cranelift is ~14% slower than a WAVM/LLVM Wasm pipeline
in steady state per the Wasmtime comparison) but compiles roughly 10x slower
([Wasmtime `compare-llvm.md`](https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/docs/compare-llvm.md)).
For a JIT that wants low warmup, that trade is backwards. LLVM also drags in a heavy
C++ build and a large API-stability surface that is a poor fit for hermetic
from-source builds.

LLVM is, however, retained as an **optional AOT cache tier** for a *stable hot
core*: the small set of expressions that are hot on essentially every AOS
evaluation (the nixpkgs `stdenv` / `mkDerivation` machinery, the standard library
prelude) could be compiled *ahead of time* with LLVM, once, cached
content-addressed, and loaded as native code with no JIT warmup at all. Because that
set is small, stable, and shared across every CI machine, the slow LLVM compile is
paid once and amortized across the entire fleet — the same logic the
[incremental cache](12-incremental-evaluation-cache.md) applies to *values*, applied
to *code*. This is an advanced measured variant, not a phase-1 item, and it is
strictly additive: it never replaces Cranelift, it pre-warms a fixed prefix.

### 5.3 Not WASM

Compiling Nix to WebAssembly and running it on Wasmtime would give portability and
a sandbox. We need neither:

- **Sandboxing is a cost, not a benefit, here.** `aos-nix` runs trusted code (the
  AOS package set) in-process. A Wasm sandbox adds a host-boundary crossing on every
  call from guest code back to the runtime (force, alloc, primops) — and our design
  is *built around* such calls being cheap, in-process, register-passing C calls
  ([§7](#7-the-runtime-abi)).
- **The custom GC fights the Wasm boundary.** Our precise generational/region GC
  ([06](06-memory-management-and-gc.md)) needs direct access to the value heap and
  to compiled-frame stack maps. Wasm's linear memory and the still-maturing Wasm-GC
  proposal would force us to either run our heap inside linear memory (losing the
  host-native layout and the precise collector) or marshal across the boundary
  constantly. Cranelift gives us native frames and user stack maps *without* a
  sandbox boundary.
- **Portability is a non-goal.** AOS targets x86-64 and aarch64 Linux. Cranelift
  covers those directly.

WASM solves problems (untrusted code, browser portability) that `aos-nix` does not
have, while taxing the things it does care about (call cost, GC integration). It is
rejected.

### 5.4 Copy-and-patch: a noted alternative baseline

Copy-and-patch compilation
([Xu & Kjolstad, OOPSLA 2021, "Copy-and-Patch Compilation"](https://arxiv.org/pdf/2011.13127);
[ACM DOI 10.1145/3485513](https://dl.acm.org/doi/abs/10.1145/3485513))
stitches together pre-compiled machine-code "stencils," patching in constants and
addresses, to produce native code with *microsecond* compile times — far faster
even than Cranelift's baseline. It is the technique behind the CPython 3.13 JIT
([PEP 744](https://peps.python.org/pep-0744/)) and the WasmNow Wasm baseline
compiler. For a tier-1 whose job is "remove interpreter overhead with the least
possible compile cost," copy-and-patch is arguably a *better* fit than Cranelift
baseline.

It is noted as a candidate **tier-1 replacement** (not a tier-2 backend — it does
no real optimization) and explicitly deferred. The reasons to start with Cranelift
for both compiled tiers are pragmatic: a single backend for tier 1 and tier 2 means
one lowering, one ABI, one set of stack-map plumbing, and one dependency. Adopting
copy-and-patch for tier 1 would mean authoring and maintaining a stencil library
(arch-specific, and a fresh source of `unsafe`), which is only worth it if profiling
shows tier-1 *compile time* — not tier-1 *code quality* — is a measured bottleneck.
That is an open question to be settled by data, in keeping with measure-first.

---

## 6. Cranelift, the GC, and stack maps

The engine and the [garbage collector](06-memory-management-and-gc.md) meet at one
place: **the collector must find live value-references inside compiled stack
frames.** In one-shot CLI mode (Tier A heap: bump-pointer arena, never free, drop at
exit) this is a non-issue — there is no collection, so there are no roots to find.
In daemon mode (Tier B heap: precise generational copying collector) it is central,
because a copying collector *moves* objects and must update every reference,
including those held in registers and stack slots of running compiled code.

Modern Cranelift puts this obligation on the frontend via **user stack maps**: the
code generator (us) is responsible for emitting CLIF that already contains the
safepoint spills/reloads and for annotating each safepoint with the stack slots
holding live GC references
([Fitzgerald, "New Stack Maps for Wasmtime and Cranelift"](https://fitzgen.com/2024/09/10/new-stack-maps-for-wasmtime.html)).
Cranelift itself does **not** ship a garbage collector; it provides the
safepoint/stack-map infrastructure for an external collector
([Bytecode Alliance article](https://bytecodealliance.org/articles/new-stack-maps-for-wasmtime)).
That division of labor is exactly what we want: our collector is precise and
custom, and Cranelift gives us the root-finding hooks without imposing a GC policy.

Consequences for the tier design:

- **Tiers 1 and 2 emit safepoints and stack maps unconditionally**, even though the
  CLI mode never collects. The cost is small and it keeps a single code path; the
  daemon mode simply *consumes* the maps the CLI mode *ignores*.
- **Safepoints are placed at allocation sites and at calls to `aos_force`** — the
  only places a collection can be triggered (allocation may exhaust the nursery;
  forcing may allocate). Between safepoints, references may live in registers
  untracked, which is sound because no collection can happen there.
- **The precise collector eliminates Boehm-style false retention.** C++ Nix uses
  the Boehm conservative collector, whose imprecision (treating any stack word that
  *looks* like a pointer as a root) both retains garbage and is a dominant cost. A
  precise collector keyed on Cranelift stack maps has neither problem; replacing
  Boehm is one of the named wins of the whole project
  ([06](06-memory-management-and-gc.md)).

The interaction between *concurrent* low-pause collection (ZGC/Shenandoah-style
colored pointers and load barriers, daemon mode only) and the JIT — specifically,
emitting load barriers in tier-2 code — is the hardest open problem in this area and
is owned by [13-parallel-evaluation.md](13-parallel-evaluation.md) and
[06](06-memory-management-and-gc.md). For this document it suffices that the
single-threaded precise generational collector needs only safepoints + user stack
maps, both of which Cranelift supplies.

---

## 7. The runtime ABI

The runtime ABI is the contract between compiled code (any tier) and the host
runtime written in Rust. It is the spine that makes tiering possible: because all
non-trivial work is a *call to a named runtime symbol*, swapping a thunk's tier
(swapping `code_ptr`) changes only the caller, never the callees, and the value
heap, GC, primops, and store logic are written **once** in Rust and shared by all
three tiers.

### 7.1 The uniform calling convention

Every compiled thunk body and lambda body has the **same C ABI signature**:

```rust
/// The uniform entry signature shared by every compiled thunk and lambda body,
/// across all execution tiers.
///
/// - `rt`  is the per-evaluation [`Runtime`] (heap, symbol table, profile,
///   inline-cache cells, store handle).
/// - `env` is the captured environment frame (de Bruijn-indexed slots).
/// - `arg` is present only for lambda bodies (a single applied argument; Nix
///   lambdas are curried, so multi-arg functions are nested single-arg lambdas).
///
/// Returns a [`Value`] (the 16-byte tagged representation, or a NaN-boxed 64-bit
/// value once that optimization is enabled) passed in registers per the platform
/// C ABI.
type ThunkFn  = extern "C" fn(rt: *mut Runtime, env: *const Env) -> Value;
type LambdaFn = extern "C" fn(rt: *mut Runtime, env: *const Env, arg: Value) -> Value;
```

`extern "C"` is mandatory: Cranelift generates code against a stable C calling
convention, and the host registers its runtime functions as C symbols. The `*mut
Runtime` / `*const Env` raw pointers and the by-register `Value` are the
**justified `unsafe` surface** of the crate (per the [unsafe policy](14-integration-with-aos.md));
they are wrapped in safe Rust at the boundary and the tree-walk oracle never uses
them.

### 7.2 The runtime symbol table

The host exposes a fixed set of `extern "C"` functions to compiled code by
registering each with `JITBuilder::symbol`, which populates the JIT's symbol table
used to resolve names "declared, but not defined, in the module being compiled"
([`cranelift_jit::JITBuilder` docs](https://docs.wasmtime.dev/api/cranelift_jit/struct.JITBuilder.html)).
The core set:

| Symbol | Signature (C) | Purpose |
|--------|---------------|---------|
| `aos_force` | `(rt, Value) -> Value` | Force a thunk to WHNF: state-check, blackhole, call `code_ptr`, cache, return. The hottest runtime call. |
| `aos_apply` | `(rt, Value fn, Value arg) -> Value` | Apply a (forced) lambda or partial application to one argument. |
| `aos_alloc_thunk` | `(rt, code_ptr, env) -> Value` | Allocate a suspended thunk. Routes through the active GC strategy (arena or generational). |
| `aos_alloc_attrs` | `(rt, shape, *fields) -> Value` | Allocate an attrset of a given [hidden class](09-attribute-sets-hidden-classes-and-inline-caches.md). |
| `aos_select_ic` | `(rt, Value attrs, sym, ic_site) -> Value` | Attribute select through a per-site [inline cache](09-attribute-sets-hidden-classes-and-inline-caches.md). |
| `aos_env_get` | `(env, slot) -> Value` | Read a de Bruijn env slot. |
| `nix.builtin.<name>` | `(rt, args...) -> Value` | One symbol per [builtin](10-primops-and-runtime-abi.md) (~120). Dispatched by perfect hashing where indirect. |
| `aos_deopt` | `(rt, deopt_record) -> Value` | Reconstruct abstract state and re-enter the tier-0 oracle (§3). |
| `aos_throw` | `(rt, err) -> !` | Raise a Nix-compatible evaluation error (e.g. infinite recursion, type error), matching C++ Nix's message for the [harness](15-differential-testing-and-benchmarking.md). |

The `nix.builtin.<name>` symbols, including `nix.builtin.derivationStrict`, are the
**dialect escape hatch** ([generalization and language dialects](28-generalization-and-language-dialects.md)
§5): the builtin identities and their runtime symbols are supplied by the Nix
dialect, while the ABI *mechanism* — the uniform signature, register-passing, and
`JITBuilder::symbol` registration — is entirely generic. A dialect registers its
primops into this table; the engine that calls them knows only the generic shape.

Two properties of this table are essential:

1. **The ABI is GC-strategy-agnostic.** All allocation goes through `aos_alloc_*`.
   When the heap strategy swaps from bump-arena (CLI) to generational copying
   (daemon), **compiled code does not change** — only the body of `aos_alloc_*`
   changes. This is the canon's explicit requirement and is what lets the same
   compiled artifact run under either heap, and lets the JIT be developed before the
   GC is finished.
2. **The ABI is tier-agnostic.** Tier 0 calls these same functions (as ordinary
   Rust calls); tier 1 calls them as C calls; tier 2 inlines some of them. The
   *semantics* of force, apply, select, and every primop are written once and never
   forked per tier — eliminating an entire class of "the JIT does X but the
   interpreter does Y" divergence bugs that would otherwise threaten `.drv` parity.

### 7.3 Import and parse caching at the ABI seam

`import` is a runtime call (`nix.builtin.import`) that resolves a path to a realpath,
content-hashes it, and returns the cached parsed+compiled module if present
([10](10-primops-and-runtime-abi.md), [12](12-incremental-evaluation-cache.md)). It
is part of the ABI because compiled code triggers imports, and the cache it consults
is the same content-addressed parse cache the frontend populates
([04](04-frontend-parser-and-ir.md)). This is where the execution engine meets the
incremental layer: a forced `import` of an unchanged file is a cache hit that
returns an already-compiled module with no parsing and no compilation — the
"fastest evaluator is the one that does not evaluate" mantra
([12](12-incremental-evaluation-cache.md)) realized at the call level.

---

## 8. Determinism and the compatibility constraint

Tiering must be **observationally invisible**. The [hard constraint](02-compatibility-constraints.md)
is byte-identical `.drv` files and store paths (SHA-256), exact string contexts, and
the same errors. The tier that produced a value **must never be observable** in the
output. Concretely:

- **No tier may reorder attrset iteration.** Deterministic attr order is required
  for compatibility ([09](09-attribute-sets-hidden-classes-and-inline-caches.md));
  a tier-2 shape specialization that changed iteration order would change
  `derivationStrict`'s env serialization and thus the `.drv`. Shape transitions
  preserve insertion/sorted order by construction.
- **No tier may change evaluation order in a way that changes observed errors.**
  Strictness analysis ([07](07-laziness-and-whole-program-analyses.md)) may force a
  binding *earlier*, but only when it has proven the binding is *unconditionally*
  forced — so the error (if any) was going to happen anyway. A binding that is only
  *conditionally* forced is never made eager. This is the soundness side condition
  on every eager-forcing optimization, and it is exactly what keeps the tree-walk
  oracle and the JIT in agreement.
- **Deopt is value-identical to no-speculation (§3.1).** Because the deopt target is
  the oracle and Nix is effect-free, a deopt cannot change the produced value or
  context. The harness diffs `.drv` output with the JIT both *off* and *on*; the two
  must be byte-identical.
- **The harness is the gate.** The differential `.drv`-diff harness against
  `nix-instantiate` across the AOS package set is run with tier 0 only, then with
  tiers 1+2 enabled. `AOS_NIX_NATIVE` ([14](14-integration-with-aos.md)) stays
  **off by default** until both are green on the full closure, and `NixCli`
  subprocess fallback is permanent. A single divergent `.drv` means a total cache
  miss and a from-source toolchain rebuild — the catastrophe the whole design is
  organized to avoid.

The discipline is: **tier 0 defines the meaning; tiers 1 and 2 are accelerators that
are required to agree with it bit-for-bit.** Speculation, scalar replacement, eager
forcing, and inlining are all only ever *performance* transforms over a fixed
denotation, and each carries a soundness side condition checked against the oracle.

---

## 9. How purity sharpens every borrowed technique

A recurring theme: each technique is borrowed from a system that had to defend it
against mutation, dynamic loading, or side effects — defenses Nix renders
unnecessary. This is the "synthesis thesis" of [03](03-architecture-overview.md)
applied to the execution engine.

| Technique | Source system | What that system must defend against | Why Nix makes it total/sound |
|-----------|--------------|--------------------------------------|------------------------------|
| Tiered compilation + deopt | HotSpot | Side effects partially performed before a deopt; rollback | No side effects: deopt is pure state reconstruction, no rollback |
| Shape/type speculation | V8 / TurboFan | Mutable objects change shape; properties added at runtime | Immutable values: a value's shape is fixed for its lifetime |
| Escape analysis + scalar replacement | HotSpot | Aliasing through mutation; identity-sensitive ops | Immutable, identity-free values: far more objects provably don't escape |
| Strictness / worker-wrapper eager compile | GHC | (Already sound in Haskell; absent in C++ Nix and Snix) | Pure + whole-program closure: analysis is total over the batch |
| Inline caches | HotSpot / V8 | Class redefinition, megamorphic deopt | No eval-time code loading: the call-site population is fixed |
| Stack-map precise GC | JVM/Cranelift users | Conservative scanning false retention | Precise maps eliminate Boehm false retention entirely |

The execution engine is not novel in its parts — every tier and trap and cache has a
named ancestor. The novelty is that **the substrate (a pure, immutable, whole-program,
batch language) upgrades each borrowed technique from "partial and carefully guarded"
to "total and structurally sound,"** which is precisely why importing the JVM/V8/GHC
playbook into a Nix evaluator is expected to pay off more than it does in the
languages those techniques came from.

---

## 10. Open questions

These are explicitly unresolved and to be settled by measurement against the AOS
package set, not by assertion:

1. **Does the JIT earn its keep at all?** If the [incremental early-cutoff cache](12-incremental-evaluation-cache.md)
   plus bump-arena heap plus tier-0 oracle already beat `nix-instantiate`
   wall-clock, tiers 1 and 2 may be unnecessary. The roadmap deliberately ranks the
   cache above the JIT. **Measure first.**
2. **Scalar replacement across deopt points (§3.2).** Materializing an
   escape-eliminated object on the deopt path is the subtlest correctness item. The
   conservative initial policy (never scalar-replace across a deopt point) may be
   too conservative to capture the benefit; tightening it is gated on the harness.
3. **Is OSR (§3.3) worth its complexity?** Its benefit is bounded to a few
   long-running single activations. Whether the AOS workload has enough of those to
   justify mid-flight tier swaps is unknown until profiled.
4. **Copy-and-patch vs Cranelift for tier 1 (§5.4).** If tier-1 *compile time* (not
   code quality) shows up as a bottleneck, a copy-and-patch stencil baseline could
   replace Cranelift baseline. This trades a maintenance/`unsafe` cost for warmup;
   it is data-driven.
5. **NaN-boxing interaction with the ABI.** The first cut passes a 16-byte tagged
   `Value` by register; Nix `i64` does not fit a NaN-box payload
   ([05](05-value-representation.md)). Whether the NaN-boxing optimization (and its
   i64-out-of-line handling) is a net win once the C ABI register-passing of a
   16-byte value is measured is open.
6. **Tier-2 + concurrent GC load barriers.** Emitting Shenandoah/ZGC-style load
   barriers in tier-2 code (daemon mode) is the hardest GC/JIT interaction and is
   owned jointly with [06](06-memory-management-and-gc.md) and
   [13](13-parallel-evaluation.md). It is out of scope for the single-threaded,
   precise-generational first cut.
7. **Cranelift API stability for user stack maps.** The user-stack-maps API is
   relatively new ([Fitzgerald, 2024](https://fitzgen.com/2024/09/10/new-stack-maps-for-wasmtime.html));
   we should expect churn and pin a Cranelift revision, mirroring the
   pin-and-upstream policy for `nix-compat` ([11](11-derivation-and-store-compatibility.md)).

---

## 11. Summary

- The expression-to-activation ratio (~10^4 vs ~10^9) mandates **compile
  per-expression once, call per-activation**, not interpret per-activation.
- Three tiers, HotSpot-style: a permanent **tree-walk oracle** (correctness,
  cold code, debugging, the safe miri-checked island); a **Cranelift baseline JIT**
  that removes interpreter overhead with fast compile; a **Cranelift optimized JIT**
  that bakes in profile-guided shape/type speculations, strictness, and escape
  analysis, guarded by **deoptimization** back to the oracle and (as a follow-up)
  **OSR** into running activations.
- A **uniform `extern "C"` ABI** (`ThunkFn`/`LambdaFn`) plus a fixed **runtime
  symbol table** (`aos_force`, `aos_alloc_*`, `aos_select_ic`, `nix.builtin.*`,
  `aos_deopt`) makes the engine GC-strategy-agnostic and tier-agnostic: semantics
  are written once in Rust, and a tier swap is a `code_ptr` swap.
- **Cranelift** is chosen for fast warmup, pure-Rust hermeticity, a first-class JIT
  symbol API, and user-stack-map support for a precise external GC. **LLVM** is
  rejected for warmup (kept only as an optional AOT cache tier for a stable hot
  core), **WASM** for its sandbox/boundary cost against our custom GC, and
  **copy-and-patch** is a noted, deferred tier-1 alternative.
- Purity is the multiplier: deopt has no effects to roll back, shapes never mutate,
  more objects provably don't escape, and analyses are total over the whole-program
  batch — so the borrowed JVM/V8/GHC techniques become *more* effective here than in
  their home languages.
- All of it is downstream of **measure-first** and the **byte-identical `.drv`
  acceptance gate**: tiers are observationally invisible, the oracle defines the
  meaning, the harness is the judge, and `AOS_NIX_NATIVE` stays off until green.

---

## Implementation checklist

Per-feature tracker for the execution tiers and the Cranelift JIT; master
roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md).
Per the unlimited-budget mandate, every item here is in scope — including
research-grade ones — built in dependency order and gated by the differential
harness, never cut for scope.

### Tier 0 — the tree-walk oracle (foundation)

- [x] Current Tier-0 safe tree-walk oracle core: recursive evaluator over the
      lowered IR in `aos_nix::eval::TreeWalk`, `aos-nix` fenced with
      `#![forbid(unsafe_code)]`, no raw function pointers or JIT path, and
      internal-diff hooks for future tier comparison ([§2.1](#21-tier-0--the-tree-walk-oracle)) — P1, `S-3`/`S-5`; gate today: focused tree-walk/thunk tests.
- [ ] Future deopt-target integration: optimized tiers must carry enough deopt
      metadata and resume state to land failed speculation back in the tree-walk
      oracle ([§2.1](#21-tier-0--the-tree-walk-oracle), [§5](#5-deoptimization-and-osr)) — P6/P7, `S-3`/`S-5`; gate: differential identity vs tier-0 oracle.
- [x] Current serial thunk machine `Suspended → Blackhole → Forced` with
      *infinite recursion encountered* on a forced black hole, backed by the P1
      atomic thunk state word ([§1.2](#12-the-execution-unit-thunk-and-lambda)) — P1, `C-12`; gate today: focused thunk lifecycle tests.
- [ ] Parallel thunk superset (`Pending`/`Awaited`/`Failed` states, waiters,
      cross-thread publication, and loom/Miri/TSan proof) layered over the serial
      state machine ([§1.2](#12-the-execution-unit-thunk-and-lambda), [13 §3.5](13-parallelism-and-concurrency.md#35-thunks-in-parallel)) — P3.5, `C-12`; gate: conformance 20-21 plus concurrency tests.
- [ ] Degenerate per-site inline cache on tier-0 select nodes (optional, toggleable off for cross-checking) ([§4](#4-the-compilation-pipeline), [09 §5.3](09-attribute-sets-hidden-classes-and-inline-caches.md)) — P5.
- [x] Current Tier-0 source-span diagnostic substrate: source-backed diagnostics
      cover lexer/parser/scope/IR/tree-walk errors, imported source provenance,
      operand and logical eval-context labels, and `addErrorContext` context
      ordering; this is the diagnostic substrate tracked in [24](24-observability-and-diagnostics.md),
      not a stepping/debugger UI ([§2.1](#21-tier-0--the-tree-walk-oracle)) — P1. Covered by
      `parse_diagnostic_reports_code_label_and_source`,
      `eval_diagnostic_reports_operand_type_spans`,
      `eval_diagnostic_reports_add_error_context_labels`,
      `embedded_eval_diagnostic_filters_context_labels_from_other_sources`, and
      `add_error_context_preserves_outer_to_inner_context_order`.
- [ ] Full source-span evaluation trace and stepping workflow remains: a trace
      stream/step controls, full `--show-trace` reconstruction, debugger or REPL
      integration, and `.drv` divergence-debugging workflow over those traces
      ([§2.1](#21-tier-0--the-tree-walk-oracle); [24](24-observability-and-diagnostics.md)
      §5–§6) — P1.

### Runtime ABI and symbol table (the tier-invariant spine)

- [ ] Uniform `extern "C"` `ThunkFn`/`LambdaFn` signature `(rt, env[, arg]) -> Value`, 16-byte `Value` register-passed ([§7.1](#71-the-uniform-calling-convention)) — P6, `S-4`/`S-12`; gate: differential `.drv` harness.
- [x] Current uniform runtime-call ABI metadata precursor:
      `ratchet-core::runtime_abi` publishes safe `RuntimeCallSignature`
      descriptors for the compiled thunk-body, compiled lambda-body, and
      builtin-primop call shapes. The descriptors pin `extern "C"`, the shared
      `rt`/`env` prefix, lambda and primop `Value` arguments, `Value` returns,
      and the 16-byte/two-register value layout, with tests cross-checking the
      covered primop arities against the builtin declaration inventory. This is
      ABI contract metadata only; it is not an exported `ThunkFn`/`LambdaFn`
      wrapper, raw-pointer call boundary, Cranelift lowering, or
      `JITBuilder::symbol` registration.
- [x] Current builtin runtime-call preflight precursor:
      `runtime_builtin_call_manifest()` keeps `nix.builtin.*` symbols in stable
      runtime-manifest order and classifies each builtin as callable
      primop-wrapper metadata, a value-only builtin symbol, or an unsupported
      arity. The preflight attaches frozen `RuntimeCallSignature` metadata for
      callable builtins while reporting value-only builtin symbols as gaps.
      Tests cover sorted symbol parity, representative callable arities,
      value-only gaps, and unsupported-arity handling. This is not Cranelift
      lowering or symbol registration: no builtin wrapper addresses, exported C
      ABI functions, raw-pointer calls, or `JITBuilder::symbol` entries exist
      here.
- [ ] Runtime symbol table registered via `JITBuilder::symbol`: `aos_force`, `aos_apply`, `aos_alloc_thunk`, `aos_alloc_attrs`, `aos_select_ic`, `aos_env_get`, `nix.builtin.<name>`, `aos_deopt`, `aos_throw` ([§7.2](#72-the-runtime-symbol-table)) — P6, `S-12`.
- [x] Current P1 tree-walk allocation substrate: `EvalHeap` routes tree-walk
      heap object creation through `BumpArena::aos_alloc_*`
      entry-point-shaped Rust helpers for strings and paths, contiguous lists,
      attrs, lambdas, primops, thunks, and raw records, giving the safe oracle a
      single allocation helper surface and arena accounting. This is direct Rust
      plumbing, not the frozen runtime/JIT ABI
      ([06](06-memory-management-and-gc.md) §2).
- [ ] Frozen runtime/JIT allocation indirection remains: `aos_alloc_*` exported
      as `unsafe extern "C"` or equivalent runtime symbols, registered with
      `JITBuilder::symbol`, bound to the selected allocator vtable at native
      startup, routed through every tier/primop allocation path, and swappable
      between bump-arena and generational bodies with byte-identical compiled code
      ([§7.2](#72-the-runtime-symbol-table)) — P3/P6, `S-8`.
- [x] Current allocation-symbol binding precursor:
      `ratchet-oracle::runtime::alloc::RuntimeAllocationEntryPoint` exposes and
      round-trips the frozen `aos_alloc_*` symbol name for each safe tree-walk
      allocation route, with tests cross-checking the inventory against
      `ratchet-core`'s allocation helper symbol table. This prevents drift
      between the oracle allocator surface and future JIT registration metadata,
      but it is not yet exported C ABI glue or Cranelift registration.
- [x] Current runtime symbol-manifest precursor:
      `ratchet-core::runtime_abi::runtime_symbol_manifest()` builds the
      deterministic, lexicographically sorted symbol table that future
      `JITBuilder::symbol` setup can consume before attaching executable
      addresses. The manifest combines every `aos_*` helper and every declared
      `nix.builtin.*` builtin, validates duplicate final symbol names, and tags
      helper entries by `RuntimeHelperRole` while tagging builtin entries
      separately. Tests cover full helper/builtin coverage, sorted uniqueness,
      duplicate rejection, and representative helper/builtin lookups. This is
      registration metadata only; exported wrappers, Cranelift module
      construction, address binding, and compiled artifact relinking remain open.
- [x] Current runtime symbol binding-manifest precursor:
      `ratchet-oracle::runtime::helpers::runtime_symbol_binding_manifest()`
      consumes the core runtime symbol manifest and preserves its order while
      classifying each symbol as a currently bound allocation/write-barrier
      helper, an unbound future helper role, or a builtin. Tests cross-check
      core-manifest order, exact safe-helper binding coverage, representative
      unbound helpers such as `aos_force` and `aos_apply`, and a representative
      builtin symbol. This is binding-status metadata only; it attaches no
      function pointers, exports no wrappers, registers no Cranelift symbols,
      and leaves builtin/forcing/call/attr/error helper addresses unbound.
- [x] Current runtime symbol registration-preflight precursor:
      `ratchet-oracle::runtime::helpers::runtime_symbol_registration_preflight()`
      turns the binding manifest into a deterministic readiness report for
      future `JITBuilder::symbol` setup: currently bindable helper metadata is
      preserved in manifest order, and every unbound helper or builtin is
      reported in the same stable order. The stricter
      `runtime_symbol_registration_plan()` refuses to produce complete
      registration metadata while missing bindings remain. Tests cover helper
      readiness, sorted missing bindings, representative forcing/call helpers,
      builtin gaps, and the current incomplete-plan error. This is a preflight
      gate only; it attaches no executable addresses and performs no Cranelift
      registration.
- [x] Current runtime symbol ABI-signature preflight precursor:
      `runtime_symbol_abi_signature_preflight()` combines safe helper ABI
      metadata with builtin call-shape metadata in stable runtime symbol order:
      allocation/write-barrier helper signatures and callable builtin
      `RuntimeCallSignature` entries are bindable metadata, while unbound helper
      roles and value-only builtin symbols stay in the gap report. Tests pin
      helper parity with the safe registration preflight, builtin parity with the
      builtin call preflight, exact binding/gap projection order,
      representative callable builtin metadata, and current helper/value-only
      gaps. This does not attach executable addresses, export wrappers, lower
      Cranelift IR, or call `JITBuilder::symbol`.
- [x] Current runtime symbol ABI-signature plan precursor:
      `runtime_symbol_abi_signature_plan()` is the checked completeness gate for
      that ABI-signature metadata. It returns a `RuntimeSymbolAbiSignaturePlan`
      only when the preflight has no gaps, and currently returns an incomplete
      error with the preserved preflight while helper/value-only gaps remain.
      Tests cover the missing count, representative current gaps, preserved
      callable builtin metadata, and a synthetic complete conversion. This is
      still metadata gating only; it does not attach executable addresses, export
      wrappers, lower Cranelift IR, or call `JITBuilder::symbol`.
- [x] Current runtime symbol native-target candidate preflight precursor:
      `runtime_symbol_native_target_candidate_preflight()` combines helper ABI
      metadata, helper Rust-callable availability, and builtin call-shape
      metadata into a target-readiness report. Allocation/write-barrier helpers
      are address-free symbol/role candidates for later wrapper generation, while
      unbound helpers, value-only builtins, and callable builtins without wrapper
      bodies stay in the gap report. Tests prove exact projection order, helper-callable
      parity, representative helper/value-only gaps, all callable builtin wrapper
      gaps, and no current helper-callable gaps. This does not attach executable
      addresses, export wrappers, lower Cranelift IR, or call
      `JITBuilder::symbol`.
- [x] Current runtime symbol native-target candidate plan precursor:
      `runtime_symbol_native_target_candidate_plan()` is the checked completeness
      gate over the address-free candidate preflight. It returns a
      `RuntimeSymbolNativeTargetCandidatePlan` only when no gaps remain and
      currently returns an incomplete error with the preserved preflight while
      helper and builtin wrapper gaps remain. Tests cover the missing count,
      representative address-free helper candidates, representative gaps, and a
      synthetic complete conversion. This does not attach executable addresses,
      export wrappers, lower Cranelift IR, or call `JITBuilder::symbol`.
- [x] Current `ratchet-jit` crate-boundary precursor:
      `ratchet-jit` is now a workspace crate with
      `#![deny(unsafe_op_in_unsafe_fn)]`, crate-level docs for the future unsafe
      execution-tier boundary, and a safe `abi` module. `abi` mirrors
      the frozen thunk, lambda, and primop `RuntimeCallSignature` metadata from
      `ratchet-core`, while runtime-symbol candidate gates remain in
      `ratchet-oracle` until a lower shared metadata layer exists. Tests prove ABI
      metadata parity and callable-kind coverage. This adds no oracle dependency,
      Cranelift dependency, exported wrappers, raw function-pointer calls,
      executable addresses, or `JITBuilder::symbol` registration.
- [x] Current `ratchet-jit` runtime-symbol inventory precursor:
      `ratchet-jit::symbols::jit_runtime_symbol_inventory()` mirrors the
      address-free `ratchet-core` runtime symbol manifest inside the JIT crate
      without depending on `ratchet-oracle`. It preserves core manifest order,
      exposes symbol-presence and kind lookups, and tests pin exact manifest
      parity, representative helper/builtin kinds, sorted order, and mixed
      helper/builtin coverage. This remains symbol metadata only: no candidate
      readiness, executable addresses, Cranelift lowering, exported wrappers, or
      `JITBuilder::symbol` registration is implemented.
- [x] Current `ratchet-jit` tier-up policy precursor:
      `ratchet-jit::tier::TierUpPolicy` names the tier-0 to tier-1 hotness
      decision as safe policy metadata: a low default invocation threshold plus
      optional accepted multi-use evidence from profiling or cardinality
      analysis. `TierUpCounter` saturates invocation observations,
      `TierUpObservation` carries invocation, demand, and current-tier evidence,
      and `TierUpDecision` reports stay/promote decisions with target tier and
      reason bits. Tests pin threshold promotion, eager multi-use promotion,
      absent/once cardinality staying cold, disabled eager promotion, combined
      reasons, zero-threshold measurement tuning, counter saturation, and
      already-tier-1 no-repeat promotion. This does not store counters beside
      thunks, mutate thunk state or code pointers, lower Cranelift IR, compile
      native code, install OSR, or run tier-1 code.
- [x] Current runtime symbol Rust-callable preflight precursor:
      `runtime_symbol_rust_callable_preflight()` preserves the stable runtime
      symbol order while attaching process-local Rust-callable metadata for the
      currently covered allocation/write-barrier helpers and reporting the same
      unbound helper/builtin gaps as the safe registration preflight. Tests pin
      helper-callable order, symbol parity with the safe helper preflight, and
      gap parity with the incomplete registration report. This is not
      `JITBuilder::symbol` registration: the addresses are Rust-callable
      storage-wrapper metadata only, not exported C ABI targets or final native
      call targets.
- [x] Current allocation ABI-signature precursor:
      `RuntimeAllocationAbiSignature` records the success-path native parameter
      and typed pointer-result shape for each `aos_alloc_*` helper, preserves the
      same order as the allocation entry-point inventory, and resolves from the
      frozen symbol name for future registration code. This remains metadata only;
      exported `unsafe extern "C"` wrappers, executable trap-transfer behavior,
      `JITBuilder::symbol` registration, native startup binding, and Tier-B body
      swapping remain open.
- [x] Current allocation-vtable precursor:
      internal `RuntimeAllocationVTable` dispatch is selected from the installed
      `RuntimeAllocator` backend and carries typed safe Rust function pointers for
      every frozen `aos_alloc_*` route. The tree-walk allocator entry points
      dispatch through that table before reaching the current Tier-A `BumpArena`
      bodies, and tests exercise both selected-table metadata and direct vtable
      allocation calls inside the crate. This is internal safe Rust dispatch
      only; exported wrappers, Cranelift symbol registration, native trap
      transfer, and Tier-B vtable installation remain open.
- [x] Current runtime-helper failure-convention precursor:
      `RuntimeHelperBinding::failure_convention` pins every currently bound
      allocation and write-barrier helper as `TrapToEvaluator`, so the native ABI
      has no null-pointer or sentinel failure result: helpers return only on
      success, while allocation or barrier failures must transfer to evaluator
      trap/error machinery. Tests pin the convention for each `aos_alloc_*` and
      `aos_gc_write_barrier` symbol. This remains metadata only; exported
      wrappers, actual trap transfer, `JITBuilder::symbol` registration, and
      native startup binding remain open.
- [ ] `import` at the ABI seam (`nix.builtin.import`) consulting the content-addressed parse + result cache ([§7.3](#73-import-and-parse-caching-at-the-abi-seam), [12](12-incremental-evaluation-cache.md)) — P2, `S-12`.

### Tier 1 — the Cranelift baseline JIT

- [ ] IR → Cranelift CLIF tree-directed lowering, fully generic (boxed values, generic `select`, runtime-checked arithmetic, every force a call) ([§2.2](#22-tier-1--the-cranelift-baseline-jit), [§4](#4-the-compilation-pipeline)) — P6, `S-3`/`S-5`; gate: differential identity vs tier-0 oracle.
- [ ] `JITBuilder`/`JITModule` construction + external-symbol resolution for the runtime ABI ([§5.1](#51-cranelift-the-chosen-backend)) — P6.
- [ ] Safepoints + user stack maps emitted **unconditionally** from tier 1 (frontend obligation; daemon GC root-finding) ([§2.2](#22-tier-1--the-cranelift-baseline-jit), [§6](#6-cranelift-the-gc-and-stack-maps)) — P6; gate: loom/miri once daemon GC lands.
- [ ] Counter-based tier-0 → tier-1 promotion (invocation counter beside `code_ptr`) ([§3.4](#34-promotion-policy)) — P6.
- [ ] Pin a Cranelift git revision (user-stack-maps API churn) ([§10](#10-open-questions)) — P6, `C-5`.

### Tier 2 — the Cranelift optimized JIT

- [ ] Shape speculation: guard `shape == expected` + constant-offset load, deopt on miss ([§2.3](#23-tier-2--the-cranelift-optimized-jit)) — P7, `S-5`; gate: differential `.drv` harness with deopt exercised.
- [ ] Type speculation: unboxed `i64` add guarded by tag check, deopt to boxed path ([§2.3](#23-tier-2--the-cranelift-optimized-jit)) — P7.
- [ ] Strictness baking / worker-wrapper: thunk-free eager compilation of proven-always-forced bindings ([§2.3](#23-tier-2--the-cranelift-optimized-jit), [07](07-laziness-and-whole-program-analyses.md)) — P7, `S-9`.
- [ ] Escape-analyzed scalar replacement of non-escaping attrsets/thunks ([§2.3](#23-tier-2--the-cranelift-optimized-jit)) — P7, `S-9`.
- [ ] Inlining + join points for small lambdas / partial applications, unboxed multi-returns ([§2.3](#23-tier-2--the-cranelift-optimized-jit)) — P7.
- [ ] Counter + profile-stability tier-1 → tier-2 promotion; per-guard deopt-count blacklisting ([§3.4](#34-promotion-policy)) — P7.

### Speculation, deoptimization, and OSR

- [ ] Uncommon-trap guards with a deopt edge per speculation ([§3.1](#31-uncommon-traps--deopt-points)) — P7, `S-5`; gate: differential `.drv` harness.
- [ ] `DeoptPoint` side tables (`ir_node`, `live_slots`, `scalar_repl`, `guard_kind`) reconstructing abstract state into the tier-0 oracle ([§3.2](#32-deopt-metadata)) — P7.
- [ ] Scalar-replaced-object **materialization** on the deopt path; first cut: never scalar-replace across a deopt point ([§3.2](#32-deopt-metadata)) — P7, `M-7`; gate: harness once tiering is real.
- [ ] On-stack replacement (OSR) into running activations (deep `foldl'` / long `genList` / `fix`-points) ([§3.3](#33-on-stack-replacement-osr)) — P7, `M-6`; gate: profile for long single activations.

### GC integration (Cranelift stack maps)

- [ ] Safepoints placed at allocation sites and `aos_force` calls; live-reference annotations consumed by the precise generational collector (daemon) ([§6](#6-cranelift-the-gc-and-stack-maps)) — P3/P7, `S-8`.
- [ ] Tier-2 + concurrent-GC load barriers (ZGC/Shenandoah colored pointers) — daemon-only ([§6](#6-cranelift-the-gc-and-stack-maps), [§10](#10-open-questions)) — P8, `R-2`/`R-3`/`R-4`; gate: loom/miri.

### Peak-throughput backends (alternative tier-1 / AOT, in scope under the budget mandate)

- [ ] **LLVM AOT tier-3** for the stable hot core (`stdenv`/`mkDerivation`/prelude): content-addressed ahead-of-time native compilation, loaded with zero JIT warmup, strictly additive to Cranelift ([§5.2](#52-not-llvm)) — P8; gate: benchmark + differential `.drv` harness.
- [ ] **Copy-and-patch** stencil baseline as an alternative tier 1 (microsecond compile) ([§5.4](#54-copy-and-patch-a-noted-alternative-baseline)) — P6/P8, `M-8`; gate: tier-1 compile-time benchmark.
- [ ] NaN-boxing of the register-passed `Value` and its i64-out-of-line handling across the ABI ([§10](#10-open-questions), [05](05-value-representation.md)) — P8, `M-4`; gate: register-passing benchmark.

### Determinism gate (observational invisibility)

- [ ] No tier reorders attr iteration; no tier changes observed-error order; deopt value-identical to no-speculation ([§8](#8-determinism-and-the-compatibility-constraint)) — every JIT phase, `S-2`; gate: differential `.drv` harness with native off vs on, byte-identical.

---

## References

- Cranelift project overview and design goals — <https://cranelift.dev/>
- Cranelift vs LLVM trade-off (compile speed vs code quality), Wasmtime docs —
  <https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/docs/compare-llvm.md>
- `cranelift_jit::JITBuilder` (host symbol registration / symbol-table resolution) —
  <https://docs.wasmtime.dev/api/cranelift_jit/struct.JITBuilder.html>
- `cranelift_jit::JITModule` —
  <https://docs.rs/cranelift-jit/latest/cranelift_jit/struct.JITModule.html>
- `rustc_codegen_cranelift` JIT driver (Cranelift as a JIT in production) —
  <https://github.com/rust-lang/rust/blob/main/compiler/rustc_codegen_cranelift/src/driver/jit.rs>
- New (user) stack maps for Wasmtime and Cranelift — Nick Fitzgerald —
  <https://fitzgen.com/2024/09/10/new-stack-maps-for-wasmtime.html>
- New stack maps for Wasmtime and Cranelift — Bytecode Alliance —
  <https://bytecodealliance.org/articles/new-stack-maps-for-wasmtime>
- HotSpot tiered compilation (C1/C2/interpreter, OSR, osr_bci) — Microsoft for Java
  Developers — <https://devblogs.microsoft.com/java/how-tiered-compilation-works-in-openjdk/>
- HotSpot deoptimization implementation — OpenJDK `deoptimization.cpp` —
  <https://github.com/openjdk/jdk/blob/master/src/hotspot/share/runtime/deoptimization.cpp>
- JVM JIT deep dive (C1, C2, tiered, uncommon traps, deopt) — w3computing —
  <https://www.w3computing.com/articles/jvm-jit-compiler-deep-dive-c1-c2-tiered-compilation/>
- Copy-and-Patch Compilation (Xu & Kjolstad, OOPSLA 2021), arXiv —
  <https://arxiv.org/pdf/2011.13127>; ACM DOI —
  <https://dl.acm.org/doi/abs/10.1145/3485513>
- CPython 3.13 copy-and-patch JIT — PEP 744 — <https://peps.python.org/pep-0744/>
- Snix (Tvix fork) component overview and `snix_eval` bytecode VM —
  <https://snix.dev/docs/components/overview/>,
  <https://snix.dev/rustdoc/snix_eval/index.html>
- OceanSprint 2025 report (Snix status, nix-compat factoring) —
  <https://oceansprint.org/reports/2025/>
