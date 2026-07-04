# RFC-0007 - Parallel Evaluation

> Part of the RFC-0007 aos-nix documentation set. This document covers how
> aos-nix exploits multiple cores: lock-free CAS thunks, work-stealing forcing,
> coarse top-level parallelism, and the hard interaction between parallel
> forcing and the precise garbage collector. It builds on
> [value representation](05-value-representation.md),
> [memory management and GC](06-memory-management-and-gc.md),
> [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md),
> and [the incremental evaluation cache](12-incremental-evaluation-cache.md).

> **Status (decision C-12): first-class, promoted early.** Parallel thunk-graph
> evaluation is no longer a rank-5 "measured follow-up" — it is a committed early
> phase (**P3.5** in [roadmap](17-roadmap-and-risks.md) §3): the L1 work-stealing
> pool (§4) and the L2 lock-free CAS thunk protocol (§3). Two guardrails make
> that safe rather than reckless: (1) the **sequential** tree-walk oracle stays
> the correctness ground truth the parallel tier is differentially diffed
> against, and (2) the parallel tier ships only after the `loom`/Miri
> memory-ordering audit (§3.2, R-4) is green — *no data races, ever*. What stays
> deferred is the **concurrent moving collector** (§5.3): it is a *separate*
> problem from parallel forcing, and one-shot CLI mode sidesteps it with
> per-worker bump nurseries + never-free.

## 1. Why parallelism, and why it is dangerous

A Nix evaluation of the AOS package set forces tens of thousands of top-level
derivations, each the root of a deep lazy thunk graph. On a modern build host
(the `builder-hil1-*` machines have many cores) a single-threaded evaluator
leaves all but one core idle while it grinds through `derivationStrict` for the
whole closure. Evaluation is embarrassingly parallel *in principle*: Nix is a
pure language, every value is immutable once forced, and two independent
derivations share no mutable state. There is no user-visible nondeterminism to
preserve — the same `.drv` files must come out regardless of how many threads
produced them (see [compatibility constraints](02-compatibility-constraints.md)).

The trap is that *purity is a property of values, not of the implementation*.
The thunk graph is **shared mutable state**: forcing a thunk overwrites it in
place, transitioning `Suspended -> Blackhole -> Forced` (see
[value representation](05-value-representation.md)). Two threads that reach the
same shared thunk — and sharing is the entire point of laziness, so this happens
constantly — race on that mutation. A naive parallel evaluator either:

1. **double-evaluates** the thunk (correct values, wasted work, and *broken
   infinite-recursion detection* because the blackhole no longer means "I am
   already forcing this"); or
2. **corrupts** the thunk by interleaving two in-place updates; or
3. **deadlocks** when thread A blocks on a thunk being forced by thread B while
   B blocks on a thunk being forced by A.

This is the same problem GHC solved for parallel Haskell, and the same problem
the C++ Nix multithreaded evaluator (edolstra's `NixOS/nix#10938`, shipped in
Determinate Nix 3.11.1) solved in 2024-2025. We adopt their proven protocol and
extend it with a coarser, lower-risk outer layer and a GC interaction design
that C++ Nix sidesteps only because it uses conservative Boehm GC — a luxury we
deliberately gave up (see [memory management and GC](06-memory-management-and-gc.md)).

> **Measurement checkpoint.** Parallel forcing is P3.5 on the RFC-0007 roadmap,
> not a phase-1 deliverable. The incremental early-cutoff cache (P2) and the
> bump-arena/precise-GC heap (P3) attack the systemic cost first. We trust the
> parallel tier only after the single-threaded evaluator is correct, the
> differential harness is green, and the `loom`/Miri memory-ordering audit is
> green. A parallel evaluator that races to the wrong answer is infinitely slower
> than a correct serial one, because a single divergent `.drv` triggers a
> from-source toolchain rebuild.

## 2. Design layers

aos-nix exposes parallelism at two granularities, with sharply different
risk/reward profiles. We build them in this order:

| Layer | Unit of parallelism | Shared mutable state | Risk | Status |
|-------|---------------------|----------------------|------|--------|
| **L1 — coarse top-level** | independent top-level derivations | only *immutable* tables (IR, symbols, hash-cons, primops) | low | first target |
| **L2 — lock-free forcing** | individual thunks | the thunk graph (CAS-claimed) | high | committed P3.5 target |

The thesis is that **L1 captures most of the available speedup at a fraction of
the complexity**, and L2 is only worth its danger once L1's load imbalance (a
few enormous derivations dominating the tail) is the measured limiter. We
describe L2 in full because its protocol is also what makes L1's *occasional*
cross-derivation sharing safe.

```text
                 aos-nix parallel evaluation

   ┌───────────────────────────────────────────────────────────┐
   │  L1: work-stealing pool over top-level derivations         │
   │                                                            │
   │   worker0      worker1      worker2      worker3           │
   │   ┌────┐       ┌────┐       ┌────┐       ┌────┐            │
   │   │drvA│       │drvB│       │drvC│       │drvD│  ← deques  │
   │   │drvE│       │drvF│       │ -- │  ◄────│drvG│  (steal)   │
   │   └────┘       └────┘       └────┘       └────┘            │
   │     │            │            │            │               │
   │  nursery0     nursery1     nursery2     nursery3  (private)│
   └─────┼────────────┼────────────┼────────────┼──────────────┘
         │            │            │            │
         └────────────┴─────┬──────┴────────────┘
                            ▼
        ┌──────────────────────────────────────────┐
        │ SHARED, IMMUTABLE (read-only after build):│
        │  • parsed/compiled IR (content-addressed) │
        │  • symbol table (u32 interning)           │
        │  • hash-cons table (maximal sharing)      │
        │  • primop registry / perfect-hash table   │
        │  • incremental eval cache (concurrent map)│
        └──────────────────────────────────────────┘
                            ▲
                            │  L2: CAS-claimed thunks live here,
                            │  in shared regions of the heap
```

## 3. L2: lock-free CAS thunks

### 3.1 The thunk state machine, made atomic

In the serial design (see [value representation](05-value-representation.md)) a
thunk is `(code_ptr, captured_env, state)` and `state` is a plain enum mutated
by the forcing thread, cycling through the serial subset
`Suspended -> Blackhole -> Forced`. The parallel state machine is a **superset**
of that serial subset: for L2 we promote the discriminant to an **atomic word**
and force every transition through compare-and-swap (CAS). The serial
`Suspended -> Blackhole -> Forced` lifecycle is exactly the uncontended,
single-thread projection of the diagram below — one model, two regimes. We follow
the exact state set that C++ Nix's multithreaded evaluator settled on, because it
is the minimal set that preserves blackhole semantics under contention:

```text
  Suspended ──CAS──► Pending ──────► Forced     (uncontended fast path)
      │                 │
      │                 ├──(another thread arrives)──► Awaited
      │                 │                                  │
      │                 └────────► Failed ◄────────────────┘
      │                              (exception propagated to waiters)
      │
   Forced / Blackhole (cyclic)  ← already-resolved, pure tag test
```

| State | Meaning | Who sets it | Who reads it |
|-------|---------|-------------|--------------|
| `Suspended` | unforced; `(code, env)` valid | thunk allocator | the claimer (via CAS) |
| `Pending` | one thread is forcing; no waiters yet | claimer (CAS from `Suspended`) | arrivals |
| `Awaited` | being forced; ≥1 thread blocked waiting | a late arrival (CAS from `Pending`) | the forcer, on completion |
| `Forced` | result installed; value valid | the forcer (release store) | everyone (acquire) |
| `Failed` | forcing threw; error stashed | the forcer | waiters (re-raise) |
| `Blackhole` | self-referential cycle detected | forcer detecting recursion on its *own* stack | itself |

The critical distinction — and the reason this is not just "a mutex per thunk" —
is between **inter-thread blocking** (`Pending`/`Awaited`, two *different*
threads) and **intra-thread cycle detection** (`Blackhole`, the *same* thread
re-entering a thunk it is already forcing). C++ Nix's `Blackhole` historically
meant "infinite recursion." Under parallelism that meaning would be wrong: a
second thread hitting a thunk the first is legitimately forcing is *not* a cycle.
So we split the concept: cross-thread reentry parks the arriving thread;
same-thread reentry (detected by recording the owning thread/fiber id in the
`Pending` word) is the genuine `infinite recursion encountered` error that Nix
programs depend on.

### 3.2 The claim protocol

```rust
/// Forces `thunk` to WHNF, coordinating with concurrent forcers.
///
/// # Errors
/// Returns the underlying evaluation error if forcing the thunk fails, or a
/// cycle error if the *current* worker re-enters a thunk it is already forcing.
fn force(rt: &Runtime, thunk: &Thunk) -> Result<Value, EvalError> {
    loop {
        // Acquire: observe a fully-published Forced/Failed result.
        match thunk.state.load(Acquire) {
            State::Forced => return Ok(thunk.value_unchecked()),
            State::Failed => return Err(thunk.error_unchecked()),
            State::Suspended => {
                // Try to claim. Encode our worker id so self-reentry is
                // detectable as a real cycle.
                let claimed = State::Pending(rt.worker_id());
                if thunk
                    .state
                    .compare_exchange(State::Suspended, claimed, AcqRel, Acquire)
                    .is_ok()
                {
                    return evaluate_and_publish(rt, thunk); // we own it
                }
                // Lost the race; re-observe.
            }
            State::Pending(owner) | State::Awaited(owner) => {
                if owner == rt.worker_id() {
                    return Err(EvalError::InfiniteRecursion); // genuine cycle
                }
                // Someone else owns it: don't spin. Help or wait (§3.3).
                return wait_or_steal(rt, thunk);
            }
        }
    }
}
```

`evaluate_and_publish` runs the compiled thunk body, then performs a **release
store** of `Forced` (or `Failed`) and wakes any parked waiters registered while
we held `Pending`/`Awaited`. The acquire/release pairing is what gives other
threads a correct, fully-constructed value: the C++ Nix design relies on the
same `std::atomic` type field with the same memory-ordering discipline, and we
mirror it exactly so our reasoning inherits theirs.

> **Why CAS, not a lock.** A per-thunk `Mutex` would be correct but pays an
> uncontended-lock cost on *every* force, and forces happen billions of times.
> The uncontended path here is a single relaxed-ish CAS that almost always wins
> immediately — the same reason LuaJIT, the JVM biased-locking lineage, and
> GHC's eager-blackholing all reach for a single atomic word over a lock object.
> Contention is rare because the thunk graph is mostly tree-shaped per
> derivation; the genuinely shared nodes are few and usually already `Forced`
> by the time a second thread arrives, collapsing to a pure tag test (§3.4).

### 3.3 Waiting vs. work-stealing on a claimed thunk

When a worker finds a thunk owned by another worker it has two options, and the
choice is the single most consequential tuning decision in L2:

1. **Park and wait** (the C++ Nix choice): register as a waiter, CAS
   `Pending -> Awaited`, and block until the owner publishes. Simple, no
   double work, but the waiting core is idle unless we hand it other work.
2. **Work-steal elsewhere** (the GHC spark choice): instead of blocking, the
   worker returns to its scheduler, pops the next independent task off its own
   deque, or steals one from a peer, and only revisits the blocked thunk later.

aos-nix uses a **hybrid**: a worker that blocks on a foreign thunk does *not*
busy-spin and does *not* immediately OS-park. It first attempts to drain its own
deque and steal a peer task (keeping the core busy), and only if there is
genuinely no other work does it park on the thunk's waiter list. This is exactly
GHC's runtime behaviour — sparks are load-balanced by work-stealing, and a
thread that blocks on a black hole yields to the scheduler rather than spinning.
Determinate Systems' parallel Nix takes the simpler park-only route because its
unit of work is coarse (whole attribute paths from `nix flake show` /
`nix search`); our finer L2 grain makes the steal-before-park hybrid worthwhile.

```text
  worker hits foreign Pending/Awaited thunk T
        │
        ├─ own deque non-empty?  ──yes──► pop & run other task, retry T later
        │
        ├─ peer deque stealable?  ──yes──► steal & run, retry T later
        │
        └─ no work anywhere ─────────────► register waiter, park until T.Forced
```

We deliberately **do not** implement GHC-style *helping* (a waiter re-doing the
foreign thunk's work speculatively). Helping risks double evaluation, which for
a pure value is merely wasteful — but `derivationStrict` and `import` have
*observable* effects (writing a `.drv` to the store, registering an
incremental-cache node); redoing them under a race is a correctness hazard we
refuse to take for a marginal latency win. Wait-or-steal never re-runs a claimed
thunk.

### 3.4 The fast path is a tag test, not an atomic

The overwhelmingly common case is forcing a thunk that is **already `Forced`**
(a let-binding referenced many times, an interned store-path string, a shared
attrset). Pointer tagging (see [value representation](05-value-representation.md),
the GHC spineless-tagless trick) encodes evaluatedness in spare pointer bits, so
the hot path is:

```rust
#[inline(always)]
fn force_fast(v: Value) -> Option<Value> {
    // WHNF bit set in the pointer tag => no atomic load, no CAS, no branch
    // into the runtime. Already-evaluated values are returned by inspection.
    if v.is_whnf_tagged() { Some(v) } else { None } // fall through to force()
}
```

Only a *tag miss* (a genuinely `Suspended` value) drops into the atomic protocol
of §3.2. This keeps the parallel overhead off the path that dominates dynamic
counts, which is why CAS-per-thunk is affordable: we pay it rarely.

### 3.6 The memory-ordering audit plan (loom / Miri / TSan)

The acquire/release discipline of §3.2 is *borrowed* from C++ Nix's
`std::atomic` thunk protocol; re-deriving it correctly in Rust's atomics model is
not optional folklore but a **committed, gated deliverable**. Per decision C-12
the parallel tier (**P3.5** in [roadmap](17-roadmap-and-risks.md) §3) is promoted
early, which makes the old "R-4, planned" memory-ordering item (§8) an **early
gate**, not a post-hoc nicety. This subsection turns R-4 into a concrete plan.

**Model the CAS protocol in loom.** loom is a concurrency permutation tester for
Rust: it runs a test many times, exhaustively exploring the executions permitted
under the C11 memory model — for every atomic operation it tries every value an
acquire load may observe given the releases that happened-before it, using state
reduction to avoid combinatorial blow-up. We model the
`Suspended -> Pending -> Awaited -> Forced/Failed` machine (§3.1, §3.2) directly
in loom's `Atomic*`/`UnsafeCell`/`thread::spawn` shims: a small harness spawns
2-3 worker threads that race to `force` the *same* thunk (and a self-reentry case
for the cycle path), and loom enumerates the interleavings. The protocol ships
*only after loom is exhaustively green on this model*.

**The invariants loom must prove.** The harness asserts each of the following as
a loom-checked property across all explored interleavings:

1. **No lost wakeup.** A thread that CASes `Pending -> Awaited` and parks is
   *always* woken: the forcer's release-store of `Forced`/`Failed` happens-after
   the waiter's registration, so a parker can never miss the publish and sleep
   forever. loom explores the exact window where registration and publish race.
2. **No double-force of an effectful primop.** At most one thread ever runs a
   given thunk body, so `import` / `derivationStrict` (which write a `.drv`,
   register a cache node — §3.3, §7) execute **exactly once per thunk**. The
   single-winner CAS `Suspended -> Pending` is the mutual-exclusion proof loom
   checks against every racing claimant.
3. **No torn read of the thunk word.** The state discriminant (and the
   worker-id it carries) is read and written only through the atomic word; loom
   confirms no interleaving observes a half-published state.
4. **No deadlock on a claimed thunk.** The wait-or-steal of §3.3 always makes
   progress: a worker that cannot claim a thunk parks/steals but never blocks the
   owner, and loom's deadlock detection must report none across the model.
5. **Correct acquire/release pairing on the value publish.** Every thread that
   observes `Forced` via an acquire load also observes the *fully constructed*
   value the forcer release-stored — the value write happens-before the state
   publish, with no reordering loom permits that exposes an uninitialized slot.

**Complement loom with Miri and ThreadSanitizer.** loom proves the *protocol* but
only over the small model it is given; two further tools cover what it cannot:

- **Miri** runs the safe tree-walk oracle ([15](15-differential-testing-and-benchmarking.md)
  §7) and small parallel harnesses under its UB checker and (data-race-aware)
  interpreter, catching undefined behavior and some races in real code paths loom
  does not model.
- **ThreadSanitizer** runs the *actual* multithreaded binary (the real
  work-stealing pool of §4, real thunks, real GC nurseries) under a dynamic
  data-race detector, catching races in code outside the loom model — the
  scheduler glue, the shared insert-or-get tables (§4.3), the fiber runtime
  (§5.5).

**This is the shipping gate for P3.5.** The parallel evaluator is **not trusted
until loom is green** on the thunk-CAS model and Miri/TSan are clean on the
parallel harness and binary. Until then the sequential tree-walk oracle (the
differential ground truth) remains the only authoritative evaluator, exactly as
the C-12 guardrails require. loom green is a *precondition* of the parallel tier
shipping, not a follow-up to it.

## 4. L1: coarse top-level parallelism

### 4.1 Why this is the first target

The roadmap ranks L1 ("coarse, low-risk") ahead of L2 because it delivers the
bulk of the speedup while touching almost no shared mutable state. The shape of
a full AOS evaluation is a wide fan of independent top-level derivations
(`pkgs.foo`, `pkgs.bar`, …), each an island. If we schedule *whole derivation
subtrees* onto a work-stealing thread pool and give each worker its **own GC
nursery**, the only shared state is **immutable and read-only after
construction**:

- the parsed/compiled IR (content-addressed, built once — see
  [frontend, parser and IR](04-frontend-parser-and-ir.md));
- the symbol table (u32 interning — see
  [attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md));
- the hash-cons / maximal-sharing table (see
  [value representation](05-value-representation.md));
- the primop registry and its perfect-hash dispatch table (see
  [primops and runtime ABI](10-primops-and-runtime-abi.md));
- the incremental evaluation cache (a concurrent content-addressed map — see
  [the incremental evaluation cache](12-incremental-evaluation-cache.md)).

Determinate Systems made the symbol table lock-free precisely because it is the
one "immutable" structure that still mutates *during* evaluation (new identifiers
intern lazily). We pre-build or grow these tables under the same lock-free /
read-mostly discipline (§4.3).

### 4.2 The scheduler: a work-stealing pool

L1 runs on a Chase-Lev work-stealing deque pool — the design that underlies
Rayon and most modern task runtimes, and the same structure GHC uses to
load-balance sparks. Each worker owns a deque; it pushes/pops its own tasks at
one end (LIFO, cache-friendly: a freshly-pushed subtree is hot) and idle peers
steal from the other end (FIFO, stealing the *oldest*, largest-grained task to
minimize steal frequency). The Chase-Lev algorithm is lock-free except for the
rare allocation when the deque grows, which matches our "no locks on the hot
path" rule.

Current implementation status: `ratchet-oracle::eval::parallel` provides a safe
standard-library scheduler precursor for this shape. It pins round-robin root
seeding, LIFO local pops, FIFO peer steals, stable task-index result collation,
and per-worker execution counters, but it deliberately does not claim the final
lock-free Chase-Lev deque or integration with Nix derivation evaluation.

```text
   roots = [ pkgs.a, pkgs.b, pkgs.c, ... pkgs.zzz ]   (tens of thousands)

   seed:  round-robin roots onto worker deques
   run:   each worker  pop() ─► force derivation subtree ─► emit .drv
   steal: empty worker  steal() oldest task from a random victim
   done:  all deques empty AND all workers idle (termination barrier)
```

We do **not** spawn a task per thunk — that would be the per-thunk-activation
trap RFC-0007 explicitly rejects (billions of tasks). The task grain is a
top-level derivation (tens of thousands), large enough that scheduling overhead
is negligible against the forcing work inside.

### 4.3 Growing the shared immutable tables safely

The symbol table and hash-cons table must accept inserts during parallel
evaluation (a new string literal interns; a new attrset hash-conses). We use the
read-mostly concurrent-map discipline rather than a global lock:

- **Symbol table**: append-only interner. Lookups are lock-free reads of a
  stable index; the rare new-symbol insert uses a sharded, lock-free hash map
  (insert-or-get returns the existing id on a race, so two threads interning the
  same string converge to one u32). This is the lock-free symbol table
  Determinate Nix shipped.
- **Hash-cons table**: same insert-or-get contract. Because Nix values are
  immutable, two threads independently constructing the structurally-identical
  attrset must end up sharing one allocation; the table's atomic insert-or-get
  guarantees it. Maximal sharing is *strengthened* by parallelism, not
  threatened by it — see [value representation](05-value-representation.md).
- **Incremental cache**: a concurrent map keyed on `hash(expr ⊕ env)`. Two
  workers computing the same memoized node race to insert; the loser discards
  its (identical, pure) result. Early-cutoff comparisons remain valid because
  the stored value-hash is deterministic — see
  [the incremental evaluation cache](12-incremental-evaluation-cache.md).

The soundness argument is uniform: **every shared table has an idempotent,
order-independent insert-or-get**, so races produce convergent results, never
divergent `.drv` output.

### 4.4 Determinism of output under nondeterministic scheduling

This is the compatibility crux. Threads finish in arbitrary order, but the
`.drv` files and store paths must be byte-identical to `nix-instantiate` every
time (see [compatibility constraints](02-compatibility-constraints.md) and
[derivation and store compatibility](11-derivation-and-store-compatibility.md)).
We guarantee it structurally:

1. **`derivationStrict` reads only immutable, fully-forced inputs.** Attr
   iteration order is fixed by the deterministic attrset representation, *not* by
   evaluation order (see
   [attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)).
2. **String contexts union order-independently.** Contexts are interned
   copy-on-write bitsets of store-path ids; set union is commutative and
   associative, so the order threads merge them in cannot change the result
   (see [derivation and store compatibility](11-derivation-and-store-compatibility.md)).
3. **Output collection is sorted, not arrival-ordered.** The `.drv` writer sorts
   inputs/outputs/env by the canonical Nix order before ATerm serialization, so
   which worker produced which input is irrelevant.
4. **Hashing is on content, never on identity.** All Nix-observed hashes are
   SHA-256 over canonical bytes; no thread id, pointer, or timestamp enters the
   hash.

The differential harness (see
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md))
runs the *parallel* evaluator against `nix-instantiate` across the full package
set, and additionally runs it at thread counts `{1, 2, 8, N}` asserting
identical output across all of them — a cheap, devastating fuzz test for any
order-dependence bug.

## 5. The hard problem: parallel GC × thunk mutation

This is where aos-nix's choices make parallelism genuinely difficult, and where
we diverge most from C++ Nix.

### 5.1 Why C++ Nix gets this for free (and we don't)

C++ Nix uses Boehm conservative GC. Boehm is non-moving: an object never changes
address, so a pointer read is just a load — no barrier, no coordination with the
collector. That is precisely why edolstra's multithreaded evaluator could focus
entirely on the thunk protocol and ignore GC: the collector and the mutators
don't fight over object locations. The price Boehm pays — false retention from
conservative stack scanning, and being "the dominant cost" in C++ Nix per our
profiling — is exactly the cost RFC-0007 set out to eliminate with a **precise,
moving** collector (see [memory management and GC](06-memory-management-and-gc.md)).

A moving collector relocates objects. The moment a collector thread can move an
object while a mutator thread is forcing a thunk, we have three new hazards on
top of the thunk race:

1. **Mutator/collector race on the thunk word.** A collector updating a moved
   object's forwarding pointer vs. a mutator CAS-ing the same object's state
   word.
2. **Stale pointers after relocation.** A worker holding a raw `*Value` that the
   collector just moved.
3. **Cross-nursery references.** L1 gives each worker a private nursery, but a
   hash-consed value shared across workers lives in a shared/tenured region;
   write-tracking those cross-region edges is the classic generational
   remembered-set problem, now concurrent.

### 5.2 Tiered answer, matching the GC tiers

Our GC has two tiers (see [memory management and GC](06-memory-management-and-gc.md)),
and parallel-GC interaction is answered per tier:

| Mode | GC | Parallel-GC strategy |
|------|----|----------------------|
| **Tier A — one-shot CLI** | bump-arena, never free, drop at exit | **trivial**: no collection during eval, so no mutator/collector race exists. Parallel forcing is fully unconstrained. |
| **Tier B — daemon / long-lived** | precise generational copying; optional concurrent (ZGC/Shenandoah-style) | **hard**: requires stop-the-world phases or load barriers (§5.3). |

The Tier-A escape hatch is enormous and deliberate: **for the build-time
bottleneck this RFC actually targets — `aos build` shelling out a fresh
evaluation — Tier A is the mode that runs.** A one-shot evaluation never
collects (it bump-allocates and drops the whole arena at `exit`), so the
collector simply does not run concurrently with forcing. L1 and L2 parallelism
in Tier A need *zero* GC coordination. This is the single most important
simplification in the whole parallel design: **the common case has no
parallel-GC problem at all.**

### 5.3 Tier B: stop-the-world first, concurrent later

For the daemon (long-lived evaluator serving many requests, where the heap must
be reclaimed), we stage it:

**Stage B0 — stop-the-world parallel GC.** All workers reach a safepoint, the
collector runs (itself parallel across cores), then mutators resume. This is the
G1/parallel-collector model. Reaching a safepoint requires every worker to be at
a GC-poll point with a precisely-described stack — which our precise collector
needs anyway. Because forcing is short and frequent, safepoint latency is low.
This is correct, simple, and sufficient until pause times measurably hurt daemon
latency. **No load barriers, no concurrent relocation, no mutator/collector
race** — the collector only runs when *no* thunk is being forced.

**Stage B1 — concurrent low-pause GC (research-grade).** Only if Stage-B0 pauses
become the measured limiter do we adopt colored-pointer + load-barrier
collection in the ZGC/Shenandoah lineage. The mechanism:

- **Colored pointers**: metadata (mark/relocation state) lives in spare
  high-order pointer bits — the same bits we already use for WHNF tagging, so the
  schemes must be co-designed (this is a noted constraint, not a solved problem).
- **Load barrier**: every pointer load runs a small check that, if the pointee
  was relocated, follows the forwarding pointer and "self-heals" the slot. ZGC
  brings pauses from 50-500 ms down to 1-5 ms this way, at ~2× heap overhead.
- **Interaction with the thunk CAS**: the load barrier must fire *before* the
  thunk-state CAS, so the CAS targets the relocated copy. Concretely, forcing
  becomes "load-barrier the thunk pointer, then CAS its state word." Shenandoah's
  Brooks-pointer indirection or ZGC's colored-pointer self-healing both make the
  *address* stable-enough for the CAS within a single forcing operation; getting
  this provably right under our exact WHNF-tag layout is an **open question** we
  flag explicitly below.

```text
   Tier B0 (ship first):           Tier B1 (advanced measured variant):

   mutators ──┐                    mutator: load ─► [barrier] ─► CAS state
              ▼ safepoint                              │
   ┌──────────────────┐                                ▼ (if relocated)
   │ parallel collector│                          follow forwarding ptr,
   │ (world stopped)   │                          heal slot, then CAS
   └──────────────────┘                          collector relocates
              ▲ resume                            CONCURRENTLY with forcing
   mutators ──┘
```

### 5.4 Region inference reduces the problem before GC runs

Tofte-Talpin region inference and escape analysis (see
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md))
shrink the parallel-GC problem from the *language* side rather than the runtime
side. Whole-program analysis proves that most intermediate thunks built inside a
single derivation's evaluation **never escape that derivation**. Such values can
be confined to the worker's private nursery (or scalar-replaced away entirely),
so they are *never* candidates for cross-thread sharing or cross-region
remembered-set tracking. The remembered set the concurrent collector must
maintain is reduced to the genuinely shared, hash-consed, long-lived values —
which are few. Purity makes escape analysis far more effective here than on the
JVM, and that effectiveness directly buys down the hardest part of §5.3.

## 5.5 The concurrency runtime: rayon, fibers, and tokio I/O

The layers above describe *what* runs in parallel (independent derivations at L1,
shared thunks at L2) and how the GC interacts. This section pins *which runtime
machinery* schedules it — and resolves a common misconception about combining
CPU and I/O concurrency in Rust.

### 5.5.1 Three concerns, three tools

The evaluator mixes three kinds of work, and each wants a different mechanism:

| Work | Nature | Tool |
|---|---|---|
| Thunk-graph forcing (L1 + L2) | CPU-bound, deeply recursive | **rayon** work-stealing (crossbeam Chase-Lev deques) |
| Eval-time blocking I/O (IFD waiting on a build; eval-time network fetchers) | I/O-bound, may block for seconds | **tokio** reactor on its own I/O threads |
| Suspending an I/O-blocked eval node so its worker frees up | scheduling glue | **stackful fibers** (green threads) |

The decisive fact: **`force` is CPU-bound deep recursion, and that is the program's
hot path.** Parallelism for it is a *CPU* concern (rayon), not an *I/O* concern
(tokio). The two are different problems and the standard mistake is to reach for
one tool for both.

### 5.5.2 Why not "just make rayon and tokio collaborate"

There is no built-in co-scheduler between rayon and tokio. **tokio** alone does
M:N collaborative scheduling — *of async tasks* (suspend on `.await`, the worker
grabs another task). **rayon** alone does work-stealing — *of CPU fork-join
tasks*, which run to completion on their worker with no I/O-suspension notion.
But a rayon task cannot transparently yield into tokio and have its rayon worker
pick up other rayon work; the bridging crates only *offload* across the two
pools, they do not *co-schedule*. So the appealing mental model — "rayon workers
that hand off to tokio on I/O and resume another green thread" — is not something
either runtime provides off the shelf.

### 5.5.3 The obstacle, and why fibers solve it

The goal is real: with hundreds of eval nodes potentially blocked on I/O (chiefly
**IFD** — eval forcing a derivation that must *build* — and eval-time network
fetchers) but only ~`ncpu` workers, a blocked node should **park and free its
worker**, not pin an OS thread. The obstacle is that the blockable point is *deep
inside the synchronous recursion* (`force → force → … → an I/O primop`); to
suspend there you must save the whole call stack. Two ways to do that:

1. **Async-color the evaluator** (`async fn force` everywhere, run on tokio).
   This works, but async recursion requires `Box::pin` per frame — heap + poll
   overhead on the single hottest path, 99.9% of which never touches I/O. We
   **reject** this: the coloring tax is paid everywhere to benefit a tiny I/O
   surface.
2. **Stackful coroutines (fibers)** — Go's model, and the **chosen** mechanism.
   Each eval node runs on a fiber. When it hits a suspendable I/O primop, the
   *entire synchronous recursive stack parks*; the worker work-steals another
   ready fiber (more CPU-bound thunk-graph forcing); the tokio reactor drives the I/O; on
   completion the fiber is rescheduled onto some worker. This delivers the M:N
   "few OS threads service many I/O-blocked nodes" behavior **without coloring
   `force` async** — the recursive hot path stays plain synchronous Rust.

```text
   worker thread (one of ~ncpu)
   ───────────────────────────
     run fiber A ──force──► IFD primop ──park fiber A──┐
       (sync recursive stack saved on A's fiber stack) │
     steal fiber B ──force──► CPU work … ──────────────┼─► tokio reactor builds
     steal fiber C ──force──► … ──────────────────────┘   the IFD derivation
                                       … on completion: reschedule fiber A
```

Fibers cost a parkable stack per in-flight blocked node (growable/segmented) and
some `unsafe` stack-switch machinery (crates such as `corosensei` / `may`
implement exactly this); the work-stealer is crossbeam-deque, the I/O reactor is
tokio. The `unsafe` is confined to the fiber runtime and SAFETY-commented; the
sequential tree-walk oracle ([15](15-differential-testing-and-benchmarking.md)
§7) stays single-threaded synchronous and is the `miri`-checked ground truth, so
the fiber scheduler is validated *against* it, never trusted on its own.

### 5.5.4 The rules that keep it correct and fast

- **Local fast reads stay synchronous.** `readFile`/`readDir`/`pathExists`/local
  `import` are microsecond syscalls; a fiber suspend/resume costs more than the
  read. Only *genuinely blocking* I/O (IFD, network fetch) suspends a fiber.
- **Never block a compute worker on I/O.** A naked `block_on` on a rayon/fiber
  worker starves the pool — avoiding exactly that is the entire reason fibers +
  the tokio reactor exist. I/O always runs on tokio's threads with the fiber
  parked.
- **A fiber blocked on a *claimed thunk* (§3.3) yields the same way** — it
  work-steals or parks rather than spinning, unifying "waiting on I/O" and
  "waiting on another worker's force" under one scheduler.
- **Scheduling nondeterminism never reaches output.** Fiber/worker ordering is
  nondeterministic; the `.drv` is not (§4.4). Purity guarantees the same result
  regardless of how fibers interleave.

### 5.5.5 Measure-gated turn-on

The fiber I/O layer pays off **only when eval-time blocking-I/O concurrency is
real** — principally IFD-heavy or fetch-heavy evaluation. A from-source distro
that minimizes IFD has mostly fast local reads, where the synchronous core
suffices. So the build order is: **sync core + rayon (CPU) + tokio reactor for
the few genuinely-blocking primops first**; introduce fiber-based suspension when
profiling shows concurrent eval-time I/O is a bottleneck. Full async-coloring
remains the documented-but-rejected alternative.

## 6. Failure, exceptions, and cancellation

Nix evaluation can abort: `builtins.throw`, `assert` failure, type errors, or
infinite recursion. Under parallelism, an error in one derivation must not
corrupt another, and must surface deterministically.

- **Per-thunk `Failed` state.** A forcing thread that throws publishes `Failed`
  with the stashed error; waiters re-raise it. The error is a value, captured
  once, observed identically by all waiters — no double-throw, no lost error.
- **Independent derivations are isolated.** L1 workers evaluate islands; an error
  in `pkgs.broken` fails only that root's task. The pool collects per-root
  results (`Ok(drv)` / `Err`) and reports them together.
- **Cancellation is cooperative.** If the caller wants fail-fast (`aos build`
  aborting on first error), a worker that publishes `Failed` on a *requested*
  root sets a shared `cancelled` flag; other workers check it at their GC-poll /
  task-boundary safepoints and unwind. We never forcibly kill a worker
  mid-force, which would leave a thunk stuck in `Pending` and deadlock its
  waiters.
- **Deterministic error selection.** When multiple roots fail, the *reported*
  error is chosen by canonical order (e.g. lowest attr path), not by which thread
  failed first — so the error message is reproducible, matching C++ Nix's
  single-threaded "first failure encountered in evaluation order" as closely as
  the differential harness demands.

## 7. What we explicitly do not do

- **No per-thunk OS threads or per-thunk tasks.** The grain is a derivation
  subtree (L1) or a CAS on an existing thunk (L2). Spawning per activation is the
  billions-of-units trap RFC-0007 rejects in its execution model.
- **No speculative helping / re-execution of claimed thunks.** Risks double
  execution of effectful primops (`import`, `derivationStrict`); we wait-or-steal
  instead (§3.3).
- **No lock-based thunk protection on the hot path.** A single atomic word with
  CAS, fronted by a tag-test fast path (§3.4).
- **No concurrent GC in the one-shot CLI path.** Tier A never collects; the
  hardest interaction simply does not arise for the build-time bottleneck we
  target (§5.2).
- **No nondeterminism leaking into output.** Every shared table is insert-or-get
  idempotent; every Nix-observed hash is content-only (§4.4).

## 8. Open questions and research-grade items

These are flagged as uncertain; none block the phase-1 serial evaluator or the
L1 coarse pool.

1. **WHNF tag bits vs. colored-pointer GC bits (Stage B1).** Both want spare
   pointer bits. Co-designing the WHNF/constructor tag layout with ZGC-style
   color bits is unsolved; it may force a wider value or a different tagging
   scheme. *Open.*
2. **Load barrier on the thunk-state CAS.** Proving the relocate-then-CAS
   sequence is race-free under our exact memory model and tag layout needs the
   formal-verification rigor applied to Chase-Lev deques under weak memory. The
   committed §3.6 audit (loom over the CAS protocol) is the methodology that would
   extend to cover the load-barrier-then-CAS sequence once Stage B1 is on the
   table; until then, Stage B0 (stop-the-world) is the shipping answer and no load
   barrier exists to audit. *Open; audit methodology in §3.6.*
3. **L1 load imbalance / the long tail.** A handful of giant derivations
   (the toolchain, `systemd`) can dominate the tail and starve L1 parallelism.
   The mitigation is L2 (force *within* a giant derivation in parallel), but the
   crossover point where L2's risk is worth its reward is a measurement, not a
   prediction. *Open, measure-first.*
4. **Memory-ordering audit (R-4).** The acquire/release discipline (§3.2) is
   borrowed from C++ Nix; re-deriving it in Rust's atomics model and validating it
   under loom/Miri/TSan is required before the parallel tier ships. Under decision
   C-12 this is now an **early gate** for P3.5, not a deferred follow-up, and the
   plan is **committed** — see §3.6 for the loom model, the enumerated invariants,
   and the Miri/TSan complement. *Committed; gating, see §3.6.*
5. **Cross-nursery sharing cost.** How often hash-consed values are genuinely
   touched by multiple workers (forcing shared-region access and, in Tier B,
   remembered-set churn) is unknown until measured on the real AOS closure.
   *Open.*

## 9. Summary

Parallelism is sound for Nix because values are immutable, but the *thunk graph*
is shared mutable state, so we adopt the proven CAS-claimed thunk protocol from
GHC and C++ Nix's multithreaded evaluator: an atomic state word, a
`Suspended -> Pending -> Awaited -> Forced/Failed` lifecycle, a tag-test fast
path for already-evaluated values, and wait-or-steal (never speculative re-run)
on contention. We layer this under a coarse, low-risk work-stealing pool over
independent top-level derivations whose only shared state is immutable
insert-or-get tables, which captures most of the win at a fraction of the risk
and is the first target. The genuinely hard part — parallel forcing against a
precise *moving* collector — is dissolved in the one-shot CLI path (Tier A never
collects, so the build-time bottleneck we target has no parallel-GC problem),
answered by stop-the-world parallel collection in the daemon, and only escalates
to colored-pointer/load-barrier concurrent GC as a measured, research-grade
follow-up. Throughout, byte-identical `.drv` output is preserved structurally —
order-independent context unions, sorted output collection, content-only SHA-256
hashing — and asserted by running the differential harness across thread counts.

## Implementation checklist

Per-feature tracker for parallel evaluation (the L1 work-stealing pool, the L2 lock-free CAS thunk protocol, the fiber/tokio I/O runtime, the loom/Miri/TSan audit, and the parallel-GC interaction); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

Parallel graph evaluation is **P3.5** (decision `C-12`): promoted from the rank-5 tail to a committed early phase, placed after P3 so per-worker nurseries build on the bump arena. Two guardrails are absolute and bind every item below: the **sequential** tree-walk oracle stays the correctness ground truth the parallel tier is differentially diffed against, and the parallel tier ships **only after** the `loom`/Miri/TSan audit (`R-4`) is green — *no data races, ever*.

### L2 — lock-free CAS thunks (§3)

- [ ] Atomic thunk state word with the superset machine `Suspended → Pending → Awaited → Forced/Failed` plus same-thread `Blackhole` cycle detection (worker/fiber id in the `Pending` word distinguishes cross-thread reentry from a genuine cycle) (§3.1) — **P3.5**, `C-12`; the word is already atomic from **P1**, so this adds a scheduler, not a representation change.
- [ ] The `force` claim protocol: acquire-load the state, single-winner CAS `Suspended → Pending`, self-reentry → `InfiniteRecursion`, release-store of `Forced`/`Failed` with waiter wakeup (§3.2) — **P3.5**, `C-12`; gated by the loom audit (§3.6).
- [x] Current L2 CAS state-word precursor:
      `ratchet-oracle::eval::thunk_cas` defines the owner-tagged atomic word
      encoding for `Suspended`, `Pending(worker)`, `Awaited(worker)`,
      `Forced`, and `Failed`; exposes acquire state loads, single-winner
      `Suspended -> Pending(worker)` claim CAS, same-worker cycle
      classification, foreign pending/awaited classification, non-parking
      foreign `Pending -> Awaited` marking, and guarded release publication to
      `Forced` or `Failed`. Active claim guards are deliberately not `Send`,
      and dropping one publishes `Failed` so safe unwinding cannot strand a
      thunk in a claimed state. Unit tests pin encoding round-trips,
      exactly-one concurrent claimant, self-cycle versus foreign contention,
      awaited publication metadata, failed terminal behavior, drop-to-failed
      unwinding, acquire/release payload visibility, and wrong-owner publish
      rejection. This is the state-word/protocol precursor only: it does not
      replace the serial tree-walk thunk cell, does not store forced values or
      captured errors, does not install waiter lists or wakeups, does not
      perform work stealing or parking, and does not satisfy the loom/Miri/TSan
      gate (§3.6).
- [ ] Wait-or-steal on a foreign claimed thunk: drain own deque, then steal a peer task, then park on the waiter list — never busy-spin, never speculative *helping* (re-running a claimed effectful thunk) (§3.3) — **P3.5**, `C-12`.
- [x] Current safe waiter/wakeup precursor:
      `ratchet-oracle::eval::thunk_wait` wraps the CAS state word with a
      standard-library mutex and condition variable so foreign workers can mark
      a thunk `Awaited`, register under the waiter mutex, check the terminal
      predicate before sleeping, and wake after the owner publishes `Forced` or
      `Failed`. The owner stores the terminal state first, then takes the same
      waiter mutex before notifying, which models the no-lost-wakeup ordering
      required by §3.6. Claim guards remain worker-affine and compile-fail
      doctests in this slice check that they are not `Send`; dropping a
      wait-cell claim publishes
      `Failed` and broadcasts to waiters. Unit tests cover forced publish
      wakeup, drop-to-failed wakeup, self-cycle classification, already
      terminal no-wait behavior, and waiter/notification counters. This is a
      blocking correctness precursor only: it does not drain local work, steal
      peer work before parking, store values/errors, implement the final
      lock-free waiter list, integrate with the evaluator scheduler, or satisfy
      the loom/Miri/TSan gate (§3.6).
- [x] Current wait-or-steal ordering precursor:
      `ParallelThunkWaitCell::claim_or_run_ready_then_wait` accepts a
      caller-supplied ready-work hook and, on a foreign-owned thunk, rechecks the
      thunk after each reported local task or stolen peer task before registering
      a waiter and entering the blocking wait-cell path. Its contention report
      records local work runs, stolen work runs, and whether a waiter was
      registered. Unit tests prove that terminal publication observed while
      ready work runs avoids waiter registration, that terminal publication
      between an idle report and waiter marking is reported as no registration,
      and that multiple reported local/stolen work items run before an idle hook
      registers and wakes through the safe waiter path. This is an
      ordering/readiness layer only: the hook is not the final Chase-Lev/rayon
      scheduler, cannot prove the caller exhausted real worker deques or peer
      steals, does not hold a scheduler park token, and still uses the blocking
      wait-cell precursor rather than a lock-free waiter list.
- [x] Current Chase-Lev ready-work poll/preflight bridge:
      `ratchet-oracle::eval::parallel_chase_lev_ready_work_queues` exposes
      owner-local Chase-Lev ready-work handles that feed the wait-or-steal hook
      exactly one local pop, peer steal, or idle `ParallelReadyWorkParkPreflight`
      at a time. Local/stolen polls preserve stable task metadata, while idle
      polls record non-locking Chase-Lev deque length observations that can be
      validated by the existing park-readiness type. Tests cover
      local-before-steal order, seeded and drained preflight depths, readiness
      validation and rejection, one-task poll metadata, idle polls not invoking
      the runner, and direct use with
      `ParallelThunkWaitCell::claim_or_run_ready_then_wait`.
      This is still a hook-shape bridge only: the idle observation can become
      stale immediately, does not reserve a scheduler park token, cannot prevent
      future ready-work enqueueing, does not prove live evaluator scheduler
      exhaustion, does not replace the blocking waiter path with a lock-free
      waiter list, and does not satisfy the loom/Miri/TSan gate (§3.3/§3.6).
- [x] Current Chase-Lev tree-walk force poll/preflight bridge:
      `TreeWalkParallelThunkCell::force_or_chase_lev_ready_then_wait_with`
      binds an owner-local Chase-Lev ready-work handle to the evaluator-native
      wait-or-steal force path. It validates that the nonzero thunk worker id
      maps to the handle's zero-based queue owner before claiming, polling, or
      running a body; contending workers then feed exactly one local pop, peer
      steal, or idle preflight into the existing poll/preflight bridge. Tests
      cover claim-owner no-poll behavior, local-then-recheck behavior,
      local-and-stolen work before replay, idle Chase-Lev preflight capture
      before blocking waiter registration, and worker/queue mismatch rejection
      before claiming, side effects, or queue consumption. This is still a
      typed bridge over the blocking wait-cell precursor: it does not attach a
      real scheduler park token, prove live scheduler exhaustion, replace
      `EvalThunk` storage, install the final lock-free waiter list, or satisfy
      the loom/Miri/TSan gate (§3.3/§3.6).
- [ ] Tag-test fast path: WHNF-tagged values return by inspection with no atomic load/CAS; only a tag miss enters the protocol (§3.4) — **P3.5**, `C-12`; co-designed with the pointer-tag work (`M-4`/`S-6`).
- [x] Current semantic WHNF tag-test precursor:
      `ratchet-oracle::eval::whnf_tag` defines the active-ABI fast-path
      boundary for force entry. `classify_whnf_tag_fast_path` returns every
      non-`Thunk` `ValueTag` as already-WHNF by inspection, and
      `checked_whnf_tag_fast_path` resolves only thunk-tag misses through
      `EvalHeap::get_thunk` before the caller enters the thunk protocol. The
      serial tree-walk `force_value` now uses this classifier at its force-entry
      boundary, and unit tests pin that inline scalars and heap WHNF tags return
      without heap lookup, thunk tags miss, foreign thunk pointers are rejected
      only on the slow path, and an already forced serial thunk still misses in
      the current 16-byte representation. This is the semantic tag-compare
      precursor only: it is not the future low-bit pointer-tag `FORCED`
      shortcut, does not skip the thunk cell for already forced thunk values,
      does not integrate with the parallel scheduler/CAS wait path, and does
      not satisfy the loom/Miri/TSan gate (§3.6).
- [x] Current frame-local single-entry thunk downgrade preflight:
      `ratchet-core::analysis::thunk_sharing` exposes
      `frame_local_single_entry_thunk_downgrade` as the named `C-8` safety
      boundary for blackhole/update elision. It accepts only `ThunkAlloc` nodes,
      returns `SingleEntry` only when `ExprFacts::thunk_sharing` has both a
      `Once` cardinality proof and a `NoEscape` frame-locality proof, returns
      `Omit` for non-contradicted absent lazy bindings, and otherwise reports
      why full update/blackhole state must remain. Unit tests pin escaping
      once-used thunks, frame-local many-entry thunks, absent thunks, strict
      absent conflicts, non-thunk nodes, malformed thunk payloads, and dangling
      thunk body ids. This is a proof/preflight API only: it does not change the
      tree-walk thunk representation, skip blackholes in the runtime, implement
      call-by-name lowering, improve cardinality/escape precision, or satisfy
      the loom/Miri/TSan gate (§3.6, §5.4;
      [07](07-laziness-and-whole-program-analyses.md) §5.1/§10).

### L1 — coarse top-level parallelism (§4)

- [ ] Chase-Lev work-stealing deque pool over independent top-level derivations, each worker with its own bump nursery; round-robin seed, LIFO local push/pop, FIFO steal, termination barrier (§4.1–§4.2) — **P3.5**, `C-12`; task grain is a derivation subtree, never per-thunk (§7).
- [x] Current per-worker nursery/hash-cons merge precursor:
      `ratchet-oracle::eval::parallel_heap` defines the deterministic planning
      boundary for worker-owned heap state before allocator internals become
      concurrent. `parallel_worker_nursery_plan` assigns each top-level task to
      a stable initial worker-local bump nursery, preserving the round-robin
      seed placement used by the safe scheduler precursor, and
      `merge_parallel_hash_cons_candidates` normalizes worker-local table
      emissions by `(worker_id, local_index)` before performing
      equality-confirmed reuse within structural-hash buckets. Unit tests prove
      idle worker nurseries are retained, worker completion order cannot change
      the canonical hash-cons winners, same-hash duplicate values converge to
      the earliest worker-local candidate, same-hash distinct values remain
      separate, equal values with mismatched hashes are admitted independently,
      and duplicate worker-local slots are rejected. This is a
      merge-contract/readiness layer only: it does not allocate evaluator
      objects, split `EvalHeap` into live per-worker heaps, publish into the
      current hash-cons tables, implement a lock-free/concurrent table, define
      allocation ownership for stolen tasks, integrate with the Chase-Lev/rayon
      scheduler, or satisfy the loom/Miri/TSan gate (§4.1–§4.3, §5) — **P3.5**
      precursor, `C-12`/`R-4`.
- [x] Current demand-graph node-table single-flight precursor:
      `SharedDemandGraph` serializes the existing in-memory node table with a
      same-process mutex, exposes insert-or-get admission status for shared
      callers, and tests that concurrent same-key misses collapse to one node
      while preserving the inserting winner's value hash. This establishes the
      convergence contract for later parallel shared tables, not the final
      lock-free append-only/CAS implementation, work-stealing integration, or
      loom/Miri audit (§4.3, [12](12-incremental-evaluation-cache.md) §8.3) —
      **P3.5** precursor, `R-4`.
- [x] Current same-root persistent blob-store maintenance lock precursor:
      independently opened `PersistCache` handles in one process now serialize
      cache-level blob-index compaction, blob-index rebuild, and blob-pack tail
      trim through the same per-store process-local mutexes used by indexed
      materialization, keyed by the canonical cache root; file-pack trimming
      also shares file-artifact and parse-artifact mapping locks while
      snapshotting those live roots. This keeps same-root maintenance rewrites
      from racing cache-level indexed or raw blob writes for the selected
      `values/` or `files/` store, and poisoned live locks fail before
      compaction/rebuild writes sidecars or tail trim truncates a pack. This is
      same-process fixed-record/pack-tail coordination only, not cross-process
      locking/CAS, raw lower-level pack or sidecar coordination, the final
      LMDB/redb index tables, work-stealing integration, or loom/Miri audit
      (§4.3, [12](12-incremental-evaluation-cache.md) §6.5) — **P3.5**
      precursor, `R-4`/`R-14`.
- [x] Current same-root persistent node-metadata writer lock precursor:
      independently opened `PersistCache` handles now acquire the
      `.locks/node-metadata.lock` advisory file before a process-local mutex
      keyed by the canonical cache root, so cache-level node-metadata
      read-modify-write operations and metadata compaction serialize for
      cooperating writers. Concurrent same-root current-demand records preserve
      every increment and poisoned live metadata locks fail before writing the
      sidecar. This is cache-level fixed-record coordination only, not raw
      lower-level sidecar enforcement, full locking/CAS, the final LMDB/redb
      node table, work-stealing integration, or loom/Miri audit (§4.3,
      [12](12-incremental-evaluation-cache.md) §6.5) — **P3.5** precursor,
      `R-4`/`S-14`.
- [x] Current same-root plus advisory persistent node-trace access lock
      precursor: independently opened `PersistCache` handles now acquire the
      `.locks/node-traces.lock` advisory file before a process-local mutex keyed
      by the canonical cache root, so cache-level trace lookups hold shared
      advisory locks while scanning the append-only log, and trace-log appends,
      tombstones, and compaction hold exclusive advisory locks for cooperating
      writers. Concurrent same-root appends preserve complete trace records and
      poisoned live trace locks fail before reading or writing the log. This is
      cache-level log coordination only, not raw lower-level sidecar
      enforcement, full locking/CAS, the final LMDB/redb node table,
      work-stealing integration, or loom/Miri audit (§4.3,
      [12](12-incremental-evaluation-cache.md) §6.5) — **P3.5** precursor,
      `R-4`/`S-14`.
- [x] Current same-root persistent artifact-mapping writer lock precursor:
      independently opened `PersistCache` handles now acquire advisory
      file locks at `.locks/file-artifacts.lock` and
      `.locks/parse-artifacts.lock` before process-local mutexes keyed by the
      canonical cache root, so cache-level file-artifact/parse-artifact mapping
      appends, mapping compaction, and file-pack tail trim/repack mapping phases
      serialize for cooperating writers. Concurrent same-root appends preserve
      complete mapping records and poisoned live mapping locks fail before
      writing the sidecars. This is cache-level fixed-record coordination only,
      not raw lower-level sidecar enforcement, cross-process pending artifact
      publication, full locking/CAS, the final LMDB/redb index tables,
      work-stealing integration, or loom/Miri audit (§4.3,
      [12](12-incremental-evaluation-cache.md) §6.5) — **P3.5** precursor,
      `R-4`/`R-10`.
- [ ] Read-mostly concurrent shared tables with idempotent insert-or-get: lock-free append-only symbol interner, hash-cons table, and the incremental cache as a concurrent content-addressed map — races converge, never diverge (§4.3) — **P3.5**, `C-12`; the hash-cons table is the `S-7`/`P2` substrate.
- [x] Current shared symbol-interner admission precursor:
      `aos-nix-syntax::SharedSymbolTable` wraps the existing dense
      `SymbolTable` behind a same-process mutex, exposes
      `SharedSymbolAdmission` from insert-or-get calls, and proves cloned
      concurrent same-key misses converge on one inserted symbol while every
      racing caller receives the same dense id. Snapshots clone the underlying
      table for consistent inspection of the serialized insertion history, and
      poisoned locks fail before interning or snapshotting. This is the
      convergence contract only; distinct new symbols racing for insertion
      still receive dense ids in mutex-acquisition order. It is not the final
      lock-free append-only symbol table, does not provide global cross-process
      ids, does not replace parser-local symbol ownership, and is not integrated
      with the parallel evaluator scheduler or loom/Miri audit (§4.3) — **P3.5**
      precursor, `C-12`/`R-4`.
- [ ] Output-determinism guarantees under nondeterministic scheduling: order-independent string-context union, sorted `.drv` output collection, content-only SHA-256 hashing, deterministic-iteration attrsets (§4.4) — **P3.5**, `C-12`/`S-13`; differential `.drv` harness asserts identical output across thread counts `{1, 2, 8, N}`.
- [x] Current parallel output-collation precursor:
      `ratchet-oracle::eval::parallel_output` canonicalizes worker-emitted
      output fragments by stable task index, unions existing canonical
      `StringContext`s in order-independent form, collects `.drv` outputs in
      lexicographic path order, computes SHA-256 digests only from `.drv` bytes,
      deduplicates identical repeated `.drv` emissions, and rejects duplicate
      task fragments or same-path conflicting bytes. This is the collation
      contract only; it is not the final thread-count differential `.drv`
      harness, does not execute the parallel scheduler, does not materialize
      derivations, and does not audit live attrset iteration under nondeterminism
      (§4.4) — **P3.5** precursor, `C-12`/`S-13`.
- [x] Current Chase-Lev-backed tree-walk raw differential precursor:
      `ratchet-oracle::eval::compare_parallel_tree_walk_raw_chase_lev_across_worker_counts`
      evaluates independent lowered roots with the serial tree-walk raw renderer,
      re-evaluates those roots through the Chase-Lev-backed tree-walk bridge for
      each requested worker count, and compares normalized raw bytes or exact
      root-local tree-walk errors in stable task order. It preserves
      source-backed root provenance, preflights worker-count encodability before
      serial evaluation, rejects persistent parse/eval cache roots, and uses
      collect-all execution so every root participates in the differential.
      Tests cover 1/3 worker-count parity, empty roots, empty worker-count
      rejection, worker-count preflight with an observable no-serial-eval guard,
      parse/eval persistent-cache rejection, root-local errors, and
      source-backed root-local errors. This is an independent-root raw-rendering
      differential only: it does not run a full derivation closure, compare live
      `.drv` materialization, prove shared-thunk graph scheduling, audit all
      nondeterministic attrset iteration, wire ready-work park tokens or CAS wait
      integration, or satisfy the full parallel evaluator parity gate (§4.4) —
      **P3.5** precursor, `C-12`/`S-13`.

### Concurrency runtime — rayon, fibers, tokio (§5.5)

- [ ] rayon (crossbeam Chase-Lev) for CPU-bound thunk-graph forcing; tokio reactor on its own threads for genuinely-blocking eval-time I/O (IFD, network fetchers) (§5.5.1–§5.5.2) — **P3.5**, `C-16`.
- [ ] Stackful fibers (green threads) so an I/O-blocked eval node parks its whole synchronous recursive force stack and frees its worker (M:N, Go-style) **without** async-coloring `force`; full async-coloring documented and rejected (§5.5.3) — **P3.5**, `C-16`; the fiber stack-switch is fenced `unsafe` (§ doc [14](14-integration-with-aos.md) §10 item 4).
- [ ] Correctness/perf rules: local fast reads (`readFile`/`readDir`/`pathExists`/local `import`) stay synchronous; never `block_on` a compute worker; a fiber blocked on a *claimed thunk* yields the same way as one blocked on I/O; scheduling nondeterminism never reaches output (§5.5.4) — **P3.5**, `C-16`.
- [ ] Measure-gated fiber turn-on: build sync core + rayon + tokio reactor first; enable fiber suspension only when eval-time blocking-I/O concurrency (IFD/fetch-heavy) justifies it (§5.5.5) — **P3.5**; `M-22` (build the variants, measure, keep the winner; never a descope).

### The loom / Miri / TSan audit (§3.6, the shipping gate)

- [ ] loom model of the `Suspended → Pending → Awaited → Forced/Failed` machine with 2–3 racing workers plus a self-reentry case (§3.6) — **P3.5**, `R-4` (committed early gate per `C-12`).
- [ ] The five loom-checked invariants: no lost wakeup, no double-force of an effectful primop, no torn read of the thunk word, no deadlock on a claimed thunk, correct acquire/release pairing on the value publish (§3.6) — **P3.5**, `R-4`; loom green is a *precondition* of shipping, not a follow-up.
- [ ] Miri over the safe tree-walk oracle + small parallel harnesses (UB + data-race checking) and ThreadSanitizer over the *actual* parallel binary (scheduler glue, shared insert-or-get tables, fiber runtime) (§3.6) — **P3.5**, `R-4`/`S-17`.

### Parallel GC × thunk mutation (§5)

- [ ] Tier-A one-shot CLI: per-worker bump nurseries, never-free, drop the arena at exit — **no collection during eval, so no mutator/collector race**; L1 + L2 fully unconstrained (§5.2) — **P3.5**, `C-12`; this is the build-time bottleneck mode and the most important simplification.
- [ ] Tier-B Stage B0 stop-the-world parallel collector for the daemon: safepoint all workers, collect (itself parallel), resume — no load barriers, no concurrent relocation (§5.3) — **P8** (daemon-only, downstream of `S-8` Tier B).
- [ ] Region inference / escape analysis to confine non-escaping intermediates to the private nursery, shrinking the cross-region remembered set before GC runs (§5.4) — **P4** analyses ([07](07-laziness-and-whole-program-analyses.md), `S-9`); feeds the single-entry-thunk frame-local restriction (`C-8`).
- [ ] **Research-grade, in scope:** Stage B1 concurrent low-pause moving GC (ZGC/Shenandoah-style colored pointers + load barriers), the load-barrier-before-CAS sequence, and the WHNF-tag vs colored-pointer-bit co-design (§5.3, open questions §8.1–§8.2) — **P8**, `R-1`/`R-2`/`R-3`/`R-4`; daemon-only, verified under loom/Miri before shipping, built (not dropped) under the unlimited-budget mandate.

### Failure, exceptions, cancellation (§6)

- [ ] Per-thunk `Failed` state (error captured once, re-raised identically by all waiters); L1 island isolation; cooperative cancellation checked at GC-poll/task-boundary safepoints (never a forced mid-force kill); deterministic canonical-order error selection (§6) — **P3.5**, `C-12`.
- [x] Current fallible L1 root execution precursor:
      `ratchet-oracle::eval::parallel_failure` executes independent top-level
      tasks whose root-local failures are collected as data rather than scheduler
      corruption, keeps successful and failed outcomes sorted by stable task
      index, selects the canonical observed error by lowest task index, and
      models fail-fast cancellation as a shared flag checked before workers probe
      queues for more top-level work; workers already past that check may still
      start another task. Unit tests cover collect-all error collation, stable
      success ordering, cooperative task-boundary cancellation, canonical
      selection over observed multi-worker failures, no cancellation under
      collect-all, worker accounting, empty task sets, worker panic reporting, and
      stable policy display. This is the L1 root-failure contract only; it does
      not attach payloads to per-thunk `Failed` states, re-raise stored thunk
      errors to waiters, wire GC-poll safepoints, interrupt in-flight work,
      integrate with Nix derivation evaluation, or satisfy the loom/Miri/TSan gate
      (§6) — **P3.5** precursor, `C-12`/`R-4`.
- [x] Current tree-walk parallel payload failed-replay precursor:
      With parallel thunk payloads enabled, `TreeWalk::force_value` now checks
      an admitted `TreeWalkParallelThunkCell` for terminal success or failure
      before entering the serial force path, then wins or waits on the sidecar
      claim before any serial body execution on a miss. Successful sidecar hits
      replay the `Value` as before; failed sidecar hits re-raise the stored
      `TreeWalkError`; and a serial force error from the sidecar owner publishes
      a failed sidecar payload before returning so later force attempts replay
      the same captured error without rerunning the serial body. Tests cover
      pre-published failed sidecar replay, same-worker claimed-sidecar
      self-cycle handling, serial division-by-zero publication and replay, and
      suspended serial `ThunkCell` preservation after failed force. This is
      still a default-off payload replay precursor only: the serial `ThunkCell`
      remains the body/state owner after sidecar admission, the live scheduler
      wait-or-steal force path does not yet execute evaluator thunk bodies, and
      the scheduler park-token, lock-free waiter-list, GC-poll cancellation, and
      loom/Miri/TSan gates remain open (§6).

## References

- Determinate Systems, *Parallel Nix evaluation* — atomic `type` field,
  `Pending`/`Awaited`/`Failed` thunk states, lock-free symbol table, 4.1×
  (`nix flake show`, 23.70s→5.77s) and 3.0× (`nix search`) speedups.
  <https://determinate.systems/blog/parallel-nix-eval/>
- Determinate Systems, *Parallel evaluation comes to Determinate Nix (3.11.1)*.
  <https://determinate.systems/blog/changelog-determinate-nix-3111/>
- NixOS/nix PR #10938, *Multithreaded evaluator* (edolstra).
  <https://github.com/NixOS/nix/pull/10938>
- Simon Marlow et al., *Runtime Support for Multicore Haskell* — sparks,
  work-stealing spark distribution, eager vs. lazy blackholing.
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2009/09/multicore-ghc.pdf>
- GHC User's Guide, *Using SMP parallelism* — `par`/spark semantics,
  `-feager-blackholing`.
  <https://downloads.haskell.org/ghc/latest/docs/users_guide/using-concurrent.html>
- Chase & Lev, *Dynamic Circular Work-Stealing Deque* (lock-free; basis for
  Rayon/crossbeam). Formal verification under weak memory:
  <https://arxiv.org/pdf/2309.03642>
- tokio-rs/loom — concurrency permutation tester: runs a test "many times,
  permuting the possible concurrent executions of that test under the C11 memory
  model," trying every value an atomic load may observe, with state-reduction to
  bound the explosion (§3.6 audit plan):
  <https://github.com/tokio-rs/loom>, <https://docs.rs/loom/latest/loom/>
- crossbeam / Chase-Lev deque in Rust.
  <https://docs.rs/crossbeam/0.3.2/crossbeam/sync/chase_lev/index.html>
- JEP 333, *ZGC: A Scalable Low-Latency Garbage Collector* — colored pointers,
  load barriers.
  <https://openjdk.org/jeps/333>
- *Deep Dive into ZGC* (ACM TOPLAS) — concurrent relocation, load-barrier
  self-healing.
  <https://dl.acm.org/doi/full/10.1145/3538532>
