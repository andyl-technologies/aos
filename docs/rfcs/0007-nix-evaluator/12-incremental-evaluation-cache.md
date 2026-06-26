# RFC-0007 - Incremental Evaluation Cache

> The fastest evaluator is the one that does not evaluate. Every other
> document in this RFC set describes how to make a single evaluation cheap;
> this one describes how to make the *second* evaluation, and every evaluation
> thereafter, nearly free. For the AOS build-time problem this is the largest
> single lever — larger than any interpreter constant factor — and it is the
> first item on the roadmap (see [roadmap and risks](17-roadmap-and-risks.md)).

## 1. Motivation: the systemic win versus the constant-factor win

The other performance documents in this set — value representation
([05](05-value-representation.md)), memory management
([06](06-memory-management-and-gc.md)), laziness analyses
([07](07-laziness-and-whole-program-analyses.md)), Cranelift tiering
([08](08-execution-tiers-and-cranelift.md)), hidden classes
([09](09-attribute-sets-hidden-classes-and-inline-caches.md)) — all attack the
cost of *one* evaluation. They turn a 10-second evaluation into, optimistically,
a 1-to-3-second evaluation. That is a constant factor, and constant factors are
bounded: you cannot evaluate faster than zero.

The incremental cache attacks a different axis. In the AOS workflow, the vast
majority of evaluations are *re-evaluations* of a package set that has barely
changed since the last one. A developer edits one package expression, or a
comment in `lib/`, or bumps a single version pin, and then asks `aos build` to
re-instantiate. Today that re-instantiation re-evaluates the entire transitive
expression closure that feeds the requested derivation — tens of thousands of
thunks, almost all of which produce *exactly the value they produced last time*.

A correct incremental evaluator does asymptotically better than a fast
batch evaluator: its cost is proportional to the *size of the change and its
fan-out*, not to the size of the program. Editing a comment recomputes nothing
observable. Bumping a leaf package recomputes that package's derivation and the
handful of derivations that consume it, not the toolchain beneath it. This is
the difference between `O(program)` and `O(change)`, and on a stable package set
`O(change)` is usually a rounding error.

This is also the lowest-risk high-value item in the whole RFC. It is *largely
independent of interpreter speed*: it sits above the evaluator as a memoization
and change-propagation layer, so it pays off even on the tier-0 tree-walking
oracle ([08](08-execution-tiers-and-cranelift.md)), before a single line of
Cranelift exists — which is why the roadmap ([17](17-roadmap-and-risks.md))
ranks it first.

### 1.1 Why this is sound in Nix and unsound almost everywhere else

Incremental computation in a general-purpose language is hard because functions
are not pure: a memoized result can be invalidated by mutation of state the
function read but did not declare as a dependency. Frameworks like Salsa,
Adapton, and Skip spend most of their complexity budget *tracking* which mutable
inputs a computation touched, so they know what to invalidate. (Skip went as far
as building a whole type system to prove the absence of side effects at a
function boundary before it would let you memoize across it.)

Nix hands us that soundness for free:

- **Purity.** A Nix expression's value is a function only of the expression and
  its captured environment. There is no hidden mutable input, no clock, no
  filesystem read that is not already reified as a store path or a
  `builtins.readFile` with a content hash. (The `import`/`readFile`/`pathExists`
  family *is* an effect on the filesystem; we treat those reads as explicit,
  hashed inputs — see §6.)
- **Immutability.** Values never mutate after construction. A memoized value
  cannot be corrupted by a later write.
- **Whole-program batch nature.** Evaluation is a closed-world batch job over a
  known fixed set of source files, not an open-ended interactive session. We can
  hash the entire input frontier up front.

Under these three properties the demand-driven incremental-computation model
becomes *total and sound* rather than partial and best-effort. The techniques we
borrow from Salsa (rust-analyzer), Adapton, Skip, and *Build Systems à la Carte*
are not approximations here; they are exact. This is the core of the synthesis
thesis ([03](03-architecture-overview.md)): a fast Nix evaluator is a fast lazy
GC'd functional-language implementation *plus* a recomputation/caching layer,
and Nix's purity is what makes the caching layer dramatically more effective than
it can be in the systems we are stealing from.

**The soundness boundary, drawn precisely.** Two pieces of machinery must not be
conflated, because they transfer to other languages on different terms
([28](28-generalization-and-language-dialects.md) §6). The *demand-graph engine*
itself — memoization, suspend/resume, parallelism, the node model, all of
`ratchet-cache` — is **fully generic**: a Salsa/Adapton-style incremental
computation library that reuses for anything, soundly, because it tracks the
dependency edges it propagates over. The *persistent content-addressed cache and
early cutoff* are a stronger claim that rests on **purity *and* closed-world-batch
nature**, and that pair does not transfer everywhere:

- **Nix** ✓ — pure, immutable, and a closed-world batch over a fixed file set; all
  three properties above hold, so cross-run persistence is exact.
- **TLA+ / TLC model-checking** ✓ — a fixed spec plus fixed constants is a closed
  world, so memoizing pure operator evaluations across a checking run, and
  early-cutoff re-checking after a spec edit, are sound (a capability TLC lacks
  today).
- **A running general-purpose program (e.g. compiled Haskell)** ✗ — its runtime is
  *open-world* (stdin, sockets, the clock), so a cross-run persistent cache over
  its execution is unsound. Only its *compile-time* evaluation (CAFs, Template
  Haskell) qualifies — a much narrower win.

The rule to carry: **the memoization engine is generic; cross-run persistent
soundness requires pure *and* closed-world-batch.** Nix and TLC have both; a
running program does not.

## 2. Evaluation as a demand-driven incremental computation graph

We model an evaluation not as a tree-walk that happens to memoize, but as the
incremental maintenance of **the demand graph** (the Salsa/Adapton lineage) — a
dependency graph of cached computations whose units we call **graph nodes**, the
same abstraction Salsa calls a query graph and Adapton calls a *demanded
computation graph (DCG)*. Throughout this document "node" denotes a graph node
of this demand graph (each corresponding to a forced thunk or a derivation, §3.1),
distinct from the AST/IR nodes of [the frontend](04-frontend-parser-and-ir.md)
and from the derivation graph (the `.drv` output DAG) of
[derivation and store compatibility](11-derivation-and-store-compatibility.md).
This demand-graph engine — memoization, change propagation, the node table, the
durable CA store — is the **`ratchet-cache`** crate of the language-agnostic
`ratchet` engine ([28](28-generalization-and-language-dialects.md) §3); nothing
in it is Nix-specific.

```text
        inputs (leaves)                 derived nodes (memoized)
        ───────────────                 ────────────────────────

   ┌──────────────────┐
   │ file:lib/foo.nix │──hash─┐
   └──────────────────┘       │      ┌────────────────────────┐
                              ├─────▶│ thunk #4173            │
   ┌──────────────────┐       │      │  key = H(expr ⊕ env)   │──┐
   │ file:pkgs/bar.nix│──hash─┘      │  value-hash = blake3…  │  │
   └──────────────────┘              └────────────────────────┘  │
                                                                 ▼
   ┌──────────────────┐              ┌────────────────────────┐  ┌────────────┐
   │ builtin:readFile │──hash───────▶│ derivationStrict #921  │─▶│  .drv path │
   │   /…/version     │              │  value-hash = blake3…  │  │ (SHA-256)  │
   └──────────────────┘              └────────────────────────┘  └────────────┘
```

Two distinct hashes flow through this graph and must never be confused:

1. **The dependency key** of a node — `H(expression-identity ⊕ environment)` —
   answers *"have I computed this exact thing before?"*. This is an internal,
   non-cryptographic identity used to find a cache entry. (See §5 for the
   hashing policy and §3 for how the key is constructed.)
2. **The value-hash** of a node — `blake3(canonical(value))` — answers *"did the
   result change?"*. This is what drives **early cutoff** (§4) and what we
   persist for cross-run, cross-machine sharing (§6).

Neither of these is the Nix-observed SHA-256. The SHA-256 store-path and
`.drv` hashes are a *third* thing, computed only at the
`derivationStrict` boundary, and are governed entirely by the
bug-for-bug-compatibility constraint ([02](02-compatibility-constraints.md),
[11](11-derivation-and-store-compatibility.md)). The incremental cache must
never let its internal hashing leak into a Nix-observed hash; doing so would
change a store path and trigger the catastrophic toolchain rebuild this whole
RFC exists to avoid. §5 makes the separation a hard invariant.

### 2.1 The three-layer trace model (Build Systems à la Carte)

Mokhov, Mitchell, and Peyton Jones's *Build Systems à la Carte* gives the
precise vocabulary for what kind of trace a build/eval system keeps, and the
trade-offs map directly onto our design:

| Trace kind            | Stores                          | Early cutoff?            | We use it for                          |
|-----------------------|---------------------------------|--------------------------|----------------------------------------|
| Verifying trace       | hashes of deps + result         | Yes (compare result hash)| In-process node freshness checks       |
| Constructive trace    | deps + the *resulting value*    | Limited (1 level only)   | The persistent value store (§6)        |
| Deep constructive     | full transitive value closure   | No (except at `n` levels)| Rejected — kills early cutoff          |

The paper's key result for us: *deep constructive traces cannot support early
cutoff except at `n` levels of dependencies* — constructive traces are the
special case `n = 1`, and the input-only verifying approach is `n = ∞`. Early
cutoff is the whole point of this document, so we keep **verifying traces** for
freshness decisions (compare value-hashes, propagate only on change) and use
**constructive storage** only as the content-addressed value store that lets us
*reconstruct* a value we have decided is fresh without recomputing it. We
deliberately avoid deep constructive traces, which would force us to choose
between early cutoff and shallow rebuilds.

## 3. Demand-driven memoization

### 3.1 What a node is

A memoized node corresponds to a thunk or a derivation. Recall from the
execution model ([03](03-architecture-overview.md),
[05](05-value-representation.md)) that a thunk is `(code_ptr, captured_env,
state)`. The incremental layer wraps the *force* operation:

```rust
/// Forces `thunk` to weak head normal form, consulting and populating the
/// incremental cache. Pure-Nix semantics guarantee the result depends only on
/// the thunk's expression identity and captured environment, so a hit is
/// always safe to return without re-running compiled code.
///
/// # Errors
///
/// Propagates any evaluation error (type error, assertion failure, infinite
/// recursion detected via blackholing) raised while forcing on a cache miss.
fn force_memoized(rt: &Runtime, thunk: ThunkId) -> Result<ValueId, EvalError> {
    let key = rt.cache.key_of(thunk);          // H(expr ⊕ env), §3.2
    if let Some(node) = rt.cache.get_fresh(key) {
        rt.stats.incr_hit();
        return Ok(node.value);                  // demand satisfied without work
    }
    rt.stats.incr_miss();

    // Record reads performed during forcing so the node's dependency edges are
    // captured automatically (Adapton-style DCG construction).
    let (value, deps) = rt.cache.tracing(key, || force_cold(rt, thunk))?;
    let vhash = rt.cache.value_hash(value);     // blake3(canonical(value)), §5
    rt.cache.insert(key, Node { value, deps, vhash });
    Ok(value)
}
```

The crucial property — and the reason this is *demand-driven* rather than a
bulk pre-pass — is that a node is created **only when it is forced**. We never
walk the whole expression tree eagerly to populate the cache; laziness
([07](07-laziness-and-whole-program-analyses.md)) and the cache cooperate so
that exactly the thunks the requested derivation actually demands become nodes.
This is the Adapton separation of *inner incremental computations* from *outer
observers*: change propagation runs only for results an observer (here, the
top-level `derivationStrict` we are instantiating) actually demands.

### 3.2 Constructing the dependency key

The key for a thunk node is a hash of its **expression identity** combined with
its **captured environment**. Both halves require care.

**Expression identity.** Each AST/IR node ([04](04-frontend-parser-and-ir.md))
is assigned a stable identity derived from the *content hash of the source file*
plus the node's position within that file's compiled IR. Because parse/compile
artifacts are already cached content-addressed by file hash
([04](04-frontend-parser-and-ir.md)), two runs over an unchanged file produce
the same expression identities for free. Editing a file changes its content
hash, which changes the identity of *every* node in that file — but, critically,
only that file. Early cutoff (§4) then prevents the change from propagating
beyond the nodes whose *values* actually moved.

**Captured environment.** A thunk closes over an environment — the values bound
in the lexical scopes it can see. We cannot hash the environment by structural
deep-walk on every force; that would reintroduce the `O(program)` cost we are
trying to eliminate. Three mechanisms keep environment hashing cheap:

1. **Slot-indexed environments.** Scope resolution
   ([04](04-frontend-parser-and-ir.md)) compiles variable references to static
   slot indices (de Bruijn-style), so an environment is a flat vector of value
   pointers, not a chain of named maps.
2. **Hash-consing / maximal sharing.** Because values are interned
   ([05](05-value-representation.md)), structurally equal values share one
   allocation and carry a precomputed value-hash. Hashing an environment slot is
   then reading a cached `u64`/`blake3` field off a pointer, not re-walking a
   structure. This is the single most important enabler: hash-consing turns
   value-hashing from a tree-walk into a field load, and Nix's immutability is
   what makes hash-consing sound.
3. **Free-variable narrowing.** Strictness/escape analysis
   ([07](07-laziness-and-whole-program-analyses.md)) already computes each
   expression's free-variable set. The key mixes in *only the slots the
   expression can actually reference*, not the whole frame. A thunk that closes
   over a 200-binding `let` but uses two of them keys on two value-hashes.

The key is therefore
`xxh3(expr_identity ‖ len₁‖vhash(fv₁) ‖ … ‖ lenₙ‖vhash(fvₙ))`, computed
in-process with xxh3 for speed (§5).

> **Decision (closed): ordered, length-prefixed combiner — never bare XOR.**
> An earlier draft combined the free-variable hashes with XOR (`⊕`). XOR is
> order- and multiplicity-blind: permuting two slots, or two slots sharing a
> value-hash, collide to the same key, producing a *false cache hit* — a stale
> value surviving a real change, i.e. a correctness bug, not merely a perf one.
> The combiner is therefore the free-variable hashes concatenated **in
> canonical slot order, each length-prefixed** (`‖` above), then hashed once.
> Wherever this document writes `⊕` as shorthand for "expression combined with
> environment" (the diagrams in §3.1, §6), it denotes this ordered combiner,
> not arithmetic XOR.

### 3.3 Granularity: what we memoize and what we do not

Memoizing *every* thunk activation is wrong — the canon's execution model
([03](03-architecture-overview.md)) is explicit that thunk activations number in
the billions while expressions number in the tens of thousands. A cache entry
per activation would cost more in hashing and table churn than it saves. We
memoize at a coarser grain:

- **Always cache:** `derivationStrict` results (the units we ultimately diff and
  persist), `import` results (file-granular, §6), and top-level attribute
  bindings of large attrsets (e.g. each `pkgs.<name>`), which are the natural
  re-use boundaries across runs.
- **Conditionally cache:** thunks whose cardinality analysis
  ([07](07-laziness-and-whole-program-analyses.md)) marks them *used-many* and
  whose value-hash is cheap (already interned). A used-once thunk gains nothing
  from a cache entry within a run and is left to ordinary forcing.
- **Never cache:** trivially cheap thunks (a literal, a variable reference, a
  small arithmetic node) where the cache probe costs more than the recompute.
  Strictness analysis already compiles many of these eagerly with no thunk at
  all.

This is the same instinct HotSpot applies to tiered compilation
([08](08-execution-tiers-and-cranelift.md)): spend the expensive machinery only
where profiling says it pays. The promotion signal here is *cross-run reuse
frequency and value-hash cost*, recorded in the persistent cache's metadata so
later runs cache the right grain.

### 3.4 The materialization threshold: when a memoized result hits disk

§3.3 decides *what grain* to cache; this subsection answers the orthogonal
question of *when a cached result is written to the durable packfile* (§6), and
the two are not the same decision. Memoization and materialization are **two
tiers**:

- **RAM-tier (memoization).** A node may be entered in the in-process memo table
  (the `nodes` map) cheaply — it is just a pointer to an already-interned value
  ([05](05-value-representation.md)) plus its dependency edges. This is free
  enough that the §3.3 "conditionally cache" set lives here: within a run, a
  used-many thunk earns a RAM memo entry the moment its second demand arrives.
- **Disk-tier (materialization).** Writing a graph node and its value to the
  durable CA store (§6) is *not* free: it costs a blake3 value-hash, a canonical
  serialization of the WHNF value, and an append to the memory-mapped packfile.
  A node is materialized to disk **only when**

  ```text
     eval_cost(node)  >  hash_cost(value) + serialize_cost(value) + io_cost
                      AND
     likely_redemanded_across_runs(node)
  ```

  Both conjuncts must hold. The first is the **cost inequality** that prevents
  persisting tiny units of work: a literal, a small arithmetic node, or a thunk
  that forces in nanoseconds can never repay the bytes it would cost to hash,
  serialize, and store — its `eval_cost` is below the floor set by the write
  itself, so it stays RAM-only or is not cached at all. The second conjunct
  guards against persisting work that is expensive but single-shot: a node demanded
  once and never again across runs is, on disk, pure overhead (the §8.2 mantra —
  caching a node never re-demanded is a net loss — applies to the *durable* tier
  specifically).

In practice this collapses to a clean default that matches §3.3's grain:

- **Never materialize:** trivial nodes (the §3.3 "never cache" set) — they fail
  the cost inequality by construction.
- **Always materialize:** `derivationStrict` results, `import`/`files/` IR, and
  large-library attribute bindings (`pkgs.<name>`). These dominate `eval_cost`
  (a `derivationStrict` drags ATerm serialization and SHA-256 hashing behind it;
  an `import` drags a whole parse+compile), and they are the canonical cross-run
  reuse boundaries, so both conjuncts hold trivially.
- **Materialize on promotion:** conditionally-cached used-many thunks graduate
  from RAM-tier to disk-tier when the persistent metadata's reuse counter (§3.3)
  shows them re-demanded across runs *and* their measured `eval_cost` clears the
  write floor.

The two-tier split is why the durable store stays small (§8.2): the billions of
cheap thunk activations never reach it, the millions of conditionally-memoized
nodes touch it only if they prove their cross-run worth, and the disk holds
roughly the set of nodes whose recomputation is genuinely expensive and
genuinely recurring.

### 3.5 The deduplication story: three layers, and why thunks are not all hashed

Deduplication in aos-nix is split across three layers that operate at different
times and granularities. They are easy to conflate, so we name them explicitly
and state the boundary between them.

1. **Compile-time thunk sharing** (full-laziness / let-floating / CSE,
   [07](07-laziness-and-whole-program-analyses.md)). Identical *thunk
   allocations* are shared **statically**, before any value exists: floating a
   loop-invariant subexpression out so it is allocated once, or common-
   subexpression-eliminating two syntactically identical thunks into one. This is
   structural sharing of *code and closures*, decided by the compiler with **no
   runtime hashing at all**.
2. **Runtime coarse memoization** (xxh3 cache keys, this document, §3). At the
   granularity of §3.3 — *not every thunk* — a forced result is memoized under
   `H(expr ⊕ env)` so a second demand for the same computation is a table hit.
   This dedups *work*, and it deliberately covers only the coarse grain the
   §3.3/§3.4 policy selects.
3. **Post-force value hash-consing** ([05](05-value-representation.md)).
   Once a thunk is forced to WHNF, structurally-equal *values* are interned:
   xxh3-keyed in-process for O(1) pointer equality, blake3-keyed in the durable
   CA store (§6). Hash-consing is what makes the store-path strings and identical
   derivation env attrsets that recur across the package set collapse to one
   allocation in RAM and one entry on disk, and it is what supplies the
   already-computed value-hashes that §3.2's keys and §4's early cutoff read as a
   field load rather than a tree-walk.

The deliberate gap in the picture: **we do not hash unforced thunks.** It is
tempting to imagine deduplicating thunks by the value they will produce, but that
is unsound. A thunk's value is unknown without forcing it, and forcing-to-hash
would (a) destroy laziness — the entire point of the evaluator — by evaluating
thunks no observer demanded, and (b) be non-terminating or error-raising in
general, because un-demanded thunks may denote infinite structures
(`let xs = [1] ++ xs`) or carry errors (`throw`/`abort`) that a correct lazy
evaluator must never trigger. Layer 1 therefore keys thunk identity on
*expression identity* (§3.2), and layer 2's cache key mixes in *only the
value-hashes of already-forced free variables* — never "the value the thunk will
become." A thunk's value-hash enters the system exactly once: at layer 3, *after*
it has been legitimately forced on demand.

## 4. Early cutoff

Early cutoff is the mechanism that turns "one file changed" into "almost nothing
recomputed". It is the single feature that makes incremental evaluation
*systemic* rather than merely a within-run memo table.

### 4.1 The mechanism

When an input changes, every node transitively keyed on it has a stale key and
must be *reconsidered*. Reconsidering a node means recomputing its value — but
before propagating that recomputation to the node's consumers, we compare the
**new value-hash** against the **old value-hash**:

```text
   input changed ──▶ node A reconsidered
                       │
                       ├─ recompute A's value
                       ├─ vhash(A_new) == vhash(A_old) ?
                       │        │
                       │        ├─ YES ──▶ EARLY CUTOFF
                       │        │          consumers of A are NOT dirtied;
                       │        │          propagation stops here.
                       │        │
                       │        └─ NO ───▶ dirty A's consumers, recurse upward.
```

This is exactly Salsa's *red-green* algorithm (the "red/green" name rust-analyzer
inherited from rustc's query system): backward flooding of invalidation stops at
the first query whose result is unchanged despite a changed input. It is also
the verifying-trace early cutoff of *Build Systems à la Carte*. We adopt the
same shape.

### 4.2 Why early cutoff is *more* powerful in Nix than in rust-analyzer

In an editor, early cutoff is valuable but bounded: a code edit usually changes
*some* observable type or diagnostic, so the cutoff frontier is shallow. In a
Nix package set the cutoff frontier is frequently the *entire* change:

- **Comments and formatting.** Nix `.drv` output is a function of *values*, not
  source text. A reformatting pass or a comment edit changes file content hashes
  (so keys go stale and nodes are reconsidered) but produces *identical values*,
  so every reconsidered node hits early cutoff at depth 0. Net recomputation:
  re-parse one file, recompute a handful of thunks, propagate nothing. The
  requested `.drv` is reproduced from cache.
- **Adding an unused binding.** A new `let` binding that nothing demands changes
  the file's content hash but is never forced, so it never even becomes a node.
  Early cutoff is not needed — laziness alone elides it.
- **Refactors that preserve values.** Renaming a local, hoisting a
  subexpression, or splitting a file in a value-preserving way recomputes the
  touched thunks and then cuts off, because the *values* that flow into
  `derivationStrict` are byte-for-byte the same.

The deeper reason is the compatibility constraint itself
([02](02-compatibility-constraints.md)): we are *already required* to produce
byte-identical `.drv` output, which means we are already required to compute a
canonical value at the `derivationStrict` boundary. The value-hash that drives
early cutoff is a hash of that very canonicalization. The thing we must compute
for correctness is the thing that powers the optimization. Purity and
immutability make the value-hash a sound change-detector; the
must-be-byte-identical requirement makes the canonical value already lie on the
critical path.

### 4.3 Interaction with the SHA-256 boundary

Early cutoff at a `derivationStrict` node is the most valuable cutoff of all,
because it can short-circuit the SHA-256 `.drv`/store-path computation
([11](11-derivation-and-store-compatibility.md)) — which itself involves ATerm
serialization and input-addressed output-path hashing. If a derivation node's
inputs are unchanged (same value-hashes for `name`, `builder`, `args`, `env`,
input-derivation references, string contexts), the node is fresh and we return
the cached `.drv` path *without re-running `derivationStrict` at all*. CA
derivations ([11](11-derivation-and-store-compatibility.md)) extend this idea one
layer down into the build graph, enabling *build-layer* early cutoff (a rebuild
whose output content is unchanged stops propagating to dependents); that is a
build concern, but the eval-layer cache is its mirror image and shares the
content-addressed discipline.

## 5. Hashing policy

The cache uses three hash functions for three jobs, and the separation is a hard
invariant, not a convenience.

| Hash      | Where                                   | Why this one                                                        |
|-----------|-----------------------------------------|---------------------------------------------------------------------|
| **xxh3**  | in-process keys (§3.2), hot probes      | Non-cryptographic, fastest portable hash (multi-GB/s); collisions are tolerable because keys are checked against an in-process table we control and a collision only risks a *recompute*, never a wrong answer. |
| **blake3**| durable value-hashes (§4), persistent CA-store keys (§6) | Cryptographic and collision-safe at fleet scale; parallel/SIMD-friendly tree hash; a blake3 collision is what we'd need to fear when a *wrong* cached value could silently flow into a `.drv`, so the durable, shared, cross-machine layer must be cryptographic. |
| **SHA-256** | *only* Nix-observed `.drv` and store-path hashing | Non-negotiable: it is the Nix on-disk format ([02](02-compatibility-constraints.md), [11](11-derivation-and-store-compatibility.md)). Any other choice changes store paths. |

### 5.1 Why not one hash everywhere

- **Why not SHA-256 for internal keys?** SHA-256 is ~10–50× slower than xxh3 and
  blake3 for bulk hashing; using it for billions of in-process probes would make
  the cache a net loss. We reserve SHA-256 for the boundary where Nix's format
  *forces* it.
- **Why not xxh3 for the durable store?** xxh3 is not collision-resistant
  against adversarial or even merely large-scale accidental inputs. The durable
  CA store is shared across CI machines and persists for the life of the project; a
  silent collision there could substitute one cached value for another and, if
  that value feeds `derivationStrict`, corrupt a `.drv`. blake3's cryptographic
  strength is the price of letting cache entries cross the trust boundary between
  machines. Published benchmarks put xxh3 around 30+ GB/s with SIMD versus
  blake3 around 7–8 GB/s on the same large-input class — both far above SHA-256 —
  so the durable layer pays roughly a 4× hashing cost for cryptographic safety,
  which is cheap relative to the evaluation it elides.
- **Why blake3 specifically over blake2/SHA-3?** It is the fastest of the
  cryptographic options on commodity x86-64, it is a tree hash (parallelizable,
  which matters once parallel forcing lands — see [13](13-parallel-evaluation.md)),
  and it produces a flat 256-bit digest convenient as a CA-store key.

### 5.2 The leak invariant

> **Invariant (no internal hash may reach a Nix-observed hash).** The output of
> xxh3 or blake3 must never appear, directly or indirectly, in the bytes that
> feed a SHA-256 store-path or `.drv` hash. The `derivationStrict` path
> ([11](11-derivation-and-store-compatibility.md)) computes its inputs from
> *values*, never from cache keys or value-hashes.

The differential harness ([15](15-differential-testing-and-benchmarking.md)) is
the enforcement mechanism: any leak would change a store path and show up as a
`.drv` diff against `nix-instantiate`. This is also why the cache is allowed to
be *advisory* — a cache that returns a stale or wrong value is caught by the
harness during development, and in production a miss merely costs a recompute,
never a wrong `.drv`, provided the leak invariant holds.

## 6. Content-addressed persistence and Attic integration

A within-run memo table already eliminates redundant work inside a single
`aos build`. The systemic win comes from making the cache **persist across runs
and across machines**. AOS already runs an Attic binary cache
([CI infra](../../) — see the AOS deployment notes) that shares *build outputs*
across CI machines and developer workstations. We extend that same
content-addressed sharing from build outputs to **eval outputs**.

### 6.1 The persistent value store

The durable cache is a content-addressed store (the CA store, or value store)
keyed by blake3:

```text
   eval-cache/
   ├── nodes/                       # verifying traces: key → node metadata
   │   └── <xxh3-key>.node          #   { vhash, dep-keys[], value-cas-ref }
   ├── values/                      # constructive store: vhash → value bytes
   │   └── <blake3-vhash>.val       #   canonical serialized Nix value (WHNF)
   └── files/                       # import cache: realpath+content → IR
       └── <blake3-filehash>.ir     #   parsed + scope-resolved + compiled IR
```

- `nodes/` holds **verifying traces**: for each computed node, its value-hash and
  the keys of its dependencies. This is what answers "is this node fresh?".
- `values/` holds the **constructive store** (Build Systems à la Carte `n = 1`):
  the canonical serialized value, content-addressed by its blake3 value-hash.
  This is what lets us *materialize* a fresh node's result without recomputing
  it. Because values are hash-consed and immutable
  ([05](05-value-representation.md)), structurally identical attrsets and strings
  — store-path strings and identical derivation env attrsets recur constantly
  across the package set — deduplicate to a single CA-store entry, exactly as Attic
  globally deduplicates NARs and chunks.
- `files/` is the parse/compile cache from
  ([04](04-frontend-parser-and-ir.md)) made durable: the whole package set is
  parsed and compiled once and reloaded thereafter.

### 6.2 Why content-addressing is the right shape here

Content-addressing gives three properties we need and that Attic already proves
out for NARs:

1. **Global deduplication.** Identical values map to one entry regardless of
   which package or which machine produced them. The hash-consing
   ([05](05-value-representation.md)) that dedups values in memory dedups them on
   disk for free, because the on-disk key *is* the value-hash.
2. **Trivial cross-machine sharing.** A value-hash is a self-certifying name. A
   CI machine can fetch a value by hash from the shared store and trust it (the
   blake3 hash verifies the bytes), the same way Attic serves NARs by hash. No
   coherence protocol, no invalidation messages — a content-addressed entry is
   immutable by construction.
3. **Safe garbage collection.** Mirroring Attic's three-level GC (local cache
   mapping → global NAR store → global chunk store), the eval CA store GCs in layers:
   prune `nodes/` entries older than a retention window, then collect `values/`
   entries no surviving node references, then collect `files/` IR no surviving
   node imports. Orphan collection is sound because references are explicit in the
   node metadata. (See [GC](06-memory-management-and-gc.md) for the in-process
   counterpart; this is its persistent analogue.)

### 6.3 Treating `import`/`readFile` reads as hashed inputs

The filesystem-reading builtins (`import`, `readFile`, `readDir`, `pathExists`,
path coercion) are the one place evaluation observes mutable external state. We
make those reads *explicit, hashed leaves* of the dependency graph:

- `import path` becomes a node keyed on `blake3(content_of(realpath))`, and its
  result is the compiled IR (`files/`) and the value produced by evaluating it.
  This is the realpath + content-hash import cache from
  ([04](04-frontend-parser-and-ir.md), [10](10-primops-and-runtime-abi.md)) made
  durable and incremental: change a file's content and only importers of that
  file are reconsidered (and most hit early cutoff).
- `readFile`/`readDir` results are leaves keyed on the content/listing hash, so a
  build that splices a file's contents into a derivation env reconsiders exactly
  when that file changes.

This is the boundary that makes the "Nix is pure" claim literally true for
caching purposes: once filesystem reads are reified as content-hashed inputs, the
entire evaluation is a pure function of `(source files, filesystem-read
contents)`, and the incremental machinery is exact.

Which nodes are pure (freely memoized and speculated) versus effectful
(at-most-once, no speculation, effects keyed as explicit inputs) is decided by a
per-node **effect tag**, and that tag is no longer a closed
`enum { Pure, Effectful }` baked into the engine. It is an **open, dialect-supplied
effect lattice** (`S-23`, [28](28-generalization-and-language-dialects.md) §5): the
engine reads only `is_speculable()` to gate speculation/re-execution and an opaque
`effect_key()` to fold into the cache key, while the Nix dialect supplies the
concrete members (`import`, `readFile`, IFD, `derivationStrict`). `ratchet-cache`
treats the effect key **opaquely** — it never interprets which Nix effect a node
carries, only whether the node is speculable and what its key contributes to
re-execution boundaries — so the engine stays language-agnostic.

### 6.4 Cache poisoning and the trust model

Because the durable cache crosses machines, its trust model matters. Three
defenses:

1. **Cryptographic addressing.** blake3 value-hashes are self-verifying; a fetched
   value's bytes are checked against the hash before use. A man-in-the-middle
   cannot substitute a value without breaking the hash.
2. **Advisory, never authoritative for `.drv`.** Per §5.2, no cached value can
   change a SHA-256 store path except by being the *correct* value; the
   `derivationStrict` boundary recomputes the Nix-observed hash from the value's
   bytes. A poisoned eval-cache value that survived blake3 verification (i.e. an
   actual collision) would still have to collide blake3 *and* produce a value
   whose canonicalization yields a malicious `.drv` — and would be caught by the
   differential harness in any case.
3. **Namespace isolation.** The eval cache lives in its own Attic namespace
   (`andyl-os` eval-cache), separate from the build-output cache, with the same
   signing/auth posture AOS already applies to build artifacts.

### 6.5 Storage engine: two engines for two data natures

The `nodes/`, `values/`, and `files/` layout of §6.1 is a logical schema; this
subsection records the on-disk engine that backs it. **Decision (closed):** the
durable cache uses *two* storage engines, chosen by the nature of the data each
holds, not one general-purpose database for everything.

**Immutable content-addressed blobs (`values/`, `files/`) — a custom
memory-mapped append-only packfile.** The serialized WHNF values and compiled IR
are content-addressed and never mutate. We store them in a single packfile in the
style of a git object store or an Attic chunk store:

- **Content-addressed.** The blake3 value-hash (or file-hash) *is* the lookup
  key; the index (below) maps it to a byte offset in the pack.
- **Zero-copy mmap reads.** The packfile is `mmap`'d; a lookup returns a pointer
  (a `&[u8]`) directly into the mapped page, with no copy and no deserialization
  step on the hot read path. Because Nix values are immutable, the borrow is
  sound for as long as the mapping lives.
- **Append-only writes.** New blobs are appended; existing bytes are never
  rewritten. GC is **repack** — copy live blobs to a fresh pack and swap it in —
  exactly the §6.2 layered collection, never an in-place delete.
- **Immutability removes the hard parts.** With no in-place update there is no
  page-rewrite torn-write window, no MVCC-over-mutable-data, no write-ahead log
  for the blob store. The classically difficult parts of a storage engine simply
  do not arise, because content-addressed data is write-once.

**Mutable metadata + the offset index (`nodes/`, blake3 → packfile-offset) —
`heed` (LMDB).** The verifying-trace node records and the hash→offset index *do*
change as nodes are recomputed, so they go in `heed`, the maintained Rust wrapper
over LMDB (the same one Meilisearch uses):

- **mmap'd B+tree with zero-copy MVCC reads.** LMDB memory-maps a single-file
  B+tree; reads return pointers into the map (zero-copy, via `heed`'s typed
  zerocopy layer), and its MVCC/copy-on-write design means **readers never block
  and never block writers** — many parallel forcing workers
  ([13](13-parallel-evaluation.md)) can read the index lock-free.
- **Single writer, batched — and that is fine.** LMDB serializes writers (one
  write transaction at a time). For us the write path is the *cold* path (a node
  is materialized once and read many times), and because every materialization is
  content-addressed it is **idempotent** — concurrent misses on the same key
  collapse to the same bytes, so batching writes behind a single writer costs
  nothing in correctness and little in throughput.
- **Crash-safe, tiny hermetic dependency.** LMDB is a small, self-contained C
  library that builds cleanly from source under the AOS hermetic-build rules; it
  needs no server process. Its `mapsize` (max map / DB size, set to a multiple of
  the OS page size) is sized generously up front for the package-set's metadata.

**Why this split, versus the alternatives:**

| Engine | Pros | Cons / verdict |
|--------|------|----------------|
| **Custom mmap packfile** (chosen for `values/`/`files/`) | Zero-copy reads (pointer into the page); append-only writes are trivial given immutability; GC-by-repack; no engine complexity for write-once data | We own the format (versioning is on us, §8.4) — acceptable for a write-once blob store |
| **heed / LMDB** (chosen for `nodes/` + index) | Zero-copy MVCC reads, lock-free for many readers; crash-safe; tiny hermetic C lib; battle-tested (Meilisearch) | Single writer (a non-issue on our cold, idempotent write path) |
| **SQLite** | Already a workspace dependency, and C++ Nix itself uses SQLite for both its store DB and its flake eval-cache, so the model is proven for *this exact problem* | **Not zero-copy** — blob reads copy out through the SQL/row layer, defeating the mmap pointer-return we want for `values/`; a full relational engine where we only need a hash→bytes map. Kept in mind as a fallback if the two-engine split proves not worth its complexity |
| **redb** (pure-Rust LMDB-alike) | No C dependency at all — strictly better for hermeticity than LMDB | Younger and less battle-tested than LMDB; noted as the **drop-in option** if the LMDB C dependency ever becomes a hermetic-build friction point |
| **RocksDB** | LSM write throughput | Heavy C++ build, large dependency surface, anti-hermetic under the AOS source-build rules — **rejected** |

**The enabling property behind all of this: the cache is advisory, not a source
of truth.** Per §5.2 and §8.3, a lost or corrupt cache entry can only ever cause
a *recompute*, never a wrong `.drv` — the differential harness
([15](15-differential-testing-and-benchmarking.md)) is truth. That lets us trade
durability for speed: LMDB runs with relaxed sync (`MDB_NOSYNC` / `MDB_MAPASYNC`),
giving crash-*safety* (the B+tree is never left structurally corrupt) without
crash-*durability* (the last few writes may be lost on power failure). Losing
those writes is harmless — the affected nodes are simply recomputed on the next
demand — so we keep the fsync off the hot path entirely.

### 6.6 Out-of-core evaluation: the mmap'd value store is the spill-to-disk Nix lacks

Vanilla C++ Nix has no swap-to-disk mechanism for the value heap: a sufficiently
large evaluation (a full `nixpkgs` instantiation, or the whole AOS closure) holds
every live value in RAM until GC reclaims it, and peak resident set is bounded
only by how much the GC can free, not by any cooperation with the OS. The
content-addressed value store (§6.1, §6.5) gives aos-nix the spill mechanism Nix
is missing — see [memory and GC](06-memory-management-and-gc.md) for the
in-process heap and collector this complements.

The mechanism is **eviction to the CA store with rematerialization on demand**:

- **Cold values evict from the heap.** A hash-consed value
  ([05](05-value-representation.md)) that has not been touched recently can be
  dropped from the in-memory value arena; future demands rematerialize it from
  the packfile by its value-hash (a zero-copy mmap read, §6.5).
- **The OS does the paging.** Because the value store is `mmap`'d, eviction and
  reload are *page-level* cooperation with the kernel: the OS pages cold value
  bytes out under memory pressure and pages them back in on access, a knob C++
  Nix's bespoke heap has no equivalent for. We get demand paging of the value
  closure for free from the mapping.
- **Eviction is write-back-free.** This is the property that makes spilling cheap.
  Because values are immutable and content-addressed, the blake3 hash *is* the
  address: if a value's bytes are already in the packfile (and any value that was
  materialized per §3.4 already is), "spilling" it is simply **dropping the
  in-RAM copy** — there is nothing to write back, no dirty page, no flush. A clean
  immutable value is reduced to a (hash → offset) reference that re-reads on
  demand.

The result is that peak RAM for a huge evaluation is bounded by the *working set*
of values demanded close together in time, not by the full set of live values —
the out-of-core property that lets aos-nix evaluate closures larger than memory
where vanilla Nix would OOM. The in-process GC ([06](06-memory-management-and-gc.md))
and this spill path are the two halves of the memory story: GC reclaims dead
values, eviction parks live-but-cold values on disk.

## 7. Worked example: a one-line version bump

To make the asymptotics concrete, trace what happens when a developer bumps
`pkgs/curl.nix` from `8.7.1` to `8.8.0` and runs `aos build curl` (and, say,
`aos build git`, which links against curl).

```text
   Run N (cold or warmed):       parse+eval whole closure feeding curl & git.
                                 Populate nodes/ values/ files/ in the CA store.

   Edit pkgs/curl.nix version + hash.

   Run N+1:
     files/ : re-parse ONLY pkgs/curl.nix (its content hash changed).
              Every other .nix file's IR is reloaded from files/.
     nodes/ : curl's derivation node is keyed on the changed `version`/`src`
              value-hashes → stale → reconsidered → new value-hash → recompute
              curl.drv (new SHA-256 store path, correctly).
     early  : git's derivation node depends on curl's *output path*, which
     cutoff   changed, so git is reconsidered and recomputes git.drv.
              The C toolchain, glibc, autoconf, etc. — every node not
              transitively keyed on curl's changed inputs — is FRESH:
              value-hashes unchanged → early cutoff at depth 0 → not recomputed.
     result : 2 derivations recomputed, ~1 file re-parsed, thousands of
              toolchain thunks served from cache. Cost ∝ change, not ∝ closure.
```

Contrast with today's `nix-instantiate`, which re-evaluates the entire closure
feeding `curl` and `git` from scratch on every invocation. The incremental cache
turns the dominant case — small edits to a large, stable package set — from
`O(closure)` into `O(touched derivations + their reverse-dependency frontier)`.

## 8. Failure modes, limits, and open questions

This is the highest-leverage item in the RFC, but it is not free of risk. We
record the limits honestly.

### 8.1 Where the cache does *not* help

- **Cold first run.** The very first evaluation on a fresh machine populates the
  cache and pays full evaluation cost (plus hashing overhead). The win is
  entirely in re-evaluation; measure-first ([01](01-motivation-and-goals.md),
  [15](15-differential-testing-and-benchmarking.md)) must confirm that the AOS
  workflow is re-evaluation-dominated, which we believe it is but have not yet
  quantified. **Open question:** what fraction of CI eval time is cold vs warm?
- **Pathological fan-out.** A change to a node near the root of the package set
  (e.g. `stdenv`, the C compiler wrapper) dirties a large reverse-dependency
  cone, and early cutoff helps only to the extent that downstream *values* are
  unchanged. A `stdenv` bump that changes every derivation's `builder` defeats
  cutoff by construction — but that is also a case where C++ Nix must do the full
  work, so we are no worse, and the cache still elides the unchanged
  *front-end/library* evaluation that does not depend on `stdenv`.
- **Wide environments hashed too eagerly.** If free-variable narrowing (§3.2) is
  imprecise, a thunk that closes over a large frame may rekey on irrelevant slot
  changes, recomputing spuriously. This is a *performance* bug, never a
  correctness bug (a spurious recompute yields the same value and then hits early
  cutoff at its consumers), but it erodes the win. **Decision (closed):** the
  baseline reuses the free-variable set the strictness/escape pass
  ([07](07-laziness-and-whole-program-analyses.md)) already computes — no extra
  analysis in the rank-1 cut. A dedicated dependency-minimization pass is a
  **measure-gated** follow-up, built only if the harness shows spurious-recompute
  rates that materially erode the cache win; because imprecision here is purely a
  performance bug (never correctness), shipping the cheap FV set first is safe.

### 8.2 Cache size and hashing overhead

The constructive value store can grow large (it stores canonical values, not
just hashes). Hash-consing bounds it by deduplication, and the three-level GC
(§6.2) bounds retention, but the value-hashing itself adds work on the *miss*
path that a non-incremental evaluator does not pay. **Open question (measure-
first):** at what node granularity (§3.3) does the value-hashing overhead on
misses stop being repaid by hits? This must be tuned against real AOS traces, not
assumed. The mantra cuts both ways — caching a node that is never re-demanded is
pure overhead.

### 8.3 Correctness anxiety and the safety net

The cache is sound *given* purity, immutability, and the explicit-input
treatment of filesystem reads (§6.3). The residual risk is an *implementation*
bug that under-tracks a dependency (a read not reified as a graph edge), which
would let a stale value survive a change it should have invalidated. Defenses, in
order of strength:

1. **The differential harness is the backstop.** Per the acceptance gate
   ([02](02-compatibility-constraints.md),
   [15](15-differential-testing-and-benchmarking.md)), every `.drv` aos-nix
   produces is diffed against `nix-instantiate`. A mis-cached value that altered a
   `.drv` is caught immediately. The cache cannot silently corrupt the build
   output without failing the gate.
2. **A `cache=off` mode.** `AOS_NIX_CACHE=0` disables persistence and the memo
   table entirely, falling back to pure tree-walk/JIT evaluation. Any time a
   cached run and an uncached run disagree, the cache has a tracking bug, and we
   have a minimal reproducer.
3. **Periodic cold re-validation.** CI runs a scheduled cold (cache-cleared)
   full-closure evaluation and diffs it against the warm result, catching latent
   under-tracking that the incremental path masks.
4. **The permanent `NixCli` fallback.** Until the harness is green on the full
   closure, `AOS_NIX_NATIVE` defaults off ([14](14-integration-with-aos.md)); the
   subprocess `nix-instantiate` path remains the production evaluator and the
   ultimate correctness reference.

### 8.4 Open questions, collected

- **Granularity policy (§3.3, §8.2):** the right set of "always/conditionally/
  never cache" rules is empirical and must be derived from AOS traces.
- **Free-variable precision (§8.1):** *closed* — baseline reuses the strictness
  pass's FV set; a dedicated minimization pass is a measure-gated follow-up only
  if spurious-recompute rates warrant it (§8.1).
- **Persistence format stability:** the on-disk `nodes/values/files` schema is a
  data contract; versioning and migration are unspecified here and need a
  schema-version field and a "discard on mismatch" policy.
- **Parallel-cache interaction:** concurrent forcing
  ([13](13-parallel-evaluation.md)) means multiple threads may miss on the same
  key simultaneously. The insert path must be a compare-and-swap (CAS)
  single-flight on the node table so duplicate work collapses; the design is
  sketched in
  [parallel evaluation](13-parallel-evaluation.md) but the single-flight
  protocol for the *persistent* store (two machines, not two threads) is an open
  question.
- **Eviction vs. correctness:** value-store GC must never collect an entry a live
  `nodes/` trace references; the reference-counting across the Attic boundary
  needs the same care Attic's own three-level GC takes.

## 9. Summary

The incremental evaluation cache models Nix evaluation as a demand-driven
incremental computation graph in the lineage of Salsa (rust-analyzer), Adapton,
Skip, and *Build Systems à la Carte*. It memoizes thunk and derivation results
keyed on `H(expression ⊕ environment)`, propagates change with **early cutoff**
(Salsa's red-green algorithm: stop when a recomputed value-hash is unchanged),
and persists results in a content-addressed value store shared across machines
through AOS's existing Attic infrastructure — extending Attic from build outputs
to eval outputs. The hashing policy is strict: xxh3 for hot in-process keys,
blake3 for the durable cryptographic CA store, and SHA-256 *only* where the Nix
on-disk format demands it, with a hard invariant that no internal hash may leak
into a Nix-observed store path. Nix's purity, value immutability, and batch
whole-program nature make this caching layer *exact* where the same techniques
are merely best-effort in general-purpose languages, and the must-be-byte-
identical `.drv` requirement ([02](02-compatibility-constraints.md)) places the
canonical value — the thing early cutoff hashes — already on the critical path.
This is the largest single performance lever in the RFC, it pays off even on the
tree-walk oracle independent of interpreter speed, and the differential harness
([15](15-differential-testing-and-benchmarking.md)) is its correctness backstop.

## Implementation checklist

Per-feature tracker for the incremental evaluation cache; master roll-up:
[implementation checklist (all phases)](22-implementation-checklist-all-phases.md).
Per the unlimited-budget mandate, every item here is in scope — including
research-grade ones — built in dependency order and gated by the differential
harness, never cut for scope.

### The demand graph and memoization (foundation)

- [x] Current in-memory demand-graph substrate: `cache::dcg` stores nodes keyed by opaque `DemandCacheKey`, maintains deterministic dependency/dependent edges, tracks clean/dirty freshness, and applies the local `EarlyCutoff` decision when a node is reconsidered, newly dirtying direct dependents only when the recomputed `ValueHash` changes or no prior hash exists. This is an in-memory substrate only; evaluator `force_memoized`, dynamic dependency tracing, persistence, impure-input leaf integration, and full `.drv` harness proof remain open ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§3.1](#31-what-a-node-is)) — P2 precursor, `S-14`/`C-20`; gate: `cache::dcg` tests.
- [x] Current demand-graph dirty-frontier scheduling substrate: `DemandGraph::dirty_nodes` exposes dirty nodes in deterministic node order, and `DemandGraph::ready_dirty_nodes` exposes only dirty nodes with no dirty transitive dependencies, so a future evaluator scheduler can recompute a frontier without bypassing early cutoff through dirty intermediates. This is a graph-side scheduling view only; automatic evaluator recomputation, dynamic dependency tracing, SCC-aware cycle handling, parallel scheduling, persistence, and cached/uncached harness proof remain open ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`C-20`; gate: `cache::dcg` tests.
- [x] Current dirty-frontier blocker diagnostic substrate: `DemandGraph::dirty_frontier` returns a `DirtyFrontier` snapshot with ready dirty nodes and `BlockedDirtyNode` entries whose blocker lists name dirty upstream nodes in deterministic node order; dependency cycles that keep a dirty node reachable from itself report that self edge as a blocker instead of making a stalled frontier look empty. This is a graph-side diagnostic only; SCC-specific errors, evaluator scheduling integration, dynamic dependency tracing, persistence, and cached/uncached harness proof remain open ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`C-20`; gate: `cache::dcg` tests.
- [x] Current graph-only ready-dirty recomputation loop substrate: `DemandGraph::recompute_ready_dirty_nodes` repeatedly snapshots the dirty frontier, calls a caller-supplied recompute callback for each ready dirty node's new `ValueHash` in deterministic node order, applies `reconsider_node` for early cutoff and dependent dirtying, and returns the ordered reconsiderations plus the final frontier. The loop cleans stable nodes, propagates changed hashes until the frontier is empty, and stops with a blocked frontier for dirty cycles or other dirty upstream blockers. This is graph-side scheduling only; evaluator node lifecycle integration, dynamic dependency capture, canonical value hashing, impure-input leaf integration, persistence, parallel/SCC-aware scheduling, and cached/uncached `.drv` harness proof remain open ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`C-20`; gate: `cache::dcg` tests.
- [x] Current EvalCache dirty-frontier adapter: `EvalCache::dirty_frontier` exposes the graph-side `DirtyFrontier` snapshot through caller-owned evaluator cache state, and `EvalCacheRuntime::dirty_frontier` reports `None` when cache observation is disabled or the same read-only snapshot when enabled. This is a read-only adapter only; evaluator-owned recomputation, node lifecycle integration, dynamic dependency tracing, persistence, and cached/uncached harness proof remain open ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`C-20`; gate: `cache::runtime` tests.
- [x] Current EvalCache ready-dirty recomputation adapter: `EvalCache::recompute_ready_dirty_nodes` and `EvalCacheRuntime::recompute_ready_dirty_nodes` expose the graph ready-dirty loop through caller-owned evaluator cache state, while disabled runtimes return `None` without invoking the recompute callback. This is an explicit cache-state adapter only; evaluator-owned node recomputation, dynamic dependency capture, canonical value hashing beyond caller-supplied `ValueHash` results, impure-input leaf integration, persistence, and cached/uncached `.drv` parity proof remain open ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`C-20`; gate: `cache::runtime` tests.
- [x] Current dynamic dependency replacement substrate: `DemandGraph::replace_dependencies` validates a caller-supplied node and replacement dependency set before atomically swapping the node's whole forward dependency set and reverse dependent edges, and the explicit impure-trace adapters use it only for nodes whose dependencies are represented by the latest explicit trace, replacing those edges on cacheable recomputes and clearing them on incomplete or uncacheable recomputes. This is explicit graph/runtime edge maintenance only; typed dependency groups, automatic evaluator-owned dynamic dependency capture, separate inner/outer observers, evaluator-integrated ready-dirty recomputation, persistence, and cached/uncached `.drv` parity proof remain open ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`C-20`; gate: `cache::dcg` and `cache::runtime` tests.
- [ ] Full demand-driven incremental graph remains: create nodes on actual force/eval demand, capture dependencies dynamically Adapton-style, separate inner/outer observers, connect the ready-dirty recomputation loop to evaluator demand, integrate impure-input leaves and persistence, and prove cached/uncached `.drv` parity ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§3.1](#31-what-a-node-is)) — P2, `S-14`/`C-20`; gate: differential `.drv` harness.
- [x] Current `force_memoized` claimed-thunk boundary: tree-walk `force_value` delegates newly claimed thunk forcing to `force_memoized_claimed_thunk`, which builds a force-cache subject only after demand reaches the thunk, routes policy-admitted subjects through the shared in-memory/durable force-cache path before evaluating the thunk body, publishes cache hits into the thunk cell, and observes successful WHNF results after admitted uncached body evaluation. Allocating a source-backed lazy attr thunk leaves the shared `EvalCache` empty until the thunk is actually forced and admitted. This is the current claimed-thunk inline payload boundary only; full demand-node lifecycle, dynamic dependency capture, canonical free-variable production, general memo lookup, persistent graph integration, and cached/uncached `.drv` harness proof remain open ([§3.1](#31-what-a-node-is)) — P2 precursor, `S-14`; gate: `source_backed_force_cache_creates_expression_node_only_on_force` plus source-backed force-cache hit/update tests.
- [x] Current standalone cache-key combiner substrate: `cache::key` defines `CacheExprIdentity` plus opaque `DemandCacheKey`, and computes one order-sensitive hot xxh3 probe plus one BLAKE3 confirmation digest over domain/version prefixes, expression identity bytes, and caller-supplied free-variable value hashes encoded as length-prefixed chunks. Tests cover stability, source/node identity changes, order sensitivity, multiplicity, length-prefix ambiguity, and demand-graph separation when hot hashes collide. This implements the C-1 ordered/length-prefixed combiner and in-process collision-confirmation rule only; canonical free-variable set/order production, real durable value-hash production, and differential false-hit harness coverage remain open ([§3.2](#32-constructing-the-dependency-key)) — P2 precursor, `C-1`; gate: `cache::key` and `cache::dcg` tests.
- [x] Current expression-node allocation/keying substrate: `DemandGraph::get_or_insert_expression_node` and `EvalCache::get_or_insert_expression_node` centralize graph insertion for a caller-supplied `CacheExprIdentity`, ordered free-variable value hashes, and optional node value hash; existing nodes keep their first value hash. This is explicit allocation/keying only; canonical free-variable discovery/order from strictness/escape analysis, real durable value-hash production, `force_memoized`, automatic evaluator expression-node lifecycle, persistence, currentTime taint propagation, and cached/uncached harness proof remain open ([§3.2](#32-constructing-the-dependency-key)) — P2 precursor, `C-1`/`C-2`/`S-14`; gate: `cache::dcg` and `cache::runtime` tests.
- [x] Current closed source-backed force-demand observation substrate: `EvalCache::observe_inline_expression_payload` and `EvalCacheRuntime::observe_inline_expression_payload` insert/reconsider expression nodes from caller-supplied identities, and tree-walk `force_value` now observes successful closed, source-backed `EvalThunkKind::Node` forces whose entire body subtree is both speculable and in a conservative self-contained IR-kind whitelist, and whose WHNF result is either an inline scalar, a Nix string payload with or without context, a Nix path payload with or without context, a replayable Nix list whose existing spine elements are non-thunk replayable payloads or suspended closed literal thunks with replayable static payloads, or a replayable Nix attrset that preserves source-order metadata and root-or-own-module binding source positions when present and whose existing bindings are non-thunk replayable payloads or suspended closed literal thunks with replayable static payloads. Position-bearing observations are admitted only when every retained binding position belongs to the forced expression's own module, and admitted payloads carry that module's source-identity hash as replay provenance. The precursor expression identity uses a domain-separated hash of source name, source bytes, module path-literal base, evaluator-option salt, and the lowered node source span, then pairs that expression-positioned artifact hash with the IR node id, so identical file bytes under different relative-path bases or node spans do not share one observed node. `NixNative` passes its caller-owned cache runtime into tree-walk evaluation, so repeated closed source-backed evaluations reuse the same demand node and apply the existing value-hash early-cutoff decision. This is observation/reconsideration only: source-less raw eval outside the lowered-IR-backed node-thunk subset, captured dynamic/scoped-global thunks, ambient/synthetic builtin values outside the admitted constant subset, search-path/global/builtin/primop/application/dialect nodes pending explicit option and impure-input keys, synthetic apply/select thunks, canonical free-variable hashes, general memo lookup, remaining suspended non-literal/non-replayable captured thunk-cell free variables, arbitrary lazy-element list and lazy-binding attrset payloads, multi-module or non-own-module binding-position persistence and module-source remapping, and other composite value hashing, persistence, and cached/uncached harness proof remain open ([§3.1](#31-what-a-node-is), [§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`S-15`; gate: `cache::runtime`, source-backed force-path tests, source-backed position-bearing attrset literal hit canary, imported own-module positioned attrset replay/remap canary, stale unprovenanced positioned payload miss/clear canary, and `unsafeGetAttrPos` positioned-attrset force-cache hit canary.
- [x] Current pure closed force-cache hit substrate: `EvalCache` keeps per-node scalar/string/path/replayable-list/replayable-attrset payload records beside demand-graph value hashes, `EvalCacheRuntime::lookup_inline_expression_payload` returns a memoized payload only for clean nodes whose payload hash still matches the graph, and tree-walk `force_value` consults this shared cache before evaluating a policy-admitted newly claimed closed source-backed thunk whose entire body subtree is both speculable and in the conservative self-contained IR-kind whitelist. Hits publish immediate scalars directly and rehydrate context-free string bytes, context-bearing string bytes plus context, path bytes with or without context, replayable Nix lists, or replayable Nix attrsets with source-order metadata and root-or-own-module binding source positions into the evaluator-local heap before finishing the thunk cell, remapping retained own-module attr positions to the current body module on replay only when the payload carries matching module-source provenance; closed literal lazy list elements and attrset bindings rehydrate as strict static replayable payload values, so thunk identity and laziness from the cold run are not preserved across the cached payload. Disabled runtimes, unknown nodes, dirty nodes, missing payloads, stale payloads, unprovenanced positioned payloads, and incompatible, multi-module, or non-own positioned payloads are misses. This is a scalar/string/path/replayable-list/replayable-attrset pure/local hit path only: source-less raw eval outside the lowered-IR-backed node-thunk subset, captured dynamic/scoped-global thunks, ambient/synthetic builtin values outside the admitted constant subset, search-path/global/builtin/primop/application/dialect nodes pending explicit option and impure-input keys, synthetic apply/select thunks, canonical free-variable hashes, remaining suspended non-literal/non-replayable captured thunk-cell free variables, arbitrary non-literal lazy-element lists and lazy-binding attrsets, broader multi-module/non-own binding-position module-source remapping, and other composite payloads, transitive dirty scheduling, persistence, `derivationStrict` SHA-256 short-circuiting, and cached/uncached harness proof remain open ([§3.1](#31-what-a-node-is), [§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`S-15`; gate: `cache::runtime` lookup tests plus source-backed force-cache hit/skip tests, positioned attrset hit/provenance canaries, imported own-module positioned attrset replay/remap canary, stale unprovenanced positioned payload miss/clear canary, and closed-literal lazy composite hit canaries.
- [x] Current force-time inline impure-edge substrate: tree-walk force now slices the impure-input trace observed while a closed source-backed thunk body evaluates, and `EvalCache::observe_inline_expression_payload_with_impure_inputs` stores a scalar/string/path/replayable-list/replayable-attrset payload only when that slice is complete and cacheable, wiring the expression node to the observed input leaves at the same time. The observation whitelist admits the existing pure subset plus cacheable input primops (`import`, `getEnv`, `pathExists`, `readDir`, `readFile`, `readFileType`) with safe children such as path literals, so stable `pathExists` and canonical plain-file filesystem-import thunks reached without symlinked path components now create expression/input edges while `currentTime`, symlinked import routes, search-path literals, and application-like forms still create no payload. Trace-backed payload records are tagged as requiring revalidation and are misses through the existing immediate-value public lookup API; incomplete or uncacheable trace observations invalidate any existing payload for the same key. Lookup remains restricted to the pure/speculable subset until the cache retains typed input identities and revalidates them before a hit. This is edge wiring and payload storage only; source-less raw eval outside the lowered-IR-backed node-thunk subset, captured dynamic/scoped-global thunks, ambient builtin values outside the admitted constant subset, search-path/global/builtin/application/dialect nodes beyond the traceable primop subset, canonical free-variable hashes, typed input-identity retention, force-time input revalidation, remaining suspended non-literal/non-replayable captured thunk-cell free variables, arbitrary lazy-element lists, lazy-binding attrsets, and other composite payloads, transitive dirty scheduling, persistence, `derivationStrict` SHA-256 short-circuiting, and cached/uncached harness proof remain open ([§3.1](#31-what-a-node-is), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` combined inline/trace tests plus source-backed `pathExists`, readFile string payload, and import force-edge tests.
- [x] Current force-time inline impure revalidation substrate: trace-backed
  inline payload records now retain the cacheable input fingerprints from their
  force-time trace, `EvalCache::lookup_inline_expression_payload_with_impure_inputs`
  revalidates those typed identities through an `ImpureInputRevalidator` before
  returning a scalar, string, path, replayable-list, or replayable-attrset payload for tree-walk
  rehydration, and changed, unavailable, uncacheable, or identity-mismatched
  fresh inputs invalidate the payload and miss. Tree-walk
  supplies a conservative options-backed revalidator for `import`, `getEnv`,
  `pathExists`, `readFile`, `readDir`, and `readFileType`, so stable
  source-backed `getEnv`, `pathExists`, `readFile`-, `readDir`-, and
  `readFileType`-backed thunks, plus canonical plain-file filesystem-import-backed
  thunks reached without symlinked path components, can hit after replaying
  their input probes, including generated `readDir` attrsets canonicalized to a
  deterministic source order and import-cache hits that replay the originally
  observed nested input trace. Changed environment values, directory listings,
  file types, read bytes, import source bytes, deleted paths, unavailable paths,
  or symlinked import routes force recomputation through the normal evaluator
  path. Revalidated cache hits append
  their fresh fingerprints back into the
  active evaluator trace so enclosing forced thunks cannot be observed as pure
  by losing nested dependencies. `readFile` revalidation is guarded by the
  option-salted expression identity for store-dir-dependent string context, and
  the older public pure lookup remains immediate-value-only. This is in-memory
  scalar/string/path/replayable-list/replayable-attrset effectful reuse only: source-less raw eval
  outside the lowered-IR-backed node-thunk subset, captured
  dynamic/scoped-global thunks, ambient builtin values outside the admitted
  constant subset,
  search-path/global/builtin/application/dialect nodes beyond the traceable
  primop subset, canonical free-variable hashes, persistent input-identity
  retention, remaining suspended non-literal/non-replayable captured thunk-cell free variables, arbitrary lazy-element lists,
  lazy-binding attrsets, and other composite payloads, transitive dirty scheduling, persistent
  graph/value cache integration, `derivationStrict` SHA-256 short-circuiting,
  and cached/uncached harness proof remain open ([§3.1](#31-what-a-node-is),
  [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor,
  `R-10`/`S-14`; gate: cache revalidation tests plus source-backed
  stable/changed `getEnv`, `pathExists`, `readFile`, `readDir`, `readFileType`,
  and import-backed hit/miss tests.
- [x] Current force-cache evaluator option identity salt: force expression identities now hash the module's `store_dir`, `home_dir`, configured `current_system`, configured `current_time`, and `eval_mode` alongside source name or lowered-IR fingerprint, path-literal base, lowered node source span, and IR node id. This prevents the current admitted force-cache path from sharing inline payloads across evaluator configurations that can change path/context, ambient builtin constants, impurity-policy behavior, or expression source position. It is deliberately conservative and may miss across option/span changes that do not affect a specific expression; full cache-key integration, canonical free-variable hashes, fine-grained option dependency tracking, persistent keys, and cached/uncached harness proof remain open ([§3.2](#32-constructing-the-dependency-key), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `C-1`/`C-2`/`R-10`; gate: force-cache identity tests for `store_dir`, `home_dir`, `current_system`, and eval mode.
- [x] Current ambient and synthetic builtin constant force-cache substrate: tree-walk admits only symbol-checked `BuiltinAttr` constants for force-cache lookup/observation: immediate true/false/null, `currentSystem`, `storeDir`, `nixVersion`, and `langVersion`; `currentTime` is observation-only and remains uncacheable through its existing impure trace. Matching configured `currentSystem` and `storeDir` thunks can now hit as context-free string payloads, while changed `currentSystem` or `storeDir` options miss through the expanded option identity salt. Reified `builtins` attrset entries for those constants are now delayed synthetic builtin-attr thunks, so constructing the attrset does not force `currentTime`, and runtime selections such as `let b = builtins; in b.currentSystem` use synthetic identities keyed by module identity, force-site `IrId` and lowered source span, builtin symbol, and execution tag. The observation-only `currentTime` canaries assert that ordinary forcing leaves persistent force metadata and trace sidecars empty, while seeded stale durable node-thunk and synthetic builtin-attr `currentTime` payloads are cleared and tombstoned without recording demand. This deliberately skips the recursive `builtins` attrset, `nixPath`, derivation, first-class primops, synthetic apply/select thunks, broader persistence, and cached/uncached harness proof ([§3.1](#31-what-a-node-is), [§3.2](#32-constructing-the-dependency-key)) — P2 precursor, `C-1`/`C-2`/`R-10`; gate: source-backed and source-less ambient and synthetic `currentSystem` hit/miss, synthetic `storeDir` hit/miss/symbol-separation, synthetic force-site span separation, synthetic immediate constants, reified `currentTime` laziness, stale synthetic `currentTime` runtime payload invalidation, observation-only `currentTime` sidecar-empty and stale-durable tombstone canaries, and source-backed/source-less `currentTime` uncacheable-trace force-cache tests.
- [x] Current source-less lowered-IR force-cache identity substrate: `cache::parse::lowered_ir_fingerprint` hashes the stable `ir.bin` and `symbols.bin` artifact encodings under the parse-cache schema version, and tree-walk uses that digest when a module has no source provenance before applying the same path-literal-base, `store_dir`, `home_dir`, configured `current_system`, configured `current_time`, and `eval_mode` salts plus lowered node and synthetic force-site source spans. This lets caller-owned in-memory cache runtimes share conservative source-less lowered-IR node-thunk and admitted synthetic builtin-attr payloads without requiring source bytes, while still separating equal-shaped IR whose symbol tables, path bases, evaluator options, node spans, or synthetic force-site spans differ. It is a source-independent identity substrate only; broader source-less raw eval surfaces, synthetic apply/select thunks, remaining composite payloads, persistence, fine-grained option dependency tracking, and cached/uncached harness proof remain open ([§3.2](#32-constructing-the-dependency-key)) — P2 precursor, `C-1`/`C-2`/`S-14`; gate: lowered-IR fingerprint tests plus source-less hit/miss, source/source-less domain separation, path/store/home/current-system/eval-mode salt, readFile revalidation, captured-free-variable tests, and source-less synthetic builtin constant hit tests.
- [x] Current inline/string/path/replayable-composite captured-free-variable force-cache key substrate: tree-walk now builds one force-cache subject for each source-backed or lowered-IR-backed node thunk, including ordered durable hashes for referenced captured lexical slots when every captured slot value is either an inline scalar supported by `ValueHash::from_inline_value`, a Nix string with or without context, a Nix path with or without context, a replayable Nix list, a replayable Nix attrset whose source-order metadata and binding positions are preserved when present, a fulfilled thunk cell whose cached value is one of those replayable values, or a suspended closed literal thunk whose static payload is one of those replayable values. Strings and paths are hashed in one durable force-capture domain with typed string/path tags; contextual values append canonical context element tags and length-prefixed path/output bytes. Replayable list/attrset captures hash the current replayable payload value hash under the same force-capture domain with a composite tag; positioned composites additionally salt the captured hash with the cache identity of every module referenced by retained binding positions, so equal raw module ids and spans from different root/import sources cannot share one demand key. Lookup and observation feed those hashes into the existing ordered/length-prefixed demand-key combiner, so repeated captured inline/string/path/replayable-composite thunks hit only when their free-variable value hashes match and miss when those captured values differ or their referenced position-source identities differ. This deliberately skips dynamic `with` scopes, scoped-import globals, arbitrary non-literal lazy-element lists, arbitrary non-literal lazy-binding attrsets, position-bearing attrsets whose retained module ids cannot be resolved to loaded module identities, lambdas, primops, suspended non-literal/non-replayable thunk-cell captures (including computed values not already forced in the captured slot), captured bodies with nested lexical-frame introducers, apply/select thunks, full strictness/escape free-variable analysis, remaining heap/composite value hashes, persistence, and cached/uncached harness proof ([§3.2](#32-constructing-the-dependency-key)) — P2 precursor, `C-1`/`C-2`; gate: captured inline/string/path/list and empty-attrset force-cache hit/miss tests, lowered lambda-argument coverage, cross-type string/path hash separation, materialized context-bearing string/path capture hash tests, preforced computed string thunk-cell capture tests, fulfilled replayable-attrset thunk-cell hash tests, direct suspended thunk-cell skip tests, caller-level suspended computed capture subject-skip canary, dynamic `with`/scoped-import global subject-skip canaries, lambda/recursive-attrset nested lexical-frame subject-skip canaries, captured lambda/primop value subject-skip canaries, synthetic apply/apply2/select thunk subject-skip canaries, captured root/imported positioned attrset source-salted admission and hit/miss canaries, source-order attrset admission canaries, captured closed-literal lazy-element list and lazy-binding attrset admission canaries, captured computed lazy-element list and lazy-binding attrset subject-skip canaries, and representative captured unsupported free-variable skip tests.
- [x] Current node-span force-cache identity precursor: source-backed and source-less node-thunk expression identities now fold the lowered node's source span into the durable expression-identity hash before pairing that hash with the existing `IrId` discriminator, and synthetic builtin-attr identities fold the lowered force-site span into their force-site `IrId`/symbol/execution identity. This moves the current identity shape toward the RFC `source content hash + IR node position` key while preserving the existing source-byte/lowered-IR fingerprint, path-literal-base, evaluator-option salt, synthetic builtin symbol/execution behavior, and ordered free-variable hash behavior. Full cache-key integration still requires canonical strictness/escape free-variable sets, real durable value hashes for all admitted values, persistent key compatibility decisions, and the cached/uncached false-hit harness ([§3.2](#32-constructing-the-dependency-key)) — P2 precursor, `C-1`/`C-2`; gate: force-cache identity and shared-runtime no-hit regression for same source bytes and same `IrId` under changed node or synthetic force-site spans.
- [ ] Full cache-key integration remains: feed source content + IR node position from the evaluator into demand-graph expression nodes, reuse the strictness/escape free-variable set for canonical slot ordering, feed real durable value hashes, and run the differential false-hit gate ([§3.2](#32-constructing-the-dependency-key)) — P2, `C-1`/`C-2`; gate: harness (false-hit = correctness bug).
- [ ] Expression identity from source content hash + IR node position; free-variable narrowing reusing the strictness/escape FV set ([§3.2](#32-constructing-the-dependency-key)) — P2, `C-2`; gate: harness.
- [ ] Memoization granularity policy (always / conditionally / never cache) ([§3.3](#33-granularity-what-we-memoize-and-what-we-do-not)) — P2, `M-11`; gate: AOS hit/overhead traces (start coarse).
- [x] Current memoization-granularity policy substrate: `cache::policy` defines `MemoizationSubject` defaults for the §3.3 always/conditional/never classes and `MemoizationClass::decide` admits conditional work only when both used-many and cheap-value-hash signals are present. `MemoizationDemand` records same-run demand counts with saturating increments, marks a computation used-many on the second observed demand, and feeds that signal into the existing admission decision when the caller supplies value-hash cost information. This is policy vocabulary only; broader evaluator subject selection, cardinality-analysis signal bridges, measured value-hash cost sampling, persistence/materialization policy refinement, and measured AOS tuning remain open ([§3.3](#33-granularity-what-we-memoize-and-what-we-do-not), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `M-11`; gate: `cache::policy` tests.
- [x] Current force-cache memoization demand signal bridge: enabled `EvalCacheRuntime` records same-run `MemoizationDemand` by the same expression identity plus ordered free-variable hashes used for force-cache payload keys, returns the current `MemoizationSubject` default admission decision, and exposes read-only demand telemetry without allocating demand-graph expression nodes. Tree-walk claimed-thunk forcing now reports `MemoizationSubject::Thunk` demand with the current cheap-value-hash signal before force-cache admission, while disabled runtimes remain no-ops. This is the same-run signal bridge only; cardinality-analysis signals, measured value-hash cost sampling, broader evaluator subject selection, and AOS tuning remain open ([§3.3](#33-granularity-what-we-memoize-and-what-we-do-not), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `M-11`; gate: `cache::runtime` memoization-demand tests plus source-backed force-cache demand bridge test.
- [x] Current force-cache memoization policy stats precursor: `EvalStats` and the `aos_nix::eval::stats` tracing event now report `force_cache_memoization_admits`, `force_cache_memoization_bypasses`, and derived `force_cache_memoization_demands` from the runtime demand/admission bridge. These counters expose the policy decision stream; the counters themselves do not choose subjects, sample costs, or tune thresholds. Cardinality analysis, measured value-hash cost sampling, broader evaluator subject selection, and AOS tuning remain open ([§3.3](#33-granularity-what-we-memoize-and-what-we-do-not), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `M-11`; gate: stats trace tests plus source-backed demand bridge stats test.
- [x] Current force-cache memoization admission gate: tree-walk consumes the force-cache `MemoizationDecision` before lookup/observation. `Bypass` forces the thunk normally and records persistent current demand, but skips in-memory and durable lookup, impure-trace slicing for force payloads, payload observation, value materialization, and force-cache hit/miss accounting. `Admit` preserves the existing lookup, revalidation, observation, materialization, and hit/miss paths. Tree-walk treats captured-free-variable node thunks, synthetic builtin-attr constants, and closed replayable composite literal node thunks as selected subjects that admit on first demand; ordinary node thunks remain conditional. Conditional thunk subjects admit on the second cheap same-run demand or on the first demand of a later run when persistent node metadata shows prior-run demand; missing subjects, disabled runtimes, lock errors, and demand-recording errors fail open to the old direct-evaluation path. This is a coarse thunk admission gate only; cardinality analysis, measured value-hash cost sampling, non-thunk evaluator subject selection, full `force_memoized` demand-node lifecycle, and AOS tuning remain open ([§3.3](#33-granularity-what-we-memoize-and-what-we-do-not), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `M-11`/`S-14`; gate: first-demand bypass/admit/hit force-cache tests plus persistent force-cache surface canaries.
- [x] Current force-cache hit/overhead stats precursor: `EvalStats` now reports force-cache-specific hits, misses, and probes separately from aggregate evaluator cache hits/misses, and the stats tracing event emits `force_cache_hits`, `force_cache_misses`, and `force_cache_probes`. The aggregate `cache_hits`/`cache_misses` fields retain their existing broad meaning by combining force-cache counts with import parse-cache and find-file cache counts. This is coarse telemetry only; it does not select memoization subjects, sample value-hash costs, attribute wall-clock overhead to individual nodes, or tune policy thresholds from AOS workloads ([§3.3](#33-granularity-what-we-memoize-and-what-we-do-not), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `M-11`; gate: stats trace tests plus source-backed force-cache hit/miss tests.
- [x] Current P1 sharing/memoization substrate: allocated thunks memoize successful WHNF results and reset to suspended on failed force; ordinary filesystem imports memoize successful evaluations by canonical import identity; heap strings and path values are consed by evaluator-local xxh3 structural hash plus equality confirmation; and current IR lowering has local shared-thunk cases. This is the call-by-need/string-path-consing substrate only: it does not implement the §3.5 three-layer incremental-cache dedup design, generic value hash-consing, or `H(expr ⊕ env)` runtime cache nodes, and unforced thunk bodies are not fed into value cons tables. ([§3.5](#35-the-deduplication-story-three-layers-and-why-thunks-are-not-all-hashed)) — P1 precursor, `C-15`/`S-7`; gate: thunk memoization, import cache, heap consing, and IR sharing tests.
- [ ] Full three-layer dedup remains: compile-time thunk sharing as an explicit optimization policy, runtime coarse memoization through demand-graph `force_memoized` nodes keyed by `H(expr ⊕ env)`, generic post-force value hash-consing for composite immutable values, and invariant/proof coverage that unforced thunks are never hashed. ([§3.5](#35-the-deduplication-story-three-layers-and-why-thunks-are-not-all-hashed)) — P2/P4, `C-15`/`S-7`.
- [x] Current open effect lattice substrate: `ratchet-core` represents effects as `EffectClass` stamps carrying only `is_speculable()` plus a stable opaque `effect_key()`, exposes the matching `Effect` trait, serializes the key in lowered-IR parse artifacts, and conservatively decodes nonzero unknown keys as non-speculable until current Nix parse-cache validation rechecks them against `aos-nix-dialect` classifiers. `ratchet-dialect::Dialect` is the registration-time interface for effect classification, and `aos-nix-dialect` supplies the concrete Nix effect vocabulary for lowered `import`, `readFile`, `derivationStrict`, file IO, environment reads, fetches, tracing, generic effectful fallbacks, plus IFD realization boundaries. This is the Phase-1b effect-lattice extraction only; automatic demand-graph effect-key folding for full memo nodes, complete impure-input leaf integration, currentTime taint propagation through memoized dependents, and cached/uncached harness proof remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — Phase 1b, `S-23` ([28](28-generalization-and-language-dialects.md) §10); gate: `ratchet-core` IR lowering/effect tests, `aos-nix-dialect` effect-member tests, and parse-cache effect validation tests.

### Early cutoff

- [x] Current standalone early-cutoff decision primitive: `cache::cutoff` defines a typed `ValueHash` wrapper for future `blake3(canonical(value))` hashes and `EarlyCutoff::decide(previous, recomputed)`, returning `CutOff` only when a prior value hash exists and equals the recomputed value hash, otherwise `Propagate`. This is the comparison primitive only; full Salsa/DCG propagation, full canonical value-hash production, node invalidation, and harness proof remain open ([§4.1](#41-the-mechanism)) — P2 precursor, `S-14`; gate: `cache::cutoff` tests.
- [x] Current inline scalar/string/path/replayable-list/replayable-attrset value-hash substrate: `ValueHash::from_inline_value` hashes validated inline WHNF `int`/`bool`/`null`/`float` payloads in the durable BLAKE3 domain `aos-nix-inline-value-hash-v1`; floats are hashed by raw IEEE bits, so this may over-propagate relative to future Nix numeric canonicalization but cannot cut off distinct bit patterns. `ValueHash` also hashes context-free string bytes, context-bearing string bytes plus canonical context elements, path bytes with or without canonical context elements, empty lists, replayable list payloads whose element payloads are length-framed, replayable attrset payloads whose binding names and value payloads are length-framed in separate durable BLAKE3 domains, and position-bearing attrset payload records whose binding position-presence tags, module ids, and source spans participate in the hash; source-provenanced positioned result payloads additionally include the retained module source-identity hash in the persistent value preimage, while attrset hashing uses raw-byte-sorted binding order for canonical attrsets and distinct source-order tags when construction order is observable. Arbitrary non-literal lazy-element list and lazy-binding attrset cacheability, multi-module/non-own-module position-bearing attrset replay, functions/thunks cacheability policy, generic hash-cons value fields, `force_memoized` integration, and harness proof remain open ([§4.1](#41-the-mechanism), [§5](#5-hashing-policy)) — P2 precursor, `S-14`/`S-15`; gate: `cache::cutoff` and `cache::runtime` tests, including positioned attrset payload lookup/hash/root-position persistence coverage, own-module imported positioned attrset replay/remap coverage, stale unprovenanced positioned payload miss/clear coverage, and source-salted positioned captured attrset hash coverage.
- [x] Current inline-value early-cutoff adapter: `DemandGraph::reconsider_inline_value_node` and `EvalCache::reconsider_inline_value_node` hash a recomputed inline scalar before applying ordinary node reconsideration; unsupported heap values fail before mutating node state. This is an inline adapter only; heap/composite canonical hashing, functions/thunks policy, real evaluator value-hash production, `force_memoized`, evaluator node lifecycle, automatic `NixNative` use, persistence, and harness proof remain open ([§4.1](#41-the-mechanism), [§5](#5-hashing-policy)) — P2 precursor, `S-14`/`S-15`; gate: `cache::dcg` and `cache::runtime` tests.
- [x] Current derivation ATerm value-hash precursor: `ValueHash::from_derivation_aterm_bytes` hashes recorded `.drv` ATerm bytes in a separate durable BLAKE3 value-hash domain and can drive `EarlyCutoff` equality for repeated derivationStrict surfaces while staying out of Nix-observed SHA-256 path and `.drv` hashing. This is a comparison-key precursor only; evaluator-owned derivationStrict demand nodes, dependency capture, SHA-256 short-circuiting, persistence, and cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§5](#5-hashing-policy)) — P2 precursor, `S-14`/`S-15`; gate: `cache::cutoff` plus tree-walk derivation ATerm tests.
- [x] Current derivation ATerm cache observation adapter: `DemandGraph::reconsider_derivation_aterm_node`, `EvalCache::observe_derivation_aterm_expression`, and `EvalCacheRuntime::observe_derivation_aterm_expression` expose caller-owned early-cutoff observation over recorded `.drv` ATerm bytes, with disabled runtimes returning `None` without mutating cache state. This is an explicit cache API only; evaluator-owned derivationStrict demand-node lifecycle, expression identity/free-variable production, dependency capture, SHA-256 short-circuiting, persistence, and cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary)) — P2 precursor, `S-14`/`S-15`; gate: `cache::dcg` and `cache::runtime` tests.
- [x] Current derivation ATerm path lookup substrate: crate-private `EvalCache::observe_derivation_aterm_expression_path`, `EvalCacheRuntime::observe_derivation_aterm_expression_path`, and `lookup_derivation_aterm_path` store caller-supplied `.drv` path bytes beside a derivation ATerm value hash and bind the graph node to the full ATerm/path side-payload hash. Lookups return path bytes only for clean nodes whose side record still matches the caller's ATerm bytes and whose current graph hash still matches the recorded ATerm/path payload. Dirty, changed, missing-key, missing-record, and disabled-runtime cases are misses. This cache-side in-memory storage/lookup substrate is now consumed by the later tree-walk cached `.drv` path reuse precursor for eligible derivations; runtime-level generic side-record persistence, dependency capture beyond hashable lexical captures, full SHA-256 store-path short-circuiting, and full cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary)) — P2 precursor, `S-14`/`S-15`; gate: `cache::runtime` tests.
- [x] Current derivationStrict ATerm evaluator observation substrate: tree-walk `derivationStrict` now observes the recorded `.drv` ATerm/path payload into the enabled `EvalCacheRuntime` after normal output path and `.drv` path computation, using a derivation-specific expression identity salted by module identity, source span, and hashable captured lexical free variables. Disabled runtimes, `with`/scoped-global environments, and unsupported captured values skip observation; repeated unchanged derivation ATerm/path payloads increment early-cutoff stats without counting cache hits or misses. This explicit observation path feeds the in-memory and persistent final-path precursors only: evaluator-owned recomputation scheduling, dynamic dependency capture beyond hashable lexical captures, full SHA-256 short-circuiting, and full cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary)) — P2 precursor, `S-14`/`S-15`; gate: tree-walk derivation ATerm cache-observation tests.
- [x] Current derivationStrict ATerm path-record writeback substrate: tree-walk `derivationStrict` now writes the already-computed absolute `.drv` path bytes into the derivation ATerm cache side record through `EvalCacheRuntime::observe_derivation_aterm_expression_path`, after normal Nix-observed path computation has completed, when eval-cache observation is enabled and derivation ATerm subject capture, runtime locking, and serialization succeed. The later cached `.drv` path reuse precursor now consults this side record for eligible static, floating-CA, and impure derivations, but output path computation, derivation modulo hashing, and deferred-placeholder `.drv` paths still use normal construction. Dependency capture beyond hashable lexical captures, full SHA-256 store-path short-circuiting, and full cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary)) — P2 precursor, `S-14`/`S-15`; gate: tree-walk derivation ATerm path-record test.
- [x] Current derivationStrict cached `.drv` path reuse precursor: tree-walk `derivationStrict` now recomputes final ATerm bytes for static, floating-CA, and impure derivations, probes the clean derivation ATerm path side record, validates that cached absolute path against the current configured store directory and expected `${name}.drv` basename, and reuses it instead of rebuilding the final `.drv` text path when the record matches. The reuse increments `derivation_aterm_path_reuses`, drives `derivation_text_path_calculations` to zero for matching clean root reuse tests, and leaves aggregate `cache_hits`/`cache_misses` and force-cache hit/miss accounting unchanged; misses, stale records, disabled runtimes, unsupported captured values, invalid cached paths, configured-store mismatches, and wrong derivation names fall back to normal path construction. Initial derivation modulo hashing, static-output misses, deferred-placeholder derivations, dependency capture beyond hashable lexical captures, full derivationStrict-node SHA-256/store-path early cutoff, and full cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary)) — P2 precursor, `S-14`/`S-15`; gate: tree-walk derivation ATerm path-reuse/text-path-calculation tests.
- [x] Current persistent derivationStrict `.drv` path side-record precursor: tree-walk `derivationStrict` now materializes exact final ATerm/path side payloads into the persistent `values/` pack keyed from the same derivation expression identity and hashable lexical free-variable value hashes as the in-memory side record. Fresh runtimes can load the payload, verify that the blob hash equals the recorded side-payload value hash, require the persisted ATerm bytes to match the freshly recomputed ATerm, and reuse the final `.drv` path through the same store-dir/name validation as in-memory hits before seeding the runtime side record. This skips only the final `.drv` text-path calculation for exact ATerm matches; final ATerm serialization, initial derivation modulo hashing, deferred-placeholder derivations, dynamic dependency capture beyond hashable lexical captures, full derivationStrict-node SHA-256/store-path early cutoff, and full cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary)) — P2 precursor, `S-14`/`S-15`; gate: persistent derivation ATerm path payload round-trip, fresh-runtime path-reuse, stale-ATerm mismatch fallback, and invalid-path fallback tests.
- [x] Current static derivation output-path reuse precursor: tree-walk `derivationStrict` now records a clean crate-private side payload for static derivations keyed by a separate input-hash-substituted pre-output ATerm identity, containing resolved output store paths plus the final derivation hash modulo. The demand-graph value hash for this side record binds the pre-output ATerm, output path payload, and final modulo hash, so changed payload observations propagate even when the pre-output ATerm key is unchanged. Later unchanged static derivations probe that record before calculating the derivation modulo hash, validate that every cached output belongs to the current output set, is inside the configured store, and has the expected output basename, then restore output paths and skip the input-addressed output path computation plus both static-output modulo hash calculations. Reuse increments `static_derivation_output_path_reuses` but does not count as a generic force-cache hit; disabled runtimes, unsupported captured values, stale/dirty/changed records, invalid payloads, and output-set mismatches fall back to normal construction. Final ATerm serialization, deferred-placeholder derivations, dynamic dependency capture beyond hashable lexical captures, and full cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary)) — P2 precursor, `S-14`/`S-15`; gate: cache runtime static-output tests and tree-walk derivation path-reuse/hash-calculation tests.
- [x] Current persistent static derivation output-path side-record precursor: tree-walk `derivationStrict` now materializes exact pre-output ATerm/static-output side payloads into the persistent `values/` pack keyed from the static-output derivation expression identity and hashable lexical free-variable value hashes. Fresh runtimes can load the payload, verify that the blob hash equals the recorded side-payload value hash, require the persisted pre-output ATerm bytes to match the freshly recomputed pre-output ATerm, and reuse output paths only after the existing output-set, configured-store, output-basename, and duplicate-output validation succeeds. This skips the static-output derivation hash/modulo work for exact pre-output matches; final ATerm serialization, final `.drv` path construction when no final-path side record exists, deferred-placeholder derivations, dynamic dependency capture beyond hashable lexical captures, full derivationStrict-node SHA-256/store-path early cutoff, and full cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary)) — P2 precursor, `S-14`/`S-15`; gate: persistent static-output payload round-trip, fresh-runtime reuse, stale-pre-output mismatch fallback, and invalid-output-path fallback tests.
- [x] Current cached derivationStrict `.drv` surface parity canary: tree-walk tests now compare cache-off, cache-on first-observation, and cache-on path-reuse runs for root static, floating-CA, and impure derivations, a static input-closure graph, a deferred-placeholder downstream graph, plus fresh-runtime persistent exact-ATerm final-path and exact-pre-output static-output hits, requiring identical recorded `.drv` paths and ATerm bytes across those runs. The static root case proves one static-output-path reuse before final `.drv` path reuse, zero derivation hash-boundary calculations, and zero final `.drv` text-path calculations on the clean reuse run; the static/floating-CA/impure root cases prove final `.drv` path reuse skips final text-path calculation, the static input-closure case proves two eligible input derivations reuse static output paths and final `.drv` paths while reducing derivation hash and text-path work without changing the downstream closure surface, the persistent floating-CA case proves a fresh runtime can skip the final text-path calculation without static-output reuse, and the persistent static case proves a fresh runtime can skip static-output hash work and final text-path work together. This is selected in-memory and exact persistent reuse parity only; full-closure cached/uncached parity, dynamic dependency capture beyond hashable lexical captures, broader modulo-hash shortcuts, and full derivationStrict-node SHA-256/store-path early cutoff remain open ([§4.1](#41-the-mechanism), [§4.3](#43-interaction-with-the-sha-256-boundary), [§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `S-14`/`S-15`; gate: tree-walk derivation ATerm/static-output path-reuse parity tests.
- [x] Current forced-payload early-cutoff stats substrate: trace-backed force-cache payload observation now reports its value-hash `Reconsideration`, first trace-backed insertion uses no synthetic prior hash, and tree-walk increments `EvalStats::early_cutoffs` when a recomputed pure or trace-backed force-cache payload returns `CutOff`. This is telemetry for the current explicit force-cache observation path only; evaluator-owned recomputation scheduling, transitive red/green propagation, canonical hashes for all values, persistence-aware cutoff accounting, and cached/uncached `.drv` parity proof remain open ([§4.1](#41-the-mechanism)) — P2 precursor, `S-14`/`M-11`; gate: `cache::runtime` and source-backed force-cache stats tests.
- [ ] Full Salsa/red-green early cutoff remains: recompute demand-graph nodes, produce canonical value hashes, compare old/new hashes, stop propagation through dependents on no-change, and prove cached/uncached `.drv` parity ([§4.1](#41-the-mechanism)) — P2, `S-14`; gate: differential `.drv` harness.
- [ ] `derivationStrict`-node early cutoff short-circuiting the SHA-256 `.drv`/store-path computation ([§4.3](#43-interaction-with-the-sha-256-boundary)) — P2; gate: harness.

### Hashing policy and the leak invariant

- [x] Current hash-routing substrate: evaluator-local string/path cons tables use xxh3 structural hashes with equality confirmation; durable frontend parse-cache keys use BLAKE3 over source bytes plus schema/flags, and file parse memo keys pair canonical realpath with BLAKE3(file bytes); Nix-observed `.drv`/store-path surfaces use SHA-256 while hash/fetch builtins use their requested Nix hash algorithms rather than evaluator-local xxh3/BLAKE3 digests. This covers the current parse/import cache and evaluator substrate only, not durable BLAKE3 value-hashes or CA-store value keys. ([§5](#5-hashing-policy)) — P1/P2 precursor, `S-15`; gate: parse-cache key, heap/string structural-hash, derivation/store-path, and hash/fetch builtin tests.
- [x] Current typed hash-domain boundary: `cache::hashing` now defines separate `HotXxh3Hash` and `DurableBlake3Hash` types. The existing string/path cons tables, heap-record structural hashes, parse-cache keys, and file-memo content hashes are threaded through those types instead of naked `u64`/`[u8; 32]`, keeping hot in-process probes and durable BLAKE3 cache addresses distinct in the current substrate. This is not the future value-hash/CA-store or demand-graph hash layer ([§5](#5-hashing-policy), [§5.2](#52-the-leak-invariant)) — P1/P2 precursor, `S-15`; gate: `cache::hashing`, `cache::parse`, and heap/string consing tests.
- [x] Current Nix-observed hash leak canary: a tree-walk derivation test evaluates a static derivation through configured parse/persist cache roots with eval-cache observation enabled while importing a real temporary file and materializing an effectful forced `builtins.pathExists ./marker` payload. It computes the actual current parse-cache BLAKE3 keys for the root and imported sources, the `ParseFileKey` content hash for the imported file, the persisted force-cache node metadata keys, materialized value hashes, node-trace value hashes plus input identity and observation hashes, and the evaluator-local xxh3 structural hash for the derivation name string, then asserts neither the recorded `.drv` ATerm bytes nor the `.drv` store path contain those internal digest renderings, Nix-base32 encodings, or raw digest bytes. It also asserts the configured import parse-cache entry, persistent file-artifact mapping, persistent force value, and effectful force trace occurred. This is a selected current-substrate regression canary, not the future type-enforced full leak-invariant harness ([§5.2](#52-the-leak-invariant)) — P1/P2 precursor, `S-15`; gate: `internal_cache_hash_canaries_do_not_reach_drv_surfaces`.
- [x] Current cache-on/cache-off `.drv` surface parity canary: `configured_import_cache_preserves_drv_surfaces` evaluates the same imported-file derivation with import caching disabled, with configured parse/persist roots on a miss/write path, and with a later persistent-hit path, then requires identical `.drv` paths and ATerm bytes across all three runs. It also scans those surfaces for the imported file parse-cache and file-content BLAKE3 renderings in hex, raw bytes, and Nix base32. This proves the selected current import cache keys/artifacts do not perturb the Nix-observed SHA-derived derivation surface for that scenario, not full-closure cached/uncached parity or full type-enforced leak-invariant coverage ([§5.2](#52-the-leak-invariant), [§8.3](#83-kill-switch-and-cache-off-mode)) — P1/P2 precursor, `S-15`; gate: focused derivation cache-surface parity test.
- [x] Current hash-builtin cache-surface canary: `configured_import_cache_preserves_hash_builtin_surface` evaluates `builtins.hashString "sha256" (import file)` with import caching disabled, with configured parse/persist roots on a miss/write path, and with a later persistent-hit path, requires identical SHA-256 hash-string output across all three runs, and scans that Nix-observed hash output for the same selected parse/import/file-content BLAKE3 and hot xxh3 canaries. This samples one hash-builtin surface under configured import cache reuse only, not every hash/fetch builtin or full type-enforced leak-invariant path ([§5.2](#52-the-leak-invariant), [§8.3](#83-kill-switch-and-cache-off-mode)) — P1/P2 precursor, `S-15`; gate: focused hash-builtin cache-surface canary test.
- [ ] Full P2 cache hashing remains: xxh3 demand-graph/in-process cache keys, BLAKE3 durable value-hashes and CA-store keys for persisted values/files, full type-enforced leak-invariant boundaries, and harness coverage proving xxh3/BLAKE3 cannot reach SHA-256 store-path or `.drv` hashes ([§5](#5-hashing-policy), [§5.2](#52-the-leak-invariant)) — P2, `S-15`.
- [ ] **Leak invariant**: no xxh3/blake3 output ever reaches a SHA-256 store-path/`.drv` hash; type-enforced ([§5.2](#52-the-leak-invariant)) — P2, `S-15`; gate: differential `.drv` harness.

### Storage engine (the durable CA store)

- [ ] Custom mmap'd append-only **packfile** for immutable content-addressed `values/`/`files/` blobs: zero-copy `&[u8]` reads, append-only writes, GC-by-repack ([§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2, `C-13`; gate: harness (advisory cache).
- [ ] `heed`/LMDB for mutable `nodes/` metadata + blake3 → offset index: zero-copy MVCC reads (readers never block), single batched idempotent writer, relaxed sync (`MDB_NOSYNC`/`MDB_MAPASYNC`) ([§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2, `C-13`; gate: loom (parallel readers).
- [x] Current persistence layout/schema substrate: `cache::persist` creates an evaluator-cache root with versioned `nodes/`, `values/`, `files/`, and `schema.toml` metadata carrying a stable format marker plus schema version; reopening a matching schema preserves contents; a well-formed schema-version mismatch discards and recreates only the owned `nodes`/`values`/`files` payload paths; malformed or wrong-format schema metadata errors rather than silently trusting or deleting it. This is layout/versioning only: no node/value/file serialization, mmap packfile, LMDB/redb metadata engine, Attic transport, GC, or harness proof ([§6.1](#61-the-persistent-value-store), [§8.4](#84-open-questions-collected)) — P2 precursor, `R-14`; gate: `cache::persist` tests.
- [x] Current content-addressed blob key/packfile path substrate: `PersistLayout` fixes store-specific append-only packfile paths under `values/` and `files/`, while `PersistBlobStore`/`PersistBlobKey` produce stable domain-separated `DurableBlake3Hash` keys for the future hash-to-offset index. This is addressing only: no byte serialization, mmap packfile format, append/read protocol, LMDB/redb offset index, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` tests.
- [x] Current immutable blob packfile codec substrate: `PersistBlobPackHeader` encodes and validates fixed packfile magic/version/header-length bytes, and `PersistBlobRecordHeader` encodes/decodes each content-addressed record's `DurableBlake3Hash` plus payload length in a stable little-endian prefix. This is format metadata only: no file creation, append protocol, mmap read path, payload hash verification, LMDB/redb offset index writes, GC/repack, or harness proof ([§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current buffered blob pack append/read substrate: `PersistBlobPack` initializes packfile headers without replacing corrupt non-empty files, appends only payloads whose BLAKE3 bytes match the caller's `DurableBlake3Hash`, returns record offsets plus payload lengths for future index storage, and reads payloads back with record hash/length and payload hash verification. This is ordinary `std::fs` IO only: no mmap zero-copy read path, LMDB/redb index integration, batched single-writer coordination, crash-durability policy, GC/repack, Attic transport, or harness proof ([§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current hash-to-offset index value codec substrate: `PersistBlobKey::index_bytes` supplies the domain-separated 33-byte index key, and `PersistBlobLocation::encode_index_value`/`decode_index_value` round-trip record offset plus payload length as stable little-endian metadata. This is codec-only: no LMDB/redb environment, tables, transactions, index writes/reads, mmap pointer reads, GC/repack, or harness proof ([§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current hash-to-offset index entry codec: `PersistBlobIndexEntry` binds a decoded `PersistBlobKey` to its `PersistBlobLocation` in one stable fixed-width record, preserving short-prefix and malformed embedded-key validation through the existing codecs. This is codec-only: no LMDB/redb environment, tables, transactions, index writes/reads, mmap pointer reads, GC/repack, or harness proof ([§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current fixed-record blob index file substrate: `PersistBlobIndex` opens/creates a sidecar index file, appends fixed-width `PersistBlobIndexEntry` records, rejects truncated record tails on open, and linearly scans records to return the newest matching hash-to-offset location. This is a simple durable sidecar only: no LMDB/redb MVCC tables, transactions, writer batching/locking, automatic integration with low-level `PersistCache::append_blob`/`read_blob`, mmap pointer reads, GC/repack, or harness proof ([§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current file-artifact mapping codec substrate: `PersistFileArtifactKey` derives a stable `files/` index key from canonical realpath bytes, source content hash, and the schema/flag-sensitive `ParseCacheKey`, while `PersistFileArtifactIndexValue` encodes a `files/` blob key plus pack location. This is codec-only: no durable index engine, parse-artifact pack payload format, lookup/write integration, mmap reads, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`; gate: `cache::persist` tests.
- [x] Current file-artifact index key decoder: `PersistFileArtifactKey::decode_index_bytes` round-trips the 33-byte tagged file-artifact mapping key, accepts longer index-key prefixes consistently with other fixed codecs, and rejects short or wrong-tag keys through `PersistPackFormatError`. This is codec-only: no durable index engine, lookup/write integration, parse-artifact payload validation, mmap reads, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current file-artifact index entry codec: `PersistFileArtifactIndexEntry` binds a decoded file-artifact mapping key to its `files/` blob index value in one stable fixed-width record, preserving malformed embedded key/value validation through the existing codecs. This is codec-only: no durable index engine, lookup/write integration, parse-artifact payload validation, mmap reads, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current fixed-record file-artifact index file substrate: `PersistFileArtifactIndex` opens/creates the `nodes/file-artifacts.index` sidecar, appends fixed-width `PersistFileArtifactIndexEntry` records, rejects truncated record tails on open, and linearly scans records to return the newest file-artifact mapping value; `PersistCache::open` initializes/exposes it and `record_file_artifact`/`lookup_file_artifact` wrap explicit writes and lookups. This is a simple durable sidecar only: no LMDB/redb MVCC tables, transactions, automatic materialization writes, parse-cache hit integration, mmap reads, cross-process writer coordination, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`; gate: `cache::persist` tests.
- [x] Current cache-level blob pack/index initialization substrate: `PersistCache::open` initializes and exposes separate value/file `PersistBlobPack` and `PersistBlobIndex` handles after schema validation and owned-directory setup, and reports corrupt non-empty packfiles or malformed fixed-record indexes instead of replacing them. This wires packfile/index lifecycle into the persistent cache root only: no automatic index updates/lookups from cache append/read calls, node metadata, mmap reads, writer batching, GC/repack, Attic transport, or harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` tests.
- [x] Current key-routed blob IO substrate: `PersistCache::append_blob` and `read_blob` route a `PersistBlobKey` to the value or file pack, preserving namespace separation for identical payload hashes while reusing the pack-level hash and record verification. These raw helpers remain buffered packfile IO only: no automatic durable hash-to-offset index lookup/update, node metadata linkage, mmap zero-copy reads, writer batching, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` tests.
- [x] Current explicit indexed blob IO helpers: `PersistCache::append_blob_indexed` appends through the key-routed pack and records the returned location in the selected `PersistBlobIndex`, while `lookup_blob_location`/`read_blob_indexed` scan the sidecar index and read/verify the indexed pack record, returning `None` for misses. This is explicit non-transactional sidecar integration only: no automatic low-level append/read indexing, node metadata linkage, mmap zero-copy reads, writer batching/locking, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` tests.
- [x] Current explicit blob-pack tail-GC helper: `PersistCache::trim_blob_pack_tail` snapshots the selected store's latest live roots (`values/` blob index entries, or `files/` blob/file-artifact/parse-artifact index entries) while holding the selected store's same-process same-root blob lock plus the file/parse mapping locks for `files/` trims, verifies each referenced pack record, and truncates only unindexed bytes after the highest live record, returning `PersistBlobPackTrim` byte/count stats. This is tail-only maintenance for unindexed trailing records: no full pack repack/relocation, cross-process/raw-writer coordination, automatic GC policy, mmap reads, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` tests.
- [x] Current blob-pack integrity scan primitive: `PersistBlobPack::records` scans a pack in record order, validates every record header and payload hash, rejects truncated or corrupt tails instead of returning partial metadata, and returns `PersistBlobPackRecord` hash/location entries for maintenance callers. This is read-only buffered scan metadata only: no live-root selection, repack/relocation writer, concurrent writer coordination, automatic GC policy, mmap reads, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` pack tests.
- [x] Current store-typed blob-pack index-entry scan adapter: `PersistCache::blob_pack_index_entries` routes a verified pack scan through the selected `values/` or `files/` store and maps every physical record, including stale duplicates and unindexed tails, to the matching `PersistBlobIndexEntry` key/location shape without writing the sidecar. This is read-only repair/repack input only: no index rebuild, live-root selection, repack/relocation writer, concurrent writer coordination, automatic GC policy, mmap reads, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` cache IO tests.
- [x] Current newest physical blob-pack index-entry scan adapter: `PersistCache::latest_blob_pack_index_entries` collapses the verified physical pack scan to newest-record-wins `PersistBlobIndexEntry` candidates per content hash in stable encoded-key order, matching sidecar latest-entry encoded-key ordering while still including unindexed physical records. This is read-only index-rebuild input only: no index rewrite, live-root selection, repack/relocation writer, concurrent writer coordination, automatic GC policy, mmap reads, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` cache IO tests.
- [x] Current read-only blob-index rebuild plan: `PersistCache::plan_blob_index_rebuild` compares a sidecar's newest hash-to-offset lookup entries with the selected store's verified newest physical pack entries and reports the exact planned entry set plus missing, stale, and dangling lookup differences. Older append-only sidecar history is ignored once newest lookups match, corrupt packs are hard errors, and the plan performs no sidecar rewrite, live-root selection, pack trimming, relocation, or writer coordination ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` cache IO rebuild-plan tests.
- [x] Current explicit blob-index rebuild helper: `PersistCache::rebuild_blob_index_from_pack` builds the verified rebuild plan for one store while holding that store's same-process same-root blob-index write lock, then replaces only that store's hash-to-offset sidecar with the plan's newest physical pack entries, indexing previously unindexed newest records, repairing stale locations, dropping dangling entries, and canonicalizing duplicate sidecar history. This is caller-driven single-sidecar repair only: no live-root selection, blob-pack trimming, full repack/relocation, cross-process/raw-writer coordination, automatic GC/repair policy, mmap reads, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` cache IO rebuild tests.
- [x] Current explicit all-blob-index rebuild helper: `PersistCache::rebuild_blob_indexes_from_packs` rebuilds the `values/` and then `files/` hash-to-offset sidecars from verified pack scans and returns both applied plans, sharing each selected store's same-process same-root blob-index write lock for its rebuild step. This is sequential and non-transactional: a committed value-index rebuild remains in place if the later file-index rebuild fails. It does not rebuild file-artifact/parse-artifact/node sidecars, select live roots, trim or repack blobs, coordinate cross-process/raw writers, or implement automatic repair/GC policy ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` all-blob-index rebuild tests.
- [x] Current idempotent indexed blob materialization substrate: `PersistCache::ensure_blob_indexed` reuses an existing sidecar location only after the pointed pack record verifies for the requested `PersistBlobKey` and payload bytes, appending a fresh record and newer index entry for missing or stale locations, including stale pointers to another valid pack record; indexed value payload, file-artifact, and parse-artifact materializers use this path so duplicate materialization does not grow `values/` or `files/` packs. This is same-process duplicate suppression only; cross-process locking/CAS, automatic compaction, GC/repack, mmap reads, LMDB/redb indexes, and harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` reuse/repair tests.
- [x] Current clone-local indexed materialization single-flight precursor: cloned `PersistCache` handles now share per-store in-process mutexes around the `ensure_blob_indexed` lookup/read/append/index critical section, so simultaneous same-key materialization through clones of one opened cache collapses the initially-missing case to one fresh verified pack record and newest sidecar entry for the selected `values/` or `files/` store. This does not compact older append-only sidecar history for stale or previously duplicated entries. Raw `append_blob_indexed` calls, multi-process writers, durable filesystem locks/CAS, automatic compaction, GC/repack, mmap reads, LMDB/redb indexes, and loom/harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures), [§8.4](#84-open-questions-collected)) — P2/P3.5 precursor, `C-13`/`R-4`/`R-14`; gate: cloned-handle concurrent and poisoned-shared-lock `cache::persist` materialization tests.
- [x] Current same-process same-root indexed materialization single-flight precursor: independently opened `PersistCache` handles in one process now store canonicalized layout paths and acquire their per-store blob materialization mutexes from a process-local weak registry keyed by the canonical persistent cache root, so simultaneous same-key materialization through separate opens of the same root shares the same `ensure_blob_indexed` critical section. The initially-missing case collapses to one fresh verified pack record and newest sidecar entry for the selected store, a poisoned same-root lock is reported before any append/index write, and an opened symlink-root handle keeps writing the canonical target it opened even if the symlink is retargeted. Raw `append_blob_indexed` calls, different roots, multi-process writers, two-machine misses, durable filesystem locks/CAS, automatic compaction, GC/repack, mmap reads, LMDB/redb indexes, and loom/harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures), [§8.4](#84-open-questions-collected)) — P2/P3.5 precursor, `C-13`/`R-4`/`R-14`; gate: independently opened concurrent, poisoned-same-root, and symlink-retarget `cache::persist` tests.
- [x] Current same-process same-root blob-store maintenance lock precursor: cache-level blob-index compaction, blob-index rebuild, and blob-pack tail trim share the same per-store root-lock registry entries as indexed materialization, so maintenance rewrites for one live canonical cache root serialize with cache-level `ensure_blob_indexed` writes for the selected `values/` or `files/` store. File-pack tail trim also shares the file-artifact and parse-artifact mapping locks while it snapshots those live roots. Poisoned live same-root locks are reported before compaction, rebuild, or trim writes sidecars or truncates a pack. Raw lower-level `PersistBlobIndex`/`append_blob_indexed`/`append_blob` users, different roots, multi-process writers, two-machine races, durable filesystem locks/CAS, LMDB/redb indexes, automatic GC/repack, and loom/harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures), [§8.4](#84-open-questions-collected)) — P2/P3.5 precursor, `C-13`/`R-4`/`R-14`; gate: poisoned same-root blob-store maintenance `cache::persist` tests.
- [x] Current same-process same-root open-initialization lock precursor: `PersistCache::open` now creates the caller-supplied root, canonicalizes it, acquires a process-local same-root open mutex from the shared weak root-lock registry, and only then performs schema validation/rewrites plus pack/index initialization through the canonical layout. If a panic poisons a live same-root open lock while another cache handle or waiter keeps that root's lock object alive, later same-root opens report the poison before touching schema or sidecars; first-open/no-survivor sticky poison remains intentionally outside the weak-registry guarantee. This is same-process initialization serialization only; raw lower-level sidecar helpers, different roots, multi-process writers, two-machine misses, durable filesystem locks/CAS, automatic repair/GC policy, LMDB/redb transactions, and loom/harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures), [§8.4](#84-open-questions-collected)) — P2/P3.5 precursor, `C-13`/`R-4`/`R-14`; gate: poisoned live same-root open-lock `cache::persist` test.
- [x] Current same-process same-root node-metadata writer lock precursor: independently opened `PersistCache` handles in one process acquire their node-metadata write mutex from the same process-local weak root-lock registry, so raw metadata appends, typed reuse/value-hash read-modify-appends, current-demand increments, run-boundary advancement, and metadata compaction serialize for a live canonical cache root. Concurrent same-root demand records keep every current-run increment, and a poisoned live metadata lock is reported before any sidecar write. Raw lower-level `PersistNodeMetadataIndex` users, different roots, multi-process writers, two-machine races, durable filesystem locks/CAS, LMDB/redb node tables, automatic GC/repack, and loom/harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures), [§8.4](#84-open-questions-collected)) — P2/P3.5 precursor, `C-13`/`R-4`/`S-14`; gate: same-root concurrent current-demand and poisoned metadata-lock `cache::persist` tests.
- [x] Current same-process same-root node-trace writer lock precursor: independently opened `PersistCache` handles in one process acquire their node-trace write mutex from the same process-local weak root-lock registry, so trace appends and trace-log compaction serialize for a live canonical cache root. Concurrent same-root trace appends keep every complete record readable, and a poisoned live trace lock is reported before any log write. Raw lower-level `PersistNodeTraceLog` users, different roots, multi-process writers, two-machine races, durable filesystem locks/CAS, LMDB/redb node tables, transactionality with metadata/value blobs, automatic GC/repack, and loom/harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures), [§8.4](#84-open-questions-collected)) — P2/P3.5 precursor, `C-13`/`R-4`/`S-14`; gate: same-root concurrent trace append and poisoned trace-lock `cache::persist` tests.
- [x] Current same-process same-root artifact-mapping writer lock precursor: independently opened `PersistCache` handles in one process acquire file-artifact and parse-artifact mapping write mutexes from the same process-local weak root-lock registry, so cache-level mapping appends and mapping compaction serialize for a live canonical cache root. Concurrent same-root appends keep every complete mapping record readable, and poisoned live mapping locks are reported before any sidecar write. Raw lower-level `PersistFileArtifactIndex`/`PersistParseArtifactIndex` users, different roots, multi-process writers, two-machine races, durable filesystem locks/CAS, LMDB/redb indexes, automatic GC/repack, and loom/harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures), [§8.4](#84-open-questions-collected)) — P2/P3.5 precursor, `C-13`/`R-4`/`R-10`; gate: same-root concurrent file/parse artifact append and poisoned mapping-lock `cache::persist` tests.
- [ ] Full P2 persistence remains: custom mmap packfile for immutable `values`/`files`, LMDB/redb mutable `nodes` metadata and indexes, serialized node/value/file records, Attic transport, GC/repack, and cached/uncached harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2, `C-13`/`R-14`.
- [ ] redb as the pure-Rust hermetic drop-in if LMDB's C dependency becomes friction ([§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2/P8, `C-13`.

### The persistent demand graph and Attic integration

- [x] Current P1 frontend artifact cache (`files/` precursor):
      `cache::parse::ParseCache` keys resolved/lowered frontend artifacts by
      BLAKE3(source bytes + schema version + parse flags), stores owned
      `resolved.bin`/`ir.bin`/`symbols.bin`/`meta.toml` under `parse/<key>/`,
      validates/decodes artifacts, reparses corrupt/incomplete entries, treats
      write failures as cache misses, and ordinary filesystem `import` consumes
      it when configured while scoped/text-store imports bypass it. `FileParseMemo`
      exists as an in-process `(canonical realpath, content hash)` helper, but
      full demand-graph `files/` integration remains future.
- [x] Current parse-artifact bundle payload codec: `ParseArtifactBundle` frames the current `resolved.bin`/`ir.bin`/`symbols.bin`/`meta.toml` artifact bytes as one versioned little-endian payload, and `ParseCacheEntry::read_artifact_bundle` reads complete entries into that bundle. This is payload-format substrate only: no automatic file-artifact materialization, automatic parse-cache integration, cache-hit selection, mmap read path, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [x] Current explicit parse-cache hit reader: `ParseCache::load_cached_bytes` computes the normal source-content key, returns `Ok(None)` for missing/incomplete entries, and decodes complete `resolved.bin`/`ir.bin`/`symbols.bin` artifacts into `CachedParse` without parsing. `load_or_parse_bytes` reuses this helper while preserving fallback-to-parse behavior for corrupt entries. This is explicit parse-cache hit reading only: no durable file-artifact lookup integration, automatic evaluator hit selection, mmap read path, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [x] Current parse-artifact bundle hydration adapter: `ParseCacheEntry::write_artifact_bundle` writes a raw bundle back into an entry, clearing `meta.toml` before payload writes and committing metadata last so partial hydration is not treated as complete. This is explicit entry hydration only: no durable index lookup, automatic file-artifact materialization, semantic validation before write, mmap read path, cache-hit integration, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [ ] Materialization (disk-tier) threshold: two-conjunct rule `eval_cost > hash+serialize+IO` **and** likely re-demanded across runs ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk)) — P2, `C-14`; gate: AOS traces.
- [x] Current materialization-threshold policy substrate: `cache::policy` defines caller-supplied `MaterializationCosts` and `MaterializationSignals`, computes `write_cost = hash + serialize + IO` with saturation, and returns `Materialize` only when `eval_cost > write_cost` and the caller-supplied reuse signal predicts cross-run reuse. This is a pure threshold decision only; persistent reuse-metadata bridges and deterministic evaluator cost observations are covered below, while RAM-tier promotion, automatic value writes outside the current force-cache bridge, GC/repack, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk)) — P2 precursor, `C-14`; gate: `cache::policy` tests.
- [x] Current materialization reuse-counter signal substrate: `MaterializationReuse` carries prior-run and current-run demand counters, saturates current-run increments, and converts prior-run demand into the existing `MaterializationSignals` cross-run reuse bit. This is policy vocabulary only: persistent storage and force-cache demand accounting are covered by later rows, while cost measurement, packfile writes, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `C-14`; gate: `cache::policy` tests.
- [x] Current materialization reuse run-boundary substrate: `MaterializationReuse::advance_run` carries current-run demand into prior-run history with saturation and clears current-run observations, so same-run demand only becomes a cross-run reuse signal for later runs. This is policy vocabulary only: persistent sidecar adapters are covered by later rows, while automatic process-boundary update, cost measurement, packfile writes, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `C-14`; gate: `cache::policy` tests.
- [x] Current materialization reuse metadata codec: `MaterializationReuse::encode_persist_metadata`/`decode_persist_metadata` define a stable 16-byte little-endian payload for previous-run and current-run demand counters, with short-prefix validation through `PersistPackFormatError`. This is codec-only: node metadata indexes and force-cache demand accounting are covered by later rows, while automatic process-boundary update, cost measurement, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store)) — P2 precursor, `C-14`; gate: `cache::persist` tests.
- [x] Current demand-node metadata codec substrate: `PersistNodeMetadataKey` derives stable persistent BLAKE3 keys for expression nodes from `CacheExprIdentity` plus ordered free-variable value hashes, and for impure-input leaves from their typed input identity hash, in domains separate from hot `DemandCacheKey`; `PersistNodeMetadataIndexValue` wraps materialization reuse counters plus an optional materialized cached-expression `ValueHash` with canonical absent/present encoding, and `PersistNodeMetadataIndexEntry` frames key/value records. This is codec-only: fixed-record index storage, force-cache demand accounting, and cache-level node-value link helpers are covered by following rows, while LMDB/redb node tables, process-boundary updates, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: `cache::persist` tests.
- [x] Current demand-node metadata index substrate: `PersistLayout::node_metadata_index_path` adds `nodes/metadata.index`, `PersistNodeMetadataIndex` appends fixed-width metadata records and resolves lookups with newest-record-wins semantics, and `PersistCache::record_node_metadata`/`lookup_node_metadata` expose the sidecar through the opened persistent cache root. This is a simple fixed-record sidecar only: typed counter update helpers and force-cache demand accounting are covered by following rows, while LMDB/redb node tables, process-boundary updates, mmap reads, GC/repack, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: `cache::persist` tests.
- [x] Current explicit node reuse counter update adapter: `PersistCache::record_node_materialization_reuse` and `lookup_node_materialization_reuse` expose typed materialization reuse counters over the raw metadata index, and `record_node_current_demand` reads the newest counters, starts from empty counters on a miss, appends a saturated current-demand increment, and returns the recorded value. Reuse updates preserve any existing materialized cached-expression value-hash link in the same metadata record, and same-process same-root writers share the metadata write lock for the read-modify-append critical section. This is caller-driven and append-only: evaluator call-site integration is covered by the force-cache accounting and public run-boundary rows below, while cross-process writer coordination, LMDB/redb node tables, compaction/GC, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: `cache::persist` tests.
- [x] Current explicit node reuse run-boundary adapter: `PersistCache::advance_node_materialization_reuse_run` looks up the newest counters for one node key, returns `None` without writing on a miss, and otherwise appends `MaterializationReuse::advance_run` so current-run observations become prior-run reuse signal for later runs while preserving any materialized value-hash link. This is caller-driven and append-only, with same-process same-root writers serialized by the metadata write lock: Drop/panic/error-path process-boundary orchestration, cross-process writer coordination, LMDB/redb node tables, compaction/GC, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: `cache::persist` tests.
- [x] Current explicit node reuse sidecar advancement: `PersistNodeMetadataIndex::latest_entries` scans the fixed-record metadata sidecar into deterministic newest-entry-per-key order, and `PersistCache::advance_all_node_materialization_reuse_runs` appends changed `MaterializationReuse::advance_run` records for all known node keys while preserving materialized value-hash links and skipping no-op counters. This is caller-driven and append-only, with same-process same-root writers serialized by the metadata write lock: Drop/panic/error-path process-boundary orchestration, cross-process writer coordination, LMDB/redb node tables, automatic compaction/GC policy, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: `cache::persist` tests.
- [x] Current public evaluator reuse run-boundary advancement: successful public tree-walk free-function evaluation exits (`eval_whnf*`, `eval_instantiation_attr_path*`, `eval_raw_bytes*`, and `eval_number_raw_bytes_with_options`) call `advance_all_node_materialization_reuse_runs` when eval-cache observation is enabled and the evaluator already opened the persistent cache root. This advances current-run force-cache demand into prior-run materialization history without creating a persistent cache for evaluations that never touched it. This is public free-function entry-point orchestration only: no low-level `TreeWalk::eval_root`/`eval_node` advancement, Drop/panic/error-path advancement, cross-process writer locking, LMDB/redb node table, automatic compaction/GC policy, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: public eval run-boundary test.
- [x] Current explicit node metadata sidecar compaction: `PersistNodeMetadataIndex::compact_latest_entries` rewrites `nodes/metadata.index` through a temporary file and rename so only the newest record for each node metadata key remains in stable key order, including any materialized value-hash link, and `PersistCache::compact_node_metadata` exposes that operation through the opened cache root. This is caller-driven, with same-process same-root writers serialized by the metadata write lock: automatic process-boundary orchestration, cross-process writer coordination, LMDB/redb node tables, automatic compaction/GC policy, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: `cache::persist` tests.
- [x] Current force-cache persistent demand accounting: tree-walk `force_value` derives `PersistNodeMetadataKey` from the same lookup-safe `ForceCacheSubject` identity and ordered free-variable hashes used by the in-memory force-cache key, lazily opens the configured persistent cache root when `eval_cache_enabled` is on, and best-effort appends `record_node_current_demand` for successful cold forces and in-memory force-cache hits. Observation-only uncacheable subjects such as `currentTime` have no metadata identity and are not counted. This is current-run demand accounting only: public successful run-boundary advancement is covered above, while Drop/panic/error-path advancement, cross-process writer coordination, durable cached-payload hit selection, LMDB/redb node tables, automatic compaction/GC policy, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: force-cache persistent-demand test.
- [x] Current node-reuse materialization decision adapter: `PersistCache::node_materialization_signals` and `node_materialization_decision` read the newest persisted `MaterializationReuse` counters for a demand-node key, treat misses as empty counters, combine prior-run reuse with caller-supplied `MaterializationCosts`, and return the same `MaterializationDecision` accepted by the existing blob/file/parse materializers. Current-run-only demand does not predict cross-run reuse until an explicit run-boundary advance has moved it into prior history. This is decision plumbing only: public successful run-boundary advancement and threshold-driven evaluator writeback are covered by separate rows, while Drop/panic/error-path advancement, cost measurement, LMDB/redb node tables, automatic compaction/GC policy, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` decision tests.
- [x] Current explicit materialization-to-pack adapter: `PersistCache::materialize_blob` consumes a caller-supplied `MaterializationDecision`, skips without hashing/writing on `KeepInMemory`, and appends through the key-routed blob pack on `Materialize`. This is adapter-only: no cost measurement, reuse metadata production, evaluator value serialization, automatic durable index update, mmap read path, GC/repack, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-14`; gate: `cache::persist` tests.
- [x] Current materialized blob index-entry accessor: `PersistMaterialization::index_entry` returns the complete `PersistBlobIndexEntry` only when a blob was materialized, binding the caller-supplied blob key and pack location the future durable index would store. This is accessor-only: no durable index write/read, evaluator value serialization, lookup path, mmap read path, GC/repack, or AOS tuning ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current threshold-to-pack signal adapter: `PersistCache::materialize_blob_with_signals` evaluates caller-supplied `MaterializationSignals` at the persistence boundary, preserves the skip-without-hash/write behavior when the threshold fails, and delegates passing signals to the key-routed blob pack append path. This is adapter-only: no cost measurement, reuse metadata production, evaluator value serialization, automatic durable index update, mmap read path, GC/repack, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-14`; gate: `cache::persist` tests.
- [x] Current explicit indexed materialization adapters: `PersistCache::materialize_blob_indexed` and `materialize_blob_indexed_with_signals` preserve skip-without-hash/write behavior, and on `Materialize` ensure the blob is present through `ensure_blob_indexed`, reusing verified sidecar locations or appending/indexing fresh records as needed. This is explicit non-transactional indexed materialization only: no cost measurement, reuse metadata production, typed evaluator payload handling, automatic raw materialization indexing, mmap read path, GC/repack, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current explicit fixed-record sidecar compaction substrate: `PersistBlobIndex`, `PersistFileArtifactIndex`, and `PersistParseArtifactIndex` expose `latest_entries` and `compact_latest_entries`, scanning append-only fixed-record indexes into deterministic newest-entry-per-key order and rewriting through a truncated temporary file plus rename; `PersistCache::compact_blob_index`, `compact_file_artifact_index`, and `compact_parse_artifact_index` expose those operations through the opened cache root. Blob-index compaction keeps the repaired newest same-key pointer after stale indexed materialization repair while leaving old pack bytes untouched and shares same-process same-root store locks; file/parse artifact compaction shares same-process same-root mapping locks. This is caller-driven maintenance only: no automatic compaction/GC policy, cross-process/raw-writer coordination, LMDB/redb indexes, pack GC/repack, mmap reads, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: fixed-record sidecar compaction tests.
- [x] Current cached-expression value payload persistence adapter: `CachedExpressionValue::encode_persistent_payload` and `decode_persistent_payload` round-trip the current replayable force-cache payload set (inline scalars, context-free strings, context-bearing strings, path payloads with or without context, replayable lists, and replayable attrsets including source-order-tagged, position-bearing, and source-provenanced position-bearing attrsets) as the canonical BLAKE3 preimage used by `ValueHash`, so `DurableBlake3Hash::for_bytes(encoded) == value_hash.as_durable_hash()`. `CachedExpressionValue::persistent_payload_len` reports the exact canonical byte length, including the source-provenance envelope, without allocating the encoded bytes. The decoder rejects malformed and non-canonical string-context payloads, malformed/truncated nested list element payloads, malformed attr-position tags, source-provenance envelopes without retained positions, positionless positioned-attrset tags, and malformed/non-canonical attrset binding payloads including duplicate source-order binding names. `PersistCache::materialize_cached_expression_value_indexed`, `materialize_cached_expression_value_indexed_with_signals`, and `load_cached_expression_value_indexed` write and read those payloads through the indexed `values/` pack by value hash, and loads rehash the decoded payload before returning it while preserving skip-without-hash/encode/write behavior when the materialization threshold fails. This is an explicit cache-level payload bridge only: no evaluator durable hit selection, no lazy-element list or lazy-binding attrset values, no mmap read path, no full AOS cost calibration, no GC/repack, and no cached/uncached harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: `cache::runtime` and `cache::persist` payload tests.
- [x] Current cached-expression node-value metadata linkage adapter: `PersistCache::record_node_materialized_value_hash`, `clear_node_materialized_value_hash`, and `lookup_node_materialized_value_hash` preserve materialization reuse counters while linking or unlinking a demand-node metadata key from the newest materialized cached-expression `ValueHash`; `materialize_cached_expression_node_value_indexed`, `materialize_cached_expression_node_value_indexed_with_signals`, and `load_cached_expression_node_value_indexed` combine that link with the indexed `values/` payload helpers. Skips do not hash, encode, write, or record metadata, and node-key loads return `None` for missing metadata, reuse-only metadata, cleared metadata, or missing value blobs. This is explicit cache-level linkage only: no evaluator durable hit selection, no node/value transactionality, no lazy-element list or lazy-binding attrset values, no mmap read path, no cost measurement, no GC/repack, and no cached/uncached harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: `cache::persist` node-value linkage tests.
- [x] Current threshold-driven force-cache persistent value writeback: tree-walk `force_value` now routes accepted replayable forced-expression payloads through `PersistCache::node_materialization_signals` and `materialize_cached_expression_node_value_indexed_with_signals` after the in-memory force-cache observation accepts a node payload. The evaluator supplies unit costs from `TreeWalkOptions::force_cache_materialization_costs`; persisted prior-run demand supplies the cross-run reuse bit, so cold same-run demand records metadata but skips durable value and trace writes until a run-boundary advance makes that demand prior history. Pure complete observations materialize only after successful expression-node reconsideration and a positive threshold decision; impure observations do the same only when the trace is cacheable and returns an expression node. Rejected impure observations and unsupported recomputed payloads clear any existing durable node-value link after the in-memory force-cache has rejected the observation or had an opportunity to invalidate any runtime payload; observation-only uncacheable subjects such as `currentTime` can clear a stale durable record through their observation identity without using that identity for demand, hit selection, or writeback, and missing durable records remain a no-op. The writeback lazily opens the configured persistent cache root, skips disabled runtimes, unavailable persistent roots, negative threshold decisions, and advisory write errors. This is threshold-driven force payload writeback/clear only: no evaluator-wide durable hit selection, no full AOS cost calibration, no lazy-element list or lazy-binding attrset values, no mmap read path, no GC/repack, and no cached/uncached harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`S-14`; gate: force-cache persistent-demand/value writeback, threshold skip/materialize, stale-clear, and observation-only `currentTime` stale-durable tombstone tests.
- [x] Current deterministic force-cache materialization cost observations: `MaterializationCostObservation` converts observed evaluator work units and canonical persistent payload byte lengths into `MaterializationCosts` by scaling caller-supplied unit costs; payload bytes are rounded to KiB cost units with a one-unit floor, and zero observed force work also uses a one-unit floor for manual observations. `CachedExpressionValue::persistent_payload_len` supplies the measured write-floor bytes without hashing or allocating the encoded payload. Tree-walk cold thunk forces and cacheable first-class impure primop calls pass the observed `thunks_forced` delta into persistent writeback; observations with non-empty impure traces also use the payload KiB units as a deterministic eval-work floor for non-thunk I/O work. Large replayable payload canaries prove that one-work-unit manual observations stay RAM-only when measured write cost dominates, that higher observed work crosses the same threshold, and that a production large `readFile` with prior demand durably materializes its value and verifying trace. This is deterministic in-evaluator cost collection only: no wall-clock sampling, AOS trace calibration, RAM-tier promotion, mmap read path, GC/repack, or cached/uncached harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `C-14`; gate: `cache::policy`, `cache::runtime`, and force-cache large-payload materialization tests.
- [x] Current node verifying-trace payload codec: `PersistNodeTracePayload` frames complete cacheable impure-input traces as versioned little-endian bytes with a magic header, typed input kind/mode tags, raw identity subjects, and observed-result hashes, plus a schema-version-4 tombstone marker for explicitly invalidating older trace records; `CacheableInputFingerprint::from_observation_hash` reconstructs the persisted fingerprints without re-reading the host. The standalone payload decoder preserves trace order, accepts version-1 trace payload bytes for direct decoding, rejects version-1 tombstone sentinels, rejects uncacheable `currentTime`, impossible kind/mode pairs, malformed tags, truncated payloads, and trailing bytes, and exposes stable payload constants for node-trace sidecars; this is payload-format compatibility only, not a non-destructive schema-3 cache-root migration. This is payload-format substrate only: cache-level sidecar storage is covered below, while evaluator durable hit selection, revalidation, currentTime taint propagation through persisted dependents, mmap read path, GC/repack, and cached/uncached harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`/`S-14`; gate: `cache::persist` node-trace payload tests plus schema-mismatch discard tests.
- [x] Current value-associated node verifying-trace sidecar substrate: `PersistLayout::node_trace_log_path` adds `nodes/traces.log`; `PersistNodeTraceLog` appends variable-length records keyed by `PersistNodeMetadataKey` and carrying the materialized `ValueHash` plus `PersistNodeTracePayload`, validates existing log records on open, and returns the newest record for a node key through linear lookup; `PersistCache::record_node_trace`, `record_node_trace_tombstone`, and `lookup_node_trace` expose the sidecar through the opened cache root. Same-process same-root cache-level appends share the trace write lock. This schema-version-4 log is a simple append-only substrate only: no LMDB/redb node table, transaction with node metadata or value blobs, automatic evaluator writeback beyond the force-cache bridge below, durable hit selection, revalidation, cross-process writer coordination, currentTime taint propagation through persisted dependents, automatic compaction/GC policy, mmap read path, or cached/uncached harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`/`S-14`; gate: `cache::persist` node-trace log and cache wrapper tests.
- [x] Current explicit node trace-log compaction substrate: `PersistNodeTraceLog::latest_entries` scans the append-only `nodes/traces.log` into the newest trace entry per node key, preserving tombstones when they are newest; `PersistNodeTraceLog::compact_latest_entries` rewrites those newest entries in stable key order through a temporary log and rename; and `PersistCache::compact_node_traces` exposes the operation at cache level. This is an explicit caller-driven maintenance primitive with same-process same-root writers serialized by the trace write lock: no automatic compaction/GC policy, LMDB/redb node table, transaction with node metadata or value blobs, cross-process writer coordination, mmap read path, or cached/uncached harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`/`S-14`; gate: node-trace log and cache compaction tests.
- [x] Current explicit all-sidecar compaction adapter: `PersistCache::compact_sidecars` runs the current value/file blob-index, file-artifact, parse-artifact, node-metadata, and node-trace compaction primitives in a deterministic order and returns `PersistCompaction` counts for the newest entries retained by each sidecar, with `PersistCompactionError` preserving the failing sidecar type. This is a caller-driven maintenance helper only: it is sequential rather than transactional, requires callers to serialize cross-process and raw lower-level sidecar writes that bypass the current same-root locks, does not rewrite blob packs or drop unreferenced blobs, and still leaves automatic compaction/GC policy, cross-process writer coordination, LMDB/redb indexes, pack GC/repack, mmap reads, Attic transport, and cached/uncached harness proof open ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`/`R-14`/`S-14`; gate: all-sidecar compaction cache test.
- [x] Current explicit storage maintenance sweep: `PersistCache::compact_storage` runs all current sidecar compaction, rebuilds value/file blob-index sidecars from verified pack scans, and then trims value/file blob-pack tails, returning `PersistStorageMaintenance` with sidecar counts, applied blob-index rebuild plans, and per-pack trim stats while `PersistStorageMaintenanceError` preserves the failing phase. Tests cover the non-transactional boundaries where sidecar compaction remains committed if value-pack scan/rebuild fails, rebuilt blob indexes remain committed if a later file-artifact root verification fails during file-pack trimming, and previously unindexed physical tail records become indexed roots before trimming. This is sequential caller-driven maintenance only: no automatic compaction/GC policy, transactionality across sidecar/rebuild/pack phases, cross-process/raw pack or sidecar writer coordination, full pack repack/relocation, LMDB/redb indexes, mmap reads, Attic transport, or cached/uncached harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`/`R-14`/`S-14`; gate: storage maintenance cache tests.
- [x] Current force-cache persistent trace writeback: after tree-walk `force_value` gets an accepted forced-expression observation and successfully materializes its value payload, it appends a value-associated `PersistNodeTracePayload` through `PersistCache::record_node_trace` using the same expression metadata key that links the materialized payload plus the payload's `ValueHash`; pure observations write a zero-input trace payload, while cacheable impure observations write their observed trace segment. Trace-write failure clears the just-linked durable value metadata so a value is not left live without a persisted verifying trace; rejected or unsupported observations clear the durable value link and append a trace tombstone so older value-associated trace log records cannot become live again through a later same-hash relink. The sidecar is still non-transactional. This is trace writeback/tombstoning only: no evaluator durable hit selection, revalidation, transaction with value materialization, currentTime taint propagation through persisted dependents, automatic compaction/GC, mmap read path, or cached/uncached harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`/`S-14`; gate: cacheable impure and pure force persistent value/trace writeback tests, plus rejected/unsupported tombstone tests.
- [x] Current value-associated trace revalidation load adapter: `PersistCache::load_cached_expression_node_value_with_trace_revalidation` reads the newest node metadata value link and newest trace record, returns a miss when either is missing, their `ValueHash` values differ, or the newest trace is a tombstone, revalidates each persisted cacheable impure input through caller-supplied `ImpureInputRevalidator`, and loads the indexed `values/` payload only after every fresh identity and observation hash still matches. This is cache-level durable-hit substrate only: no evaluator hit selection, in-memory demand-graph insertion, dirty propagation, transaction with value materialization, currentTime taint propagation through persisted dependents, automatic compaction/GC, mmap read path, or cached/uncached harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`/`S-14`; gate: `cache::persist` trace-verified node-value load tests.
- [x] Current force-cache durable hit selection: tree-walk forced-expression lookup now tries the trace-verified persistent node-value load after an in-memory force-cache miss; saturated first-class cacheable impure unary calls (`import`, `pathExists`, `readDir`, `readFile`, `readFileType`, and `getEnv`) share this path through a force-cache subject keyed by apply-node identity, builtin name, and argument value hash; pure values hit through the same path by using a zero-input trace record rather than trace absence. Hits rehydrate replayable payloads into the current evaluator heap, preserving source-order attrset metadata and root-or-own-module binding source positions when the durable payload carries those attrset tags, remapping single-module retained attr positions to the current body module only when the payload's source-provenance hash matches the current body module source, seed the caller-owned in-memory runtime with the payload and any revalidated input edges, record fresh revalidated impure inputs into the enclosing evaluation trace when present, record current-run persistent demand, and count the result as a cache hit. Missing/stale/tombstoned traces, value-hash mismatches, unavailable persistent roots, persistent read errors, stale impure observations, missing value blobs, unsupported payload rehydration, unprovenanced stale positioned payloads, and incompatible, multi-module, or non-own positioned payloads all fall back to ordinary forcing and clear stale durable payload links. This is replayable forced-expression hit selection only: no dirty propagation beyond revalidation miss fallback, lazy-element list or lazy-binding attrset values, broader multi-module/non-own binding-position module-source remapping, transaction with value materialization, currentTime taint propagation through persisted dependents, automatic compaction/GC, mmap read path, or cached/uncached harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`/`S-14`; gate: persistent effectful force-cache hit/stale-miss, tombstoned trace miss, seeded in-memory reuse, persistent source-order/root-positioned/own-module imported positioned attrset replay, stale unprovenanced positioned payload miss/clear, and persistent pure currentSystem hit tests.
- [x] Current persistent force-value `.drv` surface parity canary: `persistent_force_cache_hit_preserves_drv_surfaces` evaluates the same derivation attr path with eval cache disabled, with configured persistent force-cache demand/writeback on the cold and materializing paths, and with a fresh-runtime persistent forced-value hit for a replayed `builtins.currentSystem` payload. It requires identical `.drv` paths and ATerm bytes across all runs, requires the final run to report a force-cache hit, and scans those derivation surfaces for the persisted force-cache node/value/trace hashes in hex, raw bytes, and Nix base32. This samples the current replayable forced-value hit path inside a derivation input surface; it does not prove full cached-vs-uncached closure parity, the full leak invariant, derivationStrict-node SHA-256 early cutoff, lazy replay payloads, mmap reads, GC/repack, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `S-14`; gate: focused derivation force-cache surface canary.
- [x] Current effectful persistent force-value `.drv` surface parity canary: `persistent_effectful_force_cache_hit_preserves_drv_surfaces` evaluates the same derivation attr path with eval cache disabled, with configured persistent force-cache demand/writeback on cold and materializing paths, and with a fresh-runtime trace-verified persistent forced-value hit for a replayed `builtins.pathExists ./marker` branch inside `args`. It requires identical `.drv` paths and ATerm bytes across all runs, requires the final run to report a force-cache hit and load the expected force-cache metadata key, requires the materializing run to persist the exact path-exists trace, requires persistent-hit revalidation to replay the path-exists fingerprint into the enclosing impure-input trace, and scans those derivation surfaces for the exercised path-exists trace identity/observation hashes plus persisted force-cache node/value/trace hashes in hex, raw bytes, and Nix base32. This samples the current effectful replayable forced-value hit path inside a derivation input surface; it does not prove full cached-vs-uncached closure parity, the full leak invariant, derivationStrict-node SHA-256 early cutoff, lazy replay payloads, stale-input miss surfaces, mmap reads, GC/repack, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `S-14`; gate: focused effectful derivation force-cache surface canary.
- [x] Current first-class `import` persistent force-value `.drv` surface canary: `persistent_first_class_import_force_cache_hit_and_stale_miss_preserve_drv_surfaces` evaluates a derivation attr path whose `args` depend on `let b = builtins; in b.import ./imported.nix`, first through cache-disabled and materializing same-source runs, then through a fresh-runtime persistent hit, and finally after mutating the imported source. It requires same-source cached runs to match cache-disabled `.drv` path, ATerm bytes, and import fingerprint, requires the persistent-hit run to report a force-cache hit and load the expected force-cache metadata key, requires the changed-source persistent run to miss and recompute the changed import fingerprint, requires materializing and changed-source persistent runs to persist live trace records for the exact import traces under the same force-cache metadata key with different materialized value hashes, requires same-runtime and fresh-runtime post-recompute changed-source runs to hit without force-cache misses and requires the fresh-runtime run to load the changed force-cache metadata key, and requires the changed `.drv` path and ATerm bytes to match a cache-disabled changed-source surface while differing from the original surface. This samples first-class `import` durable hit selection and stale-input fallback inside one derivation input; it does not prove dirty propagation beyond direct revalidation fallback, full cached-vs-uncached closure parity, the full leak invariant, derivationStrict-node SHA-256 early cutoff, lazy replay payloads, mmap reads, GC/repack, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `R-10`/`S-14`; gate: focused first-class import derivation persistent hit/stale-miss surface canary.
- [x] Current filesystem impure-leaf persistent force-value `.drv` surface parity canaries: `persistent_read_file_force_cache_hit_preserves_drv_surfaces`, `persistent_read_dir_force_cache_hit_preserves_drv_surfaces`, and `persistent_read_file_type_force_cache_hit_preserves_drv_surfaces` evaluate derivation attr paths with eval cache disabled, with configured persistent force-cache demand/writeback on cold and materializing paths, and with fresh-runtime trace-verified persistent forced-value hits for `builtins.readFile`, `builtins.readDir`, and `builtins.readFileType` values used inside derivation `args`. They require identical `.drv` paths and ATerm bytes across all runs, require final runs to report force-cache hits and load the expected force-cache metadata keys, require materializing runs to persist the exact filesystem traces, require persistent-hit revalidation to replay the matching filesystem fingerprints into the enclosing impure-input trace, and scan those derivation surfaces for the exercised trace identity/observation hashes plus persisted force-cache node/value/trace hashes in hex, raw bytes, and Nix base32. This samples the current replayable filesystem impure-leaf hit paths inside derivation input surfaces; it does not cover full cached-vs-uncached closure parity, the full leak invariant, derivationStrict-node SHA-256 early cutoff, stale-input miss surfaces beyond the canaries below, lazy replay payloads, mmap reads, GC/repack, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `R-10`/`S-14`; gate: focused filesystem derivation force-cache surface canaries.
- [x] Current stale filesystem impure-leaf persistent force-value `.drv` surface canaries: `persistent_read_file_force_cache_stale_miss_preserves_drv_surfaces`, `persistent_read_dir_force_cache_stale_miss_preserves_drv_surfaces`, and `persistent_read_file_type_force_cache_stale_miss_preserves_drv_surfaces` materialize trace-verified `builtins.readFile ./input.txt`, `builtins.readDir ./dir`, and `builtins.readFileType ./target` forced-value payloads inside derivation `args`, mutate the backing filesystem input, then evaluate through the same persistent cache root. They require stale persistent observations not to reuse old filesystem payloads, require baseline materialization to persist the exact filesystem traces, require recomputation to replay and persist the changed filesystem fingerprints under the same force-cache metadata keys with different materialized value hashes, require same-runtime and fresh-runtime post-recompute changed-input runs to hit without force-cache misses and require the fresh-runtime runs to load the changed force-cache metadata keys, require the resulting `.drv` paths and ATerm bytes to match cache-off changed-input runs while differing from the original materialized surfaces, and scan original/materialized/changed/stale/post-recompute surfaces for the exercised trace identity/observation hashes plus persisted force-cache node/value/trace hashes in hex, raw bytes, and Nix base32. This samples stale filesystem leaf fallback inside derivation input surfaces; it does not cover full cached-vs-uncached closure parity, the full leak invariant, derivationStrict-node SHA-256 early cutoff, dirty propagation beyond fallback, lazy replay payloads, mmap reads, GC/repack, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `R-10`/`S-14`; gate: focused stale filesystem derivation force-cache surface canaries.
- [x] Current `getEnv` configured-environment persistent force-value `.drv` surface canary: `persistent_get_env_force_cache_hit_and_stale_miss_preserve_drv_surfaces` evaluates a derivation attr path whose `args` depend on first-class `let b = builtins; in b.getEnv "AOS_FORCE_CACHE_DRV_TEST"` with eval cache disabled, with configured persistent force-cache demand/writeback on cold and materializing paths, with a fresh-runtime trace-verified persistent forced-value hit for the same configured environment, and finally with the configured environment changed through the same persistent root. It requires same-env cached runs to match the cache-disabled `.drv` path, ATerm bytes, and `getEnv` fingerprint, requires the persistent-hit run to report a force-cache hit and load the expected force-cache metadata key, requires the changed-env persistent run to miss and recompute the changed `getEnv` fingerprint, requires materializing and changed-env persistent runs to persist exact `getEnv` traces under the same force-cache metadata key with different materialized value hashes, requires same-runtime and fresh-runtime changed-env post-recompute runs to hit without force-cache misses and requires the fresh-runtime run to load the changed force-cache metadata key, and requires the changed `.drv` path and ATerm bytes to match a cache-disabled changed-env surface while differing from the original surface. It also scans original/materialized/hit/changed/stale/post-recompute derivation surfaces for the exercised `getEnv` trace identity/observation hashes plus persisted force-cache node/value/trace hashes in hex, raw bytes, and Nix base32. This samples persistent `getEnv` hit selection and stale-input fallback inside one derivation input; it does not prove dirty propagation beyond direct revalidation fallback, full cached-vs-uncached closure parity, the full leak invariant, derivationStrict-node SHA-256 early cutoff, lazy replay payloads, mmap reads, GC/repack, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `R-10`/`S-14`; gate: focused getEnv derivation persistent hit/stale-miss surface canary.
- [x] Current stale effectful persistent force-value `.drv` surface parity canary: `persistent_effectful_force_cache_stale_miss_preserves_drv_surfaces` materializes a trace-verified `builtins.pathExists ./marker` forced-value payload inside derivation `args`, removes the marker, then evaluates through the same persistent cache root. It requires the stale persistent observation not to reuse the old marker-present payload, requires materializing and stale-miss runs to persist exact path-exists traces under the same force-cache metadata key with different materialized value hashes, requires recomputation to replay the new path-exists fingerprint, requires same-runtime and fresh-runtime marker-missing post-recompute runs to hit without force-cache misses and requires the fresh-runtime run to load the changed force-cache metadata key, requires the resulting `.drv` path and ATerm bytes to match a cache-off marker-missing run while differing from the marker-present materialized surface, and scans original/materialized/missing/stale/post-recompute surfaces for the exercised path-exists trace identity/observation hashes plus persisted force-cache node/value/trace hashes in hex, raw bytes, and Nix base32. This samples the current stale-input fallback inside a derivation input surface; it does not prove full cached-vs-uncached closure parity, the full leak invariant, derivationStrict-node SHA-256 early cutoff, dirty propagation beyond fallback, lazy replay payloads, mmap reads, GC/repack, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `S-14`; gate: focused stale effectful derivation force-cache surface canary.
- [x] Current uncacheable `currentTime` `.drv` surface canary: `persistent_current_time_force_cache_no_replay_preserves_drv_surfaces` evaluates a derivation attr path whose `args` depend on `builtins.currentTime` through a forced string conversion, requires same-time configured cached runs to match cache-disabled `.drv` path and ATerm bytes without reporting force-cache hits or misses, then changes the configured current time and requires the cached run to match the changed cache-disabled surface instead of replaying the older one, again without force-cache hits or misses. Each run records the uncacheable currentTime trace, and the canary asserts that persistent force metadata and trace sidecars remain empty. This samples currentTime inside one derivation input surface; it does not prove general currentTime taint propagation through persisted dependents, full cached-vs-uncached closure parity, derivationStrict-node SHA-256 early cutoff, mmap reads, GC/repack, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `S-14`/`R-10`; gate: focused currentTime derivation force-cache surface canary.
- [x] Current explicit file-artifact materialization adapter: `PersistCache::materialize_file_artifact` derives the file-artifact mapping key from a caller-supplied `ParseFileKey`/`ParseCacheKey`, skips without payload hashing or writing on `KeepInMemory`, and on `Materialize` appends the payload to the `files/` pack and returns the typed index value a future durable index would store. This is adapter-only: no parse-artifact payload format, automatic parse-cache integration, durable index update, lookup path, mmap read path, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current explicit indexed file-artifact materialization adapters: `PersistCache::materialize_file_artifact_indexed` and `materialize_file_artifact_indexed_with_signals` preserve skip-without-hash/write behavior, and on `Materialize` ensure the payload is present through `ensure_blob_indexed` before recording the realpath/content/parse mapping through `record_file_artifact`. Successful indexed materialization records the file-artifact mapping sidecar entry and either reuses or records the `files/` blob hash-to-offset sidecar entry. This is explicit non-transactional indexed materialization only: no automatic parse-cache integration, durable hit selection, mmap read path, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`R-10`; gate: `cache::persist` tests.
- [x] Current materialized file-artifact index-entry accessor: `PersistFileArtifactMaterialization::index_entry` returns the complete `PersistFileArtifactIndexEntry` only when an artifact was materialized, binding the mapping key and blob lookup value the future durable index would store. This is accessor-only: no durable index write/read, parse-cache integration, lookup path, mmap read path, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current explicit parse-entry materialization adapter: `PersistCache::materialize_parse_artifact_entry` consumes a caller-supplied `ParseFileKey`/`ParseCacheKey` plus source `ParseCacheEntry`, skips without reading or encoding the entry on `KeepInMemory`, and on `Materialize` bundles the existing parse artifacts and appends that payload through the file-artifact materialization adapter. This is adapter-only: no automatic parse-cache integration, durable index update, lookup path, source/key equality proof, mmap read path, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current explicit indexed parse-entry materialization adapter: `PersistCache::materialize_parse_artifact_entry_indexed` consumes the same caller-supplied `ParseFileKey`/`ParseCacheKey` plus source `ParseCacheEntry`, preserves skip-without-read/encode behavior, and on `Materialize` bundles the existing parse artifacts before delegating to indexed file-artifact materialization so the `files/` blob is reused or freshly indexed and the file-artifact mapping entry is recorded. This is explicit non-transactional indexed materialization only: no automatic parse-cache integration, durable hit selection, source/key equality proof, mmap read path, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current file/parse threshold signal adapters: `PersistCache::materialize_file_artifact_with_signals`, `materialize_file_artifact_indexed_with_signals`, `materialize_parse_artifact_entry_with_signals`, and `materialize_parse_artifact_entry_indexed_with_signals` evaluate caller-supplied `MaterializationSignals` before delegating to the existing decision-based adapters, preserving skip-without-payload-read/write behavior when the threshold fails. This is adapter-only: no automatic parse-cache integration, durable hit selection, source/key equality proof, mmap read path, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current parse metadata decoder substrate: `ParseCacheMeta::from_toml` and `ParseArtifactBundle::decode_meta` parse bundled `meta.toml` into typed schema/node/symbol counts plus the diagnostic source hint, rejecting malformed TOML, missing fields, wrong types, and out-of-range integers. This is metadata validation only: no artifact semantic validation, keyed hydration enforcement, durable index lookup, cache-hit integration, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [x] Current metadata/count/resolved-artifact validated bundle hydration writer: `ParseCacheEntry::write_artifact_bundle_validated` uses `ParseArtifactBundle::validate_meta` to decode bundled metadata, check `schema_version`, decode the bundled `resolved.bin`/`symbols.bin`/`ir.bin` artifacts, and cross-check `symbol_count`/`node_count` before creating or overwriting entry files, then delegates successful writes to the existing metadata-last bundle writer. This is decoder-backed artifact-shape and count validation only: no full artifact semantic validation beyond existing decoders, keyed hydration enforcement, durable index lookup, cache-hit integration, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [x] Current explicit file-artifact read adapter: `PersistCache::read_file_artifact` consumes a typed `PersistFileArtifactIndexValue` and reads/verifies the referenced payload through the `files/` pack. This is a typed buffered read helper only: no parse-artifact payload decoding, automatic cache-hit selection, mmap read path, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current explicit file-artifact bundle hydration adapter: `PersistCache::hydrate_file_artifact_bundle` reads a typed `files/` artifact value, decodes the `ParseArtifactBundle` payload, validates bundled metadata/schema/counts and `resolved.bin`/`symbols.bin`/`ir.bin` decoder shape through `ParseArtifactBundle::validate_meta`, and writes it into a caller-supplied `ParseCacheEntry` only after validation succeeds. This is explicit validated hydration only: no automatic cache-hit selection, source/key equality proof, mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current keyed file-artifact bundle hydration adapter: `PersistCache::hydrate_file_artifact_bundle_for_key` derives the expected `PersistFileArtifactKey` from the requested `ParseFileKey`/`ParseCacheKey`, rejects mismatches before reading the `files/` pack, and otherwise delegates to validated bundle hydration. This is explicit keyed hydration only: no automatic cache-hit selection, full artifact semantic validation beyond existing decoders, mmap read path, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current indexed file-artifact bundle hydration adapter: `PersistCache::hydrate_file_artifact_bundle_from_entry` consumes a complete `PersistFileArtifactIndexEntry`, verifies its key against the requested `ParseFileKey`/`ParseCacheKey`, and delegates matching entries to validated bundle hydration. This is explicit entry-shaped hydration only: no automatic cache-hit selection, full artifact semantic validation beyond existing decoders, mmap read path, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current indexed file-artifact lookup hydration adapter: `PersistCache::hydrate_file_artifact_bundle_from_index` derives the file-artifact mapping key from `ParseFileKey`/`ParseCacheKey`, performs `lookup_file_artifact`, returns `Ok(None)` on misses, and on hits hydrates the validated bundle into a caller-supplied `ParseCacheEntry` while returning the matched `PersistFileArtifactIndexEntry`. This is explicit cache-level lookup hydration only: no automatic parse-cache integration, durable hit selection, source/key equality proof, mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current source-derived indexed parse-cache hydration adapter: `PersistCache::hydrate_parse_cache_entry_from_source_index` derives both `ParseFileKey` and `ParseCacheKey` from one caller-supplied realpath/source byte pair, uses the normal `ParseCache` entry path for that source, and delegates matching durable file-artifact mappings to validated indexed hydration. This is explicit source-shaped hydration only: no canonical path resolution, automatic parse-cache integration, durable hit selection, mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current source-derived indexed parse-cache load adapter: `PersistCache::load_parse_cache_source_from_index` derives both source identities from one caller-supplied canonical realpath/source byte pair, hydrates the matching durable file-artifact entry into the normal `ParseCache` layout, then returns it through `ParseCache::load_cached_bytes` as a `CachedParse` hit. This is explicit caller-driven durable hit loading only: no canonical path resolution, automatic evaluator/import selection, mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`; gate: `cache::persist` tests.
- [x] Current file-derived indexed parse-cache hydration adapter: `PersistCache::hydrate_parse_cache_entry_from_file_index` canonicalizes a requested filesystem path, reads the canonical source bytes, derives the same source-shaped identities, and hydrates the normal `ParseCache` entry when the durable file-artifact index has a match. This is explicit file-shaped hydration only: no automatic parse-cache/evaluator integration, durable hit selection, mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current file-derived indexed parse-cache load adapter: `PersistCache::load_parse_cache_file_from_index` canonicalizes and reads a requested source file, hydrates the matching durable file-artifact entry into the normal `ParseCache` layout, then returns it through `ParseCache::load_cached_bytes` as a `CachedParse` hit. This is explicit caller-driven durable hit loading only: no automatic evaluator/import selection, mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`; gate: `cache::persist` tests.
- [x] Current parse-keyed persistent parse-artifact index substrate: `PersistLayout::parse_artifact_index_path` adds `nodes/parse-artifacts.index`; `PersistParseArtifactKey` encodes the `ParseCacheKey` without a realpath; and `PersistCache::materialize_parse_cache_entry_indexed`, `PersistCache::hydrate_parse_cache_entry_from_parse_index`, and `PersistCache::load_parse_cache_bytes_from_index` materialize and hydrate caller-supplied source bytes through this parse-artifact index. Materialization rejects entries whose normal parse-cache directory key does not match the supplied `ParseCacheKey`, and hydration validates bundled metadata/schema/counts plus `resolved.bin`/`symbols.bin`/`ir.bin` decoder shape before writing the target entry. This is cache API substrate only; evaluator integration is covered by the raw native expression row below. Source equality proof beyond the parse-cache entry directory key, mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`R-10`; gate: `cache::persist` tests.
- [x] Current ordinary filesystem import durable parse-cache hit selection: `TreeWalkOptions::set_persist_cache_root` configures an optional persistent cache root, and unscoped filesystem imports with a configured `parse_cache_root` now try `PersistCache::load_parse_cache_source_from_index` using the same canonical realpath/source bytes already recorded for the import input fingerprint before falling back to `ParseCache::load_or_parse_bytes` when the persistent root is unavailable, misses, or has stale/corrupt indexed artifacts; the persistent root opens lazily on the first eligible import, and scoped imports and text-store imports still bypass this path. This is evaluator import hit selection only: no mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`; gate: `cache::persist` plus tree-walk import tests.
- [x] Current ordinary filesystem import durable parse-cache writeback: unscoped filesystem imports with configured `parse_cache_root` and `persist_cache_root` now materialize successfully stored `ParseCache::load_or_parse_bytes` results into the persistent file-artifact index with `MaterializationDecision::Materialize` after durable misses or stale/corrupt durable entries fall back to normal parse loading. Writeback opens the persistent root through the same lazy advisory path as durable hit selection and ignores persistent write failures. This is ordinary import writeback only; file-backed native source roots and raw native expressions are covered separately. Mmap reads, full artifact semantic validation beyond existing decoders, GC/repack, and harness proof remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`R-10`; gate: tree-walk import tests.
- [x] Current file-backed native root durable parse-cache integration: `NixNative::lower_native_source_bytes` now accepts an optional canonical source path from file-backed instantiation roots and, when both `parse_cache_root` and `persist_cache_root` are configured, tries `PersistCache::load_parse_cache_source_from_index` before ordinary `ParseCache::load_or_parse_bytes`, then writes successfully stored fallback parses to the persistent file-artifact index. Raw `eval_expr`/`instantiate_expr` sources do not synthesize file-artifact keys. This is native file-root lookup/writeback only: no mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`R-10`; gate: native file-root parse-cache tests.
- [x] Current file-backed native root cache-off/cached closure parity canary: `native_file_instantiation_cache_off_on_and_persistent_hit_preserve_drv_closure` evaluates the same two-derivation file-root attr path with native cache disabled, with configured parse/persist/eval cache on the miss/write path, and with a fresh parse root hydrated from a persistent file-artifact hit, then requires the selected root `.drv` path and every recorded input/root ATerm byte payload to be identical. It records the persistent file-index hit and scans cache-off, cache-on miss, and persistent-hit closure paths/ATerm bytes for the exercised file-root parse-cache and file-content BLAKE3 renderings (hex, raw bytes, and Nix base32). This samples the current native file-instantiation closure surface; it is not the full cached-vs-uncached AOS closure harness, full leak-invariant harness, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P1/P2, `S-14`/`S-15`; gate: focused native file-root closure cache-parity test.
- [x] Current raw native expression durable parse-cache integration: `NixNative::lower_native_source_bytes`, when called without a canonical source path and with both `parse_cache_root` and `persist_cache_root` configured, tries `PersistCache::load_parse_cache_bytes_from_index` before ordinary `ParseCache::load_or_parse_bytes`, then writes successfully stored fallback parses through `PersistCache::materialize_parse_cache_entry_indexed`. Raw `eval_expr`/`instantiate_expr` sources use parse-keyed persistent artifacts and still do not synthesize file-artifact keys. This is raw native expression lookup/writeback only: no source equality proof beyond the parse-cache entry directory key, mmap read path, full artifact semantic validation beyond existing decoders, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`/`R-10`; gate: native expression parse-cache tests.
- [ ] Full P2 content-addressed persistence remains: verifying traces in
      `nodes/`, constructive store in `values/`, demand-graph integrated
      durable parse/compile cache in `files/`, and global dedup via hash-consing
      ([§6.1](#61-the-persistent-value-store)–[§6.2](#62-why-content-addressing-is-the-right-shape-here)) — P2, `S-14`.
- [x] Current impure-input fingerprint substrate: `cache::input` defines typed identities and deterministic durable observation hashes for `import`/`readFile`/`readDir`/`readFileType`/`pathExists`/`getEnv` inputs, plus an explicit uncacheable `currentTime` marker. Fingerprints use domain/version prefixes, length-prefixed raw byte chunks, raw-byte sorted directory entries, canonical file-type tags, and path-existence modes in the identity. This is a fingerprinting primitive only; tree-walk builtins, demand-graph leaves, allowed-path/IFD/fetch interactions, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`; gate: `cache::input` tests.
- [x] Current tree-walk impure-input observation trace: successful ordinary filesystem `import`, `readFile`, `readDir`, `readFileType`, `pathExists`, and impure-mode `getEnv` calls append `cache::input` fingerprints to `TreeWalk`/`EvalOutcome`; selected `currentTime` appends an explicit uncacheable marker; pure-mode `getEnv`, denied/failed reads, and text-store reads do not fabricate filesystem/env observations. Trace allocation/fingerprint failures mark the trace incomplete and cache-unusable without changing Nix evaluation semantics. This is an evaluator observation surface only; demand-graph leaves, dependency wiring, persistence, allowed-path/IFD/fetch interactions, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`; gate: tree-walk filesystem trace tests.
- [x] Current cache-side impure leaf substrate: `DemandCacheKey::for_impure_input` creates a domain-separated hot key plus BLAKE3 confirmation digest from a typed input identity hash; `ValueHash::from_impure_input_observation_hash` wraps observed-result hashes without claiming canonical Nix value serialization; and `DemandGraph::observe_impure_input` inserts clean cacheable input leaves or reconsiders existing leaves through early cutoff so changed observations dirty direct dependents. This is graph bookkeeping only; wiring `EvalOutcome` traces from the evaluator/cache runtime, adding edges from evaluating nodes, currentTime taint propagation, persistence, allowed-path/IFD/fetch interactions, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::key`, `cache::cutoff`, and `cache::dcg` tests.
- [x] Current cache-side impure trace ingestion substrate: `DemandGraph::observe_impure_trace` consumes a complete cacheable impure-input trace into cacheable input leaf observations, reports incomplete traces as cache-unusable before graph mutation, and reports uncacheable inputs such as `currentTime` before graph mutation regardless of trace order. This is cacheability/leaf ingestion only; wiring `EvalOutcome` traces from the evaluator/cache runtime, evaluating-node edges, currentTime taint propagation through memoized nodes, persistence, allowed-path/IFD/fetch interactions, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::dcg` tests.
- [x] Current EvalOutcome trace-to-cache substrate: `cache::EvalCache` is an explicit caller-owned demand-graph wrapper, `ImpureInputTraceSource` abstracts evaluator trace providers, and `EvalOutcome` implements that trait so completed tree-walk evaluations can be manually observed by the cache layer. This is an observation adapter only; demand/evaluating-node creation, automatic edges from evaluator-created nodes to input leaves, currentTime taint propagation through memoized nodes, persistence, allowed-path/IFD/fetch trace coverage, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` and tree-walk filesystem trace tests.
- [x] Current EvalCache runtime enable/disable substrate: `cache::EvalCacheRuntime` models disabled cache observation as a no-op and enabled cache observation as delegation to an in-memory `EvalCache`; `TreeWalkOptions::eval_cache_enabled` controls whether `NixNative` owns an enabled runtime, and enabled native evaluations automatically observe their `EvalOutcome` impure traces into that cache. This is automatic leaf ingestion only; demand/evaluating-node creation, evaluator-node cache-key integration, automatic edges from evaluator-created nodes to input leaves, value memoization, currentTime taint propagation through memoized nodes, persistence, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` tests, native eval-cache tests, and `eval_config_maps_native_cache_root_to_cache_options`.
- [x] Current graph-side impure input edge substrate: `DemandGraph::observe_impure_trace_for_node` wires complete cacheable input leaves to a caller-supplied existing node by replacing that node's whole dependency set with the latest leaves, so later changed input observations dirty that node only for current trace-owned inputs; incomplete and uncacheable traces add no leaves and clear prior dependencies from that node. This is graph-side edge wiring only for nodes whose dependencies are owned by the explicit trace; automatic demand/evaluating-node creation, cache-key integration for evaluator nodes, mixed dependency scopes, typed edge groups, automatic edges from evaluator-created nodes to input leaves, value memoization, currentTime taint propagation through memoized nodes, persistence, allowed-path/IFD/fetch trace coverage, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::dcg` tests.
- [x] Current EvalCache trace-to-node edge adapter: `EvalCache::from_graph` wraps a prebuilt demand graph and `EvalCache::observe_impure_inputs_for_node` delegates an `ImpureInputTraceSource` to `DemandGraph::observe_impure_trace_for_node` for a caller-supplied existing node. This is an explicit adapter only; automatic demand/evaluating-node creation, evaluator-node cache-key integration, automatic edges from evaluator-created nodes to input leaves, value memoization, currentTime taint propagation through memoized nodes, persistence, allowed-path/IFD/fetch trace coverage, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` tests.
- [x] Current explicit expression-trace edge adapter: `EvalCache::observe_expression_impure_inputs` and `EvalCacheRuntime::observe_expression_impure_inputs` first compute the caller-supplied expression key and observe/classify a completed trace, skip new expression-node creation for incomplete or uncacheable traces while invalidating any existing inline side payload and clearing stale dependencies for an existing key, and for complete cacheable traces get or insert the expression node before invalidating any prior side payload and replacing its input edges. This is still explicit caller-driven wiring; automatic evaluator demand-node lifecycle, evaluator-produced expression identities/free-variable value hashes, value memoization, currentTime taint propagation through memoized nodes, persistence, and edge-exactness harness coverage remain open ([§3.2](#32-constructing-the-dependency-key), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` tests.
- [x] Current expression cacheability status substrate: `ExpressionTraceObservation::cacheability` exposes a typed memoization gate that distinguishes cacheable expression nodes, incomplete traces, and uncacheable inputs such as `currentTime`. This is a status surface only; evaluator memo lookup, automatic taint propagation through already-memoized dependents, persistence, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` tests.
- [ ] Full impure-input leaf integration remains: `import`/`readFile`/`readDir`/`readFileType`/`pathExists`/`getEnv` reads reified as content-hashed leaves of the demand graph; `currentTime` taints dependent memos as uncacheable ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2, `R-10`; gate: harness (edge-exactness research-grade).
- [ ] Cross-machine sharing in a dedicated `andyl-os` eval-cache Attic namespace; blake3 self-verifying fetch; advisory-never-authoritative; layered GC ([§6.2](#62-why-content-addressing-is-the-right-shape-here), [§6.4](#64-cache-poisoning-and-the-trust-model)) — P2, `C-3`.
- [ ] Persistent-store single-flight (CAS) for two machines missing the same key ([§8.4](#84-open-questions-collected)) — P3.5, `R-4`; gate: loom.

### Out-of-core spill (the swap-to-disk Nix lacks)

- [ ] Eviction of cold hash-consed values to the CA store with rematerialization on demand (zero-copy mmap read by value-hash) ([§6.6](#66-out-of-core-evaluation-the-mmapd-value-store-is-the-spill-to-disk-nix-lacks)) — P2/P3, `C-17`; gate: harness.
- [ ] OS-level demand paging of the mmap'd value closure; write-back-free eviction (blake3 hash *is* the address — clean immutable values just drop) ([§6.6](#66-out-of-core-evaluation-the-mmapd-value-store-is-the-spill-to-disk-nix-lacks)) — P3, `C-17`; couples with the in-process GC ([06](06-memory-management-and-gc.md)).

### Correctness backstops (in-process counterpart)

- [x] Current same-process node-table single-flight precursor: `SharedDemandGraph`
      wraps the existing in-memory `DemandGraph` behind a process-local mutex,
      serializes key lookup plus insertion through
      `get_or_insert_node_with_status`/`get_or_insert_expression_node_with_status`,
      and returns `DemandNodeAdmission` so callers can distinguish the single
      inserting winner from same-key reusers. Cloned handles share the same lock
      and node table, concurrent same-key misses converge on one node without
      clobbering the winner's value hash, and poisoned node-table locks are
      reported explicitly. This is a mutex-backed in-process primitive only:
      no lock-free CAS table, thunk scheduler integration, persistent
      two-machine single-flight, or loom/Miri memory-ordering proof
      ([§8.4](#84-open-questions-collected), [13](13-parallel-evaluation.md))
      — P3.5 precursor, `R-4`; gate: `cache::dcg` tests.
- [ ] Full in-process lock-free CAS single-flight on the node table for
      concurrent same-key misses remains ([§8.4](#84-open-questions-collected),
      [13](13-parallel-evaluation.md)) — P3.5, `R-4`; gate: loom.
- [x] Current native-cache kill switch precursor: through the AOS `NixEvalConfig` env/config path, blank `AOS_NIX_CACHE` or `AOS_NIX_CACHE=0` clears `native_cache_root`; only a valid absolute root maps to `TreeWalkOptions::parse_cache_root = <root>/parse`, `TreeWalkOptions::persist_cache_root = <root>/persist`, and `TreeWalkOptions::eval_cache_enabled = true`. Native frontend lowering constructs `ParseCache` only when the parse-cache option is present, materializes file-derived parse artifacts only when the persistent-cache option is present, and `NixNative` keeps `EvalCacheRuntime` disabled when eval-cache ingestion is disabled. Forced-expression persistent demand accounting, durable hit selection, value payload writeback, verifying-trace writeback, and derivation ATerm/static-output side-record durable lookup/writeback are gated by `eval_cache_enabled`, so disabled eval-cache observation does not write persistent force or derivation side metadata even if a test caller configures a persistent root directly; the native expression disabled-persistent-root canary also proves parse persistence remains active while force metadata and trace sidecars stay empty. This covers the current durable frontend parse/IR artifact cache, in-memory impure-trace leaf ingestion, replayable forced-expression value/trace cache, and derivation side-record persistence, not full demand/evaluating-node lifecycle, persistent demand graph, generic value memoization, or in-process import result memoization. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P1/P2, `S-14`; gate: `eval_config_parses_aos_nix_cache_env_values`, `eval_config_maps_native_cache_root_to_cache_options`, `native_expression_disabled_persistent_root_leaves_force_sidecars_empty`, `disabled_eval_cache_option_skips_persistent_derivation_side_records`, native/tree-walk parse-cache tests, and native/force eval-cache disabled tests.
- [x] Current native raw-instantiation cache-off/cached closure parity canary: `native_instantiation_expr_cache_off_on_and_persistent_hit_preserve_drv_closure` evaluates the same two-derivation raw expression through disabled native cache, configured parse/persist/eval cache on the miss/write path, and a fresh parse root hydrated from a persistent raw parse-artifact hit, then requires the root `.drv` path and every recorded input/root ATerm byte payload to be identical. It records the persistent parse-index hit and scans cache-off, cache-on miss, and persistent-hit closure paths/ATerm bytes for the exercised raw-wrapper parse-cache BLAKE3 renderings (hex, raw bytes, and Nix base32). This samples the current native raw-instantiation closure surface; it is not the full cached-vs-uncached AOS closure harness, full leak-invariant harness, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P1/P2, `S-14`/`S-15`; gate: focused native closure cache-parity test.
- [x] Current native file-instantiation cache-off/cached closure parity canary: `native_file_instantiation_cache_off_on_and_persistent_hit_preserve_drv_closure` evaluates the same two-derivation file-root attr path through disabled native cache, configured parse/persist/eval cache on the miss/write path, and a fresh parse root hydrated from a persistent file-artifact hit, then requires the root `.drv` path and every recorded input/root ATerm byte payload to be identical. It records the persistent file-index hit and scans cache-off, cache-on miss, and persistent-hit closure paths/ATerm bytes for the exercised file-root parse-cache and file-content BLAKE3 renderings (hex, raw bytes, and Nix base32). This samples the current native file-instantiation closure surface; it is not the full cached-vs-uncached AOS closure harness, full leak-invariant harness, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P1/P2, `S-14`/`S-15`; gate: focused native file-root closure cache-parity test.
- [x] Current native forced-expression sidecar leak canaries: `native_instantiation_expr_force_cache_sidecar_hashes_do_not_leak_into_drv_closure` and `native_file_instantiation_force_cache_sidecar_hashes_do_not_leak_into_drv_closure` drive raw-expression and file-root attr-path `NixNative` instantiation through cache-off, persistent demand observation, durable forced-value materialization, and a fresh-runtime persistent pass for a configured `currentSystem` thunk. The final fresh-runtime passes must report force-cache hits, and the canary scanner only admits persistent node metadata entries whose linked value loads through the cached-expression payload decoder. They then scan the resulting `.drv` path and ATerm closure surfaces for forced-expression node metadata BLAKE3 addresses, materialized value BLAKE3 addresses, trace-side BLAKE3 addresses when present, and a representative context-free `NixString` xxh3 hot-hash sentinel. This extends the current native closure safety net to forced-expression persistent sidecars on both native source entry shapes; it is not the full cache-off AOS closure harness, full internal-hash leak invariant, or future value-memoization safety net. ([§5.2](#52-the-leak-invariant), [§8.3](#83-correctness-anxiety-and-the-safety-net)) — P1/P2, `S-14`/`S-15`; gate: focused native force-cache sidecar leak canaries.
- [x] Current native semantic-no-op leaf edit closure canaries: `native_file_instantiation_comment_only_leaf_edit_preserves_drv_closure` and `native_file_instantiation_unused_leaf_package_edit_preserves_drv_closure` evaluate file-root attr paths whose selected derivations depend on a leaf import through an input derivation, seed configured parse/persist cache with the first leaf source, rewrite either comments/whitespace or an unused derivation package in that leaf, and then require cache-disabled and cached runs to keep the two-derivation `.drv` closure byte-identical while the changed leaf reparses into the fresh cache root. They also scan uncached/cached first and changed closures for the exercised first/changed leaf parse-cache and file-content BLAKE3 renderings in hex, raw bytes, and Nix base32. This samples one comment/whitespace leaf edit and one unused leaf-package edit, not bounded recomputation measurement, full AOS closure coverage, the full leak invariant, or future value-memoization safety net. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P1/P2, `S-14`; gate: focused native file-root semantic-edit cache-parity tests.
- [ ] Full cache-off/cold-validation safety net remains: `AOS_NIX_CACHE=0` must bypass the future incremental persistence/value memoization layer, and CI must periodically compare cached vs uncached cold full-closure `.drv` results with the differential harness. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2, `S-14`.

## References

- Salsa, *The "red-green" algorithm* (incremental recomputation, early cutoff):
  <https://salsa-rs.github.io/salsa/reference/algorithm.html> and the Salsa
  overview <https://salsa-rs.github.io/salsa/overview.html>
- rust-analyzer / rustc query system (origin of the red-green algorithm Salsa
  inherits): <https://rustc-dev-guide.rust-lang.org/queries/salsa.html>
- Hammer et al., *Adapton: Composable, Demand-Driven Incremental Computation*
  (PLDI 2014; demanded computation graph, inner/outer observer separation):
  <https://www.cs.tufts.edu/~jfoster/papers/cs-tr-5027.pdf> and project page
  <http://matthewhammer.org/adapton/>
- Mokhov, Mitchell, Peyton Jones, *Build Systems à la Carte* (verifying vs.
  constructive vs. deep-constructive traces; early-cutoff trade-offs):
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2018/03/build-systems.pdf>
  and the *Theory and Practice* journal version
  <https://ndmitchell.com/downloads/paper-build_systems_a_la_carte_theory_and_practice-21_apr_2020.pdf>
- Skip language (side-effect tracking enabling sound memoization with reactive
  invalidation): <https://skiplang.com/blog/2017/01/04/how-memoization-works.html>
  and <https://skiplabs.io/blog/why-skip>
- Attic, multi-tenant Nix binary cache with content-addressed global
  deduplication and three-level GC: <https://docs.attic.rs/> and
  <https://github.com/zhaofengli/attic/blob/main/README.md>
- BLAKE3 vs xxHash/XXH3 performance comparison (throughput figures motivating the
  xxh3-hot / blake3-durable split):
  <https://mojoauth.com/compare-hashing-algorithms/xxhash-vs-blake3> and
  <https://devtoolspro.org/articles/sha256-alternatives-faster-hash-functions-2025/>
- heed, the maintained typed Rust wrapper over LMDB (zero-copy reads, MVCC
  readers-never-block-writers, single writer, `mapsize`): <https://docs.rs/heed>
  and the LMDB design <https://dbdb.io/db/lmdb>
- redb, pure-Rust embedded key-value store (LMDB-alike, no C dependency) — the
  hermetic drop-in alternative: <https://github.com/cberner/redb>
- C++ Nix's use of SQLite for the store database (alongside `/nix/store`) and the
  flake evaluation cache (motivating the SQLite pros/cons in §6.5):
  <https://www.tweag.io/blog/2020-06-25-eval-cache/>
