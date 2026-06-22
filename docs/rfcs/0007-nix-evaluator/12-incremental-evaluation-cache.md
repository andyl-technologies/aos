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

- [x] Current in-memory demand-graph substrate: `cache::dcg` stores nodes keyed by opaque `DemandCacheKey`, maintains deterministic dependency/dependent edges, tracks clean/dirty freshness, and applies the local `EarlyCutoff` decision when a node is reconsidered, newly dirtying direct dependents only when the recomputed `ValueHash` changes or no prior hash exists. This is an in-memory substrate only; evaluator `force_memoized`, dynamic dependency tracing, transitive scheduling, persistence, impure-input leaf integration, and full `.drv` harness proof remain open ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§3.1](#31-what-a-node-is)) — P2 precursor, `S-14`/`C-20`; gate: `cache::dcg` tests.
- [ ] Full demand-driven incremental graph remains: create nodes on actual force/eval demand, capture dependencies dynamically Adapton-style, separate inner/outer observers, schedule transitive propagation/recomputation, integrate impure-input leaves and persistence, and prove cached/uncached `.drv` parity ([§2](#2-evaluation-as-a-demand-driven-incremental-computation-graph), [§3.1](#31-what-a-node-is)) — P2, `S-14`/`C-20`; gate: differential `.drv` harness.
- [ ] `force_memoized` wrapping force: consult/populate the cache, node created only on demand ([§3.1](#31-what-a-node-is)) — P2, `S-14`.
- [x] Current standalone cache-key combiner substrate: `cache::key` defines `CacheExprIdentity` plus opaque `DemandCacheKey`, and computes one order-sensitive xxh3 key over a domain/version prefix, expression identity bytes, and caller-supplied free-variable value hashes encoded as length-prefixed chunks. Tests cover stability, source/node identity changes, order sensitivity, multiplicity, and length-prefix ambiguity cases. This implements the C-1 ordered/length-prefixed combiner rule only; demand-graph nodes, canonical free-variable set/order production, real durable value-hash production, and false-hit harness coverage remain open ([§3.2](#32-constructing-the-dependency-key)) — P2 precursor, `C-1`; gate: `cache::key` tests.
- [x] Current expression-node allocation/keying substrate: `DemandGraph::get_or_insert_expression_node` and `EvalCache::get_or_insert_expression_node` centralize graph insertion for a caller-supplied `CacheExprIdentity`, ordered free-variable value hashes, and optional node value hash; existing nodes keep their first value hash. This is explicit allocation/keying only; canonical free-variable discovery/order from strictness/escape analysis, real durable value-hash production, `force_memoized`, automatic evaluator expression-node lifecycle, persistence, currentTime taint propagation, and cached/uncached harness proof remain open ([§3.2](#32-constructing-the-dependency-key)) — P2 precursor, `C-1`/`C-2`/`S-14`; gate: `cache::dcg` and `cache::runtime` tests.
- [ ] Full cache-key integration remains: feed source content + IR node position from the evaluator into demand-graph expression nodes, reuse the strictness/escape free-variable set for canonical slot ordering, feed real durable value hashes, and run the differential false-hit gate ([§3.2](#32-constructing-the-dependency-key)) — P2, `C-1`/`C-2`; gate: harness (false-hit = correctness bug).
- [ ] Expression identity from source content hash + IR node position; free-variable narrowing reusing the strictness/escape FV set ([§3.2](#32-constructing-the-dependency-key)) — P2, `C-2`; gate: harness.
- [ ] Memoization granularity policy (always / conditionally / never cache) ([§3.3](#33-granularity-what-we-memoize-and-what-we-do-not)) — P2, `M-11`; gate: AOS hit/overhead traces (start coarse).
- [x] Current memoization-granularity policy substrate: `cache::policy` defines `MemoizationSubject` defaults for the §3.3 always/conditional/never classes and `MemoizationClass::decide` admits conditional work only when both used-many and cheap-value-hash signals are present. This is policy vocabulary only; evaluator subject selection, demand/cardinality signal production, hit/overhead tracing, `force_memoized` use, persistence/materialization decisions, and measured AOS tuning remain open ([§3.3](#33-granularity-what-we-memoize-and-what-we-do-not), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `M-11`; gate: `cache::policy` tests.
- [x] Current P1 sharing/memoization substrate: allocated thunks memoize successful WHNF results and reset to suspended on failed force; ordinary filesystem imports memoize successful evaluations by canonical import identity; heap strings and path values are consed by evaluator-local xxh3 structural hash plus equality confirmation; and current IR lowering has local shared-thunk cases. This is the call-by-need/string-path-consing substrate only: it does not implement the §3.5 three-layer incremental-cache dedup design, generic value hash-consing, or `H(expr ⊕ env)` runtime cache nodes, and unforced thunk bodies are not fed into value cons tables. ([§3.5](#35-the-deduplication-story-three-layers-and-why-thunks-are-not-all-hashed)) — P1 precursor, `C-15`/`S-7`; gate: thunk memoization, import cache, heap consing, and IR sharing tests.
- [ ] Full three-layer dedup remains: compile-time thunk sharing as an explicit optimization policy, runtime coarse memoization through demand-graph `force_memoized` nodes keyed by `H(expr ⊕ env)`, generic post-force value hash-consing for composite immutable values, and invariant/proof coverage that unforced thunks are never hashed. ([§3.5](#35-the-deduplication-story-three-layers-and-why-thunks-are-not-all-hashed)) — P2/P4, `C-15`/`S-7`.
- [ ] **Open effect lattice** (`is_speculable` + opaque `effect_key`) replacing the closed `{ Pure, Effectful }` enum; `ratchet-cache` treats the effect key opaquely, the Nix dialect supplies the members ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — Phase 1b, `S-23` ([28](28-generalization-and-language-dialects.md) §10). The one generalization that lands in this UNSAFE engine crate.

### Early cutoff

- [x] Current standalone early-cutoff decision primitive: `cache::cutoff` defines a typed `ValueHash` wrapper for future `blake3(canonical(value))` hashes and `EarlyCutoff::decide(previous, recomputed)`, returning `CutOff` only when a prior value hash exists and equals the recomputed value hash, otherwise `Propagate`. This is the comparison primitive only; full Salsa/DCG propagation, full canonical value-hash production, node invalidation, and harness proof remain open ([§4.1](#41-the-mechanism)) — P2 precursor, `S-14`; gate: `cache::cutoff` tests.
- [x] Current inline scalar value-hash substrate: `ValueHash::from_inline_value` hashes validated inline WHNF `int`/`bool`/`null`/`float` payloads in the durable BLAKE3 domain `aos-nix-inline-value-hash-v1`; floats are hashed by raw IEEE bits, so this may over-propagate relative to future Nix numeric canonicalization but cannot cut off distinct bit patterns. Heap-backed values, strings/paths/lists/attrs canonical serialization, functions/thunks cacheability policy, generic hash-cons value fields, `force_memoized` integration, persistence, and harness proof remain open ([§4.1](#41-the-mechanism), [§5](#5-hashing-policy)) — P2 precursor, `S-14`/`S-15`; gate: `cache::cutoff` tests.
- [x] Current inline-value early-cutoff adapter: `DemandGraph::reconsider_inline_value_node` and `EvalCache::reconsider_inline_value_node` hash a recomputed inline scalar before applying ordinary node reconsideration; unsupported heap values fail before mutating node state. This is an inline adapter only; heap/composite canonical hashing, functions/thunks policy, real evaluator value-hash production, `force_memoized`, evaluator node lifecycle, automatic `NixNative` use, persistence, and harness proof remain open ([§4.1](#41-the-mechanism), [§5](#5-hashing-policy)) — P2 precursor, `S-14`/`S-15`; gate: `cache::dcg` and `cache::runtime` tests.
- [ ] Full Salsa/red-green early cutoff remains: recompute demand-graph nodes, produce canonical value hashes, compare old/new hashes, stop propagation through dependents on no-change, and prove cached/uncached `.drv` parity ([§4.1](#41-the-mechanism)) — P2, `S-14`; gate: differential `.drv` harness.
- [ ] `derivationStrict`-node early cutoff short-circuiting the SHA-256 `.drv`/store-path computation ([§4.3](#43-interaction-with-the-sha-256-boundary)) — P2; gate: harness.

### Hashing policy and the leak invariant

- [x] Current hash-routing substrate: evaluator-local string/path cons tables use xxh3 structural hashes with equality confirmation; durable frontend parse-cache keys use BLAKE3 over source bytes plus schema/flags, and file parse memo keys pair canonical realpath with BLAKE3(file bytes); Nix-observed `.drv`/store-path surfaces use SHA-256 while hash/fetch builtins use their requested Nix hash algorithms rather than evaluator-local xxh3/BLAKE3 digests. This covers the current parse/import cache and evaluator substrate only, not durable BLAKE3 value-hashes or CA-store value keys. ([§5](#5-hashing-policy)) — P1/P2 precursor, `S-15`; gate: parse-cache key, heap/string structural-hash, derivation/store-path, and hash/fetch builtin tests.
- [x] Current typed hash-domain boundary: `cache::hashing` now defines separate `HotXxh3Hash` and `DurableBlake3Hash` types. The existing string/path cons tables, heap-record structural hashes, parse-cache keys, and file-memo content hashes are threaded through those types instead of naked `u64`/`[u8; 32]`, keeping hot in-process probes and durable BLAKE3 cache addresses distinct in the current substrate. This is not the future value-hash/CA-store or demand-graph hash layer ([§5](#5-hashing-policy), [§5.2](#52-the-leak-invariant)) — P1/P2 precursor, `S-15`; gate: `cache::hashing`, `cache::parse`, and heap/string consing tests.
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
- [x] Current file-artifact mapping codec substrate: `PersistFileArtifactKey` derives a stable `files/` index key from canonical realpath bytes, source content hash, and the schema/flag-sensitive `ParseCacheKey`, while `PersistFileArtifactIndexValue` encodes a `files/` blob key plus pack location. This is codec-only: no durable index engine, parse-artifact pack payload format, lookup/write integration, mmap reads, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-10`; gate: `cache::persist` tests.
- [x] Current file-artifact index key decoder: `PersistFileArtifactKey::decode_index_bytes` round-trips the 33-byte tagged file-artifact mapping key, accepts longer index-key prefixes consistently with other fixed codecs, and rejects short or wrong-tag keys through `PersistPackFormatError`. This is codec-only: no durable index engine, lookup/write integration, parse-artifact payload validation, mmap reads, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current file-artifact index entry codec: `PersistFileArtifactIndexEntry` binds a decoded file-artifact mapping key to its `files/` blob index value in one stable fixed-width record, preserving malformed embedded key/value validation through the existing codecs. This is codec-only: no durable index engine, lookup/write integration, parse-artifact payload validation, mmap reads, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current cache-level blob pack initialization substrate: `PersistCache::open` initializes and exposes separate value/file `PersistBlobPack` handles after schema validation and owned-directory setup, and reports corrupt non-empty packfiles instead of replacing them. This wires packfile lifecycle into the persistent cache root only; durable hash-to-offset index integration, node metadata, mmap reads, writer batching, GC/repack, Attic transport, and harness proof remain open ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` tests.
- [x] Current key-routed blob IO substrate: `PersistCache::append_blob` and `read_blob` route a `PersistBlobKey` to the value or file pack, preserving namespace separation for identical payload hashes while reusing the pack-level hash and record verification. This is still buffered packfile IO only: no durable hash-to-offset index lookup/update, node metadata linkage, mmap zero-copy reads, writer batching, GC/repack, Attic transport, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`R-14`; gate: `cache::persist` tests.
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
- [x] Current parse-artifact bundle payload codec: `ParseArtifactBundle` frames the current `resolved.bin`/`ir.bin`/`symbols.bin`/`meta.toml` artifact bytes as one versioned little-endian payload, and `ParseCacheEntry::read_artifact_bundle` reads complete entries into that bundle. This is payload-format substrate only: no automatic file-artifact materialization, durable index update, lookup path, bundle-to-entry hydration, mmap read path, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [x] Current parse-artifact bundle hydration adapter: `ParseCacheEntry::write_artifact_bundle` writes a raw bundle back into an entry, clearing `meta.toml` before payload writes and committing metadata last so partial hydration is not treated as complete. This is explicit entry hydration only: no durable index lookup, automatic file-artifact materialization, semantic validation before write, mmap read path, cache-hit integration, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [ ] Materialization (disk-tier) threshold: two-conjunct rule `eval_cost > hash+serialize+IO` **and** likely re-demanded across runs ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk)) — P2, `C-14`; gate: AOS traces.
- [x] Current materialization-threshold policy substrate: `cache::policy` defines caller-supplied `MaterializationCosts` and `MaterializationSignals`, computes `write_cost = hash + serialize + IO` with saturation, and returns `Materialize` only when `eval_cost > write_cost` and the caller-supplied reuse signal predicts cross-run reuse. This is a pure threshold decision only; cost measurement, reuse metadata, RAM-tier promotion, packfile writes, persistence integration, GC/repack, and AOS tuning remain open ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk)) — P2 precursor, `C-14`; gate: `cache::policy` tests.
- [x] Current materialization reuse-counter signal substrate: `MaterializationReuse` carries prior-run and current-run demand counters, saturates current-run increments, and converts prior-run demand into the existing `MaterializationSignals` cross-run reuse bit. This is policy vocabulary only: no durable counter storage, evaluator demand accounting, cost measurement, packfile writes, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `C-14`; gate: `cache::policy` tests.
- [x] Current materialization reuse run-boundary substrate: `MaterializationReuse::advance_run` carries current-run demand into prior-run history with saturation and clears current-run observations, so same-run demand only becomes a cross-run reuse signal for later runs. This is policy vocabulary only: no durable counter storage, automatic process-boundary update, evaluator demand accounting, cost measurement, packfile writes, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§8.2](#82-cache-size-and-hashing-overhead)) — P2 precursor, `C-14`; gate: `cache::policy` tests.
- [x] Current materialization reuse metadata codec: `MaterializationReuse::encode_persist_metadata`/`decode_persist_metadata` define a stable 16-byte little-endian payload for previous-run and current-run demand counters, with short-prefix validation through `PersistPackFormatError`. This is codec-only: no node metadata index, durable counter storage, automatic process-boundary update, evaluator demand accounting, cost measurement, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store)) — P2 precursor, `C-14`; gate: `cache::persist` tests.
- [x] Current explicit materialization-to-pack adapter: `PersistCache::materialize_blob` consumes a caller-supplied `MaterializationDecision`, skips without hashing/writing on `KeepInMemory`, and appends through the key-routed blob pack on `Materialize`. This is adapter-only: no cost measurement, reuse metadata production, evaluator value serialization, durable index update, mmap read path, GC/repack, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-14`; gate: `cache::persist` tests.
- [x] Current threshold-to-pack signal adapter: `PersistCache::materialize_blob_with_signals` evaluates caller-supplied `MaterializationSignals` at the persistence boundary, preserves the skip-without-hash/write behavior when the threshold fails, and delegates passing signals to the key-routed blob pack append path. This is adapter-only: no cost measurement, reuse metadata production, evaluator value serialization, durable index update, mmap read path, GC/repack, or AOS tuning ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-14`; gate: `cache::persist` tests.
- [x] Current explicit file-artifact materialization adapter: `PersistCache::materialize_file_artifact` derives the file-artifact mapping key from a caller-supplied `ParseFileKey`/`ParseCacheKey`, skips without payload hashing or writing on `KeepInMemory`, and on `Materialize` appends the payload to the `files/` pack and returns the typed index value a future durable index would store. This is adapter-only: no parse-artifact payload format, automatic parse-cache integration, durable index update, lookup path, mmap read path, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current materialized file-artifact index-entry accessor: `PersistFileArtifactMaterialization::index_entry` returns the complete `PersistFileArtifactIndexEntry` only when an artifact was materialized, binding the mapping key and blob lookup value the future durable index would store. This is accessor-only: no durable index write/read, parse-cache integration, lookup path, mmap read path, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current explicit parse-entry materialization adapter: `PersistCache::materialize_parse_artifact_entry` consumes a caller-supplied `ParseFileKey`/`ParseCacheKey` plus source `ParseCacheEntry`, skips without reading or encoding the entry on `KeepInMemory`, and on `Materialize` bundles the existing parse artifacts and appends that payload through the file-artifact materialization adapter. This is adapter-only: no automatic parse-cache integration, durable index update, lookup path, source/key equality proof, mmap read path, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current file/parse threshold signal adapters: `PersistCache::materialize_file_artifact_with_signals` and `materialize_parse_artifact_entry_with_signals` evaluate caller-supplied `MaterializationSignals` before delegating to the existing decision-based adapters, preserving skip-without-payload-read/write behavior when the threshold fails. This is adapter-only: no automatic parse-cache integration, durable index update, lookup path, source/key equality proof, mmap read path, GC/repack, or harness proof ([§3.4](#34-the-materialization-threshold-when-a-memoized-result-hits-disk), [§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`/`C-14`; gate: `cache::persist` tests.
- [x] Current parse metadata decoder substrate: `ParseCacheMeta::from_toml` and `ParseArtifactBundle::decode_meta` parse bundled `meta.toml` into typed schema/node/symbol counts plus the diagnostic source hint, rejecting malformed TOML, missing fields, wrong types, and out-of-range integers. This is metadata validation only: no artifact semantic validation, keyed hydration enforcement, durable index lookup, cache-hit integration, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [x] Current metadata/count-validated bundle hydration writer: `ParseCacheEntry::write_artifact_bundle_validated` uses `ParseArtifactBundle::validate_meta` to decode bundled metadata, check `schema_version`, decode the bundled symbols/IR artifacts, and cross-check `symbol_count`/`node_count` before creating or overwriting entry files, then delegates successful writes to the existing metadata-last bundle writer. This is metadata and artifact-count validation only: no full artifact semantic validation beyond existing decoders, keyed hydration enforcement, durable index lookup, cache-hit integration, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::parse` tests.
- [x] Current explicit file-artifact read adapter: `PersistCache::read_file_artifact` consumes a typed `PersistFileArtifactIndexValue` and reads/verifies the referenced payload through the `files/` pack. This is a typed buffered read helper only: no durable index lookup, parse-artifact payload decoding, mmap read path, cache hit integration, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current explicit file-artifact bundle hydration adapter: `PersistCache::hydrate_file_artifact_bundle` reads a typed `files/` artifact value, decodes the `ParseArtifactBundle` payload, and writes it into a caller-supplied `ParseCacheEntry`. This is explicit hydration only: no durable index lookup, automatic cache-hit selection, source/key equality proof, mmap read path, semantic validation before writing, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current keyed file-artifact bundle hydration adapter: `PersistCache::hydrate_file_artifact_bundle_for_key` derives the expected `PersistFileArtifactKey` from the requested `ParseFileKey`/`ParseCacheKey`, rejects mismatches before reading the `files/` pack, and otherwise delegates to bundle hydration. This is explicit keyed hydration only: no durable index lookup, automatic cache-hit selection, semantic validation before writing, mmap read path, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [x] Current indexed file-artifact bundle hydration adapter: `PersistCache::hydrate_file_artifact_bundle_from_entry` consumes a complete `PersistFileArtifactIndexEntry`, verifies its key against the requested `ParseFileKey`/`ParseCacheKey`, and delegates matching entries to bundle hydration. This is explicit entry-shaped hydration only: no durable index lookup, automatic cache-hit selection, semantic validation before writing, mmap read path, GC/repack, or harness proof ([§6.1](#61-the-persistent-value-store), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§6.5](#65-storage-engine-two-engines-for-two-data-natures)) — P2 precursor, `C-13`; gate: `cache::persist` tests.
- [ ] Full P2 content-addressed persistence remains: verifying traces in
      `nodes/`, constructive store in `values/`, demand-graph integrated
      durable parse/compile cache in `files/`, and global dedup via hash-consing
      ([§6.1](#61-the-persistent-value-store)–[§6.2](#62-why-content-addressing-is-the-right-shape-here)) — P2, `S-14`.
- [x] Current impure-input fingerprint substrate: `cache::input` defines typed identities and deterministic durable observation hashes for `import`/`readFile`/`readDir`/`readFileType`/`pathExists`/`getEnv` inputs, plus an explicit uncacheable `currentTime` marker. Fingerprints use domain/version prefixes, length-prefixed raw byte chunks, raw-byte sorted directory entries, canonical file-type tags, and path-existence modes in the identity. This is a fingerprinting primitive only; tree-walk builtins, demand-graph leaves, allowed-path/IFD/fetch interactions, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`; gate: `cache::input` tests.
- [x] Current tree-walk impure-input observation trace: successful ordinary filesystem `import`, `readFile`, `readDir`, `readFileType`, `pathExists`, and impure-mode `getEnv` calls append `cache::input` fingerprints to `TreeWalk`/`EvalOutcome`; selected `currentTime` appends an explicit uncacheable marker; pure-mode `getEnv`, denied/failed reads, and text-store reads do not fabricate filesystem/env observations. Trace allocation/fingerprint failures mark the trace incomplete and cache-unusable without changing Nix evaluation semantics. This is an evaluator observation surface only; demand-graph leaves, dependency wiring, persistence, allowed-path/IFD/fetch interactions, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`; gate: tree-walk filesystem trace tests.
- [x] Current cache-side impure leaf substrate: `DemandCacheKey::for_impure_input` creates a domain-separated hot key from a typed input identity hash; `ValueHash::from_impure_input_observation_hash` wraps observed-result hashes without claiming canonical Nix value serialization; and `DemandGraph::observe_impure_input` inserts clean cacheable input leaves or reconsiders existing leaves through early cutoff so changed observations dirty direct dependents. This is graph bookkeeping only; wiring `EvalOutcome` traces from the evaluator/cache runtime, adding edges from evaluating nodes, currentTime taint propagation, persistence, allowed-path/IFD/fetch interactions, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::key`, `cache::cutoff`, and `cache::dcg` tests.
- [x] Current cache-side impure trace ingestion substrate: `DemandGraph::observe_impure_trace` consumes a complete cacheable impure-input trace into cacheable input leaf observations, reports incomplete traces as cache-unusable before graph mutation, and reports uncacheable inputs such as `currentTime` before graph mutation regardless of trace order. This is cacheability/leaf ingestion only; wiring `EvalOutcome` traces from the evaluator/cache runtime, evaluating-node edges, currentTime taint propagation through memoized nodes, persistence, allowed-path/IFD/fetch interactions, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::dcg` tests.
- [x] Current EvalOutcome trace-to-cache substrate: `cache::EvalCache` is an explicit caller-owned demand-graph wrapper, `ImpureInputTraceSource` abstracts evaluator trace providers, and `EvalOutcome` implements that trait so completed tree-walk evaluations can be manually observed by the cache layer. This is an observation adapter only; demand/evaluating-node creation, automatic edges from evaluator-created nodes to input leaves, currentTime taint propagation through memoized nodes, persistence, allowed-path/IFD/fetch trace coverage, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` and tree-walk filesystem trace tests.
- [x] Current EvalCache runtime enable/disable substrate: `cache::EvalCacheRuntime` models disabled cache observation as a no-op and enabled cache observation as delegation to an in-memory `EvalCache`; `TreeWalkOptions::eval_cache_enabled` controls whether `NixNative` owns an enabled runtime, and enabled native evaluations automatically observe their `EvalOutcome` impure traces into that cache. This is automatic leaf ingestion only; demand/evaluating-node creation, evaluator-node cache-key integration, automatic edges from evaluator-created nodes to input leaves, value memoization, currentTime taint propagation through memoized nodes, persistence, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` tests, native eval-cache tests, and `eval_config_maps_native_cache_root_to_parse_cache_options`.
- [x] Current graph-side impure input edge substrate: `DemandGraph::observe_impure_trace_for_node` wires complete cacheable input leaves to a caller-supplied existing node, so later changed input observations dirty that node through ordinary dependency propagation; incomplete and uncacheable traces add no leaves or edges. This is graph-side edge wiring only; automatic demand/evaluating-node creation, cache-key integration for evaluator nodes, automatic edges from evaluator-created nodes to input leaves, value memoization, currentTime taint propagation through memoized nodes, persistence, allowed-path/IFD/fetch trace coverage, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::dcg` tests.
- [x] Current EvalCache trace-to-node edge adapter: `EvalCache::from_graph` wraps a prebuilt demand graph and `EvalCache::observe_impure_inputs_for_node` delegates an `ImpureInputTraceSource` to `DemandGraph::observe_impure_trace_for_node` for a caller-supplied existing node. This is an explicit adapter only; automatic demand/evaluating-node creation, evaluator-node cache-key integration, automatic edges from evaluator-created nodes to input leaves, value memoization, currentTime taint propagation through memoized nodes, persistence, allowed-path/IFD/fetch trace coverage, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` tests.
- [x] Current explicit expression-trace edge adapter: `EvalCache::observe_expression_impure_inputs` and `EvalCacheRuntime::observe_expression_impure_inputs` first observe/classify a completed trace, skip expression-node creation for incomplete or uncacheable traces, and for complete cacheable traces get or insert a caller-supplied expression node before wiring input leaves to it. This is still explicit caller-driven wiring; automatic evaluator demand-node lifecycle, evaluator-produced expression identities/free-variable value hashes, value memoization, currentTime taint propagation through memoized nodes, persistence, and edge-exactness harness coverage remain open ([§3.2](#32-constructing-the-dependency-key), [§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` tests.
- [x] Current expression cacheability status substrate: `ExpressionTraceObservation::cacheability` exposes a typed memoization gate that distinguishes cacheable expression nodes, incomplete traces, and uncacheable inputs such as `currentTime`. This is a status surface only; evaluator memo lookup, automatic taint propagation through already-memoized dependents, persistence, and edge-exactness harness coverage remain open ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs), [§8.3](#83-correctness-anxiety-and-the-safety-net)) — P2 precursor, `R-10`/`S-14`; gate: `cache::runtime` tests.
- [ ] Full impure-input leaf integration remains: `import`/`readFile`/`readDir`/`readFileType`/`pathExists`/`getEnv` reads reified as content-hashed leaves of the demand graph; `currentTime` taints dependent memos as uncacheable ([§6.3](#63-treating-importreadfile-reads-as-hashed-inputs)) — P2, `R-10`; gate: harness (edge-exactness research-grade).
- [ ] Cross-machine sharing in a dedicated `andyl-os` eval-cache Attic namespace; blake3 self-verifying fetch; advisory-never-authoritative; layered GC ([§6.2](#62-why-content-addressing-is-the-right-shape-here), [§6.4](#64-cache-poisoning-and-the-trust-model)) — P2, `C-3`.
- [ ] Persistent-store single-flight (CAS) for two machines missing the same key ([§8.4](#84-open-questions-collected)) — P3.5, `R-4`; gate: loom.

### Out-of-core spill (the swap-to-disk Nix lacks)

- [ ] Eviction of cold hash-consed values to the CA store with rematerialization on demand (zero-copy mmap read by value-hash) ([§6.6](#66-out-of-core-evaluation-the-mmapd-value-store-is-the-spill-to-disk-nix-lacks)) — P2/P3, `C-17`; gate: harness.
- [ ] OS-level demand paging of the mmap'd value closure; write-back-free eviction (blake3 hash *is* the address — clean immutable values just drop) ([§6.6](#66-out-of-core-evaluation-the-mmapd-value-store-is-the-spill-to-disk-nix-lacks)) — P3, `C-17`; couples with the in-process GC ([06](06-memory-management-and-gc.md)).

### Correctness backstops (in-process counterpart)

- [ ] In-process CAS single-flight on the node table for concurrent same-key misses ([§8.4](#84-open-questions-collected), [13](13-parallel-evaluation.md)) — P3.5, `R-4`; gate: loom.
- [x] Current native-cache kill switch precursor: through the AOS `NixEvalConfig` env/config path, blank `AOS_NIX_CACHE` or `AOS_NIX_CACHE=0` clears `native_cache_root`; only a valid absolute root maps to `TreeWalkOptions::parse_cache_root = <root>/parse` and `TreeWalkOptions::eval_cache_enabled = true`. Native frontend lowering constructs `ParseCache` only when the parse-cache option is present, and `NixNative` keeps `EvalCacheRuntime` disabled when eval-cache ingestion is disabled. This covers only the current durable frontend parse/IR artifact cache and in-memory impure-trace leaf ingestion, not value memoization, demand/evaluating-node lifecycle, persistent demand graph/value cache, or in-process import result memoization. ([§8.3](#83-correctness-anxiety-and-the-safety-net)) — P1/P2, `S-14`; gate: `eval_config_parses_aos_nix_cache_env_values`, `eval_config_maps_native_cache_root_to_parse_cache_options`, native/tree-walk parse-cache tests, and native eval-cache tests.
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
