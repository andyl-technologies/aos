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

## 2. Evaluation as a demand-driven incremental computation graph

We model an evaluation not as a tree-walk that happens to memoize, but as the
incremental maintenance of a **dependency graph of cached computations** — the
same abstraction Salsa calls a query graph and Adapton calls a *demanded
computation graph (DCG)*.

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
| **blake3**| durable value-hashes (§4), persistent CAS keys (§6) | Cryptographic and collision-safe at fleet scale; parallel/SIMD-friendly tree hash; a blake3 collision is what we'd need to fear when a *wrong* cached value could silently flow into a `.drv`, so the durable, shared, cross-machine layer must be cryptographic. |
| **SHA-256** | *only* Nix-observed `.drv` and store-path hashing | Non-negotiable: it is the Nix on-disk format ([02](02-compatibility-constraints.md), [11](11-derivation-and-store-compatibility.md)). Any other choice changes store paths. |

### 5.1 Why not one hash everywhere

- **Why not SHA-256 for internal keys?** SHA-256 is ~10–50× slower than xxh3 and
  blake3 for bulk hashing; using it for billions of in-process probes would make
  the cache a net loss. We reserve SHA-256 for the boundary where Nix's format
  *forces* it.
- **Why not xxh3 for the durable store?** xxh3 is not collision-resistant
  against adversarial or even merely large-scale accidental inputs. The durable
  CAS is shared across CI machines and persists for the life of the project; a
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
  and it produces a flat 256-bit digest convenient as a CAS key.

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

The durable cache is a content-addressed store (CAS) keyed by blake3:

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
  across the package set — deduplicate to a single CAS entry, exactly as Attic
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
   mapping → global NAR store → global chunk store), the eval CAS GCs in layers:
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

## 7. Worked example: a one-line version bump

To make the asymptotics concrete, trace what happens when a developer bumps
`pkgs/curl.nix` from `8.7.1` to `8.8.0` and runs `aos build curl` (and, say,
`aos build git`, which links against curl).

```text
   Run N (cold or warmed):       parse+eval whole closure feeding curl & git.
                                 Populate nodes/ values/ files/ in the CAS.

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
  key simultaneously. The insert path must be a CAS/single-flight on the node
  table so duplicate work collapses; the design is sketched in
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
blake3 for the durable cryptographic CAS, and SHA-256 *only* where the Nix
on-disk format demands it, with a hard invariant that no internal hash may leak
into a Nix-observed store path. Nix's purity, value immutability, and batch
whole-program nature make this caching layer *exact* where the same techniques
are merely best-effort in general-purpose languages, and the must-be-byte-
identical `.drv` requirement ([02](02-compatibility-constraints.md)) places the
canonical value — the thing early cutoff hashes — already on the critical path.
This is the largest single performance lever in the RFC, it pays off even on the
tree-walk oracle independent of interpreter speed, and the differential harness
([15](15-differential-testing-and-benchmarking.md)) is its correctness backstop.

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
