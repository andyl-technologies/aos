# RFC-0007 - Attribute Sets: Hidden Classes, Inline Caches, HAMT Overlays, and Iteration-Order Compatibility

> Part of the RFC-0007 aos-nix documentation set. This document specializes
> the value model of [value representation](05-value-representation.md) and the
> codegen of [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)
> to the single hottest data structure in the Nix language: the attribute set.
> It depends on the symbol interning and memory model introduced in
> [memory management and GC](06-memory-management-and-gc.md), feeds the
> derivation path in [derivation and store compatibility](11-derivation-and-store-compatibility.md),
> and its content-addressed hashing feeds [incremental evaluation cache](12-incremental-evaluation-cache.md).

## 1. Why attribute sets deserve their own document

Nix is, structurally, a language of attribute sets. The package set is one
gigantic recursive attribute set; every derivation is an attribute set; every
module-system fixpoint is an attribute set of attribute sets; `stdenv`,
`lib`, `pkgs`, and the `mkDerivation` argument convention all manifest as
attribute-set construction, attribute selection, and the update operator `//`.
A profile of any real Nix evaluation over nixpkgs or the AOS package set shows
the same three operations dominating the dynamic instruction count:

| Operation                  | Nix surface syntax        | Hot because                                              |
|----------------------------|---------------------------|---------------------------------------------------------|
| Attribute selection        | `a.b.c`, `a.b or d`       | Every `pkgs.foo`, every `stdenv.mkDerivation`, every `lib.x` |
| Attribute-set construction | `{ a = ...; b = ...; }`   | Every derivation argument, every module result          |
| Update / merge             | `a // b`                  | Every override, every `mkDerivation` arg-default merge, every module overlay |

These operations are executed billions of times across a full nixpkgs/AOS
evaluation, against attribute sets whose *shapes* (key sets and key orders) are
overwhelmingly repetitive: every `mkDerivation` call site produces argument
sets drawn from the same small vocabulary of keys (`pname`, `version`, `src`,
`buildInputs`, `nativeBuildInputs`, `phases`, ...), and every derivation
`outputs` attrset is one of a handful of shapes. This is *exactly* the
statistical regime that the object-oriented VM literature was built to exploit,
and the central thesis of this document is that Nix is a far better target for
those techniques than the languages they were invented for, because Nix
attribute sets are **immutable**.

In V8, a hidden class can be invalidated when a property is added, deleted, or
its type changes; the machinery exists in large part to *detect and recover
from* mutation. In Nix there is no mutation. An attribute set, once
constructed, is frozen forever. A shape, once assigned, is correct forever.
Inline caches never need an invalidation protocol against writes, only against
the legitimately different shapes that flow to a polymorphic site. The same
purity that makes the incremental cache of
[incremental evaluation cache](12-incremental-evaluation-cache.md) sound makes
hidden classes and inline caches *more* effective here than in the JavaScript
engines that originated them.

This document specifies four interlocking mechanisms:

1. **Symbol interning** — attribute names become `u32` symbols (§3).
2. **Hidden classes / shapes** — the identity, key set, and layout of an
   attribute set are factored out of the instance into a shared, interned
   descriptor reached through a transition tree (§4).
3. **Inline caches** — per-select-site cache cells that memoize a
   `shape -> offset` resolution and erase the dictionary lookup on the hot path
   (§5).
4. **Representation of `//`** — shape-transition + flat copy for small sets, a
   HAMT (hash array mapped trie) persistent map for large/override-heavy sets,
   chosen by a measured policy (§6).

Throughout, **deterministic, C++-Nix-identical iteration order** is a hard
correctness constraint (§7), not an optimization knob, because it is observable
through `builtins.attrNames`, `builtins.attrValues`, `builtins.mapAttrs`,
`derivationStrict`'s env construction, and therefore the bytes of the produced
`.drv`. Getting the layout fast but the order wrong produces a different store
path, a total cache miss, and a from-source toolchain rebuild — the
catastrophic outcome the entire RFC is organized to prevent
(see [compatibility constraints](02-compatibility-constraints.md)).

## 2. Baseline: how C++ Nix represents attribute sets, and what it costs

C++ Nix represents an attribute set (`Bindings`) as a flat, contiguous array of
`Attr { Symbol name; Value* value; PosIdx pos; }`, kept **sorted by symbol id**,
constructed via a `BindingsBuilder` that allocates the array at known size and
then sorts. Attribute names are interned to `Symbol` (a small integer) in a
global `SymbolTable`. Selection (`a.b`) is a binary search over the sorted
array by symbol id. The update operator `a // b` allocates a fresh array sized
`|a| + |b|` and merges.

This is already a good design — it is why C++ Nix is the fast baseline we must
*beat*, not the slow one we condescend to (cf. hnix, the Haskell evaluator,
which is notoriously slow and is a cautionary data point, not a target). But it
leaves three classes of value on the table:

1. **The key array is paid per instance.** Ten thousand `mkDerivation`
   argument sets with the same keys store ten thousand copies of the
   `[pname, version, src, ...]` symbol vector interleaved with their values.
   The keys are pure redundancy: they are determined by the construction site,
   not the instance.
2. **Selection is `O(log n)` *every time*, with no site-level memoization.**
   `pkgs.hello` re-runs the binary search on every evaluation of that
   expression. The search result — "in a set of this shape, `hello` lives at
   offset *k*" — is stable across all sets of that shape but is recomputed from
   scratch.
3. **`//` is always a full flat copy.** For module-system overlays and
   `overrideAttrs` chains, where a tiny override is applied to a large set, the
   `O(|a| + |b|)` copy dominates, and the large base set is copied wholesale on
   every overlay layer.

Hidden classes attack (1) and (2); the HAMT representation attacks (3). Neither
is novel; both are table stakes in the JS-engine world. The contribution of
this RFC is the observation that Nix immutability + whole-program batch
evaluation makes them *unconditionally* sound and lets us drop the invalidation
machinery the originals carry.

## 3. Symbol interning: attribute names are `u32`

Before any shape machinery, attribute names must be interned. This is table
stakes shared with C++ Nix.

A global, append-only `SymbolTable` maps each distinct attribute-name string to
a dense `u32` `Symbol`. Interning happens once, at parse time, in the frontend
(see [frontend, parser, and IR](04-frontend-parser-and-ir.md)); the parsed-IR
cache stores symbols, so a file parsed once never re-interns its keys. After
interning:

- Attribute-name equality is `u32` equality, not string comparison.
- A shape's key set is a vector of `Symbol`, cheaply hashable and comparable.
- The original spelling is recoverable for diagnostics and, critically, for
  the lexicographic ordering that compatibility requires (§7) — the table
  retains the string, and we precompute each symbol's **sort rank** so that
  ordering by spelling reduces to an integer compare on a cached rank (§7.3).

```rust
/// An interned attribute name. Dense, process-global, assigned at parse time.
///
/// Equality and hashing are integer operations. The original UTF-8 spelling
/// and a precomputed lexicographic sort rank are recoverable through the
/// [`SymbolTable`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Symbol(u32);

/// Interns attribute-name strings to dense [`Symbol`] ids.
///
/// Append-only and never freed during a process lifetime: in the one-shot
/// CLI tier the table dies with the arena at exit; in the daemon tier it is a
/// permanent, shared, read-mostly structure (see
/// [memory management and GC](06-memory-management-and-gc.md)).
pub struct SymbolTable { /* string interner + sort-rank index */ }
```

The interner is one of the immutable tables shared *unsynchronized* across
parallel evaluation workers (see [parallel evaluation](13-parallel-evaluation.md)):
because it is append-only and a symbol's meaning never changes once assigned,
readers need no lock, and the rare append path uses a short critical section or
a lock-free append structure.

## 4. Hidden classes (shapes) and the transition tree

### 4.1 The factoring

A **hidden class** (V8's term, and the primary term in this RFC) — called a
*map* in the original Self work (Chambers, Ungar & Lee, 1989) and a *shape* or
*structure* in V8 — is the descriptor that an attribute set's instance points to
instead of carrying its own keys. We use **hidden class** as the canonical
concept name and **shape** interchangeably as its short alias (and as the
`Shape` type name in code), the two denoting one thing.

```text
  Without shapes (C++ Nix Bindings):          With shapes (aos-nix):

  AttrSet instance                            AttrSet instance
  ┌───────────────────────────┐               ┌─────────────┐
  │ [ (sym pname, v0)         │               │ shape ──────┼──► Shape (shared)
  │   (sym src,   v1)         │               │ values: [   │    ┌──────────────────┐
  │   (sym version, v2) ] ... │               │   v0,       │    │ keys: [pname,    │
  └───────────────────────────┘               │   v1,       │    │        src,      │
   keys stored per instance                    │   v2 ]      │    │        version]  │
                                               └─────────────┘    │ offset map:      │
                                                values only;      │  pname->0        │
                                                keys shared       │  src->1          │
                                                                  │  version->2      │
                                                                  └──────────────────┘
```

A `Shape` owns:

- the **ordered key vector** (`Vec<Symbol>`) in *insertion order* — the order
  in which the construction site introduced the bindings; this is the storage
  order of the parallel `values` array;
- a **symbol → slot-offset map** for selection;
- a precomputed **iteration order** (the lexicographic permutation of the
  slots, §7) so that `attrNames`/`attrValues`/`derivationStrict` are a cached
  table walk, not a per-call sort;
- a content **fingerprint** (xxh3 of the key vector) used to deduplicate shapes
  and to hash values for the incremental cache.

An instance is then just `{ shape: &Shape, values: [Value; n] }` — a pointer
plus a flat value array. The keys, the offset map, and the iteration order are
all amortized across every set that shares the shape. For the AOS package set,
where thousands of derivation argument sets share the same handful of shapes,
this is a large constant-factor reduction in allocation volume and a
prerequisite for the inline caches of §5.

### 4.2 The transition tree

Shapes are produced not ad hoc but by walking a **transition tree** rooted at
the empty shape, exactly as V8 builds hidden classes by recording, for each
shape, the transition "add key *k*" → resulting shape. Two attribute sets
constructed by adding the same keys in the same order arrive at the *same*
`Shape` object, so shape identity is pointer identity, and `shape_a == shape_b`
is one pointer compare.

```text
                      ┌─────────────┐
                      │  empty {}   │
                      └──────┬──────┘
                 +pname      │            +x
            ┌────────────────┴───────────────┐
            ▼                                 ▼
      ┌───────────┐                     ┌───────────┐
      │ {pname}   │                     │ {x}       │
      └─────┬─────┘                     └─────┬─────┘
       +version                          +y   │
            ▼                                  ▼
      ┌──────────────┐                  ┌───────────┐
      │ {pname,      │  +src            │ {x,y}     │
      │  version}    ├────────┐         └───────────┘
      └──────────────┘        ▼
                        ┌──────────────────┐
                        │ {pname,version,  │
                        │  src}            │  ◄── the dominant mkDerivation shape
                        └──────────────────┘
```

Transition edges are cached on the parent shape in a small map
`Symbol -> &Shape`. The first construction of a given key sequence pays to
create the shapes; every subsequent construction with the same key sequence
walks existing edges and allocates only the value array. For a Nix
construction site — a *static* `{ ... }` literal in the AST — the key sequence
is fixed at compile time, so the entire shape is resolved **once per site, at
compile time**, and the runtime path for that site is "allocate a values array
of known size, fill it, attach the precomputed shape pointer." There is no
per-instance shape lookup at all for static attrsets; the transition tree is
exercised at runtime only by dynamic construction (`builtins.listToAttrs`,
computed keys `${e}`, and `//` results — §6).

### 4.3 Interaction with hash-consing

[Value representation](05-value-representation.md) specifies hash-consing
(maximal sharing) of immutable values. Shapes compose with it on two levels.
First, shapes themselves are interned by fingerprint: structurally identical
key vectors yield one `Shape`. Second, two *instances* that share a shape and
whose value arrays are pointerwise equal (after their elements are
hash-consed) are themselves candidates for hash-consing into a single
attribute-set value — which is common, because identical derivation argument
sets recur constantly across the package set. Shape identity reduces the
instance-equality check that hash-consing needs to "same shape pointer, then
elementwise pointer compare of the value array," which is cheap. This is the
mechanism by which "the identical `stdenv` flowing into thousands of
derivations is one heap object" is realized.

### 4.4 Why static typing is unnecessary and immutability is decisive

V8 must contend with property addition, deletion, and `[[Prototype]]` changes,
each of which mutates or invalidates a hidden class and forces deopt of code
specialized to it; "monomorphic" call sites silently degrade to
"megamorphic" when real-world objects drift. The entire literature on
*profile-guided offline optimization of hidden-class graphs* exists to fight
this drift. None of it applies to Nix. A Nix attribute set is constructed once
and never gains, loses, or retypes a binding. The shape assigned at
construction is the shape forever. The only source of polymorphism at a select
site is genuine: different *sets* of different *shapes* flowing to the same
`a.b` expression (e.g. a `lib` function selecting `.name` from heterogeneous
arguments). That polymorphism is bounded and handled by the inline-cache states
of §5 — but it is never spurious, and there is no write barrier and no shape
invalidation protocol. This is the concrete payoff of the synthesis thesis: a
technique that is partial and defensive in its birthplace becomes total and
offensive in Nix.

## 5. Inline caches on selection sites

### 5.1 The mechanism

An attribute selection `a.b` compiles, at every tier above the tree-walk
oracle, to a site that carries an **inline cache (IC)**: a small mutable cache
cell, embedded at (or beside) the call site, that memoizes the last
shape→offset resolution. The classic state machine (Hölzle, Chambers & Ungar,
1991, "Optimizing Dynamically-Typed Object-Oriented Languages with Polymorphic
Inline Caches", introduced for Self; adopted by HotSpot and V8) is:

```text
  Uninitialized ──first hit──► Monomorphic ──new shape──► Polymorphic ──overflow──► Megamorphic
        │                          │  (cache 1 shape)        │  (cache ≤N shapes)       │
        │                          │                         │                          │
   slow path:                 fast path:                fast path:                 slow path:
   resolve, fill cache        guard==shape?              linear guard chain         general lookup
                              load values[offset]        over N shapes              (binary search /
                                                                                     HAMT get)
```

- **Uninitialized**: first execution resolves `b` in `a`'s shape via the
  general path, then rewrites the cache cell to Monomorphic with that
  `(shape, offset)`.
- **Monomorphic**: the hot case. Guard: is `a.shape` the cached shape? If yes,
  load `a.values[offset]` — a guard compare plus a constant-offset load, no
  search. This is the entire point.
- **Polymorphic**: a second distinct shape arrives; the cache holds a small
  linear list of `(shape, offset)` pairs (V8 caps the polymorphic chain at 4
  before going megamorphic; we make the cap a tunable `N`, default 4). The
  guard chain is a short, branch-predictor-friendly sequence of compares.
- **Megamorphic**: more than `N` shapes; the site abandons specialization and
  calls the general resolver (`select_slow`), which does a binary search over
  the sorted key view (or a HAMT `get` for HAMT-backed sets, §6).

The IC is read and written by compiled Cranelift code through the uniform
runtime ABI: a `select_ic` runtime symbol (and an inlined fast-path guard
emitted directly by the baseline/optimized tiers) — see
[primops and runtime ABI](10-primops-and-runtime-abi.md) for the symbol table
and [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) for
how guards and deopt edges are emitted.

```rust
/// A polymorphic inline cache attached to one attribute-selection site.
///
/// Memoizes `shape -> slot offset` resolutions. States progress monotonically
/// `Uninitialized -> Monomorphic -> Polymorphic -> Megamorphic`; because Nix
/// attribute sets are immutable, an entry never needs invalidation, only
/// extension when a genuinely new shape reaches the site.
pub enum InlineCache {
    Uninitialized,
    /// One cached shape; the hot, branch-free-after-guard case.
    Monomorphic { shape: ShapeId, offset: u32 },
    /// Up to `N` cached shapes, checked by a short linear guard chain.
    Polymorphic { entries: SmallVec<[(ShapeId, u32); 4]> },
    /// Too many shapes seen; defer to the general resolver every time.
    Megamorphic,
}
```

### 5.2 What the baseline tier emits

For a monomorphic site the optimized tier emits, in CLIF-level terms, roughly:

```text
  ;; a.b  with IC cached as (shape=S, offset=k)
  v_shape   = load.i64 a+SHAPE_OFFSET          ; load instance shape ptr
  v_guard   = icmp eq v_shape, S               ; guard against cached shape
  brif      v_guard, fast, slow

fast:
  v_vals    = load.i64 a+VALUES_OFFSET
  v_result  = load.i64 v_vals + k*8            ; constant-offset slot load
  jump cont(v_result)

slow:
  v_result  = call select_ic(rt, a, sym_b, &ic_cell)  ; resolve + update IC, may transition state
  jump cont(v_result)

cont(v_phi):
  ...
```

The `slow` block is also the **deoptimization / uncommon-trap** edge: if the
optimized tier *speculated* monomorphism (because the site was monomorphic
during profiling), the guard failure can trigger an uncommon trap back to a
less-specialized tier rather than merely a slow-path call, per the HotSpot
deopt model described in
[execution tiers and Cranelift](08-execution-tiers-and-cranelift.md). The
choice between "slow-path call that widens the IC" and "deopt" is a tier
policy; the baseline tier always widens, the optimized tier may deopt when it
has burned the monomorphic assumption into surrounding code.

### 5.3 The tree-walk oracle still has ICs (optionally)

The tier-0 tree-walking interpreter — the correctness oracle — can carry a
*degenerate* IC on each AST select node (a single `Cell<Option<(ShapeId,
u32)>>`), giving it the monomorphic fast path without any JIT. This is cheap,
keeps the oracle from being pathologically slow on shape-stable code, and means
the IC abstraction is exercised and tested on the safe, miri-clean tree (the
unsafe JIT path reuses the same resolution logic). It is *optional* in the
sense that the oracle remains correct with ICs disabled, which is the
configuration used to cross-check IC behavior in differential testing
(see [differential testing and benchmarking](15-differential-testing-and-benchmarking.md)).

### 5.4 Why Nix sites are predominantly monomorphic

Empirically (to be confirmed by the measure-first instrumentation of §8, not
assumed), the dominant Nix select sites are monomorphic or low-polymorphic:

- `pkgs.<name>` selects from one giant fixed-shape set (the package set
  fixpoint) — monomorphic in the shape of `pkgs`.
- `stdenv.mkDerivation` / `lib.<fn>` select from one fixed shape — monomorphic.
- `drv.outputs`, `drv.drvPath`, `drv.outPath` select from the derivation shape —
  monomorphic.
- Generic library combinators (`x.name`, `x.value` in `mapAttrs'`/`listToAttrs`
  helpers) are the polymorphic minority, and bounded.

If §8 measurement contradicts this, the IC cap `N` and the megamorphic policy
are the tuning surface, and the tree-walk oracle remains the fallback. The
design does not *depend* on monomorphism for correctness — only for speed.

## 6. The update operator `//`: shape-transition, flat copy, and HAMT

`a // b` is right-biased set union: the result has all keys of `a` and `b`,
with `b`'s values winning on collision. It is the heart of override-heavy Nix
(module system, `overrideAttrs`, argument-default merging). Its cost profile is
bimodal, and so is our representation, chosen by a measured policy rather than a
single universal structure.

### 6.1 Small / shape-stable case: transition + flat copy

When both operands are small and the *result shape* is statically predictable
(common for literal `a // { onekey = v; }` overlays), the result is a flat
shaped instance:

- Compute the result key set = `keys(a) ∪ keys(b)`, preserving **a's order for
  shared keys and a-then-new-b order overall** to match C++ Nix iteration
  semantics (§7). Resolve it through the transition tree to a `Shape` (cached
  after first encounter, so repeated overlays of the same shapes are free shape
  lookups).
- Allocate one value array; fill from `a`, then overwrite/append from `b`.
- Result is `O(|a| + |b|)` in time and space.

This is exactly C++ Nix's strategy and is optimal when sets are small and
copies are cheap. For the long tail of `mkDerivation`'s internal
`{ ...defaults } // args` merges over modest sets, this is the right answer and
we keep it.

### 6.2 Large / override-heavy case: HAMT persistent map

When `a` is large and `b` is small — the module-system overlay and
`overrideAttrs`-chain regime, where a 200-key set receives a 2-key override,
and then *another* 2-key override, and so on for many layers — the flat-copy
strategy is quadratic in the number of layers: each layer copies the entire
base. The functional-programming answer is a **persistent immutable map with
structural sharing**: a **HAMT** (hash array mapped trie), invented by Phil
Bagwell in 2001 ("Ideal Hash Trees", EPFL), and used as the backbone of
Clojure's and Scala's persistent maps.

A HAMT navigates by consuming the key's hash in chunks (classically 5 bits per
level, giving 32-way branching, `O(log₃₂ n)` ≈ effectively `O(1)` for realistic
sizes). The decisive property for `//` is **structural sharing**: producing
`a // b` from a HAMT-backed `a` allocates only the trie nodes on the paths to
`b`'s keys (and their parents), sharing every untouched subtree with `a`. An
overlay of *k* keys over an *n*-key set costs `O(k · log₃₂ n)` time and space,
not `O(n)`, and a chain of *m* such overlays costs `O(m · k · log₃₂ n)` rather
than `O(m · n)`. The large base is never copied; it is pointed at.

```text
  a (HAMT, n keys)            a // {x=v2}  shares all of a except the path to x

        root                          root'                root  (still live, immutable)
       /  | \                        /  | \\               /  | \
      A   B  C   ◄──── shared ────►  A   B  C'   …          A   B  C
         /|\                                /|\
        … x=v1 …                           … x=v2 …   (only this path is fresh)
```

Because Nix values are immutable, the persistent-map invariant (old versions
remain valid and unchanged) is free — there are no defensive copies, no
freezing, no copy-on-write bookkeeping beyond the trie's own node sharing. This
is the same immutability dividend that recurs throughout RFC-0007.

For modern engineering we follow the CHAMP refinements (Steindorfer & Vinju,
"Optimizing Hash-Array Mapped Tries for Fast and Lean Immutable JVM
Collections", OOPSLA 2015), which improve cache locality and memory footprint
over the textbook HAMT by separating inline data from sub-node references and
canonicalizing node layout — relevant because our hot loop is memory-bound and
the GC of [memory management and GC](06-memory-management-and-gc.md) benefits
from compact, pointer-dense nodes.

### 6.3 The policy and the unified value view

```rust
/// Backing representation of an attribute set, selected by size and update
/// history. Both variants present the same immutable, ordered, shaped view to
/// the rest of the evaluator.
pub enum AttrSetRepr {
    /// Shape pointer + flat value array. Cache-friendly; ideal for small,
    /// shape-stable sets and the dominant static-literal case.
    Flat { shape: ShapeId, values: Box<[Value]> },
    /// Persistent HAMT (CHAMP layout) for large / override-heavy sets;
    /// `//` shares structure instead of copying the base.
    Hamt { root: HamtRef, len: u32, /* order index, see §7 */ },
}
```

The promotion policy (thresholds to be calibrated by §8 measurement, never
guessed):

1. Static literals and small `//` results below a size threshold → `Flat`.
2. A set crossing a size threshold, or the result of `//` whose left operand is
   already `Hamt`, or a set observed to be a base in a deepening override chain
   → `Hamt`.
3. `attrNames`/`attrValues`/`derivationStrict` consume either variant through
   the same ordered-iteration interface (§7), so the representation choice is
   *invisible to compatibility* — only performance, never the produced bytes,
   depends on it.

This invisibility is the load-bearing claim: **the choice between `Flat` and
`Hamt` must never change a `.drv` byte.** It changes only allocation and copy
cost. The differential harness validates this by exercising both
representations against `nix-instantiate` (§8, and
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md)).

### 6.4 Interaction with inline caches

ICs cache `shape → offset`, which presupposes a `Flat` instance with a stable
slot layout. A `Hamt` instance has no flat slot vector, so a select site that
encounters a `Hamt` value treats it as a non-cacheable shape: the IC either
records a distinguished "HAMT" entry whose fast path is a HAMT `get` keyed on
the interned symbol, or — if HAMT values are rare at that site — counts toward
the megamorphic threshold. Because the override-heavy sets that become HAMTs
(module fixpoints) are selected from through a small number of stable site
patterns, this is expected to be benign; §8 measures it. The general resolver
`select_slow` dispatches on representation, so correctness never depends on the
IC understanding HAMTs.

## 7. Iteration order: the hard compatibility constraint

### 7.1 Two distinct orders

Nix attribute sets carry **two** distinct orders, and conflating them is a
classic source of `.drv` divergence:

1. **Insertion / storage order** — the order keys were written at the
   construction site. This is *not* observable through the standard builtins
   (all of which present name-sorted output), but it is the natural storage
   order of a `Flat` instance and matters for internal consistency.
2. **Lexicographic order by attribute-name spelling** — the order in which
   `builtins.attrNames`, `builtins.attrValues`, `builtins.mapAttrs`, the `?`/
   `//` semantics, and — decisively — `derivationStrict`'s environment
   construction enumerate attributes. C++ Nix keeps `Bindings` *sorted by
   symbol id*, but `attrNames` is documented and observed to return names
   **alphabetically sorted by their string spelling** (e.g.
   `builtins.attrNames { y = 1; x = "foo"; }` → `[ "x" "y" ]`). The values
   returned by `attrValues` follow the same sorted-name order.

The bytes of a `.drv` depend on the lexicographic order, because
`derivationStrict` walks the derivation attribute set in name order to build
the environment and the ATerm serialization
(see [derivation and store compatibility](11-derivation-and-store-compatibility.md)).
**Any deviation in this order changes the `.drv` bytes, the output hash, the
store path, and triggers a full rebuild.** This is non-negotiable and is the
single most important correctness property in this document.

### 7.2 The subtlety: symbol-id order vs. spelling order

C++ Nix sorts `Bindings` by `Symbol` id, and symbol ids are assigned in
*interning order* (first-seen order), which is **not** lexicographic. So how is
`attrNames` lexicographic? Because the operations that must present sorted
output (`attrNames`, `attrValues`, the comparison and serialization paths) sort
*by name spelling* at the point of observation, while the internal `Bindings`
array is kept in symbol-id order for fast symbol-keyed lookup. aos-nix must
reproduce the **observable** lexicographic ordering exactly, regardless of how
it stores keys internally. We therefore decouple:

- **Storage order**: whatever is fastest for the representation (insertion
  order for `Flat`, hash order for `Hamt`). Internal only.
- **Observable order**: lexicographic by attribute-name spelling, computed
  identically to C++ Nix and cached on the `Shape`.

The exact collation must match byte-for-byte. C++ Nix compares symbol *strings*
with the equivalent of a C `std::string` / `strcmp` ordering over the raw bytes
(a plain unsigned-byte lexicographic compare, not locale- or
Unicode-collation-aware). aos-nix uses raw `&[u8]` ordering on the interned
spelling. This must be validated against the conformance suite and the
differential harness; locale-sensitive or codepoint-vs-byte differences are a
known landmine and are called out as an explicit verification item, not assumed
correct.

> **Open question (O-1).** Whether *any* AOS or nixpkgs attribute name contains
> multibyte UTF-8 such that byte-order and codepoint-order diverge, and whether
> C++ Nix's comparator is byte-order in all relevant versions. The safe
> implementation is raw-byte `Ord`; the harness must include adversarial
> non-ASCII key cases to confirm parity. Until confirmed, this is research-grade
> and gated behind the harness.

### 7.3 Implementation: cached sort permutation on the shape

Sorting attribute names on every `attrNames`/`derivationStrict` call would be
`O(n log n)` per call, repeated billions of times. Instead, the **lexicographic
permutation is computed once per shape and cached on it**:

- At shape creation, compute `order: Vec<u32>` = the permutation of storage
  slots that yields lexicographic name order. Since every `Flat` instance of a
  shape shares the shape, every such instance gets sorted iteration via one
  shared permutation table and zero per-instance work.
- Additionally precompute, per interned `Symbol`, a **sort rank** in the
  symbol table so that comparing two symbols by spelling is an integer compare
  on cached ranks rather than a byte comparison — turning the shape's
  permutation computation and any residual dynamic sorting into integer sorts.
  The rank index is updated as symbols are interned; because interning is
  monotonic and the spelling is fixed, a symbol's spelling-rank *relative to all
  symbols interned so far* is stable enough to compute the permutation lazily at
  first observation and memoize it. (The rank table is a sorted view over the
  symbol spellings, rebuilt incrementally; details in
  [frontend, parser, and IR](04-frontend-parser-and-ir.md).)

```rust
impl Shape {
    /// Returns the slot indices of this shape in lexicographic
    /// attribute-name order, matching C++ Nix's observable ordering for
    /// `attrNames` / `attrValues` / `derivationStrict`.
    ///
    /// Computed once per shape and cached; all instances share the result.
    pub fn iteration_order(&self) -> &[u32] { /* memoized lexicographic permutation */ }
}
```

For `Hamt` instances, which have no flat slot vector, the ordered view is
produced by collecting the trie's keys and sorting them by cached symbol rank,
memoized alongside the HAMT root so a given immutable HAMT value sorts once.
Because HAMT-backed sets are the override-heavy minority and are typically
enumerated far less often than they are selected from, this is acceptable; §8
measures whether an order-indexed HAMT variant is warranted.

### 7.4 `derivationStrict` is the acceptance-critical consumer

`builtins.derivationStrict` collects the derivation's attribute set into a
string-valued environment **in deterministic (lexicographic) attribute order**,
then hands it to the nix-compat `Derivation` builder for ATerm serialization
and SHA-256 input-/content-addressed output-path hashing
(see [derivation and store compatibility](11-derivation-and-store-compatibility.md)).
The ordering produced by §7.3 is *the* input to this path. The acceptance gate
(the `.drv`-diff harness) is, in effect, a continuous end-to-end test of this
section. We therefore treat §7 as the highest-risk part of the attribute-set
subsystem and over-test it: every shape's `iteration_order` is cross-checked
against the sorted spelling on the tree-walk oracle, and the harness diffs
real derivation envs against `nix-instantiate` byte-for-byte.

## 8. Measure-first, validation, and tuning surface

Per the measure-first discipline of [motivation and goals](01-motivation-and-goals.md),
none of the thresholds, caps, or representation choices here are committed on
intuition. The instrumentation plan:

- **Shape census.** Over a full AOS package-set evaluation, count distinct
  shapes, instances per shape, and the shape-multiplicity distribution. This
  validates (or refutes) the "few shapes, many instances" assumption that
  justifies the whole subsystem. Compare against `NIX_SHOW_STATS` counters from
  C++ Nix (values, thunks, function calls) as a sanity cross-check.
- **IC state histogram.** Per select site, record the terminal IC state
  (mono/poly/mega) and the hit rate of the monomorphic fast path. If
  megamorphic sites dominate, the IC is not paying for itself and the policy or
  `N` must change.
- **`//` size and chain-depth distribution.** Measure operand sizes and
  override-chain depths to calibrate the `Flat`↔`Hamt` threshold. The HAMT is
  only justified where deep chains over large bases actually occur; if they do
  not, `Hamt` may remain behind the measured policy (consistent with
  the ranked build sequence in [roadmap and risks](17-roadmap-and-risks.md),
  where hidden classes + PIC precede HAMT and the deeper JIT work).
- **Order parity.** The differential `.drv`-diff harness against
  `nix-instantiate` over the whole AOS closure is the acceptance gate; a single
  byte of `.drv` divergence attributable to attribute order fails the gate and
  blocks default-on, exactly as specified in
  [compatibility constraints](02-compatibility-constraints.md).

Current precursor: `ratchet-value::attrs::telemetry` provides an in-process,
byte-neutral accumulator for shape census rows, representation-dispatching
slow-select hit/miss outcomes by backing representation, IC terminal-state and
lookup histograms, `//` operand-size/result-length-upper-bound/chain-depth
histograms, HAMT merge insert/replace counts, and order-parity check outcomes.
The active tree-walk evaluator feeds it from slow-select outcomes by
representation, flat/shaped/HAMT select-cache lookup outcomes, static and dynamic
attrset-node representation decisions, selected builtin result representation
decisions, and successful `//` update merges with syntactic update-chain depth,
but native shape/PIC/HAMT runtime hooks remain open; it does not
collect full AOS package-set data and does not replace the `.drv` differential
acceptance gate.

The tuning surface exposed by this subsystem is therefore: the polymorphic cap
`N`; the `Flat`→`Hamt` size threshold and chain-depth trigger; whether the
tree-walk oracle carries degenerate ICs; and the HAMT node layout
(textbook HAMT vs. CHAMP). All are runtime/config choices that **cannot** alter
produced bytes, only speed — a property the harness enforces.

## 9. Relationship to the rest of RFC-0007

- **Builds on** [value representation](05-value-representation.md): an
  attribute-set value is a tagged value whose payload is an `AttrSetRepr`;
  shape identity feeds hash-consing and the WHNF/tagging discipline.
- **Builds on** [memory management and GC](06-memory-management-and-gc.md):
  shapes, the symbol/rank tables, and the transition tree are long-lived,
  read-mostly, shared structures; value arrays and HAMT nodes are GC-managed
  (bump-arena in one-shot mode, precise generational in daemon mode), and
  HAMT's pointer-dense nodes want the precise collector to avoid Boehm-style
  false retention.
- **Compiled by** [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md):
  IC guards, slot loads, and the slow-path/deopt edges are emitted by the
  baseline and optimized tiers; `select_ic`/`select_slow`/`alloc` are runtime
  symbols.
- **Dispatches through** [primops and runtime ABI](10-primops-and-runtime-abi.md):
  the select/update/alloc runtime symbols and their uniform
  `extern "C" fn(*Runtime, ...) -> Value` ABI.
- **Feeds** [derivation and store compatibility](11-derivation-and-store-compatibility.md):
  the lexicographic iteration order is the input to `derivationStrict` and
  thence to the `.drv` bytes — the acceptance-critical path.
- **Feeds** [incremental evaluation cache](12-incremental-evaluation-cache.md):
  shape fingerprints and hash-consed instances give cheap, stable value-hashes
  for early-cutoff memoization (xxh3 in-process, blake3 for the durable shared
  cache; SHA-256 reserved strictly for Nix-observed store/derivation hashes).
- **Shared by** [parallel evaluation](13-parallel-evaluation.md): the shape,
  transition, symbol, and rank tables are immutable/append-only and shared
  across forcing workers without locks.

## 10. Summary of decisions

| Decision | Choice | Primary source | Why it is *more* effective in Nix |
|----------|--------|----------------|-----------------------------------|
| Attribute names | Intern to `u32` `Symbol` | C++ Nix, universal | Append-only + immutable ⇒ lock-free shared table |
| Per-instance keys | Factor into shared `Shape` via transition tree | Self maps; V8 hidden classes | Sets never mutate ⇒ shape is permanent, no invalidation |
| Selection `a.b` | Polymorphic inline cache (mono→poly→mega, cap `N`=4) | Self PICs (Hölzle et al. 1991); V8/HotSpot | Polymorphism is never spurious; no write barrier |
| Small / static `//` | Shape-transition + flat copy | C++ Nix | Optimal for the small-set majority |
| Large / override-heavy `//` | HAMT/CHAMP persistent map, structural sharing | Bagwell 2001; Clojure; Steindorfer & Vinju 2015 | Immutability makes persistence free; overlays don't copy the base |
| Iteration order | Lexicographic-by-spelling, cached permutation per shape | C++ Nix observable semantics | Hard correctness constraint, not an optimization |
| Representation choice | Measured `Flat`↔`Hamt` policy; invisible to `.drv` bytes | measure-first discipline | Speed-only; never alters produced bytes |

Open questions: **O-1** (byte- vs codepoint-collation of attribute names —
§7.2); the `Flat`↔`Hamt` thresholds and whether `Hamt` ships in the first cut
at all (§8, deferred to measurement); whether HAMT-valued select sites need a
dedicated IC entry kind or fold into megamorphic (§6.4). All are gated behind
the differential harness and resolved by measurement, never by assumption.

## Implementation checklist

Per-feature tracker for attribute sets — hidden classes, inline caches, HAMT
overlays, and iteration-order compatibility; master roll-up:
[implementation checklist (all phases)](22-implementation-checklist-all-phases.md).
Per the unlimited-budget mandate, every item here is in scope — including
research-grade ones — built in dependency order and gated by the differential
harness, never cut for scope.

### Symbol interning (foundation)

- [x] Current dense-symbol substrate: file-local or explicitly threaded
      `SymbolTable`s intern attribute names and other symbol-bearing frontend
      bytes to dense `u32` `Symbol`s, retain the original byte spelling through
      `resolve`, and flow through parsed AST, resolved AST, IR, and the
      tree-walk evaluator. Runtime-created/dynamic attr keys are interned into
      the active evaluator symbol table, cached import IR remaps file-local
      symbols into that active table, and `FlatAttrs` consumes the same symbol
      universe for symbol-id lookup while computing observable lexicographic
      order from retained bytes. The table also exposes a process-local current
      raw-byte lexicographic rank for each interned symbol, used by the current
      flat/shaped/HAMT ordering precursors. This does not claim a global/shared
      table, lock-free reads, durable ranks, or process-wide shape/HAMT table
      integration ([§3](#3-symbol-interning-attribute-names-are-u32)) — P1/P5
      current substrate, `S-10`; gate: conformance 20-21.
- [ ] Global append-only/shared `SymbolTable` with cached lexicographic sort
      ranks and integration with future process-wide shape/HAMT tables remains
      open; parallel read behavior is tracked by the next row ([§3](#3-symbol-interning-attribute-names-are-u32)) — P1/P5, `S-10`; gate: conformance 20-21.
- [ ] Lock-free / unsynchronized shared read access for parallel forcing workers (append-only ⇒ no reader lock) ([§3](#3-symbol-interning-attribute-names-are-u32), [13](13-parallel-evaluation.md)) — P3.5, `C-12`; gate: loom.

### Hidden classes (shapes) and the transition tree

- [ ] `Shape` descriptor: ordered key vector, symbol → slot-offset map, cached iteration order, xxh3 key-vector fingerprint ([§4.1](#41-the-factoring)) — P5, `S-10`.
- [x] Current shape descriptor precursor: `ratchet-value::attrs::shape`
      exposes a safe `AttrShape` descriptor with symbol-sorted key vector,
      binary-search slot lookup, construction-order permutation, rank-sorted
      raw-byte lexicographic iteration permutation, shape-local inverse
      lexicographic rank table, and in-process xxh3 key-vector fingerprint. The
      descriptor alone does not install a global/shared shape table, inline
      cache, HAMT representation, or runtime fast path.
- [ ] Instance layout `{ shape: &Shape, values: [Value; n] }` (pointer + flat value array) ([§4.1](#41-the-factoring)) — P5.
- [x] Current shaped-instance precursor: `ratchet-value::attrs::shape`
      exposes `ShapedAttrs`, a safe `{ ShapeHandle, values_by_symbol }`
      instance that validates value counts, stores values in the shape's
      symbol-slot order, and iterates through the shape's source and
      lexicographic permutations. This does not carry source-position metadata,
      allocate evaluator heap objects, replace `FlatAttrs`, or affect active
      evaluation / `.drv` bytes.
- [x] Current heap-resident shaped record layout (`AOS_NIX_SHAPES=record`,
      knob-gated; the measured default is `off` — a fresh-process instruction
      comparison over all nine compute workloads found that avoiding
      projection and transient shaped views saved about 0.4% in aggregate,
      including 4.4% on attr-fixpoint, 0.9% on lambda-interp, and 0.7% on
      hash-loop. The record mode's
      clean serial win on attr-fixpoint (cold/warm -7%/-11% vs the pre-round
      baseline, other benchmarks within noise) is offset by a small
      consistent `K = 4` loss on short package evals (zlib warm up to +20%),
      where the baseline disables projection entirely, so the default flips
      only when that multi-worker tax is paid down): active flat attr
      heap records store the projected `ShapeId` in their metadata at
      construction, and because `AttrShape` slots and `FlatAttrs` storage are
      both symbol-sorted, the flat entry array *is* the shaped slot layout —
      no shaped view is materialized after construction or per select. Under
      the record mode, every static `Select`/`HasAttr`/`WithVar`/
      runtime-callable IC segment guards on the projected id through
      `ratchet-value::attrs::pic::record::RecordSelectCache` (shape-id
      compare + constant-offset entry load + key recheck), static literal
      sites resolve their shape once per `(module, node)` site and reuse the
      interned handle (the §4.2 static-resolution contract realized as a
      first-allocation memo), and same-key-set `//` results keep the left
      operand's shape id. Mode-differential render tests (serial and
      parallel-pool) pin byte-identical output across `off`/`transient`/
      `record`. Native `aos_select_ic` lowering, a per-instance shaped value
      array replacing `FlatAttrs`, and default-on remain open.
- [ ] Transition tree rooted at the empty shape; `Symbol -> &Shape` edges cached on each parent; pointer-identity shape equality ([§4.2](#42-the-transition-tree)) — P5, `S-10`.
- [x] Current shape-transition precursor: `ratchet-value::attrs::shape`
      can locally plan a key insertion against an `AttrShape`. Existing keys
      return the current symbol-sorted slot; new keys append to construction
      order and produce a child descriptor with updated source/lexicographic
      permutations. This local descriptor API does not itself cache parent
      edges or claim pointer-identity shape equality; the process-local table
      precursor below provides that substrate without making it global/shared.
- [x] Current shape-table precursor: `ratchet-value::attrs::shape`
      exposes a process-local `ShapeTable` rooted at the empty shape, interns
      `AttrShape` descriptors behind pointer-identity handles, reuses
      fingerprint-filtered raw-equal shapes, and caches new-key transition edges
      on the parent record. The active tree-walk evaluator now projects
      successful flat attr heap allocations through a process-local shape table
      for shape-census telemetry, the mirrored uncached shape-transition
      counter, and per-heap-record projected shape metadata. Select/`WithVar`
      use is limited to the transient tree-walk bridge below; this is not a
      global/shared shape table, does not provide lock-free reads, and is not
      wired into shaped heap allocation, native storage, or `.drv`-observable
      behavior.
- [ ] Compile-time shape resolution for static `{ ... }` literals (no per-instance shape lookup; runtime just fills a values array) ([§4.2](#42-the-transition-tree)) — P5.
- [x] Current static-shape-plan precursor: `ratchet-value::attrs::shape`
      exposes `StaticShapePlan`, which resolves a static literal's
      construction-order keys through the process-local transition tree once,
      stores the final `ShapeHandle`, and records source-slot to symbol-slot
      placement for filling shaped value arrays. It is not wired into IR
      lowering, evaluator shaped-value allocation, select/runtime storage, or
      `.drv`-observable behavior.
- [ ] Shape interning by fingerprint + instance hash-consing (same shape + pointerwise-equal values collapse to one heap object) ([§4.3](#43-interaction-with-hash-consing)) — P5, `S-7`.
- [x] Current shaped hash-consing precursor: `ratchet-value::attrs::shape`
      exposes `ShapedAttrConsTable`, which buckets `ShapedAttrs` by an
      in-process shaped fingerprint and reuses only candidates confirmed by the
      same interned shape pointer plus raw `Value` equality. This returns
      `Arc<ShapedAttrs>` handles; it does not allocate evaluator heap attrs,
      replace `FlatAttrs`, or affect active evaluation / `.drv` bytes.

### Inline caches on selection sites

- [ ] `InlineCache` state machine `Uninitialized → Monomorphic → Polymorphic → Megamorphic`, cap `N` (default 4), no invalidation protocol (immutability) ([§5.1](#51-the-mechanism)) — P5, `S-10`; gate: differential `.drv` harness.
- [x] Current inline-cache state-machine precursor:
      `ratchet-value::attrs::pic` exposes an opaque process-local shape id,
      shape-to-slot cache entries, default polymorphic cap `N = 4`, and checked
      `Uninitialized → Monomorphic → Polymorphic → Megamorphic` transitions.
      Repeated shapes reuse existing slots, shape/slot inconsistency is rejected,
      and cap overflow abandons specialization. This does not execute select,
      guard a runtime value, call `select_slow`, alter tree-walk behavior, or
      install deopt/uncommon-trap edges.
- [ ] Monomorphic fast path: shape guard + constant-offset load, slow path widens the IC ([§5.2](#52-what-the-baseline-tier-emits)) — P5.
- [x] Current record select-cache fast path: `ratchet-value::attrs::pic::record`
      exposes `RecordSelectCache`, the select-site cache for heap-resident
      shaped flat records. A cached hit is exactly §5.2's contract on the
      tree-walk tier: guard the record's stored projected shape id, load the
      entry at the cached constant symbol-order slot, recheck the key (which
      keeps even a cross-table id collision sound), and return the value with
      no transient view. Misses resolve by binary search and widen through
      `Uninitialized -> Monomorphic -> Polymorphic -> Megamorphic` (cap 4).
      The active tree-walk static select/hasAttr/with/runtime-callable
      bridges route flat values carrying projected shape metadata through it
      under `AOS_NIX_SHAPES=record`. This is not the native CLIF-emitted
      guard, carries no deopt edge, and its terminal states are not yet in
      the shaped-site telemetry histograms (stats counters only).
- [x] Current shaped-select fast-path precursor:
      `ratchet-value::attrs::pic` exposes `ShapedSelectCache`, which guards
      one static key on `ShapedAttrs` by interned shape pointer, loads cached
      symbol slots on hits, resolves uncached shaped lookups through the
      representation-dispatching `select_slow` shaped branch, and widens
      through the PIC state machine. The active tree-walk static
      `Select`/`HasAttr` bridge now uses this cache for flat heap values that
      carry projected shape metadata by building a transient `ShapedAttrs` view
      over the existing flat payload. It does not replace active heap storage
      with shaped values, call the native runtime helper, handle HAMT values, or
      affect `.drv` bytes.
- [x] Current flat select-cache precursor:
      `ratchet-value::attrs::pic` exposes `FlatSelectCache`, which binds one
      static key and caches key-validated symbol-order slots for current
      `FlatAttrs`. Cached hits re-check the key at the stored slot before
      loading the value; stale slots, uncached slots, and megamorphic sites
      resolve through the representation-dispatching `select_slow` flat branch.
      Missing keys do not add slot entries or change PIC state because flat
      attrsets have no stable absent slot. This does not replace active flat
      attr storage with shaped/native layouts, call the native runtime helper,
      or affect `.drv` bytes.
- [x] Current active projected-shape select/with/runtime-callable IC bridge:
      the tree-walk evaluator stores per-run flat, shaped, and HAMT select-cache
      cells by module, select-site id, and attr-path segment or with-chain
      depth. Active flat
      heap values carrying projected shape metadata use a transient
      `ShapedAttrs` view and `ShapedSelectCache` for static `Select`/`HasAttr`
      segments, active `WithVar` scope probes, and crate-internal Rust-callable
      `aos_has_attr`/`aos_select_ic` wrappers; scoped-import global fallback
      probes carry stable `GlobalVar` lookup sites and use the same bridge;
      unprojected flat values keep the
      key-validated `FlatSelectCache` fallback; projected-HAMT values use the
      HAMT policy cache described below. Builtin static-select shortcuts,
      dynamic segments, native exported keyed helpers, and native storage paths
      remain on the shared slow dispatcher.
      Cached hits increment mirrored inline-cache
      hit stats; resolved lookups and misses increment miss stats and preserve
      representation-specific slow-select telemetry; successful `EvalOutcome`
      exits also record terminal shaped/flat/HAMT select-cache site states in
      `attr_telemetry`. This is a tree-walk/Rust-callable bridge over flat
      payloads, not the final native `aos_select_ic` lowering.
- [ ] Slow-path edge doubles as the deopt / uncommon-trap edge in the optimized tier ([§5.2](#52-what-the-baseline-tier-emits), [08 §3](08-execution-tiers-and-cranelift.md)) — P7, `S-5`.
- [x] Current P1 flat selection substrate: the tree-walk
      `Select`/`HasAttr` paths evaluate receivers, attr-path segments, and
      select defaults where present under the checked semantics in
      [25](25-intermediate-representation.md) §4, while `WithVar` probes
      active scopes in lowered with-chain order and scoped-global fallback
      probes walk scoped-import overlays innermost-first. Dynamic path segments
      use the representation-dispatching `select_slow` precursor; static
      `Select`/`HasAttr` segments, active `WithVar` probes, and scoped-global
      fallback probes use the checked flat/shaped/HAMT cache bridge described
      above when metadata permits. This still claims no native `aos_select_ic`,
      `select_slow` runtime helper, active shaped/HAMT storage replacement, or
      deopt/uncommon-trap edge.
- [ ] Future P5 `select_slow` / IC resolver: representation-dispatching
      runtime helper for `Flat` binary search and `Hamt` lookup, reached from
      the PIC miss/slow path and native `aos_select_ic` machinery
      ([§5.1](#51-the-mechanism), [§6.4](#64-interaction-with-inline-caches)) — P5.
- [x] Current `select_slow` precursor: `ratchet-value::attrs::select`
      dispatches slow selection over `FlatAttrs`, `HamtAttrs`, and `ShapedAttrs`.
      Flat uses binary search, HAMT uses trie lookup, and shaped attrs resolve a
      shape slot then load the value array. Tree-walk dynamic path segments and
      scoped-global fallback probes now reach this dispatcher through checked
      cache miss paths; `FlatSelectCache`,
      `ShapedSelectCache`, and `HamtSelectCache` also use this value-level
      dispatcher for slow resolution. HAMT/shaped active evaluator storage,
      native runtime attr representation, full shaped/native PIC integration,
      and `.drv` effects remain open.

### The update operator `//`

- [ ] Small / shape-stable case: result-shape via transition tree + flat copy, preserving a-then-new-b order ([§6.1](#61-small--shape-stable-case-transition--flat-copy)) — P5.
- [x] Current shape-preserving `//` fast path + rank-free permutation merge:
      `FlatAttrs::update_right_biased` now merges the operands' cached
      lexicographic permutations by comparing resolved raw key bytes instead
      of symbol-table ranks, taking the merge off the rank view whose lazy
      rebuild is `O(symbols)` after any fresh intern (the dominant cost of
      update chains that intern a new key per layer); and
      `FlatAttrs::update_right_biased_same_keys` handles the right-keys-
      subset case (the `state // { field = v; }` record-update pattern) as an
      `O(slots)` entry copy + slot overwrite that reuses the left operand's
      lexicographic permutation verbatim — no stream merge, no rank or byte
      comparison. Both are proven representation-identical (`raw_eq`) to the
      general merge, including a dense subset-mask sweep. The production `//`
      evaluator path uses both; under `AOS_NIX_SHAPES=record` the same-key
      result also keeps the left operand's projected shape id so selects on
      merge chains stay on the record-resident fast path. Transition-tree
      result-shape resolution for key-introducing merges remains open.
- [x] Current shaped update precursor: `ratchet-value::attrs::shape`
      exposes `ShapedUpdatePlan`, which computes a small shaped `//` result
      shape through the transition tree and instantiates a shaped value array
      with the current shallow update order: left source-order bindings keep
      their slots, right values overwrite shared keys, and right-only bindings
      append in right source order. It is not wired into the active `//`
      evaluator path, HAMT policy, or `.drv` bytes.
- [ ] Large / override-heavy case: persistent HAMT (CHAMP layout) with structural sharing ([§6.2](#62-large--override-heavy-case-hamt-persistent-map)) — P5, `S-10`; gate: benchmark.
- [x] Current HAMT storage precursor: `ratchet-value::attrs::hamt`
      provides a safe immutable bitmap-indexed attr map keyed by dense
      `Symbol` ids, persistent insert/replace operations that preserve old
      roots, checked duplicate/unknown-key handling, and a cached rank-sorted
      raw-byte lexicographic ordered view. It does not change the active `//`
      evaluator path, select from HAMT values, install the final measured CHAMP
      layout, or affect observable attr iteration / `.drv` bytes.
- [x] Current HAMT update-merge precursor: `ratchet-value::attrs::hamt`
      exposes right-biased `update_from_flat` and `update_from_hamt` helpers
      that apply `//` merges through persistent insert/replace operations,
      report inserted/replaced counts, preserve old roots, and recompute the
      cached raw-byte lexicographic ordered view once for the merged result.
      The active `//` evaluator shadow-dispatch bridge described below now uses
      this path for HAMT-classified telemetry accounting. Active HAMT heap
      storage, final CHAMP tuning, and `.drv` effects remain open.
- [ ] `AttrSetRepr` `Flat` ↔ `Hamt` measured promotion policy, invisible to `.drv` bytes ([§6.3](#63-the-policy-and-the-unified-value-view)) — P5; gate: differential `.drv` harness (both representations diffed).
- [x] Current representation-policy precursor: `ratchet-value::attrs::repr`
      classifies static literals, dynamic constructions, and `//` merge results
      as future `Flat` or `Hamt` candidates using tunable flat-size and
      override-chain thresholds. Static literals are explicitly
      threshold-exempt and stay flat because their shape is known; existing
      HAMT left operands, large results, and deep override chains prefer HAMT;
      HAMT decisions explicitly require a memoized ordered view. This does not
      implement HAMT nodes, change `//`, change `FlatAttrs`, or affect
      observable attr iteration / `.drv` bytes.
- [x] Current update-dispatch precursor: `ratchet-value::attrs::repr`
      exposes `AttrSetReprValue`, a safe `FlatAttrs`/`HamtAttrs` wrapper with
      `update_from_flat_right` policy dispatch. Small flat-left merges copy into
      a new flat attrset preserving left slots plus right-only append order;
      HAMT-classified merges convert flat left operands as needed and call the
      persistent HAMT merge helper. The active tree-walk `//` path now builds
      policy-compatible flat operands and runs this dispatch after successful
      flat heap allocation so `EvalOutcome::attr_telemetry` records real HAMT
      insert/replace summaries for HAMT-classified update samples. Heap attr
      records also persist the representation kind selected by this policy
      beside the active `FlatAttrs` payload, and hash-consing keeps otherwise
      equal attrsets distinct when that representation metadata differs. The
      runtime heap payload remains `FlatAttrs` to preserve the current value
      surface; active HAMT storage, HAMT right source-order semantics, measured
      threshold calibration, and `.drv` differential proof remain open.
- [ ] HAMT-valued select-site IC policy (distinguished HAMT entry vs fold into megamorphic) ([§6.4](#64-interaction-with-inline-caches)) — P5.
- [x] Current HAMT select-policy precursor: `ratchet-value::attrs::pic`
      exposes `HamtSelectCache`, which binds one static select key and models
      the two RFC policy choices for HAMT-valued selections: cache a
      distinguished HAMT entry that keeps using keyed HAMT lookup, or fold the
      site into the megamorphic path. The HAMT attrset and select key must
      share one symbol universe, and lookups now resolve through the
      representation-dispatching `select_slow` HAMT branch. The active
      tree-walk static select/hasAttr bridge now routes heap values carrying
      projected `Hamt` metadata through `HamtSelectCache` using a transient HAMT
      view over the current flat payload, so HAMT select-site telemetry observes
      resolved and cached distinguished-HAMT outcomes. Native PIC lowering,
      active HAMT heap payloads, and megamorphic fallback policy tuning remain
      open.

### Iteration-order compatibility (acceptance-critical)

- [x] Current flat-attrset ordering substrate: `FlatAttrs` decouples internal symbol-id lookup order, construction/source order, and observable raw-byte lexicographic iteration order; `iter_lexicographic()` is used by current tree-walk consumers such as `attrNames`/`attrValues` and `derivationStrict`; unit tests cover construction order and raw `&[u8]` collation including `a\0`/`a\xff` cases ([§7.1](#71-two-distinct-orders), [§7.2](#72-the-subtlety-symbol-id-order-vs-spelling-order)) — P1, `S-10`/`S-2`; gate: flat attr/tree-walk ordering tests.
- [x] Current native derivationStrict quoted/non-ASCII ordering canary: `native_instantiation_expr_orders_quoted_non_ascii_derivation_env_attrs` instantiates a static derivation whose environment mixes ordinary keys with a quoted `é` key and asserts the emitted root ATerm environment tuples appear in raw-byte lexicographic order (`aardvark`, `builder`, `name`, `out`, `system`, `zz`, then `é`). The env-gated `configured_cpp_nix_native_drv_closure_bytes_match_cli` oracle test includes the same shape and, when `AOS_NIX_ORACLE` is configured, compares the native `.drv` root path and recorded ATerm bytes against C++ Nix materialization. This is a focused current flat/native derivationStrict canary only: global/shared symbol ranks, future shaped/HAMT evaluator representations, active cached-order consumption by those representations, full conformance 20-21, and full AOS closure ordering parity remain open ([§7.1](#71-two-distinct-orders), [§7.2](#72-the-subtlety-symbol-id-order-vs-spelling-order), [§7.4](#74-derivationstrict-is-the-acceptance-critical-consumer)) — P1 precursor, `S-13`; gate: `native_instantiation_expr_orders_quoted_non_ascii_derivation_env_attrs` plus configured C++ Nix native `.drv` byte oracle.
- [x] Current cached rank precursor: `aos-nix-syntax::SymbolTable` maintains a
      process-local current raw-byte lexicographic rank per symbol;
      `FlatAttrs`, `AttrShape`, and `HamtAttrs` sort ordered views through that
      rank snapshot; and `AttrShape` exposes a shape-local inverse rank table
      over symbol-sorted slots. Ranks are not durable, not global/shared, and
      may be recomputed when later interning changes the current table view
      ([§7.3](#73-implementation-cached-sort-permutation-on-the-shape)) — P5
      precursor, `S-10`; gate: symbol/flat/shape/HAMT ordering tests.
- [ ] Full C++-Nix-identical ordering gate remains: differential/conformance harness must include adversarial non-ASCII quoted-key cases and `.drv` byte checks; future shapes/HAMT must carry cached lexicographic permutations/per-symbol sort ranks and ordered views, and `derivationStrict` must consume that cached order ([§7.1](#71-two-distinct-orders), [§7.2](#72-the-subtlety-symbol-id-order-vs-spelling-order), [§7.3](#73-implementation-cached-sort-permutation-on-the-shape), [§7.4](#74-derivationstrict-is-the-acceptance-critical-consumer)) — P1; gate: conformance 20-21 + differential `.drv` harness (research-grade until confirmed).
- [x] Current in-process order-parity precursor: `ratchet-value::attrs::order`
      collects and validates observable raw-byte lexicographic key vectors for
      `FlatAttrs`, `HamtAttrs`, `ShapedAttrs`, and `AttrSetReprValue`, compares
      representations against each other under the same symbol universe, rejects
      unresolved symbols, and tests adversarial symbol allocation order (`b`,
      `a\xff`, `a`, `a\0`). It also cross-checks a shaped update-transition
      result against flat and HAMT views for adversarial raw-byte order,
      guarding that current value-level transition case's cached lexicographic
      permutation. This does not call C++ Nix, drive `derivationStrict`, or
      prove `.drv` byte parity.
- [x] Cached lexicographic permutation per shape + per-symbol sort rank
      (integer-compare ordering) ([§7.3](#73-implementation-cached-sort-permutation-on-the-shape)) — P5.
      Implemented by `aos-nix-syntax::SymbolTable::lexicographic_rank`
      maintaining a process-local raw-byte rank view and by
      `ratchet-value::attrs::shape::AttrShape` storing a cached
      `iteration_order` plus `lexicographic_rank_by_symbol_slot` inverse table
      over symbol-sorted slots. This remains a precursor: ranks are not
      durable/global/shared, active evaluator shapes do not consume these
      cached permutations, and `.drv` differential proof remains tracked by the
      surrounding ordering rows.
- [x] Ordered view for `Hamt` instances (collect keys, sort by cached rank,
      memoize on the root) ([§7.3](#73-implementation-cached-sort-permutation-on-the-shape)) — P5.
      Implemented by `ratchet-value::attrs::hamt::HamtAttrs`, which stores a
      cached raw-byte lexicographic `iteration_order` beside the immutable HAMT
      root, derives it from the `SymbolTable` rank snapshot on
      construction/insertion/merge, preserves it on replacements, and exposes
      it through `iteration_order` / `iter_lexicographic`. This remains a
      precursor: active evaluator HAMT wiring, runtime representation dispatch,
      and `.drv` differential proof are still tracked by the surrounding P5
      rows.
- [ ] `derivationStrict` consumes the cached order; every shape's `iteration_order` cross-checked against sorted spelling on the oracle ([§7.4](#74-derivationstrict-is-the-acceptance-critical-consumer)) — P1, `S-13`; gate: differential `.drv` harness.

### Measure-first instrumentation

- [ ] Shape census, IC terminal-state histogram, `//` size + chain-depth distribution, order-parity harness ([§8](#8-measure-first-validation-and-tuning-surface)) — P5; tuning surface (`N`, `Flat`↔`Hamt` thresholds) cannot alter produced bytes.
- [x] Current in-process telemetry precursor: `ratchet-value::attrs::telemetry`
      exposes byte-neutral counters/snapshots for shape census, slow-select
      hit/miss outcomes by representation, generic/flat/shaped/HAMT select-cache
      terminal-state histograms, shaped/HAMT select-cache lookup paths, `//` operand-size,
      result-length-upper-bound, and override-chain-depth distributions, HAMT
      merge insert/replace totals, and order-parity outcomes. The active
      tree-walk evaluator now feeds this surface from successful flat attr heap
      allocation shape-census samples, flat slow-select outcomes, static and
      dynamic attrset-node representation decisions, and selected builtin result
      representation decisions, plus `//` update merges with syntactic
      update-chain depth, and exposes the captured samples through
      `EvalOutcome::attr_telemetry`; HAMT-classified active update samples now
      also carry HAMT insert/replace summaries from the representation-dispatch
      bridge, and active static shaped/flat/HAMT select-cache terminal states
      plus shaped/HAMT lookup outcomes are recorded there too. Cache hits use
      mirrored `EvalStats` inline-cache counters while unresolved cache lookups
      keep representation-specific slow-select telemetry; the same
      successful flat-allocation shape projection separately increments
      `EvalStats::shape_transitions` for uncached process-local transition
      edges. Runtime shape/PIC/HAMT storage instrumentation, full AOS
      package-set measurements, C++ `NIX_SHOW_STATS` comparison, and `.drv`
      differential proof remain open.

## References

- Urs Hölzle, Craig Chambers, David Ungar. *Optimizing Dynamically-Typed
  Object-Oriented Languages With Polymorphic Inline Caches.* ECOOP 1991.
  Origin of PICs and the mono/poly/mega state machine, for Self.
  <https://bibliography.selflanguage.org/pics.html> ·
  <https://link.springer.com/chapter/10.1007/BFb0057013>
- Craig Chambers, David Ungar, Elgin Lee. *An Efficient Implementation of SELF,
  a Dynamically-Typed Object-Oriented Language Based on Prototypes.* OOPSLA
  1989. Origin of "maps" (hidden classes).
  <https://bibliography.selflanguage.org/>
- V8 hidden classes / shapes, transition trees, and IC states
  (monomorphic/polymorphic/megamorphic, ≤4 cap before megamorphic).
  <https://dev.to/omriluz1/hidden-classes-and-inline-caches-in-v8-fj7> ·
  <https://draft.li/blog/2016/11/28/javascript-engines-hidden-classes/>
- Phil Bagwell. *Ideal Hash Trees.* EPFL/LAMP technical report, 2001. Origin of
  the HAMT. <https://en.wikipedia.org/wiki/Hash_array_mapped_trie>
- Michael J. Steindorfer, Jurgen J. Vinju. *Optimizing Hash-Array Mapped Tries
  for Fast and Lean Immutable JVM Collections (CHAMP).* OOPSLA 2015.
  <https://michael.steindorfer.name/publications/oopsla15.pdf> ·
  <https://blog.acolyer.org/2015/11/27/hamt/>
- Clojure / Scala persistent maps via HAMT (structural sharing).
  <https://www.javacodegeeks.com/2026/02/clojures-persistent-data-structures-immutability-without-the-performance-hit.html>
- Nix Reference Manual — `builtins.attrNames` returns names alphabetically
  sorted; `attrValues` follows sorted-name order.
  <https://nix.dev/manual/nix/2.28/language/builtins.html> ·
  <https://nixos.org/manual/nix/stable/language/builtins.html>
