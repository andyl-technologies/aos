# RFC-0007 - Value Representation: Tagged Values, Pointer Tagging, and Maximal Sharing

This document specifies how `aos-nix` represents Nix runtime *values* in memory:
the in-register and on-heap encoding of every value the evaluator manipulates,
the bit-level tricks (tagged unions, pointer tagging, optional NaN-boxing) that
make those values cheap to pass and cheap to discriminate, and the hash-consing
/ maximal-sharing layer that lets structurally-equal values collapse to a single
allocation. It is the foundational layer beneath everything else in the
evaluator: the memory manager (see [memory management and GC](06-memory-management-and-gc.md))
allocates these values, the execution tiers (see [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md))
produce and consume them, attribute sets (see [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md))
are built on top of them, and the incremental cache (see [incremental evaluation cache](12-incremental-evaluation-cache.md))
keys on their content hashes.

The thesis of this RFC (see [architecture overview](03-architecture-overview.md))
is that a fast Nix evaluator is a fast implementation of a lazy,
dynamically-typed, garbage-collected functional language *plus* a caching layer.
The value representation is where "dynamically-typed" and "lazy" and
"garbage-collected" all collide in one machine word. Every design decision here
is justified by a specific prior system — GHC's STG machine, LuaJIT's NaN-tagged
`TValue`, V8's tagged pointers, OCaml/ACL2 hash-consing — and by the way Nix's
**purity and value immutability** make a technique that is partial or unsound
elsewhere become total and sound here.

A theme runs through the whole document: we present a **correct, boring first
cut** and a **measured optimization** for each mechanism, and we never let the
optimization compromise the [hard compatibility constraint](02-compatibility-constraints.md).
Value representation has no observable effect on `.drv` output *by construction*
— it is an internal encoding — but it has an enormous effect on whether we beat
C++ Nix, which is the entire point.

---

## 1. What a Nix value is

Before choosing bits, we enumerate the inhabitants. The Nix language has a small,
fixed set of value forms. C++ Nix's `Value` (`src/libexpr/value.hh`) is the
reference; we must represent the same set, with the same observable semantics,
or we cannot reach `.drv` parity.

| Nix type        | `builtins.typeOf` | Payload                                            | Notes |
|-----------------|-------------------|----------------------------------------------------|-------|
| int             | `"int"`           | 64-bit signed integer (`i64`)                      | Full `i64` range is observable; overflow wraps as in C++ Nix. |
| float           | `"float"`         | 64-bit IEEE-754 double (`f64`)                     | |
| bool            | `"bool"`          | one bit                                            | |
| null            | `"null"`          | none                                               | A singleton. |
| string          | `"string"`        | byte string + **string context**                  | Context is a set of store-path dependencies (see §8). |
| path            | `"path"`          | byte string (absolute path) + accessor identity   | Paths copy to the store when coerced. |
| list            | `"list"`          | immutable vector of values (lazy elements)         | Elements are thunks until forced. |
| attrs (attrset) | `"set"`           | immutable map symbol → value (lazy values)         | The hottest structure; see [attribute sets](09-attribute-sets-hidden-classes-and-inline-caches.md). |
| lambda          | `"lambda"`        | `(code_ptr, captured_env)` closure                 | Includes partial applications of primops. |
| primop / app    | `"lambda"`        | builtin function or partially-applied builtin      | Indistinguishable from a lambda to user code. |
| thunk           | (forces first)    | `(code_ptr, captured_env, state)`                  | **Not** a user-visible type; forcing erases it. |
| external        | `"external"`      | opaque plugin value                                | Rare; supported for completeness. |

A *thunk* is the runtime embodiment of laziness: a suspended computation that,
when *forced*, produces one of the value forms above (see
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)).
Crucially, a thunk is **not** a Nix type — `builtins.typeOf` never returns
`"thunk"`. From the language's point of view, a value is always one of the typed
forms; the thunk is an implementation detail that the value representation must
encode but the semantics must hide. The discipline of "force before observe" is
threaded through every primop and every `select`.

### 1.1 The WHNF distinction

The single most important property the value representation must encode cheaply
is: **is this value already in weak head normal form (WHNF)?** A value is in WHNF
when its outermost constructor is known — an int is an int, a list is a list
(even if its *elements* are still thunks), a lambda is a lambda. Forcing drives a
value to WHNF and no further. Nix is a *weak head* lazy language exactly like GHC:
`force` never evaluates inside a list or attrset, only the spine head.

The hot path of any lazy evaluator is *re-forcing an already-forced value*. In a
naive design, every access to a binding goes through `force`, which must check
"are you a thunk? what state are you in?" billions of times. The entire art of
fast laziness — pioneered by GHC's Spineless Tagless G-machine — is making "this
is already evaluated" a **single tag test on a value we already hold in a
register**, never an indirect call, never a heap load. That property is what
§3 (tagged values) and §4 (pointer tagging) buy us.

---

## 2. The 16-byte tagged value (first cut)

The first-cut representation, and the permanent representation of the
**tree-walk oracle** tier (see [execution tiers](08-execution-tiers-and-cranelift.md)),
is a 16-byte tagged union. We choose 16 bytes deliberately and we explain why
the obvious 8-byte NaN-box is the *optimization*, not the baseline.

### 2.1 Why 16 bytes, and why not NaN-box first

Nix integers are `i64`. The full 64-bit range is observable: `builtins.toString
9223372036854775807` must round-trip, and arithmetic must wrap with C++ Nix
semantics. A NaN-box (§4) hides a payload inside the ~51 spare bits of a quiet
IEEE-754 NaN (the top 13 bits select the qNaN pattern), and after spending a few
of those on a type tag the usable payload is ~48 bits — enough for a canonical
x86-64/AArch64 pointer but **not** a full `i64`. This is the same wall LuaJIT
hits: it treats the double as its native number and integers as a bolt-on, so
exact integers top out around 2^53 and a NaN-boxed payload cannot hold a 64-bit
int. ([LuaJIT issue #182](https://github.com/LuaJIT/LuaJIT/issues/182),
[wingolog on value representation](https://wingolog.org/archives/2011/05/18/value-representation-in-javascript-implementations).)

LuaJIT, and most NaN-boxing VMs, get away with this because their canonical
number type *is* the double and 64-bit integers are a bolt-on. **Nix is the
opposite**: `int` is a first-class 64-bit integer and `float` is the rarer type.
A representation that cannot hold a full `i64` inline would have to box large
integers, adding an allocation and a load to the single most common arithmetic
type. That is unacceptable for the baseline. So the baseline is a flat 16-byte
struct: 8 bytes of tag/discriminant, 8 bytes of payload, every `i64` and every
`f64` and every pointer inline, no exceptions.

This also matches the project's **measure-first** discipline (see
[motivation and goals](01-motivation-and-goals.md)). A 16-byte tagged value is
trivially correct and trivially debuggable; NaN-boxing is a bit-twiddling
optimization whose payoff (halving value size, doubling cache density in the
nursery, fitting a value in one register pair → one register) must be *measured*
against a working baseline before we pay its complexity and `unsafe` cost.

### 2.2 Layout

```rust
/// A Nix runtime value: a 16-byte tagged union.
///
/// The first 8 bytes are the tag word (a `ValueTag` plus reserved bits); the
/// second 8 bytes are the payload, interpreted according to the tag. Heap
/// payloads are `NonNull` pointers into the evaluator heap (see
/// [memory management](06-memory-management-and-gc.md)); immediate payloads
/// (`Int`, `Float`, `Bool`) are stored inline.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Value {
    tag: ValueTag,        // 8 bytes (only low byte meaningful in the baseline;
                          //          high bits reserved for shape/cardinality
                          //          hints once tiers exist)
    payload: Payload,     // 8 bytes
}

#[repr(u8)]
pub enum ValueTag {
    // --- immediate / WHNF forms ---
    Int      = 0x00,      // payload: i64, inline
    Float    = 0x01,      // payload: f64, inline (bit-cast)
    Bool     = 0x02,      // payload: 0 or 1, inline
    Null     = 0x03,      // payload: unused
    // --- heap / WHNF forms (payload is a pointer) ---
    String   = 0x10,      // -> NixString (bytes + context, see §8)
    Path     = 0x11,      // -> NixPath
    List     = 0x12,      // -> NixList (vector of Value)
    Attrs    = 0x13,      // -> NixAttrs (shape id + values, see RFC doc 09)
    Lambda   = 0x14,      // -> Closure (code_ptr + env)
    Primop   = 0x15,      // -> PrimopDescriptor or partial application
    External = 0x16,      // -> dyn ExternalValue
    // --- non-WHNF form (must be forced before observation) ---
    Thunk    = 0x20,      // -> Thunk (code_ptr, env, atomic state)
}

#[repr(C)]
union Payload {
    int: i64,
    float: f64,
    boolean: u64,         // 0 | 1
    ptr: NonNull<HeapObject>,
}
```

The `Copy` bound is load-bearing: a `Value` is two machine words that pass in a
register pair under the System V AMD64 ABI and the Cranelift calling convention
(see [primops and runtime ABI](10-primops-and-runtime-abi.md)). Compiled code
never dereferences a `Value` to learn its type — the tag is *in* the value. This
is the same decision LuaJIT makes with its 8-byte `TValue` and that V8 makes with
its tagged words: **the discriminant travels with the value, in registers, never
behind a pointer**.

### 2.3 Tag dispatch and the WHNF fast path

The single hottest operation is `force`:

```rust
impl Value {
    /// Returns the value in weak head normal form, evaluating a thunk if
    /// necessary. For an already-WHNF value this is a single tag comparison.
    #[inline(always)]
    pub fn force(self, rt: &mut Runtime) -> Result<Value, Catchable> {
        // Fast path: anything that is not a thunk is already WHNF.
        if self.tag as u8 != ValueTag::Thunk as u8 {
            return Ok(self);
        }
        // Slow path: drive the thunk to WHNF (see §6 and doc 07).
        rt.force_thunk_slow(self)
    }
}
```

In the 16-byte representation the WHNF test is `self.tag != Thunk` — a register
compare and a predicted-not-taken branch. There is no heap load, no indirect
call, nothing. This is already dramatically better than C++ Nix, whose `Value`
must load the discriminant from the heap object because a `Value*` is a pointer.
It is the §4/§4-pointer-tagging optimization that pushes this even further by
making the *thunk itself* carry its forced-ness in spare pointer bits, so we can
skip the `force_thunk_slow` indirect call when a thunk is already `Forced` — see
below.

---

## 3. Tagged-pointer heap objects and the WHNF bit

Heap payloads (`String`, `List`, `Attrs`, `Lambda`, `Thunk`, …) are pointers.
On x86-64 and AArch64, heap allocations from our bump arena / GC (see
[memory management](06-memory-management-and-gc.md)) are at least 8-byte aligned,
so the **low 3 bits of every heap pointer are always zero** and free for us to
use. This is *pointer tagging*, and it is the second pillar of the
representation. We harvest it from two systems:

- **GHC's dynamic pointer tagging** (Marlow, Yakushev, Peyton Jones, ICFP 2007):
  GHC stuffs into the spare low bits of a pointer-to-closure either *the
  constructor tag* (for a small enumeration) or *whether the closure is already
  evaluated*. The payoff is that a `case` scrutinee that is already in WHNF is
  recognized by a **tag test on the pointer**, avoiding the indirect `ENTER` jump
  through the closure's info table. ([STG / pointer-tagging background](https://www.microsoft.com/en-us/research/wp-content/uploads/1992/04/spineless-tagless-gmachine.pdf).)
  This is the "tagless" machine *adding tags back where they pay* — the name is
  historical irony noted in the literature.
- **V8 and the OCaml runtime**: the low bit distinguishes immediate small
  integers from heap pointers, so the common case (Smi arithmetic / int payloads)
  never touches the heap.

We do not need a constructor tag in the pointer the way GHC does — our `ValueTag`
already discriminates the value form in the *value word*. What we want pointer
tagging for is finer, thunk-internal state and small-constructor fast paths:

```text
  heap pointer, 64 bits:
  ┌────────────────────────────────────────────────────────┬───┬───┬───┐
  │              object address (bits 63..3)                │ b2│ b1│ b0│
  └────────────────────────────────────────────────────────┴───┴───┴───┘
                                                              \_________/
                                                            spare low bits
                                                            (alignment ≥ 8)

  Thunk pointers (ValueTag::Thunk):
    b0 = 1  -> thunk is FORCED; read its cached WHNF result directly,
              skipping the atomic state-word load and the slow-path call.
    b0 = 0  -> thunk is Suspended or Blackholed; consult the state word.

  Small-attrs / small-list pointers (optimization, optional):
    b1..b0 encode 0,1,2 elements inline-after-header ("constructor info"),
    letting `length`/single-key `select` skip a header load.
```

### 3.1 The forced-thunk shortcut

The interaction between §2 and §3 is the crux of cheap laziness. Consider a
binding `x` that is referenced many times in a `let`. After the first force, the
thunk is `Forced` and holds its WHNF result. Every subsequent reference should
cost as little as touching an already-forced value. With pointer tagging on thunk
pointers:

```rust
#[inline(always)]
fn deref_binding(slot: Value, heap: &Heap) -> Value {
    // `slot` is whatever the environment holds for this binding.
    if slot.tag as u8 == ValueTag::Thunk as u8 {
        let tagged = slot.payload_tagged_address(); // raw address bits only
        if tagged.has_forced_bit() {
            // FORCED bit set: the thunk's result pointer is one indirection
            // away, but we know the state without an atomic load or a call.
            //
            // Raw decoded address bits are not a dereference capability. The
            // runtime must recover the thunk through a provenance-bearing heap
            // handle or object table before reading the cell.
            let thunk = heap.thunk_handle(tagged.address_bits());
            return thunk.result_unchecked();
        }
        // not yet forced: fall to the slow path
        return force_slow(slot);
    }
    slot // already a non-thunk WHNF value
}
```

The win, exactly as in GHC, is eliminating the **indirect call / info-table
load** on the hot "already evaluated" path. Because Nix values are immutable once
forced (the `Forced` transition is monotonic — see §6), this bit is safe to read
without synchronization in single-threaded mode, and with a single acquire-load
in the parallel mode (see [parallel evaluation](13-parallel-evaluation.md)).

### 3.2 Why this is sounder in Nix than in GHC

GHC's pointer tagging must contend with *mutable thunks* that can be updated
concurrently and with a generational GC that moves objects (the tag bits must be
preserved across copying). Both are also true for us, but Nix gives us an extra
guarantee GHC lacks: **a Nix value, once in WHNF, never mutates and never
reverts.** There is no `unsafePerformIO`, no `IORef`, no mutable closure
environment that a later effect can change. The `Forced` bit is therefore a
*stable, monotonic* fact. That monotonicity is what makes both the lock-free
parallel forcing protocol (CAS the state once, never again) and the incremental
cache's value-hash keying sound. Purity converts a GHC heuristic into an
invariant.

---

## 4. NaN-boxing (the measured optimization)

NaN-boxing collapses the 16-byte value into 8 bytes by exploiting the redundancy
in IEEE-754: a quiet NaN has all exponent bits set and a non-zero mantissa, and
there are ~2^51 distinct NaN bit patterns that no legitimate floating-point
computation produces. We can stash a 3-bit type tag plus a ~48-bit payload
(pointer or small int) inside those patterns, store any genuine `f64` as itself,
and recover an 8-byte universal `Value`. This is LuaJIT's `TValue` and the technique behind
SpiderMonkey/JSC value encodings. ([NaN-boxing explainer](https://piotrduperas.com/posts/nan-boxing/),
[value representation in JS engines](https://wingolog.org/archives/2011/05/18/value-representation-in-javascript-implementations).)

```text
  8-byte NaN-boxed Value (sketch):

  any real f64 (incl. ±Inf, signaling)  -> stored verbatim, NOT a quiet NaN
  ┌──────────────────────────────────────────────────────────────────────┐
  │ sign │ exponent (11) │              mantissa (52)                      │
  └──────────────────────────────────────────────────────────────────────┘

  boxed non-double values  -> a canonical quiet-NaN prefix + tag + payload
  ┌─────────────┬──────┬───────────────────────────────────────────────────┐
  │ qNaN prefix │ tag3 │            48-bit payload (pointer / small int)     │
  └─────────────┴──────┴───────────────────────────────────────────────────┘
    tag = 001 -> heap pointer (48-bit canonical x86-64/AArch64 address)
    tag = 010 -> null / bool / small immediates
    tag = 011 -> "small int" (fits in 48 bits)         <-- the catch (§4.1)
    ...
```

### 4.1 The i64 problem, restated and resolved

The blocker is §2.1: a ~48-bit payload cannot hold a full `i64` (and even the
full ~51 spare NaN bits fall short). LuaJIT lives with this because doubles are
its native number and exact integers only need to reach ~2^53. We cannot, because `int` is Nix's native number and large integers
(timestamps, sizes, hashes-as-ints) must round-trip exactly. There are three
ways out, in increasing order of how much we like them:

1. **Box only large integers.** Inline integers in `[-2^47, 2^47)`; for the rare
   integer outside that range, allocate an 8-byte heap cell and point to it
   (tag = heap pointer to a `BoxedI64`). Almost all Nix integers are small
   (lengths, indices, small constants), so the box is cold. This is the LuaJIT
   "64-bit integer hack" generalized. Cost: a branch on the integer magnitude at
   every `int` construction, and a heap load for big-int arithmetic.
2. **Use both representations side by side.** Keep the 16-byte `Value` as the
   tree-walk and ABI value, and NaN-box only inside *dense homogeneous
   containers* (e.g. a list known to be all-ints, an arena of nursery values)
   where halving the footprint doubles cache density. This is the most
   conservative and the one we favor: it confines `unsafe` NaN-box code to a
   measured, bounded surface and never touches the cross-tier ABI.
3. **Pointer-pair "NuN-boxing" / 128-bit boxing** — keep 16 bytes but pack
   tag-in-pointer. This is just §2+§3 and is the baseline; it is here for
   completeness as the "do nothing" option.

The decision is explicitly deferred to measurement (see
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md)).
The nursery-density argument is strong — the generational hypothesis is extreme
in Nix (most thunks die immediately, see [memory management](06-memory-management-and-gc.md)),
so halving value size directly halves nursery pressure — but it is exactly the
kind of constant-factor win the RFC's ranked roadmap (see
[roadmap and risks](17-roadmap-and-risks.md)) places *after* the incremental
cache and the allocator. We will not ship NaN-boxing until a benchmark on the
real AOS package set shows it beats the 16-byte baseline by a margin that
justifies the `unsafe` surface.

> **Open question (NaN-boxing payoff).** Does NaN-boxing pay once the bump-arena
> allocator and generational GC are in place, given that the i64 box reintroduces
> a branch on the hottest type? We suspect approach (2) — NaN-box only in
> homogeneous nursery containers — captures most of the cache-density win with a
> fraction of the risk, but this is unproven and flagged as research-grade.

### 4.2 NaN-boxing and the GC must agree on pointers

If NaN-boxed values hold 48-bit pointers, the **precise GC must be able to find
and relocate them** (see [memory management](06-memory-management-and-gc.md)).
This is the well-known cost of NaN-boxing: a moving collector must decode every
boxed pointer, fix it, and re-box it, and it must never mistake a real `f64`
whose bits happen to look like a boxed pointer for an actual pointer (which is
why the qNaN prefix must be *canonical* and real doubles must be normalized away
from the boxed-pointer pattern). Because our GC is **precise** (it knows the type
of every root and field from the value tag — not conservative like Boehm), this
is mechanical: the GC's value-scanning routine masks off the tag, treats
`tag == heap pointer` payloads as roots, and ignores everything else. This is
strictly easier than in a conservative collector, and it is one more reason the
RFC abandons Boehm (see [architecture overview](03-architecture-overview.md)).

---

## 5. Hash-consing and maximal sharing

The third pillar — and the one with the largest *systemic* payoff after the
incremental cache itself — is **hash-consing**: interning immutable values so
that two structurally-equal values share one allocation. When a value is
constructed, we consult a global hash table keyed on the value's structure; if an
equal value already exists, we return the existing pointer instead of allocating.
([Hash consing, Wikipedia](https://en.wikipedia.org/wiki/Hash_consing);
[efficient symbolic computation via hash consing, arXiv 2025](https://arxiv.org/html/2509.20534v1).)

### 5.1 Why hash-consing is *sound* in Nix and only *partial* elsewhere

Hash-consing requires that interned values be **immutable** — if a shared value
could be mutated through one alias, every other alias would see the change. In
imperative languages this restricts hash-consing to a hand-curated subset
(string interning, symbol tables, BDD nodes). **Nix values are immutable by
language design.** A `string`, a `list`, an `attrs` cannot be mutated after
construction; `//` produces a *new* attrset, it does not mutate. Therefore
hash-consing is **total** in Nix: *every* WHNF value is a legitimate candidate
for interning, with no escape analysis or alias analysis needed to prove safety.
Purity converts a niche technique into a global one — the same leverage the RFC
claims throughout (see [architecture overview](03-architecture-overview.md)).

### 5.2 The three payoffs

Hash-consing buys three distinct, compounding wins, each of which the rest of the
evaluator depends on:

1. **Heap deduplication.** AOS's package set is drowning in structural
   redundancy. The same store-path string (`/nix/store/…-glibc-2.39`) appears in
   thousands of derivations. The same `stdenv`, the same `meta` attrset, the same
   `platforms` list recur across nearly every package. Interning collapses all of
   these to one allocation. On a whole-nixpkgs-scale eval this is not a
   rounding error — it is a large fraction of live heap.

2. **O(1) structural equality.** Once values are maximally shared, *structural
   equality is pointer equality*. `a == b` for two interned attrsets is a single
   `ptr_eq`, not a recursive structural walk. ([Hash consing gives constant-time
   equality via physical equality](https://en.wikipedia.org/wiki/Hash_consing).)
   Nix's `==` operator forces and compares deeply; for hash-consed operands the
   deep compare short-circuits to a pointer check at every shared subterm. This
   matters because `==` on attrsets and lists shows up in real nixpkgs code
   (e.g. `lib` overlays, `unique`, set operations).

3. **Trivial, cheap value hashing for the incremental cache.** The incremental
   cache (see [incremental evaluation cache](12-incremental-evaluation-cache.md))
   keys memoized results on a hash of the value, and performs **early cutoff** by
   comparing a recomputed node's value-hash to the previous one. If values are
   hash-consed, *the hash is computed once at interning time and stored in the
   object header* — every subsequent "hash this value" is a field read, and every
   "are these two values equal for caching purposes" is a pointer compare. Hash
   consing and early cutoff are two halves of the same idea: the cons-table key
   *is* the early-cutoff key.

### 5.3 Mechanism

```rust
/// Interns a freshly-constructed WHNF value, returning a canonical shared
/// pointer. Structurally-equal values returned by `intern` are pointer-equal.
///
/// # Errors
/// Never fails; on table growth it may allocate. Returns the canonical handle.
fn intern(table: &mut ConsTable, v: HeapObject) -> NonNull<HeapObject> {
    // 1. Compute a structural hash of `v`. For composite values this uses the
    //    *already-interned, already-hashed* children, so the hash is cheap:
    //    combine the children's stored hashes + this node's tag/shape.
    let h = structural_hash(&v);            // xxh3 in-process (see §5.4)
    // 2. Probe the table for an equal entry.
    if let Some(existing) = table.lookup(h, &v) {
        return existing;                    // share — no allocation
    }
    // 3. Miss: store the hash in the header, install, return.
    let ptr = table.alloc_and_store(h, v);
    ptr
}
```

The recursion bottoms out because children are interned *before* their parent, so
`structural_hash` of a composite never re-walks shared subtrees — it folds the
children's cached hashes. This is the standard *bottom-up* hash-consing
discipline ([type-safe modular hash-consing](https://www.researchgate.net/publication/221057062_Type-safe_modular_hash-consing)).

We do **not** hash-cons everything unconditionally — that would be a pessimization
for values that are unique and short-lived (e.g. a freshly-computed large list
that will never recur). The policy:

- **Always intern**: strings (especially store-path strings), symbols (already
  interned to `u32`, see [attribute sets](09-attribute-sets-hidden-classes-and-inline-caches.md)),
  small attrsets, `meta`-shaped attrsets, and any value that flows into a
  derivation's environment (these recur the most and feed `.drv` construction).
- **Intern on the slow path / promotion**: large composites get interned when
  they survive a nursery collection (tie the cons-table insertion to GC promotion,
  so we only pay to intern values that have proven they live — the same
  generational logic as the allocator). Nursery-local values are compared by
  identity and only canonicalized on tenuring.
- **Never intern**: thunks (they are not WHNF and they mutate to `Forced`),
  lambdas with distinct captured environments (rarely structurally equal),
  externals.

### 5.4 Hashing policy (and why three hash functions)

The RFC uses three different hash functions for three different jobs, and the
cons-table must use the right one (see also
[incremental evaluation cache](12-incremental-evaluation-cache.md)):

| Hash    | Used for                                          | Why |
|---------|---------------------------------------------------|-----|
| **xxh3**| in-process cons-table keys, hot value hashing     | Fastest non-crypto hash; collisions handled by the table's equality fallback, so non-cryptographic is fine in-process. |
| **blake3** | durable, content-addressed eval cache shared across CI machines | Cryptographic, collision-safe at scale; a collision in a *shared* cache would corrupt results, so it must be crypto. |
| **SHA-256** | **only** Nix-observed `.drv` / store-path hashes | Non-negotiable on-disk format (see [derivation and store compatibility](11-derivation-and-store-compatibility.md)). Never used for internal sharing. |

The cons-table uses **xxh3** with full structural equality as the tiebreak: a
hash collision is harmless because we still compare structurally before sharing.
This is the standard hash-consing contract — the hash is an accelerator, not the
identity. Critically, **none of these internal hashes ever leak into `.drv`
output**: a value's xxh3/blake3 hash is an internal sharing/caching key, while the
SHA-256 that determines a store path is computed by `derivationStrict` from the
ATerm serialization, completely independently. The compatibility constraint (see
[compatibility constraints](02-compatibility-constraints.md)) is unaffected by
any choice in this document, by construction.

### 5.5 Interaction with the GC

Hash-consing and a moving GC interact in a well-known way: the cons-table holds
pointers into the heap, so it is either a **GC root set** (entries keep values
alive) or a **weak table** (entries are dropped when the value is otherwise
unreachable). For Tier A (one-shot CLI eval, bump-arena, never free), the table
is simply part of the arena and dropped wholesale at exit — trivial. For Tier B
(long-lived daemon, generational GC), the cons-table must be a **weak hash table**
whose entries do not by themselves retain values, and which is *scavenged during
collection*: dead entries are removed and surviving entries have their pointers
forwarded. This is exactly how OCaml's `Ephemeron`-based hashcons and GHC's
stable-name tables behave. The mechanism is detailed in
[memory management and GC](06-memory-management-and-gc.md); here we only fix the
contract: **the cons-table never resurrects garbage, and the GC always updates
cons-table pointers on a move.**

---

## 6. Thunk state and the force protocol (representation view)

The full laziness story lives in [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md);
here we specify only the *representation* of a thunk and its state machine,
because it is part of the value layout.

```rust
/// A suspended computation. Lives on the heap; pointed to by a `Thunk`-tagged
/// `Value`. The `state` word is atomic to support lock-free parallel forcing
/// (see [parallel evaluation](13-parallel-evaluation.md)); in single-threaded
/// mode it is read and written without contention.
#[repr(C)]
pub struct Thunk {
    state: AtomicU64,             // Suspended | Blackhole | Forced(result)
    code: CodePtr,               // compiled or interpreted body
    env: EnvPtr,                 // captured environment (slots, de Bruijn)
}
```

The state machine here is the **serial** model, identical in shape to GHC's
thunk update and to Snix/Tvix's thunk discipline
([tvix-eval Thunk](https://docs.tvix.dev/rust/tvix_eval/value/thunk/struct.Thunk.html)).
It is the serial *subset* of the parallel superset
`Suspended → Pending → Awaited → Forced/Failed` that
[parallel evaluation](13-parallel-evaluation.md) introduces; single-threaded
forcing only ever visits `Suspended → Blackhole → Forced`. One model, two regimes:

```text
        force()                 evaluation completes
  Suspended ───────► Blackhole ───────────────────► Forced(WHNF value)
      │                  │                                  │
      │                  │ re-entered while Blackhole       │ re-force:
      │                  ▼                                  │ return cached
      │            infinite-recursion error                ▼ result (O(1))
      └──────────────────────────────────────────► (FORCED pointer-tag bit set)
```

- **Suspended** — not yet evaluated; `force` claims it.
- **Blackhole** — currently being forced *on this stack*. Re-entering a
  blackholed thunk is Nix's infinite-recursion detection (`error: infinite
  recursion encountered`). The representation must distinguish "blackholed by me"
  from the parallel case "blackholed by another thread," which is why `state` is
  a tagged atomic word, not a bool (see [parallel evaluation](13-parallel-evaluation.md)
  for the work-stealing/help protocol).
- **Forced** — holds the WHNF result. The transition is monotonic and the
  pointer-tag `FORCED` bit (§3.1) lets re-forces skip the state load entirely.

Two whole-program analyses (see [laziness](07-laziness-and-whole-program-analyses.md))
let us *shrink or delete* this representation per-thunk:

- **Strictness/demand analysis** proves a binding is always forced → the
  worker-wrapper transform compiles it *eagerly*, allocating **no thunk at all**.
  The value slot holds the result directly; the `Thunk` struct never exists.
- **Cardinality (0/1/many) analysis** proves a thunk is forced **at most once** →
  it needs no `Blackhole`/update machinery, only `Suspended → Forced`. The
  `AtomicU64` collapses to a simple pointer slot for single-entry thunks. ("0"
  cardinality → the binding is dead and eliminated outright.)

So the thunk representation above is the *general* case; the common case, after
analysis, is *no thunk*. This is the GHC insight — neither C++ Nix nor Snix/Tvix
perform it — and it is why the value representation must be *flexible about
thunks* rather than assuming every binding is one.

---

## 7. Lists and the value layout of containers

A `List`-tagged value points to an immutable vector of `Value` (each element a
thunk until forced — weak-head laziness stops at the spine). The representation
is a length-prefixed, contiguous `[Value]` so that `builtins.elemAt`, `length`,
and iteration are constant-time and cache-friendly:

```rust
#[repr(C)]
pub struct NixList {
    header: ObjHeader,    // GC + cons hash + shape bits
    len: u32,
    // elements: [Value; len]  -- inline, flexible-array-member style
}
```

Small lists (0/1/2 elements) get the pointer-tag small-constructor encoding
(§3) so `length` can answer without a header load. Lists feed hash-consing
heavily: `[ "x86_64-linux" ]`, `[ ]`, and `meta.platforms`-shaped lists recur
across the package set and intern to single allocations. Escape analysis (see
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md))
can scalar-replace a non-escaping list built only to be immediately folded
(`foldl'` over a `genList`), eliminating the `NixList` allocation entirely — the
representation must therefore not assume every list is heap-resident.

Attribute sets get their own document because they carry the hidden-class /
shape / inline-cache machinery; see
[attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md).
For value-representation purposes the key facts are: an `Attrs`-tagged value
points to an object whose header references an interned **shape** (the sorted key
set, in deterministic order — *required* for `.drv` compatibility) and whose body
is a flat array of `Value` indexed by shape offset, with a HAMT fallback for
large/override-heavy sets.

---

## 8. Strings and string contexts

Strings deserve explicit treatment in the value representation because of the
**string context** — a feature with no analogue in ordinary languages and with a
direct line to `.drv` correctness.

```rust
#[repr(C)]
pub struct NixString {
    header: ObjHeader,
    bytes: ByteBufPtr,        // UTF-8-ish byte string (Nix strings are bytes)
    context: StringContext,   // interned, COW bitset of store-path ids
}
```

A Nix string carries a **context**: the set of store paths it depends on. When
you interpolate a derivation into a string, the resulting string's context
records that dependency; when `derivationStrict` reads the string to build a
`.drv`, the context becomes an input edge. **String contexts must match C++ Nix
exactly** or the resulting derivation has different inputs → different store path
→ total cache miss (see [compatibility constraints](02-compatibility-constraints.md)
and [derivation and store compatibility](11-derivation-and-store-compatibility.md)).

The representation choice is therefore driven by correctness *and* speed:

- A context is a **set of interned store-path ids** (each store path interned to a
  small integer, like symbols). We represent it as a **copy-on-write bitset** (or
  a small sorted `SmallVec` for the common case of 0–2 contexts).
- String operations **union** contexts: `a + b` produces a string whose context
  is `ctx(a) ∪ ctx(b)`. `builtins.unsafeDiscardStringContext` clears it;
  `builtins.getContext` / `addDrvOutputDependencies` manipulate it explicitly.
  Each of these must reproduce C++ Nix's behavior bit-for-bit.
- COW + interning means the extremely common case — concatenating context-free
  string literals — allocates *no* context and shares the empty context
  singleton. Only strings that actually touch the store carry a non-trivial
  bitset.

String *bytes* are hash-consed aggressively (§5): store-path strings are the
single most-duplicated value in the heap. The context is hashed alongside the
bytes so that two strings with identical bytes but *different* contexts do **not**
collapse — they are observably different values to `derivationStrict`. This is a
place where naive interning would be a correctness bug, and the representation
guards against it by including the context in the cons key.

> **Layering note (string context is Nix-dialect, not generic).** The string
> context is a *Nix-specific* concept and does **not** live in the generic value
> crate. Under the `ratchet` Core/dialect factoring (see
> [generalization and language dialects](28-generalization-and-language-dialects.md)
> §4, §10), `ratchet-value` owns only the generic tagged value representation and
> the hash-consing machinery; the context bitset and its union-on-concat semantics
> move out into `aos-nix-dialect`. The two are reconciled by the cons key: the
> engine's cons-key hashing takes a **dialect-supplied discriminator**, and the
> Nix dialect supplies the string context as that discriminator — so
> identical-bytes / different-context strings still do not collapse, with the
> distinguishing data owned by the dialect rather than baked into the generic
> value crate.

---

## 9. Putting it together: the value lifecycle

The following sketch traces a value from construction to use, showing where each
mechanism fires.

```text
  source: let g = "${glibc}/lib"; in [ g g ]
  ───────────────────────────────────────────────────────────────────────

  1. parse + scope (doc 04) ─► IR with a thunk for `g`, env slot 0

  2. eval `[ g g ]`:
       - allocate NixList, len 2
       - element 0, element 1 both reference env slot 0 (the SAME thunk)
       - LIST is itself a candidate for interning (§5)

  3. force g (first reference):
       - thunk state Suspended -> Blackhole
       - run body: interpolate glibc store path -> NixString
           bytes  = "/nix/store/…-glibc-2.39/lib"   (hash-consed, §8)
           context= { id(glibc) }                    (COW bitset, §8)
       - intern the string (§5): canonical shared pointer + stored xxh3 hash
       - thunk state -> Forced(result); pointer-tag FORCED bit set (§3.1)

  4. force g (second reference):
       - tag test: Thunk + FORCED bit -> return cached result, O(1), no call

  5. the two list elements now point to the SAME interned NixString
       -> `g == g` is ptr_eq; the list serializes to a .drv input ONCE
```

Every pillar shows up: tagged dispatch (step 4's tag test), pointer tagging
(FORCED bit), hash-consing (one string allocation shared by both references and
by every other `${glibc}/lib` in the package set), and string contexts feeding
derivation inputs correctly.

---

## 10. Comparison to prior art

| System            | Value cell           | WHNF/eval marker             | Sharing            | Relevance to aos-nix |
|-------------------|----------------------|------------------------------|--------------------|----------------------|
| **C++ Nix**       | heap `Value*`        | type field loaded from heap  | none (re-allocates)| The baseline to beat; loses on the WHNF test and on redundancy. |
| **Snix / Tvix**   | Rust enum `Value`    | `Thunk` variant + force      | `Rc`-level only    | Closest peer; bytecode VM, no hash-consing, no strictness, no `.drv`-parity guarantee, defers optimization ([snix_eval docs](https://snix.dev/rustdoc/snix_eval/index.html)). |
| **GHC (STG)**     | tagged closure ptr   | dynamic pointer tag (§3)     | thunk-update sharing | Source of pointer tagging and the WHNF fast path; thunk update model. |
| **LuaJIT**        | 8-byte NaN-tag TValue| n/a (eager)                  | string interning   | Source of NaN-boxing; the i64 cautionary tale (§4.1). |
| **V8**            | tagged word (Smi/ptr)| n/a (eager)                  | hidden classes     | Tagged-pointer immediates; hidden classes for attrs (doc 09). |
| **OCaml / hashcons**| boxed/unboxed       | n/a                          | hash-consing       | Source of the maximal-sharing discipline (§5). |

The synthesis: aos-nix takes GHC's WHNF-in-the-pointer-bits, LuaJIT's
NaN-box-as-an-option, V8's tagged immediates, and OCaml-style hash-consing — and
makes all of them *total and sound* because Nix values are immutable and the eval
is a pure batch job. No prior Nix evaluator (C++ Nix, Snix/Tvix, hnix) combines
pointer-tagged WHNF, hash-consing, and a strictness-informed thunk
representation.

---

## 11. Unsafe surface and verification

This is the document where `unsafe` concentrates: tagged-union payload access,
pointer-tag bit-twiddling, NaN-box encode/decode, and raw heap pointers. Per the
project policy (see [integration with AOS](14-integration-with-aos.md)), this is
the *justified exception* to AOS's "avoid `unsafe` at all costs" rule, and it is
governed by three rules:

1. **Every `unsafe` block carries a `// SAFETY:` comment** stating the invariant
   it relies on (alignment ≥ 8 for pointer tagging; tag matches payload union
   member; NaN-box pattern is canonical).
2. **The tree-walk oracle stays safe.** The correctness oracle tier (see
   [execution tiers](08-execution-tiers-and-cranelift.md)) uses the 16-byte
   tagged value through *safe* accessors only (the union access is wrapped in
   checked constructors/getters that assert tag-payload agreement in debug
   builds). Miri and ASan run on the oracle in CI, exercising the conformance
   suite. The `unsafe` fast paths (pointer tags, NaN-box) are differentially
   checked against the oracle: any divergence is a bug in the optimized
   representation, caught before it can reach `.drv` output.
3. **No representation choice is observable.** Because the value representation is
   internal, the differential `.drv`-diff harness (see
   [differential testing and benchmarking](15-differential-testing-and-benchmarking.md))
   is a complete check: if tagged, pointer-tagged, NaN-boxed, and oracle runs all
   produce byte-identical `.drv` files across the AOS package set, the
   representation is correct *by the only definition that matters*.

---

## 12. Decisions, defaults, and open questions

**Decided (baseline):**

- 16-byte tagged `Value`; full `i64` and `f64` inline; heap forms behind
  `NonNull` pointers (§2).
- Pointer tagging of the low 3 bits for the thunk `FORCED` shortcut and optional
  small-constructor info (§3).
- Hash-consing of strings, symbols, small/recurring attrsets, and
  derivation-environment values, with the structural hash stored in the object
  header and used for both O(1) equality and the incremental cache key (§5).
- Three-tier hashing: xxh3 in-process, blake3 for the durable shared cache,
  SHA-256 only for Nix-observed hashes (§5.4).
- String context as an interned COW bitset of store-path ids, included in the
  string cons key (§8).
- Thunk state machine `Suspended → Blackhole → Forced`, atomic word,
  strictness/cardinality analysis collapsing it where provable (§6).

**Deferred to measurement (optimization):**

- NaN-boxing — most likely as approach (2), boxing only inside homogeneous
  nursery containers, gated on a measured nursery-density win that justifies the
  `unsafe` cost (§4.1).
- Small-constructor pointer-tag encoding for lists/attrs (§3, §7).
- The exact intern-on-promotion threshold for large composites (§5.3).

**Open questions:**

- *NaN-box payoff* (§4.1): does it survive the i64-box branch once the allocator
  and GC are in place? Research-grade; unproven.
- *Cons-table sizing under the daemon GC* (§5.5): the weak-table scavenge cost
  in Tier B is unmeasured; if it dominates, we may restrict hash-consing to
  strings + symbols + derivation-env values and drop opportunistic composite
  interning.
- *Context-bitset vs. sorted-smallvec crossover* (§8): the right small-set
  representation depends on the real distribution of context sizes in the AOS
  package set, which we will measure with the differential harness instrumented
  to dump context cardinalities.

None of these open questions can affect `.drv` output: they are all internal
encoding choices, validated by the same acceptance gate
(see [compatibility constraints](02-compatibility-constraints.md)).

---

## Implementation checklist

Per-feature tracker for the value representation (tagged values, pointer tagging, NaN-boxing, hash-consing, thunk/string/list/container layout); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

Value representation has no observable effect on `.drv` output by construction (§11); the gate for every item is the differential `.drv` harness running the optimized representation against the safe tree-walk oracle, plus miri/ASan on the oracle.

### Tagged-value baseline (§2)

- [x] 16-byte tagged `Value` (`tag` word + `payload` word), `Copy`, register-pair-passable; full `i64`/`f64`/`bool` inline, heap forms behind `NonNull` (§2.2) — **P1**, `S-6`/`M-4` default (no NaN-box first). Implemented in `crates/aos-nix/src/value.rs` with `#[repr(C)]`, `Copy`, a private raw `u64` payload word, static size/alignment assertions, inline scalar constructors, and heap constructors requiring `NonNull<HeapObject>`; covered by `value_layout_is_two_machine_words`, `inline_values_roundtrip_through_checked_accessors`, and `heap_values_store_aligned_non_null_pointers`.
- [x] `ValueTag` taxonomy covering every Nix value form (int/float/bool/null/string/path/list/attrs/lambda/primop/external) plus the non-WHNF `Thunk` (§1, §2.2) — **P1**. Covered by `value_tag_discriminants_match_the_rfc_layout` and `nix_type_names_match_user_visible_types`.
- [x] `force` WHNF fast path: single tag-compare, predicted-not-taken branch, no heap load (§2.3) — **P1**. Implemented as `Value::is_whnf()` delegating to `ValueTag::is_whnf()` and as `TreeWalk::force_value` returning non-thunks before heap access; covered by `whnf_fast_path_is_a_tag_predicate`.
- [x] Safe checked accessors/getters asserting tag-payload agreement in debug builds for the oracle (§11) — **P1**, `S-17`. Implemented in `crates/aos-nix/src/value.rs`: scalar accessors (`as_int`, `as_float`, `as_bool`, `as_null`), heap accessors (`as_heap_ptr`, `as_*_ptr`), `validate_payload`, and raw getter debug assertions reject wrong tags, invalid bool/null payloads, null heap pointers, unaligned heap pointers, and inline/heap tag mismatches. Covered by `checked_accessors_reject_wrong_tags_and_invalid_payloads`, `validate_payload_reports_tag_payload_invariants`, `raw_getters_assert_payload_invariants_in_debug_builds`, and `heap_accessors_reject_invalid_raw_pointer_payloads`. The standing miri/ASan CI controls remain tracked by [14](14-integration-with-aos.md)'s safety-tooling rows rather than this representation row.

### Pointer tagging and the WHNF bit (§3)

- [ ] Pointer tagging of the low 3 bits of 8-byte-aligned heap pointers; the thunk `FORCED` shortcut bit (`b0`) skipping the atomic state load / slow-path call on the already-forced path (§3.1) — **P8**, `S-6`; benchmark-gated (rank-5 follow-up), IN SCOPE.
- [x] Current pointer-tagging precursor: `ratchet-value::value::tag` defines
      the 8-byte heap-pointer alignment contract, reserves the low three pointer
      bits, exposes the thunk `FORCED` shortcut bit (`b0`), and provides safe
      checked encode/decode helpers for tagged heap address words. Raw decoded
      words do not prove pointer provenance or liveness. This does not change
      the active 16-byte `Value` ABI or skip thunk-state loads yet.
- [ ] Optional small-constructor (0/1/2-element) inline encoding for small lists/attrs so `length`/single-key `select` skip a header load (§3, §7) — **P8**, measure-gated default-off; benchmark delta required (`C6`).
- [x] Current small-constructor layout precursor:
      `ratchet-value::value::small` classifies zero-, one-, and two-slot lists
      or attrsets as inline candidates and exposes checked inline payload helpers
      for list values and attr entries. Oversized constructors remain
      heap-backed; attr payloads reject duplicate keys; unused slots are null
      padding and carry no semantic meaning. The active `NixList`/`FlatAttrs`
      heap layout and observable iteration behavior are unchanged.
- [x] Current conservative thunk publication/read discipline: `ThunkCell` uses acquire loads for state and cached-value checks, an AcqRel `Suspended → Blackhole` claim CAS, Release stores when publishing `Forced` or resetting to `Suspended`, and reads cached WHNF only after observing `Forced`; this preserves the future parallel boundary while the P1 tree-walk result slot remains `Cell<Option<Value>>`/single-threaded (§3.1–§3.2). Covered by `eval::thunk::tests::*`, especially `finish_force_publishes_cached_value`, `already_forced_thunk_returns_cached_value_without_reclaiming`, `abort_force_resets_suspended_state`, and `dropped_claim_resets_suspended_state_for_error_unwind`, plus tree-walk memoization/reset tests such as `forcing_attr_value_thunks_memoizes_whnf_results`, `shared_thunks_emit_trace_once_when_forced_repeatedly`, and `failed_thunks_reset_and_are_retried`.
- [ ] Full RFC monotonic-`FORCED` fast path/proof: unsynchronized single-threaded fast reads if retained, the pointer-tag `FORCED` shortcut that skips the atomic load (tracked above), and the true parallel forcing acquire-load protocol with `loom`/Miri audit (§3.1–§3.2) — parallel acquire path **P3.5** (`C-12`, `R-4`).

### NaN-boxing variant (§4) — build-and-measure alongside the tagged baseline

- [ ] NaN-box encode/decode: quiet-NaN prefix + 3-bit tag + 48-bit payload, real `f64` stored verbatim, canonical-prefix normalization (§4) — **P8**, `M-4`/`Q-E`; built as a competing variant, selected by register-passing benchmark vs the 16-byte baseline (winner kept, not a stop gate).
- [x] Current NaN-box layout precursor: `ratchet-value::value::nanbox`
      defines the reserved negative quiet-NaN prefix, three-bit payload tags,
      48-bit payload mask, signed-small-int range, float normalization away from
      boxed patterns, checked heap-address/immediate/small-int encode-decode,
      and GC-facing heap-payload classification. It stores address bits only,
      makes no pointer-provenance or liveness claim, and does not change the
      active 16-byte `Value` ABI.
- [ ] The i64 resolution: box-only-large-integers vs the favored approach (2) NaN-box only inside homogeneous nursery containers vs the 128-bit do-nothing option (§4.1) — **P8**, `M-4` (research-grade, IN SCOPE); benchmark-selected.
- [ ] Precise-GC agreement on boxed pointers: GC value-scanner masks the tag, treats heap-pointer payloads as roots, never mistakes a real `f64` for a pointer (§4.2) — **P8**, depends on precise GC ([06](06-memory-management-and-gc.md) **P3**).

### Hash-consing / maximal sharing (§5)

- [ ] `intern(ConsTable, HeapObject)` with bottom-up structural hashing (children interned-and-hashed first), xxh3 key + structural-equality tiebreak, hash stored in the object header (§5.3, §5.4) — **P2**, `S-7`; enables O(1) equality and the incremental-cache key.
- [ ] Interning policy: always-intern strings/symbols/small+recurring attrsets/derivation-env values; intern-on-promotion for large composites; never-intern thunks/distinct-env lambdas/externals (§5.3) — **P2**, `S-7`; intern-on-promotion threshold `M`-gated.
- [x] Current Tier-A heap-local consing substrate: the tree-walk evaluator heap
      interns immutable strings, paths, list spines, and shape-aware flat
      attrsets in separate evaluator-local tables using `HotXxh3Hash` plus
      structural-equality confirmation. The active policy deliberately leaves
      lambdas, primops, and thunks uninterned and without stored structural
      hashes, so closure environment identity, partial-application records, and
      suspended work remain distinct. This is the current safe substrate only:
      no generic post-force interning for all immutable values, object-header
      hash ABI, O(1) equality for every value, durable value hash, promotion
      threshold, or weak-table GC integration yet. Covered by heap consing tests,
      including `lambdas_primops_and_thunks_are_not_hash_consed`.
- [ ] Three-function hashing split wired through the cons-table: xxh3 in-process, blake3 durable/shared, SHA-256 only Nix-observed — none leaking into `.drv` (§5.4) — **P2**, `S-15`; leak-invariant conformance ([12](12-incremental-evaluation-cache.md) §5.2).
- [ ] GC interaction: cons-table as arena-dropped set in Tier A; weak hash table scavenged-and-forwarded in Tier B (never resurrects garbage, pointers updated on move) (§5.5) — Tier A **P3**, Tier B weak-table **P3** (`M-12` sizing measure-gated).

### Thunk representation (§6)

- [x] `Thunk { state: AtomicU64, code, env }` with the serial `Suspended → Blackhole → Forced` machine (the subset of the parallel superset), blackhole infinite-recursion detection (§6) — **P1**, `S-6`/`C-12` (atomic word from day 1). Implemented as `EvalThunk { kind, cell }`: `EvalThunkKind::Node` stores the lowered body plus captured lexical/`with`/scoped-global environments, application/select variants store their deferred work, and `ThunkCell` stores the atomic state word plus cached WHNF result. Covered by `eval::thunk::tests::*`, `allocates_thunk_values_and_recovers_body`, `allocates_apply_thunk_values_and_recovers_work`, and tree-walk recursion/cache tests such as `evaluates_static_recursive_attrsets_with_lazy_self_scope`, `forcing_attr_value_thunks_memoizes_whnf_results`, `shared_thunks_emit_trace_once_when_forced_repeatedly`, and `failed_thunks_reset_and_are_retried`.
- [ ] Strictness-driven thunk deletion (worker-wrapper eager compile → no `Thunk` struct) and cardinality-driven collapse (single-entry → no blackhole/update machinery) (§6) — **P4**, `S-9`; analyses owned by [07](07-laziness-and-whole-program-analyses.md), reductions by [26](26-optimization-pass-catalog.md).

### Containers and strings (§7–§8)

- [x] `NixList`: length-prefixed contiguous `[Value]`, constant-time `elemAt`/`length`/iteration, intern-heavy; not assumed heap-resident (scalar-replaceable) (§7) — **P1** layout; scalar replacement **P4** ([07](07-laziness-and-whole-program-analyses.md)). The P1 safe baseline is implemented in `crates/aos-nix/src/list.rs` as an immutable `Vec<Value>` spine with Rust's length field plus `len`, `get`, `as_slice`, and exact-size iteration; tree-walk `builtins.length` and `builtins.elemAt` dispatch through those constant-time accessors. Covered by `list::tests::*`, `allocates_list_values_and_recovers_spine`, `evaluates_empty_list_literals_with_owned_heap`, `evaluates_non_empty_list_literals_with_lazy_elements`, `length_primop_returns_list_spine_length_without_forcing_elements`, `elem_at_primop_returns_indexed_element_without_forcing_other_elements`, and list-concat spine-preservation tests. The frozen flexible-array heap header remains future runtime-ABI work; small-constructor tags, hash-cons interning, and scalar replacement remain tracked by separate unchecked optimization rows.
- [x] `NixString { bytes, context }`: byte string + interned COW-bitset string context; context union on `+`/interp; context included in the cons key so identical-bytes/different-context strings do not collapse (§8) — **P1** correctness (string contexts are `.drv`-observable, `S-13`); bitset-vs-smallvec crossover `M-13` (measure-gated, IN SCOPE). The P1 correctness baseline is implemented in `crates/aos-nix/src/string.rs` as `NixString { bytes: Vec<u8>, context: StringContext }`, with `StringContext` stored as a sorted, deduplicated vector of context elements; `NixString::concat`, string interpolation, and string `+` union contexts, `getContext`/`appendContext`/`unsafeDiscardStringContext` round-trip and clear contexts, and derived equality/hash include both bytes and context so identical bytes with different contexts remain distinct at representation level. Covered by `string::tests::*`, `preserves_context_bearing_strings`, configured C++ Nix string-context parity tests, `string_interpolation_evaluates_concatenates_and_unions_context`, `string_add_unions_contexts`, `substring_and_replace_strings_preserve_contexts`, and derivation context tests. Interned store-path ids and the COW bitset/smallvec representation remain future work; the store-path string hash-consing slice is tracked separately below. → string-context moves to `aos-nix-dialect` in Phase 1b ([28](28-generalization-and-language-dialects.md) §10): `ratchet-value` keeps the generic tagged value + hash-consing, the context bitset + union-on-concat semantics become the Nix dialect's, and the cons key takes the dialect-supplied context discriminator.
- [x] Aggressive byte-level hash-consing of store-path strings (§8) — **P2**, `S-7`. Implemented as a deliberate superset in the Tier-A evaluator heap: all heap strings and path values use separate cons tables keyed by `NixString::structural_hash_xxh3` and confirmed by full structural equality before reusing a canonical `Value` handle. The key includes bytes plus string context, so identical bytes with different contexts do not collapse, and path values remain in a separate namespace from string values. The same heap substrate also conses list spines by raw child `Value` identity and flat attrsets by shape id, source/lexicographic order metadata, binding positions, and raw child `Value` identity. The current hot cons-table hash is typed as `cache::hashing::HotXxh3Hash`, so heap records and cons buckets no longer store naked `u64` structural hashes. Covered by `identical_string_values_reuse_heap_record`, `identical_path_values_reuse_heap_record`, `identical_string_bytes_with_different_contexts_do_not_collapse`, `string_and_path_cons_tables_are_separate`, list/attr heap-consing tests, `structural_hash_covers_bytes_and_context`, and `cache::hashing::tests::hot_hash_is_stable_for_identical_hashable_values`; generic post-force interning policy, durable blake3 value hashing, weak-table GC interaction, and object-header hash ABI work remain tracked by the unchecked hash-consing rows above. → the generic byte-level hash-consing stays in `ratchet-value`; the context portion of the cons key becomes a dialect-supplied discriminator when string-context moves to `aos-nix-dialect` in Phase 1b ([28](28-generalization-and-language-dialects.md) §10).

### Verification (§11)

- [x] `// SAFETY:` invariant comments on every `unsafe` block (alignment ≥ 8, tag-payload agreement, canonical NaN-box pattern) (§11) — every phase touching the representation, `S-17`. The current safe tree-walk value-representation baseline is stronger: `crates/aos-nix/src/lib.rs` has `#![forbid(unsafe_code)]`, `cargo check --manifest-path crates/Cargo.toml -p aos-nix --lib` passes under that lint, and `rg 'unsafe\\s*\\{|unsafe fn|unsafe impl' crates/aos-nix/src` finds no representation unsafe blocks to annotate. Future pointer-tag, NaN-box, GC, or JIT unsafe fast paths remain unchecked until implemented and must add per-block `// SAFETY:` invariants as part of those feature rows.
- [ ] Differential check of every `unsafe` fast path (pointer tags, NaN-box) against the safe oracle: byte-identical `.drv` across the AOS package set is the complete correctness definition (§11) — gated by the differential harness in every phase.

## References

- Simon Peyton Jones, *Implementing lazy functional languages on stock hardware:
  the Spineless Tagless G-machine*. Microsoft Research.
  <https://www.microsoft.com/en-us/research/wp-content/uploads/1992/04/spineless-tagless-gmachine.pdf>
  (WHNF, tagless closures, the basis for pointer tagging and the force protocol.)
- Marlow, Yakushev, Peyton Jones, *Faster laziness using dynamic pointer
  tagging* (ICFP 2007) — background via the STG literature above; dynamic pointer
  tagging uses spare low pointer bits to encode evaluatedness / constructor tag.
- LuaJIT, *NaN-tagging / 64-bit integer hack*: <https://github.com/LuaJIT/LuaJIT/issues/182>
  (why a NaN-box payload tops out at ~52 bits and cannot hold a full `i64`).
- Andy Wingo, *Value representation in JavaScript implementations*:
  <https://wingolog.org/archives/2011/05/18/value-representation-in-javascript-implementations>
  (tagged pointers, NaN-boxing trade-offs across V8/JSC/SpiderMonkey).
- Piotr Duperas, *NaN boxing or how to make the world dynamic*:
  <https://piotrduperas.com/posts/nan-boxing/>
- *Hash consing* (Wikipedia): <https://en.wikipedia.org/wiki/Hash_consing>
  (maximal sharing, O(1) pointer equality from physical equality).
- *Efficient Symbolic Computation via Hash Consing* (arXiv, 2025):
  <https://arxiv.org/html/2509.20534v1>
- Filliâtre & Conchon, *Type-safe modular hash-consing*:
  <https://www.researchgate.net/publication/221057062_Type-safe_modular_hash-consing>
  (bottom-up hashing, weak hash tables, GC interaction).
- Snix `snix_eval` value/thunk documentation:
  <https://snix.dev/rustdoc/snix_eval/index.html> and tvix-eval `Thunk`:
  <https://docs.tvix.dev/rust/tvix_eval/value/thunk/struct.Thunk.html>
  (peer Rust Nix evaluator value/thunk representation; no hash-consing,
  no strictness, optimization deferred).
