# RFC-0007 - Primops and the Runtime ABI

> Part of the RFC-0007 aos-nix documentation set. This document specifies the
> *runtime substrate* of the evaluator: the ~120 builtin primitive operations
> ("primops"), the symbol table through which compiled code reaches them, the
> perfect-hash dispatch for builtin lookup, the semantics and caching of
> `import`, and the single uniform calling convention (the runtime ABI) that
> stitches the tree-walking oracle, the Cranelift JIT tiers, and the garbage
> collector into one coherent system.
>
> Cross-references use relative filenames: see
> [value representation](05-value-representation.md),
> [memory management and GC](06-memory-management-and-gc.md),
> [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md),
> [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md),
> [derivation and store compatibility](11-derivation-and-store-compatibility.md),
> and [the incremental evaluation cache](12-incremental-evaluation-cache.md).

---

## 1. Why this layer is load-bearing

The builtins are not an afterthought bolted onto a language core; in Nix they
*are* a large fraction of the language. `nixpkgs` is, to a first approximation,
a giant fixpoint over `builtins.derivationStrict`, `import`, `map`, `genList`,
`foldl'`, `listToAttrs`, the string primitives, and `builtins.hashString` /
`builtins.toJSON`. An evaluator that is fast at thunk forcing but slow at
builtins is slow at the only workload that matters.

This places three hard requirements on the runtime layer:

1. **Bug-for-bug compatibility.** Every primop must reproduce C++ Nix
   semantics *exactly* — including argument-forcing order, error messages where
   they are observable, string-context propagation, and the deterministic attr
   ordering that feeds `derivationStrict`. A primop that forces arguments in the
   wrong order, or that drops a string-context element, produces a different
   `.drv`, a different store path, and a total cache miss that rebuilds the
   from-source toolchain (see
   [compatibility constraints](02-compatibility-constraints.md)). The
   acceptance gate is the differential harness, not a unit test.

2. **A single uniform ABI.** The tree-walk oracle (tier 0), the Cranelift
   baseline JIT (tier 1), and the optimized JIT (tier 2) must all be able to
   call a primop, and a primop must be able to call back into `force`,
   `select_ic`, and the allocator without knowing which tier called it. There
   is exactly one calling convention. A primop is "just Rust" that obeys it.

3. **Indirection through symbols, not addresses.** Compiled code never embeds
   the address of a primop, an allocator, or a force routine as a baked-in
   constant. It references a *symbol name*; the JIT resolves that name through a
   runtime symbol table at link time. This is what lets the GC strategy swap
   (bump arena ↔ generational copying, see
   [memory management](06-memory-management-and-gc.md)) without recompiling a
   single line of JIT output, and what lets the tree-walk oracle and the JIT
   share one implementation of every builtin.

The rest of this document specifies these three things and the cross-cutting
machinery (perfect hashing, `import` caching) that makes them fast.

> **Primops are the dialect escape hatch.** Under the `ratchet` Core/dialect
> factoring (see [generalization and language dialects](28-generalization-and-language-dialects.md)
> §5), the `PrimOp` node and the runtime symbol-table mechanism described here are
> *generic engine machinery* (`ratchet`): an indexed, statically-known escape
> hatch baked at lowering through which a dialect reaches ops beyond Core. The
> *concrete* ~120-builtin set in this document is the Nix dialect's, registered
> into the generic ABI mechanism by `aos-nix-dialect`. `derivationStrict` is, in
> that lens, a distinguished *effectful* primop of the Nix dialect — the engine
> sees only an indexed escape-hatch symbol, not anything Nix-specific.

---

## 2. The uniform runtime ABI

### 2.1 The one calling convention

Every entity that compiled code can *call* — a primop, a user lambda's compiled
body, a runtime helper like `force` — presents the same C ABI signature:

```rust
/// The single calling convention shared by tree-walk, baseline JIT, and
/// optimized JIT. `Runtime` is the evaluator's mutable world (heap, symbol
/// table, caches, GC state). `Env` is the captured environment (the closure's
/// slot vector). Additional `Value` arguments are passed positionally.
///
/// # Safety
/// Callers must pass a valid `*mut Runtime` and a valid `*const Env` for the
/// callee's expected arity. The return `Value` is owned by the runtime heap.
pub type PrimopFn = unsafe extern "C" fn(rt: *mut Runtime, env: *const Env) -> Value;

pub type PrimopFn1 = unsafe extern "C" fn(rt: *mut Runtime, env: *const Env, a0: Value) -> Value;
pub type PrimopFn2 = unsafe extern "C" fn(rt: *mut Runtime, env: *const Env, a0: Value, a1: Value) -> Value;
pub type PrimopFn3 = unsafe extern "C" fn(rt: *mut Runtime, env: *const Env, a0: Value, a1: Value, a2: Value) -> Value;
```

The contract, stated precisely:

- **`rt: *mut Runtime`** — the ambient world. Threading the runtime as an
  explicit first argument (rather than a thread-local or a global) keeps primops
  re-entrant and makes parallel forcing (see
  [parallel evaluation](13-parallel-evaluation.md)) tractable: each worker can,
  in principle, carry its own `Runtime` view while sharing the immutable
  interned tables. It also matches how `rustc_codegen_cranelift` and the
  Cranelift JIT demo thread state explicitly rather than relying on hidden
  globals.

- **`env: *const Env`** — the lexical environment as a flat slot vector indexed
  by the de Bruijn-style indices the frontend assigned (see
  [frontend and IR](04-frontend-parser-and-ir.md)). A primop that takes no Nix
  arguments still receives `env` so that partially-applied builtins and
  closures share one shape.

- **`Value`** — a 16-byte tagged value in the first cut, NaN-boxed as a measured
  optimization (see [value representation](05-value-representation.md)). Because
  the value is at most 16 bytes, Cranelift passes it in a pair of registers on
  x86-64 SysV and AArch64 AAPCS, so primop calls touch no extra memory for
  argument marshalling. This is the concrete reason the value layout and the ABI
  are co-designed: the ABI is cheap *because* the value fits in registers.

- **`unsafe extern "C"`** — `extern "C"` so Cranelift can emit a normal call to
  a symbol with a stable, non-Rust-mangled signature; `unsafe` because the
  pointers are raw and the heap is manually managed. This is the justified
  exception to AOS's "avoid unsafe at all costs" rule (see
  [integration with AOS](14-integration-with-aos.md)): every such function
  carries a `// SAFETY:` comment, and the safe tree-walk oracle is what miri and
  the sanitizers run against.

Current status: the tree-walk evaluator keeps the P1 oracle stricter than that
future ABI by compiling `aos-nix` with `#![forbid(unsafe_code)]`. There are no
raw runtime-call boundaries in this crate today; the only `unsafe` spellings in
the source tree are Nix builtin names such as `unsafeGetAttrPos` and
`unsafeDiscardStringContext`. The `unsafe extern "C"` wrappers, their
`// SAFETY:` comments, and sanitizer/miri gates remain tied to the future
runtime/JIT ABI rows.

### 2.2 Arity, currying, and over/under-application

Nix functions are unary and curried; `builtins.map f xs` is
`(builtins.map f) xs`. Builtins, however, are most naturally written as
multi-argument Rust functions. We bridge this exactly as C++ Nix and Snix do:
each primop carries a static **arity** and is wrapped in a *partial-application
value* (a `PrimopApp`) that accumulates arguments until the arity is reached,
then performs the call.

```rust
/// A primop together with already-supplied arguments. A `Value::PrimopApp`
/// with `args.len() == primop.arity` is immediately reducible; below that it
/// behaves as a normal (forced) function value.
pub struct PrimopApp {
    pub primop: &'static Primop,
    pub args: SmallVec<[Value; 3]>, // most builtins are arity <= 3
}
```

The forcing machinery treats a saturated `PrimopApp` like any other redex: it
calls the underlying `PrimopFnN` with the collected arguments. An *under*-applied
primop is a perfectly good WHNF value (a function), exactly as in C++ Nix —
`builtins.map` on its own is a value you can pass around. This matters for
compatibility: code that relies on partial builtin application (and `nixpkgs`
does, constantly, e.g. `map (x: ...)` pipelines) must see the same value
identity behavior.

The wrapper is generated once per primop from its declared arity; tier-2 can
*inline* the wrapper away at saturated call sites it can prove are monomorphic,
collapsing `map f xs` into a direct call to the arity-2 entry point — an
optimization neither C++ Nix nor Snix's bytecode VM performs, and one that is
sound here precisely because builtins are pure and their arities are fixed at
compile time.

### 2.3 Argument forcing is part of the contract

A subtle but critical compatibility point: **the order and timing of argument
forcing is observable** and must match C++ Nix. `builtins.add a b` forces `a`
then `b`; `builtins.elemAt xs n` forces the list then the index; `x // y`
forces both operands to attrsets. Where Nix is lazy in an argument (e.g.
`builtins.seq` forces only its first argument to WHNF, `builtins.deepSeq` forces
recursively), aos-nix must be lazy in exactly the same place.

We encode this not as convention but as the *body of each primop*: the primop
receives values that may be thunks and calls `rt.force(v)` (a runtime symbol,
§3) at exactly the points C++ Nix's `state.forceValue` is called in
`primops.cc`. The differential harness (see
[differential testing](15-differential-testing-and-benchmarking.md)) catches any
divergence because forcing order changes which `builtins.trace` lines fire and,
more importantly for the gate, which thunks evaluate and in what order errors
surface.

The current tree-walk implementation keeps that contract at the same boundary:
static direct calls and first-class `PrimopApp` calls both enter the builtin
body with lazy `Value`s, and each builtin forces only the positions C++ Nix
forces. Focused tests cover strict numeric/comparison arguments, lazy
`seq`/`deepSeq` boundaries, list combinator order, string-context and hashing
argument order, import/path effects, trace firing, and failed-thunk retry; the
configured C++ Nix oracle suites exercise the same direct and first-class
surfaces. Future JIT inlining must preserve this exact body-level contract.

```text
  PRIMOP CALL FRAME (uniform across tiers)
  ┌──────────────────────────────────────────────────────────┐
  │ caller (tree-walk OR JIT-emitted call site)               │
  │   value a0..an already evaluated to WHNF *iff* the primop  │
  │   is strict in that position; otherwise passed as a thunk  │
  │                                                            │
  │   call  <symbol "nix.builtin.<name>">(rt, env, a0..an)     │
  └───────────────┬────────────────────────────────────────────┘
                  │ extern "C", Value in registers
                  ▼
  ┌──────────────────────────────────────────────────────────┐
  │ primop body (plain Rust)                                  │
  │   rt.force(a0)  // strict positions, matching primops.cc  │
  │   ...                                                      │
  │   rt.alloc_*(...) via runtime symbol  // never bakes addr  │
  │   return Value                                            │
  └──────────────────────────────────────────────────────────┘
```

---

## 3. The runtime symbol table

### 3.1 What lives in it

The symbol table itself — the ABI surface and its codegen-side registration —
is part of the `ratchet` engine (`ratchet-jit`; see
[generalization and language dialects](28-generalization-and-language-dialects.md)
§3): the *mechanism* for declaring and resolving runtime symbols is generic, while
the `nix.builtin.*` entries it carries are *dialect-registered* symbols supplied
by `aos-nix-dialect`. Compiled code reaches the outside world only through a
fixed, named set of **runtime symbols**. These fall into four groups:

| Group | Examples | Why a symbol (not an inlined address) |
|-------|----------|----------------------------------------|
| Allocation | `aos_alloc_thunk`, `aos_alloc_attrs`, `aos_alloc_list`, `aos_alloc_string` | GC strategy swaps (bump arena ↔ generational) with zero JIT recompilation |
| Forcing / control | `aos_force`, `aos_force_deep`, `aos_blackhole_check` | One canonical force implementation shared by all tiers; deopt hooks here |
| Attrset access | `aos_select_ic`, `aos_has_attr`, `aos_update` (`//`) | Keyed selects/presence checks use runtime inline-cache cells; single-key `aos_has_attr` returns false for non-attr receivers; update is the shared shallow-merge slow path. See [hidden classes](09-attribute-sets-hidden-classes-and-inline-caches.md) |
| Builtins | `nix.builtin.map`, `nix.builtin.derivationStrict`, … (~120) | Shared between oracle and JIT; perfect-hashed dispatch (§4) |

The allocation indirection is the single most important design decision in this
layer. Tier A of the GC is a bump-pointer arena that never frees and is dropped
wholesale at process exit; Tier B is a precise generational copying collector
(see [memory management](06-memory-management-and-gc.md)). Both expose the same
`aos_alloc_*` symbols. JIT code emitted in a one-shot CLI run and JIT code
emitted in a long-lived daemon are *byte-identical*; only the resolved symbol
target differs. This mirrors how managed runtimes (HotSpot, V8) route all
allocation through a runtime stub so the collector can be replaced behind a
stable interface — but it is *more* effective here because Nix purity means the
collector never has to coordinate with finalizers or mutable object identity.

### 3.2 How symbols are registered with Cranelift

Cranelift's JIT (the `cranelift-jit` crate) resolves names that are *declared
but not defined* in a compiled module through a host-provided symbol table.
`JITBuilder` exposes `symbol(name, addr)` to bind a single name to a host
function pointer and `symbols(iter)` / `symbol_lookup_fn(...)` to bind many or
to install a fallback resolver. The JIT uses this table to satisfy external
references at finalize time, and the resulting function pointer remains valid
until the module's memory is freed.

The final native-call path registers the entire runtime symbol set once, at JIT
construction. Current implementation slices stop earlier at checked
address/provenance metadata and strict incomplete-plan gates until final
exported wrappers and trap transfer are ready.

```rust
/// Design target: install every runtime symbol the JIT can reference.
/// Called once when the `JITModule` is built; thereafter all compiled tiers
/// resolve `aos_*` and `nix.builtin.*` names through this table.
fn install_runtime_symbols(builder: &mut JITBuilder, rt: &Runtime) {
    // Allocation + control + attrset-access helpers.
    builder.symbol("aos_force",        aos_force        as *const u8);
    builder.symbol("aos_force_deep",   aos_force_deep   as *const u8);
    builder.symbol("aos_blackhole_check", aos_blackhole_check as *const u8);
    builder.symbol("aos_alloc_attrs",  aos_alloc_attrs  as *const u8);
    builder.symbol("aos_alloc_cons",   aos_alloc_cons   as *const u8);
    builder.symbol("aos_alloc_lambda", aos_alloc_lambda as *const u8);
    builder.symbol("aos_alloc_list",   aos_alloc_list   as *const u8);
    builder.symbol("aos_alloc_raw",    aos_alloc_raw    as *const u8);
    builder.symbol("aos_alloc_string", aos_alloc_string as *const u8);
    builder.symbol("aos_alloc_thunk",  aos_alloc_thunk  as *const u8);
    builder.symbol("aos_has_attr",     aos_has_attr     as *const u8);
    builder.symbol("aos_select_ic",    aos_select_ic    as *const u8);
    builder.symbol("aos_update",       aos_update       as *const u8);

    // All ~120 builtins, by canonical name.
    for p in PRIMOP_TABLE.iter() {
        builder.symbol(p.symbol_name, p.entry as *const u8);
    }
}
```

> **Verification note.** The exact builder method is `JITBuilder::symbol` (and
> `symbols` / `symbol_lookup_fn`); these are the documented entry points on
> `cranelift_jit::JITBuilder`, and `JITModule::get_finalized_function` returns
> the callable pointer. The historical `cranelift-simplejit::SimpleJITBuilder`
> was renamed to `cranelift-jit::JITBuilder`; aos-nix targets the current
> `cranelift-jit`. See References.

In the final registered path, every symbol is a real Rust function compiled into
the aos-nix binary. The *same* `aos_force` / `nix.builtin.map` implementation
backs both the JIT (reached via the symbol table) and the tree-walk oracle
(reached via a direct Rust call), so there is no second implementation to drift
out of compatibility.

### 3.3 Symbol naming and stability

Symbol names are part of an internal ABI, but they are *stable* internal ABI:
the JIT-emitted call to `nix.builtin.derivationStrict` must resolve to the same
Rust function across runs and across the persisted incremental cache (a
compiled-IR artifact persisted in run N must still link in run N+1, see
[incremental evaluation cache](12-incremental-evaluation-cache.md)). We
therefore freeze the naming scheme:

- Builtins: `nix.builtin.<name>` where `<name>` is the Nix-visible identifier
  (`map`, `genList`, `derivationStrict`, `__add` is exposed as both `add` and
  its `__`-prefixed alias where Nix does).
- Runtime helpers: `aos_<verb>[_<qualifier>]`.

The dot-qualified builtin names are not valid C identifiers, which is fine —
Cranelift's symbol table is a string map, not a C linker — and serves as a
deliberate guard against accidentally colliding with a host C symbol.

---

## 4. Perfect hashing for builtin dispatch

### 4.1 The dispatch problem

There are two distinct lookups, and they have different performance profiles:

1. **Name → primop, at compile time.** When the frontend resolves the
   identifier `map` in the `builtins` scope, or lowers `builtins.foldl'`, it
   must map a string to a `Primop`. This happens once per *occurrence in source*
   — tens of thousands of times for the whole AOS package set, but never in an
   inner loop.

2. **`builtins.<x>` select, at run time.** A `select` on the `builtins` attrset
   with a *dynamic* attr name (rare but legal, e.g. `builtins.${name}`) needs a
   runtime name→primop lookup.

Both want an O(1), collision-free, branch-light lookup over a *fixed, known-at-
build-time* key set of ~120 names. That is exactly the use case minimal perfect
hashing was invented for: the canonical motivating example in the literature
(and in `gperf`'s own documentation) is hashing reserved words / keywords of a
programming language.

### 4.2 The construction: compile-time perfect table

We generate the builtin lookup table from the same `define_builtins!` inventory
that declares the builtin metadata. The macro emits a sorted
`BUILTIN_DECLARATIONS` slice and a const-built `BuiltinLookupTable<N>` baked into
the binary. The table is not a general `HashMap`, and it is not generated by
`rust-phf`; it is a small fixed table tailored to the frozen builtin set:

```rust
pub struct BuiltinLookupTable<const N: usize> {
    displacements: [u16; N],
    slots: [u16; N],
}

const BUILTIN_LOOKUP: BuiltinLookup = BuiltinLookupTable::build(BUILTIN_DECLARATIONS);

pub static BUILTINS: BuiltinRegistry = BuiltinRegistry::new(
    BUILTIN_DECLARATIONS,
    &BUILTIN_LOOKUP,
);
```

`BuiltinLookupTable::build` partitions declarations by a primary hash bucket,
searches a small per-bucket displacement for a collision-free secondary slot,
stores the declaration index in `slots: [u16; N]`, and asserts at const-eval time
that every slot was filled exactly once. Lookup computes the candidate slot and
then performs the final spelling compare against the declaration name. That last
compare is still required: the table is collision-free for the declared key set,
but an absent key can still land in an occupied slot and must be rejected. The
result is the dispatch property we need — no startup construction, no probe
sequence, and one bounded candidate check for exact-name lookup.

### 4.3 Why this is more than a micro-optimization here

In C++ Nix the `builtins` set is built once into a `Bindings` and looked up via
the normal attrset path. aos-nix can do better because the builtin key set is
*closed and known at our build time*, whereas a user attrset is not. We exploit
the closed set twice:

- The frontend can resolve `builtins.<staticName>` (the overwhelmingly common
  case — `builtins.map`, `builtins.fetchurl`, `builtins.toJSON` are written
  literally) **entirely at parse/lower time** into a direct IR primop boundary
  for saturated calls, with no `builtins` attrset select left on that path. The
  perfect table backs the lowering; the runtime sees the registered builtin
  directly. The later Cranelift symbol call is tracked by the runtime-symbol-table
  and JIT checklist rows.

- The rare dynamic `builtins.${name}` stays on the ordinary attrset/select path
  and uses the same registry-backed exact-name lookup. Tier-2 speculation for
  monomorphic dynamic names remains a measured policy choice.

So perfect hashing is not merely "a fast map" — it is the mechanism that lets
the common saturated builtin call *skip* dynamic attrset lookup, becoming a
direct IR boundary today and, once the JIT ABI lands, a direct symbol-table call
site. This is the same move V8 makes when it turns a property load on a
well-known object into a direct reference, generalized by the fact that our
well-known object (`builtins`) is frozen at build time.

### 4.4 The `builtins` attrset itself

Despite the lowering above, the reified `builtins` attrset must still *exist* as
a value, because Nix code can bind it (`let b = builtins; in b.map`), pass it
around, and enumerate it (`builtins.attrNames builtins`). We materialize it
lazily as an ordinary attrset whose entries are the `PrimopApp` wrappers, with a
hidden class shared by all `builtins` references (see
[hidden classes](09-attribute-sets-hidden-classes-and-inline-caches.md)). Its
attribute *order* must match C++ Nix's `builtins` ordering exactly, because
`builtins.attrNames builtins` is observable and, transitively, could feed a
derivation. We pin that order from the frozen key set.

---

## 5. The ~120 builtins

### 5.1 Inventory and structure

aos-nix implements the full primop surface of the target C++ Nix version (on the
order of ~120 entries; the exact count is version-pinned and validated against
`builtins.attrNames builtins` of the reference `nix` in the differential
harness). They group as follows:

| Category | Representative primops |
|----------|------------------------|
| Arithmetic / comparison | `add`, `sub`, `mul`, `div`, `lessThan`, `bitAnd`, `bitOr`, `bitXor`, `ceil`, `floor` |
| Type predicates / coercion | `typeOf`, `isAttrs`, `isList`, `isFunction`, `isString`, `isInt`, `isFloat`, `isBool`, `isNull`, `isPath`, `toString`, `toPath` |
| Lists | `map`, `filter`, `foldl'`, `genList`, `elemAt`, `elem`, `head`, `tail`, `length`, `concatLists`, `concatMap`, `sort`, `partition`, `groupBy`, `all`, `any`, `genericClosure` |
| Attrsets | `attrNames`, `attrValues`, `getAttr`, `hasAttr`, `removeAttrs`, `listToAttrs`, `intersectAttrs`, `catAttrs`, `mapAttrs`, `functionArgs`, `zipAttrsWith` |
| Strings | `substring`, `stringLength`, `replaceStrings`, `concatStringsSep`, `split`, `match`, `splitVersion`, `compareVersions`, `unsafeDiscardStringContext`, `getContext`, `appendContext`, `hasContext`, `addDrvOutputDependencies` |
| Hashing / encoding | `hashString`, `hashFile`, `toJSON`, `fromJSON`, `toXML`, `toBase32` (where present) |
| I/O / impure (eval-time) | `readFile`, `readDir`, `pathExists`, `readFileType`, `path`, `filterSource`, `fetchurl`, `fetchTarball`, `fetchGit`, `findFile`, `getEnv`, `trace`, `traceVerbose` |
| Control / laziness | `seq`, `deepSeq`, `tryEval`, `throw`, `abort`, `addErrorContext`, `break` |
| Imports / scope | `import`, `scopedImport` |
| Fixpoint / misc | `genericClosure`, `functionArgs`, `currentSystem`, `currentTime`, `nixVersion`, `langVersion`, `storeDir`, `placeholder` |
| **Derivations** | `derivationStrict`, `outputOf`, `unsafeDiscardOutputDependency` |

Each is a plain Rust function obeying the §2 ABI. The list above is illustrative;
the *authoritative* set is whatever `builtins.attrNames builtins` reports for the
pinned `nix` version, and the harness fails the build if aos-nix's set differs.

### 5.2 The compatibility-critical primops

A handful of primops are disproportionately dangerous because a tiny semantic
slip changes a `.drv`:

- **`derivationStrict`** — the heart of compatibility. It collects the
  environment in *deterministic attr order*, builds a `nix-compat`
  `Derivation`, serializes it as ATerm, computes input-addressed (and CA)
  output paths with SHA-256, and writes the `.drv`. This is large enough to own
  its own document; see
  [derivation and store compatibility](11-derivation-and-store-compatibility.md).
  From the ABI's perspective it is just another primop, but it is the one whose
  output the acceptance gate diffs byte-for-byte.

- **String-context primops** — `getContext`, `appendContext`,
  `hasContext`, `unsafeDiscardStringContext`, `addDrvOutputDependencies`,
  `unsafeDiscardOutputDependency`. String contexts are interned copy-on-write
  bitsets of store-path ids that flow through every string operation and are
  read by `derivationStrict` to compute a derivation's input set (see
  [value representation](05-value-representation.md) and
  [derivation compatibility](11-derivation-and-store-compatibility.md)). The
  *general* string primops (`substring`, `replaceStrings`, `concatStringsSep`,
  `++` on strings, interpolation) must **union** contexts exactly as C++ Nix
  does. A dropped context element silently changes a derivation's inputs.

- **`hashString` / `hashFile` / `toJSON`** — feed derivation attributes
  directly. Byte-exact output (including `toJSON`'s key ordering and number
  formatting, and the SHA-256/SHA-1/MD5 digests) is required.

- **`sort`** — Nix's `sort` is a specific stable-comparison algorithm whose
  result order is observable when the comparator yields ties; it must match.

These get *adversarial* differential coverage, not just example-based tests.

### 5.3 Strict-fold and the worker/wrapper payoff

`foldl'` deserves a note because it shows how this layer cooperates with the
whole-program analyses (see
[laziness and analyses](07-laziness-and-whole-program-analyses.md)). `foldl'` is
*strict in the accumulator* — that is its entire reason for existing over
`foldl`. The primop forces the accumulator on every step. When strictness
analysis has already determined that the accumulator is strict (which `foldl'`
guarantees by construction), the worker/wrapper transform can compile the fold
body to operate on an *unboxed* accumulator with no per-step thunk allocation —
turning the canonical `nixpkgs` `foldl' (acc: x: ...) init list` pattern into a
tight loop. Neither C++ Nix nor Snix performs this; it is available to us
because `foldl'`'s strictness is statically known and Nix values are immutable.

### 5.4 `tryEval`, `throw`, and the error model

`tryEval` must catch exactly the errors C++ Nix's `tryEval` catches (assertion
failures, `throw`, `abort` is *not* caught) and no others, and must restore
evaluator state cleanly. In the tree-walk oracle this is implemented as a Rust
`Result` boundary: only `Thrown` and `AssertionFailed` are converted into
`tryEval`'s `{ success = false; value = false; }`; `abort`, type errors, missing
attrs, bounds errors, and other evaluator failures continue outward. In the JIT
tiers the same semantic boundary becomes a runtime symbol
(`aos_try_begin`/`aos_try_end`) that installs a catch frame, because we do *not*
want C++-exception-style unwinding through JIT frames. This is also where the
"catchable error" distinction (which Snix makes explicit) is encoded: only
catchable errors propagate as values into `tryEval`'s `{ success; value; }`
result; everything else aborts evaluation.

---

## 6. `import` and import caching

### 6.1 Semantics

`import path` parses and evaluates the Nix file at `path` and returns its value.
`scopedImport attrs path` is the same but extends the lexical scope of the
imported file with `attrs`. The compatibility-relevant facts, confirmed against
Nix's own source and docs:

- **`import` is memoized; `scopedImport` is not.** C++ Nix caches the *result*
  of importing a given path; importing the same file twice returns the cached
  value (and re-runs no `builtins.trace`). `scopedImport` deliberately does
  **not** memoize the evaluation result — the same file imported via
  `scopedImport` twice produces two distinct evaluations, observable via
  `builtins.trace` and side effects. aos-nix must reproduce this asymmetry
  exactly, or a `nixpkgs` that leans on import memoization for performance will
  diverge in behavior (and timing).

- **`import` of a directory** imports `<dir>/default.nix`.

- **`import` of a derivation / store path** forces the path (realising it if it
  carries a string context) and imports the resulting file — this is how
  `import (fetchTarball ...)` works.

### 6.2 The two-level cache

aos-nix layers two caches, keyed differently, because the parse artifact and the
evaluation result have different invalidation rules:

```text
  import "<path>"
        │
        ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 1. PARSE/COMPILE CACHE   key = source BLAKE3 + schema/flags│
  │    value = compiled IR (arena AST + scope-resolved slots)   │
  │    -> byte-identical source is parsed once; shared across   │
  │       runs (persisted, content-addressed; realpath metadata)│
  └───────────────────────┬───────────────────────────────────┘
                          │
                          ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 2. RESULT MEMO CACHE     key = realpath (canonicalized)     │
  │    value = the imported file's evaluated Value (a thunk     │
  │            forced at most once)                             │
  │    -> matches C++ Nix `import` memoization exactly          │
  │    -> NOT populated/consulted by scopedImport               │
  └───────────────────────────────────────────────────────────┘
```

The **parse/compile cache** is keyed on deterministic frontend inputs: source
bytes hashed with BLAKE3, the parse-cache schema version, and parser flags.
Realpath is recorded only as diagnostic metadata for this durable artifact, so
byte-identical modules can share the same persisted resolved AST and IR even
when they are reached through different paths. The evaluator remaps the cached
file-local IR at each import site so module-relative path bases still come from
the requested import target path before symlink canonicalization. The lower-level `FileParseMemo` helper also exposes an
in-process `(canonical realpath, BLAKE3(file bytes))` memo for path-backed
frontends, but ordinary tree-walk import currently talks directly to the
durable content-addressed cache.

The **result memo cache** reproduces C++ Nix's `import` memoization. It is keyed
on canonical path alone (matching Nix) and stores the *value*, so a second
`import` of the same file is a hash-map hit returning an already-forced (or
forcing-in-progress) thunk. `scopedImport` deliberately bypasses this level: it
allocates a *fresh* thunk evaluated under the extended scope every time, exactly
as Nix does. The current tree-walk implementation also bypasses the durable
parse cache for `scopedImport` and text-store imports; that keeps scoped global
injection and generated-source imports out of the ordinary import fast path
until their cache identity is modeled separately.

### 6.3 Interaction with the incremental cache

The completed P2 fast path is the in-process result memo plus the durable
frontend parse/compile cache above. The remaining cross-run incremental
evaluation row is the next layer described in
[incremental cache](12-incremental-evaluation-cache.md): imported-file results
should participate in early-cutoff memoization keyed on the file expression hash
plus captured environment. Editing a comment in an imported file would then
force a re-parse of that file but, after re-evaluation, yield the same
value-hash, allowing early cutoff to stop propagation to downstream importers.
`import` is the natural granularity boundary for that future layer because files
are the unit users actually edit.

### 6.4 `findFile` and the lookup path

`import <nixpkgs>` and `<...>` angle-bracket paths resolve through `findFile`
against the evaluator's configured Nix search path. For byte-identical `.drv`
output this must resolve to the *same* concrete store path C++ Nix would
resolve, so the native evaluator treats the configured entries as the parity
boundary: `NixEvalConfig` maps representable `NIX_PATH` strings to ordered
entries, the language conformance runner maps supported `-I` flags the same way,
models C++ Nix's hidden `<nix/...>` corepkgs lookup without reflecting it through
`builtins.nixPath`, and unrepresentable ambient search paths fall back rather
than guessing. Lexical `__nixPath` bindings override angle-bracket lookup for the
body that defines them, matching the upstream language fixture. The tree-walk
evaluator caches both positive and negative lookups per configured entry list,
lookup key, and lookup origin. In AOS practice the package set is pinned (flake or
pinned `NIX_PATH`), so this is deterministic, but the harness still diffs it
because a wrong `<nixpkgs>` resolution is a silent, catastrophic divergence.

---

## 7. End-to-end: a builtin call across the tiers

To make the ABI concrete, trace `builtins.map f xs` from source to result.

**Frontend (doc 04).** The lexer/parser produces `Select(Var "builtins", "map")`
applied to `f` and `xs`. Scope resolution recognizes `builtins` as the special
builtins scope and `map` as a static key; using the PHF (§4) it rewrites the
node to a direct primop reference `Primop(nix.builtin.map)` with arity 2,
applied to `f` and `xs`. No attrset lookup survives.

**Tier 0 (tree-walk oracle, doc 08).** The interpreter sees the saturated
primop application, forces neither `f` nor `xs` itself (map's primop is
responsible for forcing `xs` to a list and is lazy in the elements), and calls
the Rust function `nix_builtin_map(rt, env, f, xs)` directly. Inside, it forces
`xs`, allocates a result list via `aos_alloc_list` (a direct Rust call here),
and builds per-element thunks of `f elem`.

**Tier 1/2 (Cranelift JIT, doc 08).** The hot thunk containing this call is
compiled. Cranelift emits a `call` to the symbol `nix.builtin.map` (resolved via
the JIT symbol table, §3.2) with `(rt, env, f_val, xs_val)` in registers
(`Value` is 16 bytes → register pair). The same Rust `nix_builtin_map` runs;
inside it, its `aos_alloc_list` and `aos_force` calls are *also* symbol
references, so when this runs in a daemon the allocations route to the
generational collector with no change to the emitted code. Tier 2, if it has
proven the call monomorphic, may inline the `PrimopApp` wrapper and even the
list-spine construction, scalar-replacing the result list if escape analysis
shows it does not escape (doc 07).

**Result.** A list value, identical in structure and (after hash-consing, doc
05) often identical in *identity* to a structurally-equal list computed
elsewhere — which is what makes the value-hash cheap for the incremental cache.

The point of the trace is that *one* Rust implementation of `map` served all
three tiers, reached either by direct call or by symbol, with allocation and
forcing always indirected through symbols so the GC and tier machinery stayed
invisible to it.

---

## 8. Compatibility hazards specific to this layer

A consolidated checklist of where this layer can silently break the
byte-identical-`.drv` gate, each of which gets adversarial differential coverage:

1. **Forcing order** in strict primops (§2.3) — wrong order changes which thunk
   errors first and which `trace` lines fire.
2. **String-context propagation** through string primops (§5.2) — a dropped or
   spuriously-added context element changes a derivation's input set.
3. **`derivationStrict` attr ordering** (§5.2, doc 11) — must be the exact
   deterministic order C++ Nix collects env attrs in.
4. **`toJSON` / `hashString` byte output** (§5.2) — key order, number
   formatting, digest encoding.
5. **`sort` tie-breaking and stability** (§5.2).
6. **`import` memoization vs `scopedImport` non-memoization** (§6.1) —
   observable via `trace` and timing; affects which side effects run.
7. **`findFile` / `<nixpkgs>` resolution** (§6.4) — wrong store path → wrong
   everything.
8. **`builtins` attr order and membership** (§4.4) — `attrNames builtins` is
   observable and version-pinned.
9. **Error catchability in `tryEval`** (§5.4) — catching too much or too little
   changes evaluated values.
10. **Integer/float semantics** — Nix ints are `i64`; overflow, `div` truncation
    toward zero, and int/float coercion in arithmetic primops must match
    (relevant to the value layout choice, doc 05).

None of these are theoretical; each corresponds to a real C++ Nix behavior that
`nixpkgs` (and therefore the AOS package set) depends on.

---

## 9. Open questions and research-grade items

- **Dynamic-builtins surface.** Some downstream code uses
  `builtins.${name}` with a computed `name`; we fall back to the PHF at runtime
  (§4.3). It is an open question whether tier-2 can profitably speculate on a
  monomorphic `name` at such sites (PIC-style, doc 09) often enough to matter,
  or whether they are rare enough to leave as a slow path. *Measure first.*

- **Inlining the most expensive primops.** Whether to give Cranelift IR-level
  bodies (not just symbol calls) for a tiny hot core (`map`, `elemAt`,
  `length`, `concatMap`, `++`) is a measured policy choice. The benefit is removing
  the call and enabling cross-primop optimization; the cost is duplicating
  semantics out of the single Rust oracle, which risks compatibility drift. The
  default position is **symbol call only**, and we only special-case after the
  benchmark says so. This is the conservative reading of the measure-first
  discipline (doc 01).

- **`nix-compat` API churn.** `derivationStrict` depends on the `nix-compat`
  crate (from the Snix project) for ATerm and store-path hashing. That crate's
  API is not yet stable; we pin a git rev and expect to upstream fixes. Tracked
  in doc 11 and the risk register (doc 17).

- **Impure primops and the incremental cache.** `readFile`, `readDir`,
  `pathExists`, `getEnv`, `currentTime`, `fetchurl`/`fetchGit` are eval-time
  *effects*. Their results must be keyed into the incremental cache as explicit
  dependencies (a `readFile` result is invalidated when the file's content hash
  changes; `getEnv` when the variable changes; `currentTime` is, strictly, not
  cacheable and `nixpkgs` avoids it in pure-eval mode). Getting the dependency
  edges exactly right is the boundary between this layer and doc 12, and is
  marked research-grade there.

- **I/O primops and the concurrency runtime.** The *blocking* I/O primops —
  chiefly IFD (an `outPath` access that forces a derivation to build) and
  eval-time network fetchers — are the suspension points for the fiber-based
  concurrency model ([parallel evaluation](13-parallel-evaluation.md) §5.5):
  hitting one parks the fiber (freeing its worker) while the tokio reactor drives
  the I/O. The fast local reads in the table above (`readFile`/`readDir`/
  `pathExists`/local `findFile`) stay **synchronous** — a microsecond syscall is
  cheaper than a fiber suspend/resume.

---

## 10. Summary

The runtime layer rests on three pillars. **One uniform ABI** —
`extern "C" fn(*Runtime, *Env[, Value...]) -> Value`, with the 16-byte value
passed in registers — lets the tree-walk oracle and both Cranelift tiers call
primops and call back into the runtime identically. **One runtime symbol table**
— `aos_alloc_*`, `aos_force`, `aos_select_ic`, and `nix.builtin.*` registered via
`JITBuilder::symbol` — means compiled code never bakes in an address, so the GC
strategy and tier machinery swap underneath it invisibly, and every builtin has
exactly one Rust implementation shared by all tiers. **Perfect-hash dispatch**
over the frozen ~120-name builtin set lets the common `builtins.<static>` call
collapse into a direct symbol call at compile time, with an O(1) runtime fallback
for the dynamic case. `import` is memoized at two levels (content-addressed parse
cache + Nix-faithful result memo), `scopedImport` is deliberately not, and both
compose with the cross-run incremental cache that is, ultimately, where the
order-of-magnitude win lives. Every primop is held to the same unforgiving
standard as the rest of aos-nix: byte-identical `.drv`, exact string contexts,
SHA-256 store hashes — verified by the differential harness, never assumed.

---

## Implementation checklist

Per-feature tracker for the primops and the runtime ABI; master roll-up:
[implementation checklist (all phases)](22-implementation-checklist-all-phases.md).
Per the unlimited-budget mandate, every item here is in scope — including
research-grade ones — built in dependency order and gated by the differential
harness, never cut for scope.

### The uniform runtime ABI (foundation)

- [ ] One `unsafe extern "C"` calling convention `PrimopFn[N](rt: *mut Runtime, env: *const Env[, a0..an: Value]) -> Value`, 16-byte `Value` register-passed ([§2.1](#21-the-one-calling-convention)) — P6, `S-12`; gate: differential `.drv` harness.
- [x] Current uniform runtime-call ABI metadata precursor:
      `ratchet-core::runtime_abi` now exposes safe `RuntimeCallSignature`
      descriptors for compiled thunk bodies, compiled lambda bodies, and
      builtin primop wrappers up to the current declared first-class arity
      maximum. The descriptors pin the shared `extern "C"` convention, the
      `rt`/`env` prefix, positional `Value` arguments, a `Value` return, and the
      16-byte/two-register `Value` layout. Tests prove thunk/lambda shape,
      primop arity coverage, rejection of unsupported arities, and parity with
      the builtin declaration inventory. This is contract metadata only: it does
      not define `unsafe extern "C"` type aliases, export wrappers, register
      Cranelift symbols, or call through raw pointers.
- [x] Current builtin runtime-call preflight precursor:
      `ratchet-core::runtime_abi::runtime_builtin_call_manifest()` preserves
      sorted `nix.builtin.*` symbol order and classifies each declared builtin as
      a callable primop wrapper shape, a value-only builtin symbol, or an
      unsupported future arity. `runtime_builtin_call_preflight()` attaches the
      frozen `RuntimeCallSignature` for callable builtin symbols and reports
      value-only symbols such as `true`, `false`, `null`, and `builtins` as
      current gaps. Tests pin order parity with the runtime symbol manifest,
      representative callable arities, value-only gaps, and the unsupported
      arity path. This is still metadata only: no builtin `unsafe extern "C"`
      wrappers, raw-pointer dispatch, `JITBuilder::symbol` entries, or executable
      builtin addresses are implemented.
- [x] P1 safe tree-walk oracle contains no unsafe boundaries: `aos-nix` has `#![forbid(unsafe_code)]`, and source scans find no Rust `unsafe` in the evaluator crate beyond builtin names such as `unsafeGetAttrPos`. The `// SAFETY:` discipline for actual `unsafe extern "C"` runtime/JIT wrappers and the miri/sanitizer CI gate remain future P6 work with the unchecked ABI/JIT rows ([§2.1](#21-the-one-calling-convention)) — P1 complete / P6 pending, `S-17`; gate: miri/sanitizer CI on the safe tree.
- [x] Arity + currying via `PrimopApp` partial-application value; under-application is a WHNF function value ([§2.2](#22-arity-currying-and-overunder-application)) — P1, `S-12`; gate: conformance 21. Implemented in the tree-walk oracle as `EvalPrimOp { symbol, args }` plus `EvalPrimOpArg`: builtin declarations expose `first_class_arity`, selecting a first-class builtin allocates an unapplied `EvalPrimOp`, applying fewer than `arity` arguments allocates a new partially applied `EvalPrimOp`, saturated first-class application dispatches through the registered builtin, and `ValueTag::Primop` is treated as a callable WHNF by `isFunction`/`typeOf`. Covered by `runtime::builtins::tests::builtin_declarations_record_first_class_arity_by_category`, heap primop record tests, `unary_type_predicate_primops_classify_whnf_values`, `type_of_primop_returns_nix_type_names`, `first_class_binary_builtin_selects_are_curried`, and broad first-class builtin tests for unary/binary/ternary primops including `map`, `filter`, `foldl'`, `scopedImport`, and `findFile`. This checkoff covers the tree-walk behavior required by the conformance-21 builtin catalog; the reusable external conformance-suite harness remains tracked in [15](15-differential-testing-and-benchmarking.md), and direct static-call/first-class forcing-order parity remains tracked by the next unchecked row.
- [ ] Tier-2 inlining of the `PrimopApp` wrapper at proven-monomorphic saturated call sites ([§2.2](#22-arity-currying-and-overunder-application)) — P7.
- [x] Tree-walk argument-forcing order/timing matched to `primops.cc` for the implemented P1 builtin surface: direct static calls and first-class `PrimopApp` calls share the same builtin bodies; strict numeric/comparison positions, lazy `seq`/`deepSeq`, list combinators (`map`/`filter`/`partition`/`foldl'`/`sort`/`elem`/`genList`), attr/string-context/hash/path/import effects, trace firing, and failed-thunk retry are covered by focused tests plus configured C++ Nix oracle suites. Future JIT inlining/lowering must preserve the same contract, the full `.drv` closure gate remains tracked in doc 15, and flake fetchers remain their own conditional rows in doc 21/doc 23 ([§2.3](#23-argument-forcing-is-part-of-the-contract)) — P1 complete / P6+ pending; gate: differential `.drv` harness (compatibility hazard #1).

### The runtime symbol table

- [ ] Fixed named symbol set registered once via `JITBuilder::symbol`: allocation (`aos_alloc_*`), forcing/control (`aos_force`/`aos_force_deep`/`aos_blackhole_check`), attrset access (`aos_select_ic`/`aos_has_attr`/`aos_update`), builtins (`nix.builtin.*`) ([§3.1](#31-what-lives-in-it)–[§3.2](#32-how-symbols-are-registered-with-cranelift)) — P6, `S-12`.
- [x] Current P3 tree-walk allocation-dispatch precursor: `EvalHeap` routes
      tree-walk heap object creation through `RuntimeAllocator::aos_alloc_*`
      entry-point-shaped Rust helpers for strings and paths, contiguous lists,
      attrs, lambdas, primops, thunks, and raw records; the installed strategy
      currently delegates to Tier-A `BumpArena`, preserving arena accounting
      while giving the safe oracle a single runtime allocation surface. This is
      direct Rust plumbing, not the frozen runtime/JIT ABI
      ([06](06-memory-management-and-gc.md) §2).
- [ ] Frozen runtime/JIT allocation indirection remains: `aos_alloc_*` exported
      as `unsafe extern "C"` or equivalent runtime symbols, registered with
      `JITBuilder::symbol`, bound to the selected allocator vtable at native
      startup, routed through every tier/primop allocation path, and swappable
      between bump-arena and generational bodies with byte-identical JIT output
      ([§3.1](#31-what-lives-in-it)) — P3/P6, `S-8`.
- [ ] Frozen, stable symbol naming scheme (`nix.builtin.<name>`, `aos_<verb>`) so persisted compiled-IR artifacts re-link across runs ([§3.3](#33-symbol-naming-and-stability)) — P2/P6, `R-14`.
- [x] Current stable-symbol naming precursor: `ratchet-core::runtime_abi`
      exposes the frozen builtin prefix `nix.builtin.`, the runtime-helper
      prefix `aos_`, typed helper-symbol declarations for the centralized
      current `aos_*` helper-name set, and a
      `Builtin::runtime_symbol()` view that renders every declared builtin as
      `nix.builtin.<visible-name>` with UTF-8 validation for future
      string-keyed JIT registration. `runtime_symbol_manifest()` now combines all
      helper and builtin symbols into one deterministic, lexicographically sorted
      `RuntimeSymbolManifestEntry` table, validates duplicate final names before
      registration, and tags helpers by `RuntimeHelperRole` while tagging builtin
      entries separately. Tests pin helper/builtin coverage, ordering,
      uniqueness, duplicate rejection, and representative builtin/helper entries.
      This is safe metadata only; no `unsafe extern "C"` wrappers,
      `JITBuilder::symbol` address registration, compiled artifact relinking, or
      native ABI entrypoints are claimed here.
- [x] Current runtime symbol binding-manifest precursor:
      `ratchet-oracle::runtime::helpers::runtime_symbol_binding_manifest()`
      consumes the core stable-symbol manifest and preserves its deterministic
      order while classifying each symbol as a currently bound safe helper, an
      unbound future helper role, or a builtin. Tests pin order parity with
      `ratchet-core`, exact bound-helper coverage, representative unbound helper
      roles, and builtin classification. This is status metadata only; it does
      not attach addresses, export native wrappers, register `JITBuilder`
      symbols, bind builtin bodies, or make compiled artifacts relinkable.
- [x] Current runtime symbol registration-preflight precursor:
      `runtime_symbol_registration_preflight()` derives a deterministic
      readiness report from the binding manifest: bindable allocation,
      call-control apply, attrset-access has-attr/select-IC/update, environment-access, forcing, and write-barrier helpers stay in runtime-manifest
      order, and missing
      helper/builtin bindings are reported in stable symbol order. The checked
      `runtime_symbol_registration_plan()` currently returns an incomplete
      registration error until error helpers and builtin
      executable bindings are added. Tests pin bindable-helper coverage,
      sorted gaps, representative missing helper roles, builtin gaps, and the
      incomplete-plan failure. This still does not register `JITBuilder` symbols,
      attach addresses, export wrappers, or relink compiled artifacts.
- [x] Current runtime symbol ABI-signature preflight precursor:
      `runtime_symbol_abi_signature_preflight()` combines the oracle's
      allocation/call-control/attrset-access/environment-access/forcing/write-barrier helper ABI metadata with
      `ratchet-core`'s builtin call-shape metadata in stable runtime symbol
      order. Callable builtin symbols now carry their frozen
      `RuntimeCallSignature` metadata in this preflight, while unbound helper
      roles and value-only builtin symbols remain missing. Tests prove helper
      parity with the safe registration preflight, builtin parity with the
      builtin call preflight, exact binding/gap projection order, representative
      callable builtin metadata, and current try-helper/value-only gaps. This is not
      executable ABI registration: no
      addresses, exported wrappers, `JITBuilder::symbol` calls, Cranelift
      lowering, or compiled artifact relinking are implemented.
- [x] Current runtime symbol ABI-signature plan precursor:
      `runtime_symbol_abi_signature_plan()` turns the ABI-signature preflight
      into a checked completeness gate: callers receive a
      `RuntimeSymbolAbiSignaturePlan` only once every runtime symbol has
      signature metadata. Today it returns an incomplete-plan error carrying the
      preflight because try-frame helpers and value-only
      builtins remain gaps. Tests pin the missing count, representative helper and
      value-only builtin gaps, preserved callable builtin metadata, and a
      synthetic complete conversion path. This is metadata gating only; no
      addresses, exported wrappers, `JITBuilder::symbol` calls, Cranelift
      lowering, or compiled artifact relinking are implemented.
- [x] Current runtime symbol native-target candidate preflight precursor:
      `runtime_symbol_native_target_candidate_preflight()` combines the stable symbol
      manifest, helper ABI signatures, helper Rust-callable availability, and
      builtin call-shape metadata into a target-readiness report. Helper symbols
      with allocation/call-control/attrset-access/environment-access/forcing/write-barrier callables are
      address-free symbol/role wrapper-generation candidates;
      error helpers, value-only builtins, and callable builtins
      without wrapper bodies remain gaps with builtin-wrapper blockers: missing
      wrapper body, runtime/env ABI decoding, native `Value` argument
      materialization, evaluator call-frame binding, active argument root
      registration, builtin dispatch binding, argument-forcing contract
      preservation, trap transfer, and native `Value` return materialization.
      Tests prove exact projection order, helper-callable parity,
      representative helper/value-only gaps, all callable builtin wrapper gaps
      and blockers, and the absence of helper-callable gaps today. This is
      readiness metadata only; no addresses, exported wrappers,
      `JITBuilder::symbol` calls, Cranelift lowering, or compiled artifact
      relinking are implemented.
- [x] Current runtime symbol native-target candidate plan precursor:
      `runtime_symbol_native_target_candidate_plan()` turns the address-free
      native-target candidate preflight into a checked completeness gate. It
      yields a `RuntimeSymbolNativeTargetCandidatePlan` only when every runtime
      symbol is a symbol/role candidate and currently returns an incomplete-plan
      error carrying the preflight while helper and builtin wrapper gaps remain.
      Tests pin the missing count, representative helper candidates,
      representative helper/builtin gaps, and a synthetic complete conversion.
      This is metadata gating only; no addresses, exported wrappers,
      `JITBuilder::symbol` calls, Cranelift lowering, or compiled artifact
      relinking are implemented.
- [x] Current runtime symbol native-export readiness gate:
      `runtime_symbol_native_export_preflight()` runs after address-free target
      candidacy and records current helper candidates as missing exported C ABI
      wrappers. It preserves family-specific blockers from allocation,
      call-control, attrset-access, environment-access, forcing, and write-barrier native-export preflights:
      missing final exported wrappers, runtime-context/environment-frame
      decoding, active force-root binding, thunk blackhole/force-cache
      integration, evaluator trap transfer, typed/native return materialization,
      allocation semantic-payload initialization, write-barrier GC-state
      extraction, and dispatch into the safe before-publish barrier path.
      It also preserves earlier builtin-wrapper blockers through nested
      native-target gaps. `runtime_symbol_native_export_plan()` still rejects as
      incomplete. This is safe readiness metadata only; no function is exported,
      no Rust callable becomes ABI-callable, no `JITBuilder::symbol` call runs,
      and no compiled artifact is relinked.
- [x] Current `ratchet-jit` ABI-boundary precursor:
      `ratchet-jit::abi` provides a JIT-side, address-free
      `JitRuntimeAbiInventory` copied from the `ratchet-core` runtime-call
      metadata source of truth. Runtime-symbol candidate gates stay in
      `ratchet-oracle` for now rather than making the JIT crate depend on the
      oracle stack. Tests pin thunk, lambda, and primop signature parity plus
      callable-kind coverage. This is a crate boundary and metadata adapter only;
      no `unsafe extern "C"` aliases, exported wrappers, raw-pointer calls, or
      `JITBuilder::symbol` registration are implemented; the narrow
      Cranelift-dependent signature adapter is tracked by the next item.
- [x] Current `ratchet-jit` CLIF-signature ABI precursor:
      `ratchet-jit::abi::clif_signature_for_runtime_call()` turns frozen
      `RuntimeCallSignature` metadata into Cranelift `Signature` values for the
      uniform runtime ABI. `rt` and `env` lower to host-pointer-sized CLIF
      parameters, while each runtime `Value` parameter or return lowers to two
      `i64` ABI slots behind a 16-byte/two-8-byte-word layout guard. Tests pin
      thunk, lambda, and primop arities 0-3. This is not executable ABI glue:
      no exported wrappers, raw-pointer dispatch, `cranelift-jit` module,
      `JITBuilder::symbol` registration, CLIF body lowering, or native call
      boundary is implemented.
- [x] Current `ratchet-jit` runtime-symbol inventory precursor:
      `ratchet-jit::symbols::jit_runtime_symbol_inventory()` exposes a JIT-side,
      address-free view of the `ratchet-core` runtime symbol manifest without an
      oracle dependency. It preserves stable manifest ordering, exposes
      symbol-presence and kind lookups, and tests pin exact core parity,
      representative helper/builtin kinds, sorted order, and mixed
      helper/builtin coverage. This is manifest metadata only; no
      candidate-readiness gates, executable addresses, exported wrappers,
      Cranelift lowering, or `JITBuilder::symbol` registration are implemented.
- [x] Current runtime symbol Rust-callable preflight precursor:
      `runtime_symbol_rust_callable_preflight()` consumes the stable runtime
      symbol manifest and attaches process-local Rust-callable helper metadata
      for currently covered allocation/call-control/attrset-access/environment-access/forcing/write-barrier helpers,
      while keeping error helpers and builtins in the
      missing-binding set. Tests prove helper-callable order, helper-symbol
      parity with the safe preflight, and gap parity with the incomplete
      registration report. This is not executable ABI registration: the
      addresses are Rust-callable metadata only, not exported wrappers,
      `JITBuilder::symbol` entries, or relinkable compiled-artifact targets.
- [x] Current `aos-nix` JIT address-candidate bridge:
      `aos_nix::jit::nix_jit_runtime_symbol_address_candidate_preflight()`
      projects oracle Rust-callable helper metadata into `ratchet-jit`
      `JitRuntimeSymbolAddressCandidate` values for currently covered
      allocation, call-control, attrset-access, environment-access, forcing, and write-barrier helpers, including
      `aos_blackhole_check`, and carries the
      oracle missing-binding set for unbound helpers and builtins. Tests prove
      those candidates are accepted by the JIT registration preflight and by the
      registered env-slot promotion path for `aos_env_get`. This is a safe
      process-local integration bridge only: it does not export C ABI wrappers,
      make addresses serializable or relinkable, cast finalized code pointers,
      dereference registered addresses, or call native code.
- [x] Current allocation ABI-signature precursor:
      `ratchet-oracle::runtime::alloc::RuntimeAllocationAbiSignature` records the
      success-path native parameter and typed pointer-result shape for every
      `aos_alloc_*` helper and resolves from the frozen symbol name. Tests keep
      that signature inventory aligned with `ratchet-core`'s allocation helper
      symbols. This remains metadata only; no exported wrappers,
      no executable trap-transfer wrappers, Cranelift registration, native
      startup binding, or compiled-symbol relinking is implemented here.
- [x] Current allocation-vtable precursor:
      internal `ratchet-oracle::runtime::alloc::RuntimeAllocationVTable`
      dispatch is selected from the installed `RuntimeAllocator` backend and
      carries typed safe Rust function pointers for every frozen `aos_alloc_*`
      route. The public tree-walk allocator entry points dispatch through that
      table before reaching the current Tier-A `BumpArena` bodies, and tests
      exercise both selected-table metadata and direct crate-internal vtable
      allocation calls. This is internal safe startup dispatch only; it does not
      export wrappers, perform native trap transfer, register Cranelift symbols,
      install a Tier-B table, or relink compiled artifacts.
- [x] Current allocation runtime-FFI trap-wrapper precursor:
      `ratchet-runtime-ffi::alloc::runtime_allocation_native_wrapper_bindings()`
      provides process-local trap-only `unsafe extern "C"` wrapper addresses for
      every frozen pointer-returning `aos_alloc_*` ABI. The wrappers abort for
      every call until runtime-context decoding, allocator extraction,
      safepoint/trap transfer, typed heap-pointer return materialization, and
      semantic payload initialization for cons/lambda/thunk payloads exist.
      `aos-nix` projects these addresses as runtime-FFI provenance for JIT
      address candidates and exposes the trap-wrapper's remaining
      native-export blockers there, proving the trap body exists while
      runtime-context decoding, trap transfer, typed pointer returns, and
      semantic payload initialization remain gated. The oracle native-export
      gate still rejects final registration. This is address/provenance
      metadata only; no wrapper allocates, initializes heap payloads, transfers
      traps, registers with `JITBuilder::symbol`, or becomes a final exported
      native ABI target.
- [x] Current runtime-helper failure-convention precursor:
      `RuntimeHelperBinding::failure_convention` pins every currently bound
      allocation, call-control, attrset-access, environment-access, forcing, and write-barrier helper as
      `TrapToEvaluator`, meaning the native ABI has no null-pointer or sentinel
      failure result: helpers return only on success, while allocation,
      call-control, attrset-access, environment-access, forcing, or barrier failures
      must transfer to evaluator trap/error machinery. Tests pin the convention for
      each `aos_alloc_*`, `aos_apply`, `aos_has_attr`/`aos_select_ic`,
      `aos_update`, `aos_env_get`, `aos_blackhole_check`, `aos_force`/`aos_force_deep`, and `aos_gc_write_barrier` symbol. This remains metadata
      only; exported wrappers, actual trap transfer, `JITBuilder::symbol`
      registration, and native startup binding remain open.

### Perfect-hash builtin dispatch

- [x] Compile-time perfect hash over the frozen builtin set, baked into the binary. The implementation uses the `define_builtins!` inventory to generate a `BuiltinLookupTable<N>` at compile time: primary buckets, per-bucket displacements, full-slot completion assertions, and exact-name lookup over the sorted registry; tests assert uniqueness, deterministic iteration, perfect slot coverage, and rejection of non-declared names ([§4.1](#41-the-dispatch-problem)–[§4.2](#42-the-construction-compile-time-perfect-table)) — P1, `S-12`.
- [x] Frontend lowering of static `builtins.<name>` saturated calls to direct IR boundaries. `IrLowerer` recognizes unshadowed top-level builtins and `builtins.<name>` selects, consults the registry's `BuiltinDirect` metadata, and lowers saturated unary/binary/ternary/direct-only forms to ordinary `IrKind::PrimOp` payloads or Nix dialect-op payloads such as `NIX_OP_DERIVATION_STRICT`; dynamic builtin scope, select defaults, shadowed `builtins`, and unsaturated first-class selects stay dynamic/first-class instead of pretending to be direct calls ([§4.3](#43-why-this-is-more-than-a-micro-optimization-here)) — P1.
- [ ] Runtime PHF fallback for dynamic `builtins.${name}`; tier-2 monomorphic-name speculation ([§4.3](#43-why-this-is-more-than-a-micro-optimization-here), [§9](#9-open-questions-and-research-grade-items)) — P7, `M-10`; gate: site-frequency profile.
- [x] Reified lazy `builtins` attrset (bindable/enumerable) with C++-Nix-pinned attr order. `BuiltinsValue` evaluates through the same registry, exposes selected builtins as first-class primop/lambda values or configured constants, preserves contextual availability for `currentSystem`/`currentTime`, and uses the sorted declaration order for `attrNames`; local and configured C++-Nix oracle tests cover `builtins.attrNames builtins`, `builtins.attrNames builtins.builtins`, `typeOf builtins.builtins`, absent lib names, and present unimplemented stubs ([§4.4](#44-the-builtins-attrset-itself)) — P1; gate: differential `.drv` harness (hazard #8).

### The ~120 builtins

- [x] Current tree-walk builtin inventory and dispatch substrate for §5.1: the
      §4 registry/perfect-table rows above provide the frozen declaration set,
      while `define_builtins!` records each builtin's execution strategy, direct
      lowering class, first-class arity, name scope, contextual availability, and
      native fallback feature. The safe `BuiltinExecutor` boundary routes direct
      and first-class tree-walk applications through typed primop enums and
      custom handlers, and pinned-oracle tests validate surface
      membership/order/availability plus present unimplemented stubs against
      `builtins.attrNames builtins`. This checkoff covers the current substrate
      and the doc 21 checked catalog rows only; `nix.builtin.*` runtime symbols,
      Cranelift/JIT wrappers, runtime PHF speculation, and the remaining full
      flake/fetchTree/getFlake protocol rows stay open ([§5.1](#51-inventory-and-structure)) — P1 complete / P6-P7 pending, `S-12`/`C-9`; gate: conformance 21.
- [ ] Full primop surface as §2 runtime/JIT ABI symbols: every completed
      builtin exposed as a `nix.builtin.*` `unsafe extern "C"` wrapper,
      registered through the runtime symbol table, and validated after the
      remaining doc 21 full-protocol rows close ([§2](#2-the-uniform-runtime-abi),
      [§3.1](#31-what-lives-in-it), [§5.1](#51-inventory-and-structure)) — P6,
      `S-12`/`C-9`; gate: conformance 21.
- [x] Compatibility-critical primops with adversarial coverage: `derivationStrict` is covered by the checked doc 11 wire-format/algorithm rows and the doc 21 builtin row; string-context primops and context-unioning are covered by configured C++ oracle tests plus focused coercion/string tests; `hashString`/`hashFile`/`toJSON` have configured C++ oracle coverage for bytes, key order, escapes, algorithms, and float formatting; `sort` matches C++ Nix's libc++ stable-sort/tie behavior with configured oracle and order-specific tests. The full transitive `.drv` closure gate remains tracked separately ([§5.2](#52-the-compatibility-critical-primops)) — P1, `S-13`; gate: differential `.drv` harness.
- [ ] `foldl'` worker/wrapper payoff: unboxed accumulator, no per-step thunk ([§5.3](#53-strict-fold-and-the-workerwrapper-payoff), [07](07-laziness-and-whole-program-analyses.md)) — P4, `S-9`.
- [x] `tryEval`/`throw`/`abort` tree-walk error model: `throw` and failed `assert` are catchable, `abort` and non-catchable evaluator errors propagate, `tryEval` is shallow, failed thunks reset and retry, and first-class `throw`/`abort` preserve the same classes. Implemented through the tree-walk `Result` boundary and covered by doc 20/doc 21 checked rows, focused control tests, and configured C++ control-flow/error-semantics oracle tests. The JIT catch-frame ABI (`aos_try_begin`/`aos_try_end`) remains future P6 work, not claimed here ([§5.4](#54-tryeval-throw-and-the-error-model)) — P1 complete / P6 pending; gate: conformance 21 (hazard #9).
- [ ] Inline hottest primops (`map`/`elemAt`/`length`/`concatMap`/`++`) as Cranelift IR bodies; default symbol-call only ([§9](#9-open-questions-and-research-grade-items)) — P6, `M-9`; gate: per-primop benchmark.

### `import` and import caching

- [x] Two-level cache: ordinary filesystem imports use a durable content-addressed parse/compile cache keyed by source BLAKE3 plus schema/flags, and a Nix-faithful result memo keyed by canonical realpath only. Cached import IR is remapped per import site so byte-identical modules reached from different directories still preserve module-relative path bases; tests cover durable hit/miss stats, remapping for formals/inherits/builtins/with-vars, and result reuse ([§6.1](#61-semantics)–[§6.2](#62-the-two-level-cache)) — P2, `S-12`; gate: differential `.drv` harness (hazard #6).
- [x] `import` is memoized, while `scopedImport` deliberately bypasses the result memo and re-evaluates under a fresh injected global scope. Current tree-walk `scopedImport` and text-store imports also bypass the durable parse cache; tests assert scoped imports trace twice and bypass parse-cache stats/artifacts ([§6.1](#61-semantics), [§6.2](#62-the-two-level-cache)) — P2; gate: conformance 21.
- [ ] Composition with the cross-run incremental cache; import as the early-cutoff granularity boundary ([§6.3](#63-interaction-with-the-incremental-cache), [12](12-incremental-evaluation-cache.md)) — P2, `S-14`.
- [x] `findFile` / `<nixpkgs>` resolution over configured search-path entries, including `builtins.nixPath` reflection, angle-bracket lookup, lexical `__nixPath` override, hidden C++ Nix `<nix/...>` corepkgs lookup, explicit `builtins.findFile`, prefix matching, ordered fallback, relative entries, path-value returns, pure/restricted filesystem policy, positive/negative lookup caching, representable `NIX_PATH` mapping in `NixEvalConfig`, and supported `-I` flag modeling in the language conformance runner. Unrepresentable ambient search paths still fall back explicitly rather than silently diverging; opt-in C++ Nix oracle tests cover the configured findFile/search-path cases ([§6.4](#64-findfile-and-the-lookup-path)) — P1; gate: differential `.drv` harness (hazard #7).

### Impure primops and the concurrency runtime

- [ ] Impure eval-time effects (`readFile`/`readDir`/`pathExists`/`getEnv`/`currentTime`/`fetchurl`/`fetchGit`) keyed as explicit content-hash inputs into the incremental cache; `currentTime` not cached ([§9](#9-open-questions-and-research-grade-items), [12](12-incremental-evaluation-cache.md)) — P2, `R-10`; gate: differential `.drv` harness (research-grade edge exactness).
- [ ] Blocking I/O primops (IFD, network fetchers) park the fiber via the tokio reactor; fast local reads stay synchronous ([§9](#9-open-questions-and-research-grade-items), [13](13-parallel-evaluation.md)) — P3.5, `C-16`/`C-27`; gate: loom.

### Compatibility-hazard gate

- [x] Current P1 focused hazard coverage exists for all ten §8 hazards (forcing
      order, context propagation, `derivationStrict` ordering,
      `toJSON`/`hashString` bytes, `sort`, import memoization, `findFile`,
      `builtins` order/membership, `tryEval` catchability, and int/float
      semantics). The checked rows in doc 10/doc 11/doc 20/doc 21, the
      configured C++ Nix oracle suites, and the property tests cover these
      hazard surfaces directly. This is focused/unit/property/configured-oracle
      coverage only; it is not the full transitive `.drv` closure acceptance
      gate and does not claim byte-green behavior over the AOS corpus ([§8](#8-compatibility-hazards-specific-to-this-layer)) — P1 surface coverage, `S-2`.
- [ ] Full adversarial differential `.drv` closure hazard gate: keep all ten
      §8 hazards byte-green over the auto-derived AOS package/system/toolchain
      corpus and its transitive closure before any default-on/cutover credit is
      claimed ([§8](#8-compatibility-hazards-specific-to-this-layer),
      [15](15-differential-testing-and-benchmarking.md) §8.1) — P1, `S-2`;
      gate: full differential `.drv` harness.

---

## References

- Cranelift JIT — `JITBuilder` / `JITModule` symbol registration and finalized
  function pointers:
  - <https://docs.rs/cranelift-jit/latest/cranelift_jit/struct.JITBuilder.html>
  - <https://docs.rs/cranelift-jit/latest/cranelift_jit/struct.JITModule.html>
  - cranelift-jit-demo (host symbols / `symbol` usage):
    <https://github.com/bytecodealliance/cranelift-jit-demo>
  - `rustc_codegen_cranelift` JIT driver (explicit symbol/runtime threading):
    <https://github.com/rust-lang/rust/blob/main/compiler/rustc_codegen_cranelift/src/driver/jit.rs>
- Perfect / minimal-perfect hashing for fixed keyword sets:
  - rust-phf (compile-time static maps, CHD): <https://github.com/rust-phf/rust-phf>
  - "rust-phf: the perfect hash function" (Mainmatter):
    <https://mainmatter.com/blog/2022/06/23/the-perfect-hash-function/>
  - gperf — A Perfect Hash Function Generator (Schmidt; reserved-word motivation):
    <https://www.dre.vanderbilt.edu/~schmidt/PDF/gperf.pdf>
- Nix builtins, `import`/`scopedImport` semantics and memoization:
  - Nix Reference Manual — Built-in Functions:
    <https://nix.dev/manual/nix/2.34/language/builtins>
  - `scopedImport` primop commit (NixOS/nix):
    <https://github.com/NixOS/nix/commit/c273c15cb13bb86420dda1e5341a4e19517532b5>
  - `src/libexpr/primops.cc` (reference forcing order / semantics):
    <https://github.com/NixOS/nix/blob/master/src/libexpr/primops.cc>
  - `derivation` vs `derivationStrict` discrepancy (issue #7569):
    <https://github.com/NixOS/nix/issues/7569>
- Snix / Tvix (prior art for Rust Nix builtins, `nix-compat`, catchable errors):
  - Snix builtins component: <https://snix.dev/docs/components/eval/builtins/>
  - Snix component overview / `nix-compat`: <https://snix.dev/docs/components/overview/>
  - Snix catchable errors: <https://snix.dev/docs/components/eval/catchable-errors/>
  - `tvix_eval` API docs: <https://docs.tvix.dev/rust/tvix_eval/index.html>
