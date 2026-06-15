# RFC-0007 - The intermediate representation (IR)

> Part of the RFC-0007 aos-nix documentation set. This document is the *contract
> specification* for the intermediate representation (IR): the single, compact,
> scope-resolved data structure that the frontend emits and that every execution
> tier consumes. Where [frontend, parser, and IR](04-frontend-parser-and-ir.md)
> describes the *pipeline* that produces the IR, this document pins down the IR
> *itself* — its node taxonomy, its post-resolution typed form, how each runtime
> concept is encoded, its effect-class annotation, and its serialization — as the
> concrete artifact an implementor builds against.
>
> Read this alongside [frontend, parser, and IR](04-frontend-parser-and-ir.md)
> (which IR is lowered from), [value representation](05-value-representation.md)
> (what evaluating IR produces), [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
> (the simplifier that rewrites IR), [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)
> (the three consumers of IR), [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)
> (attrset construction/select encoding), and [incremental evaluation cache](12-incremental-evaluation-cache.md)
> (the demand graph that keys compile-nodes by AST hash).

## 1. What the IR is, and the one-IR invariant

The IR is the *lowered, scope-resolved, desugared* form of a Nix expression. It
is **not** the raw arena AST: it is that AST after the resolver has turned every
name into a static access, after parse-time desugaring has collapsed the surface
syntax, and after the IR carries the annotation slots that the whole-program
analyses ([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md))
fill in. It is the artifact the content-addressed compile-node produces and the
artifact every tier reads.

The governing invariant, stated once and binding on everything below:

> **One IR for all tiers.** There is exactly one IR. The tier-0 tree-walking
> interpreter (the oracle) interprets it directly; the tier-1 Cranelift baseline
> JIT and tier-2 Cranelift optimizing JIT lower the *same* IR to CLIF; and the
> simplifier ([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
> §7.5) rewrites it IR-to-IR. There is never a per-tier IR, never a separate
> bytecode, never a translation step between what the oracle runs and what the
> JIT compiles.

Three consequences follow directly, and they are the reason the IR is shaped the
way it is:

- **The oracle is a valid correctness reference.** Because tier-0 and tier-1
  consume the identical IR, a divergence between them is a JIT bug, localized
  without involving C++ Nix ([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)
  §2.1).
- **Deoptimization is a direct correspondence.** A tier-2 deopt
  ([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) §3) must
  resume the oracle at "the equivalent IR position with the equivalent live
  state." Because the position *is* a `NodeId` and the live state *is* the IR's
  own `(depth, slot)` coordinates, the deopt state map is a correspondence, not a
  translation.
- **The optimizer is just an IR-to-IR pass.** The simplifier is a graph node
  (a compile-node) memoized by input-IR hash; it improves the IR the oracle
  walks *and* the IR Cranelift compiles, before any JIT exists.

The IR retains the frontend's arena discipline ([frontend, parser, and IR](04-frontend-parser-and-ir.md)
§4.1): a single `Vec<IrNode>` of fixed-stride nodes, every cross-reference a
`u32` `NodeId`, no `Box`/`Rc`/pointer graph, variable-arity children stored as a
`(start, len)` slice into a side child pool. This is what makes the IR
position-independent, serializable by near-`memcpy`, and cache-friendly under the
linear passes of the resolver and the simplifier.

## 2. The IR node taxonomy

The IR node set is small and total. Every Nix expression lowers to exactly one of
these node kinds. The taxonomy is fixed; adding a kind is an
`evaluator_schema_version` bump ([frontend, parser, and IR](04-frontend-parser-and-ir.md)
§9.2).

```text
  literals        Int  Float  Bool  Null  Str  Path
  variables       LocalVar(slot)  UpvalVar(depth,slot)  GlobalVar(sym)  WithVar(sym, chain)
  binders         Lambda(pattern, body)  Let(frame, bindings, body)  With(scrutinee, body)
  construction    AttrSet(shape, entries, rec?, dynamic?)  List(elems)
  access          Select(recv, path, default?)  HasAttr(recv, path)
  control         If(cond, then, else)  Assert(cond, body)
  operators       BinOp(op, lhs, rhs)  UnaryOp(op, operand)
  application     Apply(fn, arg)
  effects         PrimOp(prim, args)  Interp(fragments)
  laziness        ThunkAlloc(inner)
  boundary        DerivationStrict(arg)        // the .drv emission boundary
```

### 2.1 The Rust enum shape

The IR is a flat arena. `IrNode` is fixed-stride so the arena is a `Vec<IrNode>`
with O(1) random access; payloads wider than the inline `data` slot spill to side
tables (the child pool, the attrset-entry table, the frame table) addressed by
`u32` offsets — exactly as in the AST (`04` §4.1), so that lowering is a refinement
of the arena, not a new data structure.

```rust
/// A handle into the IR arena. Not a pointer: a 32-bit index that survives
/// serialization and is the unit of cross-reference throughout the IR.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(u32);

/// An interned identifier or attribute key (see `04` §3.4). Equality is `u32`
/// equality; the reverse string is recovered from the interner only for
/// diagnostics, `GlobalVar`, `WithVar`, and attribute keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Symbol(u32);

/// One IR node. Fixed size: `kind` discriminates, `data` is a union-like payload
/// sized to its widest variant, `span` indexes back into source for diagnostics
/// and deopt, and `effect` is the effect-class annotation (§5).
pub struct IrNode {
    pub kind: NodeKind,
    pub span: Span,        // (u32, u32) byte offsets; universal diagnostic currency
    pub effect: EffectClass, // Pure | Effectful (§5)
    pub data: NodeData,    // kind-discriminated payload (§2.2)
}

/// The closed set of IR node kinds. Every Nix expression lowers to exactly one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    // --- literals (no children; value inline or interned) ---
    Int, Float, Bool, Null, Str, Path,

    // --- de Bruijn variable references (post-resolution; §3) ---
    LocalVar,   // data: slot                    -> env[slot]
    UpvalVar,   // data: (depth, slot)           -> parent^depth[slot]
    GlobalVar,  // data: Symbol                  -> builtins/global (true, map, ...)
    WithVar,    // data: (Symbol, WithChainId)   -> dynamic `with` probe (§4.4)

    // --- binders ---
    Lambda,     // data: LambdaId (pattern, frame, captures) -> §4.2
    Let,        // data: (FrameId, BindingsId, body: NodeId)  -> rec frame
    With,       // data: (scrutinee: NodeId, body: NodeId)

    // --- construction ---
    AttrSet,    // data: AttrSetId (shape, entries, rec, has_dynamic) -> §4.3
    List,       // data: (ChildSlice) -> elements, each a thunked NodeId

    // --- access ---
    Select,     // data: (recv: NodeId, AttrPathId, default: OptNodeId) -> §4.3
    HasAttr,    // data: (recv: NodeId, AttrPathId)

    // --- control ---
    If,         // data: (cond, then, els): NodeId x3
    Assert,     // data: (cond: NodeId, body: NodeId)

    // --- operators ---
    BinOp,      // data: (BinOpKind, lhs: NodeId, rhs: NodeId)
    UnaryOp,    // data: (UnOpKind, operand: NodeId)

    // --- application ---
    Apply,      // data: (fn: NodeId, arg: NodeId)  (curried: one arg per node)

    // --- effects & strings ---
    PrimOp,     // data: (Prim, ChildSlice)  -> direct builtin call (§4.5)
    Interp,     // data: ChildSlice -> string-concat fragments, left-to-right

    // --- explicit laziness ---
    ThunkAlloc, // data: NodeId  -> wrap inner in a suspended thunk (§4.1)

    // --- the derivation boundary ---
    DerivationStrict, // data: NodeId (the attrset arg)  -> §4.6
}

/// Binary operator kinds. `+` is overloaded across int/float/string/path; the
/// typing decision is deferred to evaluation, matching C++ Nix (`04` §4.3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    Add, Sub, Mul, Div,           // arithmetic (+ also string/path concat)
    Concat,                       // ++ list concat
    Update,                       // // attrset update
    Lt, Gt, Le, Ge, Eq, Ne,       // relational / equality
    And, Or, Impl,                // && || -> (short-circuiting; see §4)
}

/// Unary operator kinds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnOpKind { Neg, Not }    // numeric negation, boolean negation
```

### 2.2 The side tables

Variable-arity and wide payloads live in `u32`-addressed side tables so `IrNode`
stays fixed-stride and the whole IR stays serializable:

```rust
/// Variable-arity children (list elements, primop args, interp fragments) live
/// contiguously in one pool; a node stores `(start, len)` into it.
pub struct ChildPool(Vec<NodeId>);
pub struct ChildSlice { pub start: u32, pub len: u32 }

/// Per-binder scope metadata, carried over from the resolver (`04` §6.5).
pub struct FrameInfo {
    pub slot_count: u32,          // size of this frame's env array
    pub captures: Box<[Upvalue]>, // free-var coordinates this lambda closes over
    pub rec: bool,                // self-visible frame (let / rec)
    pub has_with: bool,           // any `with` active within -> may emit WithVar
}
pub struct Upvalue { pub depth: u16, pub slot: u16 }

/// An attribute path: a dotted sequence whose components may be static symbols
/// or dynamic `${...}` expressions. Stored once, referenced by Select/HasAttr.
pub enum AttrPathSeg { Static(Symbol), Dynamic(NodeId) }
```

The literal payloads are small enough to sit inline: `Int` carries an `i64`,
`Float` an `f64`, `Bool` a bit, `Null` nothing, and `Str`/`Path` an interned
`Symbol` (the literal string body, interned exactly like an identifier).

## 3. The typed / scope-resolved form

The IR is *born resolved*. By the time a node exists in the IR arena, the
resolver ([frontend, parser, and IR](04-frontend-parser-and-ir.md) §6) has
already run, and three guarantees hold over every node:

1. **No name lookup survives except the genuinely dynamic `with` case.** Every
   `Ident` of the AST has become a `LocalVar(slot)`, `UpvalVar(depth, slot)`,
   `GlobalVar(sym)`, or `WithVar(sym, chain)`. Lexical access is an array index
   off an environment pointer — `env[slot]` at depth 0, a parent-chain walk
   `env.parent^depth[slot]` otherwise — never a hash lookup. This is the de
   Bruijn-style addressing borrowed from the lambda-calculus literature (resolve
   a use to a count of intervening binders), specialized to a `(depth, slot)`
   pair so compiled code gets an array index rather than a single collapsed
   index.
2. **Every lambda carries its exact capture list.** The `FrameInfo.captures`
   array is the lambda's free-variable set — precisely the `(depth, slot)`
   coordinates the body reads from enclosing frames, and nothing more. This is
   what the runtime closure record captures (a lambda value is
   `(code_ptr, captured_env)` per [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)
   §1.2). Precise capture keeps closure records small, keeps GC tracing cheap
   ([memory management and GC](06-memory-management-and-gc.md)), and is the
   precondition for escape analysis to prove a closure non-escaping
   ([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)).
3. **Thunking is explicit.** Every subexpression position that Nix semantics
   evaluate lazily is materialized as (or wrapped by) a `ThunkAlloc` node. The
   first lowering is conservative: it marks everything non-trivial as thunked,
   matching Nix's lazy semantics exactly. The simplifier and strictness analysis
   then *remove* `ThunkAlloc` nodes where a binding is provably always forced
   (§5, and [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
   §4). Thunk *placement* is therefore part of the IR contract, not a runtime
   decision.

This "one IR for all tiers" form is what makes the oracle/JIT relationship sound
(§1). The analyses are *annotations over this IR* — extra side fields and the
`effect` tag — not a separate representation, which is precisely why the
simplifier can be a within-IR fixpoint and the deopt map can be a direct
`NodeId`/slot correspondence.

### 3.1 Worked form

The `let x = 1; f = y: x + y; in f 41` example from
[frontend, parser, and IR](04-frontend-parser-and-ir.md) §7, in resolved IR:

```text
#0  Int(1)
#2  UpvalVar(depth=1, slot=0)        ; `x` -> enclosing let frame, slot 0
#3  LocalVar(slot=0)                 ; `y` -> lambda frame, slot 0
#4  BinOp(Add, #2, #3)
#5  Lambda(frame={slots=1, captures=[(1,0)]}, body=#4)   ; captures exactly {x}
#6  LocalVar(slot=1)                 ; `f` -> let frame, slot 1
#7  Int(41)
#8  Apply(#6, #7)
#9  Let(frame={slots=2, rec=true}, bindings=[#0,#5], body=#8)
```

No node performs a name lookup. The lambda's capture set is exactly `{(1,0)}`.
This is the artifact every tier consumes and the artifact the compile-node caches.

## 4. How runtime concepts are encoded

The IR is the meeting point between the surface language and the runtime
contracts of [value representation](05-value-representation.md),
[attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md),
and [primops and runtime ABI](10-primops-and-runtime-abi.md). This section pins
down how each runtime concept appears *in the IR*.

### 4.1 Thunks

A thunk is the runtime object `(code_ptr, captured_env, state)` whose `state`
follows the serial machine `Suspended -> Blackhole -> Forced` (and, under
parallel evaluation, the superset `Suspended -> Pending -> Awaited -> Forced/Failed`
— one model, the serial states a subset; see
[parallel evaluation](13-parallel-evaluation.md)). In the IR a thunk appears as a
`ThunkAlloc(inner)` node: it directs the lowering to emit an `aos_alloc_thunk`
call ([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) §7.2)
whose `code_ptr` is the compiled `inner` and whose `captured_env` is the current
frame.

`ThunkAlloc` is *the* unit the strictness/cardinality analysis operates on:
removing a `ThunkAlloc` (because the inner is proven always-forced and total)
is the IR-level realization of the worker/wrapper eager-compile transform. Forcing
itself is not an IR node — it is the `aos_force` runtime call emitted at every
position that demands WHNF; the IR encodes only *where thunks are allocated*, and
the demand for WHNF falls out of the consuming node (a `BinOp` forces its
operands, `Select` forces its receiver, `If` forces its condition).

### 4.2 Closures (lambdas)

A `Lambda` node lowers to a runtime closure `(code_ptr, captured_env)`. The IR
side table for the lambda holds:

- the **pattern**: either a single parameter (`x:`), or a formal-argument set
  `{ a, b ? default, ... }` with, per formal, an optional default-value `NodeId`,
  an `ellipsis` flag (`...` accepts extra attributes), and an optional `@`-alias
  binding the whole argument attrset to a slot;
- the **frame**: `slot_count` (one slot per parameter / formal / alias) and the
  `rec` flag;
- the **captures**: the exact `(depth, slot)` free-variable list (§3).

Nix lambdas are *curried*: a multi-argument function is nested single-argument
`Lambda` nodes, and `Apply` binds exactly one argument per node
([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) §1.2).
Formal-argument defaults are lazy: a default-value `NodeId` is itself thunked and
forced only if the caller omits that attribute, in the formal's own scope (so a
default may refer to a sibling formal). Pattern-match arity and the
missing/extra-attribute errors are observable and must match C++ Nix.

### 4.3 Attribute sets and select

`AttrSet` construction carries a **hidden class** (a.k.a. shapes/maps, from V8)
reference — the `shape` field names the set's layout class
([attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)).
The IR records:

- the **entries**: for each binding, the (interned) key `Symbol` and the value
  `NodeId` (thunked unless strictness proves otherwise);
- **`rec`**: whether the set is `rec { ... }` (a self-visible frame, so bindings
  resolve against each other — the resolver pushed the frame before lowering the
  right-hand sides);
- **`has_dynamic`**: whether any key is a dynamic `${...}` expression, which
  defers that key's `Symbol` to evaluation and forces the dynamic-merge path.

Attribute insertion/iteration order is *observable* — it feeds
`derivationStrict`'s environment serialization and thus the `.drv` — so the IR
preserves the source binding order and the attr-path merge rules verbatim
([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) §8;
[frontend, parser, and IR](04-frontend-parser-and-ir.md) §8). Parse-time
desugaring has already turned `a.b.c = v` into nested singleton sets merged with
siblings, so the IR sees only flat, merged `AttrSet` nodes.

`Select(recv, path, default?)` is the read side. Its `path` is an `AttrPathSeg`
sequence (static symbols and/or dynamic components); a trailing `or default`
populates the optional default `NodeId`. Lowering routes a `Select` through the
per-site inline cache helper `aos_select_ic`
([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) §4.1), so
the IR's `Select` node carries a stable **inline-cache site id** that the tiers
use to attach mono/poly/megamorphic cache state. `HasAttr(recv, path)` is the `?`
membership test, sharing the path encoding and the inline-cache machinery.

### 4.4 The `with` dynamic scope

`with e; body` makes every attribute of `e` available unqualified, but *which*
attributes exist is only known at runtime. The IR does not try to know it
statically. The `With` node holds the scrutinee and body; every unqualified name
inside that the resolver could *not* bind lexically becomes a `WithVar(sym,
chain)`, where `chain` (a `WithChainId` into a side table) records the enclosing
`with` scopes innermost-first that must be probed at runtime. Nix's resolution
order — **lexical bindings beat `with`; inner `with` beats outer** — is baked into
when a `WithVar` is emitted (only if no lexical binder shadows) and into the
chain's probe order. The runtime probe rides the same hidden-class / inline-cache
machinery as `Select`, so a `with`'s attrset shape, once seen, caches the
membership test and offset per site.

### 4.5 Primops

A `PrimOp(prim, args)` node is a *direct* call to a builtin
([primops and runtime ABI](10-primops-and-runtime-abi.md)). It exists as a
distinct node kind (rather than `Apply` onto a `GlobalVar`) wherever the builtin
identity is statically known, because that licenses the lowering to emit the
specific `aos_prim_<name>` runtime symbol
([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) §7.2) and
the simplifier to constant-fold *total* primops (`builtins.length [ 1 2 3 ] -> 3`)
or apply rewrite RULES (list fusion). A builtin reached indirectly (passed as a
value, e.g. `map builtins.length`) stays a `GlobalVar`/`Apply` and dispatches
through the generic apply path; the IR distinguishes the two so the common direct
case is fast and foldable.

Argument strictness is per-primop and matches C++ Nix exactly: an `args` slot is
thunked unless the primop is known to force it. The primop's `effect` annotation
(§5) is what gates whether the simplifier may speculate on it.

### 4.6 String contexts

A string carries a **string context** — the set of store paths and derivation
outputs that produced it ([derivation and store compatibility](11-derivation-and-store-compatibility.md)).
Context is *not* a separate IR node; it is a property of the *runtime string
value*, produced and unioned during evaluation. The IR's role is to encode the
operations that build and propagate context correctly:

- `Interp(fragments)` lowers `"a${x}b"` to a left-to-right coercion-and-`+`-fold
  of its fragments, and the fold **unions** the string contexts of every fragment
  — the IR fixes the fragment order so context union is deterministic.
- `BinOp(Add, ..)` on strings/paths likewise unions contexts.
- The context-manipulating builtins (`unsafeDiscardStringContext`,
  `getContext`, `appendContext`) appear as ordinary `PrimOp` nodes; their context
  semantics live in the runtime, not the IR.

Because string context is observable in the emitted `.drv`, the IR must never
reorder context-bearing concatenation or drop a fragment — a constraint the
simplifier's soundness rule (§5) enforces.

### 4.7 The `derivationStrict` boundary

`DerivationStrict(arg)` is the single IR node that marks the
*derivation-construction boundary*. `derivationStrict` is the primop that takes a
fully-evaluated attrset and emits a `.drv`
([derivation and store compatibility](11-derivation-and-store-compatibility.md)).
It is given its own node kind, rather than being one more `PrimOp`, for two
reasons:

1. **It is the byte-identity gate.** Everything the whole RFC defends —
   byte-identical ATerm `.drv`, identical store paths, exact string contexts —
   is observed *at this node*. The differential harness diffs `.drv` output here.
2. **It is unconditionally effectful and a hard speculation barrier.** Its
   `effect` is always `Effectful` (§5); the simplifier may never fold across it,
   speculate it, or reorder it relative to other effects, and the demand graph
   treats it as a re-execution boundary.

The IR thus makes the `.drv` boundary a first-class, statically locatable node —
the point every other consumer (harness, store layer, incremental cache) can
anchor on.

## 5. The effect-class annotation

Every IR node carries an `effect` field of type `EffectClass`. This is the
single most important *semantic* annotation in the IR after de Bruijn resolution,
because it is what licenses (or forbids) every speculative and rewriting
transform.

```rust
/// The effect class of an IR node: whether evaluating it can be done freely
/// (speculatively, eagerly, out of demand order) or must wait for genuine demand.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EffectClass {
    /// Pure: total or partial but side-effect-free. Safe to speculate, fold,
    /// hoist, CSE, and re-execute. Errors are *quarantined* — a pure node that
    /// fails when evaluated speculatively must stash the error, never surface it,
    /// until the value is genuinely demanded.
    Pure,
    /// Effectful: observes or affects the world in a way that is part of `.drv`
    /// identity or evaluation order. Never speculated, never reordered, never
    /// folded across. The runtime effects are `derivationStrict`, `import`
    /// (file I/O + parse), `import-from-derivation` (IFD: building a `.drv` to
    /// read its output during evaluation), and the reading builtins
    /// (`readFile`, `readDir`, `pathExists`, `getEnv`, ...).
    Effectful,
}
```

The classification rule:

- **Pure** covers the overwhelming majority of nodes: literals, variable
  references, lambdas, applications, arithmetic, attrset construction, select,
  `if`, `with`, and every *total* or side-effect-free builtin. A pure node may be
  speculatively parsed/compiled/evaluated on an idle worker, constant-folded by
  the simplifier, hoisted, or CSE'd.
- **Effectful** covers the nodes that touch the world or define `.drv` identity:
  `DerivationStrict` (always), and the effectful primops — `import` (file read +
  parse), IFD (import-from-derivation, which *builds* during eval), and the
  filesystem/environment readers (`readFile`, `readDir`, `pathExists`, `getEnv`).

The annotation is consumed in three places, all of which share one discipline:

- **Speculation** ([frontend, parser, and IR](04-frontend-parser-and-ir.md)
  §9.6): only pure nodes may be parsed/compiled/evaluated ahead of demand, and
  even then under **error quarantine** — a speculative failure is stashed against
  the node and re-raised *only if and when* the node is genuinely demanded, so a
  speculatively-discovered syntax or evaluation error never invents a divergence
  from C++ Nix.
- **The simplifier** ([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
  §7.5.3): a rewrite may fire only if it is observably transparent. The two sharp
  edges are both effect-class rules — *never fold a failing subexpression eagerly*
  (folding is restricted to total operations; a folded error is stashed, not
  raised) and *never make a lazy binding strict unless strictness is proven*
  (speculative eager forcing of an effectful or conditionally-forced node could
  change termination/error behavior and thus the `.drv`).
- **The demand graph** ([incremental evaluation cache](12-incremental-evaluation-cache.md)):
  the effect class gates re-execution and memoization. A pure node's result is
  memoizable and early-cutoff-eligible; an effectful node (especially
  `DerivationStrict`, `import`, IFD) is a re-execution boundary the cache must
  respect.

The unifying principle, stated once: **speculative or eager work must never
surface errors or effects until genuinely demanded** — the error-quarantine rule
that governs speculation, the simplifier, and the demand graph alike.

## 6. The IR and the demand graph

The IR is produced by a **compile-node** in the demand graph (the demand-driven
incremental memoization graph — Adapton's demanded computation graph / Salsa's
query graph; see [incremental evaluation cache](12-incremental-evaluation-cache.md)
and [architecture overview](03-architecture-overview.md) §3.4). The relationship
is precise:

- **A compile-node maps `source bytes -> IR`**, keyed by AST/content hash
  ([frontend, parser, and IR](04-frontend-parser-and-ir.md) §9.2). Because a
  file's IR is a pure function of its bytes, the compile-node is itself a pure,
  memoized graph node, schedulable on the same demand-driven, parallel,
  speculative machinery as thunks ([frontend, parser, and IR](04-frontend-parser-and-ir.md)
  §9.6) and the rayon pool ([parallel evaluation](13-parallel-evaluation.md)).
- **The simplifier is also a compile-node**, memoized by *input-IR hash*: the
  optimized IR is a pure function of the input IR, so optimization results cache
  across runs exactly like parse artifacts
  ([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
  §7.5).
- **Native compilation is a separate, lazier compile-node.** Parsing to IR
  happens on first `import` demand; Cranelift compilation of an IR function is
  deferred until that function is *hot*
  ([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)). Parse
  and native-compile are two graph nodes with different eagerness over the same
  IR.

The IR is therefore not a serial prelude to evaluation — it is a first-class,
content-addressed citizen of the deferred-execution graph, keyed and memoized
exactly like the value-level work it feeds.

Disambiguation, held throughout: "the demand graph" is this incremental
memoization graph; "graph reduction" (used in
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md))
names the lazy *evaluation* technique only; "the derivation graph" / ".drv
closure" is the Nix output DAG anchored at `DerivationStrict` nodes. The IR's
nodes are *IR nodes*; the demand graph's units are *graph nodes*; these are never
conflated.

## 7. Serialization for the content-addressed parse/compile cache

The IR is the cached artifact of the frontend's content-addressed parse/compile
cache ([frontend, parser, and IR](04-frontend-parser-and-ir.md) §9). Its arena
shape is what makes the cache cheap and sound.

### 7.1 What is serialized

The cached blob is the **scope-resolved IR arena plus its side tables**: the
`Vec<IrNode>`, the child pool, the `FrameInfo` / `AttrPathSeg` / attrset-entry
tables, and a *file-local* symbol table. Because every cross-reference is a `u32`
(`NodeId`, child-pool offset, `(depth, slot)`), the arena is position-independent:
serialization is close to a `memcpy` and the blob can be `mmap`-mapped back with
zero-copy access into the node arrays — no pointer fixup, ever.

```text
$AOS_NIX_CACHE/parse/
  <blake3-of-key>/
    ir.bin       # serialized arena: nodes (with effect tags), child pool, frame tables
    symbols.bin  # file-local symbol table (the distinct strings this file uses)
    meta.toml    # schema version, source-path hint, sizes (diagnostics only)
```

### 7.2 The cache key

The key is content-addressed, computed with **blake3** (the durable
content-addressed hash; xxh3 is reserved for in-process hot hashing, SHA-256
*only* for Nix-observed `.drv`/store hashes — never for our internal caches):

```text
parse_cache_key = blake3( file_content_bytes
                       ⧺ evaluator_schema_version
                       ⧺ relevant_lex/parse_flags )
```

`evaluator_schema_version` is bumped whenever the IR node taxonomy (§2), the
effect-class rules (§5), the resolver's slot assignment, or the serialization
layout changes — a bump invalidates the cache wholesale, which is correct and
cheap because re-deriving the IR from source is fast. The cache is purely a
function table: any entry is reproducible from source, so eviction or corruption
is only ever a performance issue, never a correctness one, and the blob is safe
to share across CI machines (Attic-backed) and to GC by LRU.

### 7.3 Symbol portability

The one subtlety is **symbol portability**. The global interner numbers `Symbol`s
by first-seen order, which depends on file *load order* and would make the same
file's IR hash differently across runs. The cache therefore stores a *file-local*
symbol table and rewrites in-IR `Symbol`s to local indices on store, remapping
them back to global `Symbol`s on load. This makes the serialized IR — and thus
its cache key and any value-hash derived from it — independent of load order,
which is the precondition for stable cross-run, cross-machine early cutoff in the
demand graph (§6).

## 8. Summary: the IR contract

- **One IR, three consumers.** The tier-0 oracle interprets it, the tier-1/tier-2
  Cranelift JITs lower it, the simplifier rewrites it. There is no per-tier IR;
  this is what makes the oracle a valid reference and deopt a direct
  `NodeId`/slot correspondence.
- **A flat arena.** `Vec<IrNode>`, fixed-stride nodes, `u32` `NodeId`
  cross-references, variable-arity children in side pools. Position-independent,
  serializable by near-`memcpy`, `mmap`-able.
- **A small, closed taxonomy.** Literals, de Bruijn variables, lambdas,
  application, `let`, `with`, attrset construction, select/has-attr, `if`,
  binary/unary ops, primop calls, interpolation, `thunk-alloc`, list, assert,
  and the `derivationStrict` boundary — each lowering to a specific runtime ABI
  symbol.
- **Born resolved.** Names are static `(depth, slot)` accesses (or the dynamic
  `WithVar`); lambdas carry exact capture lists; thunk placement is explicit.
- **Effect-classed.** Every node is `Pure` or `Effectful`; the annotation gates
  speculation, the simplifier, and the demand graph under one error-quarantine
  rule: no speculative or eager work surfaces an error or effect until genuinely
  demanded.
- **A demand-graph citizen.** A compile-node maps bytes to IR keyed by content
  hash; the simplifier is a compile-node keyed by input-IR hash; native compile
  is a lazier compile-node over the same IR.
- **Content-addressed.** The resolved IR arena is the cached artifact, keyed by
  blake3 over file content + schema version, with file-local symbol remapping for
  load-order independence.

## References

- de Bruijn indexing (scope resolution by counting intervening binders) —
  <https://en.wikipedia.org/wiki/De_Bruijn_index>
- Arena / data-oriented ASTs and `u32`-index trees (matklad) —
  <https://matklad.github.io/2020/04/13/simple-but-powerful-pratt-parsing.html>
- GHC Core-to-Core simplifier (iterated IR-to-IR rewriting to a fixpoint) —
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/comp-by-trans-scp.pdf>
- HotSpot tiered compilation and deoptimization (the oracle/JIT correspondence) —
  <https://devblogs.microsoft.com/java/how-tiered-compilation-works-in-openjdk/>
- Adapton (demanded computation graph) — <https://dl.acm.org/doi/10.1145/2594291.2594324>
- Salsa (query-based incremental computation) — <https://github.com/salsa-rs/salsa>
