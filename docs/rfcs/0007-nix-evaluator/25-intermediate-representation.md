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
> (attrset construction/select encoding), [incremental evaluation cache](12-incremental-evaluation-cache.md)
> (the demand graph that keys compile-nodes by AST hash), and
> [generalization and language dialects](28-generalization-and-language-dialects.md)
> (which factors this IR into the generic `ratchet-core` Core plus a Nix dialect).

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

The one IR is the generic **Core IR** — the lazy-functional core that lives in
the `ratchet-core` crate ([28](28-generalization-and-language-dialects.md)). The
invariant above is precisely "**one Core IR for all tiers**," and it holds intact:
the Nix-specific operations (`DerivationStrict`, `WithVar`, the string-context
value property, the builtin identities, the concrete effects) are *not* separate
IRs and not Core `IrKind` variants — they are a *dialect* that extends Core
through the indexed escape hatch already built into it (§4.5, §2.1). The three
consequences below — the oracle as a valid correctness reference, deopt as a
`NodeId`/slot correspondence, and the optimizer as an IR-to-IR pass — are
properties of the Core IR and are unchanged by the dialect layering, which is
orthogonal to the tier axis.

## 2. The IR node taxonomy

The IR node set is small and total. Every Nix expression lowers to exactly one of
these node kinds. The taxonomy is fixed; adding a kind is an
`evaluator_schema_version` bump ([frontend, parser, and IR](04-frontend-parser-and-ir.md)
§9.2).

```text
  literals        Int  Float  Bool  Null  Str  Path
  variables       LocalVar(slot)  UpvalVar(depth,slot)  GlobalVar(site,sym)
  binders         Lambda(pattern, body)  Let(frame, bindings, body)  With(scrutinee, body)
  construction    AttrSet(shape, entries, rec?, dynamic?)  List(elems)
  access          Select(recv, path, default?)  HasAttr(recv, path)
  control         If(cond, then, else)  Assert(cond, body)
  operators       BinOp(op, lhs, rhs)  UnaryOp(op, operand)
  application     Apply(fn, arg)
  effects         PrimOp(prim, args)  DialectNode(op, arg)†  DialectScopeVar(op, sym, chain)†  Interp(fragments)
  laziness        ThunkAlloc(inner)
```

**Core kinds vs dialect ops.** All unmarked entries above are **generic Core**
([28](28-generalization-and-language-dialects.md) §4): a lazy lambda calculus
that any pure-lazy-functional frontend shares. The `†` entries are payload forms
under the generic `IrKind::PrimOp` escape hatch, not separate `IrKind` variants.
For Nix, `DialectNode(NIX_OP_DERIVATION_STRICT, arg)` is the `.drv` boundary and
`DialectScopeVar(NIX_OP_WITH_VAR, site, sym, chain)` is dynamic `with` lookup.
The string-context value property and the concrete builtin/effect identities are
likewise dialect-supplied, not Core. This keeps the taxonomy a closed Core set
plus dialect-registered operations, rather than a Nix-specific grab bag.

### 2.1 The Rust enum shape

The IR is a flat arena. `IrNode` is fixed-stride so the arena is a `Vec<IrNode>`
with O(1) random access; payloads wider than the inline `data` slot spill to side
tables (the child pool, the attrset-entry table, the frame table) addressed by
`u32` offsets — exactly as in the AST (`04` §4.1), so that lowering is a refinement
of the arena, not a new data structure.

The `NodeKind` enum below is the Core taxonomy. Nix-dialect operations
(`WithVar`, `DerivationStrict`) do not sit in it as separate variants; they are
encoded as dialect-owned payloads under `IrKind::PrimOp`
([28](28-generalization-and-language-dialects.md) §5). The escape hatch is the
same mechanism `PrimOp` already uses (§4.5): an indexed, statically-known op baked
into the IR at lowering, resolved once into concrete runtime behavior — never a
per-force `dyn` dispatch. A second dialect would register *its* extra ops through
the same seam rather than minting new Core variants, which is why the Core enum
stays closed and small.

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
    pub effect: EffectTag, // dialect-supplied effect; engine sees `Effect` (§5, S-23)
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
    GlobalVar,  // data: (site, Symbol)          -> builtins/global (true, map, ...)

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
    PrimOp,     // data: PrimOp or dialect-op payload -> direct builtin / dialect op (§4.5)
    Interp,     // data: ChildSlice -> string-concat fragments, left-to-right

    // --- explicit laziness ---
    ThunkAlloc, // data: NodeId  -> wrap inner in a suspended thunk (§4.1)
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
   `GlobalVar(site, sym)`, or a dialect `WithVar` payload under `IrKind::PrimOp`.
   Lexical access is an array index off an environment pointer — `env[slot]` at
   depth 0, a parent-chain walk
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
inside that the resolver could *not* bind lexically becomes a Nix dialect
`DialectScopeVar(NIX_OP_WITH_VAR, site, sym, chain)` payload under
`IrKind::PrimOp`, where `site` is the probe's stable inline-cache site and
`chain` (a `WithChainId` into a side table) records the enclosing `with` scopes
innermost-first that must be probed at runtime. Nix's resolution order —
**lexical bindings beat `with`; inner `with` beats outer** — is baked into when a
source-level `WithVar` is emitted (only if no lexical binder shadows) and into the
chain's probe order. The tree-walk probe rides the same checked inline-cache
bridge as `Select`: successful shaped/HAMT lookups can reuse cached slots per
site and chain depth. Scoped-global fallback probes also carry stable
`GlobalVar` lookup sites and use the same bridge while walking scoped-import
overlays. Absent shaped/flat membership entries and native `aos_select_ic`
dispatch remain future work.

### 4.5 Primops

A `PrimOp(prim, args)` node is a *direct* call to a builtin
([primops and runtime ABI](10-primops-and-runtime-abi.md)). It exists as a
distinct node kind (rather than `Apply` onto a `GlobalVar`) wherever the builtin
identity is statically known, because that licenses the lowering to emit the
specific `nix.builtin.<name>` runtime symbol
([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) §7.2) and
the simplifier to constant-fold *total* primops (`builtins.length [ 1 2 3 ] -> 3`)
or apply rewrite RULES (list fusion). A builtin reached indirectly (passed as a
value, e.g. `map builtins.length`) stays a `GlobalVar`/`Apply` and dispatches
through the generic apply path; the IR distinguishes the two so the common direct
case is fast and foldable.

Argument strictness is per-primop and matches C++ Nix exactly: an `args` slot is
thunked unless the primop is known to force it. The primop's `effect` annotation
(§5) is what gates whether the simplifier may speculate on it.

The `PrimOp` node *is* the dialect escape hatch
([28](28-generalization-and-language-dialects.md) §5). Its ordinary builtin symbol
or dialect-op key is statically known and baked into the IR at lowering, so it
carries no per-force dynamic dispatch: the node kind is generic Core, while the
*builtin set* and dialect-op key space are supplied by the dialect (the Nix
dialect for RFC-0007). `DerivationStrict` (§4.7) is exactly this mechanism viewed
at one remove — a distinguished, always-effectful operation of the Nix dialect —
given its own dialect-op key/payload so it is statically locatable as the `.drv`
boundary, not because it needs a new Core node kind.

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

`DialectNode(NIX_OP_DERIVATION_STRICT, arg)` is the single Nix dialect operation
payload that marks the *derivation-construction boundary*. `derivationStrict` is
the primop that takes a fully-evaluated attrset and emits a `.drv`
([derivation and store compatibility](11-derivation-and-store-compatibility.md)).
It is given its own dialect-op key and payload, rather than being one more
ordinary builtin `PrimOp(symbol, args)`, for two reasons:

1. **It is the byte-identity gate.** Everything the whole RFC defends —
   byte-identical ATerm `.drv`, identical store paths, exact string contexts —
   is observed *at this node*. The differential harness diffs `.drv` output here.
2. **It is unconditionally effectful and a hard speculation barrier.** Its
   `is_speculable()` is always false and it carries its own `effect_key` (§5); the
   simplifier may never fold across it, speculate it, or reorder it relative to
   other effects, and the demand graph treats it as a re-execution boundary.

The IR thus makes the `.drv` boundary first-class and statically locatable by its
dialect-op key — the point every other consumer (harness, store layer,
incremental cache) can anchor on.

`DerivationStrict` is a **Nix-dialect** operation, not Core
([28](28-generalization-and-language-dialects.md) §4): it lives in
`aos-nix-dialect` as `NIX_OP_DERIVATION_STRICT` and is reached through the indexed
escape hatch (§4.5), the same way the Nix builtin table is. A non-Nix dialect
simply would not register it. Core remains unaware of derivations; the `.drv`
boundary is a property the Nix dialect adds.

## 5. The effect-class annotation

Every IR node carries an `effect` annotation. This is the single most important
*semantic* annotation in the IR after de Bruijn resolution, because it is what
licenses (or forbids) every speculative and rewriting transform.

The effect annotation is an **open, dialect-supplied lattice**, not a closed enum.
This is decision `S-23` ([28](28-generalization-and-language-dialects.md) §5–§6):
the closed `enum EffectClass { Pure, Effectful }` was the one place a Nix concept
leaked into the language-agnostic engine, so the engine instead consumes an
*effect trait* and the dialect supplies the members. The engine needs exactly two
facts from a node's effect — whether it may run ahead of demand, and an opaque key
that delimits re-execution boundaries — and it must never *interpret* the concrete
members. The Nix dialect populates the lattice with `derivationStrict`, `import`,
IFD, and the filesystem/environment readers; a dialect with no derivations (e.g. a
Haskell-Core dialect) would populate it nearly empty.

```rust
/// The effect annotation of an IR node, as the engine sees it: whether the node
/// may be evaluated freely (speculatively, eagerly, out of demand order) and the
/// opaque key the cache uses to delimit re-execution boundaries. The engine never
/// interprets the concrete members — the dialect supplies them (`S-23`).
pub trait Effect {
    /// Whether this node may be parsed/compiled/evaluated ahead of genuine demand.
    /// `true` for pure (total or side-effect-free) nodes; `false` for nodes that
    /// observe or affect the world in a way that is part of `.drv` identity or
    /// evaluation order. Even a speculable node runs under *error quarantine* — a
    /// speculative failure is stashed against the node and re-raised only if and
    /// when the node is genuinely demanded, never surfaced eagerly.
    fn is_speculable(&self) -> bool;

    /// An opaque key identifying the effect for the cache's re-execution and
    /// memoization boundaries. Pure nodes share the speculable key (memoizable,
    /// early-cutoff-eligible); each distinct effect (e.g. `derivationStrict`,
    /// `import`, IFD, a filesystem read) carries a distinct key the cache treats
    /// as a re-execution boundary. The engine compares keys; it does not decode
    /// what they mean — that meaning lives in the dialect.
    fn effect_key(&self) -> EffectKey;
}
```

The `IrNode.effect` field (§2.1) holds `EffectTag` — the dialect's concrete,
inline `Effect`-implementing tag (a small `Copy` enum kept inline so the arena
stays fixed-stride, not a trait object). The engine is generic over it and sees
only the `Effect` trait above; the Nix dialect's `EffectTag` is the closed
`{ Pure, Effectful }` pair, but the engine never names those members.

The classification rule the **Nix dialect** applies (the engine sees only the
trait above):

- **Speculable (pure)** covers the overwhelming majority of nodes: literals,
  variable references, lambdas, applications, arithmetic, attrset construction,
  select, `if`, `with`, and every *total* or side-effect-free builtin. Such a node
  may be speculatively parsed/compiled/evaluated on an idle worker, constant-folded
  by the simplifier, hoisted, or CSE'd. All pure nodes share one `effect_key`.
- **Non-speculable (effectful)** covers the nodes that touch the world or define
  `.drv` identity: `DerivationStrict` (always), and the effectful primops —
  `import` (file read + parse), IFD (import-from-derivation, which *builds* during
  eval), and the filesystem/environment readers (`readFile`, `readDir`,
  `pathExists`, `getEnv`). Each carries a distinct `effect_key` so the cache can
  treat it as its own re-execution boundary. These members are the Nix dialect's;
  the engine learns them only through the trait.

The annotation is consumed in three places, all of which share one discipline and
all of which read it *only* through `is_speculable` / `effect_key` — never by
matching a concrete member:

- **Speculation** ([frontend, parser, and IR](04-frontend-parser-and-ir.md)
  §9.6): only nodes whose `is_speculable()` is true may be parsed/compiled/evaluated
  ahead of demand, and even then under **error quarantine** — a speculative failure
  is stashed against the node and re-raised *only if and when* the node is genuinely
  demanded, so a speculatively-discovered syntax or evaluation error never invents a
  divergence from C++ Nix.
- **The simplifier** ([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
  §7.5.3): a rewrite may fire only if it is observably transparent. The two sharp
  edges are both `is_speculable` rules — *never fold a failing subexpression eagerly*
  (folding is restricted to total operations; a folded error is stashed, not
  raised) and *never make a lazy binding strict unless strictness is proven*
  (speculative eager forcing of a non-speculable or conditionally-forced node could
  change termination/error behavior and thus the `.drv`).
- **The demand graph** ([incremental evaluation cache](12-incremental-evaluation-cache.md)):
  the `effect_key` gates re-execution and memoization. A speculable node's result is
  memoizable and early-cutoff-eligible; a node with a distinct effect key (especially
  `DerivationStrict`, `import`, IFD) is a re-execution boundary the cache must
  respect. The cache compares keys; it does not decode them, which is what keeps
  `ratchet-cache` free of Nix knowledge (`S-23`).

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
shape — owned by `ratchet-core`, with the cache itself living in `ratchet-cache`
([28](28-generalization-and-language-dialects.md) §3) — is what makes the cache
cheap and sound. The serialized blob is generic Core plus the dialect's effect
tags; nothing in the on-disk format is Nix-specific beyond the file-local symbols.

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
    resolved.bin # serialized resolved frontend artifact
    ir.bin       # serialized arena: nodes (with effect tags), child pool, frame tables
    symbols.bin  # file-local symbol table (the distinct strings this file uses)
    facts.bin    # optional per-node analysis fact sidecar
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
- **Effect-classed.** Every node carries a dialect-supplied effect read through
  `is_speculable` / `effect_key` (an open lattice, not a closed enum — `S-23`); the
  annotation gates speculation, the simplifier, and the demand graph under one
  error-quarantine rule: no speculative or eager work surfaces an error or effect
  until genuinely demanded.
- **A demand-graph citizen.** A compile-node maps bytes to IR keyed by content
  hash; the simplifier is a compile-node keyed by input-IR hash; native compile
  is a lazier compile-node over the same IR.
- **Content-addressed.** The resolved IR arena is the cached artifact, keyed by
  blake3 over file content + schema version, with file-local symbol remapping for
  load-order independence.

## Implementation checklist

Per-feature tracker for the intermediate representation (the node taxonomy, the scope-resolved typed form, runtime-concept encodings, the effect-class annotation, demand-graph integration, and serialization); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

The IR is the **P1** contract (decision `S-19`): the single arena IR every tier consumes. Every item lands under the tree-walk oracle and is gated by the differential `.drv` harness ([15](15-differential-testing-and-benchmarking.md)) plus the conformance surfaces ([20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md)); the IR pipeline that produces it is owned by [frontend, parser, and IR](04-frontend-parser-and-ir.md).

### Arena and node taxonomy (§2)

- [x] Flat-arena `Vec<IrNode>` storage: fixed-stride `IrNode { kind, span, effect, data }`, compact `u32` `IrId`/`Symbol` handles, and variable-arity children in an `IrChildSlice { start, len }` over the arena child pool (§2, §2.1) — **P1**, `S-19`. Implemented by `Ir { root, arena, symbols, frames, with_chains, attr_paths, bindings, shapes }`, `IrArena { nodes: Vec<IrNode>, children: Vec<IrId> }`, `IrNode`, `IrId(u32)`, `Symbol(u32)`, and checked `push_node`/`push_child_slice` conversions that reject side tables outside `u32` addressability. Covered by `compile::ir` lowering tests that inspect arena nodes, child slices, static shapes, dynamic attr paths, with-chain side tables, thunk placement, primop arg slices, and inline-cache site ids, plus parse-cache IR artifact roundtrip/validation tests. The stable raw-memory layout and near-`memcpy` load/store guarantee remain tracked by the open serialization row.
- [x] The current closed `IrKind` taxonomy (literals, de Bruijn variables, binders/formals, construction, access, control, operators, application, direct builtins/dialect ops through `PrimOp`, interp, `ThunkAlloc`); adding a serialized kind is a schema-version bump (§2, §2.1) — **P1**, `S-19`. Implemented as the closed `#[repr(u8)]` `IrKind` enum with explicit cache-artifact tags in `cache::parse::codec::{ir_kind_tag, decode_ir_kind}`, no wildcard in the encoder match, unknown tag rejection on decode, `PARSE_CACHE_SCHEMA_VERSION` in every parse-cache key/metadata file, and `cache::parse::validate` checks tying each kind to its legal `IrData` shape and effect. Covered by `compile::ir` lowering tests across the taxonomy and parse-cache roundtrip/corruption/validation tests including inconsistent payload/effect rejection. The Phase 1b Core/dialect split is implemented by dialect payloads under `IrKind::PrimOp`, not Nix-specific Core variants.
- [x] Core/dialect split: generic Core kinds live in `ratchet-core`; the Nix-dialect operations (`WithVar`, `DerivationStrict`), the builtin table, string-context, and the effect members are owned by `aos-nix-dialect`, reached via the indexed `PrimOp` escape hatch as Nix-owned dialect payloads rather than Core `IrKind` variants (§1, §2, §4.5) — **Phase 1b** ([28](28-generalization-and-language-dialects.md) §10), `S-22`.
- [x] `BinOpKind`/`UnOpKind` enums with `+` overload deferred to evaluation, matching C++ Nix (§2.1) — **P1**; operator conformance ([20](20-nix-language-conformance.md)). Implemented as `syntax::BinOpKind`/`UnaryOpKind`, preserved in `IrData::Binary`/`IrData::Unary` by `IrLowerer::lower_binary`/`lower_unary` without type-specializing the operator at lowering time. The overloaded `+` dispatch remains in tree-walk evaluation (`TreeWalk::eval_add`), where the forced left operand selects numeric addition, string/path concatenation, or attrset-to-string coercion before concatenation. Covered by IR lowering tests for binary/unary payload preservation and pipe laziness, tree-walk numeric/string/path/add tests, and the C++-Nix operator parity cases in [20](20-nix-language-conformance.md).
- [x] Side tables: `ChildPool`/`ChildSlice`, `FrameInfo`, `Upvalue`, `AttrPathSeg` (static-symbol / dynamic-`${}`); inline literal payloads (`i64`/`f64`/bit/interned `Symbol`) (§2.2) — **P1**, `S-19`. Implemented as `IrArena`'s child pool plus `IrChildSlice`, resolver `FrameInfo { slot_count, captures, rec, has_with }` and `Upvalue { depth, slot }`, lowered `IrAttrPathSegment::{Static, Dynamic}`, and inline `IrData::{Int, Float, Bool, Symbol}` payloads. Covered by resolver capture tests (`resolves_let_lambda_to_de_bruijn_slots`, `nested_lambdas_record_transitive_capture_sets`), IR lowering tests for child slices, dynamic attr-path side-table segments, with-chain side tables, shape side tables, and inline bool/symbol payloads. The stronger exact-capture invariant and serialized cache layout remain tracked by their separate rows below.

### Scope-resolved typed form (§3)

- [x] Born-resolved lexical invariant: no lexical name lookup survives lowering; local access is `LocalVar { slot }`, captured access is `UpvalVar { depth, slot }`, and the only surviving name-bearing lookup nodes are explicit `WithVar` and `GlobalVar` dynamic/global cases (§3 item 1) — **P1**, `S-19`/`S-11`. Implemented by `ScopeResolver::resolve_identifier` classifying lexical hits before globals/with scopes and by IR lowering preserving those resolved coordinates in `IrData::Local`/`IrData::Upval`; surviving `GlobalVar` payloads carry stable inline-cache lookup sites for scoped-global fallback probes. Covered by `resolves_let_lambda_to_de_bruijn_slots`, `lexical_bindings_beat_active_with_scopes`, `global_names_are_classified_separately_from_undefined_names`, `shadowed_bool_and_null_names_remain_lexical_variables`, and the `with`-chain tests.
- [x] Exact per-lambda capture list in `FrameInfo.captures` (free-var set, nothing more) — precondition for cheap GC tracing and escape analysis (§3 item 2) — **P1**. Implemented by resolver capture bookkeeping: `lookup_symbol` identifies the binding frame/slot, `record_captures` records `Upvalue { depth, slot }` only for intervening lambda frames, stores captures in a deduplicating `BTreeSet`, and finalizes each `FrameInfo` with a sorted boxed capture slice. Covered by `resolves_let_lambda_to_de_bruijn_slots`, `nested_lambdas_record_transitive_capture_sets`, and lambda-shadowing/default tests that keep local slots out of capture lists. The later GC tracing and escape-analysis consumers remain tracked by their own memory/analysis rows.
- [x] Explicit thunk placement: `ThunkAlloc` materialized conservatively (everything non-trivial), with thunk *placement* part of the IR contract (§3 item 3) — **P1**; strictness later *removes* `ThunkAlloc` nodes (**P4**, [07](07-laziness-and-whole-program-analyses.md)). Implemented by routing lazy positions through `IrLowerer::lower_lazy`/`wrap_lazy`, which emits `IrKind::ThunkAlloc` around non-trivial nodes while leaving the explicit trivial-value whitelist (`Int`, `Float`, `Bool`, `Null`, `Str`, `Uri`) unwrapped. Covered by `materializes_thunks_at_lazy_binding_and_list_positions`, `bool_and_null_literals_are_not_thunked_in_lists`, `unsupported_literal_values_stay_lazy`, `uri_literals_are_trivial_values`, plus primop-lowering tests that assert strict versus lazy argument placement. Strictness-driven thunk deletion remains the separate P4 optimization row.

### Runtime-concept encodings (§4)

- [x] Tree-walk `ThunkAlloc(inner)` runtime semantics: allocate a suspended thunk record for `inner`, and perform forcing through consuming demand sites rather than a distinct force IR node (§4.1) — **P1**. Implemented by `TreeWalk::eval_thunk_alloc` / `alloc_thunk_for_node`, which validate the inner `IrId`, capture lexical/`with`/scoped-global environments, allocate an `EvalThunk` through `EvalHeap::alloc_thunk`, and by consumer paths calling `force_value` / `force_demanded_value` while the IR taxonomy has no force node. Covered by `compile::ir` thunk-placement tests, heap thunk allocation/state tests, lazy list/attr/select/primop tests that leave undemanded thunks suspended, and `forcing_attr_value_thunks_memoizes_whnf_results`.
- [ ] Native/runtime ABI lowering of `ThunkAlloc(inner)` to an exported `aos_alloc_thunk` call, and every WHNF-consuming native path to `aos_force`, remains **P6** ([08](08-execution-tiers-and-cranelift.md)); the current tree-walk heap uses the safe Rust thunk allocator rather than emitted runtime calls.
- [x] `Lambda` encoding: pattern (single param / formal set with lazy per-formal defaults + ellipsis + `@`-alias), frame, captures; curried single-arg `Apply`; observable arity/missing/extra-attr errors (§4.2) — **P1**; pattern conformance ([20](20-nix-language-conformance.md)). Implemented as `IrData::Lambda { pattern, body, frame }`, `IrData::FormalSet { formals, ellipsis, alias }`, lazy `IrData::Formal { default }`, and `IrKind::Apply` pair nodes. `eval_lambda` captures lexical/with/scoped-global environments, `eval_apply_expression` evaluates the argument as a lazy thunk and applies one argument at a time, and `bind_formal_set_argument` forces the argument to attrs WHNF while preserving lazy field/default values and reporting missing/extra formal errors. Covered by `lowers_let_lambda_application_to_resolved_ir`, `invalid_lambda_pattern_shapes_are_rejected_before_ir`, `simple_lambdas_apply_with_lazy_arguments`, `formal_set_lambdas_bind_attrs_defaults_ellipsis_and_aliases`, `formal_set_lambdas_report_match_errors`, and doc 20's checked function-conformance rows.
- [x] `AttrSet` IR carrying a static `shape` ref, ordered entries, `rec`, and `has_dynamic`; source-order + attr-path merge preserved (observable in `.drv`) (§4.3) — **P1** ordering correctness. Implemented as `IrData::AttrSet { shape, bindings, recursive, has_dynamic, frame }`, `IrShapeId`, and `IrShape { keys }`, with lowering deriving static keys from ordered binding runs and marking dynamic keys separately. Covered by `attrsets_reference_static_shapes_in_source_order`, `dynamic_attrset_shapes_keep_static_keys_and_dynamic_flag`, `empty_attrsets_have_empty_shapes`, `recursive_attrsets_keep_shape_and_frame`, scope attr-path merge tests, and tree-walk attrset shape validation tests.
- [ ] Hidden-class machinery for attrsets remains **P5** ([09](09-attribute-sets-hidden-classes-and-inline-caches.md), `S-10`).
- [x] `Select`/`HasAttr` node shape with `AttrPathSeg` path + `or` default + a stable inline-cache site id (§4.3) — **P1** node shape, `S-10`. Implemented as `IrData::Select { site, receiver, path, default }`, `IrData::HasAttr { site, receiver, path }`, `IrInlineCacheSiteId`, and monotonic `IrLowerer::next_inline_cache_site`; dynamic/default attribute paths lower through the attr-path side table. Covered by `assigns_stable_inline_cache_sites_to_lookups`, `inherit_from_targets_share_one_source_thunk`, dynamic attr-path lowering tests, and select/hasAttr tree-walk tests.
- [x] Tree-walk `Select`/`HasAttr` runtime semantics over lowered attr paths: evaluate the receiver and only reached dynamic path segments in Nix order, force intermediate selected values when traversal continues, apply `or` defaults for selection misses/non-attr receivers, and make `?` return false without forcing terminal values (§4.3) — **P1**, `S-10`. Implemented by `TreeWalk::eval_select`, `eval_select_from_value`, `eval_has_attr`, and `eval_attr_name`, with shared attr-path side-table lookup, dynamic flat lookups routed through the `ratchet-value::attrs::select` slow-select dispatcher, and static path segments routed through the active shaped/flat/HAMT select-cache bridge when metadata permits. Covered by select/hasAttr tests for static/dynamic paths, receiver/key evaluation order, default behavior, type errors, missing attributes, hasAttr non-forcing behavior, and projected-shaped/flat/HAMT cache telemetry.
- [ ] Native exported routing of `Select`/`HasAttr` through `aos_select_ic`; the PIC itself remains **P5**, `S-10`. The current tree-walk path and crate-internal Rust-callable `aos_has_attr`/`aos_select_ic` wrappers use checked Rust select-cache bridges, but no native ABI helper dispatch exists yet.
- [x] `With(scrutinee, body)` + Nix dialect `WithVar(site, sym, WithChainId)` baking in lexical-beats-`with` / inner-beats-outer probe order (§4.4) — **P1**; `with`-scope conformance. Implemented by the resolver classifying lexical hits as `LocalVar`/`UpvalVar` before source-level `WithVar`, building `WithChain` scopes innermost-first, and IR lowering preserving `With` pairs plus `IrData::DialectScopeVar { op: NIX_OP_WITH_VAR, site, symbol, chain }` into `IrWithChain` side tables whose scrutinees are explicit lazy scope nodes. Covered by `lexical_bindings_beat_active_with_scopes`, `with_variables_record_innermost_first_probe_chains`, `lambda_parameters_shadow_active_with_scopes`, `with_var_chains_point_to_lowered_scopes_inner_first`, `with_scrutinees_are_explicit_lazy_scope_nodes`, and tree-walk `with` probe tests.
- [x] Tree-walk `WithVar` runtime probing over lowered `WithChain` side tables: push each active `with` scrutinee as a lazy scope value, probe scopes in the baked innermost-first order, force a scope only when probing it, require probed scopes to be attrsets, and report unresolved names only when every probed attrset scope misses (§4.4) — **P1**. Implemented by `TreeWalk::eval_with`, dialect-op dispatch through `eval_primop`, `eval_with_var`, `with_chain_scope(_ref)`, and `with_scope_value`, with each active scope probe routed through the same shaped/flat/HAMT select-cache bridge as static attr paths when metadata permits. Covered by `with_scopes_capture_lexical_environments`, `with_lookup_reports_non_attr_scopes_and_missing_names`, `repeated_with_var_probe_uses_shaped_inline_cache_for_projected_flat_scopes`, invalid with-chain tests, and resolver/IR tests for lexical-before-with and innermost-first chain order.
- [ ] Native/runtime `WithVar` probing through `aos_select_ic` remains tied to the **P5** native select/PIC work; the current tree-walk path uses checked Rust select-cache bridges without native runtime helper dispatch.
- [x] `PrimOp(prim, args)` as a *direct* statically-known builtin call (vs `GlobalVar`/`Apply` for indirected builtins), per-primop argument strictness matching C++ Nix (§4.5) — **P1**, `S-12`. Implemented as `IrData::PrimOp { symbol, args }` plus `BuiltinDirect` arity, strict/lazy, and effect metadata: unshadowed direct builtin references lower through `IrLowerer::{strict_unary_primop_ref,lazy_unary_primop_ref,strict_binary_primop_ref,strict_lazy_binary_primop_ref,lazy_strict_binary_primop_ref,strict_ternary_primop_ref}` with `lower_expr` vs `lower_lazy` preserving the table's forcing contract, while shadowed/default-selected/dynamic-builtin cases remain ordinary `Apply`/`GlobalVar`/`Select` forms. Covered by `compile::ir::tests::primop_tests::*` and `compile::ir::tests::primop_shadowing_tests::*`. Full builtin-surface completion remains tracked by [10](10-primops-and-runtime-abi.md) and [21](21-builtins-conformance.md).
- [x] String-context encoding: `Interp` fixes fragment order for deterministic context union; `BinOp(Add)` unions; context builtins are ordinary `PrimOp`s — IR never reorders/drops context-bearing concat (§4.6) — **P1**; string-context parity (`S-13`). Implemented by ordered `IrKind::Interp` child slices, `IrKind::BinOp` preserving `BinOpKind::Add`, and context-manipulating builtins lowering through `IrData::PrimOp`; tree-walk `eval_interp` folds children left-to-right through `concat_strings`, `eval_add` delegates string/attr coercions to the same context-unioning concat path, and `hasContext`/`getContext`/`appendContext`/`addDrvOutputDependencies`/`unsafeDiscard*` dispatch through the direct primop table. Covered by context propagation property tests, context builtin tests, `unsafe_discard_string_context_primop_returns_context_free_string`, and the C++-oracle string-context helpers where configured. The interned/COW context representation remains tracked by [11](11-derivation-and-store-compatibility.md) §8.3.
- [x] `DialectNode(NIX_OP_DERIVATION_STRICT, arg)` as the first-class, statically-locatable `.drv` boundary with a Nix-owned dialect effect (§4.7) — **P1**, `S-13`; the differential harness anchors here. Implemented as `IrKind::PrimOp` carrying `IrData::DialectNode { op: NIX_OP_DERIVATION_STRICT, argument }` and `NIX_EFFECT_DERIVATION_STRICT`: direct unshadowed `derivationStrict` / `builtins.derivationStrict` applications lower to the dialect boundary, lexically shadowed, `builtins`-attr-shadowed, and default-selected cases stay ordinary `Apply`/`Select`, cache-parse validation accepts only the dialect node shape/effect pairing, and tree-walk dialect-op dispatch forces an attrset argument before running the `.drv` construction path. Covered by `lowers_direct_derivation_strict_to_effectful_boundary`, shadowing/default-select lowering tests, `derivation_strict_first_class_values_call_builtin`, derivation algorithm tests, and doc 11's checked `derivationStrict` rows.
- [x] Open dialect/effect-key treatment for `DerivationStrict`: model it as the Nix-dialect op reached through the indexed escape hatch, expose non-speculation through `is_speculable` / distinct `effect_key`, and replace the hardcoded `EffectClass::Effectful` barrier with the Phase 1b dialect effect lattice (§4.7, §5) — **Phase 1b**, `S-22`/`S-23` ([28](28-generalization-and-language-dialects.md) §10).

### Effect-class annotation (§5)

- [x] Dialect-open effect annotation on every node: `IrNode.effect: EffectClass` records a dialect-owned key plus speculation bit, direct primops inherit Nix-refined builtin effects, and `DerivationStrict` is a Nix dialect-op barrier (§5) — **P1**, `S-19`/`C-20`. Implemented by `EffectClass::{new,pure,from_cache_key}`, `IrLowerer::push_with_effect`, dialect effect hooks, cache artifact effect tags, native fallback preflight reporting non-speculable nodes as unsupported/fallback-eligible, and `cache::parse::validate` checks that reject inconsistent node/effect pairs. Covered by effectful primop lowering tests, `lowers_direct_derivation_strict_to_effectful_boundary`, `with_shadowed_derivation_strict_lowers_to_effectful_boundary`, `direct_builtin_declarations_mark_effectful_boundaries`, and `lowered_ir_rejects_inconsistent_node_payload_and_effect`.
- [x] Dialect-supplied effect on every node, read through `is_speculable` / `effect_key` (open lattice, not a closed enum); Nix-dialect classification rule (non-speculable = `DerivationStrict`, `import`, IFD, fs/env readers; speculable = everything else) (§5) — **Phase 1b**, `S-19`/`S-23`/`C-20` ([28](28-generalization-and-language-dialects.md) §10).
- [ ] The error-quarantine discipline consumed in all three places — speculation, the simplifier, the demand graph — so no speculative/eager work surfaces an error or effect until genuinely demanded (§5) — **P1** contract; enforced by speculation (`C-19`, [04](04-frontend-parser-and-ir.md) §9.6), the simplifier (`C-21`, [07](07-laziness-and-whole-program-analyses.md) §7.5.3), and the cache (`C-20`, [12](12-incremental-evaluation-cache.md)).

### Demand-graph integration (§6)

- [x] Current source-to-IR cache path: `ParseCache::load_or_parse_bytes` maps source bytes, schema version, and parse flags to cached resolved frontend artifacts plus lowered `Ir`; cache hits return `CachedParse { resolved, ir }`, misses parse/resolve/lower and write the artifact, and import/native frontend lowering paths consume the cached `Ir` (§6, §7.2) — parse-node **P1/P2** substrate, `C-19`/`C-20`; gate: parse-cache key/hit/recovery/artifact tests.
- [ ] Full demand-graph compile-node integration remains: represent source→IR as an actual demand-graph node with speculation/early-cutoff semantics, add the simplifier compile-node keyed by input-IR hash, and add the lazy hot native-compile node over the same IR (§6) — simplify-node **P2** (`C-21`); native-compile **P6**.
  (Reconciliation note, 2026-07-12: the simplifier compile-node is scheduled in
  **P4**, per [26](26-optimization-pass-catalog.md)'s checklist and the task
  board; this **P2** reference predates that decision and is retained for
  history — **P4** is authoritative.)
- [ ] Disambiguation held in code/comments: "demand graph" (memoization graph) vs "graph reduction" (lazy evaluation) vs "derivation graph" (`.drv` DAG); IR nodes vs graph nodes never conflated (§6) — **P1** discipline.

### Serialization (§7)

- [x] Serialize the resolved frontend artifact plus lowered IR arena, side tables, file-local symbol table, optional analysis fact sidecar, and diagnostic metadata into parse-cache entry files (`resolved.bin`, `ir.bin`, `symbols.bin`, `facts.bin`, `meta.toml`) (§7.1) — **P1**, `S-19`/`S-11`. Implemented by the explicit little-endian artifact codecs in `cache::parse::{format,codec}`: `resolved.bin` stores resolved AST nodes, child pool, frames, node-frame links, with chains, and inherit-resolution tables; `ir.bin` stores the lowered arena, child pool, frames, with chains, attr paths, bindings, shapes, effects, and payload tags; `symbols.bin` stores the file-local symbol table; `facts.bin` stores per-node `ExprFacts` when present and binds them to the lowered-IR artifact fingerprint; `meta.toml` stores schema/source/count diagnostics. Covered by `entry_paths_follow_rfc_layout`, `resolved_artifacts_roundtrip_through_entry_files`, `lowered_ir_artifacts_roundtrip_through_entry_files`, fact sidecar roundtrip/corruption tests, metadata tests, and artifact validation/corruption tests.
- [x] Current owned parse-cache artifact decode path: cache entries read versioned little-endian `resolved.bin`/`ir.bin`/`symbols.bin` streams through `cache::parse::{format,codec}` into owned `ResolvedAst`/`Ir` Rust structures and validate those mandatory artifacts, then optionally overlay fingerprint-checked `facts.bin`; no borrowed mapped views are claimed (§7.1) — **P1/P2**, `S-19`/`S-11`; gate: parse-cache artifact roundtrip/validation tests.
- [ ] Near-`memcpy` serialization and zero-copy `mmap` loading remain future work: parse/IR artifacts still need a stable raw-memory layout plus validated borrowed/mapped views to replace the current `fs::read` + owned decode path (§7.1) — **P1/P2**, `S-19`/`S-11`; gate: zero-copy artifact layout tests plus parser/IR cache parity tests.
- [x] `blake3` content-addressed cache key over file content + `evaluator_schema_version` + lex/parse flags; wholesale invalidation on schema bump; advisory function-table semantics (§7.2) — **P1**, `S-15`. Implemented for the durable parse/compile artifact cache as `ParseCacheKey::for_source`, which hashes source bytes, `PARSE_CACHE_SCHEMA_VERSION`, and `ParseCacheFlags`; `ParseCache::load_or_parse_bytes` keys entries only by that digest, treats source hints as diagnostic metadata, reparses corrupt/incomplete artifacts, and reports write failures through `CachedParse::stored` instead of changing evaluator behavior. Covered by `keys_depend_on_source_schema_and_flags`, `load_or_parse_writes_then_hits_by_source_content`, `load_or_parse_recovers_from_corrupt_artifact`, `load_or_parse_treats_write_failures_as_cache_misses`, and file-memo rekey/share tests. The broader incremental value cache remains tracked by [12](12-incremental-evaluation-cache.md).
- [x] File-local `Symbol` remapping for load-order-independent IR hash (precondition for stable cross-run/cross-machine early cutoff) (§7.3) — **P1**, `S-14` enabler. Implemented by `cache::parse::file_local_resolved` and `SymbolRemapper`, which rebuild serialized artifacts against a deterministic file-local `SymbolTable` and remap symbol-bearing node data plus inherit-resolution targets before writing `symbols.bin`/`resolved.bin`/lowered `ir.bin`. Covered by `serialization_remaps_symbols_to_file_local_ids`, `lowered_ir_artifacts_roundtrip_through_entry_files`, and corrupt/duplicate symbol rejection tests. The future zero-copy `mmap` artifact layout remains tracked by the separate serialization row.

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
