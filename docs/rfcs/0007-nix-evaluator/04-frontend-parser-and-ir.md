# RFC-0007 - Frontend: Lexer, Parser, Arena AST, Scope Resolution, and IR

> Part of the RFC-0007 aos-nix documentation set. This document specifies the
> *frontend* of the evaluator: the path from raw `.nix` source bytes to a
> compact, scope-resolved intermediate representation (IR) that every execution
> tier consumes. It also specifies the content-addressed parse/compile cache
> that ensures the AOS package set is parsed exactly once.
>
> Read this alongside [architecture overview](03-architecture-overview.md) for
> how the frontend sits in the layered stack, [value representation](05-value-representation.md)
> for what the IR's evaluation produces, [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)
> for how the IR is lowered to native code, and [incremental evaluation cache](12-incremental-evaluation-cache.md)
> for how parse artifacts feed the systemic early-cutoff cache.

## 1. Scope and role of the frontend

The frontend is the part of aos-nix that turns a sequence of source bytes into
an evaluable program. It has one job and one constraint:

- **Job**: produce a *compact, immutable, scope-resolved IR* for an expression,
  such that the tree-walk oracle (tier0), the Cranelift baseline (tier1), and
  the Cranelift optimized tier (tier2) all consume the *same* IR. There is one
  parse, one resolve, one IR — never a separate AST per tier.
- **Constraint**: the frontend is a *latency-sensitive, high-volume* component.
  Evaluating the AOS package set means parsing tens of thousands of `.nix`
  files, the overwhelming majority of which (all of nixpkgs-style library code,
  `lib/`, module fixpoints) are parsed on nearly every evaluation. The frontend
  must be fast in absolute terms *and* must be cacheable so that, in steady
  state, almost no parsing happens at all.

The frontend is deliberately *boring and total*. It contains no speculation, no
laziness, no JIT, and no `unsafe` beyond the arena allocator's well-contained
core. It is the part of aos-nix that the safe-tree CI (miri, sanitizers — see
[integration with AOS](14-integration-with-aos.md)) exercises most heavily,
because correctness bugs here corrupt *every* tier simultaneously. A parser that
mis-associates `a.b or c.d`, mis-orders attribute keys, or mis-resolves a `with`
scope does not produce a slow `.drv` — it produces the *wrong* `.drv`, which
under the [hard compatibility constraint](02-compatibility-constraints.md) means
a different store path, a total cache miss, and a catastrophic from-source
toolchain rebuild.

Everything in this document is therefore subordinate to two facts:

1. **Parity is decided here first.** Token boundaries, operator precedence and
   associativity, attribute-path desugaring, `inherit` semantics, string and
   indented-string (`''`) escape handling, and `with`/`rec` scope visibility are
   all *observable* — they change which `.drv` is emitted. The frontend must
   match C++ Nix bug-for-bug, including its quirks.
2. **The frontend is on the incremental cache's critical path.** The IR is the
   unit that gets content-addressed (§9). A stable, canonical IR with stable
   hashes is what makes early cutoff ([incremental evaluation cache](12-incremental-evaluation-cache.md))
   work. Frontend design choices (arena layout, symbol interning, scope slots)
   are made partly to produce a *hashable, structurally-shared* artifact.

## 2. Design overview and the pipeline

```text
  source bytes (.nix file or expr string)
        │
        ▼
  ┌───────────┐   on-demand, byte-oriented, no allocation per token
  │  Lexer    │   ── Token stream (kind + byte span), interns string atoms
  └───────────┘
        │
        ▼
  ┌───────────┐   hand-written recursive descent + Pratt operator precedence
  │  Parser   │   ── Arena AST (Vec<Node>, NodeId = u32 index)
  └───────────┘
        │
        ▼
  ┌───────────┐   single bottom-up pass: bind names → static slots,
  │  Resolver │   ── classify `with`/dynamic, intern symbols, mark thunk needs
  └───────────┘
        │
        ▼
  ┌───────────┐   lowered, scope-annotated, desugared
  │    IR      │   ── consumed identically by tier0 / tier1 / tier2
  └───────────┘
        │
        ▼
  ┌──────────────────────┐  content-addressed by (file content hash, evaluator
  │ Parse/Compile Cache  │   schema version) → IR blob; reused across runs/CI
  └──────────────────────┘
```

The pipeline has four stages — **lex**, **parse**, **resolve**, **lower** — and
a cross-cutting **cache**. We discuss each, then the on-disk IR and the cache.

### 2.1 Why hand-written, not generated, and not lowered-from-rnix on the hot path

The design canon mandates a *hand-written recursive-descent parser producing a
compact arena AST, NOT a rowan lossless CST on the hot path*. The reasoning:

- **rnix / rowan is a lossless CST.** rnix is the de-facto Rust Nix parser; it
  is built on matklad's `rowan` crate and is explicitly *lossless* — it
  preserves every byte of trivia (whitespace, comments) so that "printing out
  the AST prints out 100% the original code," and it parses even completely
  invalid input. That is exactly the right design for an LSP, a formatter, or a
  refactoring tool, and it is exactly the *wrong* design for an evaluator's hot
  path. A lossless CST is *heap-heavy* (every node is a reference-counted green
  node with dynamically-typed children) and *trivia-laden* (the evaluator must
  re-skip whitespace and comments at every traversal). Snix/Tvix accept this
  cost — they "make heavy use of rnix-parser" and then run a separate compiler
  pass that lowers the rnix AST to bytecode — but that is a deliberate
  separation we can collapse.
- **A compact arena AST is cache-friendly and trivially serializable.** Our AST
  is a single `Vec<Node>` where every cross-reference is a `u32` index
  (`NodeId`), not a pointer. This is the standard "data-oriented" / arena AST
  used by rustc's HIR-ish lowerings, by many production compilers, and by
  matklad's own writing on the topic: contiguous storage, no per-node
  allocation, indices that survive `mem::swap` and serialization, and excellent
  cache locality during the resolve and lowering passes. Because every edge is
  an index into a flat buffer, the entire AST/IR can be `memcpy`-serialized to
  the parse cache and `mmap`-ed back without pointer fixups (§9).
- **We may still accept rnix as a *front door*.** Lowering an existing rnix CST
  into our arena IR is a supported (optional) ingestion path — useful for
  tooling interop and for differential testing against a known-good parser. But
  it is never on the steady-state hot path; the canonical pipeline is our own
  lexer + recursive-descent parser straight into the arena. The open question of
  whether to *only* hand-roll, or to *also* maintain an rnix-lowering shim, is
  tracked in [roadmap and risks](17-roadmap-and-risks.md).

Recursive descent is the right discipline because the Nix grammar is small,
LL-friendly at the statement/binding level, and only needs real machinery for
*expression precedence*, which we handle with a Pratt (top-down operator
precedence) sub-parser (§4.3). This is the same combination Crafting
Interpreters and matklad recommend: recursive descent for the keyword-led
constructs, Pratt for the operator soup. It yields a "simple, terse, readable
parser that can handle any grammar," with precedence and associativity expressed
as data (a binding-power table) rather than as a tower of one-function-per-level
grammar rules.

## 3. The lexer

### 3.1 Responsibilities and shape

The lexer is a byte-oriented, single-pass, zero-copy scanner. It does *not*
allocate per token; it produces a stream of `Token { kind: TokenKind, span: Span }`
where `Span = (u32, u32)` byte offsets into the source. The parser pulls tokens
on demand (the lexer is an iterator with one token of lookahead buffered), so we
never materialize a full token vector for large files unless a debugging mode
requests it.

```rust
/// A lexical token: a syntactic category plus its byte span in the source.
///
/// Tokens carry no owned data. String/identifier *content* is recovered from
/// the source slice on demand and interned only when the parser decides the
/// bytes are semantically significant (an identifier, an attribute key, a
/// string fragment) rather than trivia.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span, // (start, end) byte offsets; u32 each
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    // literals & identifiers
    Int, Float, Ident, Path, SPath /* <nixpkgs> */, Uri,
    // string machinery (see §3.3)
    StrStart, StrPart, StrEnd, IndStrStart, IndStrPart, IndStrEnd, DollarBrace,
    // keywords
    Let, In, If, Then, Else, With, Rec, Inherit, Assert, Or,
    // punctuation & operators
    Assign, Semi, Colon, Comma, Dot, At, Question,
    LParen, RParen, LBrace, RBrace, LBracket, RBracket, Ellipsis,
    Concat /* ++ */, Update /* // */, Arrow /* -> */, Impl,
    Plus, Minus, Star, Slash, Less, Greater, LessEq, GreaterEq,
    EqEq, NotEq, And /* && */, OrOr /* || */, Not /* ! */,
    // trivia (retained only for tooling/diagnostics; skipped by parser)
    Whitespace, LineComment, BlockComment,
    // terminal
    Eof,
}
```

### 3.2 Why byte-oriented and span-only

Three reasons, all about throughput and parity:

1. **No per-token allocation.** Interning happens lazily and only for tokens the
   parser keeps (identifiers, keys, string fragments). Trivia (`Whitespace`,
   `LineComment`, `BlockComment`) is emitted so that an optional tooling mode can
   reconstruct source, but the parser's `bump()` skips trivia without ever
   looking at its bytes. In hot evaluation, trivia tokens cost a `match` arm and
   nothing else.
2. **Spans are the universal diagnostic currency.** Every AST node records the
   span of the tokens it was built from. Errors, `builtins.trace`-style
   provenance, and the eventual debugger all index back into the original source
   by byte offset. Storing spans as `(u32, u32)` keeps `Token` small and `Copy`
   (an 8-byte span plus a one-byte `kind`), so the parser passes tokens by value.
3. **Parity demands byte-exact tokenization.** Nix's lexer has genuine quirks we
   must reproduce: paths (`./foo`, `../bar`, `/abs`, `~/home`), search paths
   (`<nixpkgs>`), and URIs (`https://...` is a *string literal* in Nix, not a
   comment-then-path) are all distinct token classes with subtle boundary rules.
   For example, `a/b` is *division* but `a /b` (space before, none after) and
   `./a/b` are *paths*; `1.2` is a float but `1.2.3` is not; `-` can be unary or
   binary. These are observable: misclassifying a URI as `ident + division`
   changes the parse tree and thus the `.drv`. The lexer encodes C++ Nix's
   actual `flex` rules, including the maximal-munch and lookahead behaviors, and
   the differential harness ([differential testing and benchmarking](15-differential-testing-and-benchmarking.md))
   includes a *token-level* conformance layer so divergences surface at the
   lexer, not three passes later.

### 3.3 String lexing as a small state machine

Nix strings are the lexer's most intricate region because of interpolation and
two string syntaxes:

- Double-quoted strings `"...${expr}..."` with C-style escapes.
- Indented strings `''...${expr}...''` with `''`-prefixed escapes and *automatic
  indentation stripping*, computed from the minimal common leading whitespace of
  all lines.

We lex strings as a *fragment stream*, not as a single token, because a string
is really an alternation of literal fragments and embedded `${...}` expressions:

```text
  "abc${x}def"   ⇒  StrStart  StrPart("abc")  DollarBrace … RBrace  StrPart("def")  StrEnd
```

The lexer maintains a small mode stack: inside a string it emits `StrPart`/`IndStrPart`
literal runs and, on `${`, pushes back into normal-expression mode (so the
parser can recurse) until the matching `}` pops back to string mode. The
parser (§4.4) reassembles these fragments into a string-concatenation IR node.

**Indented-string de-indentation is computed at parse/lower time, not lex
time**, and must match C++ Nix exactly: the common indentation is the minimum
leading-whitespace prefix over all non-blank lines (with specific rules for
lines that are entirely whitespace, for the first line, and for the handling of
`${...}` interpolations at line starts). This is a notorious parity trap; the
algorithm is reproduced verbatim from Nix's `lexer.l`/`parser.y` and is
exercised by a dedicated corner-case suite. Escape handling (`\n`, `\t`, `\\`,
`\${`, and the `''`-forms `'''`, `''$`, `''\n`) is likewise byte-for-byte.

### 3.4 Symbol interning at the lexer/parser seam

Identifiers and attribute keys are interned to a dense `u32` `Symbol` at the
point the parser commits them to the AST. The interner is a single per-process
table (`FxHashMap<&str, Symbol>` plus a `Vec<Box<str>>` for reverse lookup),
shared across all files in an evaluation. Interning is *table stakes* for a Nix
evaluator (see [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)):
it makes attribute-name comparison a `u32` equality, makes hidden-class shape
keys cheap, and lets the resolver compare scope-bound names without touching
strings. Because the table is shared and append-only, `Symbol`s are stable
within a run and can be *renumbered deterministically* when serializing IR to
the cache (§9.3) so that cache keys do not depend on file *load order*.

## 4. The parser

### 4.1 Arena AST: the data model

The parser emits a **compact arena AST**: a single growable buffer of fixed-size
nodes, with all child references expressed as `NodeId` (a `u32` index). There
are no `Box`es, no `Rc`s, and no recursion-shaped heap graph. This is the single
most important data-structure decision in the frontend.

```rust
/// An index into the AST arena. A `NodeId` is a 32-bit handle, not a pointer;
/// it remains valid across serialization and is the unit of cross-reference
/// throughout the frontend.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(u32);

/// One AST node. Fixed size so the arena is a flat `Vec<Node>` with O(1)
/// random access and cache-friendly linear passes. Variable-arity children
/// (list elements, call arguments, attrset bindings) are stored as a
/// contiguous `(start, len)` slice into a side `Vec<NodeId>` (the "child
/// pool"), not inline.
pub struct Node {
    pub kind: NodeKind,
    pub span: Span,
    pub data: NodeData, // kind-discriminated payload, sized to its widest variant
}

pub enum NodeKind {
    // atoms
    Int, Float, Str, Path, Uri, Ident,
    // composites
    List, AttrSet, RecAttrSet, Lambda, Apply, Select, HasAttr,
    LetIn, With, Assert, IfThenElse, BinOp, UnaryOp, Inherit, Interp,
    // post-resolve forms (filled in by the resolver, §6)
    LocalVar /* slot */, UpvalVar /* depth, slot */, GlobalVar /* symbol */,
    WithVar /* dynamic lookup */,
}
```

Why this shape:

- **Locality and density.** The resolver and the lowering pass walk the AST
  *linearly* far more often than they recurse it. A `Vec<Node>` keeps the whole
  tree in a handful of cache lines per region; pointer-chasing a boxed tree
  blows the cache. This is the same argument that drove data-oriented AST/IR
  layouts in modern compilers and that matklad articulates for arena trees.
- **Index stability and serialization.** Because every edge is a `u32` offset,
  the arena is *position-independent*: we can `bincode`/zero-copy serialize it to
  the parse cache and read it back without any pointer fixup (§9). Pointers
  could never do this.
- **Cheap subtree identity.** `NodeId` equality is `u32` equality. Combined with
  hash-consing of *values* later ([value representation](05-value-representation.md)),
  this gives us cheap structural keys for the incremental cache.
- **No deep recursion drops.** Dropping a 100k-node pointer tree is a recursive
  free storm (and can stack-overflow); dropping a `Vec<Node>` is a single
  deallocation.

### 4.2 Recursive descent for the statement skeleton

The parser is hand-written recursive descent. Each *non-expression* construct —
`let … in …`, `with … ; …`, `assert … ; …`, `if … then … else …`, lambda
patterns, attribute-set bodies, list bodies — maps to one parsing function that
peeks the next significant token and dispatches. This is the part of the grammar
that is keyword-led and trivially LL(1)-ish, exactly where recursive descent is
"straightforward because you can figure out what to parse from the next token."

```rust
fn parse_expr(&mut self) -> NodeId {
    match self.peek() {
        TokenKind::Let    => self.parse_let_in(),
        TokenKind::With   => self.parse_with(),
        TokenKind::Assert => self.parse_assert(),
        TokenKind::If     => self.parse_if(),
        _                 => self.parse_pratt(0), // operator/application soup
    }
}
```

Lambda-vs-other disambiguation (the genuinely tricky LL bit) is handled with
bounded lookahead: an identifier followed by `:` is a simple lambda
(`x: body`); a `{` may begin an attribute set *or* a formal-argument pattern
(`{ a, b ? d, ... }:` or `{ a, b }@args:`), distinguished by scanning ahead for
the pattern-terminating `:` past the matching `}`. C++ Nix resolves this in its
`yacc` grammar via a GLR-ish ambiguity that we reproduce with explicit,
documented lookahead. This is parity-sensitive and has its own test cases.

### 4.3 Pratt parsing for operators

Expression precedence and associativity are handled by a Pratt (top-down
operator precedence) loop, not by a tower of grammar levels. Every infix/postfix
operator carries a *binding power*; the loop consumes operators while their left
binding power exceeds the caller's minimum, recursing for the right operand at
the appropriate power. Associativity falls out of whether the right recursion
uses the same or `power+1`. This is matklad's "simple but powerful Pratt
parsing" applied directly.

The binding-power table is *the* parity-critical artifact for expressions. Nix's
operator precedence and associativity (from highest to lowest) is fixed and must
be reproduced exactly:

| Prec | Operator(s)                     | Assoc        | Notes                                   |
|-----:|---------------------------------|--------------|-----------------------------------------|
|  1   | `e . attrpath [or e]`           | —            | attribute selection (with `or` default) |
|  2   | `e1 e2`                         | left         | function application                    |
|  3   | `- e` (numeric negation)        | prefix       | unary minus                             |
|  4   | `e ? attrpath`                  | none         | has-attribute test                      |
|  5   | `e1 ++ e2`                      | right        | list concatenation                      |
|  6   | `e1 * e2`, `e1 / e2`            | left         | multiplicative                          |
|  7   | `e1 + e2`, `e1 - e2`            | left         | additive (`+` also string/path concat)  |
|  8   | `! e`                           | prefix       | boolean negation                        |
|  9   | `e1 // e2`                      | right        | attrset update                          |
| 10   | `<`, `>`, `<=`, `>=`            | none         | relational                              |
| 11   | `==`, `!=`                      | none         | equality                                |
| 12   | `e1 && e2`                      | left         | logical and                             |
| 13   | `e1 || e2`                      | left         | logical or                              |
| 14   | `e1 -> e2`                      | none         | logical implication                     |

> The precedence numbers above are a *presentation order* for this table; the
> implementation uses the exact binding-power encoding that reproduces Nix's
> grammar, including the non-associative operators that error on chaining
> (`a == b == c` is a parse-level rejection, not a left/right fold) and the
> fact that `+` performs string/path concatenation as well as numeric addition
> — a typing decision deferred to evaluation, not parsing. Any disagreement with
> C++ Nix on these is caught by the differential harness.

`select` (`.`) is special: it is the tightest-binding form, takes an
*attribute path* (a dotted sequence possibly containing dynamic `${...}`
components), and optionally a trailing `or default`. The parser desugars
`a.b.c` into nested `Select` nodes and threads the optional `or` default
through, because that is what evaluation needs and what `?` (`HasAttr`) mirrors.

### 4.4 Desugaring performed at parse time

The parser performs a small, *parity-preserving* set of desugarings so that
downstream passes see fewer node kinds. Each desugaring is chosen so that it
does not alter observable evaluation order or error behavior:

- **String interpolation** `"a${x}b"` ⇒ `Interp([Str("a"), x, Str("b")])`, a
  single concatenation node whose evaluation coerces and `+`-folds fragments in
  left-to-right order (with string-context union — see
  [derivation and store compatibility](11-derivation-and-store-compatibility.md)).
- **Attribute paths** `a.b.c` ⇒ nested `Select`; `a.b.c = v` in an attrset ⇒
  nested singleton attrsets that *merge* with sibling keys at the same prefix.
  This merge is observable (e.g. `{ a.b = 1; a.c = 2; }`), so it follows Nix's
  exact merge-and-conflict rules.
- **`inherit`** `inherit a b;` ⇒ bindings `a = a; b = b;` resolved in the *outer*
  scope; `inherit (e) a b;` ⇒ `a = e.a; b = e.b;` with `e` evaluated once.
  Inherit is desugared but its scoping (outer vs. the enclosing `rec`) is
  preserved precisely.
- **Indented string de-indentation** (§3.3) is resolved here, producing ordinary
  `Str`/`Interp` fragments.

Desugarings that would change *order of effects* or *which thunk is forced when*
are **not** performed (e.g. we do not reorder attrset bindings, and we do not
constant-fold, at parse time — constant folding is a later, separately-validated
optimization in [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)).

### 4.5 Error recovery posture

Unlike rnix (which must recover from arbitrary invalid input for LSP use), the
evaluator's parser is allowed to *stop at the first error* on the hot path,
because an unparseable file is an evaluation error in Nix anyway. We do,
however, retain enough span and trivia information that a *diagnostics mode* can
produce C++ Nix-compatible error messages and locations — message parity is not
a `.drv`-parity requirement, but it matters for developer trust and for the
conformance suite, some of which asserts on error text.

## 5. From AST to IR: what "IR" means here

The frontend's output is not the raw AST; it is an **IR**: the AST after scope
resolution and lowering. The IR differs from the AST in three ways:

1. **Variables are resolved to static accesses.** Every `Ident` becomes a
   `LocalVar(slot)`, `UpvalVar(depth, slot)`, `GlobalVar(symbol)`, or
   `WithVar(...)` (§6). No name lookup survives into evaluation except the
   genuinely dynamic `with` case.
2. **Thunking is explicit.** Each subexpression is annotated with whether
   evaluating it requires building a thunk or can be evaluated eagerly in place.
   The first cut marks *everything non-trivial* as thunked (matching Nix
   semantics conservatively); strictness analysis later *removes* thunks (see
   [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)).
   Crucially, the IR carries the *slots* and *shape hints* that those analyses
   annotate, so the analyses are passes over the IR, not a separate
   representation.
3. **It is the single lowering source for all tiers.** tier0 interprets the IR
   directly; tier1/tier2 lower the *same* IR to Cranelift CLIF
   ([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)). There
   is exactly one IR so that a thunk compiled by tier1 and the same thunk
   interpreted by tier0 are *guaranteed* to agree — which is what makes the
   tree-walk oracle a valid correctness reference and what makes deoptimization
   (falling back from tier2 to tier0) sound.

The IR is still a flat arena (same `Vec<Node>` discipline, extended with the
post-resolve node kinds and side tables for scope frames). It is, in effect, the
AST with the holes filled in — not a new data structure.

### 5.1 Why one IR for all tiers (and why this is unusual)

Most tiered systems (HotSpot, V8) carry *different* IRs per tier (bytecode for
the interpreter, Sea-of-Nodes/Turbofan IR for the optimizer). We deliberately do
not, for two reasons specific to our situation:

- **Correctness oracle.** The tree-walk tier exists primarily to be *obviously
  correct* and to validate every other tier against it. If tier0 and tier1 ran
  different IRs, "tier0 is the oracle" would be a weaker claim. Sharing the IR
  makes tier-vs-tier differential testing a within-process check.
- **Deopt target.** tier2 speculation must be able to bail to a tier0
  interpretation of the *same program point* with the *same live state*. A
  shared IR with explicit slots makes the deopt state map (which IR slot holds
  which live value) a direct correspondence rather than a translation. This is
  the HotSpot uncommon-trap discipline, simplified by purity.

The cost — that we cannot specialize the IR shape per tier — is acceptable
because the *optimizations* (strictness, escape analysis, hidden-class
specialization) are expressed as IR *annotations* and as choices made during
CLIF lowering, not as a different IR. Open question: whether a tier2-only
"super-node" fusion IR is eventually warranted is deferred to
[roadmap and risks](17-roadmap-and-risks.md).

## 6. Scope resolution

Scope resolution is the bridge from a named AST to a slot-indexed IR. It is the
single most semantically delicate frontend pass after the parser, because Nix
has *four* distinct binding mechanisms, two of which are lexical and static and
two of which complicate static resolution.

### 6.1 Nix's binding forms

| Form          | Introduces                                  | Static? | Resolution                                    |
|---------------|---------------------------------------------|---------|-----------------------------------------------|
| `let … in`    | a fixed set of mutually-recursive bindings  | yes     | slot in the enclosing frame                   |
| `x: body`     | one lambda parameter                        | yes     | slot 0 of a new frame                         |
| `{a, b?d}@as:`| formal params + optional `@`-alias          | yes     | one slot per formal + alias slot              |
| `rec { … }`   | mutually-recursive attrset bindings         | yes     | slot in a new `rec` frame (self-visible)      |
| `with e; …`   | *all* attributes of `e`, resolved at runtime| **no**  | dynamic fallback (§6.3)                        |

The first four are *lexical*: at any program point the parser/resolver knows
statically which names are in scope and can assign each a `(depth, slot)`
coordinate — a de Bruijn-style addressing. de Bruijn indexing is exactly the
classical tool for "representing terms without naming bound variables," where a
lexically-scoped variable reference is resolved by counting the binders between
the use and its binder. We use a mild variant: a *frame depth* (how many lambda/
let/rec frames out) plus a *slot index* within that frame, which is what compiled
code wants (an array index off an environment pointer) rather than a single
collapsed index.

### 6.2 The resolution algorithm

The resolver walks the arena AST bottom-up, maintaining a stack of *scope
frames*. Each binder pushes a frame listing its bound `Symbol`s (interned at
parse time); each `Ident` reference is looked up by scanning frames inner-to-
outer:

```text
  resolve(ident sym):
    for depth, frame in scopes.iter().rev().enumerate():
        if let Some(slot) = frame.lookup(sym):
            return if depth == 0 { LocalVar(slot) }
                   else          { UpvalVar(depth, slot) }
    if any enclosing `with` is active:
        return WithVar(sym, with_chain)     # dynamic, §6.3
    if sym is a builtin/global:
        return GlobalVar(sym)               # e.g. `true`, `builtins`, `map`
    else:
        error: undefined variable `sym`     # parity-exact message & position
```

Because all names are pre-interned `Symbol`s, each frame lookup is a small linear
or hashed `u32` scan; frames are tiny (a `let`/lambda binds a handful of names),
so linear scan is typically fastest. The result is that *every lexical variable
access in the IR is a constant `(depth, slot)`* — the runtime environment is a
flat array per frame, and access is `env[slot]` (depth 0) or a parent-chain walk
(`env.parent^depth[slot]`), never a hash lookup. This is the standard "resolve
to a stack slot once, at compile time" technique that Crafting Interpreters'
resolver pass performs and that turns variable access from a map lookup into an
array index.

`rec` frames and `let` frames are *self-visible* (all bindings see each other),
so the frame is pushed *before* resolving any of its right-hand sides; a binding
referring to a later sibling is fine, and a binding referring to itself produces
the same thunk-cycle behavior Nix has (caught at force time as infinite
recursion via the blackhole, see [value representation](05-value-representation.md)).

### 6.3 The `with` problem: where static resolution stops

`with e; body` makes *every attribute of `e`* available as an unqualified name
inside `body`, but **which** attributes exist is only known at runtime (`e` is an
arbitrary, possibly lazily-computed attrset). This defeats fully-static
resolution and is the single biggest reason Nix evaluation is harder to compile
than a typical lexically-scoped language.

Our resolver does *not* try to statically know `with` contents. Instead, it
classifies each unresolved identifier under an active `with` as a `WithVar`,
recording the *chain* of enclosing `with` scopes (innermost first) that must be
probed at runtime. Critically, Nix's scoping rule is that **lexical bindings win
over `with`**, and **inner `with` wins over outer `with`** — so a name is a
`WithVar` *only if* no lexical binder shadows it, and the runtime probe walks the
`with` chain inner-to-outer. We reproduce this resolution order exactly; getting
it wrong is a parity bug.

We mitigate the runtime cost of `with` with two compile-time facts the resolver
can still record, even without knowing `e`'s contents:

- **Whether *any* `with` is in scope at all.** Most identifiers in real Nix are
  lexically bound or global; `WithVar` is comparatively rare. The resolver emits
  `WithVar` only when forced to, so the common path stays a static slot access.
- **The static `with` chain depth.** The runtime probe is bounded by the number
  of enclosing `with`s, which is statically known and usually one. The probe
  itself benefits from the attrset *hidden-class / inline-cache* machinery
  ([attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)):
  once a `with`'s attrset shape is seen, the membership test and offset are
  cached per site.

The deeper optimization — speculatively assuming a `with` resolves to a known
shape and deoptimizing if not — is a tier2 concern, not a frontend one, and is
discussed in [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).
The frontend's job is only to *mark* the dynamic sites precisely.

### 6.4 Closure capture: computing upvalues

When the resolver assigns `UpvalVar(depth, slot)` it is, by definition, recording
that a lambda body captures a binding from an *enclosing* frame. The resolver
accumulates, per lambda, the exact set of captured `(depth, slot)` coordinates —
the lambda's *free variables*. This free-variable set is what the runtime closure
record must capture (a lambda value is `(code, captured_env)` per the
[architecture overview](03-architecture-overview.md)). Computing it precisely at
resolve time means closures capture *only* what they use — no over-capture of the
whole enclosing environment — which keeps closure records small, reduces what the
GC must trace ([memory management and GC](06-memory-management-and-gc.md)), and is
a prerequisite for escape analysis to prove a closure non-escaping
([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)).

### 6.5 Resolver outputs (side tables)

The resolver annotates the arena in place and produces a few compact side
tables, all index-addressed for serializability:

```rust
/// Per-function scope metadata produced by the resolver.
pub struct FrameInfo {
    pub slot_count: u32,           // size of this frame's env array
    pub captures: Box<[Upvalue]>,  // free-var coordinates this lambda closes over
    pub rec: bool,                 // self-visible frame (let / rec)
    pub has_with: bool,            // any `with` active within → may emit WithVar
}

/// A captured variable: where it lives relative to the *defining* frame.
pub struct Upvalue { pub depth: u16, pub slot: u16 }
```

These tables, plus the rewritten `LocalVar`/`UpvalVar`/`GlobalVar`/`WithVar`
nodes, *are* the scope-resolved IR. Nothing about names remains except the
`Symbol`s needed for `GlobalVar`/`WithVar`/attribute keys.

## 7. Worked example: source → tokens → AST → IR

Consider:

```text
let
  x = 1;
  f = y: x + y;
in f 41
```

**Tokens** (trivia elided):

```text
Let  Ident("x") Assign Int(1) Semi
     Ident("f") Assign Ident("y") Colon Ident("x") Plus Ident("y") Semi
In   Ident("f") Int(41)
```

**Arena AST** (NodeIds shown as `#n`; child pools as `[...]`):

```text
#0 Int(1)
#1 Ident("y")                       ; lambda param (pre-resolve)
#2 Ident("x")                       ; body ref
#3 Ident("y")                       ; body ref
#4 BinOp(Plus, #2, #3)
#5 Lambda(param=y, body=#4)
#6 Ident("f")                       ; apply callee
#7 Int(41)
#8 Apply(#6, #7)
#9 LetIn(bindings=[x=#0, f=#5], body=#8)
```

**Scope-resolved IR** (the `let` frame has slots `x→0`, `f→1`; the lambda frame
has `y→0`):

```text
#0 Int(1)
#2 UpvalVar(depth=1, slot=0)        ; `x`  → enclosing let frame, slot 0
#3 LocalVar(slot=0)                 ; `y`  → lambda frame, slot 0
#4 BinOp(Plus, #2, #3)
#5 Lambda(frame={slots=1, captures=[(1,0)]}, body=#4)   ; captures x
#6 LocalVar(slot=1)                 ; `f`  → let frame, slot 1
#7 Int(41)
#8 Apply(#6, #7)
#9 LetIn(frame={slots=2, rec=true}, bindings=[#0, #5], body=#8)
```

After resolution, no IR node performs a name lookup: `x` is `parent[0]`, `y` is
`env[0]`, `f` is `env[1]`. The lambda's capture set is exactly `{(1,0)}` — it
closes over `x` and nothing else. This is the artifact every tier consumes, and
the artifact the parse cache stores.

## 8. Parity hazards catalogued

A consolidated list of frontend decisions that are *observable* in the emitted
`.drv` and therefore locked to C++ Nix behavior. Each has dedicated conformance
tests; divergence on any of these is a release blocker under
[compatibility constraints](02-compatibility-constraints.md).

| Area            | Hazard                                                                 |
|-----------------|------------------------------------------------------------------------|
| Lexer           | path vs. division (`a/b` vs `a /b` vs `./a`), URI-as-literal, float boundaries |
| Indented strings| common-indentation algorithm, blank-line handling, `${}` at line start |
| Escapes         | `\n \t \\ \${` in `"…"`; `'' ''$ ''\\` forms in `''…''`                 |
| Operators       | full precedence/associativity table (§4.3), non-assoc chaining errors  |
| Attr paths      | `a.b.c = …` merge rules, conflict detection, dynamic `${}` keys         |
| Attr ordering   | binding/iteration order (interacts with attrset shapes §9)             |
| `inherit`       | `inherit x` vs `inherit (e) x` scope (outer vs enclosing `rec`)         |
| `with`          | lexical-beats-`with`, inner-`with`-beats-outer probe order (§6.3)       |
| Errors          | undefined-variable detection point and message (conformance, soft gate)|

## 9. The parse / compile cache

> Full incremental machinery (early cutoff on *values*, cross-run persistence,
> Attic integration) is specified in [incremental evaluation cache](12-incremental-evaluation-cache.md).
> This section covers only the *frontend's* layer: caching the deterministic
> function `source bytes → scope-resolved IR`.

### 9.1 Why the frontend cache matters on its own

Parsing the AOS package set repeatedly is pure waste: the same `lib/` files, the
same module library, the same package definitions are re-lexed, re-parsed, and
re-resolved on every evaluation even though their bytes did not change. The
frontend cache turns "parse the whole package set" into "parse the handful of
files that changed since last run." This is a constant-factor win, but a large
and *certain* one, and it is the foundation the value-level early-cutoff cache
builds on (you cannot get early cutoff on a node you re-parse every time).

### 9.2 Cache key: content hash, not mtime

The cache is **content-addressed**. The key for a file is:

```text
parse_cache_key = H( file_content_bytes
                   ⧺ evaluator_schema_version
                   ⧺ relevant_lex/parse_flags )
```

- **`H` is blake3** for this durable, potentially cross-machine artifact —
  cryptographic and collision-safe at package-set scale, per the project hashing
  policy (xxh3 for in-process hot hashing; blake3 for durable content-addressed
  caches; SHA-256 *only* for Nix-observed drv/store hashes — never for our
  internal caches). Using blake3 here keeps a clean separation from the
  Nix-observable SHA-256 surface.
- **Content, not mtime.** mtime-based invalidation is unreliable under checkouts,
  `nix store` materialization, and CI cache restoration (which rewrites
  timestamps). Content addressing is the only sound key: identical bytes ⇒
  identical IR ⇒ identical key, regardless of path or timestamp. This mirrors how
  Nix itself is content-addressed and how Salsa/incremental frameworks key
  derived queries on input *content*.
- **`evaluator_schema_version`** is bumped whenever the IR layout, the desugaring
  set, the resolver's slot assignment, or the serialization format changes. A
  schema bump invalidates the whole cache wholesale — correct and cheap, since
  re-parsing is fast.

`import` (and the file-resolution machinery in
[primops and runtime ABI](10-primops-and-runtime-abi.md)) keys its own
parsed-file memoization on *realpath + content hash*, so a file reached via two
paths (symlinks, search-path indirection) is parsed once and the IR is shared.

### 9.3 What is cached, and serialization

The cached artifact is the **scope-resolved IR arena plus its side tables** — the
full output of §6, not the raw AST. Because the arena is index-addressed
(NodeIds, child-pool offsets, `(depth, slot)` coordinates) and carries no
pointers, serialization is close to a `memcpy`: the `Vec<Node>`, the child pool,
the `FrameInfo` tables, and a *local* symbol table are written contiguously. On
load, the blob can be deserialized cheaply (and, as an optimization,
`mmap`-mapped with zero-copy access into the node arrays).

The one subtlety is **symbol portability**. The global interner numbers
`Symbol`s by first-seen order, which depends on file *load order* and would make
the same file's IR hash differently across runs. The cache therefore stores a
*file-local* symbol table (the distinct identifier/key strings this file uses)
and rewrites in-IR `Symbol`s to *local* indices on store, remapping them back to
global `Symbol`s (interning the local strings into the shared table) on load.
This makes the serialized IR — and thus its cache key and any value-hash derived
from it — independent of load order, which is a precondition for stable
cross-run, cross-machine early cutoff.

### 9.4 Cache layout

```text
$AOS_NIX_CACHE/parse/
  <blake3-of-key>/
    ir.bin         # serialized arena: nodes, child pool, frame tables
    symbols.bin    # file-local symbol table (strings)
    meta.toml      # schema version, source path hint, sizes (diagnostics only)
```

```toml
# meta.toml — diagnostic metadata only; never part of the cache key's identity.
schema_version = 7
source_hint    = "pkgs/foo/default.nix"
node_count     = 3194
symbol_count   = 412
```

The cache is *purely a function table*: given the key, the entry is reproducible
from source, so corruption or eviction is never a correctness problem — only a
performance one. It is safe to share across CI machines (it extends AOS's
existing Attic-backed sharing from build outputs to *eval* artifacts, per
[incremental evaluation cache](12-incremental-evaluation-cache.md)), and safe to
GC by LRU.

### 9.5 Relationship to the value-level incremental cache

The frontend cache answers "have I parsed *these bytes* before?" The value-level
incremental cache ([incremental evaluation cache](12-incremental-evaluation-cache.md))
answers the far more powerful question "have I *evaluated* this expression in this
environment before, and is the result unchanged?". The frontend cache is the
*enabler*: it provides stable, content-addressed IR node identities and a stable
IR hash, which the value cache uses as part of the key for memoizing thunk and
derivation results and for early cutoff. The mantra "the fastest evaluator is the
one that does not evaluate" starts here, with "the fastest parser is the one that
does not parse."

### 9.6 Parse and compile as deferred, parallel, speculative demand-graph nodes

The frontend cache (§9.1–§9.5) treats a file's IR as a memoized, content-addressed
artifact. The natural next step is to recognize that **parsing and compiling a file
are themselves deferred units of work — graph nodes in the unified demand graph,
exactly like thunks** — and to schedule them on the same demand-driven, parallel,
speculative machinery the rest of the evaluator uses. This is the
unified-demand-graph framing of [architecture overview](03-architecture-overview.md)
§3.4: parse, compile, and force are all *node kinds* in one demand-driven
incremental dataflow graph (the Adapton/Salsa model), differing only in effect
class and granularity. A file's IR is a *pure function of its bytes* (the
parse-cache key, §9.2), which makes this not just convenient but sound.

This unifies three stages under one model:

```text
   file bytes ──parse-node──► AST/IR ──compile-node──► native code ──thunk──► value
               (cheap, lazy,            (expensive,                 (the value-
                parallel,               demand+hotness               level graph,
                speculative)            driven)                      doc 12)
```

**Lazy — parse on demand, compile on heat.** Nix `import` is already lazy: an
imported file's value is a thunk, parsed only when that thunk is first forced (a
property C++ Nix shares via its file-parse cache). We extend the laziness *down a
second level*: parsing to AST/IR happens on first `import` demand, but **native
compilation of a file's functions is deferred until they are actually hot** — the
same tiering logic [execution tiers](08-execution-tiers-and-cranelift.md) applies to
thunks, applied to files. A file that is imported but whose functions never run hot
is parsed (cheap) and never Cranelift-compiled (expensive). Parse and compile become
two nodes with *different eagerness*: parse is cheap enough to do eagerly or
speculatively; native compile stays demand- and profile-driven.

**Parallel — independent files parse and compile concurrently.** Because a file's
IR depends only on its content, parse/compile demand-graph nodes for distinct files
are independent and run on the rayon work-stealing pool
([parallel evaluation](13-parallel-evaluation.md)):
parsing the AOS package set (or nixpkgs) is embarrassingly parallel across files.
Neither C++ Nix nor Tvix does this — both parse serially, on demand, on the
evaluating thread. A parse/compile node is just another work item the work-stealing
(Chase-Lev) scheduler can run on any idle worker.

**Speculative — prefetch along statically-known import edges.** The import graph is
*partially statically knowable*: an `import ./foo.nix` with a literal path is a static
edge discoverable from a file's AST without evaluating anything. Idle workers can
**speculatively parse (and, less eagerly, pre-compile)** files reachable along those
static edges, ahead of the demand that will force them, so the IR is already warm in
the cache when the thunk forces. This is prefetching/prefaulting applied to the
front-end, hiding parse latency behind CPU work the evaluator is doing anyway.

**The non-negotiable guardrail: speculation must be side-effect-free and
error-quarantined.** This is the same discipline as the incremental cache's purity
requirement and CPU speculative execution: *a speculative parse/compile must never
change observable behavior.* This is the **error quarantine** rule (the general
**effect class** discipline of [architecture overview](03-architecture-overview.md)
§3.4: speculation and re-execution are sound only for *pure* nodes). The sharp
case is **parse errors**. In Nix, a syntax
error in a file fires **only when that file is actually imported** (errors are lazy).
If we speculatively parse a file that contains a syntax error but the real evaluation
never imports it, surfacing that error would invent a divergence from C++ Nix. So:

- A speculative parse/compile failure is **stashed against the node, not raised.** It
  is re-raised *only if and when the file is genuinely demanded* by evaluation — at
  which point it reproduces exactly the error C++ Nix would have produced at that
  point.
- Speculation does **no I/O beyond reading the candidate file** (which is itself a
  pure, content-hashed read keyed into the cache, §9.2), performs no effects, and its
  *only* observable output is a warm cache entry. Whether a file was speculated or
  parsed on demand must be **unobservable** to evaluation.
- Speculation is **bounded** — it runs only on otherwise-idle workers, prioritizes
  static edges over guesses, and caps depth — so a mis-speculated file (parsed but
  never imported) costs at most some idle-core time, never correctness.

**Why this is sound here and rare elsewhere.** Treating parse/compile as pure,
memoized, content-addressed demand-graph nodes — lazy, parallel, and speculative — is
the same synthesis thesis ([architecture overview](03-architecture-overview.md)) applied
to the front-end: Nix's purity and the content-addressed parse cache make front-end
work a first-class citizen of the deferred-execution graph rather than a serial
prelude to it. The error-quarantine rule is what keeps speculation from leaking into
the bug-for-bug `.drv` parity the whole RFC defends.

**Phasing.** The *lazy* split (parse on import, native-compile on heat) and *parallel*
parse across files are straightforward wins and ride the existing cache + rayon pool;
they are committed. *Speculative* prefetch is the measure-gated part — its
aggressiveness (how far down static edges, whether to pre-compile or only pre-parse)
is tuned against profiles, because mis-speculation wastes cores. See the
[decision register](19-decision-register.md).

## 10. Performance characteristics and measurement

Per the **measure-first** discipline ([motivation and goals](01-motivation-and-goals.md),
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md)),
we do not assume the frontend is or isn't the bottleneck — we instrument it. The
frontend exposes counters compatible in spirit with `NIX_SHOW_STATS`:

- bytes lexed, tokens produced, AST nodes, IR nodes, frames, captures;
- parse-cache hit/miss counts and hit ratio (the steady-state target is a hit
  ratio approaching 1.0 across the package set after the first run);
- wall time per stage (lex / parse / resolve / serialize), so a regression in any
  stage is attributable.

Expected shape, to be *confirmed not assumed*: after warm caches, frontend time
should be a small fraction of total eval time, with the dominant remaining cost
being the genuine *evaluation* of changed expressions. If measurement shows
parsing dominating even with warm caches (e.g. cache thrash from poor keying),
that is a frontend bug, not a reason to optimize the interpreter. The build order
in [roadmap and risks](17-roadmap-and-risks.md) puts "parser + scope + tree-walk
oracle + differential harness" in phase 1 precisely so that this baseline number
exists before any Cranelift work begins.

## 11. Prior art and where our choices come from

- **rnix / rowan** — the canonical Rust Nix parser and its lossless-CST
  substrate. We *reject it on the hot path* (lossless CST is heap- and
  trivia-heavy, wrong for an evaluator) while *respecting it* as an optional
  ingestion/interop front door and as a differential oracle. Snix/Tvix's choice
  to lower rnix → bytecode is the alternative we collapse into a single
  hand-written pipeline.
- **Snix (formerly Tvix)** — the closest active Rust prior art: a bytecode VM
  built on rnix, still explicitly not feature-complete and deferring optimization
  until nixpkgs-correct, with no `.drv`-parity guarantee and an unstable CLI. We
  borrow its *separation of concerns* and its reuse of the C++ conformance suite,
  but our frontend targets a compact arena IR shared across tiers rather than a
  single bytecode VM, and parity is our *gate*, not a later goal.
- **Crafting Interpreters / matklad** — the recursive-descent + Pratt parsing
  combination and the *resolve-variables-to-slots-once* pass are taken directly
  from this lineage. Pratt parsing expresses Nix's precedence table as data;
  the resolver turns name lookups into array indices.
- **de Bruijn indexing** — the formal basis for our `(depth, slot)` static
  addressing of lexical variables; resolving a use to a count of intervening
  binders is the classical technique we adapt to a frame/slot pair for
  array-indexed environments.
- **Arena / data-oriented ASTs** — the flat-`Vec<Node>`, `u32`-index design is
  the modern compiler-engineering default (rustc-style arenas, matklad's writing
  on arena trees) chosen here additionally for its *serializability* into the
  content-addressed parse cache.
- **Salsa / incremental computation** — motivates content-addressed,
  not-mtime keying of parse artifacts and frames the frontend cache as the base
  layer of the demand-driven incremental graph detailed in
  [incremental evaluation cache](12-incremental-evaluation-cache.md).

## 12. Open questions

1. **rnix shim: maintain or not?** **Decision (closed): hand-roll exclusively;
   rnix is a test-harness-only dependency.** The production path is the
   hand-written lexer/parser → arena IR; rnix is used solely as a cross-checking
   oracle in the differential parser tests (and any external tooling that wants a
   lossless CST consumes rnix directly, not through aos-nix). No permanent
   `rnix → arena IR` lowering path is maintained, avoiding a second frontend to
   keep in parity. Tracked in [roadmap and risks](17-roadmap-and-risks.md).
2. **Diagnostic message parity depth.** How closely must error *text* match C++
   Nix? `.drv` parity does not require it, but the conformance suite asserts on
   some messages. We treat message parity as a soft, best-effort gate.
3. **Trivia retention cost.** Emitting trivia tokens for tooling has a small hot-
   path cost (extra `match` arms). Measure whether a trivia-suppressing lexer
   mode for the pure-eval path is worth the code duplication.
4. **Tier2 super-node IR.** Whether a tier2-only fused IR ever pays for itself
   given the "one IR for all tiers" invariant (§5.1). Deferred until tiering is
   real and measured.
5. **`with`-shape speculation hooks.** What, if anything, the frontend should
   pre-compute to help tier2 speculate on `with` shapes — versus leaving it
   entirely to runtime inline caches. Cross-cuts
   [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md).

## Implementation checklist

Per-feature tracker for the frontend (lexer, parser, arena AST, scope resolution, IR lowering, and the parse/compile cache); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

Frontend is the **P1** foundation (decision `S-11`): every item below lands under the tree-walk oracle and is gated by the differential `.drv` harness plus the token-/parse-level conformance layers ([20](20-nix-language-conformance.md)) before any optimization tier exists.

### Lexer (§3)

- [x] Byte-oriented zero-copy scanner emitting `Token { kind, span }` with one-token lookahead, no per-token allocation (§3.1) — **P1**, `S-11`; token-level differential conformance ([15](15-differential-testing-and-benchmarking.md)).
- [x] `TokenKind` taxonomy incl. path / search-path (`<nixpkgs>`) / URI-as-literal classes and the maximal-munch boundary rules (`a/b` vs `a /b` vs `./a`, float boundaries) (§3.2) — **P1**; parity-hazard conformance (§8, doc 20).
- [x] String-fragment state machine: `StrStart`/`StrPart`/`DollarBrace`/… mode stack for double-quoted and indented strings (§3.3) — **P1**; corner-case suite.
- [ ] Indented-string de-indentation algorithm (common-indentation, blank-line, line-start `${}` rules) reproduced bit-for-bit, plus all escape forms (§3.3) — **P1**; dedicated corner-case conformance suite.
- [x] Trivia emission (whitespace/comments) for tooling, skipped by the parser's `bump()`; trivia-suppressing pure-eval mode left as a single retained-trivia lexer for now (§3.2, §12 Q3) — **P1** baseline, `M-16` (measure-gated; single lexer is the default).
- [ ] Symbol interner at the lexer/parser seam: dense `u32` `Symbol`, shared append-only table, deterministic renumbering for cache serialization (§3.4) — **P1**, `S-11`.

### Parser (§4)

- [x] Compact arena AST: single `Vec<Node>`, `u32` `NodeId` cross-references, side child pool for variable-arity children — no `Box`/`Rc` (§4.1) — **P1**, `S-11`; differential parser tests vs the rnix oracle (`C-7`).
- [x] Recursive-descent statement skeleton (`let`/`with`/`assert`/`if`, lambda patterns, attrset/list bodies) (§4.2) — **P1**.
- [x] Bounded-lookahead lambda-vs-attrset disambiguation reproducing C++ Nix's yacc ambiguity (§4.2) — **P1**; dedicated parity tests.
- [x] Pratt operator sub-parser with the exact Nix binding-power table, incl. non-associative chaining rejection and `+` overload deferral (§4.3) — **P1**; full precedence/associativity conformance (§8, doc 20).
- [x] `Select`/`HasAttr` attribute-path parsing with `or` defaults and dynamic `${}` components (§4.3) — **P1**.
- [ ] Parse-time desugarings — interpolation → `Interp`, attr-path merge, `inherit` / `inherit (e)`, indented-string resolution — each proven order-/error-preserving, with no constant folding or binding reorder (§4.4) — **P1**; attr-path merge + `inherit`-scope conformance (§8).
- [ ] First-error stop on the hot path plus span/trivia retention for a C++ Nix-compatible diagnostics mode (§4.5) — **P1**; error-class parity (soft gate, `C-26`/process decision).

### Scope resolution → IR (§5–§6)

- [x] Bottom-up resolver turning every `Ident` into `LocalVar(slot)` / `UpvalVar(depth, slot)` / `GlobalVar(sym)` / `WithVar(...)` via a scope-frame stack (de Bruijn `(depth, slot)`) (§6.1–§6.2) — **P1**, `S-11`.
- [x] Self-visible `rec`/`let` frames pushed before resolving RHSes, preserving Nix thunk-cycle/blackhole behavior (§6.2) — **P1**.
- [x] `with`-classification: emit `WithVar` only when no lexical binder shadows; record the innermost-first `with` chain; reproduce lexical-beats-`with` / inner-beats-outer probe order exactly (§6.3) — **P1**; `with`-scope conformance (§8). Frontend `with`-shape speculation hooks left entirely to runtime inline caches (`R-8`, **P5/P8** research-grade) — IN SCOPE, deferred in dependency order.
- [x] Precise per-lambda upvalue/free-variable capture set computation (no over-capture) (§6.4) — **P1**; prerequisite for escape analysis ([07](07-laziness-and-whole-program-analyses.md)).
- [x] Resolver side tables: `FrameInfo { slot_count, captures, rec, has_with }`, `Upvalue { depth, slot }`, index-addressed for serialization (§6.5) — **P1**.
- [ ] IR lowering: variables-resolved, thunking-explicit, single-source-for-all-tiers arena IR; conservatively thunk everything non-trivial (§5, §5.1) — **P1**, `S-11`/`S-19` (taxonomy owned by [25](25-intermediate-representation.md)).

### Parse / compile cache (§9)

- [x] Content-addressed parse cache: `blake3(file_content ⧺ schema_version ⧺ flags)` key, content-not-mtime, schema-version wholesale invalidation (§9.2) — **P1**, `S-11`/`S-15`.
- [ ] Serialize the scope-resolved IR arena + side tables by near-`memcpy`; `mmap` zero-copy load; cache layout `ir.bin`/`symbols.bin`/`meta.toml` (§9.3–§9.4) — **P1**.
- [ ] File-local symbol-table remapping for load-order-independent cache keys (precondition for stable cross-run/cross-machine early cutoff) (§9.3) — **P1**, `S-14` enabler.
- [ ] `import`/file-resolution memoization keyed on realpath + content hash, shared IR across symlink/search-path indirection (§9.2) — **P1**, `S-12`.

### Parse/compile as demand-graph nodes (§9.6)

- [ ] Lazy split: parse on first `import` demand, native-compile deferred until hot — parse and compile as two demand-graph nodes with different eagerness (§9.6) — **P1** parse-lazy committed; native-compile-on-heat ties to tiers ([08](08-execution-tiers-and-cranelift.md), **P6**); `C-19`/`C-20`.
- [ ] Parallel parse/compile of independent files on the rayon work-stealing pool (§9.6) — **P3.5**, `C-19`; differential identity vs sequential oracle + `loom`/Miri audit (`R-4`).
- [ ] Speculative prefetch along statically-known import edges, with the error-quarantine guardrail (speculative parse failure stashed, raised only on genuine demand) and bounded idle-worker scheduling (§9.6) — **P3.5/P8**, `C-19`/`M-23` (measure-gated aggressiveness, IN SCOPE); error-quarantine soundness via the effect-class discipline ([25](25-intermediate-representation.md) §5).

## References

- rnix-parser (Rust Nix parser, built on `rowan`, lossless CST):
  https://github.com/nix-community/rnix-parser and https://lib.rs/crates/rnix
- rowan / lossless syntax trees (matklad's CST design):
  https://dev.to/cad97/lossless-syntax-trees-280c
- Snix evaluator (formerly Tvix; bytecode VM on rnix, status, conformance reuse):
  https://snix.dev/docs/components/overview/ and
  https://docs.rs/crate/snix_eval (via https://snix.dev/rustdoc/snix_eval/index.html)
- Tvix eval README / status (heavy rnix use; compiler lowers rnix AST to
  bytecode; not yet feature-complete):
  https://code.tvix.dev/about/tvix/eval/README.md
- devenv adopting tvix-eval (Oct 2024):
  https://devenv.sh/blog/2024/10/22/devenv-is-switching-its-nix-implementation-to-tvix/
- Pratt parsing (top-down operator precedence): matklad, "Simple but Powerful
  Pratt Parsing": https://matklad.github.io/2020/04/13/simple-but-powerful-pratt-parsing.html
  and Bob Nystrom, "Pratt Parsers: Expression Parsing Made Easy":
  https://journal.stuffwithstuff.com/2011/03/19/pratt-parsers-expression-parsing-made-easy/
- Crafting Interpreters (recursive descent, Pratt compiling expressions, resolver
  pass turning name lookups into slots):
  https://craftinginterpreters.com/parsing-expressions.html and
  https://craftinginterpreters.com/compiling-expressions.html
- de Bruijn index (scope resolution without names; counting intervening
  binders): https://en.wikipedia.org/wiki/De_Bruijn_index
