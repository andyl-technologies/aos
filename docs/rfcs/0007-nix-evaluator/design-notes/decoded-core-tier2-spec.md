# Decoded-core compressed tier-2 emitters (S4b phase 3)

Status: SPEC — approved by the lead; implementation task #30.
Motivation: the S5 matrix wide-int cliff (cutover plan §S4b status block):
`sum-fold` 290x slower on the one-word carrier because the compressed chain
emitter declines the wide operator literal `2654435761` at the leaf, the
tier-2 fold blacklists, and the interpreted fold then boxes a fresh scalar
cell per wide intermediate (3M thunks / 876 MB for 1.5M elements).

## 1. Principle

A value only needs a compressed word when it **materializes** — crosses a
runtime-helper boundary, escapes to the caller, or is stored where the
evaluator can observe it. Operand-position literals, arithmetic
intermediates, and loop-carried accumulators never materialize, so they can
live as plain decoded `i64` SSA values with **no inline-range constraint**:
wrapping `i64` ops are exactly the tree walk's per-step semantics. The
compressed arith-tree emitter already works this way end-to-end
(`arith_tree_compressed.rs`); this note extends the same discipline to the
tier-2 body emitters (`lambda_rec/compressed.rs`,
`lambda_chain/compressed*`), which currently thread one **encoded word per
node** and therefore (a) decline wide literals and (b) deopt on every wide
intermediate through their per-node re-encode guards.

## 2. Typed value classes

Each emitted expression carries one of two SSA classes:

```text
IntDecoded(v)  # plain i64, full range — statically integer-typed nodes
Word(v)        # encoded compressed word — everything else (incl. booleans)
```

Booleans stay in `Word` (the two canonical boolean words are always inline;
there is no wide-boolean problem and `if`-condition truth remains the low
bit). Only integers earn the decoded class.

Coercions (the only guard/encode sites):

- `to_int(Word)` — combined high-half guard (`ushr 32 == 0`) then
  `ireduce`/`sextend`; guard failure branches to the shared deopt block.
  `to_int(IntDecoded)` is the identity.
- `to_word(IntDecoded)` — round-trip inline-range check, deopt when wide
  (the tree walk re-runs and boxes), else `band 0xFFFF_FFFF`.
  `to_word(Word)` is the identity.

## 3. Static class inference

A tiny grammar-directed inference assigns each node `Int`, `Bool`, or `Dyn`:

- `Int` literal (ANY width) → Int; `Bool` literal → Bool.
- Arith `BinOp` → Int; comparison `BinOp` → Bool.
- `If` → unify(then, else): Int+Int → Int, Bool+Bool → Bool, else Dyn.
- Parameter/env/upval reads, `Apply`/self-call results → Dyn.

Emission by class: Int-typed nodes produce `IntDecoded` (wide literals are
plain `iconst.i64` — this alone fixes the `2654435761` decline); Bool/Dyn
produce `Word`. Arithmetic coerces operands with `to_int` (a `Dyn` operand
gets today's guard exactly once at the coercion); comparisons likewise.
`If` joins carry the unified class (an Int/Int join keeps a decoded block
parameter, so `if p then acc * 31 + x else acc` stays decoded across the
branch — the common fold pattern).

## 4. Materialization points (v1)

- **Body return** → `to_word` (a wide final result deopts once and the tree
  walk boxes it — rare; e.g. `sum-fold`'s `mod` keeps the result inline).
- **Self-call arguments** → `to_word` in v1 (the inner ABI keeps its word
  parameter; a wide argument deopts). A later v2 may add decoded `i64`
  argument slots to the internal signature — not needed for the S5 fixtures.
- **Fold/genList loop-carried accumulator** — THE key change: when the
  operator body infers `Int`, the loop block parameter is a decoded `i64`;
  the seed coerces with `to_int` once before the loop, and the loop exit
  coerces with `to_word` once. Wide partial sums then live entirely in SSA:
  `sum-fold` runs fully native with zero boxing. When the body infers
  `Bool`/`Dyn`, the loop keeps today's word-carried form.
- **genList index** — loop-produced; pass it decoded into the generator
  body's Int coercions (it is a known integer by construction).

## 5. What does not change

Deopt/sentinel discipline (the `0xFF`-kind sentinel word remains a *word*
at every function boundary), the first-strict-use force points, the budget
threading, the stack-map spill of force inputs, the boundary entry/exit
ABI, and the two-word emitters (untouched, as always).

## 6. Increments and gates

1. (LANDED da0800bdb) `arith_tree_compressed` wide-literal embedding.
2. `lambda_rec/compressed.rs` decoded-core (lead) — template for (3).
3. `lambda_chain/compressed*` + fold-genlist decoded-core (chain-port
   after the ratchet-jit splits), incl. the decoded loop accumulator.
4. Un-gate the wide-seed and wide-intermediate chain fixtures that phase 2
   left baseline-only (`nested_dependent_lets`, `closed_arithmetic_predicate`,
   `quicksort` checksums, the `2654435761` fixtures) — they must now run
   and MATCH on both carriers with **zero deopts** where the two-word
   carrier had zero.
5. Re-run the S5 matrix compute legs: `sum-fold` and `qsort` restored to
   ~baseline-or-better is the acceptance; byte-parity battery per landing.
