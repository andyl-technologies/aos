# Dispatch model

`dispatch-model` defines portable finite assignment problems and independently
interprets their answers. It works without a solver, native libraries, an async
runtime, or an AOS installation. Use the companion `dispatch` crate for builders
and planning recipes, and `dispatch-runtime` when process-isolated optimization
is needed.

An item receives exactly one target binding or an explicitly allowed deferred
binding. Item groups express admission, co-location, and topology separation.
Sparse shared candidate domains and target-dependent demands avoid requiring a
dense item-by-target matrix. The complete schema is defined by the documented
types in `src/schema.rs`.

Three operations establish distinct contracts:

- `validate` normalizes finite sets, checks complete accounting and references,
  and produces an immutable `ValidatedProblem`. A structurally valid problem
  can still be infeasible.
- `evaluate` computes exact loads, constraint violations, repair debt,
  transition categories, and lexicographic objectives without running a solver.
- `verify` rejects hard violations and worsened repair components, then binds
  the accepted assignment and independently computed evaluation to the exact
  validated problem. It distinguishes fully feasible answers from repair
  proposals with remaining debt.

Resource inputs are unsigned 64-bit integers in declared quanta. Input rational
coefficients use signed 64-bit numerators and positive unsigned 64-bit
denominators. Serde interchange uses canonical decimal strings and reduced
rational pairs, preserving quantities above JavaScript's exact numeric range.
Aggregate arithmetic uses arbitrary-precision integers and reduced rationals.
Each reduced exact evaluation value is limited to `MAX_EVALUATION_BITS`;
comparison and reduction can use temporary products up to twice that width.
Exceeding the value limit returns numeric exhaustion rather than rounded results.

Historical ordinary charges are separate from forecast placement demands.
Final accounting charges proposed placements and retained additional holdings.
Conservative overlap keeps historical sources while charging new destinations;
an unchanged placement contributes the maximum of historical and forecast
charges rather than their sum. Fixed load and additional holdings remain
distinct from ordinary item charges.

Repair rules are explicit. Every numeric component may retain at most its
observation-derived debt. Lower total debt cannot justify creating a violation
in another target or topology member. Scope-member debt reports are sparse:
an omitted valid component has exactly zero debt and zero baseline. The verifier
still evaluates every occupied candidate member and every nonzero baseline;
`ValidatedProblem::baseline_debt` resolves implicit zeros. Explicitly selected
objective components remain visible in reports.

Warm-start hints belong to solve requests, not the semantic model. Serialized
evaluations are diagnostic data and do not become `VerifiedAssignment` objects
through deserialization. Verify imported assignments against the local validated
problem again. A successful verification proves the submitted arithmetic and
policies; consumers retain responsibility for observations, capacity reservation,
safe transitions, and execution authority.

Integration tests cover numeric interchange, immutable ownership, ordinary and
additional occupancy, componentwise repair, and malformed-input rejection.
The separate `dispatch-conformance` crate provides exhaustive small-instance
checks against an independent oracle.
