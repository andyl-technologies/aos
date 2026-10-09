# Dispatch

Dispatch is a portable resource-assignment library and scoped solver runtime.
Consumers describe items, destinations, resource accounting, constraints, and
ordered objectives. Solver workers search for proposals; the exact reference
evaluator independently checks their assignments.

The facade exposes model types, pure validation/evaluation/verification, a fluent
`ProblemBuilder`, inspectable policy recipes, and comparison/explanation/what-if
operations. Optional features expose sessions and portable solve requests:

| Feature | Interface |
| --- | --- |
| No default features | Pure model construction and exact analysis |
| `protocol` | Portable `SolveRequest` and `SearchRequestOptions` documents |
| `runtime` | Bounded sessions and execution providers; includes `protocol` |
| `systemd` | Optional Linux managed execution provider; includes `runtime` |
| `cli` | Standalone `dispatch` executable; includes `runtime` |

Default features enable the runtime and CLI. Applications select native executable
paths through trusted configuration. Rebalancer runs in a separate C++ process
behind the Rust worker; no native solver is linked into the facade.

`examples/packing.rs` builds and compares an ordinary packing policy without
starting a solver. `examples/compare.py` reads the same JSON fixtures through the
language-neutral CLI. Request documents carry the problem, options, backend name,
and optional hint without carrying executable paths or execution authority.

A result is bound to its submitted snapshot. Consumers retain ownership of
freshness checks, reservations, migrations, publication, and execution. Shared
solver code does not make concurrent resource proposals atomic.

The [user guide](https://github.com/andyl-technologies/aos/blob/master/docs/users/dispatch.md)
documents model semantics, sessions, providers, commands, and result handling.
The [protocol directory](https://github.com/andyl-technologies/aos/tree/master/protocol/dispatch)
contains language-neutral schemas and canonical commitment vectors.
