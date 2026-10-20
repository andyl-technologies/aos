# Completion boundaries and evidence

This page defines what completion requires. It does not certify an image or
release. [Migration status](consumer-migration.md) records outstanding work;
[implementation ownership](implementation-contract.md) links the current code.

| Boundary | Required evidence |
| --- | --- |
| Module configuration | Definitions in separate modules merge; recursive defaults remain lazy; private ownership and extensible options are checked. |
| Deferred graph | Missing handlers, incompatible outputs, cycles, invalid exports, and malformed identities reject before execution. |
| Package publication | Every selectable output carries its own authenticated native envelope and measurement; sibling evidence cannot be substituted. |
| Artifact phases | Unused available outputs and build-only qualification tools do not enter the runtime closure merely through metadata. |
| Retained evaluation | Actual immutable sources replay identically without build evaluation; source retention survives real GC and released roots can be collected. |
| Package lifecycle | Install, reconfigure, upgrade, remove, rollback, and pruning use the native profile and generation machinery. |
| Runtime recovery | Intent, attempted dispatch, completion, uncertainty, cancellation, and explicit retirement have tested state transitions. |
| Read-only inspection | Readers hold a consistent snapshot without creating journals, repairing tails, or changing publication state. |
| OS integration | Image and retained-source evaluations agree; boot uses the same package profile and preserves operator configuration. |
| Generated documentation | CLI, Hub API, indexed release pages, and import views use the shared native document model with explicit provenance. |
| Domain qualification | Exact candidate and scenario sources produce each cohort's expected graph; external domain observations support every claimed cell. |

Passing one boundary is not a substitute for another. A source-built
materialization test can prove lower contents and protocol behavior without
proving mount behavior on a booted host. A typed image request can validate
without proving firmware selection or a physical rollback.

Maintain one declaration for each domain setting and derive its runtime,
documentation, and qualification projections. Tests should validate behavior
and source custody, not keep duplicated production catalogs synchronized.
Superseded APIs and current-facing documentation must be removed with their last
consumer. Counts of packages, operations, tests, or generated cells are not
completion criteria.
