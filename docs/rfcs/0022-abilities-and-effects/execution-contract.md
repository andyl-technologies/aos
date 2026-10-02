# Deferred handler execution contract

This contract covers the native module graph. Earlier action registries and
provider/binding documents are superseded by the [target state](13-target-state.md).

## Boundary

Nix lowers the selected module fixed point to `aos.activation.graph`, carried
inside an `aos.package.transaction` document. The checked Rust graph validates
identities, revisions, input and result types, dependencies, composition exports,
and execution order. Nix does not execute handlers or resolve runtime results.

A terminal handler is a retained program artifact with a main executable. A
composed handler expands into typed children and result exports. Only terminal
nodes launch processes. References in inputs are resolved using checked producer
results, preserving dependency ordering.

## Process protocol

`aos-package::deployment::handler::ProcessAdapter` launches the selected executable
with one argument: `apply`, `remove`, or `observe`. It sends a serialized
`aos-ability-runtime::activation::Invocation` on stdin. That type is the source of
truth for the invocation shape, including the effect, resolved inputs, and
previous state. Authors should use the type or the executable fixture rather
than maintain an independent protocol model.

Successful `apply` stdout is the declared named result object, for example:

```json
{"message":"hello"}
```

Successful `remove` returns `{}`. Observe returns one of:

```json
{"status":"current","outputs":{"message":"hello"}}
```

```json
{"status":"absent"}
```

```json
{"status":"retry-safe"}
```

```json
{"status":"indeterminate"}
```

Stdout is protocol data. Diagnostic text belongs on stderr. Transport bounds
stdin, stdout, stderr, duration, and cancellation; failed processes do not produce
successful results. The current transport uses Linux process facilities.

## State transitions

The package transaction layer retains inputs and prepares a generation before
mutation. The effect runtime journals intent and completion, checks results, and
observes uncertain operations before retry. An indeterminate observation stops
progress instead of assuming success or repeating an unsafe action.

Changed semantic inputs or implementation artifacts receive previous state for
reconciliation. Instance removal and transaction cleanup invoke teardown;
persistent effects require explicit retirement. Handler artifacts remain rooted
until the operation or its removal no longer needs recovery.

`Transactions` commits a generation after effect completion. The most recent
caller transaction receipt closes the crash window between those two commits.
Recovery resumes pending work before accepting another generation. Retained
generations supply rollback inputs; rollback is a new reconciliation transaction.
Pruning removes old generation roots and journals interrupted cleanup. It does
not compact the bounded journals.

See [infrastructure cutover](infrastructure-cutover.md) for the concrete Rust APIs
and [runtime abilities](../../users/aos/runtime-abilities.md) for the full
build/publication/evaluation/execution path.
