# Properties, observations, and verdicts

Fault evidence answers “what physical/model action occurred?” Properties answer
“did the system meet its requirement?” A useful Crucible experiment normally
asserts both. A dropped frame is not proof that a client failed, and a client
timeout is not proof which fault caused it.

## Assertion structure

`[properties]` has a generated content ID and zero or more assertions. Each
`[[properties.assertion]]` has a stable `id`, a failure `message`, and one
temporal `property`. IDs are referenced by property terminal conditions,
savepoint selectors, `assertion_state` predicates, findings, and replay.

Unknown kinds and fields are rejected. Property state and observation history
are checkpointed, so resume does not forget a prior witness or restart a
deadline.

## Choose a temporal property

| Kind | Meaning | Use it for |
|---|---|---|
| `always` | Predicate holds at every relevant evaluation point | Safety invariants: no split brain, no invalid state, no unexpected crash. |
| `sometimes` | Predicate becomes true at least once | A witness is required but no trigger-relative deadline is needed. |
| `eventually` | After `trigger`, nested property holds within `deadline_ticks` | Bounded recovery, failover, delivery, or durability. |
| `after_quiescence` | Predicate is checked once at quiescence or the run limit | Stable final state and convergence checks. |
| `reachable` | Predicate should be reachable or unreachable | Coverage expectations and forbidden states. |

`reachable` with expectation `reachable` uses `on_unreached = "warn"` by
default or `"fail"` when absence is a test failure. Expectation `unreachable`
fails as soon as a witness appears.

An `eventually` deadline begins at the exact trigger observation coordinate.
Use it instead of a global “sometime before run end” check for recovery SLOs.
Always pair liveness properties with a finite CLI time/quantum budget.

## Predicate catalog

Predicates are structured `kind` tables or one of the named DSL strings.

| Predicate | True when | Required inputs |
|---|---|---|
| `at` | Virtual time equals a coordinate | `at_ticks` |
| `after` | A duration elapsed since an event last fired | `duration_nanos`, event `of` |
| `timer` | Named relative timer fires | `name` |
| `network_match` | A delivered frame matches | nested frame predicate, optional link |
| `console_match` | Captured serial output matches | node, deterministic regex |
| `coverage_point` | Guest executes an address/symbol | node, nested point |
| `memory_predicate` | Sampled register/memory satisfies unsigned comparison | node, place, comparison, value |
| `io_pattern` | Selected modeled I/O occurs | node, I/O kind |
| `node_state` | Node has selected lifecycle state | node, state |
| `assertion_state` | Another assertion is satisfied/violated | name, state |
| `quiescent` | No immediately runnable scheduler work remains | none |
| `named` | Registered DSL predicate resolves true | name, optional nodes |
| `guest_marker` | White-box guest emits the declared marker | marker |
| `all_of` | Every child is true | predicate array |
| `any_of` | At least one child is true | predicate array |
| `once` | Child has ever become true | predicate |
| `not` | Child is false | predicate |

Named strings are `no_crashed_nodes`, `quiescent`, `node_alive:<node>`, and
`node_crashed:<node>`. Prefer structured predicates when the claim needs
parameters or will be consumed by tooling.

Nested values are closed too:

- network frame match is `any`, exact bytes, contains bytes, or prefix bytes;
- coverage point is a guest address or resolvable symbol;
- memory place is physical address, virtual address, symbol, or register, with
  width `u8`, `u16`, `u32`, or `u64`;
- unsigned comparison is `eq`, `ne`, `lt`, `le`, `gt`, or `ge`;
- I/O kind is any, block read, block write, fsync, 9p, or network; and
- node state is started, crashed, hung, or exited.

## Observation boundaries

Crucible evaluates predicates only from deterministic observation sources.

| Observation | What it proves | Important boundary |
|---|---|---|
| Network adapter | Frame admission, route, mutation, drop, or delivery to QEMU | Does not prove application parsing or acceptance. |
| Storage adapter | Request, result, bytes, cache and durable frontier | Completion status and actual durability are separate. |
| Node/QEMU adapter | Lifecycle generation, instruction/register/memory/interrupt/clock/device action | Must be acknowledged by the matched QEMU capability. |
| Console | Stable guest serial bytes | Regex over deterministic captured stream; avoid timestamps/random text. |
| Guest marker | Explicit white-box semantic event | Requires the declared guest assertion/marker protocol. |
| Coverage | Address/symbol execution | Reachability, not semantic success. |

Use adapter evidence for the modeled cause and guest evidence for the
application consequence. For example, a recovery property can trigger on an
availability transition and require a guest “service-ready” marker by a
deadline.

## Evaluation lifecycle

Assertions move through declared lifecycle state and retain witnesses,
trigger coordinates, deadlines, and violation evidence. `assertion_state`
allows one assertion or event graph condition to depend on another without
re-evaluating its predicate. Cycles and invalid references are rejected.

Terminal behavior depends on the command:

- `run --until property` stops on the selected property boundary;
- a violated assertion produces the property-failure status class;
- `save --at property --property <id>` exports the exact violation boundary;
- `search --on-violation stop` stops at the first finding, while `collect`
  continues within budget; and
- `replay` requires the same observation and assertion evolution.

A timeout is distinct from a violated property. Treat exit 1 (counterexample)
and exit 2 (budget timeout) differently in CI.

## Evidence chain

For a signal-driven fault, the canonical explanation chain is:

```text
signal coordinate and input digest
  -> binding mapping and selector
  -> typed opportunity and phase
  -> composed effect request
  -> capability acknowledgement and adapter result
  -> observation
  -> predicate transition
  -> assertion/verdict
```

The trace may omit unchanged sample payloads under the binding observability
policy, but stable identities and digests still allow locked replay to verify
the chain. Search findings add the schedule and exact fault-mutation recipe.

## Authoring patterns

### Bounded recovery

Use the physical fault transition or a guest “fault observed” marker as the
`eventually.trigger`, then nest the application-ready predicate with an exact
deadline. Also assert `always` for invariants that may not be violated during
recovery.

### Expected isolation

Assert network drop/availability evidence separately from a guest marker that
proves protected data was not accepted. A frame predicate alone cannot grade
the application guarantee.

### Durability under power loss

Assert the storage durable frontier or selected cache-loss evidence, then use a
post-restart guest marker or memory/file observation for recovered application
state. A successful flush response is insufficient when testing a lying flush.

### Forbidden hardware state

Use `reachable` with `unreachable` for a precise forbidden observation, plus a
positive coverage witness proving the relevant code path was exercised. This
avoids passing only because the test never reached the fault site.

## Review checklist

1. Each requirement uses the temporal kind that matches its quantification.
2. Liveness has both a trigger-relative deadline and an outer run budget.
3. Physical/model evidence and application evidence are asserted separately.
4. Console regexes and markers are stable across replay.
5. Reachability tests include a positive path-coverage witness.
6. CI distinguishes violation, timeout, backend failure, and invalid input.
7. Failure artifacts retain the trace and exact terminal checkpoint.

See the [schema reference](reference.md#properties-and-predicates),
[Artifacts and replay](artifacts.md), and [Debugging](debugging.md) for the
corresponding configuration and investigation workflows.
