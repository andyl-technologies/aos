# Testing ability implementations and runtime transitions

## Exercise the production path

Once implemented, abilities are exercised through the same Nix composition,
normalized contracts, Rust validation/planning, runtime admission, and provider
implementations used by a deployment. VM and fleet harnesses supply environments,
invoke workflows, inject faults, and collect observations. They must not maintain
a second implementation of ability activation for tests.

The harness control plane and the workload's granted abilities are distinct.
A privileged guest agent may prepare fixtures or inspect results, but workload
permission checks must execute as the constrained consumer. A successful root
probe does not establish that the consumer has the intended access, and a root
denial does not establish the consumer's confinement.

Tests may mock lower interfaces when testing a pure component in isolation.
Such tests establish properties of that component and its declared assumptions;
they do not qualify the substituted runtime provider. Integration and release
tests must use the real providers for the behavior they claim to exercise.

## Existing test and qualification surfaces

| Surface | Role in this proposal | Limit of the evidence |
| --- | --- | --- |
| Nix evaluation and Rust conformance tests | Schema agreement, normalization, composition, constraints, negative cases | No live enforcement or recovery claim |
| Provider contract tests | Exercise one interface implementation and its actual resource adapters | Covers that implementation and tested context |
| [Single-VM harness](../../../lib/testing/vm.nix) | Guest activation, process identity, storage, manager interaction, reboot where supported | Harness image and recorded virtualization scope |
| [Fleet harness](../../../lib/testing/fleet.nix) | Production boot paths, multiple providers/consumers, network faults, distributed transitions | Tested topology and exact subjects; fleet naming alone does not establish release qualification |
| Container scenarios | Local-manager and foreground contracts, delegation, policy and persistent volumes | Recorded host kernel/runtime and selected interface |
| [Qualification regressions](../../../tests/qualification/default.nix) | Aggregate regression coverage referenced by shared policy | Cached derivation success is not fresh release admission |
| [Native qualification adapter](../../../lib/testing/qualification.nix) | Execute frozen release cases and collect exact-subject observations | Only the stated functions and recorded configurations |

The current single-VM and fleet harnesses have distinct backend/transport
implementations. Reuse them without assuming that a pass on one backend proves
all others. Preserve required builder features and use AOS-built tools and
shells. Test infrastructure may orchestrate these paths without depending on
the ability runtime under test for its own recovery channel.

Existing scenarios provide migration anchors. The
[activation-failure test](../../../tests/fleet/apm-system-activation-fail.nix)
exercises the current production commit/failed-unit behavior, while
[generation GC](../../../tests/fleet/config-generation-gc-roots.nix) drives
public APM operations and real collection. Extend their behavioral coverage
when the new execution path replaces the old one.

The [qualification workload fixture](../../../tests/fleet/qualification-workload.nix)
currently writes nginx configuration and controls a dedicated service directly.
It remains useful workload coverage, but does not thereby exercise recursive
ability composition. Add an ability-driven scenario that reaches the same
HTTP/TLS behavior through the real package export and activation workflow.
Do not relabel a fixture as evidence for a path it did not execute.

## Contract coverage follows interfaces and implementations

Each supported interface version defines observable behavior that provider
implementations must satisfy. Maintain reusable conformance scenarios for
request/result typing, operation semantics, resource scope, lifecycle,
sharing/exclusivity, and required guarantees. Run them against each supported
provider/backend combination where the claims differ.

An author may supply examples, fixtures, and proposed conformance cases with an
export. Trusted maintainers and qualification policy determine the required
acceptance conditions. A provider cannot define success solely as its own
callback returning true or remove a required negative test from its release
obligations. Generic schema tests cannot infer application-specific correctness.

Coverage records distinguish declared methods, exercised methods, failure
boundaries, guarantee checks, and untested scopes. Trace a requirement to its
scenario, exact implementation, observations, and result. Node counts or code
coverage alone do not establish the semantics of an ability.

Keep the existing [scenario matrix](09-implementation-and-validation.md#qualification-matrix)
as the initial contract-level inventory. Add tests for actual consumer access,
aggregate updates, conditional requirements, provider replacement, and loss of
resources between planning and use. Unsupported combinations remain explicit
rather than being reported as passing skipped tests.

## Independent observations and a complete nginx scenario

Check both the execution record and independently observable behavior. A
provider's success event is necessary diagnostic evidence, but cannot be the
only oracle for whether its operation worked. For example:

| Transition | Execution evidence | Independent observation |
| --- | --- | --- |
| Initial activation | Exact bindings and required operations completed | Both contributed virtual hosts serve their expected responses |
| Configuration change | Aggregate publication and reload linked to the new revision | New response is served; unchanged virtual host still works |
| Invalid candidate | Validation rejected; no publication committed | Prior configuration remains selected and prior responses remain available |
| Reload failure after publication | New configuration and failed/uncertain consumer state recorded | Manager/process observations and responses agree with that partial outcome |
| Consumer removal | Aggregate recomputed and applied | Removed route disappears while the remaining route works |
| Unchanged desired input | No unnecessary publication/reload operation | Relevant process/configuration revision remains unchanged |
| Credential or access revocation | Defined fence/stop/restart operation completed | Previously authorized consumer can no longer exercise the revoked access |
| Reboot/update/rollback | Recovery and generation associations retained | Durable workload records survive and the selected behavior is observed |

Use two contributors and separately scoped provider instances where needed to
test sharing without conflating identities. Include HTTP and TLS, authorized
credential delivery, an invalid certificate, a denied foreign resource, and
backend connectivity from the actual workload context. Compare durable record
content/hashes, not merely file existence.

A reload acknowledgement does not prove that new workers serve the new revision.
Readiness checks must distinguish old and new behavior. Likewise, a journal's
successful denial assertion does not replace a real attempted access from the
denied consumer. Verify that the denied operation left no unauthorized mutation.

## Fault injection at semantic boundaries

The structured operation contract exposes better fault-injection points than
arbitrary delays in a shell script. Exercise at least:

- before resource acquisition and after acquisition but before an effect;
- after intent is durable but before the external operation;
- after the external effect but before its completion record;
- immediately before and after configuration/profile/boot publication;
- during provider unavailability, lost responses, expired leases, and competing
  controller revisions;
- during cancellation, cleanup, compensation, and rollback; and
- across executor/provider upgrades with recoverable in-flight state.

Use controlled barriers or provider/harness faults when possible, and record
which boundary was actually reached. Time-based sleeps alone cannot prove that
a test interrupted the intended state. Test controls must not become an
unauthenticated production interface for suppressing authorization or changing
operation outcomes.

Distinguish a killed executor, a killed guest process, guest reboot, and loss of
VM power. They test different persistence and recovery conditions. Scope
durability claims to the tested storage stack; process-kill tests do not
establish power-loss safety. On recovery, verify independently observed state,
bounded retries, fencing, and retained inputs, including ambiguous outcomes.

Pure state-machine/model tests explore small generated operation graphs and
failure schedules. They should assert invariants such as no effect before
authorization, no publication before required validation, and no loss of an
active consumer's retained artifacts. Seeded schedules aid reproduction but do
not imply exhaustive real-world concurrency coverage. Where supported,
Crucible can add deterministic guest fault/replay coverage through its existing
protocols; it does not replace actual provider/backend qualification or alter
the Crucible/QEMU process boundary.

## Release qualification uses the existing contract

Extend [the shared qualification catalog](../../../qualification/default.nix)
and its feature modules with ability-related checks, scenario references,
subjects, bounds, and invalidation rules. Do not create a parallel "ability
passed" receipt that bypasses the
[release qualification contract](../../maintainers/qualification.md).

The existing assurance distinction remains: assessed compatibility is different
from direct execution, and complete qualification additionally requires the
applicable lifecycle/recovery checks, observation window, and review. Regression
tests and simulations do not automatically award exercised or qualified status
to a release artifact.

Qualification cases should bind the exact candidate and predecessor where
relevant, package/provider/handler artifacts, interface and operation versions,
normalized binding/effect plan identities, qualification policy, and actual
environment inventory. Retain the scenario/executor identity, expected and
observed conditions, attempts, timings, operation counts, failure records, and
recovery outcome. Map these fields into the existing versioned evidence
contracts; any required schema extension needs explicit compatibility handling.

Runtime graphs can contain run-specific assignments. Their recorded identities
must be associated with the frozen case and its admitted inputs. Repeated runs
need not have identical timestamps or resource incarnations, but must satisfy
the same contract and explain their bindings. Different bytes or providers
cannot inherit evidence just because logical request names are unchanged.

An instrumented fixture and a finalized release image are different subjects
unless the qualification contract explicitly establishes the tested boundary.
Record harness modifications and injected components. A development test image
with relaxed security cannot qualify enforcement on a production image, and
secret-bearing test fixtures must not become production release authorities.

Reassess affected claims after changes to provider/handler semantics, interface
ABI, planning/execution, policy, kernel/runtime facilities, or the supported
environment scope. Do not generalize a host-systemd pass to a container manager,
or one host kernel/runtime combination to all OCI deployments. Preserve failed,
missing, skipped, and stale evidence distinctly; mandatory unresolved cases
block the existing release gate.

## Execution tiers and failure artifacts

Keep fast pure validation and provider tests available during authoring. Run
focused VM/fleet scenarios when changing an affected implementation or boundary.
Require applicable fresh exact-artifact cases at release qualification under
the existing matrix and observation policy. Do not run every expensive fleet
combination for a documentation edit or treat a cached build as a new soak run.

On failure, retain the normalized graph, bindings, plan, composition/selection
trace, journal and correlated logs, environment inventory, and independent
probe results under appropriate access controls. Include the fault schedule
and reached boundary when applicable. The shared inspector should navigate
from the failed acceptance condition to its operation and original request.
Redaction may limit replay; the diagnostic bundle must say which inputs are
missing rather than manufacturing a successful reproduction.
