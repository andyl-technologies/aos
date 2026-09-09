# Implementation contract: data, composition, and admission

This chapter fixes implementation decisions that the architectural examples
abbreviate. The rules here, the [execution contract](execution-contract.md),
and the chapter-specific invariants govern implementations. Illustrative
helper spelling does not override them. A change to these semantics requires
an explicit design revision; internal module layout and error wording do not.

## Data ownership and schema

Use versioned, closed records built on `aos-contract`. The initial data profile
uses its integer-only canonical JSON and `Sha256Digest::of_canonical` domain
separation. Duplicate members, unsupported fields/tags, floating-point values,
and out-of-range integers fail decoding/validation. Object-member ordering is
canonical; semantically unordered collections sort by stable ID and reject
duplicates. Ordered arguments, search preferences, and operation sequences
retain their declared order. Optional fields have one schema-defined encoding;
absence and null are not interchangeable encodings of the same semantic value.

Each format has an exact `schema` discriminator, a `required_features` set,
and a closed body. Define these initial format families, each at version 1:

| Format | Required body concepts |
| --- | --- |
| `aos.ability.interface/v1` | Interface key, request/output schema, method schemas, lifecycle and guarantee semantics |
| `aos.ability.package/v1` | Exact release/artifact references, exports, declarative requirements, module entry points, handler catalog, ownership |
| `aos.ability.environment/v1` | Environment/stage identity, provider inventory, platform, policy revision, guarantees, freshness conditions |
| `aos.ability.desired/v1` | Instances, admitted contributions, expanded child requests, desired resources, typed outputs, controller assignments |
| `aos.ability.binding-plan/v1` | Input identities, exact provider choices, grants, resources, obligations, policy and environment commitments |
| `aos.ability.effect-plan/v1` | Binding-plan identity, current/desired revisions, operation graph, resource accesses, deadlines, recovery and retention obligations |
| `aos.ability.execution/v1` | Transaction identity, exact plan/artifacts, operation attempts, publication receipts, observations, terminal result |

The discriminator also names the content-digest domain. A record does not
contain its own digest; a parent/reference carries that digest and verifies the
child's canonical bytes. Artifact references additionally preserve existing
store/NAR identities and authenticated closure associations. A digest is an
identity, not proof of publisher authenticity or operator authorization.

Interface keys are namespace-qualified names plus a positive integer ABI and
an exact semantic descriptor digest. Consumers may name an exact descriptor or
an explicitly published accepted set. Different descriptors under one name/ABI
are not implicitly compatible. Version-1 matching uses exact admitted semantics;
cross-ABI adaptation requires an explicitly selected provider with its own
requirements, artifacts, and conformance tests.

Interface schemas use a closed vocabulary: Boolean, bounded integer, bounded
string/enumeration, bounded list/map, closed record, tagged union, optional
value, immutable artifact reference, resource reference, and operation-result
reference. Maps specify key constraints and maximum entries. Results also
declare their phase. No arbitrary schema evaluation, remote schema retrieval,
executable predicate, or implicit reference-to-string coercion is supported.
Additional Nix predicates remain evaluation checks, not portable solver rules.

Descriptions/source locations live in separately identified annotations.
They are authenticated with their release but excluded from semantic graph
identity. Required operations, defaults, guarantees, constraints, and handlers
are semantic. Exact source/handler artifacts remain retained for execution and
reproduction even when a prose-only edit leaves a runtime projection unchanged.

## Stable identity and references

Separate logical identity, content revision, and live incarnation:

| Identity | Construction and lifetime |
| --- | --- |
| Environment | Authority-assigned stable identity plus execution stage; a user manager and host manager differ |
| Instance | Environment plus deployment-owned instance key; package upgrades do not rename the instance |
| Request | Consumer instance plus declared local request key; child keys include their composition scope |
| Aggregate | Provider instance plus declared aggregation group; contributions retain their original request/grant IDs |
| Resource | Owning provider/environment plus logical resource key; content equality does not merge resources |
| Revision | Canonical semantic content digest; includes inputs whose change affects the requested behavior |
| Operation | Transition plan plus scoped operation key; retries retain it and have distinct attempt indices |
| Transaction | Durable controller allocation for an execution of a plan; two executions of equal plans remain distinguishable |
| Incarnation | Provider-assigned live generation/assignment token; reacquisition validates it separately from logical identity |

Persist identity tuples as typed records rather than ambiguous concatenated
strings. Display names are derived. Version 1 uses nonempty ASCII local keys of
at most 128 bytes from letters, digits, `.`, `_`, and `-`; hierarchy is a vector
of keys. Existing broker IDs remain opaque typed values under their own
contracts and are not rewritten into this local-key grammar.

A resource reference names the issuing interface/provider, logical resource,
permitted operation projection, and expected lifetime. A result reference names
the producing scoped operation and output port. All references resolve within
an authenticated admitted graph; no guessed key grants access. A result cannot
outlive the resource or artifact it references.

Known publication locations and promised runtime outputs have different types.
For example, `publishedConfiguration` in the authoring sketch is a planned
configuration resource reference. The selected provider can expose a
deterministically assigned workload path as a separate configuration value.
The actual committed revision is a runtime publication result. A consumer
cannot use that future revision to finish the same pure Nix evaluation.

## Nix authoring and evaluation contract

Keep `abilities.exports`, `abilities.imports`, and deployment-owned
`abilityBindings` as the proposed top-level vocabulary. `define`, `resultOf`,
and effect helpers construct data checked by the shared validators. The module
ABI publishes their signatures together; callers cannot substitute arbitrary
attribute sets as trusted bindings.

An export declares interface/schema, aggregation group, named lower-interface
requirements, `compose`, and `transition`. A primitive implementation declares
a registered handler instead of recursive method composition. Its request and
result still use the same schema and validation path.

`compose` receives the canonical authorized contribution map, checked instance
context, and named binding references. It returns desired child requests,
typed output projections, and any concrete conditional requirements. It does
not return side effects. New lower aliases must occur in the authenticated
declaration's bounded discovery vocabulary; generated resource instances may
use checked child keys without inventing new interface protocols.

`transition` receives old and desired owned state, a change classification,
checked bindings/resources, and the admitted observation snapshot. It returns
method calls and dependencies as a finite graph. The Rust planner performs
normalization, validation, change classification, and scheduling; the native
orchestrator invokes restricted Nix evaluation for provider-authored
constructors. Rust does not execute serialized Nix closures.

Provider selection precedes evaluation of bindings that require that provider.
The declaration pass can report unsatisfied named requirements as data, and
pure composition can carry typed unresolved references until selection
completes. Code that needs a concrete absent binding cannot run prematurely or
guess from missing-attribute exceptions. Re-evaluate the selected module set
when conditional requirements add providers. Module `imports` remain fixed for
each evaluation pass and independent of the final configuration fixed point.

Runtime results flow through operation ports. A materialization operation can
render a previously described template after acquiring an endpoint or resource.
It uses a registered renderer and explicit inputs; it does not rerun arbitrary
Nix with ambient host access. A runtime result that changes provider selection
requires another admitted planning transaction.

## One owner schedules each transition

Desired resources do not automatically execute themselves. The normalized
graph assigns each mutable resource exactly one lifecycle controller. An
aggregate export supplies the root controller for its resource group. Multiple
public exports that share one service/configuration must declare the same
aggregation/controller group and merge there before transition construction.

A controller invokes methods of lower providers to realize its desired child
resources. Those providers compose the requested method into suboperations;
they do not also schedule an independent reconciliation of the same resource.
For nginx, the configuration provider does not independently publish while
nginx's controller separately requests publication. Likewise the service
provider does not autonomously start a unit and then receive another start
from the parent graph.

If an independently managed provider supplies a shared resource, consumers
reference its declared readiness/output contract; its own controller retains
lifecycle ownership. The engine rejects conflicting controller assignments,
duplicate exclusive destinations, and unowned desired changes before effects.
The authority to contribute configuration does not make a caller a controller.

Unchanged owned resources require no effect unless observations or an explicit
reconciliation request identify drift. Every changed resource must be covered
by its controller's transition or an explicit deferred deployment obligation.
An empty effect graph cannot claim that a changed resource was activated.

## Aggregation, instance migration, and deletion

Contributions are keyed by authorized slot and normalized in stable key order.
Exclusive-slot collisions fail. Merging the same slot is permitted only when
the interface defines field-level ownership and merge rules; import order is
never the tie-breaker. Retain source/consumer provenance through the merge.

Legacy single-root packages initially map to a stable `default` instance.
Unqualified legacy contributions route only to that instance. Additional
instances require instance-aware rendering of unit names, directories,
credential destinations, endpoints, and resource ownership before admission.
Do not create a second instance by copying a global root that still targets
`nginx.service` or its directories.

Removing a contribution recomputes its provider aggregate. Removing the last
contribution does not implicitly disable an operator-enabled provider. Root
instance enablement is explicit desired state. Removing an instance stops its
owned workload and releases ephemeral resources after its consumers detach;
persistent data follows an explicit retention/deletion policy and is retained
by default. Deleting persistent data is a separately authorized operation.

Provider replacement preserves a logical resource only when an explicit
handoff/adoption contract verifies ownership, state format, and current
assignment. Otherwise plan create/transition/retire with distinct resources,
or fail for an unsupported move. A matching resource name does not transfer
ownership. Retain old implementation artifacts until retirement/recovery is
complete, without treating historical grants as current authorization.

## Deterministic binding policy

Selection precedence is: explicit deployment binding, existing exact pin, then
an operator-authored ordered candidate policy. A valid pin remains selected.
An invalid explicit binding or pin fails with a diagnostic; replacement
requires a requested rebind/update. The initial solver does not silently
upgrade providers to repair incompatibility.

Without a preference policy, a request with one eligible candidate can bind;
multiple eligible candidates are ambiguous and require a deployment choice.
With a policy, search in its declared order and use deterministic bounded
backtracking when lower requirements or resource conflicts reject a candidate.
Do not select by registry traversal order. Record rejected candidates and the
constraint that rejected them.

The constraint vocabulary consists of exact identities/accepted versions,
platform/stage equality, named operations, required guarantee sets, resource
scope containment, exclusivity, bounded integer ranges, and explicit finite
alternatives. Conjunction and declared alternative groups are supported;
arbitrary Nix predicates and absence-based provider negation are not.

For each bounded resolution pass: authenticate candidates, authorize their
potential bindings, evaluate/expand concrete requests, validate the complete
candidate graph, and compare canonical request/binding state with the previous
pass. Stop on equality; reject repeated nonconvergent states, exhausted search,
or limit violations. Inactive conditional requests disappear before final
validation and receive no grants. No effects occur during search.

## Grants, guarantees, and admission outcomes

A binding record names the caller, provider, interface, permitted methods,
resource/contribution scope, required guarantees, policy revision, lifetime,
and whether provider mediation is allowed. Caller access and provider
implementation authority are separate grants. Mediated calls validate both
without handing the caller the provider's lower handles.

Required guarantees match exact admitted semantics in version 1. There is no
implicit cross-runtime equivalence. An operator-approved adapter can provide
equivalence only as an explicit implementation with tested obligations.
Optional behavior must have a declared omission/fallback result and cannot
satisfy another consumer's required guarantee after it is omitted.

Validation returns a checked graph, a graph with explicit unresolved deployment
obligations, or structured failure. Only the first can proceed to runtime
admission, and it still needs fresh provider/resource checks. A package may be
stored without an activatable workload, but installation must not report that
workload ready. Required failed checks remain failures rather than warnings.

## Initial bounded profile

Publish a versioned limit profile with every plan. The initial profile allows
at most 32 MiB per normalized document, 64 structural/composition levels,
100,000 graph nodes or operations, 1,000,000 edges, 64 resolver rounds, and
64 candidates per unresolved alias. Documents also bound aggregate collection
items to 2,000,000 and individual strings to 1 MiB; large file contents belong
in referenced artifacts. Apply all limits together before proportional work.

Bound provider-search visits to 100,000 per plan; reaching the cap is an
explicit resolution-limit result rather than evidence of unsatisfiability.
Native evaluation policy additionally supplies finite memory, CPU, elapsed
time, and subprocess-output limits. These operational limits may terminate an
attempt but never select a different successful plan based on host speed.

These are admission ceilings, not performance promises. Operators may lower
them explicitly; increasing them requires an admitted profile revision and
resource tests. Record effective limits with diagnostics/reproduction inputs.
An implementation cannot silently truncate a graph or drop its diagnostics'
critical failure condition to fit a limit.

## Required compatibility path

Use the existing package metadata `requires-features` gate, enforced by
[`validate_supported_package_meta`](../../../crates/aos-package/src/types.rs)
and [registry parsing](../../../crates/aos-package/src/registry/parse.rs).
Register `abilities-v1` for the new manifest and `ability-effects-v1` when
activation depends on the structured runtime. Publication must add the required
features, bind the ability artifacts into provenance, and reject a manifest
whose gate or authenticated artifact association is missing.

New clients must recognize a feature only after implementing its complete
mandatory validation/admission behavior. Keep the existing module ABI gate as
well; the advertised compatible module ABI must provide the ability helpers.
An old client that supports the current gate fields rejects these unknown
features before it can ignore their behavior. Test every supported install,
upgrade, boot activation, and retained-generation entry path; direct loading
of a persisted plan also validates its format/features independently.

Do not advertise compatibility with clients predating the common feature gate.
Ability-bearing releases are not delivered through a compatibility path that
lets those clients activate them. A legacy adapter is explicitly opaque and
keeps one lifecycle owner; it does not cause both old exposed-unit activation
and the new effect graph to operate on the same service.
