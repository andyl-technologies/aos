# Implementation, migration, and qualification

## Deliver a vertical implementation before freezing the API

This RFC proposes an architecture. Acceptance does not make illustrative Nix
helpers, persisted schemas, new CLI flags, or container activation available.
The first implementation must prove a complete provider composition and its
runtime behavior before generalizing the interface across the package set.

Use shared Rust contract and validation code across AOS/APM and source-build
checks. Keep pure schema/graph validation separate from privileged resource
acquisition and execution. Existing libraries and binary entry points remain
the integration boundaries; crate names and placement are implementation
choices, not a mandate to put every responsibility in `aos-package`.

## Shared Rust libraries and dependency boundaries

Ability support is a library subsystem, not logic owned by one CLI binary.
Use cohesive modules with explicit public contracts and split crates where
reuse, portability, or authority boundaries justify it. The following are
required responsibilities; crate names are proposed rather than existing APIs:

| Library responsibility | Proposed home | Dependents |
| --- | --- | --- |
| Interface/graph types, typed identities, bounded encoding, structured diagnostics | `aos-ability-model` using existing `aos-contract` primitives | All ability consumers |
| Pure schema and graph validation, compatibility, binding checks | `aos-ability-validate` | Build checks, APM, publication checks, planner, inspectors |
| Bounded provider resolution and transition planning over explicit inputs | `aos-ability-plan` | AOS/APM workflows and offline previews |
| Graph queries, explanations, diffs, redacted view/export models | `aos-ability-inspect` | CLI, documentation, Hub, editor/debugging tools |
| Admission, scoped provider adapters, journaling, execution and recovery | `aos-ability-runtime` | Authorized native runtime controllers |
| Optional guest assertions, markers, and choices through generic Crucible interfaces | `aos-ability-crucible` | AOS executor/test profiles running inside Crucible |

The [existing contract crate](../../../crates/aos-contract/src/lib.rs) already
owns pure canonical encoding, typed digests, and bounded decoding. Reuse those
primitives rather than adding another canonical-JSON implementation. The
[documentation model](../../../crates/aos-doc-model/src/lib.rs) is a precedent
for sharing pure data semantics across APM, native Hub, and Worker consumers.
Keep package documentation's format separate from live ability-state formats.

The dependency direction is from frontends/adapters toward the shared model
and pure libraries. The model must not depend on `aos-package`, CLI parsing,
systemd connections, registry transport, a Nix subprocess runner, or credential
access. The runtime consumes validated contracts and existing broker/systemd
adapters; importing a model or visualization library must not import a
privileged executor.

Pure planning takes explicit snapshots and authenticated candidate descriptors.
Native orchestration adapters perform Nix evaluation, downloads, clock reads,
and resource discovery around that computation. Every external input becomes
an explicit recorded planning input. This keeps deterministic tests and offline
inspection possible without pretending that the outer workflow performs no I/O.

Shared model/inspection code must remain usable by native and web consumers.
Hub may render checked public contracts without a native Nix evaluator or
Linux runtime dependencies. Client-side validation improves feedback; it never
replaces authoritative checks on the execution side. The final number of crates
may be smaller initially, but these dependency and authority boundaries must
remain visible and must be exercised by more than one consumer.

## Phase 1: inventory and semantic contracts

Inventory current expose/configuration metadata, dependency consumers, graph
operations, activation recovery, profile retention, and sandbox broker
protocols. Document the owning component for each interface and operation so
two executors cannot independently control the same resource.

Specify identities, schemas, canonical encoding, compatibility rules, feature
negotiation, required versus advisory requirements, and error categories.
Define result phases and reference typing before implementing a generic
composition helper. Keep public documentation data separate from private
binding and execution records.

Exit criteria: representative contracts validate through the same AOS-built
library in source checks and APM; malformed, oversized, unknown-critical, and
unauthorized inputs fail predictably. Existing package behavior is unchanged.

Publish shared positive/negative conformance fixtures for Nix normalization and
Rust validation. Test model and inspection libraries independently of runtime
dependencies, and require native/Worker consumers to agree on the same public
view data. CLI tests verify orchestration and presentation, not a duplicate
implementation of the semantic rules.

## Phase 2: Nix authorship and recursive composition

Implement the module vocabulary for exports, imports, requirements, explicit
bindings, aggregation, typed results, and provider-owned composition. Reuse
existing configuration ownership and restricted evaluation. Publish exact
declarations with authenticated companion artifacts and generated reference
schemas.

Build one real nginx example with two application contributors. Its export
must compose through independently authored managed-configuration and systemd
providers, including credentials when configured. Exercise separate instances,
contribution removal, slot collisions, and conditional lower requirements.

Exit criteria: there is no hard-coded nginx interpretation in the central
planner; all concrete requests terminate in recognized implementations or
explicit deployment obligations; expansion is bounded; source evaluation and
registry evaluation produce equivalent normalized contracts from equal inputs.

Deliver text/JSON inspection and expandable composition traces in this phase,
so provider authors can diagnose their declarations before runtime execution
exists. Ability tooling is part of the vertical implementation, not deferred
entirely to final UI work.

## Phase 3: matching, resolution, and environment admission

Add explicit source binding and bounded registry resolution over the same
constraint vocabulary. Validate the whole candidate state before changing
live activation. Root candidate artifacts during preparation. Persist exact
provider decisions and explain conflicts and unresolved deployment inputs.

Qualify a host systemd deployment and a deliberately provisioned system
container. Verify that container-local activation cannot invoke host-only
operations. Keep the current runtime rejection until that admission path and
its enforcement are complete. A foreground deployment is a separate supported
interface, not a fallback that strips unsupported unit semantics.

Exit criteria: planned versus available providers, stale inventory, missing
delegation, provider removal, conditional TLS, incompatible ABI, and bootstrap
cycles have explicit tested outcomes. Existing system desired-package and
user-profile install workflows preserve their documented intent.

## Phase 4: structured transitions and recovery

Introduce the smallest useful operation vocabulary for the nginx vertical
slice: candidate preparation, credential binding, validation, publication,
service lifecycle, and readiness. Provider-authored transition constructors
compose these operations through exact bindings.

Reuse the existing generation commit/recovery boundary until the replacement
passes fault-injection qualification. Add durable intent/outcome records,
precondition checks, resource serialization, bounded retry, reconciliation,
and compensation where genuinely supported. Define compatibility for
interrupted transactions during executor upgrades.

Exit criteria: crash or cancellation at every effect boundary has a defined
recovery path; ambiguous external outcomes remain visible; an unchanged plan
does not spuriously reload; failed required enforcement never produces an
unconfined successful activation. Generation/profile publication and actual
consumer observations cannot contradict the recorded outcome.

Expose the operation timeline and a redacted diagnostic bundle alongside the
journal. Recovery failures must be explainable through the same inspection
model used for successful plans.

The optional [Crucible guest integration](11-crucible-integration.md) uses
these same AOS execution hooks. Its basic assertion/probe flight can proceed
against supported baseline interfaces. Typed choice campaigns, structured
measurements, and hot-fork acceleration follow the separate PR #194 dependency
and acceptance gates listed there; they are not prerequisites for ordinary
production activation or VM/fleet testing.

## Phase 5: ecosystem and operator workflows

Expand to database endpoint consumption, k3s/Cilium configuration integration,
initrd and image handoff, typed build/library edges, documentation, Hub,
editor support, generation comparison, and removal analysis. These exercise
different consumption mechanisms rather than repeating the nginx shape.

Add rollout strategies only when their providers supply concurrency, traffic
control, health, draining, and retention. Demonstrate rollback with current
authorization and state-format checks. Preserve exact store references and
active-consumer retention while richer dependency metadata is adopted.

Exit criteria: operators can trace a dependency through its use, explain a
failed binding or transition, identify mixed-generation state, and determine
whether a retained target is currently activatable.

## Qualification matrix

The [completion map](implementation-completeness.md) assigns responsibility
and evidence to the full feature set and specifies the common end-to-end
reference fixture. The nginx vertical slice is an early delivery milestone;
it does not satisfy the later platform, consumption, tooling, and qualification
requirements on its own.

| Scenario | Required result |
| --- | --- |
| Same canonical source and registry inputs | Equivalent normalized bindings and effects |
| Two applications contribute nginx virtual hosts | One authorized aggregate; independent provenance |
| Two instances produce identical bytes | Separate identities and resource scopes |
| Caller supplies foreign result name or file destination | Rejected without provider-authority escalation |
| Contribution uses a raw directive to exceed its granted scope | Rejected or separately authorized; syntax validity is insufficient |
| Runtime address used by a pure Nix renderer | Rejected phase mismatch or explicit deferred materialization |
| Recursive implementation has no terminal provider | Bounded failure with expansion trace |
| Provider selection oscillates after configuration evaluation | Bounded diagnostic, no partial activation |
| systemd package installed without a running/planned manager | Payload available; lifecycle requirement unsatisfied |
| Container manager exists without required delegation | Admission fails with missing guarantee |
| Required security provider fails in degraded boot | Consumer excluded or activation fails; guarantee never dropped |
| Candidate nginx config fails validation | Existing live configuration remains selected |
| Reload fails after publication | Committed configuration and failed/uncertain consumer state recorded |
| Crash after external effect before success record | Observe/reconcile before retrying |
| Competing controller changes resource revision | Stale operation is fenced or rejected |
| Rollback needs revoked grant or unavailable credential | Rejected or explicitly replanned under current authority |
| GC during preparation or partial activation | Candidate, recovery, and active-consumer inputs retained |
| Library metadata disagrees with actual ELF dependencies | Artifact audit fails; exact store closure preserved |
| Documentation prose changes alone | No runtime identity or restart change |
| CLI, Hub, and editor inspect the same checked graph | Same identities, edge meanings, and structured diagnostic codes |
| Source output omits its required contract check | Supported build/publication gate rejects the output |
| Redacted snapshot is missing a required planning input | Debugger reports the limitation; it does not invent a successful replay |
| Old client encounters required new execution semantics | Selection/activation fails through a qualified compatibility boundary |

Testing must include actual runtime enforcement and fault injection where
claims depend on them. Schema fixtures and simulated successful handlers do
not establish namespace confinement, filesystem atomicity, or crash recovery.
Use AOS-built test dependencies and the repository's VM/feature requirements.
Boundary changes additionally run their existing ABI and licensing gates.

[Testing and qualification](10-testing-and-qualification.md) specifies how
these cases exercise the production implementation across provider, VM, fleet,
container, and release environments. It defines independent observations,
semantic fault injection, interface coverage, exact-subject evidence, and
integration with the existing qualification catalog.

## Documentation change validation

For this RFC-only change, check chapter references, repository source paths,
Markdown structure, illustrative Nix syntax where it is a complete expression,
and consistency between examples, invariants, and implementation gates.
Inspect the prose and examples manually. Runtime qualification belongs to the
implementation phases; adding this document cannot run tests of APIs that do
not yet exist.
