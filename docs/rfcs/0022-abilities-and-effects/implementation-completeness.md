# Implementation scope and completion evidence

This checklist distinguishes the complete RFC from its first vertical slice.
The [implementation phases](09-implementation-and-validation.md) order delivery;
finishing nginx alone does not finish the broader consumption, platform,
operations, or testing design. A release may deliver a declared subset, but
must reject unsupported required contracts and describe that subset accurately.

## Responsibility and acceptance map

Names below identify responsibilities, not mandatory filenames or crate splits.
Use the shared libraries described in the implementation plan and keep native
effects out of portable model/validation/inspection code.

| Feature | Responsible surface | Completion evidence |
| --- | --- | --- |
| Closed versioned contracts and identity | Shared model and validation libraries | Canonical valid/invalid fixtures; native and web decoders agree; unknown semantics and bounded-input violations reject |
| Nix schemas and helpers | Standard AOS module library plus restricted evaluation adapter | One typed `aos.abilities` option tree supports ordinary module composition; portable option projections agree with Rust; evaluated outputs are forced and checked; no effect or secret access during evaluation |
| Recursive implementation | Provider modules plus shared graph validator | Separately authored providers compose to admitted leaves without package-name special cases; cycles, missing ports, phase errors, and scope escapes reject |
| Controller ownership and aggregation | Composition and transition planner | Two contributors cause one shared transition; two instances stay distinct; collisions and double controllers reject |
| Static matching and late resolution | Shared validator/resolver with source and registry adapters | Equal canonical inputs yield equal choices and plans; ambiguity, invalid pins, conditional TLS, backtracking limits, and oscillation have deterministic outcomes |
| Publication and client compatibility | Package construction, APR publication, APM readers | Exact signed ability artifacts and gates survive round trips; supported old clients reject before activation through every entry path; unreleased drafts leave no compatibility code |
| Authority and provider admission | Policy adapter plus existing runtime providers | Mediation checks caller and provider grants; stale assignments, missing enforcement, and foreign resources fail before dependent effects |
| Planned providers and stage handoff | Runtime orchestration and boot adapters | A planned manager becomes ready before consumer acquisition; missing root prerequisites and cyclic bootstrap fail; receiving stage safely resumes ownership |
| Complete resource lifecycle | Provider transition constructors | Create, update, restart, no-op, drift, aggregate input removal, disable, replacement, and retained-target activation follow the lifecycle table |
| Conditional execution | Shared graph validator and executor | Every branch validates before execution; selected branch is durable; skipped results cannot satisfy required dependencies |
| Durable execution | Runtime, journal, and trusted method adapters | Every intent/effect/outcome boundary has qualified crash recovery; indeterminate effects reconcile; cancellation and deadlines cannot erase ownership |
| Generations and GC | Existing profile/config/image backends plus runtime records | Partial commits remain accurately visible; active consumers and recovery artifacts survive GC; persistent deletion requires separate authority |
| Service management and containers | Scoped manager and launch adapters | Packages use the same logical service contract across host and qualified system-container execution; required features and foreground support remain explicit |
| Credentials, storage, and networking | Selected resource/enforcement providers | Exact workload views and lifetimes are enforced; renewal/revocation and stop requirements are tested; ingress and policy precede readiness |
| Build and library consumption | Derivation metadata and artifact audits | Build/host/target uses remain distinct; actual ELF/plugin dependencies agree with declared consumption; exact closure retention is preserved |
| Aggregate roles and Kubernetes | Role/package interfaces and Kubernetes adapter | k3s consumes its payloads without extra service starts; Cilium aggregate input is scoped; unauthorized objects reject and submitted revisions are observed |
| Images and initrd | Existing image/boot builders and stage interfaces | Userland and bootable artifacts carry the right contract; unavailable launch facilities remain obligations; early consumers cannot depend on late facilities |
| Rollout and rollback | Strategy providers plus ordinary runtime contracts | At least one qualified strategy handles partial completion, health failure, draining, and retention; rollback revalidates current grants and data compatibility |
| Documentation and operator tools | Evaluated option graph, shared inspection library, CLI, docs, Hub, editor | One `mkOption`/ability declaration yields every option and ability reference view; the same checked graph yields consistent identities/explanations; signed release docs differ from deployment/observation views; prose changes cause no reload |
| Debugging and visualization | Inspection queries and execution records | Expand/collapse, projection selection, dependency/removal traces, timeline, and redacted bundles work against successful and failed fixtures |
| VM/fleet and release qualification | Existing test harnesses and qualification catalog | Production path is exercised with independent probes; fresh evidence binds exact subjects and required coverage; cached regression output is not release admission |
| Optional Crucible instrumentation | AOS guest adapter and existing generic interfaces | Ordinary runtime needs no Crucible; enabled assertions/choices use the same execution; advanced campaign gates track PR #194 explicitly |

## Implementation evidence and remaining runtime qualification

The completed implementation is assessed at generated boundaries rather than
by copying the declarations into this document. The source links below point to
the owning mechanism and to executable checks that evaluate its production
projection. They deliberately contain no package, interface, method, or cell
inventory that could drift from the fixed point.

The image-time source bundle is a validated template, not an executable plan.
At stage entry, the runner probes selected package-owned root handlers and
reconstructs a checked executable plan from their fresh observations. It
retains the admission record before journaling effects, requires the same
provider assignments when resuming, and checks the admitted plan and journal
again at host receipt. The root-observation protocol, source-plan replay, and
journal state machine have focused Rust tests. The
[`ability-initrd-activation` VM flight](../../../tests/fleet/ability-initrd-activation.nix)
selects a protected observer in the initrd fixed point, interrupts a returned
provider effect once, and checks reconciliation and host receipt. Its source
and derivation evaluation do not establish that the VM flight passes; runtime
qualification remains open until the KVM flight executes successfully. The
image and module checks below establish fixed-point projection and contract
wiring; they do not substitute for that runtime qualification.

| Target-state invariant | Owning implementation | Executable evidence |
| --- | --- | --- |
| One standard typed module vocabulary | [`lib/abilities/module.nix`](../../../lib/abilities/module.nix), [`lib/abilities/types.nix`](../../../lib/abilities/types.nix), and the selected domain interfaces in [`modules/abilities/_interfaces/`](../../../modules/abilities/_interfaces/) | [`tests/abilities/interface.nix`](../../../tests/abilities/interface.nix) and [`tests/abilities/authoring-conformance.nix`](../../../tests/abilities/authoring-conformance.nix) |
| Package abilities are native package modules | [`lib/abilities/package-projection.nix`](../../../lib/abilities/package-projection.nix) and package construction in [`pkgs/default.nix`](../../../pkgs/default.nix) | [`tests/packages/documentation.nix`](../../../tests/packages/documentation.nix) rejects legacy passthru fields, private library imports, and disagreement between `package.abilities` and the signed projection |
| Selected packages drive one complete module fixed point | [`lib/default.nix`](../../../lib/default.nix), [`lib/abilities/source-stage-fixed-point.nix`](../../../lib/abilities/source-stage-fixed-point.nix), and [`modules/base/build.nix`](../../../modules/base/build.nix) | [`tests/abilities/selected-package-provider-discovery.nix`](../../../tests/abilities/selected-package-provider-discovery.nix) and [`tests/abilities/_complete-composition-evaluation.nix`](../../../tests/abilities/_complete-composition-evaluation.nix) |
| Provider-neutral service features compose independently | [`modules/abilities/_service.nix`](../../../modules/abilities/_service.nix), [`modules/abilities/_interfaces/service-management.nix`](../../../modules/abilities/_interfaces/service-management.nix), and their shared service types | [`tests/abilities/service-features.nix`](../../../tests/abilities/service-features.nix), [`tests/abilities/service-management.nix`](../../../tests/abilities/service-management.nix), and the package-specific service checks in [`tests/abilities/`](../../../tests/abilities/) |
| Concrete manager semantics are package-owned | The system manager module in [`pkgs/system/_systemd-abilities/module.nix`](../../../pkgs/system/_systemd-abilities/module.nix) and the other package-local ability modules below [`pkgs/`](../../../pkgs/) | [`tests/abilities/provider-terminal-separation.nix`](../../../tests/abilities/provider-terminal-separation.nix), [`tests/abilities/systemd-service-realization.nix`](../../../tests/abilities/systemd-service-realization.nix), and [`tests/abilities/systemd-native-resources.nix`](../../../tests/abilities/systemd-native-resources.nix) |
| Controller modules and terminal handlers stay distinct | Typed `providerModule` and `handlerDescriptor` options in [`lib/abilities/module.nix`](../../../lib/abilities/module.nix), checked planning in [`crates/aos-ability-plan/`](../../../crates/aos-ability-plan/), and dispatch in [`crates/aos-package/src/config_eval/handler_dispatch.rs`](../../../crates/aos-package/src/config_eval/handler_dispatch.rs) | [`tests/abilities/provider-terminal-separation.nix`](../../../tests/abilities/provider-terminal-separation.nix) and [`crates/aos-package/src/config_eval/bound_handler_tests.rs`](../../../crates/aos-package/src/config_eval/bound_handler_tests.rs) |
| Resource lifetimes and revisions are semantic | The shared lifetime ordering in [`lib/abilities/lifetime.nix`](../../../lib/abilities/lifetime.nix) feeds the option types, fixed-point projection, composition, and systemd static rendering; centralized revision derivation lives in [`crates/aos-ability-plan/src/source_stage.rs`](../../../crates/aos-ability-plan/src/source_stage.rs) | Source-stage tests prove store relocation does not change a revision while semantic artifact or request changes do; transition tests in [`crates/aos-ability-plan/src/transition_tests/`](../../../crates/aos-ability-plan/src/transition_tests/) cover lifetime retention and removal |
| Runtime execution follows the checked graph | [`crates/aos-ability-runtime/`](../../../crates/aos-ability-runtime/), checked handler routing in [`crates/aos-package/src/config_eval/`](../../../crates/aos-package/src/config_eval/), and provider implementations selected by their package documents | [`tests/abilities/aos-controller-terminal.nix`](../../../tests/abilities/aos-controller-terminal.nix), provider-specific ability checks, and the native adapter qualification matrix |
| Documentation has one signed package projection | [`PackageDocumentationProjection`](../../../crates/aos-doc-model/src/lib.rs), the derived [`ReleaseAbilityGraph`](../../../crates/aos-doc-model/src/ability_graph.rs), generated package documentation in [`crates/aos-package/src/documentation.rs`](../../../crates/aos-package/src/documentation.rs), and Hub verification/indexing in [`crates/aos-hub-core/src/indexer/mod.rs`](../../../crates/aos-hub-core/src/indexer/mod.rs) | [`tests/packages/documentation.nix`](../../../tests/packages/documentation.nix) plus the documentation-model, package CLI/LSP, publication, Hub indexer, release-graph storage, and shared browser tests |
| Qualification is generated from selected contracts | [`qualification/modules/_native-adapter-matrix.nix`](../../../qualification/modules/_native-adapter-matrix.nix), [`qualification/modules/_container-execution-matrix.nix`](../../../qualification/modules/_container-execution-matrix.nix), and [`qualification/modules/abilities.nix`](../../../qualification/modules/abilities.nix) | [`tests/qualification/policy.nix`](../../../tests/qualification/policy.nix) and the package-derived native adapter scenarios |
| Publication consumes evaluated production inventories | [`pkgs/_target-policy.nix`](../../../pkgs/_target-policy.nix), the closed Rust inventory model in [`crates/aos-release/src/inventory.rs`](../../../crates/aos-release/src/inventory.rs), and release planning through `Platform::ALL` | [`tests/build/release-inventory-boundary.nix`](../../../tests/build/release-inventory-boundary.nix) validates the actual selected Nix inventory through the Rust model; semantic cross-language fixtures remain in [`crates/aos/tests/release_inventory_nix_boundary.rs`](../../../crates/aos/tests/release_inventory_nix_boundary.rs) |
| Image, initrd, and package-store projections use the same contracts | Stage projection in [`modules/abilities/stages.nix`](../../../modules/abilities/stages.nix), package-owned boot providers, and package-store interfaces in [`modules/abilities/_interfaces/`](../../../modules/abilities/_interfaces/) | [`tests/abilities/initrd-boot-substrate.nix`](../../../tests/abilities/initrd-boot-substrate.nix), [`tests/abilities/package-store-read-view.nix`](../../../tests/abilities/package-store-read-view.nix), and [`tests/abilities/boot-preparation-provider.nix`](../../../tests/abilities/boot-preparation-provider.nix) |

The largest hand-written vocabulary files are cohesive schema or package
declaration units. `lib/abilities/module.nix` owns the single typed option tree;
`modules/abilities/_service-types.nix` owns the provider-neutral service vocabulary;
and `pkgs/system/_systemd-abilities/core.nix` owns the closed, interdependent
systemd declaration graph. Rust implementation files place their test modules
after the production implementation, so test volume is not counted as another
production responsibility. New functionality belongs in a focused interface,
package module, provider module, or Rust submodule rather than extending these
files with an unrelated concern.

Acceptance evidence is derived from the package and provider declarations
described in the [target state](13-target-state.md). The completion report MUST
NOT pin the current number of interfaces, methods, adapters, qualification
cells, or fixtures. Adding or removing a provider changes the generated subject
set; the release check proves that every resulting required subject has
evidence.

The source-of-truth audit traces each option, interface, implementation,
requirement, method, guarantee, default, description, handler, and realized
backend artifact from one owning module declaration or evaluated provider
output to every consumer. Package manifests, parser schemas, documentation,
Hub/editor data, and qualification inputs must be generated projections. A
test that keeps two handwritten copies equal is evidence of duplication rather
than completion.

Conformance fixtures are small semantic inputs shared by Nix and Rust
consumers. Production provider documents and matrices are generated during
checks rather than committed as snapshots. Package-specific runtime evidence
exercises the implementation shipped by the owning package through reusable
harnesses and independent observations. Reference implementations are removed
when their only purpose was to duplicate a production provider.

Every acceptance row above needs direct evidence for its stated boundary. A
schema fixture does not establish runtime behavior, a generated manifest for an
opaque script does not establish structured activation, and a matrix assembled
from a second handwritten inventory does not establish production coverage.

## Required end-to-end reference fixture

Maintain one versioned fixture across authoring, source/registry planning,
inspection, runtime, and VM tests. Its symbolic labels below stand for exact
typed identities and authenticated artifacts, not new wire syntax.

The fixture contains environment `web`, nginx instance `edge`, two application
instances `app-a` and `app-b`, and separate managed-configuration, execution,
credential-delivery, and systemd providers. Both applications receive only
their own virtual-host slots. Nginx receives separately authorized lower
implementation bindings. The systemd manager and storage are grounded in the
environment inventory; a second fixture starts a manager through a valid
planned bootstrap path. TLS is initially disabled and later enabled with an
explicit opaque credential version.

Retain the following checkpoints as shared semantic fixtures. Runtime evidence
is produced by executing the real providers, not by treating fixture JSON as
proof that the effects occurred.

1. **Declaration and binding:** source and authenticated registry paths produce
   the same normalized aggregate input map, provider selections, logical resource
   IDs, and desired configuration. No TLS credential request is active yet.
   A failed grant or ambiguous provider produces no live mutation.
2. **First activation:** one nginx controller composes candidate preparation,
   required unit/resource preparation, validation, publication, start, and
   independent behavior observation. Validation sees the candidate under the
   intended identity and filesystem view. Both applications' routes work.
3. **Single-contributor update:** changing `app-a` changes its provenance and
   the aggregate configuration revision while preserving `app-b`'s slot and
   resource identity. The declared configuration-only path publishes and
   reloads once. Repeating equal desired state with matching observations
   performs no reload.
4. **TLS and runtime inputs:** enabling TLS introduces and authorizes its
   credential requirement. Missing delivery fails admission. Candidate
   validation and actual service execution receive the same declared version
   through their proper views; secret bytes appear in neither plan nor debug
   bundle. Fixed endpoints are ordinary typed configuration. Dynamic endpoint
   allocation remains unsupported until a provider can transfer a persistent
   socket or service handle atomically to its consumer.
5. **Failure before publication:** invalid candidate configuration fails
   validation; the old live target remains selected and functional. Candidate
   cleanup does not release resources still used by the old service.
6. **Failure after publication:** reload or readiness failure retains the new
   committed configuration and records old/unknown actual consumer state.
   An explicit rollback creates a new plan under current policy. It succeeds
   only if required credentials, artifacts, and state compatibility remain.
7. **Interrupted publication:** kill the executor after the external commit
   but before its success record. Restart recovery inspects the authoritative
   selected revision, settles that operation, and never blindly republishes
   or double-starts it. Repeat with qualified guest power loss to test the
   claimed durability boundary separately from process-crash recovery.
8. **Removal and replacement:** removing `app-a` recomputes the aggregate;
   removing `app-b` does not disable an operator-enabled nginx instance.
   Explicit disable stops it and releases eligible ephemeral resources while
   retaining persistent state. Provider replacement either uses a qualified
   adoption contract or rejects the unsupported transfer before effects.
9. **Scope and retention:** a second nginx instance cannot reuse the first
   instance's exclusive destinations. A stale manager assignment or revoked
   grant blocks further dependent effects. GC during partial activation
   retains candidate, old-consumer, and recovery artifacts until their recorded
   users detach.

Expected observations identify behavior as well as manager acknowledgements.
For example, a route-specific response distinguishes the newly requested
configuration from the old one; a successful `reload` acknowledgement alone
does not prove that distinction. The fixture must avoid manufacturing success
through a test-only service-control path.

## Dependency and migration boundaries

The core contract libraries, restricted authoring, source/registry validation,
inspection, and host systemd vertical slice can develop against existing AOS
facilities. They do not depend on all proposed sandbox or campaign features
being available. Each runtime adapter must name its actual provider protocol
and guarantees; an existing backend is usable only for semantics it enforces.

Integration with the pending sandbox work in PR #232 is qualified when its
resource/view/lease interfaces are available. Do not duplicate those brokers
to claim this RFC complete, or infer their guarantees from a draft. The same
rule applies to advanced Crucible campaigns from PR #194. Baseline guest
instrumentation and ordinary VM/fleet testing have separate acceptance gates.
The baseline gate connects the production guest adapter to the native executor
boundary stream, interrupts both the activation process and the VM at a retained
effect-returned selection, reproduces reconciliation, and records the exact
selection, reached event, digest-bound adapter acknowledgements, and inspector
timeline in a durable finding. Typed adaptive campaigns remain a separate PR
#194 integration.

The RFC-0022 implementation change cuts migrated packages directly to their
final structured activation path while preserving one activation owner per
resource and the current high-level install/desired-state intent. A package's
required features, retained-generation behavior, recovery, and actual runtime
provider path are qualified together before the old path is removed. The final
tree contains no legacy classification or opaque adapter for a package migrated
within the same change. Generating a manifest for an old script is not a
migration.

Generic package-owned services derive their activation revision after
configuration rendering. The canonical revision material includes the exact
artifact identities, normalized package ability document, selected provider
implementation, and rendered semantic configuration; raw Nix store-path
strings are excluded. Package authors do not set ordinary revisions. Operators
may add narrowly typed external content inputs or use one restart token to
force reapplication.

## Details an implementor may choose

Rust type names, private module boundaries, helper spelling, CLI layout, and
the concrete journal storage implementation may be chosen within these
contracts. Freeze and publish their exact schema/API representations with
cross-consumer fixtures before declaring version 1 stable. That engineering
work must not change authority, matching, identity, lifecycle, publication,
recovery, or required failure behavior without a design revision.

An adapter may support fewer operations or guarantees initially and reject the
rest. It may not silently reinterpret unsupported requests. A new interface,
equivalence mapping, privileged primitive, or provider-specific migration must
document its additional semantics and qualify them before advertisement.
These are explicit extension gates rather than missing permission to invent
behavior in the generic engine.
