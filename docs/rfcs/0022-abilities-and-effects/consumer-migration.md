# Migration status and qualification

The native infrastructure and consumer cutover are implemented in the same PR.
Superseded APIs are removed with their callers; there are no compatibility adapters between the
unreleased designs. This page separates implementation from qualification of
an actual system image.

Read the [target state](13-target-state.md),
[infrastructure APIs](infrastructure-cutover.md), and
[code examples and execution paths](../../users/aos/runtime-abilities.md) for
the authoring and execution model.

## Implemented boundaries

Package recipes use `module = ./directory` and explicit `moduleDeps`. Native
deployment envelopes and generated option references accompany the payload.
Module dependencies supply configuration without implicitly installing their
payloads. Named runtime bindings retain their actual artifact identities.

The generic evaluator and typed graph machinery serve all installation scopes.
Domain contracts and implementations belong to their packages. Consumers cover
service management, configuration, identity and credentials, networking, kernel
settings, filesystems and storage, databases, orchestration, boot preparation,
image transitions, and execution observation. Ordinary module merging extends
shared option trees; documentation projects the same declarations and provenance.

APM resolves native envelopes, evaluates retained sources, and applies profile
transactions. Boot and later package changes share the system profile. Removal
and rollback reconcile desired deployments through the same controller; rollback
does not rewind the execution journal. Explicit retirement policy controls
persistent resources.

The immutable evaluation descriptor retains the module library, original source
identities, ordered configuration, module envelope companions, and selected
payloads. The schema-only dependency catalog remains available for offline
reconfiguration. Image stages use retained policy files, including optional
profiles and fixture policy; inline stage configuration cannot silently disappear
from replay. Initrd storage projection retains source metadata without retaining
host payloads, and full host graph validation precedes host effects.

Container construction selects a smaller package-managed scope from the broader
image configuration. It uses the same evaluator and descriptors as host profiles.
This cutover does not port kernels, toolchains, or the Linux process transport.

Hub release ingestion, indexed package pages, deployment reports, its native
artifact viewer/API, and CLI inspection use the shared native documentation
model. Release ownership and source provenance link packages, operations,
selected handlers, and configured effects. Desired configuration, journal
receipts, and observed live state remain distinct.

## Completed integration checks

Image production, conversion, publication inspection, and staging share canonical
provider metadata with a separate neutral delivery record. Finalization uses the
same serializer for observed filesystem, GPT, and EFI facts. Conversion preserves
the provider document rather than copying its schema into a second representation.
The source-built metadata fixture checks actual filesystem, GPT, FAT, and EFI
artifacts and rejects a changed payload outside the committed partition.

Qualification retains independent adopted-baseline and selected-target evaluations.
The bounded registry checks 15 required operations across six domain cohorts.
Actual image graph assertions verify that adoption does not execute the future
transition, the selected graph contains its required operation, and source custody
survives the switch. Ordinary service baselines retain their handler and dependency
configuration. These are construction and source checks, not executed release claims.

The package and release Rust suites pass 1,102 tests; focused model, handler,
metadata, Hub, and CLI suites cover their own boundaries. Source-built effects
checks cover module merging, portable constraints, generated references, source
retention, and domain handlers. The package-wide platform and generated-companion
evaluation also passes. Build and runtime validators share nonempty and single-line
string constraints, including after deferred result substitution.

The isolated first-host check passes authorized metadata adoption before effects,
repeat boot without duplicate dispatch, operator reconfiguration with module-only
dependencies, preservation of operator sources across boot, and observation-based
recovery after an interrupted effect.

Source-built checks already exercise retained-source evaluation, actual garbage
collection, EROFS materialization, and signed publication companions. Realized
closure checks verify identical full/source-only descriptor data and exclude
unselected payloads. Optional production profiles and representative fleet
stages replay to the same graphs as their image evaluations. These checks do not
establish whole-system boot or physical image-transition qualification.

## Qualification boundary

A release claim must bind the exact candidate artifacts, source context, selected
handlers, and independently observed domain evidence. A test wrapper that controls
handler responses qualifies that wrapper/backend composition. It does not qualify
the unwrapped handler's exact bytes by inference.

Each cohort retains the baseline it adopts separately from the target graph it
will exercise. Importing a fixture must not execute a future rollout before the
scenario begins. Every applicable required cell needs actual evidence; a missing
backend implementation is not a reason to mark a cell inapplicable.

Run Cargo through `aos-dev` first, then focused source-built checks through
`aos-dev` with its shared caches. Use bounded domain evaluations during iteration.
Report real VM boot and physical transition campaigns separately from pure,
handler, or schema tests.

Journals currently enforce capacity limits without automatic compaction.
Generation pruning does not remove that limitation.
