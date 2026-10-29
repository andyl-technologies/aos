# AOS engineering

This section explains how AOS is built: implementation details, design
rationale, architecture, and the internal contracts between components. It is
for people changing the source tree. Running AOS is covered in the
[user documentation](../users/README.md), and managing installation media,
releases, and forks is covered in the [maintainer documentation](../maintainers/README.md).

Pages are organized by component or feature. Each page describes the code as it
is; when the code changes, the page changes with it. A design decision is
recorded in the page for the component it affects, in the same change that
makes it. The [code style guide](code-style.md#documentation) gives the rules.

## Repository-wide

- [Code style](code-style.md) covers Rust APIs and implementation, Dendritic Nix
  modules, package expressions, comments, tests, embedded shell, and
  documentation.
- [Rust workspace](rust-workspace.md) covers crate naming, ownership, directory
  groups, dependency direction, and the inventory of workspace packages.

## Build system

- [Build system](build/README.md) maps the bootstrap, toolchain tiers, stdenv,
  and language builders.
- [Toolchain ladder](build/toolchain-ladder.md) covers the source bootstrap,
  GCC tiers, per-tier stdenv, and producer validation rules.
- [Rust builds](build/rust-builds.md) covers reusable Cargo dependency
  artifacts, their compatibility contract, development caches, and nextest.

## Downstream builds

- [Downstream quickstart](downstream/quickstart.md) starts a repository that
  takes AOS as its only flake input and tests it against a local checkout.
- [Downstream flake API](downstream/flake-api.md) is the versioned contract
  for the exported builders, package attributes, toolchain set, and
  compatibility policy.
- [Downstream binary cache](downstream/binary-cache.md) covers the cache
  settings, multi-user daemon trust, and the check that proves every toolchain
  downloads.

## Boot and trust

- [Boot chain](boot/README.md) maps verified boot, lockdown, measured boot,
  recovery, and the image-boot test harness.
- [Secure Boot](boot/secure-boot.md) covers signed systemd-boot and UKIs,
  key enrollment, the lockdown kernel, and key roles.
- [Measured boot](boot/measured-boot.md) covers TPM measurements and the
  sealing of the `/var` encryption key to an authorized boot.
- [Recovery](boot/recovery.md) covers the signed recovery UKIs and the
  noninteractive initrd failure paths.
- [Image-boot testing](boot/image-boot-testing.md) covers the checks that boot
  the real raw image under UEFI firmware.

## Host configuration

- [Host configuration](host-configuration.md) covers the image and host
  boundary, metadata acquisition and authorization, storage commit, pure
  on-host evaluation, and journaled configuration generations.

## Packages and runtime abilities

- [Runtime abilities](abilities/README.md) gives the package module model,
  ability operations, handlers, and deferred execution.
- [Package modules and evaluation](abilities/evaluation.md) covers the
  build-time envelope, module resolution, evaluation descriptors, and the
  generated reference.
- [Deferred execution and generations](abilities/execution.md) covers graph
  admission, the handler protocol, effect identity, package generations, and
  recovery.
- [Package service sandbox](packages/service-sandbox.md) covers how a typed
  service declaration becomes the unit's confinement.
- [Package and generation attestation](packages/attestation.md) covers the
  PCR 15 record of the committed native package generation.
- [Package documentation](package-documentation.md) covers generation of
  package reference documents, their signed publication, Hub verification and
  search projections, and the shared readers.
- [Package maintenance](package-maintenance/README.md) covers the
  `aos maintain` update model, components, workflow states, confinement, and
  repair boundary.
- [Update contract](package-maintenance/update-contract.md) describes the
  `mkUpstream` declaration that update tooling reads and edits.

## OCI containers

- [OCI containers](oci-containers/README.md) gives the build and distribution
  pipeline, code map, and container checks.
- [Image build](oci-containers/image-build.md) covers container definitions,
  closure layers, the layer archive ABI, and runtime initialization.
- [Distribution and publication](oci-containers/distribution.md) covers the
  shared OCI contract, Hub's Distribution data plane, verified publication, and
  garbage collection.

## Package registry

- [Package registry](registry/README.md) introduces the registry as a signed
  sha256 git repository served over dumb HTTP and maps its pages.
- [Architecture](registry/architecture.md) covers the ref layers, consumer
  paths, and the Nix-cache superset.
- [Repository layout](registry/repository-layout.md) specifies the committed
  tree: package metadata, keys, and the `store/` graph.
- [HTTP and object-store layout](registry/http-layout.md) specifies the bytes
  served at each URL and their CDN caching rules.
- [Signing and trust](registry/signing-and-trust.md) covers what is signed, the
  consumer verification chain, and anti-rollback.
- [Store realisation graph](registry/store-realisation-graph.md) covers how the
  signed tree authenticates the exact bytes of every closure member.
- [Versioning and channels](registry/versioning-and-channels.md) covers semver
  releases, channels as branches, partition tags, rollout, and anti-rollback.
- [Packs and deltas](registry/packs-and-deltas.md) covers full packs, the thin
  delta graph, client resolution, and retention.
- [Nix binary cache](registry/nix-cache.md) covers the static Nix-cache files a
  producer generates at publish.
- [Publishing pipeline](registry/publishing.md) covers the `apr` producer
  surface, atomicity, and concurrency.
- [Release stages](registry/release-stages.md) covers unpublished release
  candidates and their publication boundaries.
- [Web surface](registry/web-surface.md) covers the static pages and optional
  WASM application a registry serves.
- [Implementation](registry/implementation.md) maps the design onto the
  producer, consumer, and shared wire-format crates.
- [Comparison with APT](registry/apt-comparison.md) gives the design rationale
  against the Debian repository format.

## AOS Hub

- [AOS Hub](hub/README.md) introduces the multi-tenant registry and binary-cache
  host and maps its pages.
- [Surface topology](hub/topology.md) gives the registry and binary-cache
  surface model, its goals, and its invariants.
- [Domain model](hub/domain-model.md) defines surfaces, bindings, placements,
  endpoints, routes, and gateways.
- [Delivery and authentication](hub/delivery.md) covers route matching,
  delivery modes, network policy, and replicated publication.
- [Tenancy, authorization, and authentication](hub/tenancy-and-auth.md) covers
  the tenancy hierarchy, the authorization kernel, credentials, and audit.
- [Registry and binary-cache relationships](hub/registry-cache-relations.md)
  covers consumer cache stacks, retention subscriptions, and population
  targets.
- [Retention and garbage collection](hub/retention-and-gc.md) covers rooting
  and safe deletion of binary-cache objects.
- [Configuration changes and webhooks](hub/configuration.md) covers SQL
  change-sets, git-backed registry change requests, and webhooks.
- [Control plane and console](hub/control-plane.md) covers API, CLI, and web
  console parity and the manifests that check it.
- [Runtime](hub/runtime.md) covers the shared application core, runtime ports,
  the database backend, and the native and Worker runtimes.
- [Topology cutover](hub/topology-cutover.md) specifies the one-shot migration
  of an older deployment and its signed evidence bundle.

## Release publishing

- [Canonical release publishing](release-publishing/README.md) gives the
  pipeline from planning through signing, staging, qualification, and
  publication.
- [Release model](release-publishing/release-model.md) defines registries,
  tiers, channels, release classes, surfaces, destinations, and profiles.
- [Security and keys](release-publishing/security-and-keys.md) covers the threat
  model, signer roles, TUF metadata, and the external signing boundary.

## Crucible

[Crucible engineering](crucible/README.md) introduces the deterministic
multi-VM simulation harness and its layers.

Foundations:

- [Architecture](crucible/architecture.md) covers processes, layers, and data
  flow.
- [Glossary](crucible/glossary.md) defines the vocabulary used in the code.
- [Determinism contract](crucible/determinism.md) states what is reproducible
  and how each entropy source is eliminated.
- [Virtual time](crucible/virtual-time.md) covers instruction-count clocks and
  the picosecond timeline.
- [Execution model](crucible/execution-model.md) defines the state type and the
  operations that extend and realize it.
- [Scenario model](crucible/scenario-model.md) defines the immutable,
  content-addressed run definition.
- [Execution graph](crucible/execution-graph.md) covers the content-addressed
  checkpoint graph.
- [Scheduling](crucible/scheduling.md) covers the single authoritative
  scheduler.

QEMU integration and transport:

- [QEMU integration](crucible/qemu-integration.md) covers host-side launch,
  supervision, and QMP.
- [The atomic QEMU patch](crucible/qemu-patch.md) covers what the patch adds,
  its capability catalog, file licenses, and regeneration.
- [The in-QEMU plugin](crucible/qemu-plugin.md) covers the virtual clock, idle
  parking, I/O interception, and input injection.
- [Shared-memory ABI](crucible/shmem-abi.md) specifies the co-simulation
  region layout and wake protocol.
- [Host/plugin control protocol](crucible/control-protocol.md) specifies the
  framed socket protocol and version handshake.
- [I/O sub-nodes](crucible/io-subnodes.md) covers deterministic disk, 9p, and
  network devices.
- [Guest-host channel](crucible/guest-host-channel.md) covers the optional
  guest doorbell.

Semantics:

- [Conditions, triggers, and fault injection](crucible/conditions-and-triggers.md)
  covers the event graph and its shared predicate vocabulary.
- [Assertions and properties](crucible/assertions.md) covers temporal
  properties evaluated over the event log.
- [Event log](crucible/event-log.md) covers the single canonical record of a
  run.

Control plane:

- [Session control plane](crucible/session.md) covers the session actor and its
  commands.
- [Control API](crucible/control-api.md) covers the RPC ABI, clients, server,
  and daemon.
- [CLI internals](crucible/cli.md) covers dispatch planning and backend routing
  in the `crucible` command.

Exploration and debugging:

- [Exploration](crucible/exploration.md) covers fork, replay, search, and
  coverage-guided fuzzing.
- [Failure triage](crucible/failure-triage.md) covers root-cause signatures,
  grouping, and minimization.
- [Distributed exploration](crucible/distributed-exploration.md) covers the
  shared store, frontier, and leases.
- [Time-travel debugging](crucible/time-travel-debugging.md) covers GDB attach
  and movement through deterministic history.

Building and qualifying:

- [Testing and determinism gates](crucible/testing-and-gates.md) covers the
  layered gate harness.
- [Engineering standards](crucible/engineering-standards.md) adds
  Crucible-specific code rules.
- [Crate structure](crucible/crate-structure.md) covers crates, layers, and
  dependency rules.
- [Performance](crucible/performance.md) covers the cost model and the
  performance regression gate.
- [Packaging](crucible/packaging.md) covers the Crucible packages and their
  release assembly.
- [Workloads and worked examples](crucible/workloads.md) covers in-guest load
  and workload parameters.

### Crucible campaigns

- [Campaigns](crucible/campaigns/README.md) introduces persistent, adaptive
  exploration of one scenario lineage.
- [Campaign data model](crucible/campaigns/data-model.md) covers campaign facts,
  references, and Merkle projections.
- [Typed selectables and the choice protocol](crucible/campaigns/choice-protocol.md)
  covers the shared opportunity and selection model.
- [Exploration and guidance](crucible/campaigns/exploration.md) covers policies,
  generators, and the planner.
- [Coordinator, planner, and executor](crucible/campaigns/coordinator-and-executor.md)
  covers the boundary between campaign policy and host execution.
- [Hot fork and exact checkpoints](crucible/campaigns/hot-fork-and-checkpoints.md)
  covers how branch attempts reuse paused worlds.
- [Campaign storage](crucible/campaigns/storage.md) covers the content-addressed
  object model and its storage component graph.
- [Measurements, observability, and findings](crucible/campaigns/observability-and-findings.md)
  covers feedback, telemetry, and findings.
- [Security, compatibility, and operations](crucible/campaigns/security-and-operations.md)
  covers trust boundaries and fail-closed operation.
- [Performance and validation](crucible/campaigns/performance-and-validation.md)
  covers the campaign gate catalog and its performance checks.
- [Schema registry](crucible/campaigns/schema-registry.md) covers the single
  registry of independently versioned schemas.
- [Worked network fixture](crucible/campaigns/worked-network-fixture.md) covers
  the reference campaign that exercises the whole model.

### Crucible fault model

- [Signal-driven fault model](crucible/fault-model/README.md) introduces causes,
  effects, and opportunities.
- [Signal programs](crucible/fault-model/signal-program.md) covers the closed
  declarative signal language.
- [Bindings, opportunities, and runtime state](crucible/fault-model/bindings-and-runtime.md)
  covers how causes reach modeled hardware.
- [Effects and the fault taxonomy](crucible/fault-model/effects-and-taxonomy.md)
  covers the effect registry and real-world fault vocabulary.
- [Network fault adapter](crucible/fault-model/network.md) covers links,
  buses, fabrics, and mobile endpoints.
- [Storage and 9p fault adapter](crucible/fault-model/storage.md) covers
  durability layers and persistence faults.
- [Node faults and the QEMU fault boundary](crucible/fault-model/node-and-qemu.md)
  covers guest machine effects applied inside QEMU.
- [Recording, replay, and observability](crucible/fault-model/replay-and-observability.md)
  covers recorded traces, replay modes, and explanations.
- [Resource limits](crucible/fault-model/resource-limits.md) covers the bounds
  that keep fault state and work finite.

## Legal

The [license map](../legal/licensing.md) is the normative policy for file
licenses and the Crucible/QEMU process boundary.
