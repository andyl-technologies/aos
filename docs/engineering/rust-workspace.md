# Rust workspace

AOS Rust code lives in one Cargo workspace under `crates/`. It contains the AOS
command-line programs and system services, reusable ecosystem libraries, and
independent projects such as Hub and Crucible. The authoritative membership is
the `members` list in [`crates/Cargo.toml`](../../crates/Cargo.toml); the
workspace manifest and lockfile live directly under `crates/`.

Before adding or splitting a crate, check the [inventory](#inventory) for
existing reusable code and name collisions.

## Naming and ownership

A package's full name identifies its ownership and purpose without relying on
its filesystem path. Directories group packages for readers; they do not
introduce Cargo namespaces.

- `aos-<capability>` names a reusable ecosystem library, such as `aos-nar`,
  `aos-transfer`, or `aos-systemd-client`.
- `aos-<subsystem>-<responsibility>` names an AOS implementation, such as
  `aos-activation-sysctl` or `aos-registry-authoring`.
- `aos-hub-*` and `crucible-*` identify their respective projects.
- `aos-core` contains small portable primitives. It does not own terminal
  output, command dispatch, Nix execution, or application policy.
- Generic suffixes such as `model`, `api`, and `runtime` require an explicit
  owner.
- Each crate directory matches its full Cargo package name. Rust library names
  use the corresponding underscore spelling.

Extract a crate when independent consumers, dependencies, platforms, packaging,
licensing, or a stable public boundary justify it. Otherwise organize related
code into modules of the existing owner. Shared libraries may perform I/O; their
dependencies must match their capability rather than an application's
deployment requirements.

Crate names are not compatibility identities. Executable names, serialized
schema tags, hash and signature domains, protocol constants, and persisted
content identities keep their established spelling when a package is renamed
or moved. Source-input filters, fixture paths, generated API inputs, and Nix
package selections must track package moves explicitly.

## Directory groups

Every application workspace crate lives at `crates/<group>/<package>/`.

```text
crates/
  activation/ execution and concrete operation handlers
  artifacts/  artifact evidence, NAR archives, and OCI formats and operations
  bindings/   native library bindings
  boot/       boot identity, platform metadata, and installed boot tools
  cli/        command-line programs and presentation
  core/       portable primitives
  crucible/   deterministic execution, QEMU integration, control, and storage
  hub/        Hub domain, persistence, services, clients, and deployments
  linux/      Linux project quotas and systemd clients
  modules/    module formats and documentation
  nix/        Nix process and store-tool integration
  packages/   package consumption and deployment
  registry/   registry formats, clients, authoring, and static web application
  release/    release formats, coordination, image finalization, and signing
  transfer/   transfer protocols and progress reporting
```

A shared domain format can remain under its owning project's directory while
another project consumes it. Dependencies establish reuse; directory placement
establishes ownership.

`crates/accache/` is a separate Cargo workspace, excluded from the application
workspace, with its own lockfile and the sibling `accache` and
`accache-frontend` crates. The compiler action cache must build without
resolving the application workspace or enabling its shared caches. Its
[README](../../crates/accache/accache/README.md) covers usage and diagnostics.
Small Cargo workspaces under test fixtures likewise stay isolated for the
artifact contracts they exercise. Neither appears in the inventory below.

## Dependency direction

Applications and deployment adapters depend on reusable domain libraries, which
depend on common primitives. Shared libraries must not import an application's
CLI, runtime, or deployment policy. Portable format libraries do not acquire
native drivers merely because their native consumers use those drivers. Prefer
direct dependencies on the owning crate; a compatibility facade that retains an
application dependency undermines the boundary.

Transfer reporting follows that direction: `aos_transfer::progress` defines
observers and cloneable progress handles without terminal or transport drivers.
`aos-cli-ui` implements the terminal renderer with transfer defaults disabled,
and registry acquisition accepts observers without a terminal dependency.
Registry refresh selection, state persistence, aggregate errors, JSON output,
and recovery commands belong to `aos_package_manager::update`.

Crucible's permissive QEMU protocol and shared-memory crates stay separate from
the Apache host code and the GPL plugin and debugger code. Moving a directory
does not change license scope or authorize an otherwise invalid dependency; see
the [license map](../legal/licensing.md).

## Portable data and native effects

`aos-core` is deliberately small and portable: strict JSON (`json`), content
digests (`digest`), decoding limits (`limits`), and bounded scoped names
(`identity`). Shared code is classified by capability rather than accumulated
into a universal core. `aos-nar` owns NAR, narinfo, and cache signing;
`aos-nix` owns native Nix execution; `aos-cli-ui` owns terminal presentation.
OCI JSON keeps its own dialect in the OCI crates because its accepted inputs
differ from strict canonical AOS JSON; exact validation behavior is part of the
format contract.

`aos-deployment-format` owns immutable inventory records and deployment schemas.
`aos-deployment` evaluates inputs, retains store references, and performs
activation, accepting inventory data from callers. Registry authoring and
release coordination do not import package installation, and image
finalization uses inventory data without depending on the package manager.
Release coordination accepts domain inputs without a CLI parser. The native
registry-authoring crate keeps its APR parser and terminal adapters alongside
signing and local staging operations that accept domain inputs without a
printer. Format libraries stay separate from native signing processes, and
common DSSE framing remains in the portable registry format.

Build RPC and Hub access are separate clients: `aos-build-client` and
`aos-hub-client`. Canonical protocol sources live under
[`api/proto/`](../../api/proto/), and the generated build and Hub APIs are
separate packages. Hub separates domain policy (`aos-hub-model`), persistence
(`aos-hub-db`), and service orchestration (`aos-hub-service`); native SQL
drivers belong to the database crate and stay out of WebAssembly deployments.
The [Hub crate overview](../../crates/hub/README.md) describes each Hub package.

Module activation graphs live in `aos_module_format::graph`. Artifact evidence
lives in `aos-artifact-evidence`, independently of module activation.

`crucible-control-api` owns control messages, canonical codecs, and
compatibility contracts; `crucible-control-client` owns client transport; and
`crucible-control-server` owns server integration and live event-log adapters.
The control API is consumable by native clients and services, but it retains
session and engine dependencies and is not a WebAssembly format library.
Production VM lifecycle belongs to `crucible-daemon`.

`aos-linux-project-quota` is shared for its quota capability. Crucible storage
keeps its own project scope: its object kinds and persisted identities are
Crucible domain concepts.

The initrd preparation program is compiled directly by its Nix recipe from
`crates/boot/aos-boot-runtime/standalone/initrd_preparation.rs` and is not a
Cargo target, because its `env!` tool paths bind the exact production closure
at compile time. Its installed name is `aos-boot-preparations`; the
[boot runtime README](../../crates/boot/aos-boot-runtime/README.md) documents
the exception.

## Inventory

The workspace has 78 member packages. Packages inherit the workspace
`Apache-2.0` license unless the table lists another one.

| Package | Directory | Responsibility |
|---|---|---|
| `aos-activation` | [activation/aos-activation](../../crates/activation/aos-activation/Cargo.toml) | Durable activation and recovery of native module operation graphs |
| `aos-activation-bpf-lsm` | [activation/aos-activation-bpf-lsm](../../crates/activation/aos-activation-bpf-lsm/Cargo.toml) | Checked Linux realization of package-selected BPF-LSM policy resources |
| `aos-activation-bpf-network` | [activation/aos-activation-bpf-network](../../crates/activation/aos-activation-bpf-network/Cargo.toml) | Checked Linux realization of package-selected BPF network policy resources |
| `aos-activation-config-files` | [activation/aos-activation-config-files](../../crates/activation/aos-activation-config-files/Cargo.toml) | Reconciles portable configuration files through durable ownership receipts |
| `aos-activation-crucible` | [activation/aos-activation-crucible](../../crates/activation/aos-activation-crucible/Cargo.toml) | Crucible instrumentation adapters for activation execution |
| `aos-activation-filesystem` | [activation/aos-activation-filesystem](../../crates/activation/aos-activation-filesystem/Cargo.toml) | Validated storage allocation and filesystem views for activation |
| `aos-activation-kubernetes` | [activation/aos-activation-kubernetes](../../crates/activation/aos-activation-kubernetes/Cargo.toml) | Native module handlers for K3s configuration and Kubernetes object sets |
| `aos-activation-nftables` | [activation/aos-activation-nftables](../../crates/activation/aos-activation-nftables/Cargo.toml) | Native reconciliation of the host firewall through one owned nftables table |
| `aos-activation-nix-store` | [activation/aos-activation-nix-store](../../crates/activation/aos-activation-nix-store/Cargo.toml) | Package-owned Nix store configuration and activation |
| `aos-activation-storage` | [activation/aos-activation-storage](../../crates/activation/aos-activation-storage/Cargo.toml) | Validated block-storage operations for activation |
| `aos-activation-sysctl` | [activation/aos-activation-sysctl](../../crates/activation/aos-activation-sysctl/Cargo.toml) | Native Linux kernel-tunable operations with durable baseline restoration |
| `aos-activation-systemd` | [activation/aos-activation-systemd](../../crates/activation/aos-activation-systemd/Cargo.toml) | Systemd service, identity, listener, watchdog, and credential activation handlers |
| `aos-artifact-evidence` | [artifacts/aos-artifact-evidence](../../crates/artifacts/aos-artifact-evidence/Cargo.toml) | Portable immutable artifact identities and checked consumption evidence |
| `aos-nar` | [artifacts/aos-nar](../../crates/artifacts/aos-nar/Cargo.toml) | Nix archive formats, binary-cache metadata, and content signing |
| `aos-oci` | [artifacts/aos-oci](../../crates/artifacts/aos-oci/Cargo.toml) | Verified OCI layout, archive, and Distribution operations for AOS |
| `aos-oci-types` | [artifacts/aos-oci-types](../../crates/artifacts/aos-oci-types/Cargo.toml) | Wasm-friendly OCI image and Distribution contracts for AOS |
| `libssh2-sys` | [bindings/libssh2-sys](../../crates/bindings/libssh2-sys/Cargo.toml) | Native bindings to the AOS-built libssh2 package (`MIT OR Apache-2.0`) |
| `aos-boot-identity` | [boot/aos-boot-identity](../../crates/boot/aos-boot-identity/Cargo.toml) | Normal and recovery boot identity parsing and UKI inspection |
| `aos-boot-runtime` | [boot/aos-boot-runtime](../../crates/boot/aos-boot-runtime/Cargo.toml) | Retained boot preparation, image staging, boot selection, and initrd store operations |
| `aos-configuration-image` | [boot/aos-configuration-image](../../crates/boot/aos-configuration-image/Cargo.toml) | Deterministic configuration images, verified boot mounting, and certificate bundles |
| `aos-platform-metadata` | [boot/aos-platform-metadata](../../crates/boot/aos-platform-metadata/Cargo.toml) | Platform facts acquisition, configuration authorization, and first-boot network values |
| `aos-recovery` | [boot/aos-recovery](../../crates/boot/aos-recovery/Cargo.toml) | Recovery boot validation and emergency recovery runtime |
| `aos-storage-layout` | [boot/aos-storage-layout](../../crates/boot/aos-storage-layout/Cargo.toml) | Validated storage provisioning intent, block topology, and canonical layout values |
| `aos-cli` | [cli/aos-cli](../../crates/cli/aos-cli/Cargo.toml) | The `aos`, `apm`, and `apr` programs and related installed helper executables |
| `aos-cli-ui` | [cli/aos-cli-ui](../../crates/cli/aos-cli-ui/Cargo.toml) | Terminal presentation, structured results, progress, and command hints |
| `aos-closure-analysis` | [cli/aos-closure-analysis](../../crates/cli/aos-closure-analysis/Cargo.toml) | Image and closure profiler for AOS production artifacts |
| `aos-nix-docs` | [cli/aos-nix-docs](../../crates/cli/aos-nix-docs/Cargo.toml) | Nix package and module documentation discovery and browsing |
| `aos-core` | [core/aos-core](../../crates/core/aos-core/Cargo.toml) | Portable strict JSON, content identities, decoding limits, and scoped names |
| `crucible-campaign` | [crucible/crucible-campaign](../../crates/crucible/crucible-campaign/Cargo.toml) | Canonical campaign identities, facts, planning state, and component contracts |
| `crucible-cli` | [crucible/crucible-cli](../../crates/crucible/crucible-cli/Cargo.toml) | The `crucible` program: command parsing and presentation for the control plane |
| `crucible-control-api` | [crucible/crucible-control-api](../../crates/crucible/crucible-control-api/Cargo.toml) | Native transport-independent control contracts and canonical codecs |
| `crucible-control-client` | [crucible/crucible-control-client](../../crates/crucible/crucible-control-client/Cargo.toml) | HTTP/2 RPC clients and typed transport interfaces |
| `crucible-control-server` | [crucible/crucible-control-server](../../crates/crucible/crucible-control-server/Cargo.toml) | Lifecycle dispatch, actor adapters, and authenticated HTTP/2 servers |
| `crucible-daemon` | [crucible/crucible-daemon](../../crates/crucible/crucible-daemon/Cargo.toml) | Host process, VM lifecycle, campaigns, and interactive replay coordination |
| `crucible-determinism` | [crucible/crucible-determinism](../../crates/crucible/crucible-determinism/Cargo.toml) | Deterministic clock, scheduling, decisions, and reproducibility primitives |
| `crucible-device` | [crucible/crucible-device](../../crates/crucible/crucible-device/Cargo.toml) | Deterministic device and I/O sub-node models |
| `crucible-engine` | [crucible/crucible-engine](../../crates/crucible/crucible-engine/Cargo.toml) | Execution graphs, checkpoints, replay, and deterministic engine state |
| `crucible-guest` | [crucible/crucible-guest](../../crates/crucible/crucible-guest/Cargo.toml) | Optional guest observation and assertion instrumentation |
| `crucible-qemu-debug-gateway` | [crucible/crucible-qemu-debug-gateway](../../crates/crucible/crucible-qemu-debug-gateway/Cargo.toml) | Separate debugger process using QEMU private interfaces (`GPL-2.0-only`) |
| `crucible-qemu-host` | [crucible/crucible-qemu-host](../../crates/crucible/crucible-qemu-host/Cargo.toml) | Host-side QEMU launch, control, and observation integration |
| `crucible-qemu-plugin` | [crucible/crucible-qemu-plugin](../../crates/crucible/crucible-qemu-plugin/Cargo.toml) | QEMU instrumentation plugin and boundary publication (`GPL-2.0-only`) |
| `crucible-qemu-protocol` | [crucible/crucible-qemu-protocol](../../crates/crucible/crucible-qemu-protocol/Cargo.toml) | Versioned control messages across the QEMU process boundary (`MIT OR Apache-2.0`) |
| `crucible-qemu-shmem` | [crucible/crucible-qemu-shmem](../../crates/crucible/crucible-qemu-shmem/Cargo.toml) | Shared-memory layouts, checked offsets, and observation transport (`MIT OR Apache-2.0`) |
| `crucible-session` | [crucible/crucible-session](../../crates/crucible/crucible-session/Cargo.toml) | Live session actor and deterministic execution dispatch |
| `crucible-store` | [crucible/crucible-store](../../crates/crucible/crucible-store/Cargo.toml) | Content-addressed storage primitives |
| `crucible-store-s3` | [crucible/crucible-store-s3](../../crates/crucible/crucible-store-s3/Cargo.toml) | AWS SDK transport for the S3-compatible immutable-store leaf |
| `crucible-test-support` | [crucible/crucible-test-support](../../crates/crucible/crucible-test-support/Cargo.toml) | Cross-crate test infrastructure, gate vocabulary, and architecture checks |
| `aos-hub-api` | [hub/aos-hub-api](../../crates/hub/aos-hub-api/Cargo.toml) | Portable Hub API messages, ProtoJSON codecs, and Connect descriptors |
| `aos-hub-client` | [hub/aos-hub-client](../../crates/hub/aos-hub-client/Cargo.toml) | Typed Hub Connect-JSON client and OAuth login flows |
| `aos-hub-console` | [hub/aos-hub-console](../../crates/hub/aos-hub-console/Cargo.toml) | Typed Leptos management application for the Hub control plane |
| `aos-hub-db` | [hub/aos-hub-db](../../crates/hub/aos-hub-db/Cargo.toml) | Hub migrations, persistence queries, and portable SQL backend abstractions |
| `aos-hub-model` | [hub/aos-hub-model](../../crates/hub/aos-hub-model/Cargo.toml) | Portable Hub domain values, credential primitives, and delivery policies |
| `aos-hub-native` | [hub/aos-hub-native](../../crates/hub/aos-hub-native/Cargo.toml) | The `aos-hub` executable with native HTTP, database, and storage adapters |
| `aos-hub-service` | [hub/aos-hub-service](../../crates/hub/aos-hub-service/Cargo.toml) | Runtime-neutral Hub application services, authorization, and transport adapters |
| `aos-hub-ui` | [hub/aos-hub-ui](../../crates/hub/aos-hub-ui/Cargo.toml) | Shared Hub navigation, routes, and presentation values |
| `aos-hub-worker` | [hub/aos-hub-worker](../../crates/hub/aos-hub-worker/Cargo.toml) | Cloudflare Worker deployment with SQLite and R2 adapters |
| `aos-linux-project-quota` | [linux/aos-linux-project-quota](../../crates/linux/aos-linux-project-quota/Cargo.toml) | Pinned ext4 project-quota installation, verification, and release |
| `aos-systemd-client` | [linux/aos-systemd-client](../../crates/linux/aos-systemd-client/Cargo.toml) | Typed asynchronous client for the systemd D-Bus interface |
| `aos-module-docs` | [modules/aos-module-docs](../../crates/modules/aos-module-docs/Cargo.toml) | Native module documentation, search, comparison, and safe renderers |
| `aos-module-format` | [modules/aos-module-format](../../crates/modules/aos-module-format/Cargo.toml) | Portable module options, declarations, and checked activation graphs |
| `aos-nix` | [nix/aos-nix](../../crates/nix/aos-nix/Cargo.toml) | Nix process integration, derivation parsing, and store-tool validation |
| `aos-build-api` | [packages/aos-build-api](../../crates/packages/aos-build-api/Cargo.toml) | Generated build, cache, authentication, and garbage-collection API contracts |
| `aos-build-client` | [packages/aos-build-client](../../crates/packages/aos-build-client/Cargo.toml) | Typed client for the build server, Nix cache, garbage collection, and authentication |
| `aos-build-server` | [packages/aos-build-server](../../crates/packages/aos-build-server/Cargo.toml) | Build and binary cache server |
| `aos-deployment` | [packages/aos-deployment](../../crates/packages/aos-deployment/Cargo.toml) | Authenticated module evaluation, store retention, and journaled activation |
| `aos-deployment-format` | [packages/aos-deployment-format](../../crates/packages/aos-deployment-format/Cargo.toml) | Portable deployment envelopes, resolution locks, and admission documents |
| `aos-nix-cache` | [packages/aos-nix-cache](../../crates/packages/aos-nix-cache/Cargo.toml) | Native Nix binary-cache queries, acquisition, and upload |
| `aos-package-manager` | [packages/aos-package-manager](../../crates/packages/aos-package-manager/Cargo.toml) | Package installation, profiles, native admission, and APM/APR adapters |
| `aos-registry-authoring` | [registry/aos-registry-authoring](../../crates/registry/aos-registry-authoring/Cargo.toml) | Registry authoring, signed release transactions, staging, and static publication |
| `aos-registry-client` | [registry/aos-registry-client](../../crates/registry/aos-registry-client/Cargo.toml) | Native registry acquisition, verified catalog reads, trust pins, and provenance verification |
| `aos-registry-format` | [registry/aos-registry-format](../../crates/registry/aos-registry-format/Cargo.toml) | Portable, I/O-free registry contracts, Git object formats, and signature verification |
| `aos-registry-web` | [registry/aos-registry-web](../../crates/registry/aos-registry-web/Cargo.toml) | Browser registry navigation and verification of published static surfaces |
| `aos-image-finalizer` | [release/aos-image-finalizer](../../crates/release/aos-image-finalizer/Cargo.toml) | External final-byte assembly and verification for release images |
| `aos-package-maintenance` | [release/aos-package-maintenance](../../crates/release/aos-package-maintenance/Cargo.toml) | Pure contracts and policy for local package maintenance |
| `aos-release-coordinator` | [release/aos-release-coordinator](../../crates/release/aos-release-coordinator/Cargo.toml) | Verified publication preparation, durable release journals, and external signing coordination |
| `aos-release-format` | [release/aos-release-format](../../crates/release/aos-release-format/Cargo.toml) | Pure release contracts and offline verification for canonical publication |
| `aos-release-signer` | [release/aos-release-signer](../../crates/release/aos-release-signer/Cargo.toml) | File-backed signing process for the release signer-exchange protocol |
| `aos-transfer` | [transfer/aos-transfer](../../crates/transfer/aos-transfer/Cargo.toml) | Reusable HTTP, streaming transfer, and transport utilities |
