# Active Rust crate inventory

The workspace contains 80 Cargo packages, grouped by ownership. The full package
name carries scope. Filesystem groups reduce the directory listing and do not
change dependency identity. The authoritative membership is
[`crates/Cargo.toml`](../../crates/Cargo.toml); the
[workspace design](crate-workspace.md) explains extraction and naming rules.

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
| `aos-activation-systemd` | [activation/aos-activation-systemd](../../crates/activation/aos-activation-systemd/Cargo.toml) | Durable systemd unit installation and service activation |
| `aos-boot-identity` | [boot/aos-boot-identity](../../crates/boot/aos-boot-identity/Cargo.toml) | Parses and validates the AOS security-relevant kernel command line |
| `aos-boot-runtime` | [boot/aos-boot-runtime](../../crates/boot/aos-boot-runtime/Cargo.toml) | Retained boot preparation, image staging, boot selection, and initrd store operations |
| `aos-configuration-image` | [boot/aos-configuration-image](../../crates/boot/aos-configuration-image/Cargo.toml) | Owns native OS configuration lower images and their verified boot mounting |
| `aos-platform-metadata` | [boot/aos-platform-metadata](../../crates/boot/aos-platform-metadata/Cargo.toml) | Host and instance metadata, bootstrap networking, and metadata executables |
| `aos-recovery` | [boot/aos-recovery](../../crates/boot/aos-recovery/Cargo.toml) | Implements the bounded local interface for the AOS recovery initrd |
| `aos-storage-layout` | [boot/aos-storage-layout](../../crates/boot/aos-storage-layout/Cargo.toml) | Portable validation and canonicalization of evaluated storage layouts |
| `aos-cli` | [cli/aos-cli](../../crates/cli/aos-cli/Cargo.toml) | Shared implementation for the AOS command-line programs |
| `aos-cli-ui` | [cli/aos-cli-ui](../../crates/cli/aos-cli-ui/Cargo.toml) | Terminal presentation, structured results, progress, and command hints |
| `aos-closure-analysis` | [cli/aos-closure-analysis](../../crates/cli/aos-closure-analysis/Cargo.toml) | Image and closure profiler for AOS production artifacts |
| `aos-nix-docs` | [cli/aos-nix-docs](../../crates/cli/aos-nix-docs/Cargo.toml) | Nix package and module documentation discovery and browsing |
| `aos-module-docs` | [modules/aos-module-docs](../../crates/modules/aos-module-docs/Cargo.toml) | Native AOS module documentation, search, comparison, and safe renderers |
| `aos-module-format` | [modules/aos-module-format](../../crates/modules/aos-module-format/Cargo.toml) | Portable module options, declarations, and checked activation graphs |
| `aos-build-api` | [packages/aos-build-api](../../crates/packages/aos-build-api/Cargo.toml) | Generated build, cache, authentication, and garbage-collection API contracts |
| `aos-build-client` | [packages/aos-build-client](../../crates/packages/aos-build-client/Cargo.toml) | Typed client for AOS build server, Nix cache, garbage collection, and authentication |
| `aos-build-server` | [packages/aos-build-server](../../crates/packages/aos-build-server/Cargo.toml) | The AOS build and binary cache server |
| `aos-deployment` | [packages/aos-deployment](../../crates/packages/aos-deployment/Cargo.toml) | Authenticated AOS module evaluation, store retention, and journaled activation |
| `aos-deployment-format` | [packages/aos-deployment-format](../../crates/packages/aos-deployment-format/Cargo.toml) | Portable AOS deployment envelopes, resolution locks, and admission documents |
| `aos-nix-cache` | [packages/aos-nix-cache](../../crates/packages/aos-nix-cache/Cargo.toml) | Native Nix binary-cache queries, acquisition, and upload |
| `aos-package-manager` | [packages/aos-package-manager](../../crates/packages/aos-package-manager/Cargo.toml) | Package installation, profiles, native admission, and APM/APR adapters |
| `aos-registry-authoring` | [registry/aos-registry-authoring](../../crates/registry/aos-registry-authoring/Cargo.toml) | Native AOS registry authoring, signing, release staging, and publication |
| `aos-registry-client` | [registry/aos-registry-client](../../crates/registry/aos-registry-client/Cargo.toml) | Native acquisition and verified consumption of AOS package registries |
| `aos-registry-format` | [registry/aos-registry-format](../../crates/registry/aos-registry-format/Cargo.toml) | Portable registry contracts, Git object formats, and signature verification |
| `aos-registry-web` | [registry/aos-registry-web](../../crates/registry/aos-registry-web/Cargo.toml) | Browser registry navigation and verification of published static surfaces |
| `aos-image-finalizer` | [release/aos-image-finalizer](../../crates/release/aos-image-finalizer/Cargo.toml) | External final-byte assembly and verification for AOS release images |
| `aos-package-maintenance` | [release/aos-package-maintenance](../../crates/release/aos-package-maintenance/Cargo.toml) | Pure contracts and policy for local AOS package maintenance |
| `aos-release-coordinator` | [release/aos-release-coordinator](../../crates/release/aos-release-coordinator/Cargo.toml) | Verified publication preparation, durable release journals, and external signing coordination |
| `aos-release-format` | [release/aos-release-format](../../crates/release/aos-release-format/Cargo.toml) | Pure release contracts and offline verification for canonical AOS publication |
| `aos-release-signer` | [release/aos-release-signer](../../crates/release/aos-release-signer/Cargo.toml) | File-backed signing process for the release signer-exchange protocol |
| `crucible-cli` | [crucible/crucible-cli](../../crates/crucible/crucible-cli/Cargo.toml) | Command parsing and presentation for the Crucible control plane |
| `crucible-control-api` | [crucible/crucible-control-api](../../crates/crucible/crucible-control-api/Cargo.toml) | Native transport-independent control messages, canonical codecs, and compatibility contracts |
| `crucible-control-client` | [crucible/crucible-control-client](../../crates/crucible/crucible-control-client/Cargo.toml) | Crucible HTTP/2 RPC clients and typed transport interfaces |
| `crucible-control-server` | [crucible/crucible-control-server](../../crates/crucible/crucible-control-server/Cargo.toml) | Crucible lifecycle dispatch, actor adapters, and authenticated HTTP/2 servers |
| `crucible-daemon` | [crucible/crucible-daemon](../../crates/crucible/crucible-daemon/Cargo.toml) | Host process, VM lifecycle, campaigns, and interactive replay coordination |
| `crucible-session` | [crucible/crucible-session](../../crates/crucible/crucible-session/Cargo.toml) | Live session actor and deterministic execution dispatch |
| `crucible-campaign` | [crucible/crucible-campaign](../../crates/crucible/crucible-campaign/Cargo.toml) | Canonical campaign identities, facts, planning state, and component contracts |
| `crucible-determinism` | [crucible/crucible-determinism](../../crates/crucible/crucible-determinism/Cargo.toml) | Deterministic clock, scheduling, decisions, and reproducibility primitives |
| `crucible-device` | [crucible/crucible-device](../../crates/crucible/crucible-device/Cargo.toml) | Deterministic device and I/O sub-node models |
| `crucible-engine` | [crucible/crucible-engine](../../crates/crucible/crucible-engine/Cargo.toml) | Execution graphs, checkpoints, replay, and deterministic engine state |
| `crucible-guest` | [crucible/crucible-guest](../../crates/crucible/crucible-guest/Cargo.toml) | Optional guest observation and assertion instrumentation |
| `crucible-host-resources` | [crucible/crucible-host-resources](../../crates/crucible/crucible-host-resources/Cargo.toml) | Original Linux descriptor read leases and isolated notification custody |
| `crucible-node-format` | [crucible/crucible-node-format](../../crates/crucible/crucible-node-format/Cargo.toml) | Portable CNP data, strict JSON, canonical identities, and validation |
| `crucible-node-transport` | [crucible/crucible-node-transport](../../crates/crucible/crucible-node-transport/Cargo.toml) | Bounded host process transport, request custody, and reference-provider tools |
| `crucible-qemu-protocol` | [crucible/crucible-qemu-protocol](../../crates/crucible/crucible-qemu-protocol/Cargo.toml) | Permissive versioned control messages across the QEMU process boundary |
| `crucible-qemu-shmem` | [crucible/crucible-qemu-shmem](../../crates/crucible/crucible-qemu-shmem/Cargo.toml) | Permissive shared-memory layouts, checked offsets, and observation transport |
| `crucible-qemu-debug-gateway` | [crucible/crucible-qemu-debug-gateway](../../crates/crucible/crucible-qemu-debug-gateway/Cargo.toml) | Separate GPL debugger process using QEMU private interfaces |
| `crucible-qemu-host` | [crucible/crucible-qemu-host](../../crates/crucible/crucible-qemu-host/Cargo.toml) | Apache host-side QEMU launch, control, and observation integration |
| `crucible-qemu-plugin` | [crucible/crucible-qemu-plugin](../../crates/crucible/crucible-qemu-plugin/Cargo.toml) | GPL QEMU instrumentation plugin and boundary publication |
| `crucible-store` | [crucible/crucible-store](../../crates/crucible/crucible-store/Cargo.toml) | Content-addressed storage primitives for Crucible |
| `crucible-store-s3` | [crucible/crucible-store-s3](../../crates/crucible/crucible-store-s3/Cargo.toml) | AWS SDK transport for Crucible's S3-compatible immutable-store leaf |
| `crucible-test-support` | [crucible/crucible-test-support](../../crates/crucible/crucible-test-support/Cargo.toml) | Cross-crate test infrastructure, gate vocabulary, and architecture checks |
| `aos-hub-api` | [hub/aos-hub-api](../../crates/hub/aos-hub-api/Cargo.toml) | Portable Hub API messages, ProtoJSON codecs, and Connect descriptors |
| `aos-hub-client` | [hub/aos-hub-client](../../crates/hub/aos-hub-client/Cargo.toml) | Typed Hub Connect-JSON client and OAuth login flows |
| `aos-hub-console` | [hub/aos-hub-console](../../crates/hub/aos-hub-console/Cargo.toml) | Typed Leptos management application for the AOS Hub control plane |
| `aos-hub-db` | [hub/aos-hub-db](../../crates/hub/aos-hub-db/Cargo.toml) | Hub migrations, persistence queries, and portable SQL backend abstractions |
| `aos-hub-model` | [hub/aos-hub-model](../../crates/hub/aos-hub-model/Cargo.toml) | Portable Hub domain values, credential primitives, and delivery policies |
| `aos-hub-native` | [hub/aos-hub-native](../../crates/hub/aos-hub-native/Cargo.toml) | Native Hub deployment with HTTP, database, and storage adapters |
| `aos-hub-service` | [hub/aos-hub-service](../../crates/hub/aos-hub-service/Cargo.toml) | Runtime-neutral Hub application services, authorization, and transport adapters |
| `aos-hub-ui` | [hub/aos-hub-ui](../../crates/hub/aos-hub-ui/Cargo.toml) | Shared Hub navigation, routes, and presentation values |
| `aos-hub-worker` | [hub/aos-hub-worker](../../crates/hub/aos-hub-worker/Cargo.toml) | Cloudflare Worker deployment with SQLite and R2 adapters |
| `aos-artifact-evidence` | [artifacts/aos-artifact-evidence](../../crates/artifacts/aos-artifact-evidence/Cargo.toml) | Portable immutable artifact identities and checked consumption evidence |
| `aos-core` | [core/aos-core](../../crates/core/aos-core/Cargo.toml) | Portable strict JSON, content identities, decoding limits, and scoped names |
| `aos-linux-project-quota` | [linux/aos-linux-project-quota](../../crates/linux/aos-linux-project-quota/Cargo.toml) | Pinned ext4 project-quota installation, verification, and release |
| `aos-nar` | [artifacts/aos-nar](../../crates/artifacts/aos-nar/Cargo.toml) | Nix archive formats, binary-cache metadata, and content signing |
| `aos-nix` | [nix/aos-nix](../../crates/nix/aos-nix/Cargo.toml) | Nix process integration, derivation parsing, and store-tool validation |
| `aos-oci` | [artifacts/aos-oci](../../crates/artifacts/aos-oci/Cargo.toml) | Verified OCI layout, archive, and Distribution operations for AOS |
| `aos-oci-types` | [artifacts/aos-oci-types](../../crates/artifacts/aos-oci-types/Cargo.toml) | Wasm-friendly OCI image and Distribution contracts for AOS |
| `aos-systemd-client` | [linux/aos-systemd-client](../../crates/linux/aos-systemd-client/Cargo.toml) | Typed asynchronous client for the systemd D-Bus interface |
| `aos-transfer` | [transfer/aos-transfer](../../crates/transfer/aos-transfer/Cargo.toml) | Reusable HTTP, streaming transfer, and transport utilities |

The initrd preparation artifact is compiled directly by its Nix recipe from
`boot/aos-boot-runtime/standalone/initrd_preparation.rs`. It deliberately is
not a Cargo target: its existing `env!` tool paths bind the exact production
closure during compilation. The owning boot runtime README documents this
exception; its installed name remains `aos-boot-preparations`.

For a complete old-name → current-owner mapping, including packages whose names
stay the same, see the [rename reference](crate-renames.md).

## Merges and extractions

- `aos-contract` is merged into the portable `aos_core::{json,digest,limits}`.
  `aos_core::identity` owns generic bounded names. NAR codecs and signing are in
  `aos-nar`; Nix process/store integration is in `aos-nix`; terminal presentation
  is in `aos-cli-ui`; command error classification remains in `aos-cli`.
- `aos-ability-plan` is folded into `aos_module_format::graph`. Artifact evidence
  lives in `aos-artifact-evidence`, independently of module activation. The old
  artifact readers from `aos-doc-model` moved with the evidence formats.
- `aos-package` separates package installation in `aos-package-manager`, registry
  reading in `aos-registry-client`, registry authoring in `aos-registry-authoring`,
  portable deployment documents and inventory in `aos-deployment-format`, and
  deployment evaluation/activation in `aos-deployment`. Registry acquisition
  reports through neutral `aos_transfer::progress` observers; the package manager
  owns update command orchestration. Private-key loading, key generation, and
  external provenance signing belong to authoring; common DSSE framing remains
  in the portable registry format. Image finalization uses
  immutable inventory data without depending on package-manager installation.
- `aos-remote` separates build RPC in `aos-build-client` and Hub access in
  `aos-hub-client`. Canonical protocol sources live under `api/proto/`; generated
  build and Hub APIs remain separate packages.
- `aos-hub-core` separates domain policy in `aos-hub-model`, persistence in
  `aos-hub-db`, and service orchestration in `aos-hub-service`. Native SQL drivers
  belong to the DB crate and remain excluded from WebAssembly deployments.
- `aos-metadata-provider` wrappers are folded into `aos-platform-metadata`.
  Boot execution formerly in the systemd handler and boot preparation crate is
  in `aos-boot-runtime`. Pure release verification is `aos-release-format`;
  reusable publication preparation and verification is `aos-release-coordinator`.
- `crucible-node-contract` is now `crucible-node-format`, and
  `crucible-node-provider` is now `crucible-node-transport`. The latter keeps its
  host transport and reference-provider tools; executable and wire identities
  retain their established names.
- `crucible-host-resources` owns the first implemented host-resource capability:
  original Linux descriptor read leases shared by engine and daemon. Quotas stay
  in `aos-linux-project-quota`; future RAM, budget and supervision capabilities
  from #696 are not implemented by this extraction.
- `crucible-assert` gate vocabulary is folded into `crucible-test-support`.
  `crucible-control-api` owns message/codecs/compatibility contracts,
  `crucible-control-client` owns client transport, and `crucible-control-server`
  owns server integration. Production VM lifecycle belongs to `crucible-daemon`.

The control API is independently consumable by native clients and services, but
it retains session and engine dependencies and is not a WebAssembly format
library. Live event-log hub and stream adapters belong to the control server.
Extracting a smaller platform-independent session model would require a separate
review of its command and debugger contracts.

The [mechanical migration map](../../tools/dev/crate-migration.json) records the
original 67-package move. Its five temporary merge entries are historical inputs,
not current workspace members. Executable names, wire identities, signatures,
and persisted digest domains retain their established spelling.

## Implementation status

An unused Rust dependency is distinct from an unused package: installed
executables, Nix builds, tests, and optional platform targets are consumers too.
The merged crates above lost their package boundaries because their actual
implementations fit existing owners. Extracted crates own real implementations;
they do not retain application-backed compatibility facades.

Hub's retained-control foundation remains dormant, with its portable values and
fixtures under `aos-hub-model`. It is not enabled by this restructuring. The
uncalled internal `container_distribution_origin` service helper is retained
pending a behavior review. Proposed and scaffolded packages on unmerged branches
are identified separately in the [open-PR inventory](unmerged-crates.md); their
classification does not claim those features are complete.
