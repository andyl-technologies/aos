# Crate rename and extraction reference

This reference maps every package in the former flat 67-package workspace to its
implemented owner in the current 80-package workspace. Cargo package names carry
scope; subdirectories group related code for readers. The [workspace design](crate-workspace.md)
explains naming and dependency direction, and the [active inventory](crate-inventory.md)
lists every current package and directory.

**The meaning of `aos-core` changes.** Its former NAR, Nix-process, and terminal
utilities now belong to `aos-nar`, `aos-nix`, and `aos-cli-ui`. The current
`crates/core/aos-core` contains portable strict JSON, digests, decoding limits,
and scoped identities, including the former `aos-contract` implementation.
There is no `aos-canonical-data` package. Consumers must select the capability
they use rather than treating the surviving `aos-core` name as a compatibility
facade for its old API.

## Former package to current owner

Each former package occurs once below. Multiple destinations describe a split;
a destination shared by multiple rows describes a merge. Unchanged names still
move into the owning directory group. Links point to current manifests.

### Shared libraries

| Former package | Current package(s) | Change |
|---|---|---|
| `aos-contract` | [`aos-core`](../../crates/core/aos-core/Cargo.toml) | Merged into `json`, `digest`, and `limits`; scoped names live in `identity`. |
| `aos-core` | [`aos-nar`](../../crates/artifacts/aos-nar/Cargo.toml), [`aos-nix`](../../crates/nix/aos-nix/Cargo.toml), [`aos-cli-ui`](../../crates/cli/aos-cli-ui/Cargo.toml), [`aos-cli`](../../crates/cli/aos-cli/Cargo.toml) | Former native utilities are split by capability; command error classification belongs to the CLI. The current portable `aos-core` has a narrower purpose. |
| `aos-net` | [`aos-transfer`](../../crates/transfer/aos-transfer/Cargo.toml) | Names the reusable transfer capability; neutral progress observers do not require terminal presentation. |
| `aos-systemd` | [`aos-systemd-client`](../../crates/linux/aos-systemd-client/Cargo.toml) | Identifies a systemd D-Bus client, distinct from activation policy. |
| `aos-oci` | [`aos-oci`](../../crates/artifacts/aos-oci/Cargo.toml) | Package name retained; source moves under its owner. |
| `aos-oci-types` | [`aos-oci-types`](../../crates/artifacts/aos-oci-types/Cargo.toml) | Package name retained; source moves under its owner. |
| `crucible-linux-resource` | [`aos-linux-project-quota`](../../crates/linux/aos-linux-project-quota/Cargo.toml), [`crucible-host-resources`](../../crates/crucible/crucible-host-resources/Cargo.toml) | Quota mechanics are reusable; original descriptor read leases and notification custody retain Crucible ownership. |

### AOS applications and subsystems

| Former package | Current package(s) | Change |
|---|---|---|
| `aos` | [`aos-cli`](../../crates/cli/aos-cli/Cargo.toml) | Names the CLI implementation; installed commands keep their names. |
| `aos-profile` | [`aos-closure-analysis`](../../crates/cli/aos-closure-analysis/Cargo.toml) | Names closure and image analysis rather than a generic profile concept. |
| `aos-doc` | [`aos-nix-docs`](../../crates/cli/aos-nix-docs/Cargo.toml) | Names Nix documentation discovery, distinct from module documentation. |
| `aos-ability-model` | [`aos-module-format`](../../crates/modules/aos-module-format/Cargo.toml), [`aos-artifact-evidence`](../../crates/artifacts/aos-artifact-evidence/Cargo.toml) | Module declarations and checked graphs stay together; reusable artifact evidence is extracted. |
| `aos-ability-plan` | [`aos-module-format`](../../crates/modules/aos-module-format/Cargo.toml) | Merged into `graph`; no separate planning package remains. |
| `aos-doc-model` | [`aos-module-docs`](../../crates/modules/aos-module-docs/Cargo.toml), [`aos-artifact-evidence`](../../crates/artifacts/aos-artifact-evidence/Cargo.toml) | Module documentation is distinct from the artifact formats and readers it consumes. |
| `aos-ability-runtime` | [`aos-activation`](../../crates/activation/aos-activation/Cargo.toml) | Names durable activation of native module operation graphs. |
| `aos-ability-crucible` | [`aos-activation-crucible`](../../crates/activation/aos-activation-crucible/Cargo.toml) | Names Crucible instrumentation for activation. |
| `aos-configuration-provider` | [`aos-activation-config-files`](../../crates/activation/aos-activation-config-files/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-filesystem-provider` | [`aos-activation-filesystem`](../../crates/activation/aos-activation-filesystem/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-kubernetes-provider` | [`aos-activation-kubernetes`](../../crates/activation/aos-activation-kubernetes/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-kernel-tunable-provider` | [`aos-activation-sysctl`](../../crates/activation/aos-activation-sysctl/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-network-ruleset-provider` | [`aos-activation-nftables`](../../crates/activation/aos-activation-nftables/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-ebpf-lsm-provider` | [`aos-activation-bpf-lsm`](../../crates/activation/aos-activation-bpf-lsm/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-ebpf-net-policy-provider` | [`aos-activation-bpf-network`](../../crates/activation/aos-activation-bpf-network/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-nix-store-provider` | [`aos-activation-nix-store`](../../crates/activation/aos-activation-nix-store/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-block-storage-provider` | [`aos-activation-storage`](../../crates/activation/aos-activation-storage/Cargo.toml) | Names the activation subsystem and concrete operation handler. |
| `aos-systemd-provider` | [`aos-activation-systemd`](../../crates/activation/aos-activation-systemd/Cargo.toml), [`aos-boot-runtime`](../../crates/boot/aos-boot-runtime/Cargo.toml) | Systemd activation stays in its handler; retained boot operations move to the boot runtime. |
| `aos-package` | [`aos-package-manager`](../../crates/packages/aos-package-manager/Cargo.toml), [`aos-registry-client`](../../crates/registry/aos-registry-client/Cargo.toml), [`aos-registry-authoring`](../../crates/registry/aos-registry-authoring/Cargo.toml), [`aos-deployment-format`](../../crates/packages/aos-deployment-format/Cargo.toml), [`aos-deployment`](../../crates/packages/aos-deployment/Cargo.toml), [`aos-release-coordinator`](../../crates/release/aos-release-coordinator/Cargo.toml) | Installation, registry reading/writing, deployment data/effects, and release coordination have separate owners. |
| `aos-cache` | [`aos-nix-cache`](../../crates/packages/aos-nix-cache/Cargo.toml) | Names the Nix binary-cache capability. |
| `aos-server` | [`aos-build-server`](../../crates/packages/aos-build-server/Cargo.toml) | Scopes the server to build and binary-cache services. |
| `aos-proto` | [`aos-build-api`](../../crates/packages/aos-build-api/Cargo.toml) | Scopes generated contracts to build/cache/authentication/GC APIs. |
| `aos-remote` | [`aos-build-client`](../../crates/packages/aos-build-client/Cargo.toml), [`aos-hub-client`](../../crates/hub/aos-hub-client/Cargo.toml) | Build-server RPC and Hub access are separate clients. |
| `aos-registry-surface` | [`aos-registry-format`](../../crates/registry/aos-registry-format/Cargo.toml) | Identifies portable registry data formats and verification. |
| `aos-registry-spa` | [`aos-registry-web`](../../crates/registry/aos-registry-web/Cargo.toml) | Identifies the browser registry application. |
| `aos-boot-preparation-provider` | [`aos-boot-runtime`](../../crates/boot/aos-boot-runtime/Cargo.toml) | Preparation merges with the boot runtime; the initrd artifact remains a direct Nix compilation. |
| `aos-metadata` | [`aos-platform-metadata`](../../crates/boot/aos-platform-metadata/Cargo.toml) | Names host/platform metadata rather than arbitrary metadata. |
| `aos-metadata-provider` | [`aos-platform-metadata`](../../crates/boot/aos-platform-metadata/Cargo.toml) | Metadata wrappers merge into the implementation they wrap. |
| `aos-storage-provisioning` | [`aos-storage-layout`](../../crates/boot/aos-storage-layout/Cargo.toml) | Names portable evaluated storage-layout validation. |
| `aos-configuration-lower` | [`aos-configuration-image`](../../crates/boot/aos-configuration-image/Cargo.toml) | Names configuration lower-image construction and mounting. |
| `aos-boot-identity` | [`aos-boot-identity`](../../crates/boot/aos-boot-identity/Cargo.toml) | Package name retained; source moves under its owner. |
| `aos-recovery` | [`aos-recovery`](../../crates/boot/aos-recovery/Cargo.toml) | Package name retained; source moves under its owner. |
| `aos-maintain` | [`aos-package-maintenance`](../../crates/release/aos-package-maintenance/Cargo.toml) | Scopes maintenance contracts to AOS packages. |
| `aos-release` | [`aos-release-format`](../../crates/release/aos-release-format/Cargo.toml) | Identifies pure release contracts and verification. |
| `aos-release-signer` | [`aos-release-signer`](../../crates/release/aos-release-signer/Cargo.toml) | Package name retained; source moves under its owner. |
| `aos-image-finalizer` | [`aos-image-finalizer`](../../crates/release/aos-image-finalizer/Cargo.toml) | Package name retained; source moves under its owner. |

### Hub

| Former package | Current package(s) | Change |
|---|---|---|
| `aos-hub` | [`aos-hub-native`](../../crates/hub/aos-hub-native/Cargo.toml) | Identifies the native Hub deployment. |
| `aos-hub-core` | [`aos-hub-model`](../../crates/hub/aos-hub-model/Cargo.toml), [`aos-hub-db`](../../crates/hub/aos-hub-db/Cargo.toml), [`aos-hub-service`](../../crates/hub/aos-hub-service/Cargo.toml) | Domain values, persistence, and service orchestration are separate libraries. |
| `aos-hub-worker` | [`aos-hub-worker`](../../crates/hub/aos-hub-worker/Cargo.toml) | Package name retained; source moves under its owner. |
| `aos-hub-console` | [`aos-hub-console`](../../crates/hub/aos-hub-console/Cargo.toml) | Package name retained; source moves under its owner. |
| `aos-hub-console-contract` | [`aos-hub-ui`](../../crates/hub/aos-hub-ui/Cargo.toml) | Identifies shared Hub navigation and presentation values. |
| `aos-proto-types` | [`aos-hub-api`](../../crates/hub/aos-hub-api/Cargo.toml) | Scopes portable generated messages and Connect descriptors to Hub. |

### Crucible

| Former package | Current package(s) | Change |
|---|---|---|
| `crucible` | [`crucible-engine`](../../crates/crucible/crucible-engine/Cargo.toml) | Identifies the deterministic execution engine rather than the whole project. |
| `crucible-sim` | [`crucible-determinism`](../../crates/crucible/crucible-determinism/Cargo.toml) | Names deterministic scheduling, clock, and decision primitives. |
| `crucible-device` | [`crucible-device`](../../crates/crucible/crucible-device/Cargo.toml) | Package name retained; source moves under its owner. |
| `crucible-campaign` | [`crucible-campaign`](../../crates/crucible/crucible-campaign/Cargo.toml) | Package name retained; source moves under its owner. |
| `crucible-api` | [`crucible-control-api`](../../crates/crucible/crucible-control-api/Cargo.toml), [`crucible-control-client`](../../crates/crucible/crucible-control-client/Cargo.toml), [`crucible-control-server`](../../crates/crucible/crucible-control-server/Cargo.toml) | Messages/codecs, client transport, and server integration are separate crates. |
| `crucible-session` | [`crucible-session`](../../crates/crucible/crucible-session/Cargo.toml) | Package name retained; source moves under its owner. |
| `crucible-daemon` | [`crucible-daemon`](../../crates/crucible/crucible-daemon/Cargo.toml) | Package name retained; source moves under its owner. |
| `crucible-cli` | [`crucible-cli`](../../crates/crucible/crucible-cli/Cargo.toml), [`crucible-daemon`](../../crates/crucible/crucible-daemon/Cargo.toml) | The package name stays; VM lifecycle and interactive replay coordination move to the daemon. |
| `crucible-protocol` | [`crucible-qemu-protocol`](../../crates/crucible/crucible-qemu-protocol/Cargo.toml) | Scopes the permissive protocol to the QEMU process boundary. |
| `crucible-shmem` | [`crucible-qemu-shmem`](../../crates/crucible/crucible-qemu-shmem/Cargo.toml) | Scopes permissive shared-memory layouts to the QEMU process boundary. |
| `crucible-qemu` | [`crucible-qemu-host`](../../crates/crucible/crucible-qemu-host/Cargo.toml) | Distinguishes Apache host integration from GPL-side implementations. |
| `crucible-qemu-plugin` | [`crucible-qemu-plugin`](../../crates/crucible/crucible-qemu-plugin/Cargo.toml) | Package name retained; source moves under its owner. |
| `crucible-debug-gateway` | [`crucible-qemu-debug-gateway`](../../crates/crucible/crucible-qemu-debug-gateway/Cargo.toml) | Identifies the GPL-side QEMU debugger process. |
| `crucible-guest` | [`crucible-guest`](../../crates/crucible/crucible-guest/Cargo.toml) | Package name retained; source moves under its owner. |
| `crucible-cas` | [`crucible-store`](../../crates/crucible/crucible-store/Cargo.toml) | Names Crucible content storage. |
| `crucible-s3-store` | [`crucible-store-s3`](../../crates/crucible/crucible-store-s3/Cargo.toml) | Places the S3 transport within the Crucible storage family. |
| `crucible-harness` | [`crucible-test-support`](../../crates/crucible/crucible-test-support/Cargo.toml) | Names shared testing infrastructure and architecture gates. |
| `crucible-assert` | [`crucible-test-support`](../../crates/crucible/crucible-test-support/Cargo.toml) | Gate/assertion vocabulary merges into shared Crucible test support. |

## Five removed package boundaries

- `aos-contract` → `aos_core::{json,digest,limits}`.
- `aos-ability-plan` → `aos_module_format::graph`.
- `aos-metadata-provider` → `aos-platform-metadata`.
- `aos-boot-preparation-provider` → `aos_boot_runtime::preparation`.
- `crucible-assert` → `crucible-test-support`.

## Fifteen packages extracted in the initial migration

These packages added independently consumable implementations to the initial
77-package base. They are distinct from its 62 retained or renamed package
boundaries, giving **67 − 5 + 15 = 77**.

| Extracted package(s) | Source responsibility |
|---|---|
| [`aos-artifact-evidence`](../../crates/artifacts/aos-artifact-evidence/Cargo.toml) | Immutable artifact formats and readers formerly mixed with module declarations and documentation. |
| [`aos-nar`](../../crates/artifacts/aos-nar/Cargo.toml), [`aos-nix`](../../crates/nix/aos-nix/Cargo.toml), [`aos-cli-ui`](../../crates/cli/aos-cli-ui/Cargo.toml) | NAR/cache signing, native Nix execution, and terminal presentation from the former native core. |
| [`aos-boot-runtime`](../../crates/boot/aos-boot-runtime/Cargo.toml) | Boot operations from the former systemd handler and boot-preparation package. |
| [`aos-registry-client`](../../crates/registry/aos-registry-client/Cargo.toml), [`aos-registry-authoring`](../../crates/registry/aos-registry-authoring/Cargo.toml) | Registry acquisition/verification and native authoring/signing from the package library. |
| [`aos-deployment-format`](../../crates/packages/aos-deployment-format/Cargo.toml), [`aos-deployment`](../../crates/packages/aos-deployment/Cargo.toml) | Deployment documents/inventory and native evaluation/activation from the package library. |
| [`aos-release-coordinator`](../../crates/release/aos-release-coordinator/Cargo.toml) | Publication preparation, journaling, readback, and external signing coordination from package authoring. |
| [`aos-hub-client`](../../crates/hub/aos-hub-client/Cargo.toml) | Hub client and login operations from the former remote client. |
| [`aos-hub-model`](../../crates/hub/aos-hub-model/Cargo.toml), [`aos-hub-db`](../../crates/hub/aos-hub-db/Cargo.toml) | Domain policy and persistence from the former Hub core. |
| [`crucible-control-client`](../../crates/crucible/crucible-control-client/Cargo.toml), [`crucible-control-server`](../../crates/crucible/crucible-control-server/Cargo.toml) | Client transport and server integration from the former combined control API. |

## Later implemented Crucible owners

The current workspace adds the two CNP packages from #711 and the first real
host-resource extraction, giving **77 + 2 + 1 = 80**. The latter establishes the
owner planned for #696; its future RAM, budget and supervision work remains
separate.

| Earlier ownership | Current package | Implemented responsibility |
|---|---|---|
| `crucible-node-contract` | [`crucible-node-format`](../../crates/crucible/crucible-node-format/Cargo.toml) | Portable CNP data, strict JSON, canonical identities, and validation. |
| `crucible-node-provider` | [`crucible-node-transport`](../../crates/crucible/crucible-node-transport/Cargo.toml) | Bounded host process transport, request custody, and reference-provider tools. |
| Read leases beside the quota implementation | [`crucible-host-resources`](../../crates/crucible/crucible-host-resources/Cargo.toml) | Original Linux descriptor read leases and isolated notification custody; generic quotas stay separate. |

## Updating consumers

Use hyphenated package names in Cargo dependencies and selectors, and the matching
underscore spelling in Rust imports: for example, `aos-transfer` and
`aos_transfer::progress`, or `crucible-engine` and `crucible_engine`. An explicit
Cargo dependency alias still controls the import name. Source paths must include
the owning subdirectories; use the linked manifests rather than inferring paths
from package names.

Installed executable names, serialized schema tags, protocol constants, signature
and digest domains, and Nix package attributes have their own compatibility
contracts. A Cargo rename alone does not rename these identities. In particular,
`crucible-assert.v1` remains a gate vocabulary identity after its crate is merged.
Canonical protobuf inputs live under `api/proto/aos/{cache,build,gc,auth,hub}/v1`.

The [mechanical migration map](../../tools/dev/crate-migration.json) is the initial
move plan, including temporary packages subsequently merged or split. Use this
reference and the current Cargo manifests for the final ownership map; replaying
the initial map does not perform the later architectural refactors. See the
[tooling guide](../../tools/dev/crate-migration.md) for supported checks.

Crates on other branches are tracked separately in the
[unmerged-PR inventory](unmerged-crates.md); its remaining proposals are outside
the 80 implemented packages. Validation outcomes and their tested checkpoints are
in the [validation record](crate-migration-validation.md).
