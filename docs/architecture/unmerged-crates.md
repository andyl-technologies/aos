# Unmerged crate migration inventory

The implemented base is [PR #715](https://github.com/andyl-technologies/aos/pull/715), branch `dplecki/crate-monorepo`, with 77 workspace packages. Original master comparison: `2ee6311aea39bef7aef6ba4b566f9f502649f3f2`. This inventory classifies future packages at exact checked PR heads; it does not merge or modify owning PRs. The [workspace design](crate-workspace.md) and [active inventory](crate-inventory.md) describe implemented ownership.

| PR | Audited head | Added top-level / fixture crates | Ownership |
|---|---|---|---|
| [#713](https://github.com/andyl-technologies/aos/pull/713) | `4baf11f742e3bf3904bd01c34f7420c334765076` | 3 / 0 | AOS maintenance |
| [#711](https://github.com/andyl-technologies/aos/pull/711) | `fa3508865aba6ed03ca3ac08e7eb2df314e41f79` | 2 / 0 | Crucible node protocol/transport |
| [#696](https://github.com/andyl-technologies/aos/pull/696) | `b9aa885eb16e2b799f178be44aba4a6dfa69cd3a` | 2 / 0 | Crucible RAM/host resources |
| [#673](https://github.com/andyl-technologies/aos/pull/673) | `b01ddab52230194645697efc4397d812b3fd6d6c` | 0 / 0 | Crucible campaigns |
| [#420](https://github.com/andyl-technologies/aos/pull/420) | `412bc8cd1f75fa3b851f5cd1186ab9c21b7d1430` | 5 / 0 | Terrane |
| [#374](https://github.com/andyl-technologies/aos/pull/374) | `81679049e6cdda9e6a7ee44ec6f238d54c84f38a` | 0 / 0 | Hub |
| [#232](https://github.com/andyl-technologies/aos/pull/232) | `4280e3ba24cc15ae8f302de14b654649ef69b748` | 34 / 6 | Sandbox |
| [#231](https://github.com/andyl-technologies/aos/pull/231) | `69cc082e8c1b7be564556a4ef2d4c70fb9c67b78` | 0 / 0 | Darwin tooling |
| [#716](https://github.com/andyl-technologies/aos/pull/716) | `8cc3be107abd3b7e53e6875d831f513530e2a533` | 0 / 0 | Dispatch RFC/native dependency preparation |

Future names below are proposed for code outside the base workspace. Generic journal, descriptor and SQLite promotion require API review; base extractions are already implemented.

## Proposed names for added packages

| PR | Current package | Proposed full package name | Proposed directory |
|---|---|---|---|
| #713 | `aos-assessment` | `aos-package-assessment` | `crates/aos/maintenance/aos-package-assessment` |
| #713 | `aos-assessment-providers` | `aos-package-assessment-sources` | `crates/aos/maintenance/aos-package-assessment-sources` |
| #713 | `aos-assessment-runtime` | `aos-package-assessment-coordinator` | `crates/aos/maintenance/aos-package-assessment-coordinator` |
| #711 | `crucible-node-contract` | `crucible-node-format` | `crates/crucible/protocol/crucible-node-format` |
| #711 | `crucible-node-provider` | `crucible-node-transport` | `crates/crucible/host/crucible-node-transport` |
| #696 | `crucible-ram` | `crucible-ram` | `crates/crucible/protocol/crucible-ram` |
| #696 | `crucible-sqlite-heap` | `crucible-sqlite-heap` | `crates/crucible/storage/crucible-sqlite-heap` |
| #420 | `aos-terrane` | `aos-terrane-integration` | `crates/terrane/integration/aos-terrane-integration` |
| #420 | `terrane` | `terrane-sdk` | `crates/terrane/sdk/terrane-sdk` |
| #420 | `terrane-cli` | `terrane-cli` | `crates/terrane/cli/terrane-cli` |
| #420 | `terrane-core` | `terrane-format` | `crates/terrane/sdk/terrane-format` |
| #420 | `terrane-fs` | `terrane-linux` | `crates/terrane/linux/terrane-linux` |
| #232 | `aos-filesystem-fuse` | `aos-sandbox-filesystem-fuse` | `crates/sandbox/filesystem/aos-sandbox-filesystem-fuse` |
| #232 | `aos-filesystem-fuse-kernel-worker` | `aos-sandbox-filesystem-fuse-kernel-worker` | `crates/sandbox/filesystem/aos-sandbox-filesystem-fuse/tests/fixtures/kernel-worker` |
| #232 | `aos-filesystem-fuse-link-consumer` | `aos-sandbox-filesystem-fuse-link-consumer` | `crates/sandbox/filesystem/aos-sandbox-filesystem-fuse/tests/fixtures/link-consumer` |
| #232 | `aos-filesystem-view` | `aos-sandbox-filesystem-view` | `crates/sandbox/filesystem/aos-sandbox-filesystem-view` |
| #232 | `aos-filesystem-view-core` | `aos-sandbox-filesystem-format` | `crates/sandbox/filesystem/aos-sandbox-filesystem-format` |
| #232 | `aos-sandbox` | `aos-sandbox-controller-domain` | `crates/sandbox/controller/aos-sandbox-controller-domain` |
| #232 | `aos-sandbox-agent` | `aos-sandbox-guest-protocol` | `crates/sandbox/protocol/aos-sandbox-guest-protocol` |
| #232 | `aos-sandbox-broker` | `aos-sandbox-broker` | `crates/sandbox/host/aos-sandbox-broker` |
| #232 | `aos-sandbox-broker-session-protocol` | `aos-sandbox-broker-session-protocol` | `crates/sandbox/protocol/aos-sandbox-broker-session-protocol` |
| #232 | `aos-sandbox-broker-session-security` | `aos-sandbox-broker-session-security` | `crates/sandbox/security/aos-sandbox-broker-session-security` |
| #232 | `aos-sandbox-cache-signer` | `aos-sandbox-cache-signer` | `crates/sandbox/security/aos-sandbox-cache-signer` |
| #232 | `aos-sandbox-client` | `aos-sandbox-client` | `crates/sandbox/controller/aos-sandbox-client` |
| #232 | `aos-sandbox-controller-runtime` | `aos-sandbox-controller-runtime` | `crates/sandbox/controller/aos-sandbox-controller-runtime` |
| #232 | `aos-sandbox-coordinator-protocol` | `aos-sandbox-coordinator-protocol` | `crates/sandbox/protocol/aos-sandbox-coordinator-protocol` |
| #232 | `aos-sandbox-core` | `aos-sandbox-model` | `crates/sandbox/model/aos-sandbox-model` |
| #232 | `aos-sandbox-guardian` | `aos-sandbox-guardian` | `crates/sandbox/security/aos-sandbox-guardian` |
| #232 | `aos-sandbox-guest` | `aos-sandbox-guest` | `crates/sandbox/guest/aos-sandbox-guest` |
| #232 | `aos-sandbox-guest-root-realization` | `aos-sandbox-guest-root-realization` | `crates/sandbox/guest/aos-sandbox-guest-root-realization` |
| #232 | `aos-sandbox-guest-root-tree` | `aos-sandbox-guest-root-measurement` | `crates/sandbox/guest/aos-sandbox-guest-root-measurement` |
| #232 | `aos-sandbox-host` | `aos-sandbox-host` | `crates/sandbox/host/aos-sandbox-host` |
| #232 | `aos-sandbox-journal` | `aos-sandbox-journal` | `crates/sandbox/controller/aos-sandbox-journal` |
| #232 | `aos-sandbox-kernel-export-owner-peer` | `aos-sandbox-kernel-export-owner-peer` | `crates/sandbox/security/aos-sandbox-kernel-export-owner-peer` |
| #232 | `aos-sandbox-linux` | `aos-sandbox-linux` | `crates/sandbox/host/aos-sandbox-linux` |
| #232 | `aos-sandbox-mount` | `aos-sandbox-mount` | `crates/sandbox/host/aos-sandbox-mount` |
| #232 | `aos-sandbox-network` | `aos-sandbox-network` | `crates/sandbox/host/aos-sandbox-network` |
| #232 | `aos-sandbox-network-protected-store-fixture` | `aos-sandbox-network-protected-store-fixture` | `crates/sandbox/host/aos-sandbox-network/tests/fixtures/protected-store` |
| #232 | `aos-sandbox-network-systemd-custody-fixture` | `aos-sandbox-network-systemd-custody-fixture` | `crates/sandbox/host/aos-sandbox-network/tests/fixtures/systemd-custody` |
| #232 | `aos-sandbox-ownership` | `aos-sandbox-ownership` | `crates/sandbox/model/aos-sandbox-ownership` |
| #232 | `aos-sandbox-ownership-protocol` | `aos-sandbox-ownership-protocol` | `crates/sandbox/protocol/aos-sandbox-ownership-protocol` |
| #232 | `aos-sandbox-policy` | `aos-sandbox-policy` | `crates/sandbox/model/aos-sandbox-policy` |
| #232 | `aos-sandbox-protocol` | `aos-sandbox-protocol` | `crates/sandbox/protocol/aos-sandbox-protocol` |
| #232 | `aos-sandbox-service-journal-probe` | `aos-sandbox-service-journal-probe` | `crates/sandbox/controller/aos-sandbox-controller-domain/tests/fixtures/service-journal` |
| #232 | `aos-sandbox-services` | `aos-sandbox-services` | `crates/sandbox/controller/aos-sandbox-services` |
| #232 | `aos-sandbox-source-provider` | `aos-sandbox-source-provider` | `crates/sandbox/storage/aos-sandbox-source-provider` |
| #232 | `aos-sandbox-source-provider-ledger` | `aos-sandbox-source-provider-ledger` | `crates/sandbox/storage/aos-sandbox-source-provider-ledger` |
| #232 | `aos-sandbox-source-provider-protocol` | `aos-sandbox-source-provider-protocol` | `crates/sandbox/protocol/aos-sandbox-source-provider-protocol` |
| #232 | `aos-sandbox-source-provider-security` | `aos-sandbox-source-provider-security` | `crates/sandbox/security/aos-sandbox-source-provider-security` |
| #232 | `aos-sandbox-source-signer` | `aos-sandbox-source-signer` | `crates/sandbox/security/aos-sandbox-source-signer` |
| #232 | `aos-sandbox-storage` | `aos-sandbox-storage` | `crates/sandbox/storage/aos-sandbox-storage` |
| #232 | `aos-sandbox-verity-backing-probe` | `aos-sandbox-verity-backing-probe` | `crates/sandbox/host/aos-sandbox-linux/tests/fixtures/verity-backing` |

## Additional required future extractions

| Owning PR | Package | Directory | Responsibility |
|---|---|---|---|
| #232 | `aos-sandbox-api` | `crates/sandbox/protocol/aos-sandbox-api` | Generated public/local/shared coordinator message data from `api/proto/` |
| #696 | `crucible-host-resources` | `crates/crucible/host/crucible-host-resources` | Crucible-specific host budgets, supervision, RAM placement and measurement controls, separate from generic quota mechanics |

## Required cross-PR boundaries

- #696: `aos-linux-project-quota` stays generic; new supervision/RAM policy/measurement authority belongs in separate `crucible-host-resources`.
- #232: generated sandbox data belongs in distinct `aos-sandbox-api` sourced from `api/proto/`; `aos-build-api` is not a universal API umbrella.
- #232: review generic Linux descriptor extraction so `aos-systemd-client` does not depend on sandbox implementation.
- #232: generic journal promotion and #696 SQLite memory-control promotion remain API-review decisions before shared ownership is claimed.
- #711/#696: portable boundary components retain `MIT OR Apache-2.0`; GPL-loaded code must not acquire Apache-only library dependencies.
- #420: Terrane SDK/format remain independent of AOS integration. Keep no_std plus alloc for formats.
- #713: package assessment policy/sources/coordinator are shared local/Hub domain code under AOS maintenance.

## Directory classification

`crates/terrane/{sdk,linux,cli,integration}` and `crates/sandbox/{model,protocol,controller,host,guest,storage,security,filesystem,testing}` group their owning projects. Assessment uses `crates/aos/maintenance`. Full Cargo package names carry scope; leaf directories retain those full names. Nested fixture packages stay beside owner tests.

## Validation status

Static inventory only. No owning checkout was edited and no PR-branch build/test claims are made. Owning branches must rebase and run local hermetic builds plus project-specific integration, portability and process/license gates after migration. Base names and exported namespaces were verified against the actual 77-member workspace. Future package moves and shared-library promotions remain work for owning branches.

## Implemented exported namespaces and schema reuse

The implemented base is PR [#715](https://github.com/andyl-technologies/aos/pull/715), branch `dplecki/crate-monorepo`. Its current workspace has 77 packages. The authoritative design is `docs/architecture/crate-workspace.md`, and active paths are in `docs/architecture/crate-inventory.md`. The table below describes implemented packages. Future packages in this inventory remain work for their owning PRs.

| Former ownership | Current dependency / namespace |
|---|---|
| Contract JSON, identities, decoding | `aos_core::{json,digest,limits,identity}`; `Sha256Digest` also exported at root |
| NAR/narinfo/cache/signing | `aos_nar::{cache,info,export,pack,verify}`; extraction/hash verification consumers select `features = ["compression"]` |
| Nix execution, derivations, store tools | `aos_nix::{drv,env,identity,runner,store,error,executable}`; `NixRunner`, `NixCli`, `PathInfo` at root |
| Terminal presentation and command hints | `aos_cli_ui::{output,invocation}`; command error/exit policy stays with CLI |
| Ability model and plan | `aos_module_format`; graph validation is `aos_module_format::graph` |
| Artifact evidence formats/readers | `aos_artifact_evidence::{document,model,identity,consumption,diagnostic,limits}` plus root exports; do not route through module-format |
| Deployment schemas and inventory | `aos_deployment_format::{model,input,admission,resolution_lock,locator,inventory}` |
| Deployment effects | `aos_deployment::{artifact,document,evaluation,handler,input,nix,process,retention,source_views,store,transaction}`; no package-manager dependency |
| Hub portable model | `aos_hub_model::{domain,binding,delivery,delivery_http,endpoint,identity,...}` |
| Hub persistence | `aos_hub_db::{backend,db,dialect,value}`; import directly rather than via service facades |
| Hub orchestration/client/API | `aos_hub_service`, `aos_hub_client::{hub,login}`, and `aos_hub_api::{hub_v1,...}` |
| Crucible control | `crucible_control_api`, `crucible_control_client`, `crucible_control_server`; VM creation/lifecycle implementation is `crucible_daemon::vm_lifecycle` |

Reuse schemas field by field without changing bytes or acceptance behavior. `InstalledPackageRecord` and `PackageInventoryDetails` now live in `aos_deployment_format::inventory`; supply immutable inventory to deployment/image verification rather than depending on package-manager state APIs. Outer installed records retain their established Serde behavior and defaults for `expires_at` and `apm`. The nested `PackageInventoryDetails` retains `deny_unknown_fields`, including optional deployment/module-documentation/qualification metadata and attestation defaults. Do not tighten the outer record or alter omissions/defaults as a side effect of type movement.

OCI canonical JSON intentionally stays in `aos_oci_types::canonical`: it admits extension keys outside ASCII and full-width integer values, and follows its existing Serde schema/duplicate behavior. Strict authenticated AOS JSON in `aos_core::json` has different rules. Compare exact decoding, integer range, duplicate handling, canonical ordering and identity domains before sharing an implementation. Likewise portable node/RAM process formats and Terrane formats retain their existing license/encoding contracts.



## Dispatch names reserved by RFC-0027

PR #716 currently changes no Rust source or Cargo manifests. Its planned independent library family is `dispatch-model`, `dispatch-protocol`, `dispatch-runtime` and a consumer facade presently called `dispatch` in the RFC. Proposed package naming makes that facade `dispatch-sdk`, under `crates/dispatch/{model,protocol,runtime,sdk}`. An eventual `dispatch-cli` package may own the unchanged `dispatch` executable. The trusted worker can initially remain with its runtime owner; the C++ Rebalancer backend stays a separate process. These are planned classifications, not current workspace members. Pure model/evaluation must remain independent of native engines and async runtimes; AOS/Hub/Crucible application policy stays outside Dispatch libraries. Explicit package licenses and exact field-level schema reuse require review when implementation is created.

## Final open-head refresh

The final snapshot contains ten open PRs, including migration PR #715 and nine owning PRs above. Advanced heads for #713, #711, #696, #673 and #374 were inspected as exact local Git objects. None changes the added-package manifests or full crate inventory relative to the preceding audit. #711 expands native gem5/custody and CNP lifecycle code under existing owners; #696 additionally exports `crucible_device::DeviceSnapshotAllocation`; the latter remains a device capability. Updated handoffs retain those changes and the existing 242-symbol control API ownership map. Owning branch builds/tests remain required after migration.
