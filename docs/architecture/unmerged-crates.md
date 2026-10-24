# Unmerged crate migration inventory

The implemented base is [PR #715](https://github.com/andyl-technologies/aos/pull/715), branch
`dplecki/crate-monorepo`, with 77 workspace packages. Original master comparison:
`2ee6311aea39bef7aef6ba4b566f9f502649f3f2`. The original audit below classifies
packages at exact checked PR heads.
RFC-0021 Sandbox packages have since been migrated on this branch; their current
status is recorded separately below. The [workspace design](crate-workspace.md)
and [active inventory](crate-inventory.md) describe implemented ownership.

The open-PR heads are pinned at `2026-10-09T21:52:35.570559+00:00`; later commits are outside
this audit.

| PR | Audited head | Added top-level / fixture crates | Ownership |
|---|---|---|---|
| [#713](https://github.com/andyl-technologies/aos/pull/713) | `14c9c156fa77f347340692e4093f305a982fe09e` | 3 / 0 | AOS maintenance |
| [#711](https://github.com/andyl-technologies/aos/pull/711) | `f4ad8a311629b5bb89d2894ff31f8014f5457e5d` | 2 / 0 | Crucible node protocol/transport |
| [#696](https://github.com/andyl-technologies/aos/pull/696) | `f94a8c9a9f6dbe4d0e81e53f31bed3fee48f1cc4` | 2 / 0 | Crucible RAM/host resources |
| [#673](https://github.com/andyl-technologies/aos/pull/673) | `b01ddab52230194645697efc4397d812b3fd6d6c` | 0 / 0 | Crucible campaigns |
| [#420](https://github.com/andyl-technologies/aos/pull/420) | `412bc8cd1f75fa3b851f5cd1186ab9c21b7d1430` | 5 / 0 | Terrane |
| [#374](https://github.com/andyl-technologies/aos/pull/374) | `cf28dac8015ac69f8a19c18bc9e5b7ab9c4d008f` | 0 / 0 | Hub |
| [#232](https://github.com/andyl-technologies/aos/pull/232) | `840658431930dc94a51653b2f0f9eaea98d51d95` | 34 / 6 | Sandbox |
| [#231](https://github.com/andyl-technologies/aos/pull/231) | `69cc082e8c1b7be564556a4ef2d4c70fb9c67b78` | 0 / 0 | Darwin tooling |
| [#716](https://github.com/andyl-technologies/aos/pull/716) | `a048a32b44f7a6652a02944d82bd1ae03e3115ef` | 5 / 0 | Dispatch assignment SDK/runtime/conformance |

Except for the applied Sandbox migration described below, future names are
proposed for code outside the current workspace. Generic journal,
descriptor and SQLite promotion require API review; base extractions are already implemented.

## Proposed names for added packages

| PR | Current package | Proposed full package name | Proposed directory |
|---|---|---|---|
| #713 | `aos-assessment` | `aos-package-assessment` | `crates/maintenance/aos-package-assessment` |
| #713 | `aos-assessment-providers` | `aos-package-assessment-sources` | `crates/maintenance/aos-package-assessment-sources` |
| #713 | `aos-assessment-runtime` | `aos-package-assessment-coordinator` | `crates/maintenance/aos-package-assessment-coordinator` |
| #711 | `crucible-node-contract` | `crucible-node-format` | `crates/crucible/crucible-node-format` |
| #711 | `crucible-node-provider` | `crucible-node-transport` | `crates/crucible/host/crucible-node-transport` |
| #696 | `crucible-ram` | `crucible-ram` | `crates/crucible/crucible-ram` |
| #696 | `crucible-sqlite-heap` | `crucible-sqlite-heap` | `crates/crucible/crucible-sqlite-heap` |
| #420 | `aos-terrane` | `aos-terrane-integration` | `crates/terrane/integration/aos-terrane-integration` |
| #420 | `terrane` | `terrane-sdk` | `crates/terrane/sdk/terrane-sdk` |
| #420 | `terrane-cli` | `terrane-cli` | `crates/terrane/cli/terrane-cli` |
| #420 | `terrane-core` | `terrane-format` | `crates/terrane/sdk/terrane-format` |
| #420 | `terrane-fs` | `terrane-linux` | `crates/terrane/linux/terrane-linux` |
| #716 | `dispatch-model` | `dispatch-model` | `crates/dispatch/model/dispatch-model` |
| #716 | `dispatch-protocol` | `dispatch-protocol` | `crates/dispatch/protocol/dispatch-protocol` |
| #716 | `dispatch-runtime` | `dispatch-runtime` | `crates/dispatch/runtime/dispatch-runtime` |
| #716 | `dispatch` | `dispatch-sdk` | `crates/dispatch/sdk/dispatch-sdk` |
| #716 | `dispatch-conformance` | `dispatch-conformance` | `crates/dispatch/testing/dispatch-conformance` |

## Applied Sandbox migration on this branch

The original #232 pin above is historical. This branch now contains 45 migrated
Sandbox packages plus the separately created `aos-sandbox-api`: 46 Sandbox
members alongside the 77 implemented base packages, for 123 total and 121
default members. The optional coordinator and coordinator-protocol packages
remain outside the default-member set. Six members are nested qualification
fixtures; their directories move with their owning packages.

Current names, paths and responsibilities are in the
[active inventory](crate-inventory.md); old-to-current identities are in the
[rename reference](crate-renames.md) and
[Sandbox migration map](../../tools/dev/sandbox-crate-migration.json). The later
coordinator, ledger-replay, mount-native, Publisher and native Source owners are
included. The proposed native `aos-sandbox-cache` package is not materialized or
counted in this checkout.

Generated Sandbox public/local/shared coordinator contracts now have the actual
`aos-sandbox-api` owner, sourced from `api/proto/aos/sandbox/`. The separate
coordinator-protocol owner retains transport generation. Existing wire names,
compatibility fixtures, namespace shape and installed executable identities are
preserved. This source migration is not an RFC completion or build/test claim.

Generic descriptor and journal promotion remain API-review decisions. In
particular, `aos-systemd-client` still carries a Linux dependency on
`aos-sandbox-linux` and Sandbox-specific custody APIs; separating those mechanics
from Sandbox policy remains dependency-extraction work. Other future PR package
proposals below retain their original audit scope.

## Uncommitted local crate observed at the pinned snapshot

At the pinned snapshot, the #713 owning checkout contained uncommitted `aos-assessment-http` at
`crates/aos-assessment-http/Cargo.toml`, separate from its three committed added crates.
Proposed name/path: `aos-package-assessment-http` under `crates/maintenance/`. It owns
bounded native HTTPS source effects, explicit physical time and scoped credentials, with
reqwest/async-trait/zeroize dependencies and Apache-2.0 licensing. Keep it outside Worker
and portable coordinator dependencies. The scratch handoff records exact local source
fingerprints; this observation is not a PR-head member or a build/test claim. Review existing
`aos-transfer` bounded transport primitives where exact timeout/streaming/TLS/redirect/proxy
semantics fit; keep assessment credential custody, installed source profiles and domain policy
with this adapter. Do not merge responsibilities merely because both implement HTTP.

## Separate late inspection: assessment HTTP now committed

A bounded discovery at `2026-10-10 00:10:22 UTC` found no new owning PRs. The same
nine owners remain. PR #713 now commits the previously anticipated HTTP adapter
at `2c6c78b601d1743bd2200496314945aaf383fe3a`, with four assessment packages and
71 packages overall. The table above and original local fingerprints remain the
historical `21:52` snapshot; this separate observation does not replace its pins.
No other owning PR adds or removes a Cargo package relative to that snapshot.

| Current package / manifest | Proposed full name | Proposed directory | Actual consumer |
|---|---|---|---|
| `aos-assessment-http` / `crates/aos-assessment-http/Cargo.toml` | `aos-package-assessment-http` | `crates/maintenance/aos-package-assessment-http` | `aos` → `aos-cli` |

The Apache-2.0 native adapter now has `executor`, `credentials` and `remote`
modules. They bind process-local execution to installed pairing/limits, resolve
current scoped secret custody and send independently authenticated bounded
Native-to-Worker work. Source evaluation delegates to the shared coordinator;
pure policy/parsing remain in assessment/coordinator/sources. Keep the proposed
HTTP name, direct source-parser dependency and native feature/dependency boundary;
Worker must not import this reqwest implementation. Reuse matching `aos-transfer`
mechanics only where exact transport/security semantics fit, preserving separate
domain admission, custody and evidence authority. The scratch bundle records the
late head, committed source hashes and new exports. This is source review only,
with no owning-branch build/test claim or addition to the 77-member base.

## Additional required future extractions

| Owning PR | Package | Directory | Responsibility |
|---|---|---|---|
| #696 | `crucible-host-resources` | `crates/crucible/host/crucible-host-resources` | Crucible-specific host budgets, supervision, RAM placement and measurement controls, separate from generic quota mechanics |

## Required cross-PR boundaries

- #696: `aos-linux-project-quota` stays generic; new supervision/RAM policy/measurement
  authority belongs in separate `crucible-host-resources`.
- #232: the applied `aos-sandbox-api` extraction owns generated Sandbox data from
  `api/proto/aos/sandbox/`; `aos-build-api` retains its own build contracts.
- #232: review generic Linux descriptor extraction so `aos-systemd-client` does not depend on
  sandbox implementation.
- #232: generic journal promotion and #696 SQLite memory-control promotion remain API-review
  decisions before shared ownership is claimed.
- #711/#696: portable boundary components retain `MIT OR Apache-2.0`; GPL-loaded code must not
  acquire Apache-only library dependencies.
- #420: Terrane SDK/format remain independent of AOS integration. Keep no_std plus alloc for
  formats.
- #713: package assessment policy/sources/coordinator are shared local/Hub domain code under
  AOS maintenance.

## Directory classification

`crates/terrane/{sdk,linux,cli,integration}` and
`crates/sandbox/{model,protocol,controller,host,guest,storage,security,filesystem,testing}`
group their owning projects. Assessment uses `crates/maintenance`; Dispatch uses
`crates/dispatch/{model,protocol,runtime,sdk,testing}`. Full Cargo package names
carry scope; leaf directories retain those full names. Nested fixture packages stay beside
owner tests.

## Validation status

The original pinned audit was static and made no owning-checkout edits or
PR-branch build/test claims. The Sandbox section above records the later applied
source migration, without extending that audit into runtime qualification. Owning branches must rebase and run local hermetic builds plus project-specific
integration, portability and process/license gates after migration. Base names and exported
namespaces were verified against the incoming 77-member base. Other future
package moves and shared-library promotions remain work for owning branches.

## Implemented exported namespaces and schema reuse

The implemented base is PR [#715](https://github.com/andyl-technologies/aos/pull/715), branch
`dplecki/crate-monorepo`. That implemented base contains 77 packages; the current
branch also contains the 46 Sandbox packages described above. The authoritative
design is `docs/architecture/crate-workspace.md`, and active paths are in
`docs/architecture/crate-inventory.md`. The table below describes the base
packages. Other future packages remain work for their owning PRs.

| Former ownership | Current dependency / namespace |
|---|---|
| Contract JSON, identities, decoding | `aos_core::{json,digest,limits,identity}`; `Sha256Digest` also exported at root |
| NAR/narinfo/cache/signing | `aos_nar::{cache,info,export,pack,verify}`; extraction/hash verification consumers select `features = ["compression"]` |
| Nix execution, derivations, store tools | `aos_nix::{drv,env,identity,runner,store,error,executable}`; `NixRunner`, `NixCli`, `PathInfo` at root |
| Registry readers and producers | `aos_registry_client::{config,registry,security,...}` for verified reads; `aos_registry_authoring::{registry_ops,RegistryCommand,...}` for production and publication |
| Registry shared contracts | `aos_registry_format::{consumer,release,measurement}`; release entries and measurement digests remain portable format contracts |
| Terminal presentation and command hints | `aos_cli_ui::{output,invocation}`; command error/exit policy stays with CLI |
| Neutral registry/transfer reporting | `aos_transfer::progress::{TransferObserver,ProgressSink,TransferProgress,NoopObserver}`; available with `default-features = false`, separate from optional transport engines |
| Registry refresh outcomes versus package command | `aos_registry_client::sync::{SyncResult,RegistrySyncError,RegistryVerificationError}`; command orchestration/recovery guidance is `aos_package_manager::update::{run,verification_message}` |
| Shared DSSE framing/contracts | `aos_registry_format::provenance::{DsseEnvelope,DsseSignature,dsse_pae,DSSE_PAYLOAD_TYPE,DSSE_SIGNATURE_NAMESPACE}` |
| Producer provenance signing | `aos_registry_authoring::provenance::{ProvenanceSignature,ProvenanceSigner,sign_statement_dsse_jsonl_external}` |
| Producer private-key operations | `aos_registry_authoring::security::{public_ed25519_blob,sign_payload_signature}` and `aos_registry_authoring::sshkey::Ed25519Keypair` |
| Ability model and plan | `aos_module_format`; graph validation is `aos_module_format::graph` |
| Artifact evidence formats/readers | `aos_artifact_evidence::{document,model,identity,consumption,diagnostic,limits}` plus root exports; do not route through module-format |
| Deployment schemas and inventory | `aos_deployment_format::{model,input,admission,resolution_lock,locator,inventory}` |
| Deployment effects | `aos_deployment::{artifact,document,evaluation,handler,input,nix,process,retention,source_views,store,transaction}`; no package-manager dependency |
| Hub portable model | `aos_hub_model::{domain,binding,delivery,delivery_http,endpoint,identity,...}` |
| Hub persistence | `aos_hub_db::{backend,db,dialect,value}`; import directly rather than via service facades |
| Hub orchestration/client/API | `aos_hub_service`, `aos_hub_client::{hub,login}`, and `aos_hub_api::{hub_v1,...}` |
| Crucible control | `crucible_control_api`, `crucible_control_client`, `crucible_control_server`; VM creation/lifecycle implementation is `crucible_daemon::vm_lifecycle` |

The CLI Rust library is `aos_cli`; installed command names remain unchanged. Deployment input
acquisition uses
`aos_deployment::input::{read_evaluation_input,read_evaluation_input_in,import_evaluation_input,import_evaluation_input_retained}`.

The control API supports native clients and services and retains session/engine dependencies;
it is not a WebAssembly format library. Live `SessionEventLogHub` and `SessionEventLogStream`
exports now belong to `crucible_control_server`. Client control/watch stream `Rpc` variants
contain `Box<RpcControlStream>` / `Box<RpcWatchStream>`; wrap direct construction in `Box::new`
when adapting incoming code. The scratch handoffs include the 242-symbol ownership map for the
former `crucible-api` exports.

Registry transport receives `&dyn aos_transfer::progress::TransferObserver`, not a terminal
`Printer`. `TransferObserver` supplies default no-op `observe`, `info`, `warning` and a neutral
`transfer(label, total_bytes)` handle. `TransferProgress::new` accepts a `ProgressSink`; its
default retains silent counters, and clones share the sink. Sinks expose phase/activity-phase,
total/position/count, warning, finish/abandon and elapsed/position operations.
`aos_cli_ui::output::Printer` implements the observer directly, so CLI callers pass `&printer`;
UI transfer handles convert to neutral handles without discarding their renderer. Headless
consumers can use `NoopObserver` and disable the optional transfer-engine feature.

Registry `sync_git`, `sync_git_with_continuity`, and fetch
`resolve_objects`/`resolve_objects_with_progress` consume the neutral observer. Command
selection, consumer state persistence, aggregated errors, diagnostics and JSON output live in
`aos_package_manager::update::run(&ApmConfig, Option<&str>, &Printer) -> Result<()>`.
`aos_registry_client::sync` retains only result/error data; its old command
`run`/`run_with_options` entry points are removed. Do not restore a CLI UI dependency in
registry-client when rebasing.

Both Git acquisition APIs return the single canonical `aos_registry_client::sync::SyncResult`;
the duplicate `registry::git::SyncResult` is removed, so update explicit return
annotations/imports to the sync owner. `RegistryVerificationError` carries typed trust-roster,
signing-key and continuity refusals without terminal recovery instructions. CLI recovery text
is supplied by `aos_package_manager::update::verification_message(&RegistryVerificationError)
-> String`.

Shared DSSE envelope types, pre-authentication encoding and signature/payload namespace
constants belong to `aos_registry_format::provenance`. Production signer traits, external
signing orchestration, private-key operations and Ed25519 key generation belong to
`aos_registry_authoring`. Reader-side signing/key-generation helpers are available only under
explicit test/test-support configuration for authenticated fixtures; do not enable that feature
to restore production authoring or add private-key operations to registry-client. Keep
established DSSE payload/namespace strings and signature bytes unchanged when updating Rust
imports.

Reuse schemas field by field without changing bytes or acceptance behavior.
`InstalledPackageRecord` and `PackageInventoryDetails` now live in
`aos_deployment_format::inventory`; supply immutable inventory to deployment/image verification
rather than depending on package-manager state APIs. Outer installed records retain their
established Serde behavior and defaults for `expires_at` and `apm`. The nested
`PackageInventoryDetails` retains `deny_unknown_fields`, including optional
deployment/module-documentation/qualification metadata and attestation defaults. Do not tighten
the outer record or alter omissions/defaults as a side effect of type movement.

OCI canonical JSON intentionally stays in `aos_oci_types::canonical`: it admits extension keys
outside ASCII and full-width integer values, and follows its existing Serde schema/duplicate
behavior. Strict authenticated AOS JSON in `aos_core::json` has different rules. Compare exact
decoding, integer range, duplicate handling, canonical ordering and identity domains before
sharing an implementation. Likewise portable node/RAM process formats and Terrane formats
retain their existing license/encoding contracts.

## Dispatch implementation and boundaries

PR #716 now implements five Apache-2.0 packages: model, protocol, runtime, facade and
publish=false conformance. Rename the facade `dispatch` to `dispatch-sdk`; keep its installed
`dispatch` executable and optional CLI/runtime/protocol features. Defaults currently enable
CLI/runtime; pure consumers select `default-features = false`. Keep the worker with runtime
and the systemd probe with conformance. The native C++ Rebalancer stays a separate process.

Pure model validation/evaluation uses exact integer/rational arithmetic and has no native
engine or async dependency. Protocol currently has unconditional Tokio: its canonical/wire
DATA does not make the whole package async-free. Review feature isolation if consumers need
it; do not create another crate without a concrete boundary. Runtime owns scoped sessions,
providers and supervision, with opt-in systemd support and Unix process dependencies.
Conformance independently checks finite mathematical oracles, strict interchange and real
processes, and must remain outside the production dependency graph.

Compare Dispatch integer normalization/bounds, duplicate handling, canonical commitments and
identity/version domains against shared JSON/digest APIs before reuse. Keep application
reservation/effect authority outside Dispatch. Preserve metadata source inputs
`protocol/dispatch` and `docs/users/dispatch.md` while moving manifests.

## Final pinned open-head review

The snapshot contains ten open PRs, including migration #715 and nine owning PRs above.
Exact local objects for six advanced heads (#716, #713, #711, #696, #374 and #232) were read;
the other three retain their prior pins. #716 adds the five implemented packages above.
#713 adds real Hub consumers for its coordinator and policy/source crates, with durable
assessment and scoped source contracts; its local native HTTP adapter is recorded separately.
#232 protocol adds portable `dispatch_template`/`publication` DATA and an ownership-protocol
dependency, while accepted publication/currentness/activation remain controller operations.
#696 adds a private measurement-workflow daemon executable; its shared quota extraction
must stay separate from Crucible host resource authority. #711 and #374 add no new packages.

All nine handoffs retain the implemented export table and 242-symbol Crucible ownership map.
Owning-branch builds/tests remain required after migration; this audit made no owning checkout
changes or validation claim.
