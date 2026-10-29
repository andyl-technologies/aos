# Runtime abilities and deferred execution

A package distributes built software and, optionally, an immutable Nix module.
Interface, implementation, package, and operator modules compose through one
recursive `options`/`config` fixed point per installation scope. An ability
operation declares typed input and result modules; its selected handler is a
retained program or a composition of other operations. Evaluation produces a
deferred effect graph as data. Rust checks that graph, executes the selected
handlers, and retains results and generations.

This directory describes the implementation. The author-facing examples are in
[Runtime abilities](../../users/aos/runtime-abilities.md), and the inspection
commands are in [Inspect runtime abilities](../../users/aos/ability-inspection.md).

- [Evaluation](evaluation.md) covers package envelopes, module resolution, the
  evaluation-input descriptor, restricted evaluation, and generated reference
  documentation.
- [Execution](execution.md) covers graph admission, the handler process
  protocol, identity and lifetimes, generations, recovery, retention, and
  container bootstrap.

```mermaid
flowchart LR
  modules["Package and system modules"] --> evaluation["Nix fixed point"]
  evaluation --> graphData["Typed effect graph"]
  graphData --> runtime["Package transaction runtime"]
  runtime --> handlers["Selected handlers"]
  handlers --> primitives["OS primitives"]
```

## Ownership

The generic library in `lib/` owns recursive evaluation, typed submodules,
conditional definitions, priorities, provenance, deferred module values, and
typed output references. It contains no service, networking, database, or
init-specific lowering, and no runtime dispatches on package names.

Domain interfaces belong to the packages or system modules that own the
resource. For example, `serviceManagement` is declared by
`pkgs/system/_service-management/`, its systemd handlers live in
`pkgs/system/_systemd-abilities/`, and `initSystem.install` is declared by
`pkgs/system/_init-system/module.nix`. Independent modules may define or extend
the same domain and operation trees through ordinary imports and option merging.
A domain manager reuses its operation's input module for convenient user options
and derives effects from the final merged configuration.

Handler selection is ordinary module configuration under the operation's
`handler` option. There is no separately authored provider map, interface
registry, or runtime discovery loop. Generated documentation projects the same
fixed point, so there is no independently maintained ability catalog either.

## Operation shape

The authoring tree is declared by `lib/effects/module.nix` and
`lib/effects/execution.nix`:

```text
aos.abilities.<ability>.operations.<operation>
  input                         deferred module declaring input options
  result                        deferred module declaring result options
  handler                       selected deferred handler module, or null
  effects.<instance>
    enable                      whether to include this effect
    input                       configuration checked by the input module
    lifetime                    instance | transaction | persistent
    after                       explicit typed output dependencies
    timeoutMs                   bounded process duration
    outputs.<result>            read-only typed output references
    execution                   evaluated handler configuration
  module                        read-only reusable effect submodule
  documentation                 derived operation reference
```

A handler sets either `program` or composes `children` and `exports`. Child
modules import the lower operation's `module`, so their inputs merge and
typecheck through that operation's schema. `types.deferred T` admits a concrete
`T` or a compatible output reference; references induce graph dependencies.

A handler also declares `phase = "installation"` (the default) or `"startup"`.
Startup effects, and effects that depend on them, stay pending during
installation into an inactive runtime such as a container image build.
Independent filesystem and configuration effects can execute immediately. The
graph retains every enabled effect.

An enabled effect without a handler, an incompatible reference, a conflicting
definition, or an invalid composition fails evaluation before any mutation.
Unused interface declarations and documentation-only evaluations need no
selected handler.

## Phases

1. **Build** realizes payloads, retains module source, and generates the
   deployment envelope and documentation artifact. No activation runs in a
   build, and payload construction does not force deployment evaluation.
2. **Publication** authenticates the exact artifacts and dependency identities
   through the registry release machinery. Publishing a document does not
   authorize or perform its effects.
3. **Evaluation** resolves one exact package and module closure for a scope,
   then evaluates package, operator, and runtime modules with fixed inputs, pure
   restricted Nix, and import-from-derivation disabled. It returns the desired
   transaction and documentation without building or mutating the host.
4. **Execution** admits and retains the required artifacts, validates the
   generated graph, prepares a durable generation, executes handlers in
   dependency order, and checks their results.
5. **Reconfiguration** evaluates new desired configuration and reconciles it
   against retained state. Removal, interrupted work, rollback, and pruning use
   the same transaction and effect state machines.

Package, profile, container, and host scopes all use this machinery. OS boot is
a consumer rather than a separate whole-host interpreter. Host and operator
modules select packages with `aos.apm.desiredPackages`
(`pkgs/system/_aos-host-policy/package-selection.nix`); package roots and their
configured effects commit in the same generation.

## Code map

| Responsibility | Implementation |
| --- | --- |
| Option merging and deferred module types | `lib/modules.nix` |
| Operation, effect, and handler submodules | `lib/effects/module.nix`, `lib/effects/execution.nix` |
| Operation reference projection | `lib/effects/documentation.nix` |
| Recipe module retention and companions | `lib/build/package-modules.nix` |
| Evaluation-input descriptor | `lib/build/evaluation-input.nix` |
| Package-scope evaluation and documentation | `lib/packages/evaluate.nix` |
| Artifact identity and realized consumption | `aos_artifact_evidence` |
| Portable options, schemas, and graph validation | `aos_module_format::{option,schema,graph}` |
| Effect state machine, journal, and observer boundaries | `aos_activation` |
| Deployment envelopes and descriptors | `aos_deployment_format` |
| Restricted evaluation and private source views | `aos_deployment::{evaluation,source_views}` |
| Process dispatch and artifact retention | `aos_deployment::{handler,process,retention}` |
| Durable generations and recovery | `aos_deployment::transaction` |
| Retained package-generation admission | `aos_package_manager::deployment` |
| Descriptor replay | `aos_package_manager::native_deployment` |
| Reference and graph rendering | `aos_module_docs::runtime` |
| Hub artifact viewer and API | `aos_hub_service::web::runtime_documentation` |

The module format owns portable declarations and checked graphs, activation
owns execution, and module documentation owns rendering, search, and
comparison. Artifact evidence has its own canonical codec and admission bounds
and does not depend on the module or activation framework.

Native handlers for host resources live in `crates/activation/`:

| Crate | Resource |
| --- | --- |
| `aos-activation-sysctl` | Kernel tunables, restoring displaced baselines on removal |
| `aos-activation-nftables` | One owned nftables table, replaced atomically |
| `aos-activation-bpf-lsm`, `aos-activation-bpf-network` | Package-selected BPF LSM and network policy pins |
| `aos-activation-filesystem` | Storage allocation and non-overlapping filesystem views |
| `aos-activation-config-files` | Configuration files with durable ownership receipts |
| `aos-activation-storage` | Block devices, encryption, and ZFS pools |
| `aos-activation-nix-store` | Local Nix database convergence and persistent objects |
| `aos-activation-kubernetes` | K3s configuration and Kubernetes object sets |
| `aos-activation-crucible` | Optional Crucible observation of the executor |

The systemd service, resource-group, and container-bootstrap handlers are
Python programs in `pkgs/system/_systemd-abilities/`. The
[service sandbox](../packages/service-sandbox.md) page describes how service
inputs become unit directives.

## Verification

`checks.effects` (`tests/effects/`) evaluates recursive contracts, merging,
composition, deferred outputs, ownership, stage isolation, and artifact
freezing, then builds real publication artifacts for a small package closure.
The Cargo example `package_deployment_check` in `aos-package-manager` consumes
that fixture and exercises publication, deployment-time evaluation, process
handling, generation recovery, reconfiguration, and pruning. Rust unit tests
cover interruption at the generation/effect commit boundary and during root
cleanup.

These checks prove the infrastructure, not a particular image. A release claim
must bind the exact candidate artifacts, source context, selected handlers, and
independently observed domain evidence; see
[qualification](../../maintainers/qualification.md). Observations come from the
domain (service-manager state, account records, filesystem contents, network
behavior, cluster state, or image identity). The activation journal adds
ordering and durable result evidence but is not an independent oracle for the
mutation it records. A test wrapper that controls a handler's responses
qualifies that wrapper and backend composition, not the unwrapped handler.
