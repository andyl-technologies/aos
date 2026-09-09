# Platform and package integration

## Turn customary relationships into checked interfaces

The existing ecosystem provides the starting vocabulary. Packages retain their
native configuration schemas; abilities expose who consumes them, through
which mechanism, under whose authority, and during which stage. Ordinary
scalar options do not all need to become abilities. A boundary matters when
another component supplies behavior, resources, or a guarantee.

| Existing surface | Proposed consumption contract |
| --- | --- |
| Package executable | Execute an exact artifact on a specified platform |
| Shared library | Link/load a specified ABI with exact retained artifacts |
| Package configuration contribution | Contribute to an authorized owner and slot |
| Systemd service/unit | Use a particular manager and supported unit semantics |
| Credential reference | Deliver a secret to an authorized workload context |
| State/runtime directory | Acquire storage with ownership and lifetime rules |
| Network endpoint | Bind/connect within a named network scope |
| Firewall policy | Request enforcement through an authorized policy provider |
| Initrd facility | Consume an available early-boot provider |
| Image construction | Produce a typed bootable or userland artifact |
| Container launch | Instantiate an artifact under a separately granted runtime contract |

The current [service documentation model](../../../lib/service-documentation.nix)
already distinguishes service owners from payload-only packages. Ability
contracts should gradually supply that classification and its explanation.

## Systemd is a package and a scoped runtime provider

Installing the systemd payload supplies executables and integration metadata.
A running manager with a checked control connection supplies runtime service
management. These identities must not be conflated. The host system manager,
an initrd manager, a user manager, and a container-local manager are distinct
instances with different resources and lifetimes.

Packages continue to author typed systemd units. The interface includes the
semantics they require: identity, directories, credentials, namespace setup,
dependencies, reload behavior, restart policy, and hardening. A unit name alone
does not select a manager. `After` ordering does not establish readiness or
required-success behavior; those are separate dependencies in the plan.

The renderer must know the target environment before adding host-only sandbox
helpers or unit directives. Current host and initrd renderers are separate
surfaces in [system.nix](../../../modules/systemd/system.nix) and
[initrd.nix](../../../modules/systemd/initrd.nix). They should consume
stage-specific bindings rather than generate one host contract and remove
unsupported directives afterward.

There are two explicit container strategies:

- A system container supplies a local systemd manager and the runtime
  facilities needed by its selected units.
- An application container supplies a narrower foreground-process interface.
  A package must support that interface, or an adapter must prove that the
  selected unit subset preserves its required semantics.

Neither strategy means granting arbitrary privilege to make a unit start.
The [systemd container interface](https://systemd.io/CONTAINER_INTERFACE/)
describes concrete runtime requirements, including cgroup delegation and
filesystem/device arrangements. Its limitations are inputs to compatibility
validation, not details an image can satisfy by containing systemd binaries.

## Worked nginx integration

The baseline [nginx package](../../../pkgs/networking/nginx.nix) owns its
configuration interface and service declaration. Its integration includes
generated configuration, dynamic identity, runtime/state directories,
credential paths, service lifecycle commands, and network requirements.

The provider implementation should make these uses explicit:

| Concern | Binding and validation |
| --- | --- |
| Virtual hosts/upstreams | Authorized named contributions into the nginx instance |
| Rendered configuration | Exact artifact and managed publication location |
| Runtime directory | Instance-scoped writable runtime storage |
| Persistent state/logs | Correct identity, permissions, retention, and persistence |
| TLS credentials | Opaque credential references delivered to the selected unit |
| Listening | Authorized ports and network scope; privileged-bind permission when needed |
| Backend connectivity | Bound endpoint reachable in the nginx network context |
| Validation/reload | Exact nginx payload and selected manager, with candidate-view checks |
| Isolation | Required sandbox guarantees supported by the target executor |

For example, a credential path currently tied to `nginx.service` must be
derived from the selected unit/delivery contract before supporting multiple
instances or managers. Rewriting a path is insufficient unless the provider
actually delivers the credential there. `DynamicUser` cannot be dropped while
claiming equivalent identity and directory ownership semantics.

Host paths in configuration must be classified. A generated nginx config
artifact, an authorized persistent directory, and an arbitrary host path are
different resources. The provider may project an authorized resource into a
container view; it cannot reinterpret every path as permission to mount it.

## Kubernetes and aggregate packages

The baseline [k3s worker role](../../../pkgs/kubernetes/k3s-worker.nix)
composes payloads and configuration. Depending on containerd does not imply
that an independent containerd service should be started. The
[Cilium package](../../../pkgs/kubernetes/cilium.nix) contributes integration
configuration rather than owning a standalone service in this model.

An ability edge can therefore mean "contribute a CNI configuration" or
"provide a runtime executable to this role" instead of "start dependency."
A Kubernetes object interface must include namespace, resource-kind, and
authorization restrictions. Applying RBAC or cluster-scoped resources requires
the corresponding grant; a schema-valid object is not authorization.

Kubernetes remains responsible for its reconciliation loops. AOS submits a
desired revision and checks the agreed completion condition. Runtime-created
endpoints enter typed observations or subsequent materialization, not an
implicit read from the Nix evaluator host.

## Initrd, boot stages, and handoff

An initrd consumer can bind only facilities present in its early-boot closure
and available before it is needed. It cannot depend on host-stage storage or
credentials that it must itself unlock. Stage labels, initialization order,
and bootstrap prerequisites are part of the contract.

The [boot substrate](../../../modules/services/boot-substrate.nix) and
[initrd builder](../../../modules/base/_initrd-builder.nix) already own
staged mounts and artifact assembly. Model these relationships explicitly
without inventing a second independent boot orchestrator.

Handoff preserves logical resource identities and defined durable state. It
does not serialize pointers or blindly reuse a handle from another manager,
mount namespace, or boot. Reacquisition must check the new stage's authority.
Boot-critical requirements cannot be treated as optional degraded services.

## Security and networking

Security presets express requested policy. A bound provider must supply the
actual enforcement mechanism and evidence appropriate to that mechanism.
An attribute named `isolated` or `encrypted` does not establish either property.

Network contracts distinguish namespace membership, address/port allocation,
DNS, route policy, inbound publication, and egress enforcement. A container's
ability to listen locally does not imply host ingress or permission to modify
host firewall rules. Policy changes precede exposure when the policy is a
required guarantee. Removal ordering must close access before releasing its
enforcement resources.

The proposed sandbox brokers in [PR #232](https://github.com/andyl-technologies/aos/pull/232)
remain the resource and enforcement authorities. This RFC supplies typed
consumption and composition above those brokers. Administrative ancestry does
not require recursively nested container processes.

## Images are artifacts; launch supplies the runtime

An image builder consumes package artifacts, filesystem construction, and
possibly kernel/boot interfaces. Its result describes an artifact, not a live
grant. The [container image module](../../../modules/image/container.nix)
builds userland separately from a bootable host image.

An OCI image's launch defaults cannot grant cgroups, mounts, kernel features,
or manager access. These come from the selected runtime and operator policy.
Source builds should emit unresolved deployment obligations when runtime facts
cannot be established until launch. Admission checks those obligations before
activation, including for images that passed all static checks.

## Build tools and dynamic libraries

The same consumption vocabulary also refines build dependencies. Distinguish
executing a tool on the build platform, linking target code, loading a library
at process startup, invoking a helper later, and consuming an immutable data
artifact. Phase and platform must be explicit, especially when cross-compiling.

The current [derivation environment](../../../lib/derivations.nix) derives
include, library, and related search paths from dependency sets. A typed edge
can make the intended subset visible, but declarations alone do not prevent
ambient search paths from selecting a different dependency. Narrow per-action
inputs and preserve [runtime closure audits](../../../lib/build/runtime-closure-audit.nix).

A library interface includes target platform, ABI constraints, linkage mode,
and exact artifact identity. ELF consumers additionally need the relevant
SONAME, loader/search-path, and symbol-version expectations. A matching name
does not prove binary compatibility. Verification must inspect actual outputs,
including plugins and runtime loads that ordinary link-time edges may miss.

Initially, library consumption remains bound to the built artifact and its
retained closure. Installing a new provider does not substitute it into an
existing binary or change ambient `LD_LIBRARY_PATH`. Deployment-time library
rebinding would need its own compatibility, provenance, isolation, and rollback
design. An in-process library can exercise the process's ambient authority;
calling it an ability does not create an isolation boundary.

Preserve the Crucible/QEMU process and license boundary. Typed dependency
consumption does not authorize Apache host code to link a QEMU implementation,
nor permit native objects in the shared-memory protocol. Any later boundary
change remains subject to the required ABI and licensing gates.
