# Abilities, handles, and typed dependency consumption

## Terms

| Term | Meaning |
| --- | --- |
| Package | Authenticated distribution and authoring unit with exact artifacts |
| Instance | One configured deployment of package behavior in an environment |
| Interface | Versioned request/result schema and semantic obligations |
| Ability | An implementation offering operations or resources through an interface |
| Provider | Package or trusted environment component implementing an ability |
| Request | A consumer's required interface, parameters, scope, and guarantees |
| Grant | Operator/environment authorization to perform specified operations |
| Binding | Exact authorized connection from one request to a provider/resource |
| Handle | Runtime reference to a concrete scoped resource, acquired through a trusted provider |
| Effect | Requested state-changing operation with preconditions and outcomes |
| Plan | Validated bindings and transition operations for a specific desired state |
| Observation | Evidence about actual resources, operations, or workload state |

An interface identity is not merely a package version. One package can export
several interfaces, and several eligible providers can implement an interface.
One package can have multiple deployed instances, with distinct identities,
configuration, namespaces, credentials, and resources.

Linux `CAP_*` process privileges are one particular resource/permission kind.
They MUST NOT be conflated with the broader ability vocabulary.

## Nested boundaries and a graph of abilities

The execution model resembles an onion: outer environments bound the powers
available to inner environments. The available abilities form a graph, not a
single privilege ladder. A container may have a service manager and no device
access; another may have an accelerator device but no service manager.

```text
Kernel and administrator authority
  -> host resource providers
    -> authorized container or sandbox environment
      -> local service manager
        -> package service and its granted resources
```

This is a model of authority boundaries, not a requirement for recursively
nested containers. Logical ancestry and physical placement may differ. In
particular, the sandbox proposal's sibling host-managed runtimes remain valid.

A provider can construct higher-level functionality from its inputs: a
filesystem service can export immutable artifacts; systemd can expose service
lifecycle operations; a database service can expose an application endpoint.
Composition cannot manufacture authority absent from the outer grants.

Three operations remain separate:

1. Discover implementations and target facilities.
2. Authorize requests against operator policy and inherited ceilings.
3. Bind requests to exact resources and acquire usable runtime handles.

Presence of a socket path or package does not establish the identity, scope,
permissions, readiness, or lifetime of the intended provider.

## A typed consumption edge

Each edge records at least the following semantic information. The exact wire
schema is an implementation deliverable, not fixed by this table.

| Field | Purpose |
| --- | --- |
| Consumer identity and request name | Attribute use to a package instance or build target |
| Interface identity and compatibility | Define accepted inputs, outputs, and behavior |
| Provider and artifact identity | Pin the implementation and prevent silent replacement |
| Mechanism | Distinguish linking, executing, mounting, IPC, configuration contribution, and lifecycle operations |
| Phase and environment | Distinguish build, initrd, host, container, and activation contexts |
| Requested operations and scope | Bound authority to named resources and permitted use |
| Required guarantees | State isolation, integrity, persistence, readiness, or consistency obligations |
| Lifetime and sharing | Describe exclusive/shared use, leases, retention, and release |
| Provenance | Explain declarations, policy grants, and selection decisions |

Example edges include:

| Consumer | Provider interface | Consumption |
| --- | --- | --- |
| nginx build | OpenSSL development interface | Target headers and linker inputs |
| nginx process | Exact OpenSSL library output | ELF loading inside the process |
| nginx service | Local systemd manager | Service lifecycle |
| nginx configuration | Credential provider | Named runtime TLS paths, without secret bytes in evaluation |
| Application package | nginx virtual-host interface | Authorized named configuration contribution |
| Application instance | Database instance | Authenticated protocol endpoint |
| Image builder | Package artifact provider | Immutable closure materialization |

## Graph projections

The unified model MUST preserve different graph meanings:

- **Build:** tools and inputs required to construct an artifact, including the
  platform on which a tool executes and the platform it targets.
- **Configuration:** ownership, contributions, and value dependencies.
- **Activation:** prerequisite operations, commit boundaries, and health gates.
- **Communication:** runtime endpoints and their consumers.
- **Authority:** grants, delegation, attenuation, and enforcement.
- **Retention:** artifacts needed by retained generations or active consumers.

A build or preparation cycle is invalid unless explicitly broken by a
supported bootstrap phase. Runtime communication may be cyclic. Recursive
Nix definitions do not make an undefined value cycle valid. The complete graph
MUST NOT be forced into one DAG whose edges all imply startup ordering.

Resource conflicts require more than topological sorting: two consumers may
compete for a port, identity, configuration slot, mount destination, or
exclusive device despite having no dependency edge between them.

## Abilities and guarantees

An operation such as starting a process is an ability. A promise that the
process cannot access another instance's state is a guarantee. Multiple
mechanisms may implement a guarantee, but compatibility requires an explicit
approved equivalence, not a similarly named setting.

Required guarantees MUST either be implemented and checked or prevent
activation. Optional behavior and advisory optimization MUST be declared as
such. A missing sandbox mechanism cannot disappear from the plan while the
service is reported as equally confined.

Native applications may retain ambient authority. The contract MUST identify
that authority and the actual enforcement boundary; a typed declaration does
not prove every syscall is mediated or every effect was inferred.

## Identity, handles, and revocation

Nix values and serialized plans carry logical references, not privileged file
descriptors. Runtime handles MUST be acquired from authenticated providers and
bound to the intended object, namespace, assignment, and lifecycle generation.
Raw paths, PIDs, descriptor numbers, and interface names are diagnostics, not
portable proofs of authority.

Persistent records retain logical bindings and provider evidence. Actual
handles are reacquired and verified after restart. A stale handle or snapshot
cannot authorize a new incarnation. Where the sandbox runtime provides
ownership leases and fencing, consumers MUST use that existing contract.

Removing a declaration does not necessarily revoke an already-open descriptor
or unload library code. Providers MUST specify their actual revocation behavior:
close, fence, stop the consumer, restart it, or report that immediate revocation
is unavailable. Required revocation guarantees are part of compatibility.

## Invariants

- **A1:** Availability does not grant authority.
- **A2:** Every effect is attributed to an authorized consumer/provider binding;
  opaque implementations are explicitly classified rather than assumed safe.
- **A3:** Child requests cannot exceed inherited policy ceilings.
- **A4:** Required guarantees cannot be weakened silently.
- **A5:** Package, instance, interface, resource, and generation identities are
  distinct and versioned where they cross a persisted boundary.
- **A6:** Static matching and late resolution validate the same contract.
- **A7:** Evaluation produces data and artifacts; privileged runtime effects
  occur only through authorized implementations.
- **A8:** Exact artifact retention and existing store-reference tracking remain
  authoritative even when richer consumption metadata is available.
- **A9:** Rollback and restart revalidate current authority and environment
  obligations; historical success is not a perpetual grant.
- **A10:** New interface declarations do not automatically authorize new
  privileged operation implementations.
