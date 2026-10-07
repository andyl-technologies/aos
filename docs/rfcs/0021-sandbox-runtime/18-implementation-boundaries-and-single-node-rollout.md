# Implementation boundaries and single-node rollout

This amendment is normative for implementation scope, crate ownership, and
delivery order. It supersedes earlier wording that includes coordinator
implementation in initial delivery, puts placement in the local Controller,
or treats broad source coverage as a completed runtime. The complete product
design remains documented; not every described feature belongs in the first
implementation phase. This scope is specific to RFC-0021, not Crucible.

These are target boundaries and migration requirements, not a claim that the
current source already satisfies them. The [production authority
amendment](17-production-authority-closure.md) continues to govern admission,
custody, currentness, fencing, and recovery. A smaller deployment scope never
permits weaker authority checks or fabricated readiness.

## Delivery boundary

The first implementation phase targets one host, one local Controller, and
locally provisioned ownership authority. The first end-to-end milestone is:

```text
public CLI/API -> Create -> boot/Ready -> execute/observe -> Stop -> Delete
```

It includes private writable storage, private default-drop networking, the
selected nspawn backend, Guest execution, Guardian expiry, hard resource
admission, and restart reconciliation. Every required producer and protected
handoff must exist; an unqualified backend or missing authority remains closed.
The normal installed path, not a separately implemented canary, establishes
completion. CLI delivery cannot wait for a fleet coordinator.

This milestone also includes the minimal protected Source ancestry, Cache,
Publisher, Policy and compiler/deployment currentness producers required by
section 17's Create contract for the selected profile. Deferring their richer
user-facing features does not defer those admission owners, invent empty
authority, or bypass the held cross-owner decision.

Subsequent single-node slices add native attachment/hierarchy, local snapshots
and restore, environments/cache/Git, advanced local policy, and immutable FUSE
in the order in [the implementation plan](14-implementation-plan.md). Optional
FUSE and remote-source profiles do not block the first local lifecycle. Each
advertised profile must pass its own admission and conformance requirements.

The first implementation phase does **not** implement or enable:

- fleet discovery, cross-node placement, draining, or reassignment;
- coordinator/node remote transport, reconnect/resync, or coordinator watches;
- cross-node snapshot transfer or destination restore orchestration;
- cluster consensus, failover, federation, or cluster networking; or
- multi-node services, configuration, credentials, or background workers.

Their contracts remain documented for a later implementation phase. A local
request selecting another node fails explicitly rather than entering a dormant
remote path. Local scheduling means capacity admission and choosing among
eligible resources on this host, not distributed placement.

Stable node IDs, assignment epochs, ownership leases, boot/incarnation fences,
Guardian deadlines, and protected snapshot inventories remain local safety
requirements. Local ownership must not require coordinator code, a simulated
fleet, or an online off-host service. It retains the independently protected
local authority and any required provisioned local floor; it does not claim
cross-host exclusivity or whole-host rollback resistance without their proofs.

## Dependency direction

Arrows below mean "depends on", not IPC or privilege inheritance:

```text
local application assembly -> local Controller / domain integration
domain integration         -> authenticated session / domain effect owner
domain effect owner        -> shared data / journal / Linux mechanics

later coordinator assembly -> coordinator implementation
coordinator implementation -> coordinator protocol / local-control contracts
```

The local Controller and every shared foundation must be independent of the
coordinator implementation. Domain effect owners do not import Controller
orchestration. Data/protocol crates do not import effect owners or application
assembly. Sharing a crate never combines service identities or privileges;
separate daemon custody, sockets, MAC domains, and failure domains remain.

## Target crate ownership

Names marked **new** describe planned extractions. Existing names describe
target responsibilities, not an inventory of current dependencies. A new
crate needs a cohesive owner, a useful dependency boundary, and concrete
consumers; a helper or individual protocol phase does not warrant a crate.

### Shared data and mechanisms

| Crate | Ownership | Excluded |
| --- | --- | --- |
| `aos-sandbox-core` | Portable IDs/models, policy math, capability descriptions, nonauthorizing backend/control contracts, shared bounded codec primitives | Filesystem ownership, Linux effects, service startup, coordinator-only models |
| `aos-proto` | Shared public and node-local generated schemas | Coordinator-only generated services and transport |
| `aos-sandbox-protocol` and role-specific protocol crates | Canonical local messages, signatures, decoded evidence, pure semantic validation | Keys, FD custody, runtime implementations, listeners |
| `aos-sandbox-journal` (**new**) | Generic framed transactions, locking, durability, replay, bounded capacity mechanics, compaction | Domain namespaces/transitions, signers, Controller plans, arbitrary authority issuance |
| `aos-sandbox-linux` | Audited UAPI, owned descriptors, fixed process/namespace/syscall mechanics | Product policy, wire authority, application assembly |
| `aos-systemd` | Typed manager transport and unit/cgroup observations | Sandbox policy and daemon orchestration |

Domain namespaces, typed record validation, protected writer admission,
transition rules, historical membership, and semantic commit belong to the
domain owning the state. Generic journal replay returns data and durability
outcomes, not domain authority. Moving codec primitives into core must not
move role-specific validation or canonical signing domains there.

Agent wire values needed by protocol consumers remain in a portable module
of `aos-sandbox-agent`; Linux executable/bootstrap/effect code moves to Guest
or application ownership. Protocol crates must not depend on a concrete agent
executable implementation merely to use shared message types.

### Local authority and Controller

| Crate | Ownership | Excluded |
| --- | --- | --- |
| `aos-sandbox-broker-session-security` | Protected credentials, peer/process authentication, session sequencing, replay/currentness, sealed transport custody | HTTP/API registration, concrete domain dispatch, Controller reconciliation, unrelated binaries |
| `aos-sandbox-broker` | Common protected broker admission/configuration, plan/lease verification and authenticated record mechanics | Controller implementation, generic domain authority issuance, domain-specific semantic commits |
| `aos-sandbox-ownership` (**new**) | Protected local lease issuer, durable epoch/floor and inventory ownership currently misplaced under `multi_node` | Fleet membership, placement, remote transport, consensus |
| `aos-sandbox-policy` (**new**) | Policy compilation, independent Root binding/held-cut decisions, role-specific semantic commit and recovery | Generic journal implementation, daemon listener loops |
| `aos-sandbox-source` (**new**) | Source ancestry/genesis/successors and protected source-domain state | Source-provider physical acquisition, remote coordinator transport |
| `aos-sandbox-cache` (**new**) | Residency, consumer/object pins, quota, eviction and physical currentness | Filesystem presentation, Controller lifecycle, shared writable cache semantics |
| `aos-sandbox-publisher` (**new**) | Immutable publication, publisher policy, admission and protected catalog transitions | Guest execution and general Controller routing |
| `aos-sandbox` | Local admission, desired state, lifecycle orchestration, reconciliation, public projections and local-control implementation | Privileged effects, coordinator placement, generic security/journal engines |
| `aos-sandbox-client` (**new**) | Public API client, credentials and observation/operation handling used by CLI | Controller/effect-owner dependencies and privileged runtime closure |

The local ownership extraction follows the actual protected owners, not their
current names: leases and inventory used for local recovery move below the
coordinator boundary; remote transfer planning does not. An ownership crate
does not acquire all domain inventories simply because they share a journal.
Resource-specific inventory authority remains with its physical owner.
The existing broker facade becomes the owner of its common authority engine,
not a reexport of Controller implementation. Physical role/namespace admission
and semantic commit remain with the respective domain owner.

### Effects, views, and application assembly

Host, Storage, Mount, and Network retain their existing implementation crates
(`aos-sandbox-host`, `aos-sandbox-storage`, `aos-sandbox-mount`, and
`aos-sandbox-network`). Guest and Guardian retain `aos-sandbox-guest` and
`aos-sandbox-guardian`. They own concrete role-specific effects, independently
verified observations, and their protected state; they do not host the public
Controller or import its implementation.

The four Source-provider crates retain distinct responsibilities:
`protocol` owns decoded messages, `ledger` owns pure records/reducers,
`security` owns protected key/process/descriptor custody, and the provider
owns durable acquisition/effect/recovery orchestration. Common mechanics are
shared without merging those authority boundaries.

`aos-filesystem-view-core` owns portable view semantics;
`aos-filesystem-view` owns realization/metadata state; and
`aos-filesystem-fuse` owns its narrow FUSE ABI and worker behavior. Git/Nix/OCI
adapters are source-specific modules behind view/publisher contracts, not
special cases in the Controller or mount broker. Filesystem consumers may
depend on narrow authenticated outcome APIs, never application assembly.

`aos-sandbox-services` (**new**) is a thin application package for daemon
entry points, configuration, listener ownership, service registration and
concrete domain/session integration. Role modules such as `controller`,
`host`, `storage`, `mount`, `network`, `policy`, and `publisher` have explicit
feature-selected dependencies and binaries with `required-features`.
There is no default "all services" dependency closure. Separately built role
packages may replace this package if they improve closure isolation.

Cargo `required-features` controls binary selection, not library dependencies.
Role derivations select isolated package/feature invocations and verify the
actual unified dependency graph, including dependency-artifact and package-test
builds. Do not build all roles together and infer isolated closures from the
names of separately installed binaries.

Assembly may join a session capability to a concrete domain owner through
safe APIs, but does not duplicate business state machines or expose signing
seeds. Shared application setup remains private. A Controller client does not
link broker effect implementations just to send local requests. The `aos`
CLI uses the client crate; privileged helpers remain separately packaged.

## Interface contracts

These are internal Rust interfaces, not a stable ABI or authorization plugin
system. Exact signatures follow the selected existing semantics and owned
types. Interfaces are introduced for real boundaries, not anticipated plugins.

| Interface | Declaring owner | Operations and contract |
| --- | --- | --- |
| `LocalNodeControl` | Portable control contracts in core | Submit a bounded desired-state proposal; inspect capabilities, operation and inventory projections. The local Controller independently authenticates/adopts proposals; no host paths or trusted observations enter through this port. |
| `LocalAdmission` | Controller | Admit resources/affinity on this host or return a typed rejection. It never discovers nodes or grants ownership leases. Later placement consumes its nonauthorizing capability information. |
| `RuntimeBackend` | Portable backend contracts in core | Prepare/start/observe/stop/recover under admitted, operation-bound inputs. Opaque handles retain incarnation/custody; ambiguous effects return retained recovery state, not inferred success. |
| `StorageEffects`, `NetworkEffects`, `MountEffects` | Respective domain crate | Execute a closed typed plan under the domain's protected permit, then independently verify physical results. No arbitrary command, property map, rule text, path or FD role is accepted. |
| `SourceProviderBackend` | Provider contracts | Class-specific acquire/inspect/release with exact retained source identity. Backend output is untrusted until protected owner verification; unsupported physical classes remain unavailable. |
| Journal transaction API | Journal crate; typed wrapper in each domain | Compare expected head, append a bounded transaction and return applied/uncertain/failure outcomes. Domain wrappers alone admit semantic transitions and resolve ambiguity. |
| `WorkerExchange<Profile>` | Shared local transport/Linux mechanics | Fixed executable/peer, READY, bounded records/FDs, deadline, ACK and quiescence. Profiles supply closed roles/formats, never caller-selected commands or keys. |

Traits may expose untrusted proposals or observations, but implementations
cannot manufacture verified grants, receipts, currentness witnesses or ready
states. Those types have private fields and constructors controlled by the
protected owner. A boolean "verified" result, scalar digest, or caller-supplied
timestamp is never sufficient evidence. Verification remains mandatory even
when a backend is injected for composition.

Authority-bearing scopes preserve writer borrows, descriptor ownership,
operation identity and fencing until durable commit/effect handoff. A trait
call cannot detach that scope, widen its lifetime or expose a signer. Test
doubles stay under test compilation; externally supplied backend data passes
the same production validation. Independently deployed backends use versioned
IPC, not privileged dynamic loading or Rust layouts across processes.

## Shared modules and legibility

Each domain separates, where useful, `model`, `codec`, `admission`, `owner`,
`effects`, `observation`, and `recovery`. These are responsibilities, not a
requirement for empty modules or identical directory templates. Service setup
belongs in assembly; reusable mechanics belong below domain owners.

Share bounded readers/writers, checked arithmetic, worker exchange mechanics,
method registries, retained-result/first-failure bookkeeping and test builders
where behavior is genuinely repeated. Keep canonical domains, semantic
preconditions, physical verification and crash boundaries explicit. One
declarative method registry supplies shared metadata; it does not replace
method-specific verification with a generic permissive dispatcher.

Do not introduce a universal owner/context containing every role, a field for
every hypothetical backend, forwarding layers without a contract, or a new
record family per refactor. Implementation and co-located tests are reviewed
separately under the repository's file-size and documentation standards.

## Multi-node boundary reserved for later

`aos-sandbox-coordinator-protocol` (**new**) owns coordinator-only generated
schemas, messages, version negotiation and assignment/watch/transfer models.
`aos-sandbox-coordinator` (**new**) owns fleet placement, draining, remote
reconciliation, transfer and coordinator transport. Shared identities and
local ownership contracts remain below both crates.

The application-level `multi-node` feature is off by default and uses optional
dependencies. It is not enabled transitively by any local crate, default
feature, local Nix package or system module. Coordinator services and settings
require explicit selection. A source-only feature flag is not production
qualification; remote capabilities remain unadvertised until the later phase.

The local package/default-member selection excludes coordinator crates;
coordinator-only protobuf generation and service registration are excluded
as well. A workspace-wide/all-features build is an explicit development check,
not evidence that the default local package has a coordinator-free closure.
Build checks inspect the actual selected dependency/package graphs.

Existing multi-node code is classified before relocation: necessary local
owners move to local crates; retained future implementation moves to the
optional coordinator boundary; obsolete parallel code is removed. First-phase
work does not expand dormant distributed functionality or simulate a remote
coordinator to unblock local creation.

## Removal and migration plan

1. Map each public/local operation from entry point through admission, owner,
   effect, observation and recovery. Record actual consumers, including
   packaging and selected daemon modes; names such as `Dormant` are not proof
   of absence. Choose one canonical implementation per supported profile.
2. Remove superseded paths with their exports, constructors, codecs, fixtures,
   checks, package selectors and documentation. Test-only consumers do not
   justify retaining an obsolete production implementation. Unfinished required
   paths keep one implementation and explicit fail-closed gates.
3. Extract generic journal/codec mechanics and typed local ownership contracts,
   then move domain state out of the central crate. Move existing code rather
   than retaining a second copy or permanent compatibility facade.
4. Separate session security from concrete integration and application assembly;
   consolidate repeated worker/transition mechanics without opening authority.
5. Extract and default-disable coordinator code, including generated schemas;
   remove remaining local-to-coordinator dependency edges.
6. Consolidate fixtures and module documentation. Keep a compact current
   implementation/evidence index rather than appending another historical
   progress ledger.

RFC-0021 has no deployed protected data at this amendment. Earlier PR-only
formats and APIs receive no automatic backward-compatibility guarantee. Check
remaining consumers and development fixtures before removing a format; never
silently discard retained state. Established formats outside this undeployed
feature keep their own compatibility obligations. Canonical signed semantics
are not reinterpreted under an existing version.

Canaries and tests use the canonical production implementation where possible.
A distinct path needs a documented difference in authority or behavior, not
just a different stage name. Cleanup preserves limits, denial behavior,
ambiguity, lifetime and recovery obligations. Deliberately reserved features
have explicit optional ownership; otherwise unused speculative implementations
are removed rather than kept under misleading compatibility names.

## Exit criteria

The local milestone requires the real public lifecycle above, authenticated
broker/Guest effects, expiry containment, resource failure handling and restart
reconciliation. Component tests or checked historical tasks cannot substitute
for those connected operations. Subsequent features report their own scope.

The boundary cleanup requires:

- one documented current path per operation/profile and no superseded exports;
- acyclic dependencies, with data below authority and assembly above effects;
- a default local dependency/package graph free of coordinator implementation,
  generated coordinator services and remote workers;
- sealed authority types and unchanged independent service confinement;
- shared mechanics with explicit role/semantic validation;
- implementation-target and test compilation for affected Rust packages,
  default and explicitly selected feature graphs, and behavior/fault tests for
  changed invariants; and
- a compact ownership map that distinguishes source, connected behavior and
  qualification, without using LOC or task-checkbox counts as completion.

Use `aos-dev` and AOS-built dependencies for implementation verification. This
documentation amendment does not run qualification, enable FUSE or multi-node,
provision keys/floors, or claim production admission. Later multi-node delivery
requires its own selected package, endpoint fencing, partition, transfer and
rolling-upgrade gates before advertisement.
