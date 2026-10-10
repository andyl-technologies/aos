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

The private `local_inventory::draining::verified_observation` owner is selected
only by `multi-node`. It retains the existing trusted drain evidence factories,
protected joins, commitments and currentness validation. Raw drain reports,
model layouts, phase checks and retained-history validation remain available by
default; decoded history does not become fresh drain authority. This source
boundary does not isolate the remaining protected ownership/Journal dependency
group or qualify distributed execution.

The private `local_inventory::assignment::acceptance_evidence` and
`restore_admission` owners also require `multi-node`. They retain the original
sealed assignment-acceptance and destination restore-admission factories, with
their exact verifier, capability, publication and currentness joins. Local
assignment models, snapshot manifests and resume DATA, and canonical retained
history remain available by default. Destination restore-admission evidence is
not the local snapshot/restore implementation or permission to execute a restore.

Authenticated chunk, dependency-range and protected transfer-checkpoint handoffs
belong to the existing private `assignment::remote_verification` owner, selected
only by `multi-node`. Its original carrier checks, scoped commitments and
streaming/replay validation remain together. Completed snapshot receipts used
by shared drain observations and canonical Journal history remain available by
default; their retained model layouts and recovery validation do not depend on
this selected handoff owner.

The selected `local_inventory::protocol::remote_exchange` owner also retains
complete authenticated resync inventory and watch-bootstrap validation. Raw
inventory, cursor and stable-UID semantics, canonical codecs, and retained
history validation remain available by default.

The complete remote assignment plan and prepared semantic-grant chain also
requires `multi-node`. `assignment::observation_reducer` retains the private
move-only plan and its exact effect commitment; `journal::assignment_effect`
retains the original journal reducer's sealed prepared-grant factory and
reservoir. The selected protected assignment owner still joins that grant to
its committed publication and independently current effect-time carrier.
Default intent and observation models, complete retained-history replay,
partial-effect recovery and Controller lifecycle transfer inventory remain
available. This cut adds no authority or distributed qualification.

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
| `aos-sandbox-protocol` and role-specific protocol crates | Canonical local messages, signatures, decoded evidence, pure semantic validation; `cache_state` owns complete inert Cache accounting, catalog, and partition DATA | Keys, FD custody, runtime implementations, listeners |
| `aos-sandbox-journal` (**new**) | Generic framed transactions, locking, durability, replay, bounded capacity mechanics, compaction | Domain namespaces/transitions, signers, Controller plans, arbitrary authority issuance |
| `aos-sandbox-linux` | Audited UAPI, owned descriptors, fixed process/namespace/syscall mechanics | Product policy, wire authority, application assembly |
| `aos-sandbox-guest-root-tree` | Existing nonauthorizing Guest template comparison, offline digest and complete descriptor-relative tree capture with retained native causes | Guest execution/population/label/publication effects, protected root admission, writer exclusion, resource and readiness authority |
| `aos-systemd` | Typed manager transport and unit/cgroup observations | Sandbox policy and daemon orchestration |

Domain namespaces, typed record validation, protected writer admission,
transition rules, historical membership, and semantic commit belong to the
domain owning the state. Generic journal replay returns data and durability
outcomes, not domain authority. Moving codec primitives into core must not
move role-specific validation or canonical signing domains there.

The Cache DATA enclosure moves the existing accounting owner and catalog
transitions once, without native descriptors, protected capabilities, or live
loans. Protected Cache admission, full and incremental recovery proofs, and
physical/currentness owners remain in domain integration. This is not a complete
Cache extraction or isolation of the Cache signer's native dependency closure.

The concrete native journal pilot now owns the original files and append poison,
configuration DATA, coordinates, identity and namespace-provenance sets, and
materialized DATA map in `aos-sandbox-journal::owner`. The domain wrapper keeps
its semantic indexes, genuine loans, admission and final crossings at their
original steps. Native file replacement retains the original lock and poison;
upper histories and authority-instance rotation remain upper. This contiguous
ownership cut is partial: protected opening, typed replay, compaction admission,
and the protected Policy/Source/Cache/Ownership crate boundaries still require
their separate migrations.

Borrowed native suffix measurement also owns the exact before/after accounting,
signed prefix deltas, raw namespace/key duplicate checks, and checked record and
frame extents in `aos-sandbox-journal::native_suffix`. Actual upper mutation
graphs stay borrowed through measurement; closed owner semantics, Source forecast
buffers, every alternative and historical/current cut, and the final headroom
check remain upper. Removing duplicate key/value and width-only floor buffers
does not move admission, opening, descriptor custody, or authority below the
domain boundary, and is not qualification or a complete protected owner cut.

Protocol's `domain_ledger` owns the complete typed transaction/Idempotency
DATA, legacy capacity-reservation schema and identities, and schema-bound
record/reducer/replay DATA. It reuses generic Journal framing and bounded
mechanics; the original role validators still borrow their actual evidence.
Decoded phases and projections are DATA, not sealed currentness, capacity,
postcommit authority, or physical admission. Domain wrappers retain the real
Journal, protected guards, writer/lock loans, native causes, semantic indexes,
full capacity-family dispatch, and closed authority factories. This shared
DATA boundary is a prerequisite for further role migration, not removal of the
whole protected Journal/Policy/Source/Cache/Publisher dependency cycle.

Protocol's `domain_ledger::public_operation` also owns the complete immutable
public admission/authorization DATA, 64-byte durable metadata, separate closed
durable method registry, shared Operation state DATA and established resource
projection/resourceVersion. Private fields remain private. Its checked DATA
constructors, codecs and projections are publicly accessible across the crate
boundary and return the lower DATA error; Domain directly uses those identities
and converts errors to the original Reconciler variants. This is an explicit
undeployed API cutover, not identical prior visibility. The actual Journal,
protected admission, authentic clock acquisition, Effect/Repair consistency
checks and current public authorization remain Domain-owned. Historical DATA
construction and projection grant no authority and do not complete the
Controller ledger or protected Journal dependency cut.

Protocol's `public_api::mutation_history` owns complete plain/Nix/FUSE historical
DATA selection and context binding, Nix and FUSE canonical carriers, original
authority coordinates and assignment preimages. Canonical codecs, historical
joins, whole preimage comparisons and compiler resource-version hashing share
this owner. Its public DATA constructors and comparisons are an explicit
undeployed API cutover; decoded or assembled history grants no current authority.
The former Native Nix carrier module is removed and callers use the shared owner.

Native retains authenticated capture, protected Journal selection, paid resource
owners, writer/descriptor loans, clocks and all current-authority rechecks. The
public Native FUSE identity keeps a private historical enclosure and its existing
read surface; there is no public raw-history conversion to that identity. This
complete historical-family prerequisite adds API and adapter code and earns no
deletion credit for relocation. It does not complete the durable Effect or
OwnershipGate extraction, remove protected Controller/Journal admission
backreferences, or establish production lifecycle qualification.

Controller mutation Effects require retained authenticated admission context;
the public bare-envelope factory and its acceptance fallback are retired.
Canonical decoding rejects bare V3/V5/V6 rows, including Applied and terminal
history, at the existing request-validation frontier. Such rows can block
whole-ledger reconciliation and public projection; their Journal bytes remain
intact, with no inferred context, automatic upgrade or deletion. Context-bearing
history, broker Effects and reserved Observe children retain their own semantics.

Protocol's complete `domain_ledger::operation` DATA owner now holds both native
Operation record versions, their full decoder and unchecked encoder, all five
private Copy fields, and the Operation/Effect key grammar. Public DATA getters,
infallible field assembly and state/metadata replacement are an explicit
undeployed API cutover; they perform no admission or semantic transition checks.
Domain keeps the original protected Journal, Effect, OwnershipGate, draft,
Idempotency, clock, recovery and currentness recipes and converts lower DATA
errors to the original Reconciler causes at their existing boundaries. Journal's
actual materialized-row Effect key uses Protocol directly. This cohesive format
owner relocates one complete recipe and earns no engine-deletion credit; it does
not complete the protected Controller/Journal boundary.

The complete ordinary/Q04 Effect history codec and its semantic/hash helpers
belong to a private descendant of the Native Effect owner. Original model fields
and factory scopes stay intact; current-authority recipes keep their Native owners.
Domain Journal owns the complete capacity transfer, settlement and Delete recipes;
fixed history operations preserve their original row and error frontiers. Journal
retains opaque original Effect/Gate holders without inspecting Native plans or
drafts. Gate's codec remains with its complete private owner. This organization
removes aggregate recipe callbacks without removing a Cargo dependency or
completing the portable Effect/Gate or protected admission boundaries.

Protocol transaction DATA extent accounting and its duplicate-key index share the lower
journal's `NativeRecordValidation` owner with native suffix measurement. Keys
borrow the actual records; domain Idempotency checks remain between the extent
and key-registration stages. The shared fold adds no admission, configuration
gate, or persistence proof and does not change protected owner boundaries.

The domain journal's private `protected_storage` group co-locates protected
names, descriptor/lock loans, rooted opening and recovery, and complete retained
opening/failure reservoirs. Their original fields, drop order, native causes,
and name bookends remain unchanged; the actual native owner stays private to
Journal. Semantic replay, protected admission, compaction guards, and authority
factories remain domain-owned. This organization adds no constructor, descriptor
escape, or callback and does not complete a protected role-crate migration.

The private `journal::semantic_append` group owns the complete ordinary and
closed semantic append recipes, paired advisory preflights, Q04 adapters and
append-only guards as inherent methods on the original Journal. Its private
`AppendScope` and `PreflightScope` name passive selectors; fourteen escalating
routing methods are retired. Ordinary appends and forecasts use one fixed
entrypoint each. Native appends carry the actual original loans separately to
the unchanged final engine, including all independent Q04 loan lifetimes.

The nine-field forecast scope cannot select project-genesis phases; the original
fixed recipes retain that separate private selection. Append and forecast keep
their distinct validation/error order, state-clone and frame lifetimes, Cache
locks, clocks, first causes and publication chronology. Actual callers retain
their original outcomes and postchecks. Selector visibility stays within Journal
and its descendants; protected constructors and crate/public APIs do not widen.
This dispatch consolidation removes production routing code without a Cargo
edge cut, complete protected owner migration or production qualification.

Linux owns the unchanged bounded optional credential reader and its retained
native read DATA; role-specific decoding, key separation, and startup admission
remain with their original owners.

Agent wire values needed by protocol consumers remain in a portable module
of `aos-sandbox-agent`; Linux executable/bootstrap/effect code moves to Guest
or application ownership. Protocol crates must not depend on a concrete agent
executable implementation merely to use shared message types.

### Local authority and Controller

| Crate | Ownership | Excluded |
| --- | --- | --- |
| `aos-sandbox-broker-session-security` | Protected credentials, peer/process authentication, session sequencing, replay/currentness, sealed transport custody | HTTP/API registration, concrete domain dispatch, Controller reconciliation, unrelated binaries |
| `aos-sandbox-cache-signer` | Existing independent Cache-only credential owner and fixed Root/Controller readback exchange | Controller runtime, Q04 authority, publication; native Cache-view replay remains in `aos-sandbox` pending the Cache-domain extraction |
| `aos-sandbox-source-signer` | Existing independent Source-only credential owner and fixed Root readback exchange | Controller/Root writer custody, admission, currentness and paid grants; native Source-view replay remains in `aos-sandbox` pending the Source-domain extraction |
| `aos-sandbox-broker` | Common protected broker admission/configuration, plan/lease verification and authenticated record mechanics | Controller implementation, generic domain authority issuance, domain-specific semantic commits |
| `aos-sandbox-ownership` (**new**) | Protected local lease issuer, durable epoch/floor and inventory ownership currently misplaced under `multi_node` | Fleet membership, placement, remote transport, consensus |
| `aos-sandbox-policy` (**new**) | Policy compilation, independent Root binding/held-cut decisions, role-specific semantic commit and recovery | Generic journal implementation, daemon listener loops |
| `aos-sandbox-source` (**new**) | Source ancestry/genesis/successors and protected source-domain state | Source-provider physical acquisition, remote coordinator transport |
| `aos-sandbox-cache` (**new**) | Residency, consumer/object pins, quota, eviction and physical currentness | Filesystem presentation, Controller lifecycle, shared writable cache semantics |
| `aos-sandbox-publisher` (**new**) | Immutable publication, publisher policy, admission and protected catalog transitions | Guest execution and general Controller routing |
| `aos-sandbox` | Local admission, desired state, lifecycle orchestration, reconciliation, public projections and local-control implementation | Privileged effects, coordinator placement, generic security/journal engines |
| `aos-sandbox-controller-runtime` (**new**) | Concrete Controller session integration, retained operation flights, private Controller signing recipes and runtime startup composition | Generic peer/session mechanics, public client transport, other roles' signers |
| `aos-sandbox-client` (**new**) | Public API client, credentials and observation/operation handling used by CLI | Controller/effect-owner dependencies and privileged runtime closure |

The local ownership extraction follows the actual protected owners, not their
current names: leases and inventory used for local recovery move below the
coordinator boundary; remote transfer planning does not. An ownership crate
does not acquire all domain inventories simply because they share a journal.
Resource-specific inventory authority remains with its physical owner.

The historical lease state machine now resides in `aos-sandbox-ownership`:
canonical durable records, authenticated historical recovery, successor/CAS
validation, and borrow-bound preparation/publication of its resident maps.
Prepared records are inert transaction DATA, not proof of a durable commit.
The domain adapter retains the original issuer, protected clock and native
journal, and publishes only after their existing commit succeeds. This is a
partial extraction, not a completed protected local-owner boundary: fixed
bootstrap, lease issuance, rollback floors, and local inventory remain with
their existing owners until their concrete custody boundaries can move intact.
The existing broker facade becomes the owner of its common authority engine,
not a reexport of Controller implementation. Physical role/namespace admission
and semantic commit remain with the respective domain owner.

Concrete Controller runtime integration belongs above session security, not
inside its general-purpose library or the thin service-entry package. Moving
this owner must not create a dependency back from security to the runtime.
Startup authentication retains the original captured launch image and admitted
role profile; no public constructor accepts a replacement profile or invented
absence. Operation flights retain their original session and writer custody.
Private signing recipes remain private to this concrete owner rather than
becoming generic signing callbacks. Unconsumed speculative issuance recipes
are removed instead of gaining new public ports merely to permit relocation.

The complete Controller integration now belongs to
`aos-sandbox-controller-runtime` above Session Security. Its private retained
broker-exchange and inventory transport owners move with their actual Controller
callers, sealed transport targets, and application error projections; Session
Security has no dependency back to Runtime. Its inventory owner retains the actual
capture-candidate fence, authenticated session, pending exchange, authority
effect, output-registration attempt, optional Nix attempt, and Git coverage
custody in their original drop order. Private Controller credentials and
concrete exchange decisions belong to this integration group, not generic transport.
The existing selected service entry and named inventory exports remain the
application-facing ports. Services selects Runtime for Controller alone;
other roles keep their original lower owners. This cut does not isolate
Session Security's concrete domain dependency closure.

Session Security's private `dormant_handshake::host_catalog_publication` owns
the complete catalog descriptor/recovery reservoir and its execution, physical
readback, proven-absent retry, and error-terminal recipes. Original fields,
drop order, native failures, currentness checks, and public paths remain intact.
Shared session mechanics stay with their original owners. This private grouping
does not remove domain dependencies or establish runtime qualification.

Initial traffic-key proof stays private and retains only checkpoint drafts.
Its unused durable typestates are removed; protected Controller and Network
checkpoint and recovery owners remain in their existing domains.

Controller Runtime's private `resident_custody` child owns the unchanged partial
parent/worker slots, genuine worker loans, first native causes, and negative
terminal fences.

Within the Controller integration, private `activation` owns the complete
ordinary and retained startup recipes, journal assembly, readiness notification
and serving handoff. Its `configuration` child owns fixed process inputs and
closed activation parsing. The public run entry is a direct reexport of that
recipe, not a second startup engine. Resident custody remains in its original
owner; moving the recipes does not add recovery for callee-local failures.

Private `commands` owns the bounded command vocabulary, admitted request
payloads, response projection and complete journal-owner dispatch. Private
`public_rpc` owns client-facing registration, authorization and routing. The
private `worker` owns the complete reconciliation loop, retained history
recovery, broker inventories, catalog publication and retry classification.
Both startup routes borrow that same loop. Private `effects` retains one concrete
executor with focused admission, lifecycle, snapshot coordination and execution
children. The original field order, constructor moves, pending native outcomes
and journal/session borrow boundaries remain on that same owner. The root keeps
the shared authenticated broker-session slots used across these owners. These
internal boundaries clarify responsibilities without creating public authority
factories or isolating the remaining concrete domain dependency closure.

The private Runtime `inventory_transport` module owns the five sealed
initialization, successor, send, receive, and commit transport stages. It borrows
the original session; Controller retains preparation, competing-operation gates,
method context, pending custody, polling, and native-error parking. This module
boundary remains internal to the complete Controller owner.

The fixed raw ownership-clock sampler now belongs to a private session-security
mechanics module. Controller credential and lease factories remain private to
the Controller integration; lower clock consumers no longer import that owner.
The unconsumed old policy barrier recipe is removed. The selected original
generation-1 Q04 owner and live Controller hold credential recipes remain;
retiring the old bridge's pure fixtures does not qualify that selected path.
Fixed inventory/history attestation recipes remain beside the protected
session key and recovery owner. Closed Controller composition methods return
only their original sealed completions; they expose no caller-selected endpoint,
scalar signer, mutable HELLO, initialization selector, or verification context.
Opaque historical views are DATA only and never accepted as currentness evidence.
In the current live inventory
recipe, terminal revalidation drops its journal-and-peer loan before deriving
the canonical challenge packet and signing. That freshness gap remains an
implementation obligation, not a freshness claim established by this
refactor. A later semantic change must retain the genuine loan through signing and
keep historical predecessor, request, session, checkpoint, catalog, and cold
terminal joins inside their protected owner; detached outcomes or digests
cannot substitute for that custody.

Canonical broker/lease and Publisher signing preparations and immutable
completed artifacts belong to Protocol's `authorization_artifact` module.
Signing keys and protected currentness recipes remain with their original owners;
this artifact ownership cut does not remove SessionSecurity's domain dependencies.

The pure compiler, its bounded candidate model, and public Policy verifier
credentials belong to `aos-sandbox-policy`, depending only on Core and
serialization, hashing, cryptography and error libraries. Their computations
return nonauthorizing DATA; credential decoding delegates to Core's canonical
format and does not establish protected custody or currentness. The existing
offline key-pin helper remains in Services, with an independent build/test
selection rather than the Policy daemon's security and effect dependency graph.
Its installed CLI is unchanged; the daemon and aggregate package retain their
existing dependencies. Protected current-Create source joins, Root binding,
journal admission, held-cut decisions, publication, and recovery remain in the
domain integration and still require the larger Policy ownership extraction.

Protected compiler Candidate V3 is the sole retained body grammar. The earlier
plan-less V2 path and its optional preimage/readback state are removed; old bytes
are refused without repair or deletion. Canonical fixtures share the existing
real compiler and V3 encoder across all four cache domains. Current V1 and the
compiler commitment hash remain unchanged. Complete preimage consistency still
grants no current Root or read authority.

### Effects, views, and application assembly

Host, Storage, Mount, and Network retain their existing implementation crates
(`aos-sandbox-host`, `aos-sandbox-storage`, `aos-sandbox-mount`, and
`aos-sandbox-network`). Guest and Guardian retain `aos-sandbox-guest` and
`aos-sandbox-guardian`. They own concrete role-specific effects, independently
verified observations, and their protected state; they do not host the public
Controller or import its implementation.

`aos-sandbox-guest-root-realization` owns the complete physical fresh-root
population, fixed SELinux projection/readback, and durable marker publication
recipes. Host's detached-root verifier, Storage's publisher and inventory, and
Guest's actual PID 1 manager projection consume this owner directly. Host and
Storage do not depend on Guest execution merely to realize or inspect a root.
The separate `aos-sandbox-guest-root-tree` remains a nonauthorizing measurement
owner. Protected template selection, authenticated admission, root/writer
custody, replay, deadline predicates, worker quiescence, and ambiguous-outcome
recovery remain with their original Host, Storage and Guest callers. This cut
adds no producer or authority and does not qualify the connected lifecycle.

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

The complete Cache recovery codec reader now uses Core's bounded byte mechanics
across its fourteen component, atomic-envelope, and typed-checkpoint parser
roots. Cache retains its fixed headers, capacity limits, canonical booleans and
optional fields, closed codes, commitments, and semantic validation. Envelope
hashing includes the original header, and EOF validation still precedes digest
comparison. This removes the duplicate recovery byte engine without changing
protected Cache admission, custody, or recovery authority, and establishes no
new runtime qualification or protected Cache crate boundary.

LocalInventory retained Journal, store history, bootstrap and clock formats use
the same Core reader with their original bounds and error classifications.
Canonical domain checks and exact authenticated-prefix capture remain local;
the private read adapters are removed. Protected factories and the
public Node carrier decoder retain their existing contracts.

Do not introduce a universal owner/context containing every role, a field for
every hypothetical backend, forwarding layers without a contract, or a new
record family per refactor. Implementation and co-located tests are reviewed
separately under the repository's file-size and documentation standards.

Reconciler's private `operation_ledger` retains the OwnershipGate model and codec
and uses Protocol's complete Operation record and key owner directly. Gate
decoding reuses Core's bounded reader; immutable draft validation stays native.
Protected admission, activation, currentness, clocks and Journal custody remain
with their actual owners; the protected-owner extraction is incomplete.

## Multi-node boundary reserved for later

`aos-sandbox-coordinator-protocol` (**new**) owns coordinator-only generated
schemas, messages, version negotiation and assignment/watch/transfer models.
`aos-sandbox-coordinator` (**new**) owns fleet placement, draining, remote
reconciliation, transfer and coordinator transport. Shared identities and
local ownership contracts remain below both crates.

The first complete extracted Coordinator responsibility contains deterministic
placement, ordered-watch producer/client handling and committed-lease protobuf
projection. It depends on selected Domain local-control contracts; Domain has no
dependency on this implementation. The former remote placement/watch modules
and inherent intent/lease adapters are removed immediately. Selection owns the
intent adapter, while a free converter borrows the actual committed lease.

The retained canonical codec owns the six generated watch-data conversions once.
Public structural cursor/event constructors, bounded body encoding and the exact
capability-binding copy are explicit undeployed DATA API cutovers. They mint no
authenticated bootstrap, carrier grant, current observation or ownership lease.
Sealed producers, protected transport/store orchestration and their genuine
custody remain Domain-owned. Separate explicit Coordinator test selection keeps
the normal application/default-member feature graph unchanged. This cohort earns
no deletion credit for relocation and does not complete Coordinator isolation,
the protected authority boundary or runtime qualification.

The application-level `multi-node` feature is off by default and uses optional
dependencies. It is not enabled transitively by any single-node role crate, default
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

Later coordinator acceptance must advance desired generation contiguously within
an assignment epoch, reject same-fence semantic equivocation, and retain exact
protected journal succession. Drain observation advancement must check the node
phase and each assignment's allowed progress edge under current evidence. These
reserved requirements do not imply an enabled coordinator or a live admission
path; unused warm status caches are not durability or effect authority.

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
