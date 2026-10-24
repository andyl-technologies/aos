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

The view-service, immutable cache, publisher, and FUSE-worker implementation
belongs to Terrane, as specified by RFC-0024's
[sandbox integration](https://github.com/andyl-technologies/aos/pull/420).
Integration waits for the Terrane implementation and its interfaces to settle;
this workline must not build a second view service or storage engine. The
sandbox Controller, broker session protocol, privileged Mount broker, and
Storage broker's ZFS workspace transactions remain sandbox responsibilities.
Terrane integration is a subsequent delivery slice and is not part of the first
local lifecycle completion claim.

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

## Controller recovery range

The selected source defines the finite Controller range and
[its versioned local formats](09-protocols-and-formats.md#controller-image-and-recipient-compatibility).
This is a source contract, not evidence of installed availability or successful
runtime qualification.

The existing Controller baseline B excludes permanent subdivisions, including
FirstGlobal P, and is partitioned as B=N+R. R, per-recipient allowance A and
finite recipient count K must be explicitly declared, with checked K*A<=R in
all 22 dimensions. Initial receiving reserves R and spends within N; each
genuine later recipient reserves B-A on its own same-B ledger. Every consumed
allowance remains charged. There is no default K, automatic cap increase, refund
or new account. The actual compiled receiving programme must fit its allowance
before growth; a declaration alone proves no operational headroom.

Standing P remains reserved or committed under its original permanent
BootLifetime claim and cannot be released. Its CPU dimension is a rate outside
B, reused only for sequential native recipients; the installed quota comes from
P, not A. The image's memory, task and NOFILE controls remain authoritative.
This does not establish a generic unpriced CPU exemption or waive other
financial and physical checks.

PID1 enables the range only after the initial protected bank seal, readback and
actual ACK/Confirm posts. It consumes each new ordinal before dependent growth
or clone, retaining cumulative parent M debt and bounded attempt history.
A candidate's EOF or pre-ACK death is negative only. Another ordinal still
requires its actual held PIDFD death, manager reap, cgroup Empty, delivery
closure and account/native posts. Malformed input or uncertain native, issuer,
account or close results fence further entry; no failed prefix is reset.

The latest physical donor may differ from the last confirmed recipient.
The same actual PID1 range owner retains that distinction, while the exact bank
CAS advances only from its real committed predecessor and archives that row
unchanged. Unconfirmed attempts do not acquire fictional ACKs. Existing Source
seeds, original deadlines and A8 settlement history remain literal; fresh
recovery still needs its genuine current authority and native proofs. Lost
native custody across unsupported daemon reexec or reboot cannot be recreated
from range DATA.

The Controller recovery-reserve route requires the matched V11 producer and
consumer with no V10 reserve fallback. No-recovery Controller startup remains
initial-only; independent F image families retain their own closed role
recipes. Source compilation, native ABI/stack and limit checks, actual funded
profile fit, pre-ACK crash handling and range exhaustion must all be qualified
on the normal path. These declarations and source changes do not
substitute for matching qualification receipts. This contract changes no
deferred FUSE, VM, fleet or first-lifecycle scope.

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

Planned responsibilities below are TARGET boundaries, not an inventory of
current dependencies. **New** marks a planned responsibility extraction, not
necessarily a missing package: Journal, Policy, Ownership, Runtime, Client,
Services and Coordinator packages exist with remaining boundaries described
in the current index. Source, Cache and Publisher role packages remain planned.
A new crate needs a cohesive owner, useful dependency boundary and concrete
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

Controller mutation Effects require retained authenticated admission context;
the public bare-envelope factory and its acceptance fallback are retired.
Canonical decoding rejects bare V3/V5/V6 rows, including Applied and terminal
history, at the existing request-validation frontier. Such rows can block
whole-ledger reconciliation and public projection; their Journal bytes remain
intact, with no inferred context, automatic upgrade or deletion. Context-bearing
history, broker Effects and reserved Observe children retain their own semantics.

Public specification descriptors share one closed V1/V2 role validator, including
the original Q04 descriptor frontier. Retained specification lookups compare the
complete descriptor, and local slot/Storage/Network metadata checks require the
media version selected by decoded canonical bytes. Native `AOSSLT02` and Mount
`AOSMSL02` slot records retain that explicit version in their digests and replay;
earlier PR-only slot records are refused unchanged, without migration or deletion.
Genuine V1 specifications retain their semantics and cannot supply implicit
execution credentials. These descriptor checks grant no Create authority or
Ready state and do not enable V2 remote transfer.

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

The unconsumed Source16 client and its exclusive I/O cell are retired. The
installed signer still refuses that request before context growth, key access
or native observation. Current-Nix preflight DATA and the native observation
owner remain in `aos-sandbox`; this removal does not issue a paid receiving
origin or establish the protected Source Cargo boundary.

The unused Controller-only and all-owner receipt-comparison sessions are
retired with their exclusive challenge producer. Their detached observations
never supplied the required simultaneous writer cut. Shared Root entropy
has one private mechanics owner; fixed binding, original Q04 and genesis
continuations retain their custody. The complete read barrier remains closed.

The local ownership extraction follows the actual protected owners, not their
current names: leases and inventory used for local recovery move below the
coordinator boundary; remote transfer planning does not. An ownership crate
does not acquire all domain inventories simply because they share a journal.
Resource-specific inventory authority remains with its physical owner.

Concrete Controller runtime integration belongs above session security, not
inside its general-purpose library or the thin service-entry package. Moving
this owner must not create a dependency back from security to the runtime.
Startup authentication retains the original captured launch image and admitted
role profile; no public constructor accepts a replacement profile or invented
absence. Operation flights retain their original session and writer custody.
Private signing recipes remain private to this concrete owner rather than
becoming generic signing callbacks. Unconsumed speculative issuance recipes
are removed instead of gaining new public ports merely to permit relocation.

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
The eight Host/Storage/Mount/Network inventory-pair completions and the fixed
Host effect completion retain the exact protected terminal journal-and-peer loan
through challenge-message derivation, signing, typed construction and final currentness
checks. Supplied inventory must equal that loan's authenticated outcome. A failed
signing or construction result retains precedence over its failed postcheck.
These checks protect the Controller's terminal custody during attestation; they
do not hold the independent broker writer through a later Controller commit.
Storage effect/atomic and historical attestations retain their separate
currentness obligations. Historical predecessor, request, session, checkpoint,
catalog and cold-terminal joins remain inside the protected owner; detached
outcomes or digests cannot substitute for that custody.

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

The four Source-provider crates retain distinct responsibilities:
`protocol` owns decoded messages, `ledger` owns pure records/reducers,
`security` owns protected key/process/descriptor custody, and the provider
owns durable acquisition/effect/recovery orchestration. Common mechanics are
shared without merging those authority boundaries.

The existing `aos-sandbox-filesystem-format`, `aos-sandbox-filesystem-view`, and
`aos-sandbox-filesystem-fuse` crates retain portable semantics, metadata state,
and the narrow FUSE ABI and qualification work already implemented. Their
presence does not establish a production view service. The subsequent Terrane
integration supplies the view service, immutable cache, view publisher, and
FUSE workers; it must reuse the sandbox contracts and conformance requirements
rather than introduce a second storage engine here. Git/Nix/OCI adapters remain
behind view/publisher contracts, not special cases in the Controller or Mount
broker. Filesystem consumers may depend on narrow authenticated outcome APIs,
never application assembly.

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

## Current ownership and remaining boundaries

The target tables above describe intended responsibilities. This index describes
current source ownership; a private module grouping is not a Cargo boundary,
and shared DATA or mechanics are not protected authority. Source links do not
establish connected behavior or selected qualification.

Current boundaries preserve original resident fields and factory scopes, and
validation, error, allocation, cleanup, custody and final-crossing chronology.
Selected native physical ownership is not qualification on other Unix targets.

| Current owner | Responsibility and retained boundary |
| --- | --- |
| [Model](../../../crates/sandbox/model/aos-sandbox-model/src/lib.rs) and [Protocol](../../../crates/sandbox/protocol/aos-sandbox-protocol/src/lib.rs) | Portable models, bounded codecs and canonical historical/local DATA; role admission and fresh currentness remain with native owners. |
| [Linux descriptors](../../../crates/linux/aos-linux-descriptors/src/lib.rs) and [Sandbox Linux](../../../crates/sandbox/host/aos-sandbox-linux/src/lib.rs) | Shared process pins, plain Unix streams, sealed credentials, boot identity and positional hashing sit below Sandbox-specific process/namespace, subject and packet mechanics. Neither grants a service role. |
| [Systemd client](../../../crates/linux/aos-systemd-client/src/lib.rs) | Typed manager transport and observations use shared Linux descriptor mechanics without a Sandbox implementation dependency. |
| [Journal](../../../crates/sandbox/controller/aos-sandbox-journal/src/lib.rs) | Portable framing/native DATA and opt-in physical custody; Domain retains typed semantic admission and final crossings. |
| [Ledger replay](../../../crates/sandbox/controller/aos-sandbox-ledger-replay/src/lib.rs) | Shared Source, Root and Cache saved-state models and complete replay comparisons; native roles retain construction, writer/descriptor custody, currentness and posts. |
| [Domain Journal](../../../crates/sandbox/controller/aos-sandbox-controller-domain/src/journal.rs) and [protected domain adapter](../../../crates/sandbox/controller/aos-sandbox-controller-domain/src/protected_domain_journal.rs) | Native role transitions, original retained causes and cross-owner loans; private organization, not protected role-crate isolation. |
| [Source](../../../crates/sandbox/storage/aos-sandbox-source/src/lib.rs) and [Domain Source integration](../../../crates/sandbox/controller/aos-sandbox-controller-domain/src/source_domain/mod.rs) | Source owns Linux fixed native construction, provider state and signer purposes; Domain still retains its fixed-writer integration and lifecycle/Q04 coordination. This is a package extraction, not complete Source/Lifecycle closure. |
| [Cache](../../../crates/sandbox/storage/aos-sandbox-cache/src/lib.rs) | Cache owns its journal adapter, fixed role writers, admission/recovery and physical/currentness owners. Domain and Security consume finite owner APIs; historical Cache DATA remains in Protocol and Ledger replay. |
| [Ownership](../../../crates/sandbox/model/aos-sandbox-ownership/src/lib.rs) | Historical lease state and successor/CAS comparison; genuine issuer, clock and commit custody remain with their original owners. |
| [Policy](../../../crates/sandbox/model/aos-sandbox-policy/src/lib.rs) and [native Policy](../../../crates/sandbox/model/aos-sandbox-policy/src/native.rs) | Portable compiler/publication DATA is separate from opt-in Linux native journals, Root authority/Target, publication and Current owners. Native constructors require actual original loans; the package boundary does not establish a complete Current programme. |
| [Controller Runtime](../../../crates/sandbox/controller/aos-sandbox-controller-runtime/src/lib.rs), [Security](../../../crates/sandbox/security/aos-sandbox-broker-session-security/src/lib.rs) and [Source](../../../crates/sandbox/security/aos-sandbox-source-signer/src/lib.rs)/[Cache](../../../crates/sandbox/security/aos-sandbox-cache-signer/src/lib.rs) signers | Concrete Controller remains above session custody. Security still depends on Domain; neither signer manifest declares a Domain dependency. |
| [Guest root tree](../../../crates/sandbox/guest/aos-sandbox-guest-root-measurement/src/lib.rs) and [realization](../../../crates/sandbox/guest/aos-sandbox-guest-root-realization/src/lib.rs) | Separate nonauthorizing measurement and physical realization; original admission/effect/recovery custody remains at callers. |
| [Coordinator](../../../crates/sandbox/controller/aos-sandbox-coordinator/src/lib.rs) | Explicitly selected placement/watch/projection; protected remote handoffs remain selected Domain owners. |

### Shared mechanics and canonical DATA

Core's bounded reader serves Cache's fourteen component, atomic-envelope and
typed-checkpoint roots, without a duplicate recovery byte engine. Cache retains
headers, capacities, canonical booleans/optional fields, closed codes, commitments
and semantic validation; envelope hashes include the header and EOF precedes
digest comparison. Protected Cache admission, custody and recovery authority do
not change. Guardian's five reducer decoders share those byte mechanics; its
closed selectors, sequence ceilings and protected recovery stay local.
LocalInventory retained Journal/store/bootstrap/clock formats share
that reader without private read adapters; original bounds/errors, canonical
domains, exact authenticated prefixes, protected factories and public Node
carrier-decoder contracts remain local.

`aos-linux-descriptors` owns generic process pins, plain Unix stream correlation,
sealed read-only credentials, bounded boot identity and positional hashing, with
no Sandbox dependency. Systemd uses that owner directly in production and tests.
Sandbox Linux retains namespace/proc observations, private ancillary parsing,
subject admission and fixed role-specific credential producers. Received FDs
move through their original resident slots; this extraction does not authorize a
role, duplicate a descriptor or turn historical bytes into native evidence.
Linux retains the bounded optional credential reader and role-specific retained
reads; key separation and startup admission remain with their callers. Portable
Guest messages live below Guest executable/bootstrap/effect composition.

Journal's `owner` retains the original files/append poison, configuration,
coordinates, identity/namespace-provenance sets and materialized DATA map. File
replacement preserves lock and poison; Domain retains semantic indexes, genuine
loans, admission/final crossings, histories and authority-instance rotation.
`native_suffix` borrows actual upper mutation graphs for before/after accounting,
signed prefix deltas, raw key/namespace duplicate checks and checked record/frame
extents. Closed semantics, Source forecast buffers, all alternatives and
historical/current cuts, and final headroom remain upper. Shared accounting
replaces duplicate key/value and width-only floor buffers without moving
admission, opening, descriptor custody or authority below Domain.

Protocol transaction extent accounting and its duplicate-key index share
Journal's `NativeRecordValidation` with suffix measurement. Keys borrow actual
records; Domain Idempotency checks occur between extent checking and key
registration. This fold grants no admission, configuration gate or persistence.

Opt-in `protected-unix` selects Journal's physical `protected_storage`: the actual
directory, basename, UID, passive compaction-denial marker, rooted traversal,
no-follow opening, independent name observation and temporary replacement custody.
Domain Journal preserves this location's destruction position. Its private
`protected_storage` keeps opening orchestration, original failure reservoirs,
typed replay, the public lock-custody identity/private factory and semantic
compaction admission. Controller/Cache/Root/Source loans, currentness and final
authority crossings stay Native; lower constructors/observations grant no domain
authority. Standalone default Journal remains portable. Protected opening,
typed replay, compaction admission and protected role migrations are still partial.

Protocol's `domain_ledger` owns complete transaction/Idempotency DATA,
capacity schemas/identities and schema-bound record/reducer/replay DATA, reusing
Journal framing/bounded mechanics. Its `capacity_family` owns all seven closed
record families, shared accounting and complete-state selection. Original Source
provenance stays typed through an explicit normal dependency on Source Ledger.
Native suffix builders retain whole private graph/Journal geometry; lower DATA
errors project to the original Journal variants at native caller frontiers.
Role validators still borrow actual evidence. Decoded phases/projections are not
sealed currentness, capacity, postcommit or physical admission. Native wrappers
retain actual Journal/guards, writer/lock loans, causes, indexes and closed
prepared/recovered capacity factories.

Its `public_operation` owns immutable admission/authorization DATA, 64-byte
durable metadata, a separate closed durable method registry, Operation state
and established projection/resourceVersion. Private fields stay private; checked
constructors/codecs/projections are public passive DATA APIs returning lower
errors projected to original Reconciler variants. This undeployed cutover changes
visibility. Journal, admission, authentic clock acquisition, Effect/Repair
consistency and current public authorization remain Domain-owned.

`public_api::mutation_history` owns complete plain/Nix/FUSE history selection and
context binding, canonical Nix/FUSE carriers, original authority coordinates,
assignment preimages/whole comparisons, historical joins and compiler
resource-version hashing. Native callers use this single owner, not a second Nix
carrier module. Public DATA constructors/comparisons are undeployed API cutovers,
not current authority. Native retains authenticated capture, protected selection,
paid resource owners, writer/descriptor loans, clocks and current-authority
rechecks. Its public FUSE identity keeps the original read surface/private
historical enclosure, with no public raw-history conversion.

`domain_ledger::operation` owns both Operation record versions, full decoder,
unchecked encoder, five private Copy fields and Operation/Effect key grammar.
Public DATA getters, infallible assembly and state/metadata replacement are
undeployed cutovers, not admission or semantic transition checks. Domain retains
Journal, native Effect/Gate admission and activation, clocks, recovery/currentness
recipes and original Reconciler error projections. Journal's materialized-row
Effect key uses Protocol directly, as does its public projection metadata.

Protocol's `authorization_artifact` owns canonical broker/lease and Publisher
signing preparations and immutable completed artifacts. Signing keys and
protected currentness stay with original owners, not this DATA API.

### Native continuations and local authority

Protocol's `domain_ledger::effect_history` owns the complete V2-V6 Effect history
codec, model, context and dispatch DATA. Native Effect retains signed/current
and Guardian factories, private history enclosures and receipt validation;
Protocol's `domain_ledger::controller_history_relation` owns three complete
historical recipes: atomic Delete metadata, Controller capacity transfer and
Controller capacity settlement. Gate/Effect intermediates stay private. Native
Journal selects the predecessor bytes/key once; actual Journal, descriptor,
writer and clock loans remain with their original owners.
Consumers use the canonical DATA owner directly; obsolete Native DATA exports
and historical decoders are retired. Passive history DATA conveys no authority.
Protocol's `publication::bound_effect` owns the complete checked draft-to-effect
binding DATA, including the private template recipe and consuming operation
coordinates. Native gated admission, historical Delete and runtime-intent checks
use that canonical owner directly, projecting errors at their original frontiers.
Publication currentness, activation and effect custody remain Native.
Protocol's `domain_ledger::ownership_gate` owns the complete Gate plan/state,
V1 codec and immutable Claim/Draft context validation, using existing lower DATA.
Delete metadata uses the complete lower batch/Gate/Effect relation, with the
original final malformed-transaction refusal after Native current-map checks.
Live activation and current publication validation remain Native.
Protocol's `domain_ledger::lifecycle_model` owns the complete typed resource/edge
vocabulary, both postorder rules and the unchanged shared model-error declaration.
Native wrappers retain their original causes; graph admission remains upper.
Protocol owns the complete `domain_ledger::delete_batch` grammar, checked borrowed
views, owned outcomes and tombstone/collection/handoff DATA. Native Journal
admission and real-writer COMMIT readback remain upper.
One explicitly gated lower synthetic fixture serves codec and Native replay tests;
its dev-only feature does not activate production defaults.
Native Controller transfer/settlement retain actual grant recovery, consumed
append accounting, purpose and row-order checks, and protected COMMIT. Lower
history comparisons preserve full Plan/State/dispatch and metadata equality;
they cannot establish capacity, Root authority or full Project replay closure.
The superseded Reconciler historical helper owners and exports are retired.
Native `reconciler::project_admission::original_history` owns the complete
retained/live/scoped original-Create revision chain, replay/projection/capacity
joins, flight and terminal readbacks, and history-floor acceptance. Its opaque
Controller Journal borrow remains beside the complete validated factory and
Source ACK validation. Prepare, dispatch and Source outcome transitions remain
with their Native owner; current publisher policy and clocks remain separate.
Metadata aliases use Protocol directly; the superseded alias facade is retired.

Private `journal::semantic_append` retains complete ordinary/closed append,
paired advisory preflight, Q04 adapter and append-only-guard inherent recipes on
the original Journal. Passive private `AppendScope`/`PreflightScope` provide one
ordinary append and one forecast entrypoint without escalating routing layers.
Actual original loans reach the unchanged final engine separately, including all
independent Q04 lifetimes. The nine-field forecast cannot select project genesis;
fixed recipes retain that private selection. Append/forecast preserve distinct
validation/errors, state-clone/frame lifetimes, Cache locks, clocks, first causes,
publication, caller outcomes and postchecks. Selectors stay within Journal and
descendants; protected constructors and crate/public APIs do not widen.

Q04 terminal resource retention uses that same append engine with a private loan
of the retained co-issuance, eight commit results and seven posts. Both Controller
history guards validate the exact terminal successor; native name, position and
original-input checks repeat before the final clock crossing. Ordinary terminal
DATA and advisory forecasts remain closed. This commits the retained use without
refunding its inclusive capacity, clearing Q04 history or opening Storage effects.
Seeded append/reopen regressions cover these journal mechanics, not installed
Root/PID1 admission or the complete Create continuation.

Cache bootstrap rechecks compare complete borrowed records with the retained
validated originals. Held physical Cache checks stream the original manifest
with fixed scratch; initial unknown-file replay keeps its complete decoder.
Changed payloads with valid headers, nonzero generations and checksums are
stale heads. Verified sessions share the authority's immutable checkpoint
evidence while preserving independent per-partition verification and currentness.
Broker owned decoding and exact sealed-member matching share field parsers.
Selected Nix Storage preparation adds its actual admitted plan/lease/request
deadline check immediately before the ordinary native append, retaining the
kernel sample and native result independently. This adds no receiving payment
or exception to the existing journal authority guards.

Private `protected_domain_journal::capacity` owns complete domain reservation
admission, authenticated recovery and terminal settlement on the original Journal.
The unused ID-plus-binding adapter recipe is retired; exact pending, full-request
and unique stable-binding recovery retain their original authority and chronology.
Resident fields and shared postcommit issuance remain parent-owned; this private
organization does not isolate protected Cargo dependencies.

Private `journal::original_release_capture` owns native Release capture, replay
comparison, retained first-cause transfer and copy pricing on the original Journal.
Capture fields, shared COMMIT observation and the replay parser stay parent-owned.
Controller/Root recipes remain undeployed; this private group grants no cleanup
admission and creates no protected Cargo boundary.

Linux `journal::controller` owns the intact Controller Journal profile, identity
and opening-construction group; `JournalShape` stays beside its producer with
Linux-only availability. Crate-root `protected_domain_journal` keeps original
Journal custody through planning, append, readback, recovery and postcommit for
Lifecycle, Hierarchy, Git, Environment, Cache, Policy and Publisher. Publisher's
two retained-effect recovery paths share one private helper; original transaction
identity and actual reservation/Journal custody stay Native. These are private
source responsibilities, not protected Cargo owners.

Private `publisher_admission::protected_journal::record_codec` owns complete
mutation, current-head, completion-effect and capacity-settlement grammars,
reducer framing and checkpoint commitments. Semantic replay, key selection,
resident types and all protected Journal/capacity/postcommit custody stay
with the journal owner. This private organization is not a Cargo boundary.

`source_domain` owns the live fixed Source Journal, paid opening originals and
original Q04 loans in private `fixed_writer`. The separate
`aos-sandbox-source` package owns its fixed native Source journal, paid
construction and signer purposes, sharing complete replay with
`aos-sandbox-ledger-replay`. Lifecycle retains schemas, accepted identities and
its private verifier factory; Domain retains the actual fixed-writer integration.
The package split does not establish complete protected Source/Lifecycle closure.

The unused Policy, Publisher and Cache Controller-result conversions are
retired. Canonical applied transactions retain their exact postcommit and
acknowledgement custody. Cache record selection and session-branded reducer
inputs belong to the Cache package; sealed factories and currentness remain
with that package's protected owner. Domain callers retain their original loans
and cross-owner coordination.

Cache's private `recovery::logical_pin` owns complete Acquire/Renew/Release
planning with one shared successor recipe. Complete retained-ledger and exact
PinAcquire/PinDrain checks remain at their original gates; protected commit,
independent physical settlement, causes and custody stay with native Cache owners.
Returned payloads remain plans, not current grants.

Protocol `cache_state` owns inert Cache accounting/catalog transitions without
descriptors, protected capabilities or live loans. Cache's separate package owns
protected admission, recovery proofs and physical/currentness custody; its old
Domain `cache_residency` implementation is retired. Source and native Policy
packages also exist, while Publisher remains integrated in Domain. Security
still has a Domain dependency; the Source and Cache signer manifests no longer
do. These concrete boundaries do not isolate every protected Controller/Journal
owner or qualify the public lifecycle. Historical DATA is not a current grant.
Shared engines retire duplicate mechanics; relocated source earns zero deletion
credit, even when passive APIs/adapters add code.

Ownership holds canonical historical lease records, authenticated historical
recovery, successor/CAS validation and borrow-bound resident-map preparation/
publication. Prepared records are inert transaction DATA until the original
Domain issuer, protected clock and native Journal commit succeeds. Fixed
bootstrap, lease issuance, rollback floors and local inventory remain upper.
The broker facade must own its common authority engine rather than reexporting
Controller implementation; physical role/namespace admission and semantic commit
belong to the domain owner.

Policy's default feature set is empty. Its compiler, publication schemas and
comparison DATA depend on Model, Protocol and broker-session Protocol, alongside
serialization/hash/cryptography/error libraries. They return nonauthorizing DATA;
credential decoding uses the canonical model format without protected custody or
currentness. The `native-journal` feature adds Linux-only Broker, Cache, Journal,
Ledger replay, Linux descriptors and ownership-protocol dependencies; Journal's
physical owner is selected with `protected-unix`. Domain explicitly selects that
native feature, so a portable Policy default does not make Domain portable.
Native Policy owns actual Root journals, original Authority/Target loans,
publication/readback and finite append gates. Current and other continuations
still require their complete genuine producers, callers, incoming accounting and
qualification; these exports and source moves do not prove them. Services'
offline key-pin helper retains independent selection and unchanged installed CLI.

Source, Cache and shared Linux descriptors are current workspace/default members;
coordinator packages remain outside default members. These are manifest facts,
not a transitive-graph or selected runtime qualification result.

### Runtime custody and physical effects

Runtime owns concrete Controller integration above Security, with no Security
backedge. Private retained broker exchange/inventory transport keep actual callers,
sealed targets and application errors. Inventory retains capture-candidate fence,
authenticated session, pending exchange, authority effect, output-registration
attempt, optional Nix attempt and Git coverage custody in original drop order.
Controller credentials/concrete exchange decisions stay private here, not generic
transport. Existing selected service entry/named inventory ports remain; Services
selects Runtime only for Controller and other roles retain their lower owners.

Private `resident_custody` retains partial parent/worker slots, genuine worker
loans, first native causes and negative terminal fences. `activation` owns ordinary/
retained startup, Journal assembly, readiness and serving; `configuration` owns
fixed process inputs/closed parsing. Public run directly reexports that recipe;
there is one startup engine and no added recovery for callee-local failures.
`commands` owns bounded vocabulary, admitted payloads, response projection and
Journal dispatch; `public_rpc` owns registration/auth/routing. Both startups borrow
one `worker` reconciliation/history-recovery/inventory/catalog/retry loop. One
`effects` executor has admission/lifecycle/snapshot/execution children, preserving
field order, constructor moves, pending outcomes and Journal/session borrows.
The root keeps shared authenticated session slots; private organization adds no
public authority factory or isolated concrete Domain dependency closure.

Private `inventory_transport` owns five sealed initialization/successor/send/
receive/commit stages borrowing the original session. Controller retains preparation,
competing-operation gates, method context, pending custody, polling and native
error parking within this same complete owner.

Security uses the canonical broker-session Protocol manifest and role pins
without a compatibility facade or duplicate pin array. Native loader and
context errors retain their original redacted field classes; protected files,
process custody and currentness remain Security-owned. Passive type identities
and redacted Debug labels cut over directly to the canonical DATA API.

Security stores the canonical Protocol historical checkpoint directly,
without a second checkpoint wrapper. Historical failures retain the original
redacted Security error at native frontiers; protected session and Journal
owners retain their private fields, actual custody and currentness checks.

Private `recovery::journal::current_session` owns the complete authenticated
initial/successor request, retained terminal, outcome commit and exact recovery
recipes on the original Journal. Resident fields, physical/schema operations,
floor custody and peer checks stay with that owner; effective factory scopes
and genuine currentness loans are preserved. This is not a Cargo boundary.

Security's private `dormant_handshake::host_catalog_publication` retains complete
catalog descriptor/recovery reservoirs, execution, physical readback, proven-absent
retry and error-terminal recipes, original fields/drop order/native failures/
currentness/public paths. Shared session mechanics stay in their original owners.
Initial traffic-key proof is private checkpoint drafts only, without unused durable
typestates; protected Controller/Network checkpoint and recovery stay in their
domains. Neither artifact ownership nor this grouping isolates Security's Domain
dependency or establishes runtime qualification.

Guest-root-realization owns complete fresh-root population, fixed SELinux
projection/readback and durable marker publication. Host's detached-root verifier,
Storage's publisher/inventory and Guest's PID 1 manager consume it directly,
without Host/Storage importing Guest execution for realization/inspection.
Guest-root-tree remains nonauthorizing measurement. Original Host/Storage/Guest
template selection, authenticated admission, root/writer custody, replay, deadline
predicates, worker quiescence and ambiguous recovery remain upper; this adds no
producer/authority or connected lifecycle qualification.

### Selected Coordinator and remote owners

Coordinator owns deterministic placement, ordered-watch producer/client handling
and committed-lease protobuf projection, depending on selected Domain local-control
contracts without a Domain dependency on its implementation. Selection owns the
intent adapter; a free converter borrows the actual committed lease. There is no
parallel remote placement/watch or inherent intent/lease adapter engine. One
canonical codec owns six generated watch conversions; public structural cursor/
event constructors, bounded body encoding and exact capability-binding copy are
undeployed passive API cutovers, not authenticated bootstrap/carrier grants/current
observations/ownership leases. Sealed producers, protected transport/store and
genuine custody remain Domain-owned. Explicit Coordinator tests do not change the
normal application/default-member graph; relocation is not deletion, complete
Coordinator isolation, protected closure or runtime qualification.

Selected Domain remote owners require `multi-node`: drain `verified_observation`
keeps trusted evidence factories/protected joins/commitments/currentness; assignment
`acceptance_evidence`/`restore_admission` keep sealed factories and exact verifier/
capability/publication/currentness joins. Destination admission is neither local
snapshot/restore implementation nor permission to restore. `remote_verification`
keeps authenticated chunks, dependency ranges, protected transfer checkpoints,
carrier checks/scoped commitments and streaming/replay together; `remote_exchange`
keeps authenticated resync inventory/watch bootstrap. `observation_reducer` keeps
the private move-only assignment plan/exact effect commitment;
`journal::assignment_effect` keeps sealed prepared-grant factory/reservoir. The
protected owner joins that grant to committed publication and independently
current effect-time carrier.

Default DATA still includes raw drain reports/model layouts/phase checks, local
assignment and intent/observation models, snapshot manifests/resume DATA, completed
snapshot receipts for shared drain/history, raw inventory/cursors/stable-UIDs,
canonical codecs/retained-history validation, full replay/partial-effect recovery
and Controller lifecycle transfer inventory. Their retained layouts/recovery do
not depend on selected handoffs; decoded history is not fresh drain authority.
These gates do not isolate the remaining protected Ownership/Journal group or
qualify distributed execution.

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
