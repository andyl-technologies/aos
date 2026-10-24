# SourceBirth derivation worker implementation plan

This nonnormative plan describes the isolated private construction mechanism
for RFC-0025. The worker and its retained parent integration now exist; the
[implementation status](implementation-status.md) records executed results;
the [qualification plan](qualification-plan.md) defines the broader gates.
The implementation does not yet establish common Ready or full native
qualification. The design discussion below retains its original proposal scope.

## Purpose and first delivery

The current Source18 preparation path stops after initializing an in-process
Birth construction owner. Its later stages validate the launch, decode and
compare Coordinators, materialize two JSON trees, encode two canonical banks,
and construct a private Birth. The name `BirthWorker` currently denotes that
in-process stage; it does not describe process isolation.

The proposed `DeriveSourceBirth` job puts the complete pure validation and bank
derivation in a measured, confined child. The parent retains the original
Source, launch, registration, once state and native resources. It receives only
two canonical byte banks and a bounded closed result, then performs its genuine
private Birth construction. It need not reconstruct a Coordinator or JSON tree
from the worker response.

This reduces the construction boundary to a small number of actual input,
work, output and process owners. RFC-0025 requires bounded operations, admitted
transfers, retained failures and enforced resource limits; it does not prescribe
a separate authority ledger for every temporary parser value. Existing
same-process constructor contracts nevertheless remain binding. The new route
must use an explicitly selected mechanism and actual resource policy rather
than claim that child limits satisfy an old same-process quote.

The first delivery is a connected installed-source fixture that starts from
the same initialized occurrence, executes the confined derivation, accepts the
same two banks and constructs the genuine parent Birth. A standalone facade or
successful child serializer is only a prerequisite.

## Current boundary and ownership

| Existing owner | Defining source | Role in this plan |
| --- | --- | --- |
| Daemon Prepared and its three Member attempts | [import18_templates.rs](../../../crates/crucible/crucible-daemon/src/node_qualification/packet_collection/complete/installed/source/fresh_target/prepared/import18_templates.rs) | Retain the operational job, inputs, results and cleanup owner beside the original launch. |
| Engine Source construction | [import18_prebirth.rs](../../../crates/crucible/crucible-engine/src/node_adapters/cnp/semantic/packet_complete_source/ack_peer/import18_prebirth.rs) | Bind the actual Source and initialized occurrence; select the separate isolated transition and accept banks. |
| Transport launch and Coordinator schemas | [native5.rs](../../../crates/crucible/crucible-node-transport/src/reference_packet/service/native5.rs), [continuation.rs](../../../crates/crucible/crucible-node-transport/src/reference_packet/coordinator/continuation.rs) | Remain the defining schema, validation and decode implementations. |
| Pure SourceBirth and registration views | [views.rs](../../../crates/crucible/crucible-engine/src/node_adapters/cnp/semantic/packet_complete_source/ack_peer/import18_prebirth/views.rs) | Move within Engine behind the shared pure derivation facade. |
| Parent private Birth | [import18_construction.rs](../../../crates/crucible/crucible-engine/src/node_adapters/cnp/semantic/packet_complete_source/ack_peer/birth/import18_construction.rs) | Consume accepted banks and retain the real parent executable File, revision, fresh key and partial output. |

Earlier manifest, typed launch and original Source construction remain existing
input boundaries. They do not validate arbitrary new candidate Coordinator
bytes and are not requalified by this job. Later SDK, Initial, recipe, report,
bootstrap and native-startup consumers remain outside this delivery.

## Package and layer boundary

Add a dedicated L4 control-plane binary, proposed as
`crucible-source-birth-worker` under `crates/crucible/`. It calls a narrow
pure facade in the L3 `crucible-engine`, which composes the existing L2 Transport
schemas and validators. Proposed API names describe data operations only.

| Component | Responsibility |
| --- | --- |
| L4 worker | Read the private request, call the selected pure algorithm, write bounded banks or diagnostics. |
| L3 Engine pure facade | Share operand views, lossless codec and derivation algorithm with the in-process reference path; expose no Source or accepted-bank authority. |
| L2 Transport and Format | Keep current schema, strict parser, policy, canonicalization and scalar definitions; factor pure launch operand adapters here where required. |
| L2 HostResources | Supply the parent's generic process/storage containment, original child wait and quarantine custody. |
| Parent Daemon and Engine | Select the installed mechanism, retain the operation, authenticate the same Source and accept banks before private Birth. |

Use ordinary L4-to-L3-to-L2/L1 dependencies. Transport and HostResources gain no
upward Engine dependency or layer exception. Keep the worker root safe, with an
explicit binary target and no plugin or dynamic-library entry point. Do not
expose the entire private ack-peer module to make the binary compile.

Engine's dependency closure is larger than a pure-data library: it includes
other public APIs and permissive protocol/shared-memory crates. Disabling its
default features does not prove a minimal resolved feature or runtime closure.
Inspect the actual standalone production artifact. A future neutral-library
extraction may reduce that cost after measurement; it is not required before
this first connected path.

## One selected mechanism and one initialized occurrence

Freeze the private in-process or isolated-worker mechanism before Source
construction. The isolated selection binds the executable and runtime closure,
algorithm revision, private codecs and confinement/resource profile. Neither a
runtime environment variable nor an executable pathname selects authority.
Failure never falls back to the in-process path or renews the occurrence.

Factor initialization so the existing spent acknowledgement-Birth attempt,
registration and private-launch custody are retained exactly once. The isolated
branch begins from that same `Initialized` owner. It must not first run
`launch.validate` in the parent, require another Source, or mark the old
Validated/Coordinator/Materialized/Encoded stages complete without their
objects. Give this route explicit deriving and encoded-bank states instead.

The parent authenticates creator process/thread, original Source, installation
selection, unchanged launch operands, unbound preparation and original
registration before beginning the job. It installs an opaque, non-Clone,
non-Serialize job association and a quota-owned export destination before writes
or callbacks. Source loans end
before spawning, waiting or whole-Prepared observation. Conflicting Source
construction is unavailable until this retained job reaches its terminal state.

The parent binds its complete private launch identity, including withheld fields,
separately from the projected request digest. It retains original input and lease
currentness checks through export and acceptance. A redacted digest, exported
PID or child task identifier never replaces that original association.

An internal child task remains subordinate to the original logical operation;
it is not a new semantic operation ID. Same-ID retries return its retained
pending or terminal state and reject changed material. This first mechanism has
no automatic child retry and never retries ambiguous native work.

## Pure schedule and independent expected data

Preserve the complete existing pure schedule in the child:

1. Full launch serialization credit, storage/profile/metadata and selected
   tuple checks, controller/reference and schema checks, scalar checks,
   candidate ContentRef/media verification, the first Coordinator decode,
   program canonicalization and configuration comparison, then every selected
   policy constructor and its repeated decodes/validators.
2. The separate prebirth Coordinator decode and closed validation, followed by
   comparison against the actual retained original Source Coordinator.
3. SourceBirth/registration materialization, original Hello/prospective
   registration comparison, and both canonical encodings in their current order.

Factor a borrowed pure launch adapter used by both the original FullLaunch
reference and the worker projection. Do not synthesize a launch with dummy
secrets, paths or process fields. Transport remains the single schema owner;
Engine composes the pure workflow.

The expected Coordinator comes from the original producer/reactive Source,
not a second copy of the candidate. Parent origin and local-owner checks remain
real parent authority checks. Export their original dispositions where a later
comparison needs them; the child cannot exercise parent guards. Missing-world,
wrong-variant and reactive-owner refusals that originally follow candidate
decode must not replace an earlier malformed-candidate error. Carry deferred
closed refusal facts and consume them at the original comparison point, unless
the admitted preconditions prove them unreachable.

## Private input and result

Export exact candidate bytes plus exhaustive inert launch, registration and
independent expected-world operands. Keep admission-token contents, effects-path
spelling, signing keys, process/native handles and lease-control descriptors in
the parent. Controller PID/UID scalars and executable ContentRef are inert
operands, not transferable process authority.

Where launch serialization observes a secret only through its shape, export the
exact shape: unpadded URL-safe base64 serialized extent for the original token
length, and the exact quoted path extent or original invalid-UTF8 disposition.
Consume these facts at their original serialization positions. Observing a
ContentRef mismatch while sealing the copy must likewise not preempt an earlier
serialization/schema failure. Submission integrity/resource failures have their
own operational classification.

The projected-data codec must preserve the complete admitted typed domain:
string/key bytes, full signed and unsigned integers, finite float bits including
negative zero, ordered containers and literal reserved keys in both Serde
configurations. Use a lossless tagged stream with an iterative walker and a
checked, pre-admitted work-stack bank. The attempt owns partial stack and spool
output. Existing typed Source values have no assumed generic strict64 proof;
exhaustion is an explicit operational outcome, not a new semantic nesting limit.
A simpler encoding is acceptable only after full-domain equality proof. JCS is
used at the original output stage, not to compare typed expected data.

The planned response uses a fixed 240-byte versioned envelope with closed
status/stage/error tags, correlation and input commitments, two bank lengths
and digests, diagnostic length/digest, explicit coordinate presence/basis and
zero reserved fields. Success carries exactly SourceBirth then Registration and
EOF; errors carry no banks and a bounded diagnostic. Numeric tags, request
header fields and complete malformed/positive vectors must be frozen before
integration. Reject unknown, reordered, trailing or unscoped request roles.
No Rust enum layout or native pointer crosses the channel.

The parent validates the fixed header and checked length sum against the
original selected allowance before allocating payload storage. It reserves only
actual lengths, streams and hashes payloads through fixed buffers, retains all
partial bytes and requires exact EOF. It performs no general JSON/Coordinator
parse on the response. A checksum binds bytes; the installed algorithm and
original child/job association supply the trusted computation boundary.

## Error and acceptance order

Preserve the first pure error's category, reason and observable coordinates.
Strict quoted-token serde coordinates can be token-relative; do not relabel
them as whole-input coordinates or invent offsets by reparsing. Keep a closed
structured diagnostic beside the current outward mapping:

| Original failure | Parent runtime mapping |
| --- | --- |
| Launch validation or Coordinator decode/closed validation | UnsupportedFacet |
| Original Source-world comparison | ForeignAuthority |
| Either view-to-Value conversion or canonical write | ResourceLimit |
| Hello declaration | UnsupportedFacet |
| Prospective registration comparison | ForeignAuthority |

The private diagnostic is not a transported `serde_json::Error` object. Do not
manufacture an original JSON error with `Error::custom`, truncate diagnostic
text silently, or replace an earlier failure with a later census error.
Diagnostic construction/output must itself fit the actual admitted demand;
excess becomes a distinct operational resource failure.

Once the original child is reaped and its task population is empty, the parent
reauthenticates the same Source, selected mechanism, launch/plan, spent
occurrence and job association. Returned banks are retained before any fallible
join. A private, non-Clone, non-Deserialize accepted-bank owner is created only
through this join; arbitrary Vecs, hashes or serialized receipts cannot create
it. A separately admitted private-Birth entry consumes those same banks once
and invokes the genuine parent File/key construction. Rejection and partial
Birth failure retain the original banks and attempts.

Keep output SourceBirth/registration schema IDs, domains and semantics
unchanged only after byte-for-byte success and refusal-order parity. Worker
implementation/artifact identities change. Any published resource-axis, error
or extension incompatibility requires an explicit version/binding decision
before selection; it cannot be hidden behind existing Source18 labels.

## Enforced resources and cleanup

Generic containment must be extracted as an actual HostResources capability;
existing QEMU launch guards and planner process ownership are precedents, not
already qualified worker sandboxes. Install private storage quota before input
export. Before the worker executable or loader runs, install and authenticate:

- Memory and task/process ceilings, CPU rate plus a finite group-wide CPU and
  operational budget, descriptor limits and aggregate writable storage/output.
- A descriptor allowlist with fresh independent read-only input copies and
  dedicated result channels. Retain original read-lease/currentness authority in
  the parent; inherited read-only descriptors can still share mutable
  open-file-description controls.
- No-new-privileges, required credential separation, actual filesystem
  confinement and no network/native endpoint access. Derive and test syscall,
  loader and filesystem policy for the measured executable/runtime closure.

A production Linux profile can combine delegated cgroup-v2 controls, quota-owned
disk storage, a read-only measured runtime/input mount and isolated network
plus syscall restrictions. CPU rate alone is not a finite group-total budget;
per-process limits alone do not cover descendants. Either contain/account every
allowed descendant or enforce and verify that none can be created.

Use disk-backed input copies under real quota, not tmpfs or memfd. Filesystem
quota does not bound pipes: result/stderr readers need independent cumulative
limits, fixed drain buffers and concurrent drain/poll. Excess requests stop;
it must not grow an unbounded log or discard sink. Parent input/result,
executable/runtime overhead and cleanup overlap remain separately admitted.
Requested maxima are neither allocated backing nor proof of containment.

Install the caller-owned attempt and pre-reserved cleanup slot before spawn.
Retain the original child and wait/cleanup ownership throughout the entire spawn
handshake, including setup and exec failure. On successful return, transfer the
actual Child into the reserved owner before any fallible callback or observation.
A trusted `std::Command` path is acceptable if its actual internal Process,
exec-error and wait behavior, together with the enforced signal/reaper policy,
establishes this custody and cleanup invariant. That proof is implementation
work; a custom structural spawn return is not required by this plan.

Drop/unwind cannot drop the last cleanup owner. Submitted kill, EOF, timeout or
cancellation is not successful reap. Require the real primary wait result and
an authenticated empty task group, protected against child/group identity reuse.
Only then release namespaces, process limits and storage. Failed wait, kill or
group census transfers those same owners and partial results to quarantine.

Missing delegation or confinement returns HostControlsUnavailable before child
launch. There is no privileged retry, unsandboxed fallback or fabricated empty
group receipt. Deployment availability must be established by its registered
fixture; this plan establishes none.

The child receives only an independent inert disk-backed copy, without original
Source, native or lease-control descriptors. Irrevocable cancellation or caller
drop must revoke bank acceptance before the original Source, input and leases
may release through their normal owners. Retain the actual Child, cgroup,
watchers, private copied input, output, quota and cleanup slot until primary wait,
authenticated empty group and cleanup complete. Keep live same-ID registry and
terminal tombstone obligations separate: cancellation cannot renew the occurrence
or accept late banks, but those logical records do not require retaining all
original Source references for child cleanup.

Capture refuses while a job is active, containing or quarantined. Preserve the
logical operation, spent state and original result that affect later admission.
Cleanup of disposable pure scratch is not modeled rollback and must execute no
guest work. Completed bank/once provenance stays in the actual Source closure.
Any later pending-job snapshot support needs an explicit continuation/restart
contract; it is outside this delivery.

## Installation and implementation sequence

Build the worker separately from the broad controller/test-double package set,
using the pinned AOS workspace source, shared vendor and lockfile. Its measured
installation records the release executable/runtime closure, algorithm/codecs,
source/recipe provenance and supported host constraints. Build order is worker,
then measured installation, then the controller's compiled selection; the worker
must not depend on its parent installation. Include the worker in the controller
runtime closure and release artifact inventory, not only build dependencies.

Register the new package, bin and tests in the closed layer/artifact/unsafe and
workspace inventories. Verify actual source-filter membership and standalone
production feature resolution. Retain existing QEMU implementation exclusions
and permissive boundary neutrality. An Apache worker may link Engine and
permissive data/protocol crates; it must not link/load QEMU implementation,
include its headers or expose its callbacks. Patched QEMU distribution still
requires the matching corresponding-source artifact.

| Phase | Deliverable and finite exit |
| --- | --- |
| 1. Shared pure algorithm | Factor the Transport operand adapter and Engine facade; original in-process bytes/errors/order match an independent old oracle. |
| 2. Codec and worker artifact | Freeze lossless request/result vectors; build and measure the standalone L4 executable with its real dependency/runtime closure. |
| 3. Generic containment | Implement actual process/storage/descriptor/confinement ownership, proved spawn-handshake custody, bounded draining and wait/empty-group/quarantine. |
| 4. Parent integration | Extend the same Member/Source occurrence and whole-owner census; run the selected child, move two accepted banks into genuine parent Birth, retain every failed overlap. |
| 5. Qualified installation | Execute ordinary and real-control fixtures on final pinned source and bind only that accepted mechanism. |

These are work packages for one coherent delivery, not independent completion
claims. Source-only helper extraction must not be presented as the connected
worker milestone. Keep the original mechanism and ordinary tests intact.

## Validation and qualification boundary

| Test family | Required observation |
| --- | --- |
| Pure differential and codec | Actual producer/reactive fixtures; exact old/new banks and original typed expected equality; malformed/duplicate/unknown data, deferred guard order, UTF16 JCS order, literal reserved keys and full numeric representation in default/raw-value builds. |
| Real process protocol | Measured child, bounded output, crash/EOF/partial/foreign-task cases and parent-drop custody; absent host controls still refuse production authority. |
| Registered Linux containment | Genuine positive job and missing-control refusals; real memory/CPU/task/fd/storage/output limits, no outside writes/network/native handles, inherited-fd census, parent survival after child OOM/kill, descendants and delayed-reap quarantine. |
| Parent acceptance | Same initialized Source and actual registration; wrong Source/launch/plan/worker/mechanism, input change/lease revocation, exact/one-short bank admission, duplicate handoff, unwind and parent File/key failure retain originals. |

Use source-built AOS tools and registered checks. Positive containment cases
require actual delegated controls in the dedicated fixture; do not convert them
into ignored placeholders or report a refusal-only run as positive coverage.
Run the worker's own unit/integration/binary targets as well as applicable full
libraries, all-feature/all-target, strict and mandatory application-target gates.
Source capture by an application build alone does not prove compilation of this
private executable. Public process-boundary changes additionally need ABI and
license gates.

Worker success grants no Initial, recipe, bootstrap acknowledgement, native
Hold/Arm/World, execution, Ready, capture or fresh-restoration capability. Native
continuation, QEMU live-only integration, gem5 full-system and KVM qualification
remain separate RFC-0025 tracks. Measure matched derivation latency and peak
resources only after correctness and containment pass, including process startup
and enforcement cost; this plan promises no performance improvement and no
persistent worker pool.
