# Security, compatibility, and operations

Campaigns retain complete machine state, accept structured guest input, run
large adaptive workloads, and move artifacts through pluggable stores. This page
describes their trust boundaries and fail-closed operational behavior.

## Trust domains

```text
scenario / policy author   trusted to define the admitted experiment
campaign operator          authorized to allocate, steer, retain, export
guest application          untrusted protocol producer
QEMU / plugin process      separate GPL process; protocol peer
coordinator                sole writer of the campaign ref and facts
local executor             trusted host appliance; returned bytes untrusted until validated
planner engine             untrusted pure proposal producer
store graph / backends     untrusted for integrity; trusted per deployment for availability
```

Every object that crosses a process or store boundary is length-bounded,
schema-validated, and content-authenticated before use. A faulty executor or
planner can withhold work or return bad bytes; coordinator validation, replay,
and content checks reject inconsistent objects. Planner processes receive a
read-only bounded planning bundle and no store credentials or ref capability.
Executors receive only the immutable-object capability their attempts need.

## Guest protocol safety

Guest choice and measurement messages are untrusted. Admission ceilings cover
counts, identifier bytes, alternatives, landmarks, constraints, outstanding
requests, message sizes, and per-run totals. Decoders validate before
allocating, use checked arithmetic, reject aliasing offsets, and never reflect
unbounded guest strings into logs. A guest can only request a selection from an
admitted guest domain; it cannot request an undeclared environment mutation or
supply its own effect.

A guest choice deadlock is bounded by modeled timeout and lifecycle policy, and
the host records whether a timeout occurred before or after a selection was
committed. A policy virtual-time or quantum timeout is a replayable modeled
result. Expiry of the optional host watchdog is an infrastructure abort and is
never published as a guest timeout.

## Resource admission

Before running, the daemon validates ceilings for selectables, candidate and
observation cardinality, branch depth and path length, request, proposal,
attempt, and finding counts per grant, event-log, coverage, metric, and
projection bytes, hot templates, live worlds, vCPUs, RAM, dirty pages,
descriptors, and overlays, exact-closure and store quotas, and per-step planner
computation, output, reads, fuel, cancellation, and wall-clock supervision.

No admitted policy algorithm may have a single poll, decode, or validation step
that is unbounded in its admitted input. Resource exhaustion pauses or rejects
work with explicit status; it never silently changes selected values, stop
conditions, or modeled faults.

## Hot-fork isolation

The fork coordinator is a high-risk QEMU capability. It requires a closed
supported-device and backend manifest, one authorized host controller and
generation, exact quiescence acknowledgements, complete inherited-descriptor
disposition, new branch-private disks, rings, sockets, logs, and temporary
files, containment reapplied before resume, a template that cannot receive
child commands, children that cannot reach siblings, and rollback of every
child on a partial world-fork failure. A child executes no guest instruction
before its rebind is acknowledged, and the capability is unavailable for any
launch profile, device, backend, or kernel outside the validated manifest. See
[hot fork and checkpoints](hot-fork-and-checkpoints.md).

## License and process boundary

QEMU fork coordination, device quiescence, VMState extraction, and any code
that includes QEMU headers are GPL-side. The Apache host sends public protocol
commands and stores opaque, versioned artifacts. Shared memory contains checked
offsets and wire values, never QEMU or Rust-native objects. Guest assertions,
objectives, guidance, and policy evaluation stay in the Apache host. The
normative policy is [Crucible licensing](../../../legal/licensing.md); every new
or removed QEMU file updates `pkgs/emulation/qemu-patches/LICENSES.md`.

## Provenance and compatibility

A campaign lineage records the scenario schema and ID, policy and generator
versions, Crucible version, QEMU build and atomic-patch digest, machine type
and device capability manifest, control, shared-memory, guest-choice, and
measurement protocol versions, exact-closure and codec versions, deterministic
execution capabilities, and immutable guest image and configuration
identities.

- Every decoder admits only its exact current version and rejects every other
  version before interpreting the body.
- Runtime and offline tools never rewrite noncurrent objects into current ones;
  producers create current authenticated objects directly.
- Exact closure restore requires the declared QEMU, machine, and device
  contract.
- Hot templates never survive a daemon or QEMU restart.
- Replay is separately typed and authenticated; it is not a fallback for
  incompatible exact state.

| Change | Reuse |
| --- | --- |
| Worker count, memory limit, cache policy | Same snapshot semantics; operational only |
| Additional budget grant | Same lineage; accounting fact |
| Guidance weights or candidate policy | Same lineage; new policy revision for future proposals |
| Retention policy | Same lineage; new policy and pin projection |
| Objective over already retained samples | Same lineage; re-evaluate observations |
| Choice domain, signal program, topology, workload, or property semantics | New scenario and lineage |
| Guest or QEMU binary, atomic patch | New lineage |

There is no prefix-equivalence reuse across scenario changes. Variation a user
expects to explore should be declared as choice domains in the original
scenario.

## Authorization

The local campaign listener derives its principal from Linux peer credentials,
never from a request assertion. `crucible_daemon::campaign_policy` loads a
strict, bounded `crucible.campaign-local-policy` TOML file that maps exact
effective UID/GID pairs to principals and grants each principal individual
`CampaignServiceOperation`s for one campaign name or all names (`"*"`).
Unknown fields and operation labels fail closed, and the PID is retained only
for diagnostics. Mutating commands carry the principal, a command ID, the
expected snapshot, and authorization evidence; the principal is audit metadata
and never enters modeled identity. Exact-state access (savepoints, finding
objects, debug sessions, triage replay) is granted as separate operations, so
ordinary campaign operation does not imply access to retained guest state.

The policy file and the durable campaign state root must be exact-owner
regular files and directories with no group or other write permission. The
state root is single-writer locked for the daemon's lifetime, the socket
namespace is held under an exclusive lock, stale cleanup is limited to
same-owner sockets, and different socket paths cannot let two daemons share one
campaign ref namespace. `crucible serve --read-only` denies every campaign
mutation after ordinary authorization, so a permissive policy file cannot
weaken it. The user guide shows a policy example in
[Start the single-host owner](../../../users/crucible/campaigns.md#start-the-single-host-owner).

## Failure behavior

| Failure | Behavior |
| --- | --- |
| QEMU child or executor operation dies | Reservation discarded; attempt repeats |
| Coordinator or daemon dies | Campaign ref stays valid; projections and queues are rebuilt |
| Store write interrupted | Unreachable staging or incomplete multipart object; old ref remains |
| Ref compare-and-swap conflict | Stale command rejected; the head is re-read and an unexpected conflict is diagnosed as an ownership violation |
| Duplicate observation | Idempotent content and credit admission |
| Conflicting observation | Conflict retained; affected planning path stops |
| Hot child rebind fails | Child killed; no graph edge; another tier is used |
| Store tier unavailable | A policy-admitted readable tier is used, or work pauses; durability is never silently weakened |
| Host maintenance | Exact closures persisted and pinned, hot processes released, offline transfer, separate restore |

No operational failure becomes a modeled result unless the scenario explicitly
models that failure through a recorded selection and execution evidence.

## Export

An archive is described by a content-addressed `CampaignArchiveManifest`
(`crucible_campaign::archive`): the source snapshot, the closure policy
(`metadata`, `findings`, `debug`, `executable`, or `mirror`), the selected exact
checkpoints, the retained roots, and digests of the selected and omitted
inventory pages. Inspection reports object counts and logical bytes split into
metadata, evidence, and guest-state classes for both the selected and omitted
sets, so an operator can see how much retained guest state an export carries
before moving it.
