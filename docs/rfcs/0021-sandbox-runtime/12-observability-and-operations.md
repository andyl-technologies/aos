# Observability and operations

## Resource status

Every resource exposes desired state, observed state, conditions, generation,
resource version, assignment epoch, and last successful reconciliation time.
The system does not collapse these into one optimistic status string.

The portable public status correlates:

- portable sandbox UID and current incarnation;
- desired and observed lifecycle phases;
- assigned node, assignment epoch, ownership lease generation/expiry, and
  guardian state;
- backend capability profile, root generation, and transaction state;
- environment generation and pinned closure references;
- attachment generations and health;
- active execution resources;
- cache/disclosure domain and logical usage; and
- the most recent audit-event cursor.

Protected operator diagnostics and coordinator-node observations additionally
correlate transient-unit invocation, cgroup, payload pidfd, namespace, mount,
FUSE-worker, dataset, snapshot, and storage-transaction identifiers. The
broker-local inventory is narrower still and uses only the handles required by
its fixed operations. These are distinct schemas and authorization surfaces,
not optional fields in the portable public resource.

PIDs, unit names, cgroup paths, namespace inode numbers, mount unique IDs, ZFS
dataset names, and worker processes are node-local observations. They never
become durable public identity or authorization input.

## Conditions

Conditions are typed and include `True`, `False`, or `Unknown`, desired
generation, observation sequence, reason, last-transition time, and freshness.
The observation sequence is monotone; condition truth may change without a
desired-generation change as health or dependencies change. A new observation
replaces the named condition at a higher sequence rather than merging by wall
clock. Representative conditions are:

- `Ready`: the runtime and every required policy/attachment are verified;
- `EnforcementReady`: all hard policy is installed;
- `ViewsReady`: requested attachment generation is present in the current
  namespace generation;
- `EnvironmentReady`: the selected environment closure is realized and pinned;
- `Quiesced` or `Frozen`: the corresponding barrier is observed;
- `Degraded`: an explicitly advisory feature is unavailable;
- `Blocked`: reconciliation needs capacity, a dependency, or operator action;
- `Fenced`: an assignment or incarnation lost authority and its guardian has
  contained the payload; and
- `ResidualState`: deletion is logically complete but node-local resources
  still require reaping.

`Ready` is false if a hard mount attribute, identity mapping, seccomp rule,
network filter, quota, or capability restriction cannot be verified. A FUSE
fallback may be selected only if it satisfies the requested semantic and
security capability; it is not a universal way to turn enforcement failure
into `Degraded`.

## Events and audit

State changes append structured events with a stable event UID, timestamp,
resource version, operation ID, actor, authenticated transport identity,
decision, policy revision, node epoch, and causal predecessor. Watch streams
are resumable from a cursor. A cursor gap requires a relist and does not permit
the consumer to infer missing authorization decisions.

Audit events cover:

- capability issue, attenuation, use, expiry, and revocation;
- ownership lease issue/renewal/expiry, broker-plan acceptance, and guardian
  containment;
- create, place, start, stop, suspend, resume, fork, restore, and delete;
- execution admission, attachment, exit, cancellation, and data-channel
  principal;
- filesystem-view publication, replacement, detach, and hard revocation;
- snapshot barrier outcome and every external dependency;
- cache admission, cross-domain denial, pin, and generation-fenced eviction;
- backend capability or policy drift; and
- privileged broker requests and their closed typed result.

Audit records contain opaque resource identifiers and normalized relative
slots, not secret material or arbitrary host paths. Command arguments and
environment values follow a separate redaction policy; they are not logged
wholesale by default.

## Metrics

Metrics are bounded in cardinality. Project, backend, node, status class, and
capability profile may be labels; sandbox IDs, mount IDs, content digests, Git
references, and paths are not general metric labels.

Required metric families include:

- sandbox and execution counts by phase;
- reconcile attempts, duration, conflicts, fencing failures, and residuals;
- lease renewal margin, guardian expiry/death containment latency, and stale
  cleanup denial;
- create-to-ready, exec-start, freeze, snapshot, resume, and delete latency;
- active native and FUSE attachments, replacement and detach duration;
- FUSE requests, queue congestion, errors, forgets, open handles, registered
  backing files, fallback bytes, and worker restarts;
- structural-index mapped bytes, resident bytes, nodes touched, and rebuilds;
- logical cache bytes, physical resident bytes where measurable, residency
  profile, authorization leases, kernel pins, duplicate avoidance, and
  evictions;
- cgroup CPU, memory, swap, I/O, PID, pressure, and OOM events;
- operation-scope CPU, memory, PIDs, I/O, network, logs, staging, cancellation,
  and output by project/class;
- ZFS ARC size, metadata/data split, hit/miss, dirty, reclaim, configured
  maximum, and pressure interaction;
- ZFS referenced/logical bytes, quota failures, snapshot holds, and clone
  lineage depth; and
- leaked or mismatched namespaces, mounts, units, datasets, leases, and
  allocation records found by reconciliation.

## Logs and traces

Control-plane requests, reconciler steps, node operations, guest-agent calls,
and view realization share operation and trace IDs. The privileged brokers log
the fixed verb, validated object handles, peer identity, generation fence, and
outcome. They do not accept or log arbitrary option maps.

FUSE per-request logging is disabled in normal operation because it is high
volume and can disclose path information. Bounded diagnostic sampling requires
an operator capability and applies path hashing or redaction appropriate to the
disclosure domain.

## Reconciliation inventory

After daemon restart, systemd daemon-reexec, or host reboot, the node compares
durable intent with an independently enumerated inventory:

- transient units and invocation IDs from the manager;
- assignment guardians, boot IDs, authority expiries, and lease generations;
- cgroup IDs and payload membership;
- live pidfds and namespace identities;
- mount topology and unique IDs through `listmount` and `statmount`;
- FUSE connections and worker ownership;
- ZFS datasets, origins, snapshots, GUIDs, and holds;
- UID/GID and network allocations;
- GC roots, cache leases, and content generations; and
- guest-agent incarnation handshakes.

Names alone never establish ownership. Every adopted object must carry or
resolve to the expected sandbox UID, incarnation, and node epoch. Ambiguous
objects are quarantined and surfaced as residual state; the reconciler does not
guess and delete them.

## Capacity and admission

Nodes publish allocatable and reserved capacity for CPU, memory, swap, PIDs,
storage, UID/GID ranges, veth/network policy, mount count, FUSE connections,
worker memory, file descriptors, and cache residency. Admission reserves hard
capacity before creating effects. Reservations are reconciled against actual
usage but are not silently overcommitted across hard boundaries.

Operators can cordon a node, drain selected sandboxes through snapshot/stop and
replacement, or leave durable sandboxes stopped in place. A node does not
advertise migration merely because snapshots can be copied; destination
runtime, filesystem, identity, and environment capabilities must all match.

## Upgrades

Daemon upgrades use versioned durable records and a read-old/write-current
migration path. Rollback remains supported until every record has crossed the
declared compatibility point. The controller, node daemon, brokers, guest
agent, and FUSE worker negotiate protocols independently.

This deployed-upgrade contract does not require preserving every PR-only
predecessor before initial delivery; section 18 defines that cleanup baseline.

An upgrade that changes canonical snapshot or tree semantics creates a new
format version; it does not reinterpret old signed objects. A node-local mmap
index may simply be invalidated and rebuilt.

Rolling upgrades fence each node assignment, stop new admissions, drain broker
operations, and prove inventory reconciliation before the node is uncordoned.
Changing the systemd, kernel, ZFS, or seccomp capability set triggers the same
probe and readiness process as a fresh node.

Initially those admission/drain/recovery steps apply to the single host.
Fleet rolling-upgrade coordination and cordon scheduling belong to the later
multi-node phase, not a required service for local upgrades.

## METHOD46 floor initialization and recovery

The initial Controller Storage-client and Storage-broker floor producers remain
unqualified. Public admission stays closed until the genuine funded producers,
installed journal hooks and connected QEMU/vTPM recovery gates pass. The
canonical record codecs and a successful transport fixture do not provide an
operator initialization command. The current status is tracked in
[the implementation ledger](16-implementation-tasks.md).

Initialization is a separate manual purpose. Normal daemon startup consumes a
completed floor and cannot initialize one or adopt an initial intent. The two
purposes have fixed, distinct NV indices and salt handles, as specified in
[the initial approval format](09-protocols-and-formats.md#initial-method46-provisioning-approval).
A producer must independently establish its normal public pins, the approval
key's separation from endpoint/Nix/Root keys, stopped owners and native cgroups,
exclusive main-writer custody, and exclusion of concurrent jobs and migrations.
Its canonical request comes from that same held, schema-admitted main journal.
A copied cut, supplied key or matching filename establishes none of these facts.

Independent approval covers the entire canonical request. The producer must
publish and fsync the separate signed `AOSBII01` intent and its parent before
its first encrypted Extend. Cold recovery must reverify the approval and the
same current request before interpreting authenticated TPM observations:

| Retained initial state | Required disposition |
| --- | --- |
| Approved intent and exact authenticated Unwritten index | The first Extend remains outstanding. |
| Same approved intent and authenticated Written value equal to its first target | Publish the initial checkpoint without another Extend. |
| Changed request, invalid approval or conflicting Written value | Refuse initialization and preserve the retained state. |
| Already completed initial checkpoint | Fence repeated initialization; normal startup owns subsequent recovery. |

These dispositions are comparison results. Only the genuine funded owner with
current native custody may perform the corresponding durable or TPM operation.
The initial intent is distinct from the normal successor `AOSBTI01` intent and
must never be converted into one to bypass startup admission.

After initialization, main history, the `AOSBTF01` checkpoint, any exact prepared
successor transaction and the authenticated NV value form one recovery state.
A restart may complete only the exact prescribed successor. Missing, malformed,
foreign or divergent state leaves admission closed; it cannot be repaired by
copying an older checkpoint over a newer one. Diagnostics identify the fixed
purpose and refusal stage without exposing private index authentication,
hierarchy authentication or signing seeds.

## Backup and disaster recovery

The local Controller journal, protected ownership/domain state, retention
ledger, portable snapshot manifests, canonical tree objects, and required
immutable content are backed up according
to their independent retention policies. Node-local unit names, mount IDs,
FUSE indexes, and rebuildable caches are not backup state.

The later multi-node phase additionally backs up its coordinator state under
its own retention and authority policy. A coordinator database or remote
backup authority is not a dependency of initial single-node operation.

A restore drill must prove that held storage snapshots and external immutable
dependencies still match their recorded identities. Missing dependencies leave
the sandbox stopped and `Blocked`; recovery never substitutes a different
environment or cache object with the same display name.

For a METHOD46 deployment, a disk backup is not a rollback mechanism for the
physical TPM. Preserve the protected main journal and floor sidecar together
with the exact immutable deployment/profile and public salt-key identity; keep
credential recovery material under its separate secret-storage policy. An
older disk image must still pass current authenticated NV reconciliation.
Restoring a matching disk/TPM pair is useful in an isolated QEMU qualification
test but does not demonstrate that an older production disk can pass a newer
physical floor.

TPM loss, clearing, replacement or an unavailable pinned salt key is not an
ordinary daemon restart. Do not redefine the existing index, generate another
salt key or reuse initialization to make the old history appear current. Such
a deployment remains blocked until an explicitly authorized reprovisioning or
migration procedure establishes its new scope and retained-state disposition.
That procedure is a release requirement; it is not supplied by the initial
record decoder or by the test-only provisioning fixture.
