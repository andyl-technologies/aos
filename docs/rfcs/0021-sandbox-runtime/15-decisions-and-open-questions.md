# Decisions, alternatives, and open questions

## Decision ledger

These decisions are part of the proposed architecture rather than unresolved
implementation preferences.

| Area | Decision | Consequence |
| --- | --- | --- |
| Product surface | Sandboxes are generic resources; agents are ordinary clients | One lifecycle and security model serves development, CI, and automation |
| Hierarchy | Logical ancestry is independent of runtime, cgroup, storage, Git, and mount graphs | Descendants can move nodes without changing identity or unit paths |
| Runtime | nspawn transient units are the first backend | AOS reuses systemd supervision without exposing nspawn as the API |
| Host authority | An unprivileged reconciler uses separate root-only host, storage, mount, and network brokers | Public/network parsing never shares a root process with systemd, ZFS, or mounts; PID 1 and dataset authority remain split |
| Ownership expiry | An authority-signed lease arms a host-owned `CLOCK_BOOTTIME` guardian before start | Reconciler or guardian death and expiry stop the payload and default-drop its network before reassignment |
| Runtime control | No machined dependency in v1 | Sandbox identity and reconciliation remain portable and AOS-owned |
| Networking | Netd prepares a default-drop namespace and down veth; systemd joins it before nspawn exec | Guest boot has no pre-policy transmission interval and link activation follows readiness |
| Nesting | Child sandboxes are host-managed siblings | No guest receives nspawn, mount, systemd-host, or ZFS authority |
| Local storage | Prefer ZFS snapshots/clones when capability probes pass | Fast CoW does not make ZFS ancestry the logical tree |
| Dynamic mount | Native descriptor-based idmapped mounts are the first usable path | FUSE is not placed on ordinary live local I/O |
| Inspection | Immutable filtered views are the noninterfering default; native live reads require a kernel-coupling grant | Read-only mount flags do not silently grant socket/FIFO or inode-lock interaction |
| Portable view | FUSE serves immutable, filtered, synthesized, or remote trees | AOS builds namespace semantics while kernel passthrough carries file data |
| FUSE failure | Connections/workers are isolated per attachment or failure domain | Revocation and OOM have bounded blast radius at some mount overhead |
| Sharing | Only immutable verified bytes cross trust boundaries | Writable workspaces, Git state, and mutable caches remain private or serviced transactionally |
| Strict cache isolation | Separate backing-filesystem cache identities, not merely inodes | Cross-domain reflink, clone, dedup, and shared ARC keys are prohibited or placement fails |
| Git | Each sandbox owns an independent repository and uses Git smart protocol | Git is synchronization/history, never the security or lifecycle boundary |
| Nix | One authoritative store service per trust/disclosure domain | Sandboxes do not concurrently mutate one store with independent state databases |
| Package changes | Advance an immutable environment generation | Existing processes retain their old environment; future execs see the new mount |
| Suspend | Freeze is memory-resident; hibernate is snapshot plus stop | No claim of VM-like RAM, TCP, or FUSE request checkpointing |
| Snapshot | Manifest plus coordinated owned storage and pinned external immutable dependencies | Mounted shared writable state is rejected or explicitly outside rollback |
| Protocol | Public API, node protocol, local privileged protocol, and portable formats version independently | Multi-machine evolution does not expose Linux handles or freeze internal formats |
| Execution transport | V1 uses OpenSSH with holder-bound credentials and forced policy | The guest agent remains an internal control participant; another public stream requires a versioned follow-up RFC |
| Extensibility | Built-in traits first; out-of-process protocol for independent backends | No privileged `dlopen` ABI or Rust layout crosses trust/version boundaries |

## Rejected alternatives

### Git linked worktrees as sandboxes

Linked worktrees share a common Git directory, refs, object maintenance,
configuration, and lifecycle. They remain useful developer tooling but cannot
provide the required authority, storage, process, or failure boundary. This RFC
keeps ordinary repositories inside sandboxes and obtains same-node byte sharing
from CoW storage or verified immutable packs.

### Recursive nspawn

Giving a sandbox enough authority to start nested containers exposes a much
larger kernel, cgroup, mount, network, and device control surface. It also ties
logical descendants to one host. Descendant creation is an authenticated
request to the host service for another sibling runtime.

### Machined as source of truth

Machined supplies useful flat machine registration and administrative tools,
but it does not own AOS ancestry, capability delegation, storage lineage,
environment generations, cache leases, assignment fencing, or portable
snapshots. Its user-namespace dynamic-bind limitation also conflicts with the
native view path. Enabling it would add another identity and lifecycle database
without removing the need for the AOS controller.

Machined may be reconsidered later as a derived observability registration if
it provides a demonstrated interoperability benefit. It still would not
become the public API or authoritative store.

### systemd-mountfsd or systemd-nsresourced as the primary broker

These services solve useful generic namespace-resource problems, but the AOS
boundary requires sandbox incarnation fencing, source capability resolution,
view revisions, storage and cache leases, post-attach verification, and
portable multi-node semantics. Reusing their kernel-facing implementation
ideas is reasonable; making their current D-Bus models authoritative would
leak a different lifecycle and authorization model into the protocol.

They remain off for v1. A later reuse decision requires a concrete reduction
in privileged AOS code and proof that their authorization, descriptor, resource
accounting, and recovery contracts satisfy this RFC.

### FUSE for every file

FUSE is valuable when AOS synthesizes a namespace. Putting it in front of live
local workspaces creates avoidable metadata latency, failure coupling, cache
accounting, and coherence work. Native descriptor mounts preserve kernel
semantics for the common case; passthrough reduces data-path overhead for
immutable FUSE views.

### One shared writable build cache directory

Tool caches frequently contain mutable indexes, lock files, partial outputs,
absolute paths, and insufficient compatibility keys. Sharing such a directory
between mutually untrusted workloads creates corruption and disclosure
channels. Cross-boundary reuse is immutable CAS publication through a
validating service; private mutable accelerators remain inside their domain.

### One FUSE daemon for the host

A single connection minimizes process count but couples revocation, queue
congestion, OOM, malformed inputs, cache policy, and recovery across unrelated
projects. The default uses a worker/connection failure domain narrow enough to
stop or replace one attachment. Measurements may justify pooling workers, but
connections, quotas, leases, and abort authority remain isolated.

### Mutable distributed POSIX views

Correct rename, mmap, locks, cache invalidation, reconnect, conflict, and
failure semantics amount to a distributed filesystem. It is not a necessary
dependency for remote sandbox placement. V1 transfers immutable snapshots and
uses service protocols for mutation.

### Process checkpoint/restore

CRIU-style memory and kernel-object restoration adds substantial kernel and
application compatibility requirements and interacts poorly with FUSE,
networking, secrets, and external services. This RFC defines memory-resident
freeze and durable snapshot-plus-stop. A future checkpoint backend must expose
its narrower compatibility profile explicitly.

## Questions resolved by phase-0 measurements

These questions do not change the authority or object model. Phase 0 must
resolve them before the affected implementation is enabled:

1. What exact ZFS dataset decomposition minimizes snapshot pause and write
   amplification while excluding store, caches, secrets, sockets, and mounted
   views?
2. Does the production ZFS/kernel combination satisfy every required idmapped
   mount and clone behavior, or must a capability profile reject some identity
   maps?
3. Can the packaged Nix daemon's untrusted-client mode enforce project
   substituter, signature, GC-root, disclosure, and resource policy, or is a
   narrowing proxy required?
4. Which exact OpenSSH configuration meets startup, certificate,
   forced-command, forwarding-denial, PTY, signal, SFTP, audit, and closure-size
   requirements on AOS?
5. Which low-level Rust FUSE implementation has acceptable maintenance,
   cancellation, async, ABI, memory, and passthrough extension behavior under
   AOS's no-host-tools build policy?
6. Does idmapping a FUSE mount behave correctly on both supported
   architectures? Until proven, presentation metadata is synthesized per
   incompatible identity map.
7. What worker/connection grouping minimizes mount/process overhead without
   violating independent abort, quota, disclosure, and OOM failure domains?
8. Which backing layouts preserve passthrough and one page-cache identity for
   compressed NAR/CAS inputs without creating a second unbounded data cache?
9. What numeric latency, memory, mount-count, FD, snapshot amplification, and
   recovery budgets should each supported hardware profile enforce?
10. Does an enforcing SELinux design fit AOS's production policy, or should the
    host brokers use a different proven MAC/BPF-LSM confinement mechanism?

## Deferred protocol questions

The public protocol reserves independent versioning and capability discovery,
but it does not standardize premature mechanisms. Ownership exclusivity,
fail-stop lease expiry, and endpoint fencing are locked requirements; later
RFCs must decide:

- the consensus/storage implementation of the strongly consistent ownership
  lease authority and its operational deployment across failure domains;
- snapshot transport selection between ZFS send/receive and canonical portable
  trees for heterogeneous nodes;
- holder-bound remote capability encoding and federation trust;
- immutable remote revision notification and prefetch policy;
- cross-node service identity and project networking; and
- whether a derived industry-facing sandbox API profile is useful beyond AOS.

Those decisions may add transports or realizers. They may not expose node-local
paths/FDs as portable identity, weaken incarnation fencing, merge authority with
optimization, or turn unknown policy into permissive behavior.

## Criteria for reopening a locked decision

A locked decision can be reopened only with an RFC that states the invariant
it replaces, supplies an adversarial threat analysis, demonstrates a material
complexity or performance improvement, defines migration and protocol impact,
and passes equivalent exact-kernel fault, resource, and compatibility tests.
Convenience of an existing command-line tool or backend-specific API is not by
itself sufficient.
