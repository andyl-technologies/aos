# Architecture and component boundaries

## Overview

```text
CLI / API clients
        |
        v
Sandbox control service
desired state, capability evaluation, scheduling, audit
        |
        +---------------- coordinator-to-node assignment ----------------+
                                                                         |
                                                                         v
                                                               aos-sandboxd
                                                       node reconciliation and
                                                            desired state
                                               /   |    |    \
                                              v    v    v     v
                                      aos-viewd  hostd mountd netd
                                          |       root fixed-function brokers
                              +-----------+-----------+
                              v           v           v
                         FUSE workers  publisher  source adapters
                              |           |           |
                              +--- immutable backing -+
                                          |
                                   short-lived mount
                                    namespace worker
```

The names are implementation-oriented and are not embedded in portable
resource identities.

## Sandbox control service

The control service owns:

- public authentication and authorization;
- project and ancestry policy ceilings;
- capability issuance and revocation generations;
- durable sandbox, view, attachment, snapshot, and lease desired state;
- node placement, assignment epochs, and capacity reservations;
- idempotency records and audit events; and
- orchestration of multi-object operations such as snapshot and cascading
  deletion.

It never performs host mount syscalls and never serializes a host path into a
node assignment.

## `aos-sandboxd`

The node sandbox daemon owns:

- reconciliation of assigned sandbox generations;
- desired transient-unit construction and unprivileged observation;
- runtime backend lifecycle;
- storage-backend transactions;
- the catalog of sandbox exports and destination slots;
- coordination of freeze, snapshot, restore, and deletion barriers;
- node-local view and mount leases; and
- reporting requested versus observed enforcement.

It is unprivileged and delegates host mutations through typed local protocols.
It does not shell out to `systemd-run`, `systemctl`, `machinectl`, `nsenter`, or
`zfs` in the production path.

## `aos-sandbox-hostd`

The root-only host broker owns the narrow systemd and storage operations that
AOS has not proven safe to delegate directly to an unprivileged daemon. It:

- calls the typed `aos-systemd` transient-unit API;
- verifies unit names, property sets, sandbox generation, and cgroup ancestry;
- performs closed storage-driver operations over broker-owned datasets;
- returns pinned observations rather than reusable host paths; and
- has no public/network listener, source parser, or project-policy evaluator.

The broker accepts a fixed operation vocabulary, not arbitrary D-Bus
properties, unit fragments, commands, ZFS subcommands, or dataset names. If a
future AOS policy mechanism proves that `aos-sandboxd` can safely perform an
operation without root, that individual verb may move out of the broker after a
separate review.

## `aos-viewd`

The view service is unprivileged and owns:

- source-adapter execution;
- validation and canonicalization of untrusted tree descriptions;
- portable tree object storage;
- compilation of node-local mapped indexes;
- verified immutable backing objects;
- cache admission, reservations, pins, eviction, and scrub;
- materialization and prefetch scheduling; and
- supervision requests for per-view FUSE workers.

It has no mount-namespace administration capability. Network credentials are
scoped to source adapters and disclosure domains. A FUSE worker has no upstream
network access; cache misses are requested from the view service.

## `aos-view-publisher`

The publisher is a separate, networkless service identity that alone owns the
committed portable-object, mmap-index, and immutable-backing roots. Producers
write only private staging. The publisher creates a new inode under its own
root, copies or safely reflinks from a passed staging descriptor, hashes and
validates size after the copy, fsyncs file and directory, and publishes with
no-replace semantics. A reflink is acceptable only when later producer writes
cannot modify the published inode.

Neither `aos-viewd`, a source adapter, a FUSE worker, nor a sandbox receives a
writable descriptor or directory permission for a committed inode. Read-only
mode bits and service ownership are defense in depth, not the final
immutability mechanism. A backend must enable
[fs-verity](https://docs.kernel.org/filesystems/fsverity.html) on a supported
filesystem and bind its measured digest, or expose only a read-only ZFS
snapshot generation (or an equivalently proven immutable primitive). Live ZFS
dataset inodes are not passthrough backing merely because the publisher owns
them. Publication closes every staging writer before the sealed object becomes
eligible for passthrough. The same protocol protects executable backing files
and mapped indexes, not only downloaded content.

## Per-view FUSE workers

FUSE workers are separate transient systemd services with one attachment-owned
connection by default. A measured implementation may host compatible
connections in one process, but disclosure, quota, abort, and accounting remain
per connection. They:

- serve the immutable lookup/readdir/getattr/readlink/open protocol;
- retain only touched inode state;
- map the validated runtime index read-only;
- request authorized backing handles from the view service; and
- request privileged passthrough registration from the mount broker.

They run outside sandbox cgroups and freezer domains. Freezing a sandbox must
not freeze the filesystem server required by that sandbox. Workers receive
explicit memory, FD, task, and request-queue limits; one worker failure faults
only its attachments.

An active FUSE connection is not handed to a replacement daemon as an upgrade
mechanism. Upgrades drain attachments and remount a new worker generation.

## `aos-mountd`

The privileged broker has:

- no upstream network access or credentials;
- no generic command execution;
- no parsing of NAR, Git, OCI, project configuration, or remote manifests;
- no public listener;
- no acceptance of arbitrary source or destination paths; and
- a small typed local IPC with strict message and FD bounds.

It owns a catalog of broker-minted opaque handles backed by pinned descriptors.
Callers cannot turn an arbitrary descriptor into a mount source. The broker
verifies the caller's Unix credentials, sandbox generation, operation, handle
class, mount attributes, target slot, and expected FD roles.

Mount-namespace entry occurs only in a single-threaded, short-lived worker. The
long-lived async broker never calls `setns(2)`. The child receives validated
descriptors and a closed syscall plan, applies it, returns a structured result,
and exits.

The worker is a separate fixed helper executable started through a safe
fork/exec or clone/exec path; it never continues Rust code in a copied
multithreaded broker process. Before namespace entry it receives a sealed plan
and exact FD-role table, applies `close_range`, resets signals, installs a
sanitized empty environment, and sheds unrelated capabilities. After entry it
uses pinned target-root descriptors, `fchdir`/`chroot`, and a narrow seccomp
profile so the old host root and cwd remain unreachable. It must exit after one
operation.

FUSE passthrough registration currently requires `CAP_SYS_ADMIN`. The broker
performs the registration only for immutable, verified backing handles in the
same disclosure domain as the FUSE connection. It never accepts a caller's
unclassified arbitrary file descriptor for registration.

## `aos-netd`

The root-only network broker owns fixed netlink and firewall operations for
sandbox veth creation, address/route assignment, egress policy, published
endpoints, teardown, and inventory. It accepts typed profile handles and
prevalidated endpoint sets, never arbitrary nftables text, interface names, or
commands.

Every request binds sandbox UID, incarnation, assignment epoch, policy
generation, network-namespace descriptor, and expected link identity. The
broker verifies netns, ifindex, link peer, MAC, and allocation generation after
effects; interface names are diagnostics because they truncate, collide, and
are reusable. Network leases and external rule objects carry the same fencing
token as the assignment.

## Source adapters

An adapter translates a source into the generic view model. Initial adapters
are:

- AOS/Nix closure and NAR;
- local sandbox export;
- AOS sandbox snapshot;
- Git commit/tree;
- local immutable directory registered by the broker; and
- OCI artifact layers.

Adapters parse and validate before the FUSE syscall path. They produce portable
tree objects, content descriptors, and source-specific provenance. Adapter
names and versions are capabilities negotiated with the node; the core service
does not grow a universal request containing optional fields for every source.

## Reuse versus build

| Facility | Decision |
| --- | --- |
| systemd transient units and cgroup v2 | Reuse through `aos-systemd`. |
| `systemd-nspawn` | Reuse as the initial runtime backend. |
| `systemd-machined` | Optional future inventory projection; not authority. |
| `systemd-nsresourced` | Reconsider for future unprivileged UID-range delegation; not v1. |
| `systemd-mountfsd` | Reuse neither protocol nor privilege boundary for tree views. |
| Linux new mount API and pidfds | Use directly behind a small audited Rust UAPI boundary. |
| OpenZFS | Reuse for datasets, clones, snapshots, quotas, and holds where available. |
| overlayfs | Reuse for one bounded private CoW layer over an immutable lower. |
| FUSE protocol implementation | Prefer a maintained Rust library if the passthrough and cancellation spike passes; do not rewrite the protocol gratuitously. |
| `aos-cache` | Reuse transport, compression, and Nix-cache concepts; build a separate lease-aware node residency engine. |
| AOS protobuf/Connect infrastructure | Reuse for public and coordinator APIs. |
| Git smart protocol and libgit2 | Reuse; put AOS authorization in front of standard upload-pack/receive-pack transport. |

The current `rustix` dependency may not expose every Linux 6.18 operation. Any
direct syscall wrapper is isolated in a small Linux-only module or crate, uses
the kernel UAPI definitions, documents each `unsafe` invariant, and has ABI,
size, invalid-FD, namespace-race, and seccomp tests.

## Failure containment

The component boundaries prevent several node-wide failure modes:

- malformed tree data cannot directly exercise mount privilege;
- a network parser compromise does not gain `CAP_SYS_ADMIN`;
- a public API compromise cannot send arbitrary properties to PID 1 or commands
  to ZFS;
- one FUSE worker OOM does not abort every active view;
- cache eviction cannot directly detach a mount;
- sandbox payload OOM does not kill its filesystem worker; and
- mount broker failure leaves durable desired state for reconciliation rather
  than becoming the only record of what exists.
