# Testing and performance gates

## Test philosophy

This subsystem crosses the kernel mount API, namespaces, systemd, ZFS, FUSE,
Nix, Git, networking, and distributed reconciliation. Unit tests alone are not
evidence that the boundary works. Release gates run the production path on the
exact AOS kernel, systemd, libseccomp, ZFS, and userspace builds on every
supported architecture.

Tests use AOS-built tools and hermetic fixtures. They do not introduce nixpkgs,
host Docker images, host `fusermount`, or an untracked dependency on a runner's
systemd configuration.

## Model and protocol tests

Property and state-machine tests cover:

- sandbox, execution, snapshot, attachment, and operation transitions;
- ancestry changes, cycle rejection, depth/fanout limits, and post-order
  subtree transactions;
- capability attenuation and the intersection of node, project, ancestor, and
  request policy;
- reservations, ownership lease generations, semantic-plan identity, kernel
  pins, expiry, guardian fail-stop, generation fencing, and idempotency;
- concurrent operations with stale resource versions or assignment epochs;
- public protobuf compatibility, unknown observation fields, and rejection of
  unknown authority-bearing fields; and
- portable tree, sparse layout, view, snapshot, trust-policy, signature
  statement, and descriptor-role canonicalization independent of
  serialization.

Fuzz targets include public RPC decoders, portable tree parsers, snapshot
manifests, local `SOCK_SEQPACKET` frames, descriptor-role tables, path
normalization, and journal recovery at every effect boundary. Fuzzed local
messages include missing, extra, duplicated, reordered, wrong-type, and
credential-mismatched file descriptors.

## Linux boundary tests

The audited Linux wrapper tests invalid and recycled pidfds, namespace file
descriptors, empty paths, overlong names, all flag combinations, wrong mount
types, stale mount IDs, and errors before and after namespace entry. Tests run
on x86_64 and aarch64 so numeric syscall filtering and any vendored UAPI cannot
accidentally cover only one architecture.

The path-race corpus includes `..`, symlink swaps, magic links, bind mounts,
mount crossing, renamed targets, deleted parents, procfs links, hard links,
concurrent replacement, and attacker-created nested mounts. Sources are
resolved beneath pre-opened roots and attachment slots remain broker-owned.

Crash injection occurs after intent persistence, storage creation, unit start,
pidfd acquisition, mount preparation, namespace publication, post-publication
verification, observation persistence, and acknowledgement. Every case must
reconcile to exactly one verified generation or an explicit blocked/error
condition.

Publisher injection covers writer close, hash, seal enable/verify, private
inode fsync, no-replace publication, final-parent fsync, and catalog commit.
Recovery may adopt only the exact sealed object or quarantine it.

## Runtime VM tests

Production-equivalent VM tests prove:

- a booted nspawn sandbox with machined absent and `--register=no`;
- hostile image and host `.nspawn` settings cannot alter the fixed launch plan;
- user namespace maps, capability bounding, pre-PID1 argument-aware seccomp,
  device policy, cgroups, and private networking match the admitted policy;
- the service manager joins the broker-pinned network namespace before nspawn
  exec, nspawn receives no namespace path, and private-user setup cannot replace
  or escape that namespace;
- supervisor and payload cgroups are identified correctly;
- guest reboot changes namespace generation and replays attachments;
- daemon restart, systemd daemon-reexec, and host reboot reconcile desired
  state without adopting unrelated units;
- node-daemon death, every broker death, guardian death, ownership-lease
  expiry, host suspend past expiry, boot-ID change, and stale renewal replay
  default-drop networking and stop the old payload before reassignment;
- OpenSSH supports command, PTY, resize, signal, exit, disconnect-cancel, and
  detached bounded-output behavior, while the in-sandbox agent performs only
  readiness, authorization handoff, observation, and quiesce without
  privileged-path command parsing;
- immutable parent inspection works while child-to-parent and sibling access
  fail; native kernel-coupled inspection separately proves and reports
  socket/FIFO and lock interaction; and
- network profiles deny, route, and publish only their declared flows,
  including a packet attempt at every prepare/start/readiness boundary,
  spoofing, tc-BPF `CLOCK_BOOTTIME` lease expiry during host suspend/resume,
  guardian/netd death, and namespace exhaustion cases.

The security profile gate runs with the production MAC mechanism enforcing.
It proves that sandboxd, hostd, the mount worker, view workers, guest agent, and
payload have their declared domains. It separately covers storaged and its
workers, netd, the guardian, and the host-privileged nspawn supervisor with its
exact path/device/capability/syscall/address-family allowlists. The current
permissive or disabled AOS SELinux posture is not accepted as evidence for this
gate.

## Storage and lifecycle tests

Tests exercise the production ZFS version and the real dataset layout:

- snapshot, hold, clone, quota, refquota, and deletion at high depth/fanout;
- logical ancestry different from ZFS origin ancestry;
- parent deletion before child and out-of-order snapshot release;
- same-domain but cross-account clone refusal, worst-case retained-origin
  charging, and cross-account materialization;
- ZFS publication exposes only an already-held read-only snapshot GUID, and
  crash recovery never adopts a live dataset as immutable backing;
- crash-consistent and guest-quiesced coordinated snapshots;
- attached native and FUSE views during snapshot;
- exclusive writable-export lease conflict and drain;
- restore with a new incarnation after node restart;
- suspend with verified no-progress and later thaw;
- hibernate without claims about RAM, TCP, or open FUSE requests;
- open-FD delayed reap, hard revocation, and interrupted cascade deletion;
- expired-plan cleanup cannot release shared holds, destroy reassigned state,
  roll back publication, or remove current external endpoints; and
- storage send/receive only between endpoints whose capability profiles match.

ZFS idmapped-mount behavior is a mandatory probe. Failure selects a separately
specified safe presentation or rejects the request; tests must prove no path
falls back to recursive ownership changes or a broader identity map.

## Filesystem view conformance

The same semantic suite runs against every compatible realizer. It covers
regular files, directories, symlinks, hard links, sparse files, normalized
timestamps, xattrs, ACL policy, executable bits, forbidden special files,
large directories, Unicode byte names, maximum legal names, and malformed
portable trees.

Native tests cover nonrecursive clone behavior, idmaps, immutable mount
attributes, atomic replacement, mount unique-ID verification, nested source
mount exclusion, descriptor lifetime after detach, and the explicitly stronger
socket/FIFO/lock semantics of kernel-coupled live inspection.

FUSE tests cover:

- lookup/forget balance and nonreuse of live node IDs;
- stable readdir cookies and `READDIRPLUS` behavior;
- positive and negative entry-cache lifetimes per immutable revision;
- backing registration, concurrent opens, close races, and hard limits;
- `allow_other + default_permissions`, supplementary groups, ACL masks,
  unmappable IDs, user-namespace ancestry, sandbox-root DAC capabilities, and
  passthrough open denial before backing selection;
- passthrough read, mmap, splice/copy, sparse, compressed-backing, and
  incompressible-file behavior;
- worker OOM, abort, restart, lazy detach, outstanding requests, and open FDs;
- bounded fallback reads with passthrough disabled; and
- rejection of FUSE/overlay backing cycles.

Identity tests include mapped, unmapped, and incompatible UID/GID policies. A
FUSE idmapped-mount optimization is enabled only after both architectures pass
the exact-kernel conformance suite.

## Nix, cache, and Git tests

Sibling sandboxes build concurrently through one authoritative Nix store
service per trust/disclosure domain. An untrusted client must not become a
trusted Nix user, alter store objects directly, select unauthorized
substituters or keys, pin arbitrary host paths, or disclose the existence of a
cross-domain object.

Environment tests realize and pin a closure, atomically advance the mounted
generation, run old and new executions concurrently, restore a snapshot, and
prove host GC cannot remove referenced store paths. Project hooks execute only
inside the sandbox.

Cache tests inject partial writes, digest and size mismatch, concurrent
publication, collision, quota races, process death, cache-service OOM, lease
expiry with live opens/mappings, and GC-generation races. Strict-domain tests
cover filesystem cache identity, reflink/clone/dedup refusal, and ZFS ARC keys;
separate inodes alone do not pass. Cross-trust mutable cache sharing must fail.

Git tests use independent repositories and ordinary smart protocol. They run
status, diff, log, fetch, repack, commit, and receive concurrently with child
inspection, snapshots, cache GC, and deletion. A snapshot view must remain
stable across a child ref transaction or pack rewrite. Immutable pack
acceleration must retain its exact generation until every alternate and open
descriptor releases its kernel pin.
The cheap sanitized Git-fork capability additionally proves sublinear local
setup from one complete immutable pack generation, private subsequent object
writes, and no alternate sharing across object-read audiences. Protocol clone
is measured and reported as the compatible slow path.

## Performance methodology

Phase 0 records reproducible baselines before numeric release budgets are
frozen. Measurements identify hardware class, kernel, filesystem features,
compression, dataset settings, tree shape, hot/cold cache state, security
profile, and concurrency. Results report p50, p95, p99, variance, and resource
cost; a single best-case number is not a budget.

Required measurements are:

- create, local fork, boot-to-ready, stopped resume, and first command latency;
- first command in an already realized project environment;
- native view attach, replace, and detach latency;
- freeze/quiesce/snapshot pause and restore-to-ready latency;
- FUSE metadata operations per second and p99 lookup/readdir latency;
- sequential/random read and mmap throughput, CPU per GiB, context switches,
  and faults relative to native read-only mounts;
- cold and warm Git status and compiler source-tree scans;
- heap, mmap virtual, resident, and page-cache bytes per view, million nodes,
  touched node, open handle, and negative-lookup storm;
- mount-table and reconciliation cost by sandbox depth, fanout, and attachment
  count;
- ZFS space amplification for source edits, builds, Git repack, and snapshot
  retention;
- ZFS ARC growth, double caching, reclaim latency, and payload/control-plane
  behavior under node pressure;
- cache hit ratio, duplicate-write avoidance, admission latency, eviction cost,
  and physical residency; and
- host recovery time with realistic numbers of units, datasets, mounts, leases,
  and stopped sandboxes.

Passthrough measurements explicitly compare enabled and disabled modes and
verify actual memcg/page-cache charging on the AOS kernel. The implementation
must remain bounded and correct without passthrough even when that mode does
not meet the package-view performance profile.

## Gate progression

Initial measurements establish per-hardware budgets in checked-in test
profiles. Subsequent releases may tighten them or add profiles, but may not
replace a regression with an unreviewed larger threshold. Correctness,
isolation, and hard resource limits are release blockers independent of
performance.

Native dynamic attachment is the first vertical-slice performance gate. The
immutable FUSE profile has a separate gate and does not delay validating the
usable nspawn/ZFS/Nix/native-view core; the RFC is fully implemented only when
both profiles pass their declared gates.
