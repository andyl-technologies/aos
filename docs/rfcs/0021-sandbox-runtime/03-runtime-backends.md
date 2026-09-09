# Runtime backends and the nspawn implementation

## Backend-neutral contract

The runtime backend realizes an already authorized and resolved sandbox plan.
It does not evaluate public policy. A backend implementation provides:

```text
probe() -> BackendCapabilities
prepare(plan, storage_handles, attachment_slots) -> PreparedRuntime
start(prepared, incarnation) -> RuntimeObservation
exec(runtime, execution_spec) -> ExecutionHandle
freeze(runtime) -> FreezeObservation
thaw(runtime) -> RuntimeObservation
stop(runtime, deadline) -> StopObservation
inspect(runtime) -> RuntimeObservation
destroy(prepared_or_runtime) -> DestroyObservation
```

Snapshotting storage and coordinating view barriers are sandbox-daemon
operations, not opaque backend calls. A VM backend may additionally advertise a
backend-local memory/device checkpoint capability; that checkpoint is not a
portable sandbox snapshot.

Each capability is explicit. A backend unable to implement a hard requested
feature rejects `prepare`; it never ignores the field. The control service may
reschedule to a capable node or return an unsatisfied-enforcement condition.

The capability vocabulary describes semantics, not implementation names. Its
initial dimensions include private user namespaces, live mount attachment,
private networking, cgroup freeze, durable storage snapshot, cheap fork,
portable restore, backend-local checkpoint, and cross-node migration. A
backend-local checkpoint does not imply portable restore, and a filesystem
snapshot does not imply process checkpointing.

## Initial nspawn backend

The first backend runs `systemd-nspawn` as a transient systemd service. AOS
reuses nspawn for:

- mount, PID, user, UTS, and IPC namespace construction;
- booting an AOS userspace with systemd as container PID 1;
- capability and syscall restriction;
- inheritance of the broker-prepared private network namespace;
- integration with the host service manager and cgroup v2; and
- orderly signal and shutdown behavior.

AOS retains ownership of sandbox identity, registration, dynamic mounts,
storage, capabilities, and desired state. `systemd-machined` is not required.
Its administrative object model is not the sandbox API, and its dynamic bind
operation rejects user-namespaced machines in the systemd series currently
packaged by AOS.

The nspawn command always includes `--settings=no`. Host or image-adjacent
`.nspawn` files must not inject mounts, capabilities, pivot roots, or other
settings outside the resolved sandbox plan. The systemd package must be
upgraded from 259.1 to at least the patched 259 stable series before this
backend is enabled because versions before 259.4 are affected by
[GHSA-9mj4-rrc3-gjcx](https://github.com/systemd/systemd/security/advisories/GHSA-9mj4-rrc3-gjcx).

## Transient unit ownership

`aos-systemd` is extended with typed support for starting and observing
transient units. The root-only `aos-sandbox-hostd` calls that API on behalf of
the unprivileged reconciler and sends exact properties through D-Bus rather
than constructing shell commands. The unit name is a node-local projection of
the sandbox UID and incarnation and is never a public identifier.

The transient service owns:

- one delegated cgroup subtree;
- nspawn supervisor lifetime;
- mandatory `Restart=no`; only the reconciler may create a new incarnation;
- stdout/stderr journal routing for boot diagnostics;
- runtime and mount-helper ordering dependencies;
- device and capability ceilings for nspawn itself; and
- cleanup ordering relative to view workers and storage.

It also has `BindsTo=` and ordering dependencies on the assignment guardian.
If that guardian exits, expires, or cannot be reconstructed after reboot,
systemd stops the nspawn service independently of the node reconciler.

The nspawn backend uses one opaque, flat service name beneath
`aos-sandboxes.slice`; it does not encode the logical ancestor path in a unit
name or nested slice. The reconciler, not PID 1, owns incarnation replacement,
so `Restart=no` prevents systemd from silently creating a new mount namespace
without replaying the manifest. `CollectMode=inactive-or-failed` permits dead
transient units to be collected after observations have been persisted.

The typed transient-unit builder admits a closed property set including:

```text
Type=notify
NotifyAccess=main
Delegate=yes
DelegateSubgroup=supervisor
Slice=aos-sandboxes.slice
Restart=no
CollectMode=inactive-or-failed
KillMode=mixed
OOMPolicy=kill
BindsTo=aos-lease-guard-<incarnation>.service
After=aos-lease-guard-<incarnation>.service
TasksMax=<resolved bound>
MemoryHigh=<resolved bound>
MemoryMax=<resolved bound>
CPUQuota/CPUWeight=<resolved policy>
IOWeight/IO limits=<resolved policy>
DevicePolicy=closed plus a typed allowlist
CapabilityBoundingSet=<closed nspawn-supervisor set>
RestrictAddressFamilies=<closed union required by supervisor and payload profile>
SystemCallFilter=<closed inherited supervisor/payload ceiling>
ProtectSystem=strict
ExtraFileDescriptors=<one detached root mount named aos-sandbox-root-mount-v1>
PrivateTmp=yes
TemporaryFileSystem=/run/systemd/nspawn:rw,mode=0700,nosuid,nodev,noexec,size=16M
SELinuxContext=<dedicated nspawn-supervisor domain>
NetworkNamespacePath=<broker-pinned prepared namespace>
TimeoutStartSec/TimeoutStopSec=<bounded policy>
```

The nspawn supervisor is itself an explicit privileged attack surface. It runs
in a dedicated enforcing MAC domain with a golden host-filesystem allowlist:
read-only AOS store paths and kernel API files required by the backend, the
single broker-resolved private root, its prepared network namespace, its unit
cgroup, journal/control sockets, and no other tenant roots. The exact
capability, syscall, address-family, and device set is generated from the
phase-0 trace and then closed. Unit-level seccomp and address-family filters are
inherited, so they are ceilings over the union needed by the supervisor and
selected payload; the pre-PID1 filter below narrows the payload further.
Directory-backed sandboxes receive no loop, block, FUSE, module, BPF, perf, or
ptrace access. The production MAC gate tests the nspawn supervisor separately
from payload and brokers, including a fixed SELinux process transition for
guest PID 1 rather than leaving it in the supervisor domain.

The fixed `ExecStart` pins nspawn from its absolute AOS store path and addresses
that executable through the retained descriptor. The argument profile includes
`--boot`, `--quiet`,
`--keep-unit`, `--register=no`, `--settings=no`, an opaque `--machine` label,
`--aos-root-mount-fd=aos-sandbox-root-mount-v1` for the private root, an explicit
`--private-users=<uid-base>:<count>` allocation,
`--private-users-ownership=map`, `--notify-ready=yes`, and a fixed
`--selinux-context=<payload-domain>`. The service manager joins the
broker-pinned prepared namespace before it executes nspawn; nspawn inherits the
namespace and receives no network namespace path. This avoids nspawn's
unpatched [259-series ordering
failure](https://github.com/systemd/systemd/issues/36363) when its own
`--network-namespace-path` is combined with private users, so AOS does not need
to carry an additional network-ordering patch. It never asks nspawn to create a
veth or raise an external link. It never uses `-U`,
`--private-users=pick`, `auto` ownership, or `--volatile` for a durable root.
Neither the property set nor argv is supplied by the public caller.

The privileged workspace publisher prepares a detached recursive root mount.
It travels as one named D-Bus file descriptor, not a root pathname for the
restricted supervisor to reopen. Nspawn's AOS descriptor profile requires the
exact role and arity, rejects host root and non-directory objects, and retains
an inode-based exclusive lock. Its supervisor-local descriptor alias is never
canonicalized for image lookup or pathname locking. Nspawn clones the detached
tree for each boot, applies the fixed idmap to the detached root alone with
`mount_setattr`, and attaches it with `move_mount`, retaining a detached
replacement for subsequent boots. Child idmaps and read-only mount boundaries
remain intact; the profile does not use upstream's unmount-and-remap path for
an already assembled tree. The descriptor and lock are close-on-exec,
and the setup channel is removed from `LISTEN_*` before collecting payload
activation descriptors. The payload close-other-descriptors step also excludes
these setup pins. Renaming or replacing the published root pathname cannot
redirect the mounted root. An attached directory descriptor is not a substitute:
the kernel rejects importing it across mount namespaces. Host remains
capability-free; it cannot create this mount on behalf of a missing publisher.
Readiness still requires post-launch payload-root
identity verification against the broker's original pin.

Private temporary directories and the bounded private nspawn runtime tmpfs
provide setup scratch space without granting writable access to other host
paths. The root mount is derived from the transferred object rather than a
`ReadWritePaths` exception that reopens a host pathname. These mechanics do not
replace the enforcing MAC allowlist, identity-allocation checks, or production
qualification gates.

Before nspawn starts, `aos-netd` creates and pins a network namespace owned by
the host user namespace, leaves its veth down, installs default-drop,
anti-spoof, route, egress, and endpoint state under the signed assignment plan,
including the fixed tc-BPF `CLOCK_BOOTTIME` lease gate, and verifies the
resulting kernel objects. Nspawn
inherits that prepared namespace through the fixed transient-unit property.
Netd raises the link only after runtime and policy readiness; every recovery
path leaves an unrenewed or unknown link default-drop and down. This removes
any boot interval in which guest code can transmit before policy exists.

The payload profile computes the exact complement of the reviewed AOS boot
allowlist across the kernel's supported capability range and passes that
complement through `--drop-capability`; `--capability` adds only allowlisted
entries absent from nspawn's defaults. Nspawn applies additions before drops,
so `--drop-capability=all` is not used as a reset mechanism. The node
post-validates the payload's observed `CapBnd`, permitted, effective,
inheritable, and ambient sets before readiness. The baseline candidate is
`CAP_CHOWN`,
`CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_KILL`, `CAP_SETGID`,
`CAP_SETUID`, `CAP_SETPCAP`, `CAP_NET_BIND_SERVICE`, and `CAP_SETFCAP` inside
the private user namespace; phase 0 may remove entries but may not add a
capability without updating the threat analysis and fixtures. `CAP_SYS_ADMIN`,
`CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_SYS_BOOT`,
`CAP_NET_ADMIN`, `CAP_BPF`, and `CAP_PERFMON` are absent.

The payload also uses `--no-new-privileges=yes`, a closed nspawn
`--system-call-filter`, and an AOS argument-aware seccomp layer inherited by
every untrusted execution. V1 installs the latter through an audited AOS nspawn
patch in the payload child after namespace/setup syscalls and immediately
before `execve` of guest PID 1. The profile is compiled into the exact AOS
nspawn build and selected only by a closed broker-generated profile ID; no
guest file or arbitrary BPF program is parsed. Name filtering denies mount,
unmount, new mount API, `pivot_root`, `setns`, `unshare`, BPF, module, perf, and
ptrace operations. The argument filter permits ordinary `clone` only when
every new user/mount/cgroup and other forbidden namespace flag is clear. It
returns `ENOSYS` for `clone3` so libc falls back to inspectable `clone`;
unrestricted `clone3` is never allowed. Tests begin with the first guest PID
and include independently systemd-started services, not only agent executions.
This is the nspawn analogue of an inherited `RestrictNamespaces` boundary,
not a name-only filter claim.

The sandbox base system is built to boot without guest mount administration.
If the exact AOS guest cannot do so, that is a failed phase-0 gate rather than
permission to inherit nspawn defaults. Static nspawn-created API mounts count
against admission; `/dev/fuse` and host control sockets are not present in the
payload.

The payload lives in nspawn's payload sub-cgroup, separate from the supervisor.
The node daemon resolves its leader from the expected cgroup, opens a pidfd,
and validates cgroup and unit identity before using the payload's namespaces.
A PID read from a state file or D-Bus property without pidfd pinning is
insufficient.

The nspawn supervisor's `MainPID` is not assumed to be guest PID 1. The
implementation obtains the unit control group through typed systemd
observations, recursively enumerates only its exact delegated `payload`
subtree, and pidfd-pins the process whose nested PID is 1. It then rechecks the
unit invocation, cgroup ID and membership, parent/supervisor relationship,
namespace identities, nested PID, and incarnation. Where available,
`GetUnitByPIDFD` provides an additional manager-side cross-check. No attachment
depends solely on nspawn's notification fields or the later guest-agent
connection.

On Linux 6.18, the implementation uses pidfd namespace ioctls to acquire mount
and user namespace descriptors and revalidates liveness. A payload reboot or
namespace replacement changes the runtime observation and forces attachment
replay under a new namespace generation.

## Root filesystem

The nspawn root is assembled from:

- an immutable AOS system or sandbox-base view;
- one private persistent or ephemeral writable dataset;
- private `/tmp` and runtime state;
- declared package-environment and project attachments; and
- broker-owned empty destination slots.

The root must contain only AOS-built software. It does not download an upstream
container base or import nixpkgs. A project may choose a minimal command
environment or booted systemd environment, but both derive from AOS closures.

Native sandbox datasets store portable, unshifted UID/GID ownership. The
sandbox root itself is idmapped to the allocated user namespace; sources
record their on-disk identity map. A native view is admitted only when the
source map can be proven to compose with the consumer map. A tree already
shifted for another sandbox is rejected or normalized through an immutable
copy/FUSE presentation; it is never recursively chowned.

Where ZFS is available, a sandbox writable root is a dataset or clone with an
explicit quota, reservation policy, encryption-root relationship, and snapshot
lineage. Storage drivers may implement an equivalent contract with reflink or
another native CoW facility, but a node advertises the precise snapshot,
rollback, quota, and idmap capabilities it actually supports.

## ZFS storage contract

A node creates roots only beneath broker-owned pool/dataset catalogs. Dataset
names never come from public input. The default decomposition gives each
sandbox separate private root and workspace datasets beneath a project
capacity dataset; store, cache, secrets, runtime sockets, and attachment-anchor
mounts are excluded. Phase 0 may refine that decomposition from measured write
amplification, but not the ownership boundaries.

Each private dataset has `refquota` for its directly referenced writable state.
The project ancestor has a `quota` covering descendant datasets and retained
snapshots, plus `filesystem_limit` and `snapshot_limit`. Controller admission
reserves worst-case private growth and snapshot retention before effects, while
the pool keeps an operator emergency reserve that tenants cannot consume.
Space properties may lag and are observations, not permission to exceed the
reserved ledger. The backend conformance suite pins these meanings to the
[OpenZFS 2.4 property contract](https://openzfs.github.io/openzfs-docs/man/v2.4/7/zfsprops.7.html).

Physical shared-origin blocks are accounted once at pool/project level and as
logical dependency bytes for every consumer. `refquota` alone is not accepted
as complete admission accounting for clone/snapshot relationships. The node
reports referenced, unique, snapshot, descendant, and pool-free dimensions
separately.

A clone inherits the origin's encryption root, key relationship, block
ownership, and retention dependency. Cheap clone is therefore allowed only
within the same disclosure, encryption, storage-accounting, and retention
domain. The destination reserves its worst-case logical growth and retained
origin obligation before the hold/clone transaction commits. A cross-account
fork materializes a portable tree or uses a proven non-raw send/receive path
into a new accounting/encryption root and re-verifies the result. A future
shared-origin escrow would need explicit charging and deletion rights; raw send
or a matching disclosure domain alone does not establish separation.

Every origin snapshot receives a GUID-bound hold before a dependent clone is
published. Normal lifecycle never invokes recursive destroy and never promotes
a clone: promotion reverses dependency ownership and is permitted only as a
separately fenced offline lineage-rewrite operation. Deletion releases explicit
holds and destroys exact GUID/name pairs in dependency order. `EBUSY`, an
unknown hold, or an unexpected clone leaves `ResidualState` with data intact.

## User namespaces and identity

The default nspawn backend allocates a private user namespace. The sandbox's
identity map is immutable for one incarnation. Native source mounts are cloned
and idmapped with the target user namespace before attachment; backing trees
are not recursively chowned.

The node records:

- the portable guest identity policy;
- the allocated node UID/GID range;
- the pinned user namespace identity;
- whether every attached filesystem accepted the requested mapping; and
- any backend-specific mapping diagnostics.

Identity allocation is fenced to the sandbox incarnation and reclaimed only
after the runtime, namespace descriptors, mounts, and backing datasets are
released. Reuse while an old namespace remains pinned is prohibited.

## Networking

The default sandbox receives a private network namespace and loopback. Network
profiles are closed typed policies rather than arbitrary nspawn arguments:

- isolated: loopback only;
- project: project-scoped service endpoints and optional sibling routes;
- outbound: mediated egress under the project network policy;
- published: explicitly authorized ingress endpoints; and
- host: exceptional, separately authorized, and not considered a strong
  network boundary.

The sandbox tree does not imply a network topology. Parent/child connectivity
is explicitly granted. Network identity and policy survive snapshot as desired
state; live connection state does not.

## Exec and interactive access

Lifecycle control and execution data are separate. Every guest contains a
small `aos-sandbox-agent` for incarnation handshake, readiness, quiesce, and
handoff of an already authorized execution to a forced local command. It
accepts a closed node-internal protocol only through a host-provided Unix
channel and never receives host mount or systemd authority. It is not a public
streaming protocol.

The v1 execution data plane is OpenSSH inside the sandbox, using short-lived
holder-bound certificates and forced-command/subsystem policy. It supplies a
standard multi-machine transport for PTY resize, signals, exit status, flow
control, disconnect policy, SFTP, and Git without defining another terminal
framing protocol. Direct unrestricted SSH port forwarding and agent forwarding
remain off unless separately granted.

The client proves possession of an ephemeral private key and submits only its
public key during execution admission. The returned certificate binds that key
to execution UID, sandbox incarnation, principal, expiry, and closed OpenSSH
critical options; the endpoint never returns private key material. `sshd`
accepts only the AOS execution CA, disables password and host-based login, and
hands the certificate principal to a forced-command gate that rechecks the
live execution record. Shell, subsystem, and forwarding rights are explicit
certificate/profile features. V1 has no PTY/stream reattachment; detached
non-PTY execution and bounded output capture are separate execution features.
A certificate cannot select an arbitrary account or escape to a different
execution.

Phase 0 must prove startup, namespace, certificate, forced-command, PTY,
signal, SFTP, forwarding denial, audit, and closure-size behavior for the exact
AOS OpenSSH build and configuration. If that probe fails, the v1 backend stays
disabled until a follow-up RFC defines and versions an alternative public data
plane; an unspecified agent-stream fallback is not permitted.

Production runtime management does not invoke `systemctl`, `systemd-run`,
`machinectl`, `nsenter`, or a generic nspawn CLI wrapper as subprocess
porcelain. Machined, mountfsd, and nsresourced remain disabled for the v1
backend. Persistent unit files exist only for daemons, sockets, slices, and
network infrastructure; sandbox instances are reconstructed transiently from
desired state.

## Freeze and OOM behavior

The payload cgroup has `memory.oom.group=1` when the selected workload policy
requires sandbox-atomic OOM. View workers, the node daemon, mount broker, and
storage helpers are outside that cgroup. The assignment guardian is also
outside and receives a small measured protection sufficient to execute the
fail-stop path. The node service never gives the sandbox payload a protected
negative OOM score.

Freeze applies to the exact delegated payload cgroup after execution admission
is closed. `FreezeUnit` would also freeze the nspawn supervisor, so the v1 host
daemon instead opens the verified payload cgroup directory, writes its
`cgroup.freeze`, and observes `cgroup.events` through pinned descriptors. It is
not successful until the payload reports frozen and the view/storage barrier
has reached the requested consistency point. Thaw writes and observes the same
payload cgroup. The fixed host protocol exposes semantic freeze/thaw verbs, not
a cgroup path.

## Alternative backends

Future backends may include bubblewrap-style process sandboxes, microVMs, or
remote execution pools. They implement the same public semantics only for
advertised capabilities. A microVM view may use virtiofs rather than a mount
namespace, and a process sandbox may not support durable booted services. These
differences appear as capabilities and unsatisfied requirements, not as hidden
behavior changes.
