# Security analysis

## Trust model

The design treats as mutually distrustful:

- sandbox payloads, including sandbox root;
- sibling and unrelated projects;
- remote source servers;
- tree, NAR, Git, OCI, and snapshot metadata;
- public API callers beyond their authenticated authority;
- stale coordinators and delayed requests; and
- node services outside their explicit local role.

The host kernel, AOS boot trust, system manager, privileged brokers, and
controller policy database are trusted within the selected shared-kernel
security tier. A future microVM backend narrows the shared-kernel assumption but
does not change the public authority model.

## Privilege decomposition

No network-facing process has mount or system-manager privilege.

`aos-sandbox-hostd` has the authority needed for a closed set of transient-unit
and storage operations. It accepts no arbitrary D-Bus property, command,
dataset name, or unit text.

`aos-mountd` has the authority needed for descriptor-based mount creation,
namespace entry, attachment, detachment, and FUSE passthrough registration. It
accepts no arbitrary host path or mount option string.

`aos-netd` has only the netlink/firewall authority needed for typed sandbox
links, addresses, routes, egress, and published endpoints. It accepts no rule
text or caller-selected host interface identity.

Each broker has a dedicated MAC domain, no upstream credentials, no general
network access, tight syscall filters, bounded IPC, and an auditable operation
vocabulary. Splitting them prevents a view-parser compromise from becoming
mount privilege and prevents a mount bug from becoming arbitrary PID 1
configuration.

The unprivileged node daemon is not the root of broker authority. Every broker
independently verifies and persists its audience-specific controller-signed
authorization plan, assignment tuple, policy commitment, and fail-stop lease
before effects. Compromising the daemon can request only the closed verbs and
bounds in an unexpired plan; it cannot mint a newer fence, change a handle's
role, or renew authority by replay.

## Enablement blockers

The initial backend is disabled until all of these gates pass:

- AOS upgrades systemd 259.1 to at least 259.4, with 259.8 the current stable
  candidate at the RFC date, rebases its patches, and proves `--settings=no` against
  hostile host and image-adjacent `.nspawn` files;
- transient-unit mutation is reachable only through the fixed root host daemon
  and mount namespace mutation only through the smaller mount broker/worker;
- every privileged component runs in a dedicated enforcing MAC or equivalent
  policy proven on a production-like labeled root—the current disabled or
  permissive SELinux posture is not sufficient;
- libseccomp knows every required Linux 6.18 mount/pidfd syscall or the audited
  Linux boundary installs verified numeric filters for each architecture;
- ZFS idmaps, target/source race resistance, stale pidfd and namespace reuse,
  hard mount/FD limits, and lazy-unmount non-revocation pass exact-kernel tests;
- untrusted Nix clients and cache publishers cannot acquire trusted-user,
  store-mutation, GC-root, substituter, key, path-disclosure, or cross-domain
  authority; and
- private networking proves address/route spoofing resistance and no general
  device or host-network capability is delegated by a default profile.

## Path and descriptor safety

Public APIs identify logical resources. A privileged broker maps them through a
catalog populated by trusted reconciliation. Relative paths resolve beneath a
pre-opened root with `openat2`; symlinks, magic links, traversal, and optionally
mount crossings are rejected.

Source and target descriptors are pinned and type checked. After entering the
target mount namespace, the short-lived worker resolves only a predeclared slot
or a path beneath one pre-opened project root. Arbitrary `/etc`, `/proc`,
`/sys`, `/dev`, runtime-socket, and cgroup destinations are never accepted from
a sandbox request.

Mount flags are computed from typed policy. The caller cannot submit an option
string. `nosuid` and `nodev` are mandatory for ordinary views; `noexec` is the
default except for authorized verified package or tool views.

## User namespace boundary

Every nspawn sandbox uses a private user namespace unless an exceptional policy
explicitly selects a weaker tier. Native mounts receive the actual target
idmap. The node verifies that the backing filesystem supports the mapping before
readiness.

Guest root receives no host mount, device, module, BPF, perf, ptrace, keyring,
or cgroup administration authority beyond the resolved policy. Namespace setup
is reinforced by capability bounds, seccomp, devices cgroup, Landlock where
applicable, MAC policy, and network policy following RFC-0001's layered
approach.

## FUSE boundary

Tree parsing, network fetch, and cache policy are unprivileged. FUSE workers are
unprivileged and per failure domain. The mount broker opens `/dev/fuse`, mounts
the filesystem, and performs passthrough registration only for broker-known
immutable content.

The broker must not register an arbitrary FD supplied by the FUSE worker. It
opens or validates backing identity beneath the authorized cache partition,
checks regular-file type, immutable publication state, disclosure domain,
view/connection association, open mode, and expected digest handle.

The immutable publication state includes a kernel/storage-enforced seal:
fs-verity with the expected digest on a supported filesystem, a read-only ZFS
snapshot generation, or an equivalently tested backend. A live inode remains
ineligible while any producer alias could mutate it. Mode bits, ownership, a
read-only descriptor, or a prior hash are not sufficient.

Passthrough is an authorization lifetime decision. Existing descriptors and
memory mappings can outlive later policy change or lazy unmount. Security
revocation stops the consuming cgroup; the API does not claim immediate
per-open revocation.

FUSE stack depth is explicitly bounded. Backing files on FUSE and recursive
service dependencies are rejected. Worker binaries and control files live
outside served namespaces.

## Cache isolation and poisoning

Content identity is necessary but not sufficient for cache admission. The
service verifies source authority, signature/provenance policy, digest, size,
format, tree relationship, and disclosure domain before publication.

Cache hits never bypass authorization. Strict and trust-group domains use
separate backing inodes so they do not share page-cache timing. Public/project
sharing acknowledges residual timing and resource-contention side channels;
it is not advertised as complete microarchitectural isolation.

Writable staging is private. Publication is separately authorized and atomic.
A failed or canceled producer cannot leave partially verified bytes reachable
under a committed identity.

## Tree parser threats

The parser defends against:

- path traversal and alternate separators;
- malformed symlinks and policy-forbidden absolute or escaping link targets;
- duplicate, unsorted, or colliding names;
- integer overflow and oversized allocations;
- deep nesting and exponential matcher trees;
- invalid sparse extents and content sizes;
- hard-link identity confusion;
- oversized xattrs, ACLs, or metadata maps;
- device nodes, sockets, and FIFOs outside explicit policy;
- decompression bombs; and
- algorithm or media-type confusion.

Fuzzing begins at raw bytes and exercises parse, canonicalize, index compile,
mmap validate, FUSE lookup, and delta application.

Ordinary permitted symlinks retain VFS semantics and may resolve outside the
view into the consumer's own namespace. Read-only inspection defaults to
no-follow, while security-sensitive subtree traversal uses fd-relative
`openat2` with a beneath policy. The implementation does not claim that a FUSE
mount alone confines all later consumer path resolution to its subtree.

## Capability and confused-deputy defense

Every capability binds holder, audience, operation, resource selector,
incarnation, policy digest, expiry, revocation generation, and delegation
limits. Node services exchange audience-specific proofs, not forwarded user
bearer credentials.

Sandbox, view, attachment, execution, and snapshot IDs are references, not
authority. The service reauthorizes each operation. Cached decisions include
the complete authority and policy generation in their key.

Parent/child authority attenuates monotonically. A child cannot renew past its
parent, increase delegated resource pools, broaden cache sharing, or delegate
an operation the parent could not delegate.

## nspawn configuration

Nspawn is launched with `--settings=no`; no workload-supplied `.nspawn` file is
loaded. Only an upgraded patched systemd build may enable the backend. The
resolved transient unit and argv are checked against golden policy fixtures.

Machined is not the authority. Enabling it later for inventory must not expose
administrative bind, copy, open-root, or shell operations outside AOS
capabilities.

## Git threats

Host-privileged processes never run Git against a sandbox-controlled working
tree or repository configuration. Git hooks, filters, attributes, alternates,
config includes, and submodule helpers run only inside the owning sandbox.

Cross-sandbox exchange uses an authenticated smart-protocol endpoint over a
repository whose complete ODB is readable by that audience. Different read
audiences receive physically separate sanitized export repositories or packs;
hidden refs are not confidentiality. Pushes enter receive-pack quarantine and
are promoted only after object and compare-and-swap ref validation. Raw `.git`
sharing is off by default. Filesystem inspection does not imply permission to
execute Git over child configuration, update refs, or publish commits.

## Secrets and devices

Secrets are typed projections with short lifetime, explicit consumers, and a
snapshot retention rule. They do not enter ordinary view indexes, backing-file
caches, Git, or portable snapshots. Memory-backed projection is charged to
memory and does not support a false secure-erasure guarantee.

Devices are typed grants with node placement and backend implications. Device
state is external unless a backend-specific checkpoint proves otherwise.
Device nodes in arbitrary tree data are rejected.

## Denial of service

Hard bounds cover sandboxes, ancestry depth, fanout, views, attachments,
mounts, FUSE connections, inodes, indexes, rules, sets, tree nodes, file size,
extents, xattrs, cache pins, disk, memory, tmpfs, PIDs, FDs, request queues,
fetch bytes, decompression, snapshots, and operations.

Foreground work has bounded priority over speculation; it does not have
unbounded priority over other tenants. Rate limits and fair-share scheduling
apply within disclosure domains and projects.

## Audit requirements

The audit log records capability issuance and attenuation, policy decisions,
node assignment, mount and view transitions, cache-domain selection,
publication, snapshot consistency, suspension, hard revocation, cascade
deletion, and privileged broker operations.

It records stable resource IDs and policy digests but redacts secrets, raw
tokens, host paths, and unnecessary content identities. Security-significant
events are not sampled.
