# Implementation sequence and code ownership

## Delivery strategy

Implementation proceeds as vertical slices with falsifiable exit criteria.
The public model includes the full design, but optional backends do not block
proof of the smaller native path. No phase may temporarily grant sandboxes raw
host systemd, mount, ZFS, Nix-trusted-user, or FUSE authority.

## Phase 0: blockers and executable probes

Before runtime code:

1. upgrade AOS systemd from 259.1 to at least 259.4, with 259.8 the current
   stable candidate at the RFC date, and rebase its AOS patches;
2. add and validate required kernel configuration, including FUSE passthrough;
3. prove the exact Linux 6.18 pidfd namespace, `openat2`, `open_tree_attr`,
   `mount_setattr`, `move_mount`, `statmount`, and `listmount` path on x86_64
   and aarch64;
4. resolve libseccomp support for the required syscalls, using audited numeric
   filters only if the packaged library cannot name them;
5. prove nspawn user namespaces, fixed transient-unit properties, payload
   leader discovery, internal reboot, and `--settings=no` in an AOS VM;
6. prove ZFS 2.4 snapshot/hold/clone/quota/idmapped-mount behavior on the exact
   AOS kernel;
7. prove an immutable backing backend using fs-verity or read-only ZFS snapshot
   generations, including passthrough and crash recovery;
8. prove strict physical Nix-store domains and either the untrusted-client
   contract or a required narrowing proxy;
9. select and prove an enforcing host MAC boundary for every daemon/helper;
10. benchmark native dynamic mounts and the candidate FUSE implementation; and
11. prove the exact OpenSSH execution data plane, forced-command policy, and
    forwarding denials; failure keeps the backend disabled pending a follow-up
    RFC for a separately versioned alternative.

The output is a checked-in feature-probe matrix and baseline report. An absent
hard kernel or confinement feature changes placement capability or blocks the
backend; it is not papered over in later phases.

## Phase 1: portable model and protocols

Implement resource IDs, generations, desired/observed state machines,
capability attenuation, reservations, operations, snapshot and tree schemas,
and public `aos.sandbox.v1` messages. Implement the bounded local broker
protocol and descriptor-role validation without performing privileged effects.

Exit criteria: model/property tests, protobuf compatibility fixtures, canonical
format vectors, authority decoder tests, local protocol fuzzing, and simulated
multi-node assignment fencing pass without Linux-specific dependencies in the
portable core.

## Phase 2: journal, controller, and host boundary

Implement the unprivileged single-node reconciler, durable desired-state
journal, typed `aos-systemd` transport extensions, root-owned host daemon, and
audited Linux UAPI boundary. Run fixed transient test services, reconcile them
after process and PID 1 restarts, and inventory all residual resources.

Exit criteria: crash injection at every record/effect boundary converges; no
public request reaches a privileged parser; no arbitrary systemd property,
host path, namespace ID, mount option, or subprocess command crosses the host
protocol.

## Phase 3: bootable sandbox and execution

Build an AOS sandbox guest root, private ZFS workspace/root, identity
allocation, cgroup policy, private networking baseline, transient nspawn unit,
and the selected guest execution endpoint. Keep machined disabled.

Exit criteria: an unprivileged client creates, starts, executes in, stops, and
deletes a user-namespaced sandbox in the AOS VM; resource/OOM and device policy
are verified; guest reboot produces a new namespace generation; no host tool or
nixpkgs dependency enters the build.

## Phase 4: native dynamic views and hierarchy

Implement source handles, broker-owned destination slots, detached idmapped
mount construction, short-lived namespace workers, atomic attachment
replacement, post-attach verification, leases, and explicit read-only
descendant inspection. Add a minimal crash-consistent owned-workspace snapshot
and manifest for stable inspection. Add child creation with attenuated
authority and aggregate admission policy.

Exit criteria: live attachment, replacement, detach, stable snapshot
inspection, tree authorization, race corpus, reboot replay, and hard revocation
pass. This is the minimum usable v1 vertical slice.

## Phase 5: project environments, Git, and caches

Implement immutable project-environment generations, GC-root pinning, read-only
store presentation, the constrained Nix build capability, cache disclosure
domains, transactional artifact publication, and normal independent Git
repositories with optional immutable-pack acceleration.

Exit criteria: a running sandbox advances its package environment atomically;
old executions remain well-defined; concurrent sibling builds cannot corrupt
or escalate the store; Git inspection and synchronization use standard
protocols; cross-domain cache existence and content remain undisclosed.

## Phase 6: durable lifecycle

Extend the minimal snapshot slice with dependency-closure quiesce/freeze
barriers, coordinated multi-dataset snapshots, fork, restore,
memory-resident suspend/resume, hibernate-as-snapshot-plus-stop, topological
deletion, deferred reap, and full boot reconciliation.

Exit criteria: every lifecycle crash point, open-FD case, dependency conflict,
node reboot, and interrupted cascade reaches its specified state without
recursive ZFS destruction or stale-handle reuse.

## Phase 7: network and policy profiles

Implement project service discovery, mediated egress, explicitly published
ingress, per-sandbox identity, quota, and spoofing defenses. General device
assignment and host networking remain outside default profiles.

Exit criteria: positive and negative connectivity tests, policy replacement,
namespace exhaustion, stale identity, and tree/sibling isolation pass under the
production network manager and firewall.

## Phase 8: portable trees and immutable FUSE

Implement canonical tree compilers, node-local mmap indexes, per-view FUSE
workers, backing-file registration, bounded fallback reads, cache admission,
identity presentation, immutable remote fetch, and worker recovery.

Exit criteria: parser fuzzing, semantic conformance, passthrough, memory/OOM,
page-cache sharing, disclosure-domain isolation, worker crash, and performance
profiles pass on all supported architectures. Mutable distributed POSIX is not
part of this phase.

## Phase 9: multi-node and rollout

Add placement, assignment epochs, authenticated node transport, immutable
snapshot transfer, resumable watch, draining, and restore to a compatible
destination. Roll out CLI and automation skills only against public API
features that have passed their node gates.

Exit criteria: stale coordinators and partitioned nodes cannot both mutate one
sandbox generation; interrupted transfer resumes or restarts safely; missing
external dependencies block restore; rolling upgrades preserve all supported
format and protocol versions.

## Rust ownership

The proposed boundaries are:

| Component | Responsibility | Explicitly excluded |
| --- | --- | --- |
| `aos-proto` | Public `aos.sandbox.v1` descriptors and Connect API | Linux and backend details |
| `aos-sandbox-core` | Portable model, policy math, state machines, manifests, journal contracts, backend traits | D-Bus, syscalls, ZFS commands |
| `aos-sandbox-linux` | Audited pidfd, namespace, path-resolution, and new-mount-API wrappers | Public parsing and policy |
| `aos-sandbox` | Client library, unprivileged controller/node reconciler, operations, placement | Direct privileged effects |
| `aos-sandbox-host` | Root-only fixed host protocol and typed systemd/storage/freeze verbs | Public/network listeners and arbitrary paths/options |
| `aos-sandbox-mount` | Root-only descriptor mount broker and one-shot namespace helper | Source parsing, network, and arbitrary paths/options |
| `aos-sandbox-net` | Root-only typed veth, netlink, firewall, endpoint, and network-lease broker | Public policy parsing and arbitrary rule text |
| `aos-sandbox-view` | Portable-tree compiler, isolated publisher, FUSE worker, view/cache client | Sandbox lifecycle authority |
| `aos-sandbox-agent` | In-guest readiness, exec/PTY, signal, and quiesce endpoint | Host control and mount authority |
| `aos-systemd` | Typed D-Bus transport for transient units and unit/cgroup observations | Sandbox policy and arbitrary property maps |
| `aos` | User-facing CLI backed by the client library | Privileged runtime closure |

Internal backend traits are a Rust implementation detail, not a stable ABI.
A backend that must evolve independently becomes a separate process with a
versioned, capability-negotiated protocol. Privileged code never loads dynamic
plugins with `dlopen`.

The Linux crate is the sole place for any required `unsafe` and vendored UAPI.
Each unsafe operation documents descriptor type, lifetime, namespace,
single-threading, and generation invariants. Safe crates pass owned descriptor
types rather than integer FDs.

## Nix packages and modules

`modules/services/sandbox-runtime.nix` owns `aos.sandbox.*` options, persistent
daemon/socket/slice/network configuration, tmpfiles, policy assertions, and
checks. Deliberately imported implementation helpers live under
`modules/services/_sandbox-runtime/`. Per-sandbox transient units are never
rendered into `/etc`.

A focused sandbox-root builder composes the existing AOS module and closure
assembly machinery into a bootable root and seed snapshot. It may factor common
code from package-root image construction, but it does not reinterpret
RFC-0001 package exposure sandboxes as durable development runtimes.

Host daemon, view worker, guest agent, client, and CLI outputs are packaged so
the ordinary CLI closure does not retain root-only helpers. Every dependency is
an AOS source-built package. A FUSE userspace library selected in phase 0 is
packaged hermetically rather than taken from the host.

## Reuse and build ledger

Reuse:

- nspawn, systemd manager D-Bus, cgroup v2, networkd/resolved;
- Linux namespaces, descriptor mount API, idmapped mounts, and FUSE;
- ZFS snapshot, hold, clone, quota, and compatible send/receive;
- Git protocol v2, upload-pack/receive-pack, bundles, and partial clone;
- Nix daemon/store semantics and signed substituters;
- AOS Hub's immutable distribution model; and
- RFC-0011 generation activation and RFC-0012 lease/root-reason principles.

Build:

- sandbox resource model, capabilities, desired-state journal, and reconciler;
- fixed privileged host boundary and Linux wrappers;
- filesystem-view metadata plane and immutable FUSE realization;
- environment-generation and cache-domain integration;
- snapshot manifests, assignment fencing, public API, CLI, and skills; and
- exact-kernel VM, security, compatibility, and performance gates.

Do not build in v1:

- a Git object protocol or shared writable Git directory;
- a replacement Nix store/database;
- mutable distributed POSIX storage;
- process-memory checkpoint/restore;
- a stable in-process plugin ABI; or
- a second container manager around machined.
