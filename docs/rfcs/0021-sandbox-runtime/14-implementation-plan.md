# Implementation sequence and code ownership

## Delivery strategy

Implementation proceeds as vertical slices with falsifiable exit criteria.
The first implementation phase is single-node: the first connected milestone
is Phase 3's public Create/boot/execute/Stop/Delete lifecycle on one host.
Phase 4 and then Phases 5-8 add separately gated local profiles. Multi-node
implementation is reserved for a later phase; Phase 9 is not a dependency of
local CLI delivery, local fencing, or single-node completion.

The public model documents the full design, but optional profiles and future
coordinator code do not block proof of the smaller native path. Do not expand
unused distributed implementations while the local lifecycle is incomplete.
The [boundary amendment](18-implementation-boundaries-and-single-node-rollout.md)
owns the crate/interface and removal plan. No phase may temporarily grant
sandboxes raw host systemd, mount, ZFS, Nix-trusted-user, or FUSE authority.

## Phase 0: blockers and executable probes

Before enabling each affected runtime/profile, prove its prerequisites below.
This list is a probe catalog, not a requirement to implement FUSE, remote fetch
or future profiles before the first local lifecycle. Optional-profile probes
gate those profiles only; required local safety probes remain mandatory:

1. upgrade AOS systemd from 259.1 to at least 259.4, select 259.8 as the
   maintained 259-series patch level at the RFC date, and rebase its AOS
   patches;
2. add and validate required kernel configuration, including FUSE passthrough
   and `CONFIG_FS_VERITY`, and prove a default publication profile when ZFS is
   disabled;
3. prove the exact Linux 6.18 pidfd namespace, `openat2`, `open_tree_attr`,
   `mount_setattr`, `move_mount`, `statmount`, and `listmount` path on x86_64
   and aarch64;
4. resolve libseccomp support for the required syscalls and implement the
   audited nspawn pre-PID1 argument-filter patch, using audited numeric filters
   only if the packaged library cannot name them;
5. prove nspawn user namespaces, service-manager entry into the broker-pinned
   prepared network namespace before nspawn exec, fixed transient-unit and
   supervisor-MAC profiles, payload leader discovery, internal reboot, and
   `--settings=no` in an AOS VM;
6. prove the fixed tc-BPF host-veth lease gate uses `CLOCK_BOOTTIME` and drops
   across daemon death and host suspend/resume before any payload packet;
7. prove ZFS 2.4 snapshot/hold/clone/quota/idmapped-mount behavior on the exact
   AOS kernel;
8. prove an immutable backing backend using fs-verity or read-only ZFS snapshot
   generations, including passthrough and crash recovery;
9. prove strict physical Nix-store domains and either the untrusted-client
   contract or a required narrowing proxy;
10. select and prove an enforcing host MAC boundary for every daemon/helper,
   the nspawn supervisor, and assignment guardian;
11. benchmark native dynamic mounts and the candidate FUSE implementation; and
12. prove the exact OpenSSH execution data plane, forced-command policy, and
    forwarding denials; failure keeps the backend disabled pending a follow-up
    RFC for a separately versioned alternative.

The output is a checked-in feature-probe matrix and baseline report. An absent
hard kernel or confinement feature changes placement capability or blocks the
backend; it is not papered over in later phases.

## Phase 1: portable model and protocols

Implement the portable IDs, generations, desired/observed transitions,
capabilities, reservations, operation/spec/trust/signature contracts and public
`aos.sandbox.v1` messages consumed by the first local lifecycle. Add further
tree/view/snapshot contracts with their local slices, rather than making full
future source coverage a prerequisite. Implement local ownership-lease
generations, bounded broker protocols and descriptor-role validation without
performing privileged effects. Coordinator-only models and generated messages
stay outside the default local closure.

Exit criteria: model/property tests, protobuf compatibility fixtures, canonical
format vectors, authority decoder tests, local protocol fuzzing, and stale
local epoch/generation and lease tests pass without Linux-specific dependencies
in the portable core. Cross-node simulation belongs to the later phase.

## Phase 2: journal, controller, and host boundary

Implement the unprivileged single-node reconciler, durable desired-state
journal, typed `aos-systemd` transport extensions, separate root-owned
host/storage/mount/network brokers, the assignment guardian, and the audited
Linux UAPI boundary. Run fixed transient test services, reconcile them after
process and PID 1 restarts, and inventory all residual resources.

Exit criteria: crash injection at every record/effect boundary converges; no
public request reaches a privileged parser; no arbitrary systemd property,
host path, namespace ID, mount option, dataset name/option, or caller-supplied
subprocess command crosses a broker protocol.

## Phase 3: bootable sandbox and execution

Build an AOS sandbox guest root, private ZFS workspace/root, identity
allocation, cgroup policy, private networking baseline, transient nspawn unit,
prepared default-drop network namespace, and the selected guest execution
endpoint. Keep machined disabled.

Deliver the public client/CLI against this normal installed path, including
operation observation and deterministic errors for unsupported profiles. No
coordinator process or remote control exchange participates in local creation.

Include the minimal protected Source/Cache/Publisher/Policy and current
compiler/deployment producers required by section 17's Create admission.
Later user-facing profiles do not defer these initial authority prerequisites.

Exit criteria: an unprivileged client creates, starts, executes in, stops, and
deletes a user-namespaced sandbox in the AOS VM; resource/OOM and device policy
are verified; guest reboot produces a new namespace generation; no host tool or
nixpkgs dependency enters the build.

## Phase 4: native dynamic views and hierarchy

Implement source handles, broker-owned destination slots, detached idmapped
mount construction, short-lived namespace workers, atomic attachment
replacement, post-attach verification, leases, and explicit read-only
descendant inspection, separating immutable inspection from explicitly
kernel-coupled live reads. Add a minimal crash-consistent owned-workspace
snapshot and manifest for stable inspection. Add child creation with attenuated
authority and aggregate admission policy.

Exit criteria: live attachment, replacement, detach, stable snapshot
inspection, tree authorization, race corpus, reboot replay, and hard revocation
pass. This extends the first usable local lifecycle with the native attachment
and hierarchy profile; optional FUSE is not required for this slice.

## Phase 5: project environments, Git, and caches

Implement immutable project-environment generations, GC-root pinning, read-only
store presentation, the constrained Nix build capability, cache disclosure
domains, transactional artifact publication, and normal independent Git
repositories. Implement immutable-pack acceleration for every node advertising
the cheap sanitized Git-fork capability.

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

## Phase 9: multi-node (reserved for later implementation)

Only after the connected local lifecycle and required single-node profiles
are established, implement the separately selected coordinator package. Add
cross-node placement using the existing local ownership epochs, authenticated
node transport, immutable snapshot transfer, resumable watch, draining, and
restore to a compatible destination. This phase is not part of the first
implementation commitment.
Its crates, generated protocols, services and configuration are behind an
off-by-default `multi-node` feature. Public CLI and automation skills already
ship against qualified local features; later remote features require their own
advertisement and gates.

Exit criteria: stale coordinators and partitioned nodes cannot both mutate one
sandbox generation; interrupted transfer resumes or restarts safely; missing
external dependencies block restore; rolling upgrades preserve all supported
format and protocol versions.

## Rust ownership

The canonical target map and internal interface contracts are in
[section 18](18-implementation-boundaries-and-single-node-rollout.md). It replaces
the earlier mixed Controller/client/placement ownership and production-inert
adapter descriptions. New crate names are planned extractions, not assertions
that those packages already exist.

Shared models/codecs and generic journal/Linux mechanics sit below protected
domain owners. Session-security owns sealed authentication and custody, not
Controller orchestration or concrete daemon dispatch. Application assembly
depends on both domain owners and narrow security interfaces. The local
Controller and shared foundations never depend on coordinator implementation.
Local lease/inventory ownership currently located under `multi_node` must move
below that boundary before the optional coordinator is isolated.

Internal backend traits are a Rust implementation detail, not a stable ABI.
A backend that must evolve independently becomes a separate process with a
versioned, capability-negotiated protocol. Privileged code never loads dynamic
plugins with `dlopen`.

Reusable Linux syscall mechanics and vendored UAPI belong in
`aos-sandbox-linux`. The RFC-0021 source currently has the following complete
`unsafe` ownership table. The Host, Network, and Mount service-entry rows are
existing activated transitional boundaries used by `run()` and the existing
Nix services; this source tranche adds no new activation and does not constitute
production qualification. The fixed FUSE worker-entry row is a separate,
disabled source-only ownership boundary, not an installed worker qualification:

| Owner | Permitted boundary | Status |
| --- | --- | --- |
| `aos-sandbox-linux` | Reusable direct syscalls, vendored UAPI, inherited-FD claiming, fixed spawning, pidfds, namespaces, and descriptor validation | Canonical reusable Linux boundary |
| `aos-filesystem-fuse` | `abi.rs`, `callbacks.rs`, `control.rs`, and the scoped call in `lib.rs` needed for the libfuse C ABI and synchronous callback trampolines | Narrow FUSE-specific exception; not a general syscall home |
| `aos-filesystem-fuse` | The single `FixedFuseWorkerStartupV1::capture()` call in `bin/aos-filesystem-fuse-worker.rs`, before signal handlers, threads, or existing owners of the exact inherited FDs 3..7 | Transitional fixed-entry ownership claim only; table capture, syscall mechanics and descriptor validation remain Linux-owned; activation and connected-worker qualification remain closed |
| `aos-sandbox-host` | `activation.rs` and `main.rs` initial ownership claim for the inherited systemd listener | Existing activated transitional boundary; target migration is a safe Linux-owned startup wrapper |
| `aos-sandbox-network` | `activation.rs` and `main.rs` initial ownership claim for the inherited systemd listener | Existing activated transitional boundary; target migration is a safe Linux-owned startup wrapper |
| `aos-sandbox-mount` | `helper.rs`, `keeper.rs`, and the mount helper/daemon entrypoints that claim fixed inherited descriptor tables | Existing activated transitional boundaries; target migration is safe Linux-owned startup wrappers |

No other RFC-0021 crate is authorized to add an unsafe boundary. Every unsafe
operation must have a specific need that safe Rust cannot reasonably meet and
must document descriptor type, lifetime, namespace, single-threading, and
generation invariants in an adjacent `SAFETY` argument. After initial process
ownership is established, crates pass owned descriptor types rather than
integer FDs.

The fixed worker entry forwards the Linux API's exclusive, single-threaded
original-table contract; it may not adopt caller-selected integers or wrap the
ownership claim in an unsound safe factory. The Linux boundary rejects extra
or missing descriptors, owns the original five-role transfer, and returns
owned types. This row authorizes no general syscall helper or additional
unsafe boundary in the FUSE crate.

## Nix packages and modules

Feature modules under `modules/sandbox/` own `aos.sandbox.*` options, persistent
daemon/socket/slice/network configuration, tmpfiles, policy assertions, and
checks. `modules/default.nix` discovers these modules automatically. Each
feature keeps its options and configuration together; shared controller
identity lives in `modules/sandbox/controller.nix`. Underscore-prefixed helpers
in the same directory are imported explicitly, not auto-discovered.
Per-sandbox transient units are never rendered into `/etc`.

A focused sandbox-root builder composes the existing AOS module and closure
assembly machinery into a bootable root and seed snapshot. It may factor common
code from package-root image construction, but it does not reinterpret
RFC-0001 package exposure sandboxes as durable development runtimes.

Host/storage/mount/network daemons, guardian, view worker, guest agent, client,
and CLI outputs are packaged so the ordinary CLI closure does not retain
root-only helpers. Every dependency is an AOS source-built package. A FUSE
userspace library selected in phase 0 is packaged hermetically rather than
taken from the host.

This paragraph describes the target package split. Source-only protocol,
runtime, guest-agent, migration, and protected-journal modules are not thereby
installed, enabled, advertised, or added to a production closure. Packaging
and activation remain subject to their phase exit criteria and qualification
gates.

The default local package and system-module selection exclude coordinator
crates, coordinator-only protobuf generation, remote services and their
credentials. The later `multi-node` feature uses optional dependencies and
explicit package/role selections; no local default enables it transitively.
Dependency/closure checks cover the actual local selections, not merely
source-level conditional compilation.

The first packaged candidate is libfuse 3.18.2. Its source-built AOS package
contains the shared library, headers, and package metadata but no mount helper,
setuid program, utility, init script, udev rule, or policy file. Packaging and
ABI-metadata checks do not select the production worker boundary by themselves.
Selection remains gated on the broker-supplied custom-FD lifecycle test, exact
AOS Linux UAPI parity, cancellation behavior, and the `SBX-P0-11` resource and
latency measurements. A small bounded raw codec remains the fallback if those
tests show that libfuse cannot meet the admission model.

## Reuse and build ledger

Reuse:

- nspawn with one narrow pre-PID1 filter patch, systemd manager D-Bus, cgroup
  v2, and networkd/resolved;
- Linux namespaces, descriptor mount API, idmapped mounts, and FUSE;
- ZFS snapshot, hold, clone, quota, and compatible send/receive;
- Git protocol v2, upload-pack/receive-pack, bundles, and partial clone;
- Nix daemon/store semantics and signed substituters;
- AOS Hub's immutable distribution model; and
- RFC-0011 generation activation and RFC-0012 lease/root-reason principles.

Build:

- sandbox resource model, capabilities, desired-state journal, and reconciler;
- separate fixed privileged host/storage/mount/network boundaries, one-shot
  workers, lease guardian, fixed network lease gate, and Linux wrappers;
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
