# RFC-0021: Generic sandboxes and filesystem views

- **Status:** Accepted design; single-node implementation first
- **Date:** 2026-09-03
- **Audience:** maintainers of `aos`, AOS system images, systemd integration,
  package and cache infrastructure, storage, security policy, and distributed
  control-plane APIs.
- **Relates to:** [RFC-0001](../0001-package-sandboxing/README.md),
  [RFC-0005](../0005-ca-trust-map.md),
  [RFC-0011](../0011-on-host-config-eval/README.md), and
  [RFC-0015](../0015-hermetic-cargo-artifacts.md).

## Summary

AOS will provide a generic sandbox service for interactive development,
builds, CI jobs, operators, and automation. A sandbox is a durable logical
object with an isolated runtime, a private writable workspace, resource and
authority ceilings, a place in an explicit ancestry tree, and lifecycle
operations for execution, inspection, snapshot, suspend, resume, fork, and
deletion. The service is not specific to coding agents; agents use the same
public CLI and API as every other client.

The initial production runtime backend is `systemd-nspawn`, launched as
a transient systemd unit without making `systemd-machined` the source of truth.
AOS owns desired state, capability delegation, storage lineage, mount
attachment, and reconciliation. Backends remain pluggable: the portable API
describes sandbox semantics and required capabilities rather than nspawn
arguments.

The first implementation phase is single-node. Its first connected milestone
is public Create, boot/Ready, execution/observation, Stop, and Delete on one
host, with local ownership, private storage/networking, hard resource policy,
and restart reconciliation. Native views and the other local profiles follow
as separate slices. Multi-node protocols remain documented, but coordinator
implementation, remote placement/transfer, and cluster deployment are reserved
for a later phase behind explicit optional crate and feature boundaries.

The [implementation-boundary amendment](18-implementation-boundaries-and-single-node-rollout.md)
defines the target crate splits, internal interfaces, removal of superseded
paths, and delivery order. It does not assert that the current source has
completed those changes. Source coverage and historical ledger entries are not
proof of connected or qualified production behavior.

Dynamic filesystem attachment is part of the first architecture, not an
afterthought. A source-neutral **filesystem view** abstraction selects among:

- native detached, idmapped mounts for same-node live datasets;
- native snapshots or clones for local copy-on-write state;
- a new AOS FUSE service for immutable, synthesized, filtered, or remotely
  backed trees; and
- explicitly materialized trees when neither native mounting nor FUSE can
  satisfy the requested semantics.

The FUSE path uses compact immutable tree indexes, lazy inode creation, a
bounded content cache, and Linux backing-file passthrough so steady-state file
I/O uses native backing inodes. Namespace metadata and file bytes remain
separate. A portable logical tree schema is versioned independently from its
replaceable node-local mmap index.

Sandbox lineage is a control-plane tree, not recursive container nesting and
not unbounded overlay-on-overlay stacking. A parent receives no ambient access
merely because it is an ancestor. It may receive an explicit attenuated
capability to inspect or attach a descendant export. Same-node live views
create placement affinity; remote descendants are inspected through immutable
snapshot views or service protocols.

## Locked architectural decisions

1. Sandboxes are generic AOS resources. Agent skills are adapters over the
   stable `aos sandbox` CLI and never acquire a private daemon protocol.
2. The ancestry tree governs delegation and lifecycle; runtimes are sibling
   host-managed objects rather than recursively nested nspawn instances.
3. `systemd-nspawn`, transient units, systemd supervision, and cgroup v2 are
   reused. AOS does not use machined, `systemd-mountfsd`, or
   `systemd-nsresourced` as the v1 sandbox authority.
4. The public contract is desired-state and capability based. Host paths,
   PIDs, namespace paths, file-descriptor numbers, mount IDs, and FUSE backing
   IDs are node-local implementation details.
5. Dynamic mounts are represented by immutable view revisions and independent
   attachment objects. One view may have many attachments.
6. Authorized kernel-coupled live local trees use native mounts. Noninterfering
   inspection and synthesized, filtered, or lazily fetched immutable content
   use FUSE or materialization.
7. Shared bytes are immutable. Every writable upper or workspace is private;
   shared mutable caches require a transactional service interface.
8. Authority, namespace construction, hard resource policy, and advisory
   optimization compile separately. Optimization can never expand authority.
9. Hard enforcement that cannot be installed prevents `Ready`. Only policy
   explicitly marked advisory may degrade.
10. An ownership-authority lease and host-owned `CLOCK_BOOTTIME` guardian fence
    every active assignment independently of the unprivileged reconciler.
11. Suspend, snapshot, restore, and delete are reconciliation operations over
    durable desired state. A filesystem snapshot alone is never described as
    a complete sandbox snapshot.
12. Tree, view, snapshot, policy, and RPC versions are independent compatibility
    domains.
13. Initial implementation is single-node. Portable identity and local fencing
    retain future compatibility, but coordinator implementation and multi-node
    enablement belong to a later optional phase; no phase claims coherent live
    remote POSIX mounts.
14. Shared data and mechanisms sit below protected domain owners; application
    assembly sits above them. The local implementation never depends on a
    coordinator implementation. Superseded paths are removed, not accumulated
    as permanent compatibility layers.

## Documents

- [Goals, non-goals, terminology, and invariants](00-goals-and-invariants.md)
- [Sandbox objects, ancestry, delegation, and placement](01-domain-model-and-tree.md)
- [Architecture and component boundaries](02-architecture.md)
- [Runtime backends and the nspawn implementation](03-runtime-backends.md)
- [Filesystem views, FUSE, and native realizers](04-filesystem-views.md)
- [Capabilities and policy language](05-policy-and-capabilities.md)
- [Cache, memory, OOM, and capacity](06-cache-memory-and-oom.md)
- [Project environments, package changes, and Git](07-project-environments-and-git.md)
- [Lifecycle, snapshots, suspension, recovery, and deletion](08-lifecycle-and-recovery.md)
- [Protocols and portable data formats](09-protocols-and-formats.md)
- [Canonical portable format profile](09-portable-format-profile.md)
  ([CDDL schema](portable-v1.cddl))
- [Security analysis](10-security.md)
- [CLI, inspection, and automation skills](11-cli-and-skills.md)
- [Observability and operations](12-observability-and-operations.md)
- [Testing and performance gates](13-testing-and-performance.md)
- [Implementation sequence and code ownership](14-implementation-plan.md)
- [Decisions, alternatives, and open questions](15-decisions-and-open-questions.md)
- [Implementation task ledger](16-implementation-tasks.md)
- [Production authority closure amendment](17-production-authority-closure.md)
- [Implementation boundaries and single-node rollout](18-implementation-boundaries-and-single-node-rollout.md)

## Completion scope

Initial single-node completion is defined by the connected lifecycle and
boundary criteria in the implementation-boundary amendment. Later local
profiles and multi-node enablement have independent exit gates; neither
unimplemented FUSE nor deferred coordinator work prevents demonstrating the
first native local lifecycle. No unavailable feature is advertised as ready.

## Full design conformance

The full design, including subsequently selected profiles, is implemented only
when:

- an unprivileged client can create, execute in, inspect, fork, snapshot,
  suspend, resume, and delete a sandbox through the public CLI;
- a sandbox can create a policy-bounded descendant without receiving node
  privilege;
- native live views and immutable FUSE views attach dynamically to a running
  user-namespaced nspawn sandbox through descriptor-based mount operations;
- an AOS project development environment can advance to a new immutable
  package-view generation without rebuilding the sandbox root;
- identical authorized immutable files share one physical backing inode and
  backing-filesystem cache identity inside the configured disclosure domain,
  with page-cache/ARC behavior measured for the selected backend;
- strict cache modes demonstrably use separate backing-filesystem cache
  identities and do not share reflinks, clones, dedup, or ZFS ARC keys across
  their isolation boundary;
- million-entry trees remain proportional to the touched working set in heap
  use and do not require eager inode construction;
- hard memory, PIDs, storage, brokered mount-count, conservative FD, cache-disk,
  pin, and registration ceilings fail admission rather than silently degrading;
- FUSE worker OOM, daemon restart, node reboot, interrupted mount replacement,
  stale coordinator requests, and partial snapshot transactions reconcile to
  explicit terminal or recoverable states;
- FUSE mounts prove `allow_other + default_permissions`, exact ID/ACL mapping,
  and passthrough permission checks, while default descendant inspection omits
  live socket/FIFO/lock coupling;
- lease expiry, daemon/guardian death, host suspend, and reboot stop the old
  payload and default-drop its network before ownership can move;
- self-contained snapshots reject every external mutable dependency, including
  a live source mounted read-only, and restore with a new sandbox incarnation;
- all authorization, delegation, cache, tree-parser, mount-race, snapshot, and
  multi-node fencing conformance gates pass; and
- the implementation remains hermetic and contains no dependency on nixpkgs or
  host tools.
