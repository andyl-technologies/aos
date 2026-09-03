# Project environments, package changes, and Git

## Project integration

A project may declare a sandbox profile through its AOS/Nix development
configuration. The profile resolves to:

- an immutable base system or command environment;
- package and tool closure roots;
- environment variables and executable facade;
- workspace and cache declarations;
- network and service requirements;
- hard resource ceilings and requested reservations;
- child-delegation policy; and
- advisory materialization and prefetch policy.

The controller coordinates evaluation through the existing hermetic,
authenticated AOS configuration path. Untrusted project expressions and hooks
never execute in the privileged host control plane; they run in an evaluation
or project sandbox with declared inputs. The resolved closure, policy, and
source revision are content addressed and stored in sandbox desired state.
Starting an existing sandbox never depends on re-evaluating mutable project
files.

The default CLI discovers the project root using the same repository-aware
rules as other AOS commands. It accepts an explicit project or profile to avoid
ambient directory ambiguity.

## Package environment views

A package environment is an immutable filesystem view revision. It normally
presents:

- the exact authorized `/nix/store` closure;
- a generated profile/facade tree;
- package metadata and provenance; and
- optional read-only source or documentation objects.

Its identity commits to the project/flake source, lock digest, selected output
attribute, target system, realized closure, generated environment artifact,
policy, and cache/disclosure domain. The host pins every required closure with
a durable GC root or equivalent lease for as long as a sandbox or snapshot
references the generation.

The view may be native when every store path already exists safely on the node,
or FUSE-backed when the namespace is filtered or objects should arrive lazily.
It never bind-mounts the complete host Nix store into an untrusted sandbox.

Applying a package change is transactional:

1. resolve and authorize the requested AOS packages;
2. compute the complete view, closure, reservation, and replacement plan;
3. atomically persist the new desired environment generation, operation,
   preconditions, and reservations before effects;
4. fetch and verify missing closure objects;
5. compile a new immutable package view revision;
6. prepare its index and required executable backing files;
7. attach the immutable facade at a generation-specific slot;
8. extend the sandbox's append-only store view with any newly leased paths;
9. switch the `current` convenience facade for future execution admission;
10. mark the desired generation observed and active; and
11. retain old facades and closure paths until their execution/snapshot leases
    release.

Each execution receives generation-specific `PATH`, environment, and facade
paths and holds a lease on that generation. The sandbox-visible store is an
append-only union of every closure leased by an active execution or retained
snapshot, so a later `exec`, `dlopen`, plugin load, or configuration reopen by
an old process still finds its admitted immutable store paths. The mutable
`current` facade is only a selector for new admissions and is never the claimed
identity of an existing execution. The CLI can request a restart barrier when
an application requires every process to move to one generation.

An `apm` invocation inside the sandbox uses a scoped sandbox-package endpoint
or produces a proposed environment change for the controller. It does not gain
the host Nix daemon socket, an unfiltered store, or authority to attach paths.
The controller returns the same plan and effective-policy explanation as an
outside caller.

One root-owned Nix store service is authoritative for a writable store and
state database within each configured trust/disclosure domain. Strict domains
use physically distinct store directories and backing inodes as well as
distinct databases; hard-link optimization, auto-optimization, reflink
deduplication, and cache publication may not recreate cross-domain sharing.
Sandboxes normally receive only their read-only closure view. Interactive Nix
builds are an explicit capability using a proven untrusted-client configuration
or a narrowing proxy; the raw trusted host daemon socket is not exposed.
Trusted Nix users are treated as root-equivalent. Two independent Nix state
databases never concurrently mutate the same store directory.

## Runtime OS adaptation

The same generation switch can update a sandbox's broader userspace without
replacing its private workspace:

- package environment;
- generated `/etc` or application configuration view;
- service-unit view admitted by policy; and
- executable facade.

Changes that affect the booted init system, UID database, capabilities, device
policy, root layout, or backend contract require a new sandbox incarnation.
The planner reports that boundary before applying the change.

## Workspace storage

Each sandbox receives a private workspace dataset. A child may begin from:

- an empty tree;
- a snapshot of its parent's workspace;
- an immutable Git commit/tree;
- a project template revision; or
- a publishable snapshot selected by the caller.

Native ZFS clones are preferred for same-pool forks. The storage lineage is
logical and explicit; it does not rely on Git branches or overlay depth.

Workspace fork has two explicit modes. The default sanitized project fork
excludes repository administration storage, creates a fresh repository with
`clone --no-local` over the authorized smart protocol, and overlays the
snapshotted working files. Staged/index state is carried only through an
explicit, validated Git-state export. A byte-exact fork clones `.git`, hooks,
config, reflogs, and any accidentally stored credentials and therefore
requires a distinct `inherit-repository-administration` grant. A cheap storage
clone is never described as sanitized.

This boundary follows Git's own
[security guidance](https://git-scm.com/docs/git#_security) for obtaining a
clean configuration and hooks boundary from an untrusted repository.

A parent may attach a child's workspace read-only through an explicit live-view
grant. Read-write sharing is exceptional and must declare an application-level
coherency policy. A parent that wants changes normally fetches commits or
imports a sealed snapshot instead.

## Git is a protocol, not an isolation boundary

Every sandbox repository has private mutable refs, index, working tree, hooks,
and configuration. AOS never executes host-privileged Git while using a
sandbox-controlled `.git` directory. Raw `.git` mounting across the boundary is
an explicit high-trust diagnostic mode, not the default collaboration path.

Repository exchange uses the Git smart protocol through an AOS-authorized
transport:

- read authority covers an entire exchange repository/object database;
- callers requiring different readable object sets receive physically separate
  generated bare exports, bundles, or packs containing only authorized
  reachability;
- pushes terminate in a broker-owned bare exchange repository, use
  [receive-pack quarantine](https://git-scm.com/docs/git-receive-pack.html),
  validate every proposed ref transition and object,
  and publish under compare-and-swap;
- object packs may be cached as immutable content inside the disclosure domain;
- sanitized forks do not copy credentials or helper configuration; and
- hooks run only inside the sandbox that owns the repository.

The v1 implementation uses standard upload-pack/receive-pack over authenticated
OpenSSH/ProxyCommand or smart HTTP, mapping a logical sandbox repository handle
to an authorized endpoint. The logical URL works locally and across nodes and
contains no host repository path. A custom `git-remote-aos` helper is deferred
unless standard URL rewriting and transports cannot express the authorization
or routing requirement.

Ref advertisement, hidden refs, namespaces, and upload-pack negotiation are not
object-confidentiality controls: a client may request reachable or guessed
objects. AOS never serves differently classified objects from one shared Git
ODB and relies on an allowlisted ref name to conceal them. Git documents this
limitation in its
[namespace security contract](https://git-scm.com/docs/gitnamespaces#_security).

## Parent and child Git workflow

A typical child workflow is:

1. the parent creates a child from a workspace snapshot or Git commit;
2. the controller allocates a private repository/ref namespace for the child;
3. the child edits, builds, tests, and commits locally;
4. the parent inspects live files through a read-only view if co-located;
5. the parent fetches the child's committed ref through the Git protocol; and
6. merging or publishing remains an explicit Git operation by an authorized
   principal.

Uncommitted work is preserved by workspace snapshots, not inferred from Git.
Deleting a child with uncommitted or unpublished changes requires a retention
or cascade decision.

Running Git against a child-controlled `.git` can execute or consult hooks,
filters, textconv, config includes, credential helpers, fsmonitor, and other
repository-controlled programs. Git-semantic inspection therefore runs inside
the child's security context or in a fresh constrained inspection sandbox over
a sanitized exchange repository. A parent may read exported files, but its
ordinary execution context never treats the child's raw `.git` as trusted.

## Git object sharing

Git object content is immutable, but repositories contain mutable refs,
reflogs, indexes, configuration, and hooks. AOS may share verified object packs
or loose objects through the filesystem-view cache while keeping mutable
repository administration private.

Git alternates that expose a host path are not portable and can become an
authority escape. If an optimization uses alternates internally, the Git
gateway owns and validates them, pins the exact immutable pack generation for
the entire alternate lifetime, and exposes only a stable sandbox path. On
same-node ZFS forks, CoW already shares Git bytes and alternates add no default
benefit. The portable behavior remains ordinary fetch negotiation, bundles, or
partial-clone/promisor protocol.

## Build caches

Project profiles identify cache services by logical class:

- immutable download/source cache;
- compiler-result CAS;
- dependency metadata service;
- private incremental output directory; and
- publishable build result staging.

The sandbox receives protocol endpoints or filesystem views appropriate to the
class. Tools such as compilers that safely consume a content-addressed remote
cache should use the service. Tools that assume a mutable local directory
receive a private directory by default. Project-wide shared mutation is enabled
only by a specific adapter with locking, atomicity, poisoning, quota, and
version-skew semantics.

## Reproducibility

Every execution records:

- project configuration and policy digests;
- package environment view revision;
- workspace snapshot or live generation;
- Git commit and dirty/snapshot state where known;
- attached view revisions;
- cache disclosure and publication classes; and
- runtime backend capability fingerprint.

Warm caches affect performance, not logical input identity. A reproducible
execution can be reconstructed from retained source and tree commitments even
after node cache eviction.
