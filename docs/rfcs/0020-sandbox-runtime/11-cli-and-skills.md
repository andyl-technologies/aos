# CLI, inspection, and automation skills

## One public interface

Humans, CI systems, coding agents, and other automation use the same public
API. The `aos sandbox` CLI is porcelain over `aos.sandbox.v1`; it is not a
second source of lifecycle semantics. Every mutating command accepts an
idempotency key, supports a bounded wait for its operation, and can return the
operation without waiting.

Every command that emits structured information supports `--json`. JSON mode
uses the public resource schema and stable string enum names. Human output may
change for clarity; JSON fields follow the public compatibility rules. Secret
or holder-bound capability material is never printed by default.

The primary command surface is:

```text
aos sandbox create
aos sandbox get
aos sandbox list
aos sandbox tree
aos sandbox children
aos sandbox start
aos sandbox stop
aos sandbox suspend
aos sandbox resume
aos sandbox exec
aos sandbox attach-exec
aos sandbox cancel-exec
aos sandbox snapshot
aos sandbox restore
aos sandbox fork
aos sandbox delete
aos sandbox events

aos sandbox view create
aos sandbox view attach
aos sandbox view replace
aos sandbox view detach
aos sandbox view list

aos sandbox cache status
aos sandbox cache pin
aos sandbox cache unpin
```

Commands accept opaque sandbox IDs and unambiguous project-scoped selectors.
Names are labels, not identities. Relative selectors such as `self`, `parent`,
and `child:<label>` are resolved by the service under the caller's capability;
the client does not discover hidden objects while resolving a name.

## Creation and planning

`aos sandbox create` accepts a declarative specification or a checked-in
project preset. It has a dry-run form that resolves policy, required backend
capabilities, environment generations, storage, cache domains, network
profile, and capacity without performing effects.

The dry-run result distinguishes:

- requirements the selected node can enforce;
- requirements that require different placement;
- advisory preferences that would degrade;
- reservations that would be acquired; and
- capabilities that would be delegated to the new sandbox.

A child creation request issued from inside a sandbox derives the parent and
caller identity from the authenticated control channel. A `--parent` flag is
available only to principals holding the corresponding control-plane
authority; it is never trusted merely because a sandbox process supplied it.

## Execution

`aos sandbox exec` creates an `Execution` resource. Its input is an argument
vector, working-directory handle, environment overlay, terminal mode, timeout,
and declared endpoint capabilities. A shell string is CLI sugar interpreted
only when the caller explicitly requests a sandbox-resident shell.

The command supports:

- noninteractive stdin/stdout/stderr streaming;
- PTY allocation and resize;
- signal forwarding and explicit cancellation;
- exact exit status and terminating signal; and
- bounded output capture as an alternative to streaming.

V1 does not reattach a disconnected byte stream or PTY. By default SSH
disconnect cancels that execution. An explicitly detached execution runs with
no live PTY, writes bounded captured output, and is later inspected through the
execution resource; attaching to that historical output is not stream replay.

No execution data path travels through the privileged host daemon. The client
uses the authorized OpenSSH route. The in-sandbox agent is an internal control
participant, not a client-selectable stream transport.

## Tree inspection

`aos sandbox tree` is bounded and paginated. It defaults to the caller's
authorized subtree and prints desired phase, observed phase, placement, health,
and aggregate resource reservations. It never recursively embeds the complete
resource, execution, snapshot, and attachment graph in one reply.

Filesystem inspection is explicit:

```text
aos sandbox snapshot child-a --purpose inspect
aos sandbox view attach \
  --source snapshot:<id> \
  --to self:inspection/child-a \
  --read-only --noexec
```

The CLI may offer a shorter `aos sandbox inspect-files` workflow, but it still
defaults to a filtered immutable snapshot view and exposes the snapshot,
view, and attachment objects in status. There is no implicit host path, linked
Git worktree, or privileged namespace traversal hidden behind the command.

Native live read-only inspection requires
`live-kernel-coupled-read` and is labeled non-atomic and interfering: it may
connect to sockets/FIFOs or participate in source inode locks despite `ro`. A
snapshot provides stable noninterfering bytes for review or audit, but not
automatically a Git-semantic checkpoint: it may capture an index lock or
partial Git transaction. Git status/diff runs
inside the child context or a fresh constrained inspection sandbox with
sanitized repository administration. A committed ref obtained through the
smart protocol is the stable Git-semantic interface. Read-write inspection
requires an exclusive export lease and normally a quiesced child.

## Destructive commands

Delete defaults to one sandbox and rejects live dependents. Recursive deletion
requires `--cascade`, displays the complete authorized post-order plan, and
uses one operation ID for the transaction. `--force` means stop for hard
revocation before deferred cleanup; it does not bypass snapshot holds, storage
safety checks, authorization, or audit retention.

Snapshot and view deletion report leases preventing reclamation. They do not
silently invalidate a running sandbox. Operators can enumerate the holders and
revoke only through an authority that includes those consumers.

## Skills for automation

Agent-facing skills are small workflow descriptions layered over the public
CLI. They do not encode a second protocol or receive broader host authority.
The initial skill set should cover:

1. creating or entering a project sandbox;
2. creating a descendant with attenuated limits;
3. inspecting a descendant through a read-only snapshot view;
4. advancing a project environment generation;
5. suspending, resuming, snapshotting, and forking;
6. preserving work and handing a sandbox to another principal; and
7. safely deleting a leaf or a reviewed subtree.

Each skill performs discovery before mutation, prints the target sandbox UID
and project, propagates idempotency keys, and waits on the returned operation.
Skills must use `aos sandbox` or the public client library. They must not invoke
`systemctl`, `systemd-run`, `machinectl`, `nsenter`, `mount`, `zfs`, raw FUSE
ioctls, or broker sockets.

Skills treat a sandbox as durable until deletion succeeds. Ending an agent
session does not imply deletion, and deleting a Git branch does not imply that
the associated sandbox storage is disposable.

## Capability handling

Interactive clients normally authenticate to the coordinator and receive a
short-lived holder-bound session. In-sandbox clients receive an attenuated
capability through a pre-opened control channel. The channel binds sandbox UID,
incarnation, project, principal, and allowed verbs; those values are not
caller-controlled request fields.

Capabilities may be exported only in an explicitly requested sealed or
holder-bound form. CLI configuration stores references in the user's existing
credential facility rather than placing bearer tokens in environment
variables, command lines, shell history, project files, or snapshot manifests.

## Compatibility and discovery

`aos sandbox capabilities` exposes public API feature names and node/backend
capabilities separately. Scripts request semantic features such as
`dynamic-native-view`, `durable-snapshot`, or `immutable-fuse-passthrough`; they
do not branch on nspawn flags, systemd versions, ZFS dataset paths, or kernel
syscall numbers.

When a newer CLI talks to an older service, unsupported hard requirements fail
before effects. The server projects ProtoJSON to the client's negotiated
schema. A registered `ObservationExtension` that the CLI does not understand
may be printed as its type, version, and policy-permitted opaque bytes; raw
unknown protobuf fields are not promised to survive JSON projection. Unknown
authority-bearing policy is rejected.
