# 6. Sessions and execution

## 6.1. Sessions, providers, and backends

A Dispatch session is an application-owned execution context. It binds an
execution provider, granted resource profile, backend selection policy, bounded
pending work, and prepared-input namespace. It supplies cheap clonable handles
through which an application submits independent solves. Cloning a handle MUST
retain the same session identity, limits, and accounting; it MUST NOT establish
a new entitlement.

A session is distinct from a worker pool, process, systemd unit, and cgroup. Its
provider MAY create several workers, initialize them lazily, or execute through
a remote service. A worker MUST have at most one active solve, including input
materialization and result verification. A session MUST bound its worker count.
An application MAY use several sessions, but their combined resource usage MUST
remain subject to the application's aggregate entitlement where the provider
claims application-level enforcement.

An execution provider determines where computation runs and how its lifecycle
and resources are controlled. A solver backend implements allocation semantics
and search. Rebalancer is a backend; subprocess, systemd, embedded, and remote
execution are providers. Selecting a backend MUST NOT silently change provider
guarantees, caller identity, or resource entitlement. Provider and backend
capabilities MUST be negotiated separately.

Dispatch MUST support application-owned execution without a shared host-wide
daemon. An operating system MAY expose shared launch facilities or remote
execution, but these facilities MUST preserve explicit ownership and admission
boundaries. Library and command-line consumers MUST be able to execute without
a network service.

## 6.2. Initialization and execution profiles

Session initialization MUST resolve the provider, authorize the requested
profile, negotiate capabilities, and return the granted limits and guarantees.
Initialization MAY defer worker creation until the first accepted operation.
In that case, backend negotiation MUST use trusted capability metadata bound
to the selected executable and build identity. The live worker handshake MUST
confirm that identity and the required capabilities before materializing a
problem. A mismatch MUST produce an explicit capability or execution error;
it MUST NOT silently replace the grant or backend. A provider without trusted
metadata MUST start a worker to complete negotiation.

Initialization MUST NOT imply that input has been materialized. Initialization
failures MUST distinguish unavailable providers, unauthorized profiles,
unsupported guarantees, and invalid configuration.

Profiles MUST select warm or fresh execution explicitly:

| Profile | Worker lifecycle | Appropriate use |
|---|---|---|
| Warm | Reuses bounded application-owned workers | Repeated solves under one stable resource profile |
| Fresh | Starts a worker for each solve and retires it afterward | Distinct budgets or isolated, infrequent computation |

Dispatch MUST NOT choose between these profiles using an undocumented problem
size threshold. Implementations MAY add an explicit automatic-selection policy
after qualification, but MUST report the selected mode and effective limits.
Cold process startup, managed-unit startup, warm communication, model
construction, search, and verification SHOULD be measured separately.

A warm worker MUST remain within one resource owner and stable accounting
boundary. A provider MUST NOT transfer warmed workers between owners to reuse
their allocations. Prepared inputs and native state MUST NOT be shared across
owners without an explicitly authorized sharing contract.

The application MUST be able to observe worker startup failure independently
of solve infeasibility. Startup, model materialization, native search, and
verification are execution stages, not allocation outcomes.

## 6.3. Admission and pending work

Every session MUST bound both the count and retained bytes of pending requests.
It MUST also bound prepared inputs, active workers, diagnostic buffers, and
retained results. A request MUST declare or expose its input size before the
session retains an unbounded payload. Shared immutable inputs MAY be accounted
once, but accounting MUST include their resident ownership and MUST NOT rely
only on compressed wire size. Admission MUST reserve capacity for a terminal
record so that simultaneous completions cannot exhaust result metadata storage.
Optional progress buffers MUST NOT consume that reservation. Candidate payloads
MAY have separately granted retention limits and MUST report omission or expiry.

Admission MUST fail promptly with an overload result when a configured bound
would be exceeded. Dispatch MUST NOT accumulate an unbounded queue while
waiting for native workers. Applications MAY implement retry or external
backpressure. An optional asynchronous wait-for-admission operation MUST itself
have bounded waiters and an explicit deadline.

Admission occurs before large input expansion. Work accepted for later
execution MUST occupy the pending bounds until dispatched, cancelled, or
expired. An application that submits through several handles MUST share these
bounds. Separate sessions MUST NOT bypass an enforced aggregate application
budget by creating additional workers or retained inputs.

Accounting transitions between queued, active, prepared, and retained-result
ownership MUST be atomic with respect to admission. Shared data MAY change
accounting categories, but MUST NOT become temporarily uncharged. Session
grants MUST disclose terminal-record retention and its finite expiry.

Provider admission concerns actual computation resources. It MUST NOT modify
the submitted problem's item priorities, capacity policy, or objective tiers.
Conversely, a high-priority item inside a problem MUST NOT confer permission to
consume more solver CPU or memory.

## 6.4. Deadlines, cancellation, and terminal results

A solve deadline MUST begin when submission starts, before queue waiting. It
MUST cover admission waiting when requested, worker startup, input transfer,
materialization, search, verification, and terminal-result construction.
Providers MUST propagate the remaining budget between stages. A remote
provider MUST NOT assume synchronized client and server clocks; its protocol
MUST define duration accounting and how client-side expiration bounds waiting.

A watchdog outside the native solver process MUST enforce hard cancellation
when the provider advertises it. A backend's cooperative timeout is useful but
MUST NOT substitute for this watchdog. Cancellation MUST terminate the worker
tree where descendants can continue consuming resources. A warm worker killed
for cancellation MUST be replaced before reuse.

Cancellation is a request with an acknowledged outcome. Completion MAY win a
race with cancellation. The session MUST publish one terminal result and MUST
report whether the operation completed, was cancelled, reached a limit, or
failed. It MUST NOT rewrite an already committed completion as cancellation.
Dropping a result watcher MUST NOT implicitly cancel the solve.

A result that reaches a deadline MUST distinguish a verified candidate already
accepted before the terminal decision from an unverified or absent candidate.
A deadline MUST NOT be extended silently to finish verification. Backend
failure, process termination, and memory exhaustion MUST NOT become claims of
allocation infeasibility.

Wall-clock budgets include scheduler contention. A throttled worker MAY expire
with little search completed. CPU time, search time, wall time, and the selected
resource profile SHOULD be reported separately when measurable.

## 6.5. Requested, granted, and effective resources

Resource contracts MUST distinguish these states:

| State | Meaning |
|---|---|
| Requested | Caller preference or required guarantee awaiting authorization |
| Granted | Entitlement authorized by the provider or its trusted controller |
| Enforced | Bound or behavior implemented by an identified mechanism |
| Best effort | Advisory target or cooperative behavior without that mechanism |
| Rejected | Request cannot be authorized or its required guarantee cannot be met |

Granted resources MUST report their enforcement status. A provider MUST reject
a required guarantee it cannot supply; it MUST NOT silently downgrade it to
best effort. Solver thread configuration is a cooperative setting, not a
physical CPU quota. Solver allocation estimates are not hard memory limits.

The resource owner or trusted controller MUST establish caller entitlement.
An untrusted caller MUST NOT select arbitrary cgroup paths, systemd slices,
privileged execution identities, or unrestricted priority values. Authorized
profiles MAY expose simpler choices such as interactive, batch, or maintenance
execution. Their concrete limits and identity mapping belong to deployment
policy and MUST be inspectable in the session grant.

Where aggregate application enforcement is advertised, CPU importance MUST
apply at the application boundary as well as any worker boundary. Adding
workers or sessions MUST NOT multiply that application's aggregate CPU share.
A provider without aggregate enforcement MUST disclose its accounting scope
and reject requests requiring application-wide guarantees. Cgroup weights
distribute available CPU among competing sibling groups; they do not guarantee
solve deadlines. Hard memory ceilings
also do not reserve physical memory merely because individual ceilings sum to
a host's capacity. Hierarchical weights, limits, and protections have distinct
semantics in the [Linux cgroup-v2 resource distribution model](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#resource-distribution-models).

## 6.6. Provider contracts

### 6.6.1. Subprocess

The subprocess provider MUST execute the native backend in a separate process
and communicate over the versioned worker protocol. It MUST identify available
process-tree cancellation and accounting mechanisms. On Linux, ordinary child
processes inherit their parent's cgroup, so this provider can preserve existing
application accounting without creating a new resource controller.

Process separation alone MUST NOT be advertised as independent memory or OOM
containment. An inherited cgroup can include the application controller and
other children. The provider MUST report whether memory limits are inherited,
independently enforced, or best effort. Portable external consumers MAY supply
their own launcher or supervisor without changing backend semantics.

### 6.6.2. Systemd

The systemd provider MUST launch managed services with their resource policy
established before substantial model or solver allocation. Warm profiles MAY
use persistent services; fresh profiles MAY use transient services. The
provider MUST use systemd's supported management interfaces or an explicitly
delegated subtree. It MUST NOT mutate arbitrary manager-owned cgroups.
[Systemd's delegation contract](https://systemd.io/CGROUP_DELEGATION/) defines
ownership of those subtrees; its
[transient settings](https://github.com/systemd/systemd/blob/main/docs/TRANSIENT-SETTINGS.md)
include resource-control properties.

The trusted Rust runner and C++ engine MUST both execute within the worker's
budget. Decoding, model construction, optimization, verification, and bounded
diagnostics MUST NOT move their substantial allocations into an unrestricted
launcher. An external runtime watchdog MUST retain the ability to stop the
managed service if either process stalls.

An illustrative hierarchy is:

```text
application.slice                 aggregate entitlement and CPU importance
  controller.service
  application-dispatch.slice      aggregate solver allowance
    dispatch-worker-1.service     warm worker, one active solve
    dispatch-worker-2.service     optional bounded additional worker
```

This hierarchy is conceptual; unit names and parent relationships MUST be
created according to systemd naming and authorization rules. The outer budget
MUST cover all sessions and workers charged to that application. A UID-based
user slice MAY supply a further aggregate limit, but MUST NOT be treated as an
application identity when unrelated programs share that UID.

The provider SHOULD map CPU importance to `CPUWeight`, ceilings to `CPUQuota`,
memory pressure control to `MemoryHigh`, and hard memory limits to `MemoryMax`.
`TasksMax` limits tasks, including native threads; it MUST NOT be interpreted as
solve concurrency. `RuntimeMaxSec` limits a service's lifetime and MUST NOT be
used as the sole per-request timeout for a persistent worker. These meanings
are specified by systemd's
[resource-control documentation](https://github.com/systemd/systemd/blob/main/man/systemd.resource-control.xml)
and [service documentation](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml).

The provider MUST report outer-limit failures as well as worker-limit failures
when identifiable. A leaf memory limit does not guarantee survival if an
enclosing application budget is exhausted. Warmed memory MUST NOT be reassigned
by migrating a process after materialization: Linux does not move existing
stateful charges with ordinary process migration. See the
[kernel's cgroup organization guidance](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#organize-once-and-control).

### 6.6.3. Embedded

An embedded provider MAY run a compatible backend within the caller's process.
It MUST advertise cooperative cancellation and shared process memory. It MUST
NOT claim hard termination, separate OOM containment, or independent process
isolation. It MUST reject profiles requiring those guarantees. Embedded
execution is suitable only when the application accepts these consequences;
protocol semantics and independent verification still apply.

### 6.6.4. Remote and custom

A remote provider MUST authenticate the caller and obtain a server-issued
grant before accepting substantive execution. The grant MUST specify session
lifetime, limits, enforcement guarantees, and retention policy. A client
disconnect MUST have explicit lease semantics: it MAY leave work running for
a bounded interval, but MUST NOT create an indefinitely orphaned session.
Lease expiry MUST stop admission and initiate bounded cleanup.

Shared remote execution requires identity mapping, admission, and accounting
even when server workers use cgroups. These responsibilities MUST NOT be
omitted on the assumption that process isolation supplies fairness. A custom
provider MUST expose the same guarantee vocabulary and capability negotiation.
Dispatch MUST NOT require a remote implementation or shared daemon for local
operation.

## 6.7. Prepared inputs and worker recovery

Prepared handles MUST declare one of two scopes. A session-input handle binds
to the session generation, model identity, and negotiated semantics; it
represents runtime-retained immutable input that can be sent to a fresh or
replacement worker. A worker-local handle additionally binds to one worker
generation and represents input retained by that worker. Both MUST remain
within their owner's storage budget. Preparation MUST NOT promise a retained
expression graph, native search state, or incremental-update capability unless
the backend explicitly advertises that behavior.

A worker crash, hard cancellation, or replacement MUST invalidate its
worker-local handles. Session-input handles MAY survive worker replacement;
they MUST be invalidated when their owning session generation ends. Relevant
server restart MUST invalidate handles unless a separately granted recovery
contract preserves them. A stale-handle error MUST be explicit. The caller MAY
prepare again from its immutable source problem. Automatic
retry MUST respect the original deadline and MUST NOT hide execution failures
or duplicate side effects of a custom provider.

Reusing a worker MUST NOT relax verification or allow one request to inherit
another request's mutable solver state implicitly. Providers SHOULD recycle
workers when their declared lifecycle policy requires it. Cached state MUST
remain within the owner's retained-byte budget.

## 6.8. Explicit session shutdown

Sessions MUST expose asynchronous close with `Drain` and `Cancel` modes.
Closing MUST stop admission across all cloned handles. `Drain` MAY finish
accepted work until the close deadline. `Cancel` MUST request cancellation of
accepted work immediately. Both MUST have a bounded timeout and report work
that completed, was cancelled, or could not be confirmed stopped.

A typical lifecycle is:

```text
initialize session -> receive granted profile -> clone handles
submit -> admit -> materialize -> solve -> verify -> terminal result
optional worker reuse or replacement
close(Drain | Cancel, timeout) -> cleanup report
```

Rust `Drop` MUST NOT be presented as a guarantee of asynchronous cleanup or
remote cancellation. Dropping the final local handle MAY initiate best-effort
cleanup; managed process lifetimes and remote leases MUST supply independent
bounds. Applications requiring confirmed cleanup MUST await explicit close.

Managed local workers MUST have an owner-liveness relationship or finite lease
that does not depend on normal client destruction. Loss of the owning control
connection or expiration of that relationship MUST initiate bounded cleanup.
The owner connection is distinct from individual result watchers; losing a
watcher MUST NOT terminate the session. A provider unable to establish owner
cleanup MUST disclose that limitation and reject profiles requiring it.
