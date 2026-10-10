# Campaign service process resources

The built-in campaign store uses one native SQLite allocator per daemon
process. Parallel campaign stores borrow that process owner; a store does not
install a separate native heap ceiling. Its existing storage, task, descriptor,
and Rust allocation budgets remain distinct.

Production `crucible serve` runs as the generated `crucible-campaign.service`.
Enable `aos.services.crucibleCampaign` with an explicit `processResources`
contract. Every field is required; the module supplies no resource defaults.
It installs containment before service helpers and the main executable start,
and publishes the same strict policy at `/etc/crucible/campaign-process.toml`.
A direct shell invocation cannot substitute a cgroup path, environment value,
current PID, or numeric heap limit for that original contract.

The contract contains these independent purposes:

| Fields | Purpose |
| --- | --- |
| `memoryMaxBytes`, `tasksMax`, `fileDescriptors` | Complete service memory and task ceilings, and original soft/hard descriptor limit. |
| `runtimeSeconds`, `startupTimeoutSeconds` | Main invocation lifetime and separate startup timeout. |
| `cpuQuotaPercent` | Service CPU quota at the fixed 100 ms period. |
| `baselineResidentBytes` | Loaded mappings, parsing, service runtime, allocator overhead, and thread stacks. |
| `metadataBytes` | Original process and managed SQLite ownership controls. |
| `sqliteBootstrapBytes` | Permanent linked-native globals and independently qualified initialization peak. |
| `sqliteHeapBytes`, `sqliteConnections` | One positive native heap ceiling and fixed managed connection roster. |
| `workerThreads`, `blockingThreads`, `threadStackBytes`, `mainThreadStackBytes` | Authored runtime pool sizes, worker stack extents, and main soft/hard stack bound. |

The resident partitions must fit `memoryMaxBytes` without overflow. Runtime
threads and their stacks must fit the task and baseline purposes. The roster
must fit the descriptor contract. These checks validate the policy's shape;
the operator still needs a source-bound upper qualification for loaded native
storage, initialization, and the complete enclosing runtime. A measured
allocator high-water does not supply that upper bound.

Startup authenticates the root service manager's main PID and invocation,
checks the immutable executable and evaluated policy, and verifies the installed
limits. These readbacks authenticate an existing operator grant; they do not
create capacity. The deadline remains the original main invocation deadline,
including elapsed startup time. The process owner exists before the ordinary
Tokio pool and listener, and the same heap flows into built-in repository and
catalog preparation. A borrowed heap larger than a catalog's existing maximum
is refused rather than treated as a per-catalog memory cap.

The permanent bootstrap credit and original actor remain retained for the
process lifetime. Managed native connections close before their controls and
heap credit. Failed or uncertain native cleanup retains that same ownership.
The allocator release request may release nothing, and no SQLite shutdown is
performed. A zero native usage sample supplements the managed census; it does
not prove the absence of foreign native handles.
