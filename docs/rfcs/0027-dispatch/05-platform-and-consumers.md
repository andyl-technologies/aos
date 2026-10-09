# 10. AOS and application interfaces

## 10.1. Platform boundary

AOS exposes Dispatch as installed libraries, executables, and configurable
execution facilities. Platform integration MUST preserve the portable model
and session contracts. It MUST NOT make AOS deployment identifiers, package
store paths, service types, or consumer-specific resource records part of the
assignment model.

The platform owns installation and authorization of execution profiles. A
profile specifies permitted backend builds, supervision mode, aggregate
entitlement, worker limits, concurrency, queue and cache bounds, and lifecycle
policy. A profile MAY express relative importance through authorized names
such as interactive, batch, or maintenance. The returned session grant MUST
identify the concrete effective limits and enforcement mechanisms.

For managed AOS execution, application-owned services beneath an application
solver slice are RECOMMENDED. The system module MUST establish aggregate
accounting across the application's sessions. A shared UID MUST NOT imply a
shared application entitlement. Installation of Dispatch MUST NOT require a
host-wide service that receives every application's assignment data.

An authorized application MAY use a portable subprocess provider, a custom
supervisor, or a remote provider. Selecting a different provider MUST NOT alter
the semantics of capacities, constraints, objectives, or verified results.

## 10.2. Packaging and distribution

AOS packages MUST build Dispatch and selected native backends hermetically
from source using the AOS toolchain and packaged dependencies. Build-time code
generation MUST use packaged tools. Native library dependencies and their
licenses MUST remain explicit. Distribution MUST retain applicable upstream
notices and identify backend build provenance.

The portable libraries and protocol definitions MUST be buildable without AOS
system modules. They MUST NOT require an AOS package manager, Nix store layout,
systemd installation, or application-specific configuration. Backend discovery
MUST permit an explicit executable or endpoint chosen by trusted application
configuration. An assignment problem MUST NOT choose executable paths.

Release metadata MUST distinguish library version, model semantic version,
protocol version, and backend build identity. A compatible library update does
not authorize a model semantic change. Cross-language examples and schemas
MUST be distributed with the public interface.

## 10.3. Library operations

The public interface MUST provide equivalent operations for these functions:

| Operation | Contract |
| --- | --- |
| Build and validate | Construct a finite immutable model; reject malformed references, unsupported numeric ranges, and invalid semantics |
| Evaluate | Compute exact usage, named violations, and objective values for a supplied assignment |
| Verify | Classify a supplied candidate as feasible, authorized repair, or invalid for the exact model |
| Open session | Resolve execution and backend policy, authorize limits, and return negotiated guarantees |
| Solve | Submit bounded work with an explicit deadline and return one terminal result |
| Prepare and release | Retain immutable input within scoped accounting and release its handle |
| Observe | Obtain bounded status and optional progress without changing solve ownership |
| Cancel | Request termination with an acknowledged completion or cancellation outcome |
| Compare and explain | Report exact differences between assignments and named contributions to evaluation |
| Close | Stop admission and drain or cancel accepted work with bounded cleanup |

Builders MAY offer policy recipes for common packing, replica spreading, and
evacuation problems. Each recipe MUST expand into ordinary model operations
whose constraints and objective tiers are inspectable. A recipe MUST NOT add
hidden admission policy or silently substitute approximate semantics.

What-if analysis MUST construct a distinct immutable problem. It MUST NOT
mutate a running solve's observation basis. Comparison across different
problems MUST identify changed inputs and MUST NOT imply that scores computed
under different units or policies are directly comparable.

Pure operations execute within the caller's resource context. Runtime
operations MUST use the configured execution boundary for substantive model
materialization and verification. Documentation MUST make this distinction
clear so callers can select isolation for expensive offline evaluation too.

## 10.4. Command-line and language-neutral use

The `dispatch` executable MUST expose validation, evaluation, solving, result
explanation, and assignment comparison. It SHOULD expose benchmark execution
using the same session and backend contracts. Machine-readable input and
output MUST follow the published model and result schemas. Human-readable
diagnostics MUST NOT be mixed into the machine-readable result stream.

A command MUST distinguish invalid input, unsupported capabilities, overload,
execution failure, and a completed search without a feasible candidate.
Exit-status documentation MUST define these categories; consumers MUST NOT
need to infer infeasibility from diagnostic text.

The CLI MUST support an explicit local execution profile. Remote execution MAY
be supported through an explicit endpoint and authenticated session. Endpoint
selection and credentials belong to caller configuration, not model data.
Progress streams MUST be bounded and separable from final results.

Illustrative command shapes are:

```text
dispatch validate --problem problem.json
dispatch evaluate --problem problem.json --assignment assignment.json
dispatch solve --problem problem.json --profile batch --result result.json
dispatch explain --problem problem.json --result result.json
dispatch compare --problem problem.json --before before.json --after after.json
```

These examples define operation intent. Language clients MUST use the
published schemas rather than parsing a human-readable rendering of these
commands. A streaming local process interface MAY provide repeated requests
without launching a CLI process for each solve.

## 10.5. Consumer adaptation

A consumer adapter performs five responsibilities:

1. Translate observations into items, targets, topology, and resource units.
2. Declare policy through explicit constraints and objective tiers.
3. Preserve an observation basis that the consumer can revalidate.
4. Interpret results without promoting search status into authority.
5. Reserve resources and execute changes through the consumer's own protocol.

Dispatch MUST NOT infer application policy from item names or opaque metadata.
Application adapters MAY evolve independently. The following profiles are
informative examples of prospective consumers, not mandatory dependencies or
coupled deployment requirements.

### 10.5.1. Crucible campaigns

A campaign adapter can represent runnable attempts as items and executors as
targets. Dimensions can express executor slots, CPU allocation, resident RAM,
and disk occupancy. Eligibility can encode required capabilities and available
artifacts. Optional admission can select work for a bounded planning horizon;
objective tiers can express campaign policy and locality.

The adapter MUST charge each resource once according to its actual accounting
definition. A semantic CPU-work ceiling MUST NOT be substituted for concurrent
CPU capacity. Artifact staging or metadata that is included in a total demand
MUST NOT be added again as a separate demand.

Executor admission remains authoritative. The campaign controller must obtain
its normal ownership or admission token before launching an attempt. Solver
cancellation does not cancel a running campaign attempt; attempt resources
remain charged until the executor's release condition is satisfied.

### 10.5.2. Terrane storage

A storage adapter can represent packs or replica shards as items and storage
children as targets. It can encode byte capacity, failure-domain spread,
locality, current placement, and physical movement costs. Replicas have distinct
item identities linked by a group; a deferred replica cannot count toward
durability or an active copy requirement.

Distinct child identities do not imply distinct hosts or zones. The adapter
must supply the topology needed by its durability policy. It must also model
destination staging and retained source occupancy when overlap matters.

The storage system retains authority over publication, custody transfer,
retirement, and garbage collection. A placement proposal does not authorize
deletion of an existing copy. Any deterministic placement policy used for
ordinary writes remains distinct from an optimization proposal unless the
storage system explicitly makes that proposal authoritative.

### 10.5.3. Sandbox resource scheduling

A sandbox adapter can represent schedulable components as items and nodes or
execution destinations as targets. Resource dimensions can include CPU, RAM,
disk, and device allocations. Eligibility can encode capabilities, affinity,
and acceptable ownership state. Components that require one local execution
environment can be represented by a colocation group or a compound item.

Nested resource grants must be translated according to their accounting
relationship. Inclusive grants MUST NOT be summed again as independent child
usage. A placement for a live pinned component does not establish that
migration is supported. The scheduler retains admission and ownership
authority, and must reject stale placement results before changing those
records.

### 10.5.4. Other and external consumers

The same model can describe service replica placement, cache allocation,
batch-job admission, maintenance evacuation, or offline planning. Dispatch
MUST NOT require these consumers to share an AOS controller process, resource
type registry, or application state database.

Consumers that share physical capacity MUST declare partitions or use a common
reservation authority. A common solver service does not itself provide that
authority. Compute priority of the solving session and priority of modeled
items remain independent policy decisions.

# 11. Operational considerations

## 11.1. Observability

Session diagnostics MUST expose granted and enforced resources, backend build,
model and protocol versions, worker generation, lifecycle state, and terminal
reason. Measurements SHOULD distinguish queue waiting, startup, transfer,
model construction, search, verification, and result delivery. CPU time and
wall time MUST be labeled distinctly.

Resource exhaustion MUST be reported separately from allocation infeasibility.
When possible, diagnostics SHOULD identify whether a leaf worker limit or an
ancestor application limit was reached. An unavailable measurement MUST be
reported as unavailable, not as zero.

Metrics and logs MUST use bounded cardinality and bounded buffers. Full item
identifiers, observation references, and model payloads SHOULD NOT become
default metric labels or logs. Detailed artifacts MAY be retained under an
explicit access and retention policy.

## 11.2. Reproducibility and artifacts

A solve artifact SHOULD record the immutable problem, request options,
backend identity, effective execution profile, candidate, evaluation, search
evidence, and relevant timing. It MUST identify omitted data and MUST NOT imply
durability merely because an artifact can be exported.

Providing a seed does not establish deterministic output across thread counts,
backend builds, machines, or execution limits. A backend advertising replay
MUST define the exact scope of that guarantee. Reproducing a valid evaluation
is independent of reproducing a heuristic search trajectory.

Artifacts MUST be self-contained enough for evaluation without a live session.
Prepared handles and service-local cache references MUST NOT substitute for
the immutable inputs needed to re-evaluate an exported candidate.

## 11.3. Policy and upgrade management

Operators SHOULD separate interactive, batch, and maintenance entitlements
when their latency or isolation requirements differ. Authorized profiles MUST
remain bounded even when a consumer opens multiple sessions. Warm pools SHOULD
start with the minimum useful concurrency; expansion MUST stay within the
aggregate grant.

Backend upgrades MUST preserve model semantics or negotiate an incompatible
capability/version change. A running request MUST remain bound to its selected
backend build. Restarting a worker MUST invalidate affected prepared handles.
Rolling an execution profile MUST NOT silently move warmed allocations to a
different resource owner.

A service MAY terminate sessions during an upgrade according to its declared
lease and shutdown contract. Durable job recovery is a separate optional
capability; callers MUST NOT assume it from reconnect support or retained
result metadata.
