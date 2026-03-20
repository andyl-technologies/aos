# AOS Distributed System

AOS is a lightweight distributed system built on four core building blocks.
Each block is independent but composable — together they form a complete
platform for distributed builds, deployments, and orchestration.

## Building Blocks

### Store — Content-Addressed Data

The **store** is a distributed content-addressed object store. Every piece of
data — source code, build outputs, system images, configuration — is a store
object identified by its content hash. Store objects are immutable: the same
hash always refers to the same content.

**Key properties:**
- **Content-addressed.** Objects are identified by blake3 merkle tree hash.
  Two identical objects from different sources share the same hash.
- **Git-compatible.** The internal structure uses git tree/blob format for
  merkle verification, subtree dedup, and git tooling compatibility.
- **CDC chunked.** Files are split into content-defined chunks for efficient
  dedup and parallel transfer. Shared chunks across similar objects are stored
  once.
- **Peer-to-peer transfer.** Objects are discovered via DHT provider records
  and transferred via resolve + chunk stream protocols.
- **Retained by affinity.** Statute mount affinities control which nodes pin
  store objects. Nodes matching a mount's affinity automatically fetch and
  retain referenced objects.

The store is the foundation — every other building block depends on it.
Job specs, workflow specs, build outputs, and system configurations are all
store objects.

**Docs:** [store.md](store.md), [git-store.md](git-store.md),
[storage.md](storage.md), [store-upload.md](store-upload.md),
[fetch.md](fetch.md), [mounts.md](mounts.md)

---

### Statute — Consensus and Governance

**Statute** is a BFT key-value store providing consensus-backed mutable state.
While the store handles immutable content, Statute handles mutable
configuration, authorization, and governance — anything that needs global
agreement and audit history.

**Key properties:**
- **BFT consensus.** Chained HotStuff protocol tolerates f < n/3 Byzantine
  validators. All validators converge to the same state.
- **UCAN-authorized.** Every write requires a UCAN delegation chain from the
  genesis key. Fine-grained access control per key path.
- **Schema-validated.** CUE schemas validate values before consensus.
  Deterministic validation ensures no consensus divergence.
- **Merkle-trie state.** Full state is committed in each block. Any value is
  verifiable via merkle proof against a finalized block.
- **Auditable history.** Every mutation is recorded with author, timestamp,
  and UCAN proof. Full history queryable by key.

Statute replaces DHT-stored configuration (ClusterConfig, UCAN revocations)
with consensus-backed state that has versioning, rollback protection, and
schema validation.

**Docs:** [statute.md](statute.md)

---

### Jobs — Execution

**Jobs** are units of work executed by peers within a cluster. A job creates
an isolated container — either a hermetic Nix build, a FOD fetch, or a
mutable service container — and runs it to completion.

**Key properties:**
- **Three job types.** BuildSpec (hermetic Nix build from .drv), FetchSpec
  (download FOD from upstream), RunSpec (mutable container with configurable
  capabilities).
- **Decentralized scheduling.** No central scheduler. Each peer independently
  decides whether to claim a job based on load, affinity (local store content),
  and eligibility (system, features, labels, taints).
- **Two-phase execution.** Creator posts the job, builder claims it (load-
  staggered first-claim), creator starts the container on the builder.
  Reservation tokens enable zero-latency DAG pipelining.
- **Systemd slice isolation.** Each cluster's jobs run in a dedicated cgroup
  slice. Per-cluster resource limits, per-job resource requests/limits (k8s
  style).
- **Content-addressed outputs.** Build outputs are chunked, hashed, and
  published to the store. Output hashes match `nix build` exactly.

Jobs are the execution primitive. Workflows compose jobs into DAGs.

**Docs:** [jobs.md](jobs.md), [containers.md](containers.md),
[scheduling.md](scheduling.md), [load-reports.md](load-reports.md)

---

### Workflows — Orchestration

**Workflows** are reactive DAGs executed autonomously by the cluster. A
workflow describes a computation graph — like a Nix build graph — as a set
of named steps with dependencies, each producing or requiring a store object.

**Key properties:**
- **Deterministic control flow.** All conditions are content-addressed (store
  hashes). Actions may be non-deterministic (builds), but the workflow DAG is
  a pure function of its inputs.
- **Five step types.** `input` (required store object), `fetch` (download
  FOD), `build` (hermetic Nix build), `await_workflow` (inter-workflow dep),
  `decision` (conditional skip).
- **Idempotent execution.** All step types are safe to re-execute (partitions,
  crashes, rebalancing). RunSpec is intentionally excluded — mutable containers
  cannot guarantee idempotent re-execution.
- **Speculative claiming.** An executor that completes step A can speculatively
  claim step B in the same message. Combined with reservation tokens, a chain
  of builds can pipeline through one builder with zero inter-step latency.
- **Autonomous.** The client can disconnect after submission. The workflow
  executes in the cluster and the client reconnects later to check status.
- **Validated.** Workflow specs are validated at submission time (DAG
  acyclicity, input existence, fetch source validity, cross-workflow cycle
  detection).
- **Reactive mounts.** Workflow definitions can be mounted as reactive Statute
  mounts at any path. The mount watches read dependencies — when a dependency
  changes (e.g., a git ref is pushed, a config is updated), the mount
  automatically creates a new workflow run. This eliminates explicit workflow
  submission for event-driven use cases. Parameters are just mount-local keys
  (`read(./arg)`) that trigger re-evaluation when written.

Workflows compose jobs into arbitrarily complex build graphs.

**Docs:** [workflow.md](workflow.md), [workflow-spec.md](workflow-spec.md),
[workflow-validation.md](workflow-validation.md)

---

## Composition

The four building blocks compose to create a distributed cloud-like
environment:

### Package Building

A client evaluates a Nix flake, produces a workflow spec with the full build
DAG, and submits it to the cluster. The workflow engine:

1. Fetches FOD sources from upstream mirrors (FetchSpec jobs)
2. Builds derivations in dependency order (BuildSpec jobs)
3. Pipelines builds through builders with local input affinity
4. Publishes outputs to the store
5. Pins outputs on nodes matching mount affinities

The client disconnects during the build and reconnects later to fetch the
final output. See [workflow-spec.md](workflow-spec.md) for the GNU Hello
example.

### Service Deployment

An operator writes a cluster config to Statute, defining the desired service
state. Peers read the config, create RunSpec jobs with INIT_SYSTEMD, and
run systemd-based containers with host network access. The containers
mount their system profile from the store via FUSE.

### Continuous Integration

A workflow mount watches a git ref in Statute (e.g., `/repos/main/head`).
When a new commit is pushed, the mount's read dependency changes, triggering
a new workflow run that builds the full package set and runs tests. Results
are written back to Statute. Failed builds are retried automatically
(workflows are idempotent). Multiple commits build in parallel across the
cluster — each push creates an independent reactive run.

### Infrastructure as Code

Statute stores the desired state of the cluster (configs, schemas, UCAN
delegations). CUE schemas validate every configuration change. The full
history of who changed what, when, and why is auditable. Rollback is a
single transaction pointing to a previous config version.

## Network Architecture

```
                    ┌─────────────────────────────┐
                    │        Statute (BFT)         │
                    │  Consensus · Governance · KV  │
                    └─────────┬───────────────────┘
                              │ reads config,
                              │ writes status
        ┌─────────────────────┼─────────────────────┐
        │                     │                      │
  ┌─────▼─────┐        ┌─────▼──────┐        ┌──────▼──────┐
  │   Store    │◄───────│    Jobs    │───────►│  Workflows  │
  │  (CAS)    │ outputs │ (Execution)│ composes│(Orchestrate)│
  │           │◄───────│            │        │             │
  └───────────┘ inputs  └────────────┘        └─────────────┘
```

- **Store** is the data plane — immutable content flows through it.
- **Statute** is the control plane — mutable config and governance.
- **Jobs** are the compute plane — execute work in isolated containers.
- **Workflows** are the orchestration plane — compose jobs into DAGs.

## Peer Roles

A single AOS daemon can participate in any combination of roles:

| Role | Store | Statute | Jobs | Workflows |
|---|---|---|---|---|
| **Builder** | Serves + produces | Follower | Claims + executes | Executes steps |
| **Cache** | Serves | Follower | — | — |
| **Validator** | Serves | Validator | — | — |
| **Submitter** | Uploads | Follower | Creates | Submits |
| **Observer** | Reads | Follower | Reads | Reads |
| **Full** | All | Validator | All | All |

Roles are determined by UCAN capabilities and daemon configuration, not by
a role field. A peer is a "builder" because it has `/aos/job/claim` and a
`clusters.X.labels.jobs = "true"` config — not because it declares itself as one.

## Relationship to Other Docs

- [store.md](store.md) — content-addressed store (data plane)
- [statute.md](statute.md) — BFT KV store (control plane)
- [jobs.md](jobs.md) — job execution (compute plane)
- [workflow.md](workflow.md) — workflow orchestration (orchestration plane)
- [daemon.md](daemon.md) — daemon architecture, multi-cluster, systemd slices
- [auth.md](auth.md) — UCAN authorization model (shared across all blocks)
- [enrollment.md](enrollment.md) — network enrollment and key management
- [cloud-init.md](cloud-init.md) — automated provisioning
- [protocol.md](protocol.md) — wire protocol index
- [overview.md](overview.md) — protocol summary
