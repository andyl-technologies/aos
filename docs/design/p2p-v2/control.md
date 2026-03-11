# ControlSignal CRDT and LoadReport

ControlSignal is a decentralized CRDT for managing replica sets -- keeping N
instances of a job specification running across the cluster. It replaces the
role of the Kubernetes replication and deployment controllers. Published on the
GossipSub topic `aos/cluster/{cluster_ident}/control/announce`, authorized by
`/aos/control/announce WHERE .cluster == {cluster_ident} AND .operation HAS
{control_op}`.

LoadReport is a periodic metric broadcast published on
`aos/cluster/{cluster_ident}/load/announce`, authorized by `/aos/load/announce
WHERE .cluster == {cluster_ident}`.

---

## 1. ControlSignal CRDT

The ControlSignal CRDT is a **desired-state map** keyed by replica set name.
Each signal declares how many instances of a job template should be running.
Peers independently observe the desired state, compare it to actual state,
and reconcile by starting or stopping jobs.

The map uses **last-writer-wins (LWW) per name**: when two signals target the
same replica set name, the one with the higher timestamp wins. Signals
targeting different names are independent and both survive merging.

### Wire Format

```protobuf
message ControlSignal {
    string cluster_id = 1;
    string signal_id = 2;          // ULID -- globally unique, lexicographically sortable
    uint64 timestamp = 3;          // microseconds since epoch (LWW ordering)
    string author = 4;             // PeerId of the admin who issued this

    oneof signal {
        ReplicaSet replica_set = 10;
        ReplicaSetDelete replica_set_delete = 11;
    }

    string ucan = 5;
}
```

Fields:

- `cluster_id` -- the cluster this signal belongs to.
- `signal_id` -- ULID for dedup and deterministic tie-breaking.
- `timestamp` -- microseconds since epoch. Used for LWW conflict resolution.
- `author` -- PeerId of the signal author.
- `ucan` -- UCAN proof chain authorizing the control operation.

---

## 2. ReplicaSet

A ReplicaSet declares: "keep N instances of this job template running across
peers matching a selector."

```protobuf
message ReplicaSet {
    string name = 1;                     // unique service name (e.g., "ci-runner")
    JobSpec template = 2;                // job template for each replica
    uint32 replicas = 3;                 // desired instance count (0 = stopped)
    NodeSelector selector = 4;           // which peers can run replicas
    UpdateStrategy update_strategy = 5;  // how to roll out changes
}

message ReplicaSetDelete {
    string name = 1;
}
```

- `name` -- unique identifier for this replica set within the cluster.
- `template` -- the `JobSpec` used to create each replica. Each instance
  gets a unique `job_id` and `nonce` derived from the replica set name and
  instance index.
- `replicas` -- desired number of running instances. Setting to 0 stops all
  instances without deleting the replica set definition.
- `selector` -- `NodeSelector` constraints (system, features, labels)
  determining which peers are eligible to run replicas.
- `update_strategy` -- how to transition when the template changes.

### Update Strategies

```protobuf
message UpdateStrategy {
    oneof strategy {
        RollingUpdate rolling = 1;
        Recreate recreate = 2;
    }
}

message RollingUpdate {
    uint32 max_surge = 1;          // max extra instances during update
    uint32 max_unavailable = 2;    // max instances down during update
}

message Recreate {}                  // kill all old, then start all new
```

**RollingUpdate** -- replace instances one (or a few) at a time. At any point
during the rollout, at least `replicas - max_unavailable` instances are
healthy, and at most `replicas + max_surge` total instances exist.

**Recreate** -- stop all old instances, then start all new instances. Simpler
but incurs downtime.

### ReplicaSetDelete

Removes the replica set from the desired-state map. All instances are
drained and stopped. A `ReplicaSetDelete` at timestamp T supersedes any
`ReplicaSet` with the same name at timestamp < T.

---

## 3. Reconciliation Loop

Each peer independently runs a reconciliation loop that compares desired
state (from merged ControlSignals) against actual state (running jobs):

```
loop every reconciliation_interval:
    desired = local desired-state map (from merged ControlSignals)
    actual  = running jobs managed by replica sets on this peer

    for each replica_set in desired:
        if I match replica_set.selector:
            my_share = compute_share(replica_set, eligible_peers)
            running  = count_my_instances(replica_set.name)

            if running < my_share:
                start (my_share - running) new jobs from replica_set.template
            if running > my_share:
                stop (running - my_share) oldest jobs
```

### Replica Distribution

With N eligible peers and R desired replicas, each peer independently
computes its share:

```
base  = floor(R / N)
extra = R mod N

Each peer sorts eligible PeerIds lexicographically.
Peers at index 0..extra get (base + 1) replicas.
Peers at index extra..N get base replicas.
```

This requires no coordination -- each peer reaches the same assignment given
the same desired-state map and set of eligible peers (from LoadReport).
Eligible peers are those that: (a) match the selector, (b) have a recent
LoadReport (not timed out).

---

## 4. Rolling Update Flow

Consider a replica set `ci-runner` with 4 replicas, `RollingUpdate {
max_surge: 1, max_unavailable: 1 }`, running template v1. An operator
publishes a new `ReplicaSet` with template v2.

Each peer independently reconciles:

1. **Observe**: desired template is v2, running instances use v1.
2. **Constraints**: at most 1 instance may be unavailable (3 must run), at
   most 5 total (4 + max_surge).
3. **Start new**: a peer with capacity starts one v2 instance (total: 4 v1 +
   1 v2 = 5).
4. **Stop old**: once v2 is healthy (DHT heartbeat present), one v1 instance
   stops (total: 3 v1 + 1 v2 = 4).
5. **Repeat**: peers continue starting v2 and stopping v1 until all 4 are v2.

Peers coordinate through observation -- they see which instances are running
cluster-wide via DHT job records and GossipSub announcements. If two peers
both try to start a new instance and that would exceed max_surge, the
replica distribution algorithm ensures only the assigned peer proceeds.

---

## 5. CRDT Merge Semantics

The ControlSignal CRDT is a map from replica set name to
`(timestamp, signal)`.

**Merge rules:**

1. **Same name, different timestamps**: higher timestamp wins.
2. **Same name, same timestamp**: tie-break by `signal_id` (lexicographic,
   lower wins). ULIDs are timestamp-prefixed, so ties are extremely rare.
3. **Different names**: both signals kept (independent).

**Consistency**: the merge function is commutative, associative, and
idempotent. Peers may receive signals in any order and converge to the same
desired-state map.

**Garbage collection**: `ReplicaSetDelete` signals act as tombstones. They
are retained for a configurable tombstone TTL (default: 24h) to prevent
deleted replica sets from reappearing when a delayed `ReplicaSet` signal
arrives.

---

## 6. LoadReport

LoadReport is a periodic broadcast informing scheduling and reconciliation
decisions. Each peer publishes a LoadReport at a regular interval.

### Wire Format

```protobuf
message LoadReport {
    string cluster_id = 1;
    string peer_id = 2;
    uint64 timestamp = 3;

    ResourceUsage usage = 4;
    ResourceCapacity capacity = 5;

    uint32 running_jobs = 6;
    uint32 running_services = 7;
    string system = 8;
    repeated string features = 9;
}

message ResourceUsage {
    double cpu_fraction = 1;
    uint64 memory_used_bytes = 2;
    uint64 disk_used_bytes = 3;
}

message ResourceCapacity {
    uint32 cpu_cores = 1;
    uint64 memory_total_bytes = 2;
    uint64 disk_total_bytes = 3;
}
```

- `system` -- architecture (e.g., `x86_64-linux`). Used for job matching.
- `features` -- capabilities (e.g., `kvm`, `big-parallel`). Used for
  feature-gated workloads.
- `running_jobs` / `running_services` -- current load on this peer.

### Scheduling Use

LoadReports are **not** a CRDT -- they are ephemeral observations. Each peer
maintains a table of the most recent LoadReport per peer (keyed by peer_id,
overwritten on each receive).

LoadReports serve two purposes:

1. **Job claiming**: when a job is posted and multiple peers are eligible,
   lower-loaded peers claim first. Implemented as a random backoff
   proportional to load -- a peer at 20% CPU claims faster than one at 80%.

2. **Replica placement**: the reconciliation loop uses LoadReports to
   determine which peers are eligible (have recent reports = alive) and to
   prefer placing replicas on peers with more available capacity.

If a peer's LoadReport is older than `peer_liveness_timeout` (from
ClusterConfig, or a built-in default), that peer is considered offline and
excluded from replica distribution.
