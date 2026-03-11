# P2P Build Jobs: Submission, Claiming, and Scheduling

Job submission, claiming, scheduling, and affinity for the AOS distributed
build system using libp2p. There is no central scheduler -- scheduling is
emergent from local decisions made independently by each daemon node.

---

## Job Submission

A build job enters the mesh through the following sequence:

1. The client evaluates the Nix expression locally to obtain a `.drv` path.
2. The client uploads the derivation's input store paths to the mesh via
   the daemon's P2P interface (see [store.md](store.md)).
3. The daemon publishes the job to the GossipSub topic `build/wanted/{universe}/{system}`.

### Job Message Format

```json
{
  "job_id": "uuid",
  "drv_path": "/nix/store/abc123-foo.drv",
  "drv_hash": "abc123",
  "universe": "default",
  "arch": "x86_64-linux",
  "features": ["kvm"],
  "priority": 0,
  "input_hashes": ["hash1", "hash2", "hash3"],
  "submitted_at": 1709900000,
  "submitter_peer_id": "QmDaemon1"
}
```

Field descriptions:

- `job_id` -- unique identifier for this submission (UUID v4).
- `drv_path` -- the full Nix store path of the derivation to build.
- `drv_hash` -- the hash portion of the store path, used as the canonical key
  for deduplication and DHT lookups.
- `universe` -- the target universe for this build (e.g. `"default"`, `"dev"`).
- `arch` -- the target architecture (e.g. `"x86_64-linux"`, `"aarch64-linux"`).
- `features` -- required system features (e.g. `["kvm"]`, `["big-parallel"]`).
- `priority` -- numeric priority. 0 is normal; higher values are more urgent.
- `input_hashes` -- store path hashes of the derivation's build-time closure.
  Used by daemons to compute affinity scores.
- `submitted_at` -- Unix timestamp of submission.
- `submitter_peer_id` -- the libp2p peer ID of the daemon that submitted the job.

Every daemon subscribed to `build/wanted/{universe}/{system}` on the GossipSub mesh
receives this announcement. GossipSub delivers messages to ALL subscribers -- it is a pub/sub
broadcast, not a work queue.

---

## Build Claiming

Because GossipSub delivers to all subscribers rather than providing work-queue
semantics, a claiming protocol prevents all daemons from starting the same job
simultaneously.

### Claim Flow

1. Daemon receives job from `build/wanted/{universe}/{system}`.
2. Daemon evaluates eligibility: architecture match, required features, and
   available capacity.
3. Daemon checks the Kademlia DHT: `GET("build:{drv_hash}")`.
   - If a record exists, another daemon has already claimed this job. Skip it.
   - If no record is found, proceed to claim.
4. Daemon writes a DHT record: `PUT("build:{drv_hash}", {peer_id, status: "building", started_at})`.
5. Daemon publishes to GossipSub topic `build/claimed/{universe}/{system}`:
   ```json
   {
     "drv_hash": "abc123",
     "daemon_peer_id": "QmDaemon7"
   }
   ```
6. Daemon begins executing the build.

### DHT Claim Record Format

```json
{
  "peer_id": "QmDaemon7",
  "status": "building",
  "started_at": 1709900005
}
```

The `status` field transitions through: `"building"` -> `"announcing"` ->
`"complete"` (or `"failed"`). The daemon updates the DHT record at each
transition.

### Race Conditions and Duplicate Work

The Kademlia DHT is eventually consistent. Two daemons may both issue
`GET("build:{drv_hash}")`, both receive "not found", and both issue `PUT`
simultaneously. This results in duplicate work -- two daemons build the same
derivation concurrently.

**Why this is acceptable:**

- Nix builds are deterministic. Both daemons produce identical output store
  paths with identical content.
- Both daemons announce as DHT providers. Provider records are additive --
  multiple providers for the same content-addressed path is harmless.
- There is no data corruption risk, only wasted compute.
- In practice, DHT propagation latency is sub-second. Races are rare for
  normal-priority jobs because affinity-based delays (described below) naturally
  stagger claim attempts across daemons.

**Mitigations for expensive builds:**

- **Quorum reads:** Before claiming, query multiple DHT peers for
  `"build:{drv_hash}"` and wait for a majority response rather than relying on
  a single lookup. This reduces the window for false negatives.
- **Delayed claiming with affinity scoring:** Daemons with lower affinity wait
  longer before attempting to claim (see the scheduling section below). This
  naturally staggers claim attempts over approximately one second, giving the
  DHT time to propagate the first claim.
- **GossipSub `build/claimed/{universe}/{system}` announcement:** The claiming daemon
  publishes to `build/claimed/{universe}/{system}` immediately after writing the DHT record. GossipSub
  message propagation is typically faster than DHT record propagation, so other
  daemons learn about the claim sooner than they would from DHT alone.

---

## Scheduling via Affinity-Based Delayed Claiming

There is no central scheduler. Each daemon independently decides whether and
when to claim a job based on its **affinity score** -- the fraction of the
job's input store paths that the daemon already has in its local Nix store.

### Algorithm

```rust
fn should_claim(&self, job: &BuildJob) -> ClaimDecision {
    // Hard filters
    if job.arch != self.arch { return ClaimDecision::Skip; }
    if self.active_jobs >= self.max_jobs { return ClaimDecision::Skip; }
    if !job.features.iter().all(|f| self.features.contains(f)) {
        return ClaimDecision::Skip;
    }

    // Compute affinity: fraction of job's inputs already in local store
    let overlap = job.input_hashes.iter()
        .filter(|h| self.store_bloom.contains(h))
        .count();
    let affinity = overlap as f64 / job.input_hashes.len().max(1) as f64;

    // High affinity -> claim immediately
    // Low affinity -> delay, giving better-matched daemons priority
    if affinity > 0.8 {
        ClaimDecision::ClaimNow
    } else {
        let delay_ms = (1000.0 * (1.0 - affinity)) as u64;
        ClaimDecision::ClaimAfter(Duration::from_millis(delay_ms))
    }
}

enum ClaimDecision {
    Skip,
    ClaimNow,
    ClaimAfter(Duration),
}
```

When a daemon receives `ClaimAfter(delay)`, it schedules a deferred claim
attempt. Before executing the deferred claim, it re-checks the DHT to see if
another daemon has claimed the job in the interim. If claimed, it drops the
job silently.

### How Affinity is Computed

Each daemon maintains a **bloom filter** of its local Nix store path hashes.
This data structure has the following properties:

- Cheap to compute: scan the Nix store on startup (`ls /nix/store`), insert
  each hash. Update incrementally as builds complete (insert new output hashes).
- Cheap to test: O(k) per hash, where k is the number of hash functions
  (typically 3-7).
- Space-efficient: a bloom filter with 1 million entries and a 1% false
  positive rate requires approximately 1.2 MB.
- False positives are acceptable: a daemon may overestimate its affinity
  slightly, causing it to claim a job sooner than it should. The worst case is
  that it needs to download a few extra inputs.
- No false negatives: if the daemon has a store path, the bloom filter will
  always report it as present.

The job message includes `input_hashes` -- the store hashes of the derivation's
build-time closure. The daemon tests each hash against its bloom filter to
estimate the fraction of inputs already available locally.

### Emergent Scheduling Properties

The affinity-based delay mechanism produces several desirable scheduling
behaviors without any central coordination:

- **Cache-warm daemons claim first.** A daemon that already has 90% of a
  job's inputs claims within 100ms. A daemon with 50% overlap waits 500ms. A
  daemon with nothing cached waits the full 1000ms. The most efficient daemon
  for any given job naturally wins.

- **Minimized input transfer.** Because the best-matched daemon claims first,
  it needs to fetch fewer inputs from peers before starting the build. This
  reduces both build latency and network bandwidth.

- **No thundering herd.** Claim attempts are spread over approximately 1 second
  proportional to inverse affinity. Even with 100 daemons, they do not all hit
  the DHT simultaneously.

- **New daemons warm up gradually.** A freshly provisioned daemon with an
  empty store always waits the maximum delay. It only gets work when all
  "warm" daemons are busy or have skipped the job. Over time, it accumulates
  store paths and begins winning claims for related jobs.

- **Specialization emerges naturally.** A daemon that has been building
  Haskell packages accumulates GHC and Haskell library store paths. It
  develops high affinity for future Haskell jobs and claims them quickly.
  Another daemon that has been building kernel modules develops affinity for
  kernel-related work. No explicit assignment is needed.

---

## Daemon Capabilities

Each daemon advertises its capabilities via a Kademlia DHT record:

```
DHT Record:
  key: "daemon:{peer_id}"
  value: {
    "arch": "x86_64-linux",
    "features": ["kvm", "big-parallel"],
    "max_jobs": 8,
    "active_jobs": 3,
    "store_bloom": "<base64-encoded bloom filter>",
    "last_updated": 1709900000
  }
  TTL: 5 minutes (re-published every 2 minutes)
```

Field descriptions:

- `arch` -- the architecture this daemon can build for.
- `features` -- system features available (e.g. `"kvm"` for VM tests,
  `"big-parallel"` for high-core-count builds).
- `max_jobs` -- maximum concurrent builds this daemon will run.
- `active_jobs` -- current number of running builds. Updated on each
  re-publish.
- `store_bloom` -- base64-encoded bloom filter of local Nix store path hashes.
  Other peers can use this to estimate which daemon is best suited for a
  given job without that daemon needing to be online at query time.
- `last_updated` -- Unix timestamp of the last update.

The TTL is 5 minutes. Daemons re-publish every 2 minutes to keep records
fresh. If a daemon goes offline, its record expires within 5 minutes and peers
stop considering it for scheduling estimates.

Daemons can query peer capability records to:

- Estimate cluster capacity (total `max_jobs - active_jobs` across all
  daemons).
- Provide feedback to clients ("estimated build time", "N daemons available for
  your architecture").
- Decide whether to accept or queue new submissions.

---

## Priority

Jobs include a `priority` field. The value 0 is normal priority; higher values
indicate more urgent jobs.

### Daemon-Side Priority Queue

Each daemon maintains a local priority queue of pending jobs -- those received
via GossipSub `build/wanted/{universe}/{system}` but not yet claimed. On each scheduling tick
(when a build slot becomes available), the daemon selects the highest-priority
eligible job from this queue and attempts to claim it.

### Starvation Prevention via Aging

To prevent low-priority jobs from starving indefinitely, job priority increases
with age:

```rust
fn effective_priority(job: &BuildJob, now: u64) -> u64 {
    let age_minutes = (now - job.submitted_at) / 60;
    job.priority + age_minutes
}
```

A normal-priority job (priority 0) that has been waiting for 10 minutes has an
effective priority of 10. This ensures that even the lowest-priority jobs
eventually rise above freshly submitted normal-priority work.

### Priority Interaction with Affinity

Priority and affinity are orthogonal concerns:

- **Priority** determines which job a daemon picks from its queue.
- **Affinity** determines how quickly the daemon attempts to claim that job.

A high-priority job with low affinity is selected first from the queue but
claimed after a delay. A low-priority job with high affinity is selected later
but claimed immediately when its turn comes. This means high-priority jobs go
to the best-matched available daemon, while low-priority jobs fill in the gaps.

---

## Derivation Graph Awareness

Build requests often involve not a single derivation but an entire dependency
graph (DAG). A `build-closure` request asks the system to build a set of
derivations where some depend on the outputs of others.

### Daemon-Driven Topological Publishing

The daemon handling the client request is responsible for managing the
dependency ordering:

1. The client submits a closure of `.drv` paths representing the full build
   graph.
2. The daemon topologically sorts the DAG.
3. The daemon publishes **leaf derivations** first -- those with no unbuilt
   dependencies (all inputs already exist in the mesh).
4. As builds complete (the daemon monitors `build/claimed/{universe}/{system}` and DHT
   status records), it identifies newly unblocked derivations and publishes
   them to `build/wanted/{universe}/{system}`.
5. This continues until the root derivation is built.

### Alternative: Eager Publishing with Daemon-Side Readiness Checks

An alternative approach publishes the entire closure at once and lets daemons
determine readiness independently:

1. The daemon publishes all derivations in the closure to `build/wanted/{universe}/{system}`
   simultaneously, including dependency metadata:
   ```json
   {
     "job_id": "uuid",
     "drv_path": "/nix/store/abc123-foo.drv",
     "drv_hash": "abc123",
     "arch": "x86_64-linux",
     "features": [],
     "priority": 0,
     "input_hashes": ["hash1", "hash2"],
     "dep_drv_hashes": ["def456", "ghi789"],
     "submitted_at": 1709900000,
     "submitter_peer_id": "QmDaemon1"
   }
   ```
2. When a daemon considers claiming a job, it first checks that all entries in
   `dep_drv_hashes` have a DHT record with `status: "complete"`.
3. If any dependency is not yet complete, the daemon keeps the job in its
   local queue and re-evaluates on each scheduling tick.

**Trade-offs:**

- Topological publishing is simpler for building daemons (they only see
  ready-to-build jobs) but requires the submitting daemon to track build
  completion and manage state.
- Eager publishing reduces submitting daemon complexity but increases
  builder-side logic and DHT query load (builders repeatedly check dependency
  status).

The recommended approach is **daemon-driven topological publishing** because it
keeps builder logic simple and avoids redundant DHT queries across many daemons
all polling for the same dependency completions.

### Parallelism Within the DAG

Independent branches of the DAG are published simultaneously. For example, if
building a package requires both `openssl` and `zlib` and neither is cached,
both are published as separate jobs and can be built concurrently by different
daemons. The dependent package is published only after both complete.

The submitting daemon tracks the DAG state in memory:

```rust
struct ClosureBuild {
    /// All derivations in the closure, keyed by drv_hash
    derivations: HashMap<String, DerivationState>,
}

struct DerivationState {
    drv_path: String,
    /// drv_hashes this derivation depends on
    deps: Vec<String>,
    status: BuildStatus,
}

enum BuildStatus {
    /// Waiting for dependencies to complete
    Blocked,
    /// Published to build/wanted/{universe}/{system}, waiting for a daemon to claim
    Published,
    /// Claimed by a daemon
    Building { daemon_peer_id: String },
    /// Output announced to mesh
    Complete,
    /// Build failed
    Failed { error: String },
}
```

When a derivation transitions to `Complete`, the submitting daemon checks all
derivations that depend on it. If all of a derivation's dependencies are now
`Complete`, it transitions the derivation from `Blocked` to `Published` and
announces it on `build/wanted/{universe}/{system}`.
