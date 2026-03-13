# Wire Protocol

Single source of truth for all protobuf message definitions. Behavioral
semantics live in companion documents; authorization rules live in
[permissions.md](permissions.md).

---

## Quick Reference

### DHT Records

| Key | Value | TTL | Signature | Description |
|---|---|---|---|---|
| `aos:cluster:{cluster_id}` | Provider record | Short (heartbeat) | None (self-advertising) | Cluster membership advertisement |
| `aos:cluster:{cluster_id}:config` | `ClusterConfig` | Long | Root key | Cluster configuration and certificate tree |
| `aos:cluster:{cluster_id}:job` | Provider record | Short (1 min) | None (self-advertising) | Job creation acceptor advertisement |
| `aos:cluster:{cluster_id}:job:{job_id}` | Provider record | Short (heartbeat) | None (self-advertising) | Job executor advertisement |
| `aos:cluster:{cluster_id}:job:{job_id}:state` | `JobState` | Short (heartbeat) | Job key | Job liveness heartbeat and resource usage |
| `aos:store:{store_hash}` | Provider record | GC LRU eviction | None (content-addressed) | Store object provider advertisement |
| `aos:store` | Provider record | Short (1 min) | None (self-advertising) | Active store replicator advertisement |
| `aos:auth:token:{token_hash}:revoke` | `RevocationRecord` | Mirrors token expiry | Issuer key | UCAN revocation record |
| `aos:workflow:{workflow_id}` | Provider record | Workflow lifetime | None (self-advertising) | Workflow tracker advertisement |
| `aos:workflow` | Provider record | Short (1 min) | None (self-advertising) | Workflow start acceptor advertisement |

### GossipSub Topics

| Topic | Message | Description |
|---|---|---|
| `aos/cluster/{id}/jobs/announce` | `JobPost` | Job lifecycle CRDT (create, claim, start, exit, error, cancel) |
| `aos/cluster/{id}/load/announce` | `LoadReport` | Peer resource utilization reports |
| `aos/auth/token/revoke` | `RevocationNotice` | UCAN revocation notifications |
| `aos/auth/token/issue` | `IssuanceNotice` | UCAN issuance notifications (optional) |
| `aos/store/publish` | `StorePublish` | New store object announcements |
| `aos/store/replicate` | `ReplicateMessage` | Store replicator coordination (claims, success, nack) |
| `aos/store/purge` | `StorePurge` | Store object purge requests |
| `aos/workflows/announce` | `WorkflowPost` | Workflow creation and cancellation |
| `aos/workflows/active/{id}/state` | `WorkflowStateMessage` | Per-workflow state transitions and snapshots |

### Stream Protocols

| Protocol | Request | Response | Description |
|---|---|---|---|
| `/aos/store/manifest/1.0.0` | `ManifestRequest` | `ManifestResponse` | Fetch store object manifest (file tree + chunk refs + closure hints) |
| `/aos/store/chunk/1.0.0` | `ChunkRequest` | stream of `Chunk` | Batch fetch store object chunks |
| `/aos/job/create/1.0.0` | `JobCreateRequest` | stream of `JobCreateStatus` | Submit a job; full lifecycle until running (disconnect = cancel) |
| `/aos/job/start/1.0.0` | `JobStartRequest` | stream of `JobStartStatus` | Start a claimed job on the builder (disconnect = cancel) |
| `/aos/job/log/1.0.0` | `LogRequest` | `LogResponse` | Stream job container logs |
| `/aos/job/exec/1.0.0` | `JobExecRequest` | `ExecFrame` (bidirectional) | Execute a command inside a running container |
| `/aos/workflow/start/1.0.0` | `WorkflowStartRequest` | stream of `WorkflowStartStatus` | Submit a workflow to a bootstrap node (disconnect = cancel) |
| `/aos/workflow/info/1.0.0` | `WorkflowInfoRequest` | `WorkflowInfoResponse` | Fetch workflow spec and current state |
| `/aos/workflow/log/1.0.0` | `WorkflowLogRequest` | stream of `WorkflowTransition` | Fetch or tail workflow transition history |
| `/aos/workflow/list/1.0.0` | `WorkflowListRequest` | `WorkflowListResponse` | List known workflows (paginated) |

---

## Common Types

```protobuf
message StreamError {
    uint32 code = 1;              // 404=not found, 403=forbidden, 500=internal
    string message = 2;
}
```

---

## DHT Messages

```protobuf
// DHT key: aos:cluster:{cluster_id}:config
// See auth.md for certificate tree semantics.
message ClusterConfig {
    string cluster_id = 1;
    bytes root_public_key = 2;
    repeated IntermediateCert intermediates = 3;
    uint32 replication_factor = 4;    // min replicator copies per store object (default 3)
    uint64 min_hold_duration = 5;     // microseconds; min time publisher retains before GC (default 1hr)
}

message IntermediateCert {
    string cert_id = 1;
    bytes public_key = 2;
    string name = 3;                  // human label (e.g. "ops-admin")
    repeated string capabilities = 4; // delegatable capabilities
    uint64 not_before = 5;            // epoch microseconds
    uint64 not_after = 6;             // epoch microseconds
    bytes signature = 7;              // signed by root or parent intermediate
    string parent_cert_id = 8;        // "" for root-signed
}

// DHT key: aos:auth:token:{token_hash}:revoke
// See auth.md for revocation semantics.
message RevocationRecord {
    bytes token_hash = 1;
    uint64 revoked_at = 2;           // epoch microseconds
    string issuer = 3;               // PeerId of the token issuer
    bytes signature = 4;             // issuer signs (token_hash, revoked_at)
}

// GossipSub topic: aos/auth/token/revoke (global, not cluster-scoped)
message RevocationNotice {
    bytes token_hash = 1;
    string cluster_id = 2;
}

// GossipSub topic: aos/auth/token/issue (global, not cluster-scoped)
// Optional notification when a UCAN is issued. Enables proactive topic
// admission, audit logging, and revocation cache warming.
message IssuanceNotice {
    bytes token_hash = 1;
    string issuer = 2;               // PeerId of the issuing intermediate
    string subject = 3;              // PeerId of the recipient (aud)
    repeated string capabilities = 4; // capabilities granted
    uint64 not_after = 5;            // token expiry (epoch microseconds)
    string cluster_id = 6;
}

// DHT key: aos:cluster:{cluster_id}:job:{job_id}:state
// Refreshed periodically by the executing peer as a liveness signal.
message JobState {
    string job_id = 1;
    string peer_id = 2;
    uint64 refreshed_at = 3;         // epoch microseconds
    JobPhase phase = 4;
    ResourceUsage usage = 5;
}

enum JobPhase {
    JOB_PHASE_STARTING = 0;
    JOB_PHASE_RUNNING = 1;
    JOB_PHASE_STOPPING = 2;
}
```

---

## Job Messages

See [jobs.md](jobs.md) for lifecycle semantics,
[containers.md](containers.md) for container runtime behavior.

```protobuf
// GossipSub topic: aos/cluster/{id}/jobs/announce
// CRDT-merged job lifecycle record.
message JobPost {
    string cluster_id = 1;
    string job_id = 2;
    string ucan = 3;

    oneof delta {
        JobCreate create = 4;
        JobClaim claim = 5;
        JobStart start = 6;
        JobExit exit = 7;
        JobError error = 8;
        JobCancel cancel = 9;
    }

    optional string workflow_id = 10;    // if this job was submitted by a workflow
    optional string workflow_step_id = 11;
}

message JobCreate {
    string spec_hash = 1;            // store hash of the JobSpec store object
    string creator = 2;              // PeerId of the submitting peer
}

// Stored as a store object. job_id = store hash of this message.
// The store object may also contain a build.drv file for build jobs.
message JobSpec {
    uint64 nonce = 1;
    uint64 deadline = 2;              // absolute epoch microseconds
    ContainerSpec container = 3;
    NodeSelector node_selector = 4;
    ResourceLimits limits = 5;

}

// Container configuration. The mode oneof enforces that only hermetic
// containers can capture store output — mutable containers (with network,
// exec, etc.) cannot produce deterministic store objects.
message ContainerSpec {
    InitMode init = 1;
    ViewSpec view = 2;

    oneof mode {
        HermeticContainer hermetic = 3;  // sealed, deterministic, can capture output
        MutableContainer mutable = 4;    // capabilities granted, no output capture
    }
}

// Sealed container: no network, no exec, deterministic output.
// The only container type that can produce new store objects.
message HermeticContainer {
    OutputSpec output = 1;               // store output capture via OverlayFS
}

// Open container: capabilities granted via bitmask. Cannot capture store output.
message MutableContainer {
    uint32 capabilities = 1;             // bitmask of ContainerCapability flags
}

// Bit flags for mutable container capabilities.
// Combined via bitwise OR in MutableContainer.capabilities.
enum ContainerCapability {
    CONTAINER_CAP_NONE = 0;              // no capabilities (hermetic-like but no output capture)
    CONTAINER_CAP_NETWORK = 1;           // bit 0: host NAT network access
    CONTAINER_CAP_EXEC = 2;              // bit 1: allows /aos/job/exec/1.0.0
}

enum InitMode {
    INIT_DIRECT = 0;                     // run entrypoint as PID 1
    INIT_SYSTEMD = 1;                    // systemd as PID 1, activation script
    INIT_BUILD = 2;                      // minimal build-init, parse .drv, exec builder
}

// Defines the FUSE view: a read-only projection of store objects.
// The view is the transitive closure of the listed store hashes.
// See view.md for view semantics and fuse.md for the FUSE implementation.
message ViewSpec {
    repeated string store_hashes = 1;
}

// Capture build output from the OverlayFS upper layer as new store objects.
// Only valid inside HermeticContainer.
message OutputSpec {
    string drv_path = 1;                // path to .drv within the job store object
    repeated string outputs = 2;        // output names to capture ("out", "dev", "lib")
}

message NodeSelector {
    string system = 1;                // e.g. "x86_64-linux"
    repeated string features = 2;     // e.g. ["kvm", "big-parallel"]
    map<string, string> labels = 3;   // e.g. {"gpu": "a100"}
    repeated Toleration tolerations = 4;
}

message Toleration {
    string key = 1;
    string value = 2;                 // empty = match any value for this key
    TaintEffect effect = 3;
}

enum TaintEffect {
    NO_SCHEDULE = 0;
    PREFER_NO_SCHEDULE = 1;
    NO_EXECUTE = 2;
}

message ResourceLimits {
    uint64 memory_bytes = 1;          // 0 = unlimited
    uint32 cpu_cores = 2;            // 0 = unlimited
    uint64 disk_bytes = 3;           // 0 = unlimited
}

message JobClaim {
    string peer_id = 1;
    string start_ucan = 2;
}

// Stream protocol: /aos/job/create/1.0.0
// Full job lifecycle: ingest → publish → claim → start → running.
// Client disconnect at any point before terminal status = global cancellation.
// Only accepted by nodes advertising on aos:cluster:{cluster_id}:job.
message JobCreateRequest {
    string cluster_id = 1;
    Manifest manifest = 2;           // job spec store object manifest
    repeated Chunk chunks = 3;       // all chunks for the job store object (inline)
    string ucan = 4;                 // requester's authorization
}

message JobCreateStatus {
    oneof status {
        JobCreateProgress progress = 1;
        JobStart started = 2;        // container running (terminal, success)
        JobError failed = 3;         // could not start (terminal, failure)
    }
}

message JobCreateProgress {
    JobCreatePhase phase = 1;
    string message = 2;             // human-readable status
}

enum JobCreatePhase {
    JOB_CREATE_INGESTING = 0;        // ingesting job spec store object
    JOB_CREATE_PUBLISHING = 1;       // publishing to DHT + gossipsub
    JOB_CREATE_CLAIMING = 2;         // waiting for a peer to claim
    JOB_CREATE_STARTING = 3;         // claim received, calling /aos/job/start on builder
    JOB_CREATE_SYNCING = 4;          // builder syncing store objects
}

// Stream protocol: /aos/job/start/1.0.0
// Response is a stream: progress updates followed by a terminal started/failed.
// Client disconnect before terminal status = cancel job startup.
message JobStartRequest {
    string cluster_id = 1;
    string job_ucan = 2;
    string start_ucan = 3;
    optional ReservationToken reservation = 4;
    optional Manifest manifest = 5;   // root manifest hint (saves builder a round-trip)
}

message JobStartStatus {
    oneof status {
        StartProgress progress = 1;   // intermediate updates (non-terminal)
        JobStart started = 2;         // container running (terminal, success)
        JobError failed = 3;          // could not start (terminal, failure)
    }
}

message StartProgress {
    StartPhase phase = 1;
    uint32 manifests_total = 2;
    uint32 manifests_fetched = 3;
    uint64 chunks_bytes_total = 4;
    uint64 chunks_bytes_fetched = 5;
    string message = 6;              // human-readable status
}

enum StartPhase {
    START_PHASE_RESOLVING = 0;       // resolving closure from manifest references
    START_PHASE_FETCHING = 1;        // downloading manifests + chunks
    START_PHASE_CREATING_VIEW = 2;   // mounting FUSE view
    START_PHASE_STARTING = 3;        // spawning container
}

message JobStart {
    string peer_id = 1;
    string machine_id = 2;           // stable machine identifier (sd-id128)
    uint64 started_at = 3;           // epoch microseconds
    string job_identity = 4;         // PeerId from the job's ephemeral keypair
}

message ReservationToken {
    string builder_peer_id = 1;
    string creator_peer_id = 2;
    uint64 valid_until = 3;          // epoch microseconds (~30s from creation)
    bytes signature = 4;             // builder signs (creator_peer_id, valid_until)
}

message JobExit {
    int32 exit_code = 1;
    uint64 duration_ms = 2;
    repeated StoreOutput outputs = 3;
    optional ReservationToken reservation = 4;
}

message StoreOutput {
    string store_hash = 1;
    string name = 2;                 // e.g. "out", "dev", "lib"
    uint64 nar_size = 3;
}

message JobError {
    string message = 1;
    int32 exit_code = 2;
    string phase = 3;                // starting / running / unknown
    uint64 duration_ms = 4;
    ErrorSource source = 5;
}

enum ErrorSource {
    ERROR_SOURCE_CONTAINER = 0;
    ERROR_SOURCE_RUNTIME = 1;
    ERROR_SOURCE_LIVENESS = 2;
    ERROR_SOURCE_TIMEOUT = 3;
}

message JobCancel {
    string cancelled_by = 1;
    string reason = 2;
    uint64 cancelled_at = 3;         // epoch microseconds
}
```

### Exec

```protobuf
// Stream protocol: /aos/job/exec/1.0.0
// Execute a command inside a running job's container (like docker exec).
message JobExecRequest {
    string cluster_id = 1;
    string job_id = 2;
    repeated string command = 3;     // e.g. ["bash", "-l"]
    bool tty = 4;                    // allocate a PTY
    bool interactive = 5;            // forward stdin
    map<string, string> env = 6;
    string working_dir = 7;
    string user = 8;
}

// Bidirectional multiplexed frames on the exec stream.
message ExecFrame {
    oneof frame {
        bytes stdout = 1;            // daemon -> client
        bytes stderr = 2;            // daemon -> client
        bytes stdin = 3;             // client -> daemon
        WindowResize resize = 4;     // client -> daemon
        ExecExit exit = 5;           // daemon -> client (terminal)
        ExecSignal signal = 6;       // client -> daemon
    }
}

message WindowResize {
    uint32 rows = 1;
    uint32 cols = 2;
}

message ExecExit {
    int32 exit_code = 1;
    bool signaled = 2;
    int32 signal = 3;
}

message ExecSignal {
    int32 signal = 1;                // POSIX signal number
}
```

---

## Store Messages

See [store.md](store.md) for transfer flow,
[storage.md](storage.md) for chunking strategy.

```protobuf
// GossipSub topic: aos/store/publish (global, not cluster-scoped)
// Announces that a new store object is available. Published after the peer
// has written the provider record to the DHT via start_providing.
message StorePublish {
    string store_hash = 1;
    string name = 2;                 // human-readable name (e.g. package name)
    uint64 nar_size = 3;
    string peer_id = 4;              // publishing peer
    string ucan = 5;
}

// Stream protocol: /aos/store/manifest/1.0.0
message ManifestRequest {
    string store_hash = 1;
}

message ManifestResponse {
    oneof result {
        Manifest manifest = 1;
        StreamError error = 2;
    }
}

message Manifest {
    string store_hash = 1;
    string name = 2;
    bytes nar_hash = 3;              // SHA-256 of the NAR serialization
    uint64 nar_size = 4;
    repeated Entry entries = 5;      // depth-first file tree (chunks for this object only)
    repeated string references = 6;  // immediate store hash deps (authoritative, from reference scanning)
    repeated ClosureHint closure = 7; // transitive deps beyond immediate (best-effort)
}

// Transitive dependency hint included in manifest responses.
// The serving peer walks its local closure DB and includes known deps.
// Like DNS additional records: opportunistic, may be incomplete.
message ClosureHint {
    string store_hash = 1;
    repeated string references = 2;   // that dep's immediate refs (empty = peer lacks this object locally)
}

message Entry {
    string path = 1;                 // relative path within the store object
    oneof kind {
        DirEntry dir = 2;
        FileEntry file = 3;
        SymlinkEntry symlink = 4;
    }
}

message DirEntry   { uint32 mode = 1; }
message FileEntry  { uint64 size = 1; bool executable = 2; repeated ChunkRef chunks = 3; }
message SymlinkEntry { string target = 1; }

message ChunkRef {
    bytes hash = 2;                  // xxh3-128 (16 bytes); field 1 reserved
    uint32 size = 3;
}

// Stream protocol: /aos/store/chunk/1.0.0
message ChunkRequest {
    repeated bytes hashes = 1;       // xxh3-128 hashes to fetch
}

message Chunk {
    bytes hash = 1;
    bytes chunk = 2;                 // empty = hash not found
}
```

### Replication Messages

```protobuf
// GossipSub topic: aos/store/replicate (global, not cluster-scoped)
// Coordination between replicators: advertisements, claims, success/nack.
message ReplicateMessage {
    oneof message {
        ReplicateAdvertise advertise = 1;
        ReplicateRescind rescind = 2;
        ReplicateClaim claim = 3;
        ReplicateLeaseRenew renew = 4;
        ReplicateLeaseCancel cancel = 5;
        ReplicateSuccess success = 6;
        ReplicateNack nack = 7;
        ReplicateRebalance rebalance = 8;
    }
}

message ReplicateAdvertise {
    string peer_id = 1;
    uint64 reserved_bytes = 2;       // total replication pool size
    uint64 used_bytes = 3;           // used by unpinned replicated objects
    uint64 free_bytes = 4;           // available for new replications
    uint64 ttl = 5;                  // advertisement validity (microseconds)
}

message ReplicateRescind {
    string peer_id = 1;
}

message ReplicateClaim {
    string store_hash = 1;
    string peer_id = 2;
    uint64 lease_duration = 3;       // microseconds; scaled by nar_size
}

message ReplicateLeaseRenew {
    string store_hash = 1;
    string peer_id = 2;
    uint64 lease_duration = 3;
}

message ReplicateLeaseCancel {
    string store_hash = 1;
    string peer_id = 2;
}

message ReplicateSuccess {
    string store_hash = 1;
    string peer_id = 2;
}

message ReplicateNack {
    string store_hash = 1;
    string peer_id = 2;
    NackReason reason = 3;
}

enum NackReason {
    NACK_POOL_FULL = 0;
    NACK_NETWORK_ERROR = 1;
    NACK_TIMEOUT = 2;
    NACK_OBJECT_TOO_LARGE = 3;
}

message ReplicateRebalance {
    string store_hash = 1;
    string peer_id = 2;             // replicator that detected the shortfall
    uint32 current_providers = 3;   // observed provider count
}

// GossipSub topic: aos/store/purge (global, not cluster-scoped)
// Best-effort request to remove a store object from peers.
message StorePurge {
    string store_hash = 1;
    string peer_id = 2;             // requester
    string reason = 3;
    string ucan = 4;                // /aos/store/purge authorization
}
```

---

## Log Messages

See [jobs.md](jobs.md) for log streaming behavior.

```protobuf
// Stream protocol: /aos/job/log/1.0.0
message LogRequest {
    string cluster_id = 1;
    string job_id = 2;
    optional string after_cursor = 3;
}

message LogResponse {
    oneof result {
        LogEvent event = 1;
        StreamError error = 2;
    }
}

message LogEvent {
    string cursor = 1;
    uint64 realtime_usec = 2;
    uint64 monotonic_usec = 3;
    Priority priority = 4;
    string unit = 5;
    string syslog = 6;
    uint32 pid = 7;
    string cgroup = 8;
    bytes line = 9;
    map<string, bytes> fields = 10;
}

enum Priority {
    EMERGENCY = 0;
    ALERT = 1;
    CRITICAL = 2;
    ERROR = 3;
    WARNING = 4;
    NOTICE = 5;
    INFO = 6;
    DEBUG = 7;
}
```

---

## Load Messages

See [load-reports.md](load-reports.md) for submission rate, EWMA smoothing,
and delta encoding semantics.

```protobuf
// GossipSub topic: aos/cluster/{id}/load/announce
message LoadReport {
    string peer_id = 1;
    uint64 timestamp = 2;
    uint64 sequence = 3;

    oneof report {
        LoadFull full = 4;
        LoadDelta delta = 5;
    }

    bytes signature = 6;
}

message LoadFull {
    string system = 1;
    repeated string features = 2;
    ResourceCapacity capacity = 3;
    ResourceState cpu = 4;
    ResourceState memory = 5;
    ResourceState disk = 6;
    uint32 jobs_running = 7;
    uint32 jobs_claimed = 8;
    SmoothedTrend cpu_trend = 9;
    SmoothedTrend memory_trend = 10;
}

message LoadDelta {
    optional ResourceState cpu = 1;
    optional ResourceState memory = 2;
    optional ResourceState disk = 3;
    optional uint32 jobs_running = 4;
    optional uint32 jobs_claimed = 5;
    optional SmoothedTrend cpu_trend = 6;
    optional SmoothedTrend memory_trend = 7;
}

message ResourceCapacity {
    uint64 total = 1;                // bytes or millicores
    uint64 reserved = 2;            // host overhead, non-allocatable
}

message ResourceState {
    uint64 active = 1;
    uint64 claimed = 2;
    uint64 free = 3;
}

message SmoothedTrend {
    double ewma = 1;
    double slope = 2;                // rate of change (for extrapolation)
}
```

---

## Workflow Messages

See [workflow.md](workflow.md) for execution model and transition ordering.

```protobuf
// GossipSub topic: aos/workflows/announce (global)
message WorkflowPost {
    string workflow_id = 1;          // = store hash of the WorkflowSpec object
    string ucan = 2;

    oneof delta {
        WorkflowCreate create = 3;
        WorkflowCancel cancel = 4;
    }
}

message WorkflowCreate {
    string spec_hash = 1;            // store hash of the WorkflowSpec store object
    string creator = 2;              // PeerId of submitting client
}

// Stored as a store object. workflow_id = store hash of this message.
message WorkflowSpec {
    uint64 nonce = 1;
    uint64 deadline = 3;             // epoch μs; workflow must complete by this time
    uint64 expiration = 4;           // epoch μs; workflow state deleted after this time
    repeated WorkflowStep steps = 7;
}

message WorkflowStep {
    string id = 1;                   // unique name within the workflow (e.g., "build-gcc")
    StepAction action = 2;
    repeated string deps = 3;        // step IDs that must complete before this step is ready
    optional uint64 timeout = 4;     // per-step timeout in microseconds (from claim time)
}

message StepAction {
    oneof action {
        EnsureStoreObject ensure = 1;
        AwaitWorkflow await_workflow = 2;
        StepDecision decision = 3;
    }
}

// Ensure a store object exists, producing it from a source if needed.
// If output_hash already has providers, the step completes immediately.
// Otherwise, the source determines how to produce it.
message EnsureStoreObject {
    string output_hash = 1;          // expected output store hash

    oneof source {
        string drv_hash = 2;        // build from a derivation (.drv path within workflow object)
        FetchSource fetch = 3;      // download from URLs (for FODs)
    }
}

// Download a fixed-output object from upstream mirrors.
// The executor tries each URL in order until one succeeds, then verifies
// the content against the expected hash.
message FetchSource {
    repeated string urls = 1;        // mirror URLs to try (in priority order)
    string hash = 2;                 // expected content hash (SRI format, e.g. "sha256-...")
}

message AwaitWorkflow {
    string workflow_id = 1;
    optional string step_id = 2;     // wait for specific step, or omit for workflow completion
}

message StepDecision {
    oneof condition {
        string store_object_exists = 1;  // store hash to check
    }
}

message WorkflowCancel {
    string reason = 1;
    uint64 cancelled_at = 2;         // epoch μs
}

// GossipSub topic: aos/workflows/active/{workflow_id}/state
// Envelope for all messages on the per-workflow state topic.
message WorkflowStateMessage {
    oneof message {
        WorkflowTransition transition = 1;
        WorkflowStateSnapshot snapshot = 2;
    }
}

message WorkflowTransition {
    string workflow_id = 1;
    uint64 sequence = 2;             // per-executor local counter (dedup only, not ordering)
    string step_id = 3;
    StepTransition transition = 4;
    string executor = 5;             // PeerId
    uint64 timestamp = 6;            // epoch μs (canonical ordering key with executor)
    repeated bytes causal_deps = 7;  // hashes of transitions this one depends on
    optional StepResult result = 8;
    bytes hash = 9;                  // hash(workflow_id, step_id, transition, executor, timestamp, causal_deps)
}

// Periodic full state snapshot published to the state topic.
// Each peer publishes at offset hash(peer_id ⊕ workflow_id) % sync_window.
// First publisher per window wins; others skip.
message WorkflowStateSnapshot {
    string workflow_id = 1;
    string publisher = 2;            // PeerId
    uint64 timestamp = 3;            // epoch μs
    WorkflowStatus status = 4;
    map<string, StepState> step_states = 5;
    uint64 transition_count = 6;     // total transitions applied
    bytes state_hash = 7;            // hash of the serialized state (for consistency check)
}

enum StepTransition {
    STEP_READY = 0;
    STEP_CLAIMED = 1;
    STEP_RUNNING = 2;
    STEP_COMPLETED = 3;
    STEP_FAILED = 4;
    STEP_SKIPPED = 5;
}

message StepResult {
    repeated string output_hashes = 1;  // store hashes produced (for submit_job steps)
    optional string error = 2;          // error message (for failed steps)
    optional string job_id = 3;         // associated job ID (for submit_job steps)
}

// Stream protocol: /aos/workflow/info/1.0.0
message WorkflowInfoRequest {
    string workflow_id = 1;
}

message WorkflowInfoResponse {
    oneof result {
        WorkflowInfo info = 1;
        StreamError error = 2;
    }
}

message WorkflowInfo {
    string spec_hash = 1;           // store hash of the WorkflowSpec
    WorkflowStatus status = 2;
    map<string, StepState> step_states = 3;
    string creator = 4;
}

enum WorkflowStatus {
    WORKFLOW_PENDING = 0;
    WORKFLOW_RUNNING = 1;
    WORKFLOW_COMPLETED = 2;
    WORKFLOW_FAILED = 3;
    WORKFLOW_CANCELLED = 4;
    WORKFLOW_EXPIRED = 5;
}

message StepState {
    StepTransition status = 1;
    optional string executor = 2;
    optional uint64 claimed_at = 3;
    optional StepResult result = 4;
}

// Stream protocol: /aos/workflow/log/1.0.0
message WorkflowLogRequest {
    string workflow_id = 1;
    optional uint64 after_sequence = 2;  // resume from this sequence number
    bool follow = 3;                     // keep connection open and stream new transitions
}

// Response is a stream of WorkflowTransition messages.

// Stream protocol: /aos/workflow/list/1.0.0
message WorkflowListRequest {
    optional WorkflowStatus status_filter = 1;
    optional string creator_filter = 2;       // filter by creator PeerId
    uint32 page_size = 3;                     // max results per page
    optional string page_token = 4;           // pagination cursor
}

message WorkflowListResponse {
    repeated WorkflowListEntry workflows = 1;
    optional string next_page_token = 2;
}

message WorkflowListEntry {
    string workflow_id = 1;
    string creator = 2;
    WorkflowStatus status = 3;
    uint64 deadline = 4;
    uint32 steps_total = 5;
    uint32 steps_completed = 6;
}

// Stream protocol: /aos/workflow/start/1.0.0
// Submit a workflow to a bootstrap node for execution.
// Client disconnect before terminal status = cancel workflow globally.
// Only accepted by nodes with workflow.accept_remote_starts = true.
message WorkflowStartRequest {
    string cluster_id = 1;
    Manifest manifest = 2;          // workflow store object manifest
    repeated Chunk chunks = 3;      // all chunks for the workflow store object (inline)
    string ucan = 4;                // requester's authorization
}

message WorkflowStartStatus {
    oneof status {
        WorkflowStartProgress progress = 1;
        WorkflowStarted started = 2;    // workflow announced and tracking (terminal, success)
        StreamError failed = 3;          // 409=duplicate, 403=forbidden, 413=too large, 503=not accepting
    }
}

message WorkflowStartProgress {
    WorkflowStartPhase phase = 1;
    string message = 2;             // human-readable status
}

enum WorkflowStartPhase {
    WORKFLOW_START_INGESTING = 0;    // ingesting workflow store object
    WORKFLOW_START_PUBLISHING = 1;   // publishing to DHT + store/publish
    WORKFLOW_START_ANNOUNCING = 2;   // announcing on workflows/announce
}

message WorkflowStarted {
    string workflow_id = 1;          // = store hash of the workflow spec object
    string bootstrap_peer = 2;      // PeerId of the bootstrap node
}
```
