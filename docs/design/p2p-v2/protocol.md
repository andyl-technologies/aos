# AOS P2P v2 Wire Protocol

## 1. DHT Records

Four key types stored in the Kademlia DHT.

| Key Pattern | Value | TTL | Signature |
|---|---|---|---|
| `aos:profile:{peer_id}` | `ProfileSpec` | Short (heartbeat) | Peer key |
| `aos:job:{job_id}` | `JobPost` (CRDT) | Long (job lifetime) | UCAN chain |
| `aos:store:{store_hash}` | `Manifest` | Long | Content-addressed (hash-verified) |
| `aos:cluster:{cluster_id}` | `ClusterConfig` | Long | Cluster identity key |

### Value Formats

**Peer record** — advertises the node's current profile and activation type:

```protobuf
message ProfileSpec {
	string store_hash = 1;
	ActivationType activation = 2;
}

enum ActivationType {
	NONE = 0;
	ACTIVATION_TYPE_SYSTEMD_V1 = 1;
}
```

**Job record** — CRDT-merged job lifecycle state:

```protobuf
message JobPost { // CRDT
	string cluster_id = 1;
	string job_id = 2;
	string ucan = 3;

	oneof delta {
		JobSpec create = 4;
		JobClaim claim = 5;
		JobStart start = 6;
		JobExit exit = 7;
		JobError error = 8;
		JobCancel cancel = 9;
	}
}
```

**Cluster record** — global cluster configuration:

```protobuf
message ClusterConfig {
	string cluster_id = 1;
	bytes cluster_public_key = 2;
}
```

---

## 2. GossipSub Topics

Three publish/subscribe topics for real-time announcements.

### `/aos/job/announce`

Job lifecycle deltas broadcast to cluster members.

- **Message format:** `JobPost`
- **Authorization:** `/aos/job/announce WHERE .cluster == {cluster_ident} AND .operation HAS {post_op}`

### `/aos/load/announce`

Periodic load reports for decentralized scheduling.

- **Message format:** `LoadReport`
- **Authorization:** `/aos/load/announce WHERE .cluster == {cluster_ident}`

### `/aos/control/announce`

Decentralized controller signals (replaces k8s node/replication/deployment controllers).

- **Message format:** `ControlSignal`
- **Authorization:** `/aos/control/announce WHERE .cluster == {cluster_ident} AND .operation HAS {control_op}`

---

## 3. Stream Protocols

Four libp2p stream protocols for request/response interactions.

### `/aos/store/manifest`

Fetch the content manifest for a store path.

- **Request:** `ManifestRequest`
- **Response:** `ManifestResponse` (oneof: `Manifest` or `StreamError`)
- **Authorization:** `/aos/store/read`

### `/aos/store/chunks`

Fetch content chunks by hash.

- **Request:** `ChunkRequest`
- **Response:** stream of `Chunk` (a chunk with empty `chunk` bytes indicates hash not found, or a `StreamError` for batch-level failures)
- **Authorization:** `/aos/store/read`

### `/aos/job/exec`

Request job execution on a claiming peer.

- **Request:** `ExecRequest`
- **Response:** `ExecResult`
- **Authorization:** `/aos/job/exec WHERE .job == {job_ident}`

### `/aos/job/logs`

Stream log events from a running job.

- **Request:** `LogRequest`
- **Response:** `LogResponse` (oneof: stream of `LogEvent` or `StreamError` for unknown job_id)
- **Authorization:** `/aos/job/read WHERE .cluster == {cluster_ident} OR .job == {job_ident}`

---

## 4. Protobuf Definitions

### 4.1 DHT Messages

```protobuf
message ProfileSpec {
	string store_hash = 1;
	ActivationType activation = 2;
}

enum ActivationType {
	NONE = 0;
	ACTIVATION_TYPE_SYSTEMD_V1 = 1;
}

message ClusterConfig {
	string cluster_id = 1;
	bytes cluster_public_key = 2;
}
```

### 4.2 Job Messages

```protobuf
message JobPost { // CRDT
	string cluster_id = 1;
	string job_id = 2;
	string ucan = 3;

	oneof delta {
		JobSpec create = 4;
		JobClaim claim = 5;
		JobStart start = 6;
		JobExit exit = 7;
		JobError error = 8;
		JobCancel cancel = 9;
	}
}

message JobSpec {
	uint64 nonce = 1;
	uint64 deadline = 2;             // Absolute epoch timestamp (microseconds). Job must complete by this time.

	// See containers.md for the runtime behavior of each container type.
	message ContainerSpec {
		message BuilderSpec {
			string derivation = 1;
		}
		message ProfileContainer {
			string profile = 1;
		}
		oneof container_type {
			BuilderSpec builder = 1;
			ProfileContainer profile = 2;
		}
	}

	ContainerSpec container = 3;

	// Scheduling constraints
	NodeSelector node_selector = 4;
	ResourceLimits limits = 5;
	NetworkMode network = 6;
}

message NodeSelector {
	string system = 1;                   // required system (e.g., "x86_64-linux")
	repeated string features = 2;        // required features (e.g., ["kvm", "big-parallel"])
	map<string, string> labels = 3;      // required peer labels (e.g., {"gpu": "a100"})
}

message ResourceLimits {
	uint64 memory_bytes = 1;             // max memory (0 = unlimited)
	uint32 cpu_cores = 2;               // max CPU cores (0 = unlimited)
	uint64 disk_bytes = 3;              // max scratch disk (0 = unlimited)
}

enum NetworkMode {
	NETWORK_NONE = 0;                    // no network access (required for build jobs)
	NETWORK_HOST = 1;                    // host NAT (for profile/service containers)
}

message JobClaim {
	string peer_id = 1;
	string exec_ucan = 2;
}

message ExecRequest {
	string job_ucan = 1;
	string exec_ucan = 2;
}

message ExecResult {
	oneof result {
		JobStart started = 1;
		JobError failed = 2;
	}
}

message JobStart {
	string peer_id = 1;       // PeerId of the executing peer.
	string machine_id = 2;    // Stable machine identifier (sd-id128).
	uint64 started_at = 3;    // Microseconds since epoch.
	string job_identity = 4;  // PeerId from the job's ephemeral keypair.
}

message JobExit {
	int32 exit_code = 1;               // Process exit code (0 = success).
	uint64 duration_ms = 2;            // Wall-clock ms from start to exit.
	repeated StoreOutput outputs = 3;  // Store objects produced (build jobs).
}

message StoreOutput {
	string store_hash = 1;   // Content address of the output.
	string name = 2;         // Output name (e.g. "out", "dev", "lib").
	uint64 nar_size = 3;     // NAR-serialized size in bytes.
}

message JobError {
	string message = 1;           // Human-readable error description.
	int32 exit_code = 2;          // Process exit code, if available.
	string phase = 3;             // Phase where error occurred (starting/running/unknown).
	uint64 duration_ms = 4;       // Wall-clock ms from start to failure.
	ErrorSource source = 5;       // What produced the error.
}

enum ErrorSource {
	ERROR_SOURCE_CONTAINER = 0;   // Container process failed.
	ERROR_SOURCE_RUNTIME = 1;     // Container runtime failed.
	ERROR_SOURCE_LIVENESS = 2;    // DHT liveness record expired.
	ERROR_SOURCE_TIMEOUT = 3;     // Job exceeded deadline.
}

message JobCancel {
	string cancelled_by = 1;   // PeerId requesting cancellation.
	string reason = 2;         // Human-readable reason.
	uint64 cancelled_at = 3;   // Microseconds since epoch.
}

message JobState {
	string job_id = 1;          // Job identifier.
	string peer_id = 2;        // PeerId of the executing peer.
	uint64 refreshed_at = 3;   // Microseconds since epoch of last refresh.
	JobPhase phase = 4;        // Current lifecycle phase.
	ResourceUsage usage = 5;   // Current resource consumption.
}

enum JobPhase {
	JOB_PHASE_STARTING = 0;
	JOB_PHASE_RUNNING = 1;
	JOB_PHASE_STOPPING = 2;
}
```

### 4.3 Common Messages

```protobuf
message StreamError {
	uint32 code = 1;       // error code (similar to HTTP: 404=not found, 403=forbidden, 500=internal)
	string message = 2;    // human-readable error description
}
```

### 4.4 Store Messages

```protobuf
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
	bytes nar_hash = 3;
	uint64 nar_size = 4;
	repeated Entry entries = 5;
}

message Entry {
	string path = 1;
	oneof kind {
		DirEntry dir = 2;
		FileEntry file = 3;
		SymlinkEntry symlink = 4;
	}
}

message DirEntry { uint32 mode = 1; }

message FileEntry {
	uint64 size = 1;
	bool executable = 2;
	repeated ChunkRef chunks = 3;
}

message SymlinkEntry { string target = 1; }

message ChunkRef {
	bytes hash = 2;
	uint32 size = 3;
}

message ChunkRequest {
	repeated bytes hashes = 1;
}

message Chunk {
	bytes hash = 1;
	bytes chunk = 2;
}
```

### 4.5 Log Messages

```protobuf
message LogResponse {
	oneof result {
		LogEvent event = 1;
		StreamError error = 2;
	}
}

message LogRequest {
	string cluster_id = 1;
	string job_id = 2;
	optional string after_cursor = 3;
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

### 4.6 Control Messages

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

message ControlSignal { // CRDT
	string cluster_id = 1;
	string signal_id = 2;          // ULID — globally unique, lexicographically sortable
	uint64 timestamp = 3;          // microseconds since epoch (LWW ordering)
	string author = 4;             // PeerId of the admin who issued this

	oneof signal {
		ReplicaSet replica_set = 10;
		ReplicaSetDelete replica_set_delete = 11;
	}

	string ucan = 5;
}

// Desired state: "keep N instances of this job spec running"
message ReplicaSet {
	string name = 1;                     // unique service name (e.g., "ci-runner", "dev-shell")
	JobSpec template = 2;                // job template for each replica
	uint32 replicas = 3;                // desired instance count (0 = stopped)
	NodeSelector selector = 4;          // which peers can run replicas
	UpdateStrategy update_strategy = 5; // how to roll out changes
}

message ReplicaSetDelete {
	string name = 1;                     // removes the replica set from desired state
}

message UpdateStrategy {
	oneof strategy {
		RollingUpdate rolling = 1;
		Recreate recreate = 2;
	}
}

message RollingUpdate {
	uint32 max_surge = 1;          // max extra instances during update
	uint32 max_unavailable = 2;    // max instances that can be down during update
}

message Recreate {}                  // kill all old, then start all new
```
