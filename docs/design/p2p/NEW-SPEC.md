# DHT

| Key Format | Value Format | TTL | Signature Validation |
| :---- | :---- | :---- | :---- |
| aos:store:{object\_id} | ProviderRecord | GC LRU Eviction Function | None |
| aos:profile:{peer\_ident} | ProfileSpec | Long-lived | PeerIdentity |
| aos:job:{job\_ident} | JobState | Job Liveness Check (Short-lived) | JobIdentity |
| aos:cluster:{cluster\_ident} | ClusterConfig | Long-lived | ClusterIdentity |

# 

# GossipSub

| Topic Format | Message Format | Authorization |
| :---- | :---- | :---- |
| aos/cluster/{cluster\_ident}/jobs/announce | JobPost (CRDT) | /aos/job/announce WHERE .cluster \== {cluster\_ident}AND .operation HAS {post\_op} |
| aos/cluster/{cluster\_ident}/load/announce | LoadReport | /aos/load/announceWHERE .cluster \== {cluster\_ident} |
| aos/cluster/{cluster\_ident}/control/announce | ControlSignal (CRDT) | /aos/control/announceWHERE .cluster \== {cluster\_ident}AND .operation HAS {control\_op} |

# 

# Stream Protocols

| Protocol ID | Request Format | Response Format | Authorization |
| :---- | :---- | :---- | :---- |
| /aos/store/manifest/1.0.0 | ManifestRequest | Manifest | /aos/store/read |
| /aos/store/chunk/1.0.0 | ChunkRequest | Chunk (stream) | None |
| /aos/job/exec/1.0.0 | ExecRequest | ExecResult | /aos/job/execWHERE .job \== {job\_ident} |
| /aos/job/log/1.0.0 | LogRequest | LogEvent (stream) | /aos/job/readWHERE .cluster \== {cluster\_ident}OR .job \== {job\_ident} |

# Protocol Messages

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

```protobuf
message JobState {
	// TODO: Active job state used for liveness/health checks.
}
```

```protobuf
message ClusterConfig {
	// TODO: Global timeouts, other cluster config.
	//
	// The cluster is created with a per-cluster long-lived identity, used to
// bootstrap the cluster and root administer the cluster, which can create
// UCAN authorizations similar to k8s auth tokens.
}
```

```protobuf
message JobPost { // CRDT
	string cluster_id = 1;	// Cluster identity.
	string job_id = 2;		// Job identity (via job-specific peerid).

	oneof delta {
		JobSpec create = 1;
		JobClaim claim = 2;

		// Note: Job creator must call /aos/job/exec/1.0.0 to start the
		//       job on the selected peer which submitted the first claim.

		JobStart start = 3;
		JobExit exit = 4;
		JobError error = 5;
		JobCancel cancel = 6;
	}

	string ucan = 3;
}

message JobSpec {
uint64 nonce = 1;
	string profile_id = 2;
uint64 deadline = 3;

// TODO: Borrow from k8s PodSpec.
//
// We want: affinity, anti-affinity, runtime constraints (limits),
// tolerations, node selector.
//
// Volumes are limited to local volumes.
//
// There should be a special volume to accept writable nix store mount overlays
// for creating new store objects (network MUST be disabled, and a similar
// isolation is required in the JobSpec to nix sandboxes)
//
// Only a single container (based on the profile) is created.
//
// Network is either none or host nat for now.
}

message JobClaim {
	string peer_id = 1;
	string exec_ucan = 2;	// Exec authorization for job identity holder.
}

message ExecRequest {
	string job_ucan = 1;	// Delegation of job identity to peer via ucan.
	// Note: the job will inherit the job identity via systemd secrets
// so it can participate in libp2p itself.
	string exec_ucan = 2;	// Exec authorization from JobClaim.
}

message ExecResult {
	oneof result {
		JobStart started = 1;
		JobError failed = 2;
	}
}

message JobStart {
	// TODO
}

message JobExit {
	// TODO
}

message JobError {
	// TODO
}

message JobCancel {
	// TODO
}
```

```protobuf
message LoadReport {
// TODO: Report periodically load between all nodes to influence
// 	  decentralized scheduling decisions.
}
```

```protobuf
message ControlSignal { // CRDT
// TODO: This is a decentralized CRDT to replace the k8s
//       node/replication/deployment controllers.
}
```

```protobuf
message ManifestRequest {
	string store_hash = 1;
}

message Manifest {
string store_hash = 1;           // e.g., "abc123"
string name = 2;                 // e.g., "llvm-18.0"
bytes nar_hash = 3;              // SHA-256 of the NAR serialization (32 bytes)
uint64 nar_size = 4;             // uncompressed NAR size
repeated Entry entries = 5;      // file tree (depth-first order)
}

message Entry {
string path = 1;                 // relative path: "bin/clang", "lib/libLLVM.so"

oneof kind {
DirEntry dir = 2;
FileEntry file = 3;
SymlinkEntry symlink = 4;
	}
}

message DirEntry {
uint32 mode = 1;                 // permission bits (e.g., 0755)
}

message FileEntry {
uint64 size = 1;                 // total file size in bytes
bool executable = 2;             // executable bit
repeated ChunkRef chunks = 3;    // ordered chunk list — concatenate to reconstruct
}

message SymlinkEntry {
string target = 1;               // symlink target path
}

message ChunkRef {
bytes hash = 2;                  // xxh3-128 (16 bytes)
uint32 size = 3;                 // chunk size in bytes
}
```

```protobuf
message ChunkRequest {
	repeated bytes hashes = 1;		// xxh3-128 (16 bytes)
}

message Chunk {
	bytes hash = 1;			// xxh3-128 (16 bytes)
	bytes chunk = 2;
}
```

```protobuf
message LogRequest {
	string cluster_id = 1;			// Cluster identity
	string job_id = 2;				// Job identity
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
EMERGENCY = 0;   // system is unusable
ALERT = 1;       // action must be taken immediately
CRITICAL = 2;    // critical conditions
ERROR = 3;       // error conditions
WARNING = 4;     // warning conditions
NOTICE = 5;      // normal but significant
INFO = 6;        // informational
DEBUG = 7;       // debug-level messages
}
```

