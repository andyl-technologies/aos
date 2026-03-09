# Daemon

The AOS distributed build system has one binary: `aos daemon`. Every node runs
the same code, joins the same libp2p mesh, and manages a local Nix store.
Configuration determines what each node does -- execute builds, accept local
control commands, both, or neither. There is no separate "gateway" process.

## Role

Every daemon:

- Generates or loads a persistent ed25519 peer identity
- Joins the libp2p mesh via mDNS and seed peers
- Participates in the Kademlia DHT (stores and retrieves records)
- Subscribes to GossipSub topics (`builds/wanted`, `builds/claimed`,
  `builds/result`, per-build log topics)
- Serves the `/aos/nar-fetch/1.0.0` and `/aos/log-replay/1.0.0` stream
  protocols to peers
- Manages the local Nix store (GC, store path queries)
- Advertises capabilities and store bloom filter via DHT

What varies by configuration:

- **Control socket** (`[control]`): accepts local commands over a Unix socket,
  authenticates callers via `SO_PEERCRED`, maps Unix groups to capabilities
- **Build subsystem** (`[build]`): claims jobs, executes `nix-store --realise`,
  signs outputs, streams logs

## Configuration

All behavior emerges from a single TOML configuration file:

```toml
[p2p]
listen_addr = "/ip4/0.0.0.0/udp/4001/quic-v1"
seed_peers = [
    "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/QmPeerId1",
]

# Unix socket control interface (optional -- enables local user interaction)
[control]
socket = "/run/aos/control.sock"
socket_group = "aos"

[control.groups]
aos-admin = ["submit", "observe", "manage", "fetch"]
aos-build = ["submit", "observe"]
aos-read  = ["observe"]

# Mesh authorization
[auth]
mode = "ucan"                    # or "open" for dev/testing
root_pubkey_file = "/etc/aos/root.pub"
token_file = "/etc/aos/daemon.ucan"

# Build execution (optional -- enables build claiming)
[build]
max_jobs = 8
arch = "x86_64-linux"
features = ["kvm"]
max_build_duration = "4h"

[store]
gc_interval = "1h"
max_store_size = "100G"

[signing]
secret_key_file = "/etc/aos/signing-key"
```

Roles emerge from which sections are present:

| `[control]` | `[build]` | Effective role |
|--------------|-----------|----------------|
| yes          | yes       | Full daemon. Accepts local commands via Unix socket, executes builds, participates in mesh. |
| no           | yes       | Build-only daemon. Claims and executes builds, streams logs, serves NARs to peers. No local control interface. |
| no           | no        | Cache peer. Stores and serves paths via libp2p but does not build or accept local commands. |

## Authentication

The daemon has two authentication surfaces corresponding to its two interfaces:
local users on the Unix socket, and peers on the libp2p mesh.

### Local Auth (Unix Socket + SO_PEERCRED)

When a client connects to the control socket, the daemon calls `getsockopt`
with `SO_PEERCRED` to obtain the caller's UID, GID, and PID. It then resolves
the UID's group memberships and maps them to capabilities using the
`[control.groups]` table.

Capabilities:

| Capability | Description |
|------------|-------------|
| `submit`   | Submit build requests and upload store paths |
| `observe`  | Watch build logs, query build status, list peers |
| `manage`   | Trigger GC, modify daemon configuration at runtime |
| `fetch`    | Fetch store paths from the mesh on behalf of a local user |

A caller receives the union of capabilities from all matching groups. If no
group matches, the connection is rejected.

### Mesh Auth (UCAN)

Peer-to-peer authorization uses UCANs (User Controlled Authorization Networks).
Each daemon holds a UCAN token (`[auth].token_file`) signed by the root key
(`[auth].root_pubkey_file`). The UCAN encodes:

- The daemon's peer identity (audience)
- Granted capabilities (e.g., `build/*`, `nar/fetch`, `log/replay`)
- Expiry and optional caveats (e.g., architecture restrictions)

When a peer opens a stream protocol, it presents its UCAN in the handshake. The
receiving daemon validates the chain of trust back to the root public key. In
`mode = "open"`, UCAN validation is skipped entirely -- suitable for
development and testing but not production.

Delegation: a daemon with sufficient authority can mint child UCANs for new
peers using the `delegate` control command. The child UCAN is attenuated (equal
or fewer capabilities, equal or shorter lifetime).

## Unix Socket Control

The control socket provides a JSON-line protocol for local users. Each request
is a single JSON object terminated by a newline; each response is likewise a
single JSON line.

Socket path is configurable (default `/run/aos/control.sock`). The daemon
creates the socket with the group specified by `socket_group` and mode `0770`,
so only members of that group can connect.

### Commands

**build** -- Submit a build request to the mesh.

```json
{"cmd": "build", "drv_path": "/nix/store/abc123-foo.drv"}
```

Response: a stream of JSON lines (one per log event), terminated by a line
with `"kind": "complete"` or `"kind": "error"`.

```json
{"seq": 0, "kind": "status", "line": "claimed by QmPeerId2"}
{"seq": 1, "kind": "log", "line": "building phase: unpack"}
{"seq": 2, "kind": "log", "line": "building phase: configure"}
{"seq": 42, "kind": "complete", "outputs": ["/nix/store/xyz-foo"]}
```

Requires: `submit` capability.

**watch** -- Attach to logs for an in-progress build.

```json
{"cmd": "watch", "drv_hash": "abc123", "from_seq": 0}
```

Response: same streaming format as `build`. If the build is already complete,
returns the final result immediately. If still in progress, replays buffered
history then live-tails.

Requires: `observe` capability.

**status** -- Query status of a build or the daemon itself.

```json
{"cmd": "status", "drv_hash": "abc123"}
```

```json
{"cmd": "status"}
```

The first form returns the build's current state from the DHT. The second
returns daemon-level information: active builds, store size, peer count, uptime.

Requires: `observe` capability.

**gc** -- Trigger garbage collection of the local Nix store.

```json
{"cmd": "gc"}
```

Requires: `manage` capability.

**peers** -- List connected mesh peers and their capabilities.

```json
{"cmd": "peers"}
```

Requires: `observe` capability.

**delegate** -- Mint a child UCAN for a new peer.

```json
{"cmd": "delegate", "peer_id": "QmNewPeer", "capabilities": ["build/*", "nar/fetch"], "lifetime_secs": 86400}
```

Returns the encoded UCAN token string.

Requires: `manage` capability.

## Lifecycle

```
1. Start
   |-- Generate or load peer identity (ed25519 keypair)
   |-- Join libp2p mesh (mDNS + seed peers)
   |-- Build store bloom filter from local Nix store
   |-- Publish capabilities to DHT
   |-- Subscribe to GossipSub: builds/wanted, builds/claimed, builds/result
   |-- Register stream protocol handlers: /aos/log-replay/1.0.0, /aos/nar-fetch/1.0.0
   |-- If [control]: bind Unix socket, start accepting connections
   |-- If [build]: enable job claiming in the main loop
   +-- Start capability refresh timer (120s interval)

2. Main Loop
   |-- Handle swarm events (GossipSub messages, stream requests, DHT queries)
   |-- If [build] and capacity available:
   |   |-- Evaluate pending jobs (arch, features, bloom affinity)
   |   |-- Claim via DHT, announce on builds/claimed
   |   |-- Fetch missing inputs from peers via /aos/nar-fetch/1.0.0
   |   |-- Execute nix-store --realise
   |   |-- Sign outputs, announce as DHT provider
   |   |-- Stream logs via GossipSub + buffer for replay
   |   +-- Publish result to builds/result
   |-- If [control]:
   |   |-- Accept Unix socket connections
   |   |-- Authenticate caller via SO_PEERCRED
   |   +-- Dispatch commands (build, watch, status, gc, peers, delegate)
   +-- Refresh capabilities periodically

3. Shutdown
   |-- If [control]: stop accepting new connections, drain in-flight commands
   |-- If [build]: unsubscribe from builds/wanted, wait for in-flight builds (with timeout)
   |-- Remove capability record from DHT
   +-- Disconnect from mesh
```

## Main Loop Implementation

```rust
struct Daemon {
    swarm: Swarm<AosBehaviour>,
    config: DaemonConfig,
    active_builds: Arc<AtomicU32>,
    store_bloom: BloomFilter,
    log_buffers: HashMap<String, Arc<LogBuffer>>,
    control: Option<ControlSocket>,    // present when [control] is configured
}

impl Daemon {
    async fn run(&mut self) -> Result<()> {
        self.publish_capabilities().await?;

        let mut capability_interval = tokio::time::interval(Duration::from_secs(120));
        let mut pending_jobs: BinaryHeap<PrioritizedJob> = BinaryHeap::new();

        loop {
            tokio::select! {
                // Handle swarm events (GossipSub messages, stream requests, etc.)
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event, &mut pending_jobs).await?;
                }

                // Try to claim and execute pending jobs (only when [build] is configured)
                _ = tokio::time::sleep(Duration::from_millis(100)),
                    if self.config.build.is_some()
                    && !pending_jobs.is_empty()
                    && self.active_builds.load(Ordering::Relaxed)
                        < self.config.build.as_ref().unwrap().max_jobs => {
                    if let Some(job) = pending_jobs.pop() {
                        self.try_claim_and_execute(job).await?;
                    }
                }

                // Handle incoming control socket connections (only when [control] is configured)
                Some(conn) = async {
                    match &mut self.control {
                        Some(ctl) => Some(ctl.accept().await),
                        None => None,
                    }
                } => {
                    self.handle_control_connection(conn).await?;
                }

                // Refresh capabilities periodically
                _ = capability_interval.tick() => {
                    self.publish_capabilities().await?;
                }

                // Graceful shutdown signal
                _ = shutdown_signal() => {
                    self.graceful_shutdown().await?;
                    break;
                }
            }
        }
        Ok(())
    }
}
```

## Build Execution

Build execution requires `[build]` to be configured. It proceeds in three
phases: fetching missing inputs from peers, running `nix-store --realise`, and
announcing the daemon as a provider for outputs.

### Job Evaluation and Claiming

When a job arrives on `builds/wanted`, the daemon evaluates whether it should
claim it. Hard filters (architecture, required features) are checked first.
If the daemon is eligible, it computes an affinity score based on bloom filter
overlap with the job's input closure. Higher affinity means the daemon already
has more of the required inputs in its local store, so it claims faster.

```rust
async fn try_claim_and_execute(&mut self, job: BuildJob) -> Result<()> {
    let build_config = self.config.build.as_ref().unwrap();

    // Hard filters
    if job.arch != build_config.arch { return Ok(()); }
    if !job.features.iter().all(|f| build_config.features.contains(f)) { return Ok(()); }

    // Affinity-based delay
    let affinity = self.compute_affinity(&job);
    if affinity < 0.8 {
        let delay = Duration::from_millis((1000.0 * (1.0 - affinity)) as u64);
        tokio::time::sleep(delay).await;
    }

    // Check DHT for existing claim
    let claim_key = format!("build:{}", job.drv_hash);
    if let Some(_existing) = self.dht_get(&claim_key).await {
        return Ok(()); // Someone else claimed it
    }

    // Write our claim
    let claim = BuildClaim {
        peer_id: self.swarm.local_peer_id().to_string(),
        status: "building".to_string(),
        started_at: now(),
    };
    self.dht_put(&claim_key, &claim, Duration::from_secs(1800)).await?;

    // Announce claim
    let claimed_msg = ClaimedMessage {
        drv_hash: job.drv_hash.clone(),
        builder_peer_id: self.swarm.local_peer_id().to_string(),
    };
    self.gossipsub_publish("builds/claimed", &claimed_msg)?;

    // Execute build in background
    let active = self.active_builds.clone();
    active.fetch_add(1, Ordering::Relaxed);
    let job_clone = job.clone();
    tokio::spawn(async move {
        let result = execute_build(job_clone).await;
        active.fetch_sub(1, Ordering::Relaxed);
        result
    });

    Ok(())
}
```

### Build Phases

Logs are streamed line-by-line via GossipSub and buffered in memory for replay
requests from any peer.

```rust
async fn execute_build(
    job: BuildJob,
    swarm: &mut Swarm<AosBehaviour>,
    log_buffer: Arc<LogBuffer>,
) -> Result<BuildResult> {
    let drv_hash = &job.drv_hash;
    let topic = gossipsub::IdentTopic::new(format!("builds/logs/{drv_hash}"));

    // Phase 1: Fetch missing inputs
    emit_status(swarm, &topic, &log_buffer, "fetching-inputs", drv_hash);
    fetch_missing_inputs(&job.drv_path, swarm).await?;

    // Phase 2: Execute nix-store --realise
    emit_status(swarm, &topic, &log_buffer, "building", drv_hash);

    let mut child = Command::new("nix-store")
        .args(["--realise", &job.drv_path])
        .stderr(Stdio::piped())
        .spawn()?;

    let stderr = child.stderr.take().unwrap();
    let mut lines = BufReader::new(stderr).lines();
    let mut seq = 0u64;

    while let Some(line) = lines.next_line().await? {
        let event = LogEvent {
            seq,
            kind: "log".to_string(),
            line: line.clone(),
            timestamp: now(),
        };

        // Buffer for replay
        log_buffer.append(event.clone());

        // Publish to mesh
        swarm.behaviour_mut().gossipsub
            .publish(topic.clone(), serde_json::to_vec(&event)?)?;

        seq += 1;
    }

    let status = child.wait().await?;

    // Phase 3: Handle result
    if status.success() {
        let outputs = query_outputs(&job.drv_path).await?;

        // Sign outputs and announce as provider for output store paths via DHT
        emit_status(swarm, &topic, &log_buffer, "signing-and-announcing", drv_hash);
        for output in &outputs {
            let key = store_path_to_kad_key(output);
            swarm.behaviour_mut().kademlia
                .start_providing(key)?;
        }

        // Emit completion event
        let complete = LogEvent {
            seq,
            kind: "complete".to_string(),
            line: serde_json::to_string(&serde_json::json!({
                "success": true,
                "outputs": outputs,
            }))?,
            timestamp: now(),
        };
        log_buffer.append(complete.clone());
        swarm.behaviour_mut().gossipsub
            .publish(topic.clone(), serde_json::to_vec(&complete)?)?;

        // Update DHT with result
        let result = BuildResult {
            status: "complete".to_string(),
            outputs: outputs.clone(),
            completed_at: now(),
        };
        dht_put(&format!("build:{drv_hash}"), &result, Duration::from_secs(86400)).await?;

        // Publish to result topic
        gossipsub_publish("builds/result", &result)?;

        // Update bloom filter with new store paths
        for output in &outputs {
            store_bloom.insert(&extract_store_hash(output));
        }

        Ok(result)
    } else {
        let error = LogEvent {
            seq,
            kind: "error".to_string(),
            line: format!("build failed with exit code {:?}", status.code()),
            timestamp: now(),
        };
        log_buffer.append(error.clone());
        swarm.behaviour_mut().gossipsub
            .publish(topic.clone(), serde_json::to_vec(&error)?)?;

        // Update DHT
        dht_put(&format!("build:{drv_hash}"), &BuildResult {
            status: "failed".to_string(),
            ..
        }, Duration::from_secs(3600)).await?;

        Err(anyhow!("build failed"))
    }
}
```

### Nix Store Retry

If `nix-store --realise` fails with daemon connection errors, the daemon retries
with exponential backoff (up to 3 attempts). It emits `store-unavailable` log
events so watchers know what is happening.

## Log Replay Handler

The daemon handles incoming `/aos/log-replay/1.0.0` stream requests from any
peer. It first replays buffered history from the requested sequence number, then
live-tails the build if it is still in progress.

```rust
async fn handle_log_replay(
    mut stream: libp2p::Stream,
    log_buffers: &HashMap<String, Arc<LogBuffer>>,
    log_txs: &HashMap<String, broadcast::Sender<LogEvent>>,
) -> Result<()> {
    let request: ReplayRequest = read_framed(&mut stream).await?;
    let drv_hash = &request.drv_hash;

    let buffer = log_buffers.get(drv_hash)
        .ok_or_else(|| anyhow!("no build in progress for {drv_hash}"))?;

    // Phase 1: Replay buffered history
    for event in buffer.events_from(request.from_seq) {
        write_framed(&mut stream, &event).await?;
    }

    // Phase 2: Live tail (if build still in progress)
    if let Some(tx) = log_txs.get(drv_hash) {
        let mut rx = tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => {
                    write_framed(&mut stream, &event).await?;
                    if matches!(event.kind.as_str(), "complete" | "error") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    Ok(())
}
```

## NAR Fetch Handler

The daemon serves the `/aos/nar-fetch/1.0.0` stream protocol, allowing any peer
to fetch store paths directly.

```rust
async fn handle_nar_fetch(
    mut stream: libp2p::Stream,
) -> Result<()> {
    let request: NarFetchRequest = read_framed(&mut stream).await?;

    // Resolve store hash to full path
    let store_path = resolve_store_path(&request.store_hash)?;

    // Generate narinfo
    let narinfo = generate_narinfo(&store_path)?;
    write_framed(&mut stream, &narinfo).await?;

    // Stream NAR data (optionally compressed)
    let mut child = Command::new("nix-store")
        .args(["--dump", &store_path])
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdout = child.stdout.take().unwrap();
    let mut buf = vec![0u8; 64 * 1024]; // 64KB chunks
    loop {
        let n = stdout.read(&mut buf).await?;
        if n == 0 { break; }
        stream.write_all(&buf[..n]).await?;
    }

    Ok(())
}
```

## Bloom Filter for Store Affinity

The daemon maintains a bloom filter representing the set of store paths in its
local Nix store. This filter is published to the DHT as part of the daemon's
capability advertisement, allowing job evaluation to estimate how many of a
build's inputs the daemon already has.

```rust
struct StoreBloomFilter {
    filter: BloomFilter<String>,
}

impl StoreBloomFilter {
    fn from_local_store() -> Result<Self> {
        let mut filter = BloomFilter::with_rate(0.01, 1_000_000); // 1% FPR, 1M items
        let output = Command::new("nix-store")
            .args(["--query", "--all"])
            .output()?;
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if let Some(hash) = extract_store_hash(line) {
                filter.insert(&hash);
            }
        }
        Ok(Self { filter })
    }

    fn contains(&self, hash: &str) -> bool {
        self.filter.contains(&hash.to_string())
    }

    // Serialize for DHT capability advertisement
    fn to_bytes(&self) -> Vec<u8> { ... }
}
```

## Graceful Shutdown

Shutdown proceeds in two phases, draining active subsystems concurrently:

**Control socket drain** (when `[control]` is configured):
- Stop accepting new connections
- Wait for in-flight commands to complete (with timeout)
- Send error responses to streaming watchers so they know to reconnect

**Build drain** (when `[build]` is configured):
- Unsubscribe from `builds/wanted` (stop accepting new jobs)
- Wait for in-flight builds to complete (with configurable timeout)
- If timeout expires, emit `error` log events for incomplete builds so watchers
  know to retry

**Common shutdown** (all nodes):
- Remove capability record from DHT
- Disconnect from mesh

## CLI

```
aos daemon              # start with default config
aos daemon --config /etc/aos/daemon.toml
```

## Module Listing

```
aos-daemon/
  src/
    lib.rs              # crate root
    main_loop.rs        # main event loop (select! over swarm + jobs + control)
    build.rs            # build execution (fetch inputs, realise, announce)
    bloom.rs            # store bloom filter
    config.rs           # DaemonConfig deserialization
    control.rs          # Unix socket control interface, JSON-line protocol
    auth.rs             # SO_PEERCRED local auth, UCAN mesh auth
    log_replay.rs       # /aos/log-replay/1.0.0 handler
    nar_fetch.rs        # /aos/nar-fetch/1.0.0 handler
    signing.rs          # output signing and trust management
    store.rs            # local Nix store management
    ucan.rs             # UCAN token parsing, validation, and delegation
```

## Resource Management

- Build concurrency controlled by `max_jobs` semaphore (when `[build]` is
  configured)
- Each build gets exclusive access to its allocated resources
- The daemon tracks disk space and refuses jobs when store is too full
- CPU/memory limits can be enforced by the container runtime (k8s resource
  limits, cgroups)
- Control socket connection limits are bounded by file descriptor limits; the
  daemon does not impose its own limit beyond OS defaults
