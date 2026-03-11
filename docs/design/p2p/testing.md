# Testing: Acceptance Criteria and Test Harnesses

This documents the acceptance criteria and test harness implementations
for the AOS P2P distributed build system. Every major subsystem has
concrete, runnable criteria organized into three test tiers.

## Overview

Three test tiers:

- **Unit tests** -- In-process Rust tests. Fast, deterministic, no I/O.
  For algorithms (CRDT merge, merkle tree, bloom filter, FastCDC
  chunking, affinity scoring, LRU TTL estimation).

- **Integration tests** -- Single-machine, multiple components. Spawns
  real LMDB, real FUSE mounts, real pack files. Tests chunk store, FUSE,
  and view interactions end-to-end on one host.

- **Multi-node tests** -- Multiple daemon instances (separate processes
  on localhost with different ports/sockets, or QEMU VMs). Tests mesh
  formation, sync convergence, build distribution, NAT traversal.

## Test Infrastructure

### Multi-daemon test harness

A test harness that spawns N daemon instances on localhost, each with
its own:

- libp2p identity (generated per-test)
- QUIC port (ephemeral)
- Unix socket path (temp dir)
- Chunk store directory (temp dir)
- LMDB state directory (temp dir)
- FUSE mount point (temp dir)

```rust
struct TestCluster {
    daemons: Vec<TestDaemon>,
    root_key: Keypair,          // shared UCAN root for the test
    temp_dir: TempDir,
}

struct TestDaemon {
    peer_id: PeerId,
    process: Child,
    socket_path: PathBuf,
    quic_port: u16,
    chunk_dir: PathBuf,
    fuse_mount: PathBuf,
}

impl TestCluster {
    /// Spawn N daemons, wait for mesh formation, return cluster handle.
    async fn spawn(n: usize, config: TestConfig) -> Result<Self>;

    /// Wait until all daemons are connected to each other.
    async fn wait_for_mesh(&self, timeout: Duration) -> Result<()>;

    /// Wait until all daemons report the same sync merkle root.
    async fn wait_for_sync_convergence(&self, timeout: Duration) -> Result<()>;

    /// Get a control socket client for daemon i.
    fn client(&self, i: usize) -> ControlClient;

    /// Kill daemon i (simulate crash).
    fn kill(&mut self, i: usize);

    /// Restart daemon i (simulate recovery).
    async fn restart(&mut self, i: usize) -> Result<()>;

    /// Partition daemons into groups (simulate network partition).
    async fn partition(&mut self, groups: &[&[usize]]) -> Result<()>;

    /// Heal partition.
    async fn heal_partition(&mut self) -> Result<()>;
}
```

### FUSE test harness

For testing FUSE views without a full daemon:

```rust
struct TestFuse {
    chunk_store: ChunkStore,
    mount_point: PathBuf,
    fuse_handle: JoinHandle<()>,
}

impl TestFuse {
    /// Create a chunk store, ingest test data, mount FUSE.
    async fn mount(mode: FuseMode, entries: &[TestEntry]) -> Result<Self>;

    /// Verify a file is readable and has expected content.
    fn assert_file(&self, path: &str, expected: &[u8]);

    /// Verify a path returns ENOENT.
    fn assert_not_found(&self, path: &str);

    /// Verify readdir returns expected entries.
    fn assert_readdir(&self, path: &str, expected: &[&str]);
}
```

### Property-based testing

Use `proptest` or `quickcheck` for CRDT and merkle tree correctness:

```rust
// CRDT merge is commutative
proptest! {
    fn merge_commutative(a: SyncState, b: SyncState) {
        let ab = merge(&a, &b);
        let ba = merge(&b, &a);
        assert_eq!(ab, ba);
    }
}
```

## System Acceptance Criteria

For each system below, concrete acceptance criteria define what must
pass. Each criterion is tagged with its test tier
(unit/integration/multi-node).

### 1. Chunk Store

**Acceptance Criteria:**

- [ ] FastCDC produces deterministic chunks for the same input regardless of call context
- [ ] Chunks are deduplicated: ingesting the same file twice produces one copy in pack files
- [ ] Cross-version dedup: ingesting two versions of a file with a 1-byte diff shares >90% of chunks
- [ ] Pack file rotation: when a pack exceeds max_size, a new pack is started; sealed packs are read-only
- [ ] Pack compaction: after removing chunks, compaction rewrites packs with >30% dead space, all location indexes updated
- [ ] Chunk read via pread: read_chunk returns correct data for any chunk in any pack
- [ ] Manifest stores complete file tree (dirs, files with chunk lists, symlinks with targets)
- [ ] Manifest reconstruction: reconstructing a store path from manifest + chunks produces byte-identical content
- [ ] NAR hash: on-the-fly NAR hash computation matches `nix-store --dump | sha256sum`
- [ ] Concurrent writes: multiple threads ingesting different files don't corrupt the chunk store
- [ ] LMDB transactional safety: crash during chunk write doesn't corrupt the index
- [ ] Zstd compression: compressed chunks decompress to original data; chunks below min_compress_size are stored uncompressed

**Tests:**

```rust
#[test]
fn chunk_determinism() {
    let data = random_bytes(1_000_000);
    let chunks_a = chunk_file(&data);
    let chunks_b = chunk_file(&data);
    assert_eq!(chunks_a, chunks_b);
}

#[test]
fn cross_version_dedup() {
    let mut data = random_bytes(1_000_000);
    let chunks_a = ingest(&data);
    data[500_000] ^= 0xff;  // flip one byte
    let chunks_b = ingest(&data);
    let shared = chunks_a.intersection(&chunks_b).count();
    assert!(shared as f64 / chunks_a.len() as f64 > 0.90);
}

#[test]
fn manifest_roundtrip() {
    let store_path = create_test_store_path();  // dir with files + symlinks
    let manifest = chunk_store.index_store_path(&store_path)?;
    let reconstructed = chunk_store.reconstruct(&manifest, &temp_dir)?;
    assert_dirs_equal(&store_path, &reconstructed);
}

#[test]
fn nar_hash_matches_nix() {
    let store_path = create_test_store_path();
    let our_hash = compute_nar_hash(&store_path);
    let nix_hash = Command::new("nix-store").args(["--dump", &store_path])
        .pipe(Command::new("sha256sum")).output()?;
    assert_eq!(our_hash, parse_hash(&nix_hash));
}

#[tokio::test]
async fn concurrent_ingest() {
    let store = ChunkStore::open(temp_dir)?;
    let handles: Vec<_> = (0..10).map(|i| {
        let store = store.clone();
        tokio::spawn(async move {
            let data = random_bytes(500_000);
            store.ingest(&format!("test-{i}"), &data).await
        })
    }).collect();
    for h in handles { h.await??; }
    // Verify all 10 paths are retrievable
}

#[test]
fn pack_compaction() {
    // Ingest 100 chunks, remove 50, compact, verify remaining 50 readable
    // Verify pack file size decreased
    // Verify LMDB locations updated
}
```

### 2. FUSE ViewFs

**Acceptance Criteria:**

- [ ] Eager mode: mount blocks until all chunks are local; all reads are instant (no network)
- [ ] Async mode: mount returns immediately with manifests; background fetch populates chunks; read() on unfetched file blocks briefly then succeeds
- [ ] Lazy mode: mount returns immediately with manifests; read() triggers on-demand chunk fetch; fetched chunks cached in pack file
- [ ] readdir returns correct entries from manifest (all modes)
- [ ] stat returns correct file sizes, modes, types from manifest (all modes)
- [ ] Symlinks resolve correctly
- [ ] ENOENT for paths not in the view's projection
- [ ] Concurrent reads from multiple processes don't corrupt or deadlock
- [ ] OverlayFS integration: writes go to upper layer, reads fall through to FUSE lower
- [ ] Access tracking: every read() updates the per-view access.mdb
- [ ] View projection: only closure roots in the view's projection are visible
- [ ] Large file support: files >4GB read correctly (multiple chunks)
- [ ] Executable bit preserved from manifest

**Tests:**

```rust
#[tokio::test]
async fn eager_mode_blocks() {
    // Start FUSE with eager mode, remote chunks
    // Verify mount doesn't complete until chunks arrive
    // Once mounted, verify read() is instant (< 1ms)
}

#[tokio::test]
async fn lazy_on_demand_fetch() {
    // Mount with lazy mode, no local chunks
    // readdir() works (manifest only)
    // stat() returns correct sizes (manifest only)
    // read() triggers fetch, returns correct data
    // Second read() is instant (cached in pack file)
}

#[tokio::test]
async fn view_projection_enoent() {
    // Create view with projection = Closure(drv_hash)
    // Verify paths IN the closure are visible
    // Verify paths NOT in the closure return ENOENT
}

#[tokio::test]
async fn overlay_writes() {
    // Mount FUSE + OverlayFS
    // Write to $out path
    // Verify write went to upper layer
    // Verify reads of input paths still work from lower (FUSE)
}
```

### 3. libp2p Mesh

**Acceptance Criteria:**

- [ ] Two daemons on same machine discover each other via mDNS within 5 seconds
- [ ] Two daemons with seed peer config connect and form mesh within 10 seconds
- [ ] GossipSub messages reach all subscribers within 2 seconds (mesh of 10)
- [ ] DHT put/get round-trips correctly (write on daemon A, read on daemon B)
- [ ] DHT provider records: start_providing on A, get_providers on B returns A
- [ ] Connection limits enforced: daemon rejects connections beyond max_established
- [ ] Idle connections close after timeout (60s)
- [ ] QUIC transport: connections encrypted, PeerId verified
- [ ] NAT detection: AutoNAT correctly identifies public vs private peers
- [ ] Peer scoring: peers sending invalid messages accumulate negative scores
- [ ] Identify protocol: peers exchange addresses, Kademlia routing table updated

**Tests:**

```rust
#[tokio::test]
async fn mdns_discovery() {
    let cluster = TestCluster::spawn(2, TestConfig::mdns_only()).await?;
    cluster.wait_for_mesh(Duration::from_secs(5)).await?;
    assert_eq!(cluster.daemons[0].connected_peers().await?, 1);
}

#[tokio::test]
async fn gossipsub_fanout() {
    let cluster = TestCluster::spawn(5, TestConfig::default()).await?;
    cluster.wait_for_mesh(Duration::from_secs(10)).await?;

    // Publish on daemon 0
    cluster.client(0).publish("test/topic", b"hello").await?;

    // All others receive within 2s
    for i in 1..5 {
        let msg = cluster.client(i).recv("test/topic", Duration::from_secs(2)).await?;
        assert_eq!(msg, b"hello");
    }
}

#[tokio::test]
async fn dht_provider_roundtrip() {
    let cluster = TestCluster::spawn(3, TestConfig::default()).await?;
    cluster.wait_for_mesh(Duration::from_secs(10)).await?;

    cluster.client(0).start_providing("hash123", Duration::from_secs(300)).await?;
    tokio::time::sleep(Duration::from_secs(2)).await; // DHT propagation

    let providers = cluster.client(2).get_providers("hash123").await?;
    assert!(providers.contains(&cluster.daemons[0].peer_id));
}

#[tokio::test]
async fn network_partition_and_healing() {
    let cluster = TestCluster::spawn(6, TestConfig::default()).await?;
    cluster.wait_for_mesh(Duration::from_secs(10)).await?;

    // Partition: [0,1,2] | [3,4,5]
    cluster.partition(&[&[0,1,2], &[3,4,5]]).await?;

    // Each side still works
    cluster.client(0).publish("test/topic", b"side-a").await?;
    cluster.client(3).publish("test/topic", b"side-b").await?;

    // Heal
    cluster.heal_partition().await?;
    cluster.wait_for_mesh(Duration::from_secs(10)).await?;

    // Messages flow again
}
```

### 4. Sync Protocol

**Acceptance Criteria:**

- [ ] CRDT merge is commutative: merge(A,B) = merge(B,A)
- [ ] CRDT merge is associative: merge(merge(A,B),C) = merge(A,merge(B,C))
- [ ] CRDT merge is idempotent: merge(A,A) = A
- [ ] Concurrent adds on different paths both survive merge
- [ ] Concurrent add+remove: higher timestamp wins
- [ ] Timestamp tie: alive (add) wins over dead (remove)
- [ ] GossipSub delta propagation: delta published on daemon A reaches daemon B within 2s
- [ ] Anti-entropy: daemon joining late catches up via merkle walk within 30s
- [ ] Merkle tree: root hash changes when any entry changes
- [ ] Merkle tree: identical states produce identical root hashes
- [ ] Merkle walk efficiency: syncing 1 changed entry out of 10,000 transfers O(log n) hashes
- [ ] Consistency milestone: all daemons report same root hash after convergence
- [ ] UCAN path validation: delta with insufficient path permission is rejected
- [ ] Vector clock: causally related updates are ordered correctly; concurrent updates trigger per-element merge

**Tests:**

```rust
// Property-based tests
proptest! {
    #[test]
    fn crdt_commutative(a in arb_sync_state(), b in arb_sync_state()) {
        assert_eq!(merge(&a, &b), merge(&b, &a));
    }

    #[test]
    fn crdt_associative(a in arb_sync_state(), b in arb_sync_state(), c in arb_sync_state()) {
        assert_eq!(merge(&merge(&a, &b), &c), merge(&a, &merge(&b, &c)));
    }

    #[test]
    fn crdt_idempotent(a in arb_sync_state()) {
        assert_eq!(merge(&a, &a), a);
    }
}

#[test]
fn concurrent_adds_both_survive() {
    let mut a = SyncState::new();
    let mut b = SyncState::new();
    a.insert("profiles/dylan", entry("hash1", 42, true));
    b.insert("profiles/alice", entry("hash2", 45, true));
    let merged = merge(&a, &b);
    assert!(merged.contains_key("profiles/dylan"));
    assert!(merged.contains_key("profiles/alice"));
}

#[test]
fn merkle_root_deterministic() {
    let mut state = SyncState::new();
    state.insert("a", entry("h1", 1, true));
    state.insert("b", entry("h2", 2, true));
    let root1 = merkle_root(&state);
    let root2 = merkle_root(&state);
    assert_eq!(root1, root2);
}

#[tokio::test]
async fn anti_entropy_catchup() {
    let cluster = TestCluster::spawn(3, TestConfig::default()).await?;
    cluster.wait_for_mesh(Duration::from_secs(10)).await?;

    // Add 100 entries on daemon 0
    for i in 0..100 {
        cluster.client(0).sync_put(&format!("key/{i}"), &format!("hash{i}")).await?;
    }
    cluster.wait_for_sync_convergence(Duration::from_secs(10)).await?;

    // Kill daemon 2, add 50 more entries
    cluster.kill(2);
    for i in 100..150 {
        cluster.client(0).sync_put(&format!("key/{i}"), &format!("hash{i}")).await?;
    }

    // Restart daemon 2 -- should catch up via anti-entropy
    cluster.restart(2).await?;
    cluster.wait_for_sync_convergence(Duration::from_secs(30)).await?;

    // Verify daemon 2 has all 150 entries
    for i in 0..150 {
        let val = cluster.client(2).sync_get(&format!("key/{i}")).await?;
        assert_eq!(val.store_hash, format!("hash{i}"));
    }
}

#[tokio::test]
async fn ucan_path_rejection() {
    // Daemon with UCAN scoped to sync/staging/profiles/dylan/*
    // Attempt to write sync/staging/profiles/alice/... -> rejected
    // Attempt to write sync/staging/profiles/dylan/config -> accepted
}
```

### 5. UCAN Auth

**Acceptance Criteria:**

- [ ] Root key generates valid UCAN tokens
- [ ] UCAN chain verifies back to root public key
- [ ] Expired UCAN is rejected
- [ ] Revoked UCAN is rejected (DHT revocation list)
- [ ] Delegation attenuation: child UCAN cannot grant capabilities the parent doesn't have
- [ ] Path-scoped capabilities: `sync/write` on `profiles/dylan/*` allows `profiles/dylan/config` but rejects `profiles/alice`
- [ ] `/aos/auth/1.0.0` handshake: peer with valid UCAN is admitted; peer with invalid UCAN is rejected and connection closed
- [ ] GossipSub messages with invalid UCAN are rejected and sender's peer score penalized
- [ ] Connection gating: blocked PeerId is immediately disconnected
- [ ] Open mesh mode: all peers admitted without UCAN (dev/test only)
- [ ] SO_PEERCRED: local socket auth correctly maps uid/gid to capabilities

**Tests:**

```rust
#[test]
fn ucan_chain_verification() {
    let root = Keypair::generate();
    let daemon = Keypair::generate();
    let client = Keypair::generate();

    let ucan1 = issue_ucan(&root, &daemon, vec![Cap::all()], Duration::from_secs(3600));
    let ucan2 = delegate_ucan(&daemon, &client, vec![Cap::sync_read("staging/*")], &ucan1);

    assert!(verify_chain(&[ucan2, ucan1], &root.public()));
}

#[test]
fn ucan_path_attenuation() {
    // Parent has sync/write on staging/*
    // Child requests sync/write on staging/profiles/dylan/* -> OK (subset)
    // Child requests sync/write on production/* -> FAIL (not in parent)
}

#[tokio::test]
async fn auth_handshake_reject() {
    let cluster = TestCluster::spawn(2, TestConfig::ucan_mode()).await?;

    // Spawn a rogue peer with no UCAN
    let rogue = TestDaemon::spawn_no_ucan().await?;
    rogue.connect_to(&cluster.daemons[0]).await;

    // Connection should be rejected
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!cluster.daemons[0].is_connected_to(&rogue.peer_id).await?);
}
```

### 6. Build System

**Acceptance Criteria:**

- [ ] Job submitted on daemon A is received by daemon B via GossipSub
- [ ] Affinity-based claiming: daemon with 90% cache hit claims before daemon with 10%
- [ ] DHT claim: after claiming, other daemons see the claim and skip the job
- [ ] Duplicate claim (race): both daemons produce identical outputs, both become providers
- [ ] Missing inputs fetched from mesh before build starts
- [ ] Build runs in nspawn with --private-users=pick (container UID 0 != host UID 0)
- [ ] Ephemeral view (eager FUSE): only declared inputs visible, undeclared paths return ENOENT
- [ ] OverlayFS: build output written to $out, self-references work
- [ ] Log streaming: build logs published to GossipSub, receivable by subscribers
- [ ] Log replay: late joiner gets full log via /aos/log-replay/1.0.0
- [ ] Build timeout: build exceeding max_build_duration is killed and cleaned up
- [ ] Crash cleanup: on daemon restart, stale FUSE mounts and containers are cleaned up
- [ ] Build result: outputs chunked, signed, announced as DHT provider, published to build/result/{universe}/{system}
- [ ] Priority + aging: higher-priority jobs claimed first; old jobs age into higher priority

**Tests:**

```rust
#[tokio::test]
async fn end_to_end_build() {
    let cluster = TestCluster::spawn(3, TestConfig::with_builds()).await?;

    // Submit a build on daemon 0
    let drv_path = create_test_derivation()?;
    let result = cluster.client(0).build(&drv_path).await?;

    // Verify: some daemon claimed and built it
    assert!(result.success);
    assert!(!result.outputs.is_empty());

    // Verify: output is fetchable from any daemon
    for i in 0..3 {
        let providers = cluster.client(i).get_providers(&result.outputs[0]).await?;
        assert!(!providers.is_empty());
    }
}

#[tokio::test]
async fn affinity_claiming() {
    // Daemon 0 has 90% of inputs cached, daemon 1 has 10%
    // Submit build -- daemon 0 should claim first
}

#[tokio::test]
async fn build_isolation() {
    // Build with inputs [A, B, C]
    // Inside container: A, B, C visible
    // Inside container: D (exists in store but not in inputs) returns ENOENT
}

#[tokio::test]
async fn log_replay() {
    // Start a slow build on daemon 0
    // Wait for some log lines
    // Connect daemon 2 as late joiner
    // Verify daemon 2 gets all historical log lines + live tail
}

#[tokio::test]
async fn build_crash_recovery() {
    let cluster = TestCluster::spawn(3, TestConfig::with_builds()).await?;

    // Start a build on daemon 1
    let drv_path = create_slow_derivation()?;  // takes 30+ seconds
    cluster.client(0).build_async(&drv_path).await?;
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Kill daemon 1 mid-build
    cluster.kill(1);

    // Wait for DHT claim to expire or submitter to detect crash
    // Job should be re-announced and claimed by daemon 2
    let result = cluster.client(0).wait_for_build(&drv_path, Duration::from_secs(120)).await?;
    assert!(result.success);
}
```

### 7. Daemon

**Acceptance Criteria:**

- [ ] Starts in full mode when no upstream socket exists
- [ ] Starts in forward mode when upstream socket exists at well-known path
- [ ] Control socket: SO_PEERCRED correctly identifies connecting user
- [ ] Control socket: group-based capability mapping works (admin/build/read groups)
- [ ] Control socket: unauthorized commands are rejected with error
- [ ] JSON-line protocol: well-formed requests get well-formed responses
- [ ] Streaming responses: build logs stream line-by-line over the socket
- [ ] Graceful shutdown: in-flight builds complete (within timeout), new jobs rejected
- [ ] Capability advertisement: DHT record contains correct arch, features, active_jobs
- [ ] Capability refresh: DHT record updated every 120s
- [ ] Multiple views: daemon can manage multiple views in different universes
- [ ] Config reload: daemon responds to SIGHUP by reloading config (where safe)

**Tests:**

```rust
#[tokio::test]
async fn auto_detect_forward_mode() {
    // Create upstream socket
    let upstream = create_mock_upstream_socket().await?;

    // Start daemon -- should auto-detect forward mode
    let daemon = TestDaemon::spawn(TestConfig::auto_detect()).await?;
    assert_eq!(daemon.mode().await?, DaemonMode::Forward);
}

#[tokio::test]
async fn control_socket_auth() {
    let daemon = TestDaemon::spawn(TestConfig::default()).await?;

    // Connect as user in aos-build group -> submit allowed
    // Connect as user in aos-read group -> submit rejected, observe allowed
}

#[tokio::test]
async fn graceful_shutdown() {
    let cluster = TestCluster::spawn(3, TestConfig::with_builds()).await?;

    // Start a build
    let drv_path = create_test_derivation()?;
    cluster.client(0).build_async(&drv_path).await?;

    // Signal graceful shutdown on the builder
    let builder = find_builder(&cluster, &drv_path).await?;
    cluster.signal(builder, Signal::SIGTERM);

    // Build should complete (not be killed)
    let result = cluster.client(0).wait_for_build(&drv_path, Duration::from_secs(60)).await?;
    assert!(result.success);
}
```

### 8. Views + GC

**Acceptance Criteria:**

- [ ] View projection: Full projection shows all universe content
- [ ] View projection: Closure projection shows only transitive deps of a derivation
- [ ] View projection: SyncPath projection shows only content at a specific sync namespace path
- [ ] View projection: Filter projection shows only matching packages
- [ ] Sync modes: send-only publishes CRDT deltas but ignores incoming
- [ ] Sync modes: receive-only applies incoming deltas but doesn't publish
- [ ] Sync modes: none ignores all sync traffic
- [ ] GC TTL policy: paths not accessed within TTL are evicted
- [ ] GC budget policy: paths evicted LRU when disk usage exceeds budget
- [ ] GC manual policy: paths evicted only on explicit `aos gc` command
- [ ] GC does NOT publish CRDT removals (local-only)
- [ ] Explicit `apm remove` DOES publish CRDT removal
- [ ] Provider TTL (TTL policy): provider_ttl = max_age - time_since_last_access
- [ ] Provider TTL (budget policy): provider_ttl proportional to LRU rank
- [ ] Provider TTL (pinned/CRDT): provider_ttl = max TTL
- [ ] Post-GC re-advertisement: surviving paths get fresh provider TTLs
- [ ] Profile generations: install creates new gen, rollback switches symlink
- [ ] Profile GC protection: paths in recent generations are not evicted

**Tests:**

```rust
#[tokio::test]
async fn gc_ttl_eviction() {
    // Create view with TTL=5s (short for testing)
    // Add a path, wait 6s, run GC
    // Verify path is evicted from roots
    // Verify provider record expired
}

#[tokio::test]
async fn gc_budget_eviction() {
    // Create view with budget=1MB
    // Add paths totaling 2MB
    // Run GC
    // Verify coldest paths (by LRU) are evicted first
    // Verify remaining paths fit in budget
}

#[tokio::test]
async fn gc_does_not_sync_removal() {
    let cluster = TestCluster::spawn(2, TestConfig::default()).await?;
    // Add path to view on both daemons via CRDT
    // Run GC on daemon 0 (evicts the path locally)
    // Verify daemon 1 still has the path (GC doesn't propagate)
}

#[tokio::test]
async fn explicit_remove_syncs() {
    let cluster = TestCluster::spawn(2, TestConfig::default()).await?;
    // apm install curl on daemon 0 -> CRDT add -> daemon 1 gets it
    // apm remove curl on daemon 0 -> CRDT remove -> daemon 1 removes it
}

#[tokio::test]
async fn provider_ttl_lru_aware() {
    // Create view with budget policy
    // Add 100 paths, access some frequently
    // Check provider TTLs: hot paths have long TTL, cold paths have short TTL
}

#[tokio::test]
async fn profile_rollback() {
    // Gen 1: {gcc, python}
    // Gen 2: {gcc, python, curl}  (install curl)
    // Gen 3: {gcc, curl}          (remove python)
    // Rollback to gen 2: {gcc, python, curl}
    // Verify python is accessible again
}
```

### 9. APM (Package Manager)

**Acceptance Criteria:**

- [ ] Registry resolution: symlink tree correctly maps package name to store path
- [ ] Registry closure: fetching registry store path brings all .drv files and outputs
- [ ] Priority overlay: higher-priority registry shadows lower for same package name
- [ ] Registry-scoped resolution: transitive deps resolve from same registry
- [ ] `apm install curl`: resolves, fetches or builds, roots in view, updates profile
- [ ] `apm remove curl`: removes from profile, publishes CRDT removal
- [ ] `apm upgrade`: detects new version in registry, installs new, removes old
- [ ] `apm rollback`: switches to previous profile generation
- [ ] `apm update`: fetches latest registry via sync protocol
- [ ] `apm search`: finds packages by name pattern across registries
- [ ] `apm verify`: NAR hash of installed path matches expected
- [ ] `apm source --verify`: rebuild from .drv produces same output hash
- [ ] Cross-view sharing: installing a package already in another view is instant (no transfer)
- [ ] CRDT propagation: `apm install` on machine A makes package available on machine B

**Tests:**

```rust
#[tokio::test]
async fn install_from_mesh() {
    let cluster = TestCluster::spawn(3, TestConfig::with_registry()).await?;

    // Build a registry with curl on daemon 0
    // apm install curl on daemon 1
    // Verify curl is rooted in daemon 1's view
    // Verify curl is fetchable (chunks came from daemon 0)
}

#[tokio::test]
async fn registry_priority() {
    // Configure two registries: company (600), aos-core (500)
    // Both have openssl but different versions
    // apm install openssl -> gets company's version
}

#[tokio::test]
async fn install_propagates_via_crdt() {
    let cluster = TestCluster::spawn(2, TestConfig::default()).await?;

    // apm install curl on daemon 0
    cluster.client(0).apm_install("curl").await?;

    // Wait for CRDT propagation
    cluster.wait_for_sync_convergence(Duration::from_secs(10)).await?;

    // Verify curl available on daemon 1
    assert!(cluster.client(1).has_package("curl").await?);
}
```

### 10. Shell / Login

**Acceptance Criteria:**

- [ ] `aos shell {universe}` finds a peer with login capability
- [ ] `/aos/shell/1.0.0` stream provides interactive terminal
- [ ] Container has FUSE view scoped to the universe
- [ ] Container has scoped control socket (apm/aos commands auto-scoped)
- [ ] Named shells persist across disconnects (DHT tracks host + status)
- [ ] `aos shell --resume {name}` reconnects to the same container on the same host
- [ ] `aos shell --stop/--delete` stops/destroys the container
- [ ] ZFS dataset created for container writable layer
- [ ] ZFS snapshot works (--snapshot flag or auto-snapshot on failure)
- [ ] Profile activation script runs on container creation and profile update
- [ ] UCAN shell/create capability required; connection without it is rejected
- [ ] Container uses --private-users=pick (UID isolation)

**Tests:**

```rust
#[tokio::test]
async fn shell_create_and_resume() {
    let cluster = TestCluster::spawn(3, TestConfig::with_login()).await?;

    // Create named shell
    let shell = cluster.client(0).shell_create("staging", "mydev").await?;
    assert!(shell.is_running());

    // Run a command inside
    let output = shell.exec("echo hello").await?;
    assert_eq!(output.trim(), "hello");

    // Disconnect
    shell.disconnect().await?;

    // Resume from a different client
    let shell2 = cluster.client(0).shell_resume("mydev").await?;
    assert!(shell2.is_running());

    // Verify same container (file written earlier still exists)
    let output = shell2.exec("cat /tmp/test-file 2>/dev/null || echo missing").await?;
}

#[tokio::test]
async fn shell_zfs_snapshot() {
    // Create shell, write some data
    // Snapshot
    // Write more data
    // Inspect snapshot -- should have first data but not second
}

#[tokio::test]
async fn shell_auto_scoped() {
    // Create shell in universe "staging"
    // Inside shell: apm install curl
    // Verify curl installed in staging view (not some other view)
    // Verify CRDT delta published to sync/staging
}
```

### 11. Observability (aos net)

**Acceptance Criteria:**

- [ ] `aos net status`: returns peer count, active builds, store stats
- [ ] `aos net peers`: lists connected peers with latency, jobs, status
- [ ] `aos net builds`: shows active/recent builds with status
- [ ] `aos net builds --follow`: streams build events in real-time
- [ ] `aos net logs --drv {hash}`: streams logs for a specific build
- [ ] `aos net store find {hash}`: finds providers for a store path
- [ ] `aos net topology`: shows GossipSub mesh graph
- [ ] `aos net latency`: shows per-peer latency from background pings
- [ ] `aos net bandwidth`: shows current and historical bandwidth by protocol
- [ ] `aos net views`: lists views across the mesh
- [ ] `aos net sync status`: shows CRDT consistency across peers
- [ ] `aos net sync wait`: blocks until all peers reach consistency milestone
- [ ] `aos net events --json`: streams events in NDJSON for monitoring tools
- [ ] Prometheus metrics: gauge/counter/histogram metrics exported correctly

**Tests:**

```rust
#[tokio::test]
async fn net_peers_lists_all() {
    let cluster = TestCluster::spawn(5, TestConfig::default()).await?;
    cluster.wait_for_mesh(Duration::from_secs(10)).await?;

    let peers = cluster.client(0).net_peers().await?;
    assert_eq!(peers.len(), 4); // 5 total minus self
}

#[tokio::test]
async fn net_sync_wait() {
    let cluster = TestCluster::spawn(3, TestConfig::default()).await?;

    // Add entry on daemon 0
    cluster.client(0).sync_put("key/1", "hash1").await?;

    // Wait for convergence
    cluster.client(0).sync_wait("", Duration::from_secs(10)).await?;

    // All daemons should now have the entry
}
```

## CI Integration

### Test matrix

```yaml
tests:
  unit:
    runs-on: any
    command: cargo test --workspace
    timeout: 5m

  integration:
    runs-on: [kvm]  # needs FUSE + nspawn
    command: cargo test --workspace --features integration
    timeout: 15m

  multi-node:
    runs-on: [kvm, big-parallel]
    command: cargo test --workspace --features multi-node
    timeout: 30m

  property:
    runs-on: any
    command: cargo test --workspace --features proptest -- --test-threads=1
    timeout: 10m
```

### Feature flags

```toml
[features]
default = []
integration = []    # enables tests that need FUSE, LMDB, real filesystem
multi-node = []     # enables tests that spawn multiple daemon processes
proptest = ["dep:proptest"]  # enables property-based tests
```

## Relationship to Other Docs

- **chunks.md**: Chunk store acceptance criteria test FastCDC, pack files, LMDB, dedup
- **views.md**: View/GC criteria test projections, FUSE modes, LRU eviction, provider TTL
- **sync.md**: Sync criteria test CRDT properties, merkle anti-entropy, consistency milestones
- **auth.md**: Auth criteria test UCAN chains, path permissions, handshake, revocation
- **builds.md**: Build criteria test nspawn isolation, ephemeral views, log streaming
- **daemon.md**: Daemon criteria test lifecycle, control socket, graceful shutdown
- **package.md**: APM criteria test registry resolution, profile management, CRDT propagation
- **mesh.md**: Mesh criteria test discovery, GossipSub, DHT, NAT traversal
