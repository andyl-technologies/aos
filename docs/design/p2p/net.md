# `aos net` -- Network Observability and Interaction

## Overview

`aos net` provides full observability into the P2P mesh: peers, builds, store paths, topology, latency, bandwidth, logs, views, and more. It is the operator's window into the distributed build cluster.

All `aos net` subcommands support the `-i`/`--identity` flag to use either the local daemon socket or a CLI-local P2P client.

When used without `-i`, it queries the local daemon (which relays mesh information via its GossipSub/DHT state). When used with `-i <identity>`, it joins the mesh directly as a lightweight client.

## Subcommands

### aos net status

Cluster health summary -- the "dashboard" view.

```
$ aos net status
Cluster: aos-prod (root: QmRoot...)
Mode: full (47 peers, 3 views)
Uptime: 14d 7h 23m

Peers:
  Online:    47
  Draining:  3
  Offline:   2 (last seen >1h ago)

Views:
  default     47 peers   412,391 paths   1.2TB store
  staging     12 peers   89,142 paths    340GB store
  ci           8 peers   23,847 paths    89GB store

Builds:
  Active:    23
  Queued:    7
  Completed: 1,847 (last 24h)
  Failed:    12 (last 24h)

Transfer:
  Inbound:   4.2 GB/h
  Outbound:  3.8 GB/h
  Chunks:    847,291 served (last 24h)

Store:
  Total paths:  847,291 (deduplicated across peers)
  Chunks indexed: 12,847,102
  Dedup ratio:  3.2x (store content vs chunk-unique bytes)
```

**Data source.** This command aggregates local daemon state -- no active network queries are issued.

- **Peer count**: from `Swarm::connected_peers()` (connected peers) combined with the Kademlia routing table (known but not necessarily connected peers). The "offline" count comes from DHT records for peers that have not responded to pings.
- **View info**: aggregated from DHT `daemon:{peer_id}` records. Each daemon periodically publishes a capability record to the DHT advertising the universes it participates in, its store size, and its active job count. The local daemon caches these records and refreshes them every 2 minutes.
- **Build counts**: maintained locally by observing GossipSub messages on `build/claimed/{universe}/{system}` and `build/result/{universe}/{system}` topics. The daemon keeps a rolling window of recent builds in memory (default 24h retention). No DHT or active queries are needed -- all build state is derived from passively received GossipSub messages.
- **Transfer stats**: local byte counters on each libp2p stream, aggregated by protocol. These are computed from the daemon's own connection metrics, not from peer reports.
- **Store/chunk stats**: local chunk index LMDB statistics. The "deduplicated across peers" total is an estimate derived from the union of manifests seen via DHT `daemon:{peer_id}` records, not a precise global count.

### aos net peers

List connected peers with optional detail.

```
$ aos net peers
PEER                 STATUS   VIEWS                 JOBS    LATENCY
QmDaemon1...abc      online   default,staging       4/8     2ms
QmDaemon2...def      online   default,ci            7/8     3ms
QmDaemon3...ghi      online   default               0/4     45ms
QmDaemon4...jkl      draining default,staging       2/8     3ms
QmDaemon5...mno      offline  default               -       -

$ aos net peers --verbose
Shows additional: arch, features, store size, chunk count, uptime,
connected peers count, UCAN expiry, last heartbeat, bandwidth in/out

$ aos net peers --view staging
Filter to peers participating in a specific view

$ aos net peers --json
JSON output for scripting/dashboards
```

**Data source.** Combination of local connection state and DHT records. No active probing is triggered by this command (it reads already-collected data).

- **Connected peers**: `Swarm::connected_peers()` -- immediate, no network call. This is the authoritative list of peers the daemon currently has open connections to.
- **Peer capabilities, arch, features, views, store size**: from DHT `daemon:{peer_id}` value records. The daemon refreshes these records from the DHT every 2 minutes and caches them locally. If a peer's record is missing from cache, it is omitted (not fetched on demand).
- **Latency**: from the libp2p ping protocol (`/ipfs/ping/1.0.0`). The daemon runs a background ping task every 30 seconds against all connected peers. Results are stored in memory with a rolling window (last 100 measurements per peer). The displayed value is the median of recent measurements.
- **Status**: determined from local observations, not from the peer itself. "online" means connected and responding to pings. "draining" means the peer announced drain via a GossipSub message on the `cluster/drain` topic. "offline" means a DHT record exists for the peer but there is no active connection and pings have timed out.
- **Jobs**: derived from observing GossipSub `build/claimed/{universe}/{system}` messages. The daemon tracks which peer claimed which build and updates when `build/result/{universe}/{system}` messages arrive. This is passive observation -- the daemon does not query peers for their job lists.

### aos net builds

Active and recent builds across the mesh.

```
$ aos net builds
VIEW      DRV       PACKAGE      PEER         STATUS    DURATION
staging   abc123    foo-1.0      QmDaemon1    building  2m31s
ci        def456    bar-2.0      QmDaemon2    building  0m45s
staging   ghi789    baz-3.0      QmDaemon1    complete  5m12s
ci        jkl012    qux-1.2      -            queued    0m15s

$ aos net builds --follow
Stream new builds as they start, update status in real-time.
Shows claimed, building, complete, failed transitions.

$ aos net builds --view ci
Filter to builds in a specific view

$ aos net builds --active
Only show in-progress builds (queued + building)

$ aos net builds --failed
Only show failed builds (last 24h by default, --since to override)

$ aos net builds --history --since 7d
Show build history for the last 7 days

$ aos net builds --stats
Build statistics: total, success rate, avg duration, by view, by peer
```

**Data source.** All build data comes from GossipSub observation and local state. The daemon does not poll peers for build status.

- **Job submissions**: observed on GossipSub `build/wanted/{universe}/{system}` topic. When a client submits a build request, the daemon publishes a WANTED message. All peers subscribed to that universe's topic receive it.
- **Claims**: observed on GossipSub `build/claimed/{universe}/{system}` topic. When a peer picks up a build, it publishes a CLAIMED message.
- **Completions/failures**: observed on GossipSub `build/result/{universe}/{system}` topic. The builder publishes the result (success with output hash, or failure with error).
- **Build state table**: the daemon maintains an in-memory `HashMap<DrvHash, BuildState>` updated from GossipSub events. This table has a configurable retention window (default 24h). Entries older than the retention window are dropped from memory. This is the data source for the default `aos net builds` view and for `--active` and `--failed` filters.
- **Build history** (`--history`): the daemon writes completed build records to a local LMDB database for longer-term queries. This database is persisted across daemon restarts. The `--since` flag queries this database rather than the in-memory table.
- **`--follow`**: subscribes to the relevant GossipSub topics (via the control socket's streaming mode) and streams events as they arrive. No polling.

### aos net logs

Build log streaming -- follow logs for specific builds or all builds.

```
$ aos net logs --drv abc123
Stream logs for a specific build (connects to building peer for replay + live tail)

$ aos net logs --view staging --follow
Follow all build logs in a view (multiplexed)

$ aos net logs --peer QmDaemon1 --follow
Follow all builds on a specific peer

$ aos net logs --failed --since 1h
Show logs for recently failed builds (for debugging)
```

**Data source.** Logs come from a combination of GossipSub broadcast and direct peer-to-peer streams.

- **Live logs**: the building peer publishes log lines to GossipSub topic `build/logs/{drv_hash}`. Any peer (or CLI client) subscribed to this topic receives log lines as they are emitted. This is the primary mechanism for `--follow` on active builds.
- **Replay**: for builds that are already in progress or recently completed, the daemon uses the `/aos/log-replay/1.0.0` request-response protocol. This is a direct libp2p stream to the building peer -- the client sends the derivation hash, and the peer streams back all buffered log lines followed by any new lines (if the build is still running).
- **Log source discovery**: the daemon looks up DHT record `build:{drv_hash}` to determine which peer is building (or built) a derivation, then connects to that peer for replay. If the building peer is already a connected peer, the DHT lookup is skipped.
- **`--failed`**: queries the local build history LMDB for recently failed builds, then fetches logs from the builder peer (if still connected) via `/aos/log-replay/1.0.0`, or from peers that cached the logs via GossipSub. If no peer has the logs, the command reports that logs are unavailable.

### aos net store

Query store paths across the mesh.

```
$ aos net store find abc123
Which peers have this store path? Show view membership, chunk status.

PEER          VIEWS            CHUNKS   SIZE     LAST_ACCESS
QmDaemon1     staging          482/482  124MB    2h ago
QmDaemon3     default          482/482  124MB    1d ago
QmDaemon5     default,prod     482/482  124MB    5m ago

$ aos net store providers <hash>
List all peers that respond HAVE for this store path's manifest.

$ aos net store chunks <hash>
Show the chunk manifest for a store path: file tree, chunk count,
chunk hashes, which chunks are available locally vs remote.

$ aos net store search <name-pattern>
Search store paths across the mesh by name pattern.
(Queries manifests on connected peers)

$ aos net store diff <hash1> <hash2>
Compare two store paths chunk-by-chunk. Shows which files differ,
which chunks are shared, estimated transfer size for delta.
Useful for comparing package versions.

$ aos net store size --view staging
Total store size for a view across all peers.
Shows: total, unique (deduplicated), shared overhead.
```

**Data source.** Store commands use a mix of active queries and local index lookups. Several subcommands issue network requests and have associated timeouts.

- **`find`**: broadcasts `WANT_MANIFEST({universe}, {hash})` to connected peers using the AOS content routing protocol. Peers respond with `HAVE` (including their chunk availability) or `DONT_HAVE`. Results are aggregated from all responses received within a 2-second timeout. This is an active fan-out query.
- **`providers`**: same mechanism as `find` but returns the raw peer list without additional metadata. Functionally equivalent to asking "who has this?" across the mesh.
- **`chunks`**: looks up the manifest in the local chunk index (LMDB). If the manifest is not in the local store, the daemon fetches it from a peer via `WANT_MANIFEST` and then displays the chunk tree. The chunk-level availability information (local vs remote) comes from cross-referencing the manifest's chunk list against the local chunk index.
- **`search`**: sends a custom `/aos/store-search/1.0.0` request-response stream to connected peers with the name pattern. Each peer searches its local manifest database and returns matching entries. This is an active fan-out query with a configurable timeout (default 2 seconds). Results are merged and deduplicated by the querying daemon.
- **`diff`**: fetches both manifests (locally or from peers), compares chunk lists, and reports differences. This is pure computation on manifest data once both manifests are obtained. No additional network calls beyond manifest retrieval.
- **`size`**: aggregates store sizes from DHT `daemon:{peer_id}` records for peers in the specified view. This uses cached DHT data, so no active queries are issued. The result reflects the last-known state (up to 2 minutes stale).

### aos net topology

Mesh topology visualization.

```
$ aos net topology
Shows the GossipSub mesh graph: which peers are connected to which,
mesh degree per peer, overlay structure.

PEER          CONNECTIONS   MESH_PEERS   RELAY
QmDaemon1     12            8            no
QmDaemon2     15            8            no
QmDaemon3     3             3            yes (via QmRelay1)
QmDaemon4     8             6            no
...

$ aos net topology --dot
Output in Graphviz DOT format for visualization:
  aos net topology --dot | dot -Tpng > mesh.png

$ aos net topology --view staging
Show topology for a specific view's GossipSub mesh
```

**Data source.** All data comes from the local libp2p node's state. No network queries are issued. This means the output reflects this peer's view of the network, not a global view.

- **GossipSub mesh state**: the `gossipsub::Behaviour` exposes which peers are in the mesh for each topic, along with mesh parameters (D, D_lo, D_hi per topic). The daemon reads this directly from the behaviour's internal state.
- **Kademlia routing table**: the `kad::Behaviour` exposes k-bucket contents, showing which peers are known to the DHT layer and their last-seen timestamps.
- **Connection state**: `Swarm::connected_peers()` with connection metadata including transport type (QUIC, TCP+Noise), connection direction (inbound/outbound), and connection duration.
- **`--dot`**: traverses the above data structures and emits Graphviz DOT output. Nodes are peers, edges are connections, and GossipSub mesh membership is indicated by edge style.
- **Important caveat**: this command shows the LOCAL peer's view of the topology, not a global view. Each peer sees only its own connections and mesh neighbors. For a global topology view, an operator would need to query multiple peers (via `-i` or the `/aos/metrics/1.0.0` protocol) and merge the results.

### aos net latency

Peer-to-peer latency measurement.

The default display shows latency from this peer to all connected peers, sorted by latency. This scales to any mesh size.

```
$ aos net latency
PEER              LATENCY    JITTER    LOSS
QmDaemon1         2ms        0.3ms     0%
QmDaemon4         3ms        0.5ms     0%
QmDaemon2         4ms        0.8ms     0%
QmDaemon3         45ms       2.1ms     0%
QmDaemon7         128ms      12ms      2%
...
(47 peers)
```

The `--matrix` flag produces the full NxN latency matrix. This is useful for small clusters but does not scale. If the mesh has more than 20 peers, a warning is printed suggesting `--region` or `--histogram` instead.

```
$ aos net latency --matrix
              Daemon1  Daemon2  Daemon3  Daemon4
Daemon1       -        2ms      45ms     3ms
Daemon2       2ms      -        47ms     4ms
Daemon3       45ms     47ms     -        44ms
Daemon4       3ms      4ms      44ms     -
(warning: matrix display is unwieldy for >20 peers; consider --region or --histogram)
```

The `--top N` flag shows only the N fastest or slowest peers:

```
$ aos net latency --top 5 --slowest
PEER              LATENCY    JITTER    LOSS
QmDaemon9         312ms      45ms      5%
QmDaemon7         128ms      12ms      2%
QmDaemon3         45ms       2.1ms     0%
QmDaemon12        38ms       1.8ms     0%
QmDaemon8         22ms       1.2ms     0%
```

The `--region` flag groups peers by latency band, giving a quick summary of network locality:

```
$ aos net latency --region
LAN (<5ms):        12 peers   avg 2.3ms
Datacenter (<20ms): 28 peers   avg 8.7ms
Regional (<100ms):  5 peers    avg 67ms
Remote (>100ms):    2 peers    avg 142ms
```

The `--histogram` flag shows a latency distribution as a bar chart:

```
$ aos net latency --histogram
  0-5ms   ████████████████████████  24 peers
  5-20ms  ████████████████          16 peers
  20-50ms ████                       4 peers
  50-100ms██                         2 peers
  100ms+  █                          1 peer
```

The `--peer` flag shows detailed latency to a specific peer, including min/avg/max/p99/jitter/loss:

```
$ aos net latency --peer QmDaemon3
Latency to QmDaemon3:
  Min:    44.2ms
  Avg:    45.4ms
  Max:    48.1ms
  P99:    47.9ms
  Jitter: 1.2ms
  Loss:   0% (0/100)
  Window: last 100 pings (50 min)
```

The `--continuous` flag keeps measuring and reporting latency at a configurable interval (useful for monitoring drift or debugging connectivity issues).

**Data source.** All latency data comes from the libp2p ping protocol (`/ipfs/ping/1.0.0`), which sends a 32-byte payload and measures round-trip time.

- The daemon runs a background ping task every 30 seconds against all connected peers. Results are stored in memory with a rolling window of the last 100 measurements per peer. This background data is the source for the default display, `--region`, `--histogram`, and `--top`.
- **`--peer X`**: actively pings peer X multiple times (like the standard `ping` command), reporting each result as it arrives. This issues new pings rather than reading from the background window.
- **`--continuous`**: keeps pinging at a configurable interval and updates the display.
- **`--matrix`**: for the NxN matrix, latency values between peers OTHER than the local peer are obtained from the `/aos/metrics/1.0.0` protocol -- each peer is queried for its own latency measurements. This requires active network calls and is the reason the matrix is slow for large meshes.

### aos net bandwidth

Network bandwidth monitoring.

```
$ aos net bandwidth
Current and historical bandwidth usage.

DIRECTION   RATE        TOTAL (24h)   TOTAL (7d)
Inbound     12.3 MB/s   4.2 GB        28.7 GB
Outbound    8.7 MB/s    3.8 GB        24.1 GB

By protocol:
  WANT_MANIFEST:  120 KB/s in,   340 KB/s out
  WANT_CHUNK:     11.2 MB/s in,  7.8 MB/s out
  GossipSub:      45 KB/s in,    52 KB/s out
  DHT:            8 KB/s in,     12 KB/s out
  Log streams:    890 KB/s in,   450 KB/s out

$ aos net bandwidth --per-peer
Bandwidth breakdown by peer: who are we transferring the most with?

PEER          INBOUND     OUTBOUND    TOTAL
QmDaemon1     4.2 MB/s    1.1 MB/s    5.3 MB/s
QmDaemon2     3.1 MB/s    2.4 MB/s    5.5 MB/s
QmDaemon3     0.8 MB/s    3.2 MB/s    4.0 MB/s

$ aos net bandwidth --per-view
Bandwidth breakdown by view.

$ aos net bandwidth --follow
Real-time bandwidth monitor (updates every second)

$ aos net bandwidth --history --since 7d
Historical bandwidth graph (hourly averages)
```

**Data source.** All bandwidth data comes from local byte counters. No network queries are issued.

- Each libp2p connection and stream has byte counters (bytes sent and received) maintained by the transport layer. The daemon aggregates these counters by protocol (WANT_MANIFEST, WANT_CHUNK, GossipSub, DHT, log streams, ping), by peer, and by view.
- **Current rate**: computed from a sliding window of the last 10 seconds of byte counts. This gives a smoothed instantaneous rate.
- **Per-protocol breakdown**: each libp2p stream is opened with a protocol identifier, so byte counts are naturally attributed to protocols.
- **Per-view**: derived from per-protocol counters. GossipSub topics are universe-scoped (e.g., `build/wanted/staging/x86_64-linux`), so universe attribution is straightforward. For WANT_CHUNK and WANT_MANIFEST, the universe is encoded in the request.
- **Per-peer**: maintained per-connection. Each connection is to a single peer, so byte counts per connection map directly to per-peer counts.
- **Historical** (`--history`): the daemon writes hourly bandwidth summaries to LMDB. These summaries persist across restarts and allow querying historical trends.
- **`--follow`**: updates the display every second using the sliding window. Uses the control socket's streaming mode.

### aos net views

View information across the mesh.

```
$ aos net views
VIEW         PEERS   PATHS      SIZE     GC_POLICY    PINS
default      47      412,391    1.2TB    ttl=30d      23
staging      12      89,142     340GB    ttl=7d       8
ci           8       23,847     89GB     ttl=24h      0
production   5       156,293    890GB    manual       142

$ aos net views staging
Detailed info for a specific view: peers, GC policy, pins,
recent builds, store size trend.

$ aos net views --pins staging
List pinned closures in a view and which peers have them.
```

**Data source.** View data comes from DHT records and local configuration. Most queries use cached data with no active network calls.

- **Peer count per view**: aggregated from DHT `daemon:{peer_id}` records. Each daemon's capability record lists the universes it participates in. The local daemon caches these records.
- **Store size per view**: each daemon reports its per-universe store size in its DHT capability record. The total is a sum across all peers' reported sizes (not deduplicated).
- **Path count**: same source as store size -- reported per-universe in the DHT capability record.
- **GC policy**: for this daemon's views, read from local configuration. For other daemons' universes, read from their DHT capability records.
- **Pins**: from DHT `pin:{universe}:{hash}` records. Each pin is a separate DHT record.
- **`--pins`**: queries the DHT for all pin records matching the universe prefix. This is an active DHT query (Kademlia GET with prefix iteration) and may take a few seconds for views with many pins.

### aos net identity

Show current identity and capabilities.

```
$ aos net identity
PeerId: QmAbc123...
Mode: daemon socket (/run/aos/control.sock)
Daemon PeerId: QmDaemon1...
Views: default, staging (via daemon)
Capabilities: submit, observe, manage (via daemon local policy, group: aos-admin)

$ aos net identity -i ci
PeerId: QmCi456...
Mode: P2P client (ephemeral)
UCAN issuer: QmRoot... (cluster root)
UCAN expiry: 2026-04-01T00:00:00Z (23 days remaining)
Views: ci
Capabilities: submit, observe
Seed peers: /ip4/1.2.3.4/udp/4001/quic-v1/p2p/QmSeed1
```

**Data source.** All data is read from local state. No network calls are made.

- **Socket mode**: the daemon's identity is read from the control socket (`net-identity` action). The daemon returns its peer ID, views, and the capabilities granted to the connecting user (based on Unix socket peer credentials and local policy).
- **P2P mode** (`-i`): the keypair is read from the identity's `key.ed25519` file, and the UCAN is read from `token.ucan`. The peer ID is derived from the keypair. No network connection is established just to display identity information.
- **Capabilities**: parsed from the UCAN token's `att` (attenuation) field.
- **UCAN expiry**: parsed from the UCAN `exp` field and compared against the current time.

### aos net events

Raw event stream from the mesh -- useful for debugging and monitoring tools.

```
$ aos net events
[12:34:01] peer.connected      QmDaemon5 (default, staging)
[12:34:02] build.claimed       staging:abc123 by QmDaemon1
[12:34:05] build.log           staging:abc123 "configuring..."
[12:34:15] chunk.served        abc123:chunk_47 -> QmDaemon3
[12:34:16] build.complete      ci:def456 (3m12s, 482 chunks)
[12:34:20] gc.started          QmDaemon2 view=ci
[12:34:21] peer.disconnected   QmDaemon4 (draining)

$ aos net events --filter build.*
Only build-related events

$ aos net events --filter "view=staging"
Only events for a specific view

$ aos net events --json
JSON output for piping to monitoring tools (Prometheus, Grafana, etc.)
```

**Data source.** Events come from two sources: GossipSub messages and local daemon lifecycle events.

- **GossipSub events**: all GossipSub messages the daemon receives are translated into typed events. Build-related messages (`build/wanted/{universe}/{system}`, `build/claimed/{universe}/{system}`, `build/result/{universe}/{system}`, `build/logs/{drv_hash}`) become `build.*` events. Chunk transfer messages become `chunk.*` events.
- **Local events**: peer connect/disconnect events come from the libp2p Swarm's `SwarmEvent` stream. GC phase transitions, chunk indexing progress, and build status changes are generated by the daemon's internal subsystems.
- **Event buffer**: the daemon maintains a circular event buffer (configurable size, default 10,000 events) in memory. When `aos net events` is called without `--follow`, it dumps recent events from this buffer. With `--follow`, it streams from the buffer tail plus new events as they arrive.
- **`--filter`**: applied locally to the event stream before display. The filter runs on the daemon side (when using the control socket) or on the CLI side (when using `-i` P2P mode), reducing the data sent over the socket.
- **`--json`**: serializes each event as a JSON line (NDJSON format), suitable for piping to jq, monitoring collectors, or log aggregation systems.

### aos net ping

Direct peer-to-peer connectivity test.

```
$ aos net ping QmDaemon3
PING QmDaemon3 (via libp2p):
  64 bytes: seq=1 time=45.2ms
  64 bytes: seq=2 time=44.8ms
  64 bytes: seq=3 time=46.1ms
--- QmDaemon3 ping statistics ---
3 packets transmitted, 3 received, 0% loss
rtt min/avg/max = 44.8/45.4/46.1 ms
```

**Data source.** Uses the libp2p ping protocol (`/ipfs/ping/1.0.0`) directly. This is an active probe -- each ping opens a stream, sends a 32-byte random payload, and waits for the echo response. The round-trip time is measured from send to receive.

- If the target peer is already connected, the ping stream is opened on the existing connection.
- If the target peer is NOT directly connected, the daemon first performs a Kademlia peer routing query to discover the peer's addresses, establishes a connection, and then pings. This means the first ping may have higher latency due to connection setup.
- The statistics (min/avg/max, loss) are computed from the pings sent during this invocation, not from the background ping window.

## Data Retention

The daemon separates data into three categories based on persistence requirements.

**In-memory (lost on daemon restart):**
- Connected peer list and connection metadata
- Latency measurements (rolling window of 100 per peer)
- Current bandwidth rates (10-second sliding window)
- Build state table (in-memory HashMap, 24h retention window)
- Event buffer (circular buffer, default 10,000 events)
- GossipSub mesh state and Kademlia routing table

**LMDB (persisted across daemon restarts):**
- Build history: completed build records (derivation hash, builder peer, duration, success/failure, output hash). Written when a build completes or fails. Retained indefinitely (or until explicit pruning).
- Bandwidth summaries: hourly aggregates of bytes sent/received by protocol and by view. Used by `aos net bandwidth --history`.
- Chunk index: mapping of store path hashes to chunk manifests. This is the local content-addressable store index.

**Ephemeral (not stored at all):**
- Individual GossipSub messages (processed and discarded after updating in-memory state)
- Raw ping payloads
- DHT query results (cached briefly by Kademlia but not explicitly stored)

## Querying Remote Peers

Several `aos net` subcommands need information from other peers, not just local state. For these cases, the daemon implements the `/aos/metrics/1.0.0` request-response protocol.

Each daemon can serve its local metrics on request. The protocol works as follows:

1. The querying peer opens a `/aos/metrics/1.0.0` stream to the target peer.
2. The request specifies which metric categories are needed (e.g., `latency`, `bandwidth`, `topology`, `builds`).
3. The target peer responds with the requested metrics from its local state.
4. The querying peer aggregates responses from multiple peers.

This protocol is used by:
- `aos net latency --matrix`: queries each peer for its latency measurements to build the NxN matrix.
- `aos net status` in P2P mode (`-i`): queries a sample of peers (not all) and aggregates. In large clusters, the daemon queries a random sample of sqrt(N) peers plus all peers in the Kademlia closest bucket, which gives a statistically representative view without flooding the mesh.
- `aos net topology` when building a broader view: the local view is always available without queries, but operators can request other peers' views via this protocol.

For commands that use DHT records (like `aos net peers`, `aos net views`, `aos net store size`), the DHT itself handles distribution -- records are stored on the peers closest to the record key (per Kademlia), and lookups are routed through the DHT. No direct `/aos/metrics/1.0.0` call is needed.

## The -i / --identity Flag

All `aos net` subcommands support `-i` / `--identity`:

```
# Via daemon socket (default)
aos net peers                    # daemon relays its mesh state

# Via P2P identity
aos net peers -i ci              # join mesh as "ci" identity, query directly
aos net peers -i ~/.aos/dev.ucan # explicit UCAN path
```

When using `-i`, the CLI:
1. Loads the keypair and UCAN from the identity
2. Spins up an ephemeral libp2p peer
3. Joins the mesh via seed peers (from the identity config)
4. Performs the query
5. Exits (unless --follow is specified)

The identity is loaded from `~/.aos/identities/{name}/`:
```
~/.aos/identities/
  ci/
    key.ed25519        # P2P keypair
    token.ucan         # UCAN (capabilities, universes, expiry)
    seed_peers         # mesh entry points (one multiaddr per line)
```

Or from an explicit path to a UCAN file.

## Implementation

### Metrics Collection

Each daemon collects metrics locally and serves them via the control socket:

```json
{"action": "metrics"}
-> {
    "peer_id": "QmDaemon1...",
    "uptime_secs": 1234567,
    "connected_peers": 12,
    "active_builds": 4,
    "store_paths": 412391,
    "chunks_indexed": 3847102,
    "bandwidth": {
      "inbound_bytes_sec": 12300000,
      "outbound_bytes_sec": 8700000,
      "inbound_total_24h": 4200000000,
      "outbound_total_24h": 3800000000,
      "by_protocol": { ... }
    },
    "latency": { ... },
    "views": { ... }
  }
```

For P2P queries (`-i` mode), the client queries peers directly via the `/aos/metrics/1.0.0` request-response protocol (described in the "Querying Remote Peers" section above).

### Daemon Control Socket Extensions

The control socket protocol adds these commands for `aos net`:

```json
{"action": "net-status"}
{"action": "net-peers", "view": "staging", "verbose": true}
{"action": "net-builds", "view": "ci", "active_only": true}
{"action": "net-topology"}
{"action": "net-latency"}
{"action": "net-bandwidth"}
{"action": "net-views"}
{"action": "net-store-find", "hash": "abc123"}
{"action": "net-store-chunks", "hash": "abc123"}
{"action": "net-events", "filter": "build.*"}
{"action": "net-ping", "peer": "QmDaemon3"}
```

### Streaming Commands

Commands with `--follow` use the control socket's streaming capability:

```json
{"action": "net-events", "follow": true, "filter": "build.*"}
-> {"event": "build.claimed", "view": "staging", "drv": "abc123", ...}
-> {"event": "build.log", "drv": "abc123", "line": "configuring...", ...}
-> {"event": "build.complete", "drv": "abc123", ...}
-> ... (continuous stream)
```

### Prometheus / Grafana Integration

The daemon can optionally expose metrics in Prometheus format:

```toml
[metrics]
prometheus_listen = "0.0.0.0:9090"  # optional
```

Or `aos net events --json` can be piped to a metrics collector.

Metrics exported:

- `aos_peers_connected` (gauge, labels: view)
- `aos_builds_active` (gauge, labels: view, peer)
- `aos_builds_total` (counter, labels: view, status)
- `aos_build_duration_seconds` (histogram, labels: view)
- `aos_bandwidth_bytes_total` (counter, labels: direction, protocol)
- `aos_store_paths` (gauge, labels: view)
- `aos_chunks_served_total` (counter)
- `aos_chunk_dedup_ratio` (gauge)
- `aos_gc_runs_total` (counter, labels: view, phase)
- `aos_latency_seconds` (histogram, labels: peer)

## Relationship to Other Commands

| Command | Uses `-i`? | Transport |
|---------|-----------|-----------|
| `aos build` | Optional | Socket (default) or P2P |
| `aos net` | Optional | Socket (default) or P2P |
| `aos view` | No | Socket only (daemon manages views) |
| `aos gc` | No | Socket only (daemon runs GC) |
| `aos store` | No | Socket only (daemon manages store) |
| `aos auth` | No | Local filesystem (key operations) |
| `aos package` | No | Socket + registry (package management) |
| `aos fmt/lint/...` | No | Local only (no daemon needed) |
