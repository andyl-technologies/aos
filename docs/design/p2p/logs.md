# Log Streaming, Replay, and Durability

This documents log streaming, replay, and durability for the AOS distributed build system using libp2p.

## Overview

Build logs flow through three mechanisms depending on the scenario:
1. **Live streaming**: GossipSub for real-time log fan-out to all interested parties
2. **Replay**: Direct libp2p stream to the daemon peer for late joiners
3. **Fallback**: Peer log cache for when the building daemon is gone

## Live Log Streaming (GossipSub)

Daemon publishes each log line as a GossipSub message:

```
Topic: builds/logs/{drv_hash}
Message: {
  "seq": 42,           // monotonically increasing sequence number
  "kind": "log",       // or "status", "complete", "error"
  "line": "building foo-1.0...",
  "timestamp": 1709900042
}
```

### Building Daemon Side

```rust
let topic = gossipsub::IdentTopic::new(format!("builds/logs/{}", job.drv_hash));
swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

let mut seq = 0u64;
while let Some(line) = stderr_lines.next_line().await? {
    // Buffer locally for replay
    log_buffer.append(LogEvent { seq, kind: "log", line: line.clone(), timestamp: now() });

    // Publish to mesh
    let msg = serde_json::to_vec(&LogEvent { seq, kind: "log", line, timestamp: now() })?;
    swarm.behaviour_mut().gossipsub.publish(topic.clone(), msg)?;
    seq += 1;
}

// Terminal event
let complete = LogEvent { seq, kind: "complete", ... };
log_buffer.append(complete.clone());
swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_vec(&complete)?)?;
```

### HTTP-Serving Daemon Side (Subscriber)

The daemon handling the client request subscribes to `builds/logs/{drv_hash}` when a client requests a build. It translates GossipSub messages to SSE frames:

```rust
// GossipSub message received
fn handle_gossipsub_message(msg: gossipsub::Message, client_tx: &broadcast::Sender<SseFrame>) {
    let event: LogEvent = serde_json::from_slice(&msg.data)?;
    let sse = format!("id: {}\nevent: {}\ndata: {}\n\n", event.seq, event.kind, event.line);
    let _ = client_tx.send(sse);

    // Also cache locally for late-joiner fallback
    log_cache.insert(drv_hash, event);
}
```

Multiple daemons can subscribe to the same topic -- GossipSub fans out automatically. Multiple clients on the same daemon share one subscription via the broadcast channel.

## Log Replay for Late Joiners

GossipSub is ephemeral -- if you weren't subscribed when a message was sent, you missed it. Late-joining clients need historical log lines.

### The Protocol: /aos/log-replay/1.0.0

When a client connects to an HTTP-serving daemon for a build that's already in progress:

1. The daemon looks up the building peer via DHT: `GET("build:{drv_hash}")` -> `{peer_id: daemon_A}`
2. The daemon opens a direct libp2p stream to Daemon A using the `/aos/log-replay/1.0.0` protocol
3. The daemon sends a replay request: `{drv_hash, from_seq: 0}`
4. Daemon A responds with all buffered log lines from seq 0, then keeps the stream open for live tailing

```
HTTP-Serving Daemon                 Daemon A (builder)
  |                                    |
  |  OPEN /aos/log-replay/1.0.0       |
  |  {drv_hash: "abc123", from_seq: 0}|
  |---------------------------------->>|
  |                                    |
  |  <<--- {seq:0, kind:"status", ...} |  --+
  |  <<--- {seq:1, kind:"log", ...}    |    | buffered
  |  <<--- {seq:2, kind:"log", ...}    |    | replay
  |  ...                               |    |
  |  <<--- {seq:500, kind:"log", ...}  |  --+
  |                                    |
  |  <<--- {seq:501, kind:"log", ...}  |  --+
  |  <<--- {seq:502, kind:"log", ...}  |    | live tail
  |  ...                               |    | (stream stays open)
  |                                    |  --+
  |                                    |
  |  <<--- {seq:999, kind:"complete"}  |  stream closes
```

### Building Daemon Handler

```rust
async fn handle_log_replay_request(mut stream: libp2p::Stream, log_buffer: &LogBuffer, log_tx: &broadcast::Sender<LogEvent>) {
    let request: ReplayRequest = read_request(&mut stream).await?;

    // Phase 1: Send buffered history
    for event in log_buffer.events_from(request.from_seq) {
        write_event(&mut stream, &event).await?;
    }

    // Phase 2: Follow live
    let mut rx = log_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => {
                if write_event(&mut stream, &event).await.is_err() {
                    break; // client disconnected
                }
                if matches!(event.kind.as_str(), "complete" | "error") {
                    break; // build done
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}
```

### Log Buffer (Ring Buffer)

The daemon maintains a ring buffer of log events (same concept as the existing `LogBuffer` in aos-server):

```rust
struct LogBuffer {
    events: RwLock<VecDeque<LogEvent>>,
}

const MAX_EVENTS: usize = 100_000;
```

This caps memory usage at ~100K events (~10-50MB depending on line length). For extremely long builds, oldest lines are dropped from the buffer but are still available in the caches of other daemons that subscribed via GossipSub.

## SSE Reconnection

When an SSE client disconnects and reconnects (browser retry, network blip):

1. Client sends `Last-Event-ID: 342` header
2. The daemon requests replay from the builder with `from_seq: 343`
3. Client resumes seamlessly from where it left off
4. Works even if client reconnects to a different HTTP-serving daemon -- the daemon contacts the same builder peer via DHT lookup

## Fallback: Daemon Log Cache

Daemons cache log events they receive via GossipSub. If the building daemon crashes and a late joiner requests logs:

1. The HTTP-serving daemon checks if the builder peer is reachable -- it's not
2. The daemon serves logs from its own cache (partial -- only events received while subscribed)
3. The daemon marks the logs as partial: `{partial: true, reason: "builder_unreachable"}`

Multiple daemons caching the same logs provides redundancy. If daemon A has events 0-300 and daemon B has events 200-500, a smart client or daemon can merge them.

## Durability

Completed build logs are stored locally by the building daemon and by any other
daemon that was subscribed to the build's GossipSub topic. There is no external
archive. If the building daemon and all daemons that cached the log go down, the
log is lost. This is acceptable -- the build can be re-triggered, and the log is
a byproduct, not the artifact.

## Lifecycle Summary

```
Build starts     -> Building daemon buffers locally + publishes to GossipSub
Client connects  -> HTTP-serving daemon subscribes to GossipSub topic (live)
Late joiner      -> HTTP-serving daemon requests replay from builder (direct stream)
Client reconnect -> HTTP-serving daemon requests replay from from_seq (direct stream)
Builder crashes  -> HTTP-serving daemon serves from its own GossipSub cache (partial)
Build completes  -> Building daemon persists log locally; other daemons retain cached copy
Historical query -> Ask peers who cached the log (builder or subscribing daemons)
```

## Message Ordering

GossipSub does not guarantee message ordering. Log events include a `seq` field (monotonically increasing per build). Receivers buffer and reorder:

```rust
fn insert_ordered(buffer: &mut BTreeMap<u64, LogEvent>, event: LogEvent) {
    buffer.insert(event.seq, event);
    // Flush consecutive events to the client
    while let Some(next) = buffer.get(&next_expected_seq) {
        emit_to_client(next);
        next_expected_seq += 1;
    }
}
```

Small gaps (due to network reordering) are resolved within milliseconds. If a gap persists for >1 second, request the missing events from the daemon via the replay protocol.
