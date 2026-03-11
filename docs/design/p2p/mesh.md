# libp2p Mesh Formation, Peer Discovery, and NAT Traversal

This document specifies how AOS daemon and client nodes form a peer-to-peer
mesh using rust-libp2p. The mesh carries build job announcements, claim
messages, completion notifications, and log streams over GossipSub, while
Kademlia and mDNS handle peer discovery across LAN and WAN boundaries. A
layered NAT traversal strategy ensures builders behind residential or cloud NATs
can participate without VPN tunnels or manual port forwarding.

Two peer types participate in the mesh:

- **Daemons** -- long-lived processes that build, serve store paths, and relay.
  Daemons hold full-capability UCANs and participate in all GossipSub topics.
- **Clients** -- ephemeral or long-lived processes that request builds, tail
  logs, and fetch store paths. Clients hold limited-capability UCANs (e.g.,
  `build/submit`, `build/observe`) and do not claim or execute build jobs.

All code examples target `libp2p 0.54+` with the `tokio` async runtime.

---

## Peer Discovery

### LAN Discovery (mDNS)

On local networks (development machines, on-prem build clusters sharing a
subnet), peers discover each other via multicast DNS with zero configuration.
Each peer announces its presence by publishing a DNS-SD record containing its
PeerId and listening multiaddrs. Other peers on the same broadcast domain
receive these announcements and immediately dial.

No seed nodes are required for LAN-only operation. A developer starting two
builder daemons on the same machine or two machines on the same office network
will see them form a mesh within seconds.

mDNS is enabled unconditionally. On networks where multicast is blocked (most
cloud VPCs), mDNS simply produces no events and Kademlia handles discovery
instead.

```rust
use libp2p::mdns;
use std::time::Duration;

let mdns_config = mdns::Config {
    ttl: Duration::from_secs(300),
    query_interval: Duration::from_secs(30),
    enable_ipv6: false,
};

let mdns_behaviour = mdns::tokio::Behaviour::new(mdns_config, local_peer_id)?;
```

When mDNS discovers a peer, the `MdnsEvent::Discovered` event fires with the
peer's ID and multiaddrs. The swarm event handler adds these addresses to the
Kademlia routing table so that LAN-discovered peers also participate in DHT
queries:

```rust
SwarmEvent::Behaviour(AosBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
    for (peer_id, multiaddr) in peers {
        log::info!("mDNS discovered peer {peer_id} at {multiaddr}");
        swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
    }
}
```

### WAN Discovery (Kademlia DHT)

For peers across different networks, data centers, or cloud regions, Kademlia
provides a structured overlay for peer routing. Once a node connects to any
single existing mesh participant, its Kademlia routing table populates
automatically through iterative lookups. The node performs a `FIND_NODE` query
for its own PeerId, which causes it to discover peers at exponentially
increasing distances in the key space. Within a few seconds the new node has a
representative sample of the full mesh.

```rust
use libp2p::kad::{self, store::MemoryStore, Config as KadConfig, Mode};

let mut kad_config = KadConfig::new(
    libp2p::StreamProtocol::new("/aos/kad/1.0.0"),
);
// How long a record lives in the DHT before expiring.
kad_config.set_record_ttl(Some(Duration::from_secs(3600)));
// How often a node re-publishes its records.
kad_config.set_publication_interval(Some(Duration::from_secs(600)));
// Replication factor: how many peers store each record.
kad_config.set_replication_factor(
    std::num::NonZeroUsize::new(20).expect("nonzero"),
);

let store = MemoryStore::new(local_peer_id);
let mut kademlia = kad::Behaviour::new(local_peer_id, store);
kademlia.set_mode(Some(Mode::Server));
```

On startup, the node bootstraps by connecting to seed peers and issuing a
bootstrap query:

```rust
// Add seed peers to the routing table.
for (peer_id, addr) in &seed_peers {
    kademlia.add_address(peer_id, addr.clone());
}

// Initiate bootstrap: performs FIND_NODE for our own PeerId,
// populating the routing table with nearby peers.
kademlia.bootstrap()?;
```

After bootstrap completes, the node is fully integrated into the DHT. It will
answer routing queries from other peers and propagate address information
throughout the mesh.

### Seed Nodes

Seed nodes are ordinary peers listed in the daemon configuration so that new
nodes have at least one address to dial on first startup. They have no special
role, no elevated privileges, and no unique state. Any long-lived peer can serve
as a seed node -- the only requirement is a stable multiaddr.

Configuration in the AOS daemon config file:

```toml
[mesh]
seed_peers = [
    "/ip4/198.51.100.10/udp/4001/quic-v1/p2p/12D3KooWExampleSeed1...",
    "/ip4/203.0.113.20/udp/4001/quic-v1/p2p/12D3KooWExampleSeed2...",
]
```

Parsed and applied at startup:

```rust
use libp2p::{Multiaddr, PeerId};

/// Parse a multiaddr that ends with /p2p/<peer_id> into its components.
fn parse_seed(s: &str) -> anyhow::Result<(PeerId, Multiaddr)> {
    let addr: Multiaddr = s.parse()?;
    let peer_id = addr
        .iter()
        .find_map(|proto| match proto {
            libp2p::multiaddr::Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("seed multiaddr missing /p2p/ component"))?;

    // Strip the /p2p/ suffix for the dial address.
    let dial_addr: Multiaddr = addr
        .iter()
        .filter(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
        .collect();

    Ok((peer_id, dial_addr))
}
```

Multiple seeds provide redundancy, but even a single reachable seed is
sufficient to join the mesh. If all seeds are unreachable, the node falls back
to mDNS for LAN discovery and retries seed connections on a backoff schedule.

The mesh survives the permanent loss of every seed node. Once peers have
discovered each other through the DHT, they maintain direct connections and
continue to exchange routing information independently of the original seeds.

---

## Mesh Formation

### Combined NetworkBehaviour

All protocols are composed into a single `NetworkBehaviour` derive struct. This
is the standard rust-libp2p pattern for combining multiple sub-protocols into
one cohesive swarm behaviour:

```rust
use libp2p::{
    autonat, gossipsub, identify, kad, mdns, relay,
    swarm::NetworkBehaviour,
};
use libp2p_stream;

#[derive(NetworkBehaviour)]
struct AosBehaviour {
    /// LAN peer discovery via multicast DNS.
    mdns: mdns::tokio::Behaviour,
    /// WAN peer discovery and routing via Kademlia DHT.
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Pub/sub messaging for build coordination.
    gossipsub: gossipsub::Behaviour,
    /// Multiplexed byte streams for direct file transfers (store path exchange).
    stream: libp2p_stream::Behaviour,
    /// NAT detection: asks peers to probe our reachability.
    autonat: autonat::Behaviour,
    /// Relay client: connect through relay peers when behind NAT.
    relay_client: relay::client::Behaviour,
    /// Peer identification: exchange listen addresses and protocol support.
    identify: identify::Behaviour,
    /// Connection gating: block peers whose UCANs have been revoked.
    allow_block_list: libp2p::allow_block_list::Behaviour<libp2p::allow_block_list::BlockedPeers>,
}
```

Each sub-behaviour produces its own event type. The `#[derive(NetworkBehaviour)]`
macro generates an `AosBehaviourEvent` enum with a variant per sub-behaviour.
The swarm event loop matches on this enum to dispatch events.

### The Identify Protocol and Kademlia Address Propagation

The Identify protocol is critical for Kademlia to function correctly. When two
peers connect, they exchange `Identify` messages containing:

- Their PeerId
- Their observed address of the remote peer (the address as seen from the other
  side of the connection, which may differ from the local listen address due to
  NAT)
- Their listen addresses
- Supported protocols

This information feeds into Kademlia in two ways:

1. **External address discovery**: When peer B tells peer A "I see you at
   address X", peer A learns its own external address. This is essential for
   peers behind NAT -- without Identify, they would only know their private
   LAN address and could not advertise a routable address in the DHT.

2. **Address book updates**: The listen addresses reported by a remote peer are
   added to Kademlia's routing table, allowing the DHT to route queries to
   that peer.

```rust
use libp2p::identify;

let identify_config = identify::Config::new(
    "/aos/id/1.0.0".to_string(),
    local_keypair.public(),
)
.with_push_listen_addr_updates(true)
.with_interval(Duration::from_secs(300));

let identify_behaviour = identify::Behaviour::new(identify_config);
```

Handling Identify events to feed Kademlia:

```rust
SwarmEvent::Behaviour(AosBehaviourEvent::Identify(identify::Event::Received {
    peer_id,
    info,
    ..
})) => {
    // Add all reported listen addresses to the Kademlia routing table.
    for addr in &info.listen_addrs {
        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
    }

    // If the remote peer reported our external address, add it as an
    // external address so we advertise it in the DHT.
    if let Some(observed) = info.observed_addr {
        swarm.add_external_address(observed);
    }
}
```

### Swarm Setup with QUIC Transport

QUIC is the primary transport. It provides encryption (TLS 1.3), multiplexing,
and UDP-based connectivity in a single layer, eliminating the need for
separate Noise + Yamux configuration. UDP-based transport is also significantly
better for NAT traversal than TCP.

```rust
use libp2p::{identity, noise, quic, relay, SwarmBuilder};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let local_keypair = identity::Keypair::generate_ed25519();
    let local_peer_id = local_keypair.public().to_peer_id();

    log::info!("Local PeerId: {local_peer_id}");

    let mut swarm = SwarmBuilder::with_existing_identity(local_keypair.clone())
        .with_tokio()
        .with_quic()
        // Also support relayed connections for NAT traversal.
        .with_relay_client(noise::Config::new, libp2p::yamux::Config::default)?
        .with_behaviour(|keypair| {
            let peer_id = keypair.public().to_peer_id();

            // mDNS for LAN discovery.
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                peer_id,
            )?;

            // Kademlia for WAN discovery.
            let store = kad::store::MemoryStore::new(peer_id);
            let mut kademlia = kad::Behaviour::new(peer_id, store);
            kademlia.set_mode(Some(kad::Mode::Server));

            // GossipSub for pub/sub messaging.
            let gossipsub = build_gossipsub(keypair)?;

            // Stream protocol for direct transfers.
            let stream = libp2p_stream::Behaviour::new();

            // AutoNAT for reachability detection.
            let autonat = autonat::Behaviour::new(peer_id, Default::default());

            // Relay client for NAT traversal.
            let relay_client = relay::client::Behaviour::new(
                peer_id,
                Default::default(),
            );

            // Identify for address exchange.
            let identify = identify::Behaviour::new(
                identify::Config::new(
                    "/aos/id/1.0.0".to_string(),
                    keypair.public(),
                ),
            );

            Ok(AosBehaviour {
                mdns,
                kademlia,
                gossipsub,
                stream,
                autonat,
                relay_client,
                identify,
            })
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(Duration::from_secs(60))
        })
        .build();

    // Listen on QUIC.
    swarm.listen_on("/ip4/0.0.0.0/udp/4001/quic-v1".parse()?)?;
    swarm.listen_on("/ip6/::/udp/4001/quic-v1".parse()?)?;

    // Bootstrap from seed peers.
    let seed_peers = config.mesh.seed_peers.clone();
    for seed in &seed_peers {
        let (peer_id, addr) = parse_seed(seed)?;
        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        swarm.dial(addr)?;
    }
    swarm.behaviour_mut().kademlia.bootstrap()?;

    // Subscribe to build coordination topics (universe-scoped).
    // Each daemon subscribes to topics for the universes it serves.
    for universe in &config.universes {
        for system in &config.systems {
            let topics = [
                gossipsub::IdentTopic::new(format!("build/wanted/{universe}/{system}")),
                gossipsub::IdentTopic::new(format!("build/claimed/{universe}/{system}")),
                gossipsub::IdentTopic::new(format!("build/result/{universe}/{system}")),
            ];
            for topic in &topics {
                swarm.behaviour_mut().gossipsub.subscribe(topic)?;
            }
        }
    }

    // Main event loop.
    loop {
        let event = swarm.select_next_some().await;
        handle_swarm_event(&mut swarm, event).await?;
    }
}
```

---

## GossipSub Configuration

GossipSub is the pub/sub layer that carries all build coordination messages.
It maintains a partial mesh of peers per topic, forwarding messages through
the mesh with logarithmic amplification via gossip.

### Mesh Parameters

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `D` | 6 | Target number of mesh peers per topic |
| `D_lo` | 4 | Minimum mesh peers before grafting |
| `D_hi` | 12 | Maximum mesh peers before pruning |
| `D_lazy` | 6 | Peers to gossip IHAVE messages to |
| Heartbeat | 5s | Interval for mesh maintenance |

These are the standard GossipSub v1.1 defaults and work well for meshes up to
thousands of peers.

### Message Authentication and UCAN Validation

All messages are signed with the publishing peer's identity key (the same
Ed25519 key used for TLS/Noise). This prevents message forgery and allows peers
to attribute messages to their source for scoring purposes.

In addition to the Ed25519 signature, every GossipSub message carries a UCAN in
its envelope. The GossipSub validation callback verifies the UCAN before
accepting the message (see the Security section for details). Messages with
missing, expired, or insufficient-capability UCANs are rejected, which triggers
peer scoring penalties and eventual mesh pruning.

### Topic Structure

The mesh uses four topic families:

- **`build/wanted/{universe}/{system}`** -- Published by the daemon handling a client
  request when a build is requested. Contains the derivation hash, output hash
  (if known), and builder requirements (architecture, features). Daemons
  subscribe to the universe+system-scoped topics for universes and architectures
  they serve.

- **`build/claimed/{universe}/{system}`** -- Published by a daemon when it accepts a job.
  Contains the derivation hash and the claiming peer's ID. Prevents duplicate
  work: other daemons that see a claim for a derivation they were about to
  build will back off (with configurable contention resolution).

- **`build/result/{universe}/{system}`** -- Published when a build completes (success or
  failure). Contains the derivation hash, output store path, output hash, and
  build duration. Other daemons subscribe to learn where to fetch results.

- **`build/logs/{drv_hash}`** -- Per-build log streaming. Subscribers receive
  incremental log output in real time. Peers subscribe on demand when a user
  requests log tailing and unsubscribe when the build completes or the user
  disconnects.

### GossipSub Construction

```rust
use libp2p::gossipsub::{self, MessageAuthenticity, ValidationMode};
use std::time::Duration;

fn build_gossipsub(
    keypair: &identity::Keypair,
) -> anyhow::Result<gossipsub::Behaviour> {
    let config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(5))
        .validation_mode(ValidationMode::Strict)
        // Duplicate detection window. Messages seen within this window
        // are not re-forwarded.
        .duplicate_cache_time(Duration::from_secs(60))
        // Maximum message size: 256 KiB (log chunks can be large).
        .max_transmit_size(256 * 1024)
        // Mesh parameters (using defaults, listed explicitly for clarity).
        .mesh_n(6)
        .mesh_n_low(4)
        .mesh_n_high(12)
        .gossip_lazy(6)
        .build()
        .map_err(|e| anyhow::anyhow!("gossipsub config error: {e}"))?;

    let mut behaviour = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        config,
    )?;

    // Register a validation callback that checks UCANs on every inbound
    // message.  Messages with invalid or missing UCANs are rejected, which
    // feeds into peer scoring (invalid_message_deliveries_weight).
    // In open-mesh mode (see Security section) this callback accepts all
    // messages unconditionally.
    behaviour.set_message_validation_callback(move |peer_id, message| {
        validate_ucan_message(peer_id, message, &ucan_verifier)
    });

    Ok(behaviour)
}
```

### Message Handling

```rust
SwarmEvent::Behaviour(AosBehaviourEvent::Gossipsub(gossipsub::Event::Message {
    propagation_source,
    message_id,
    message,
})) => {
    let topic = message.topic.as_str();
    let data = &message.data;

    match topic {
        t if t.starts_with("build/wanted/") => {
            let job: BuildJob = serde_json::from_slice(data)?;
            log::info!(
                "Build wanted: {} (from {propagation_source})",
                job.drv_hash,
            );
            handle_build_request(&mut swarm, job).await?;
        }
        t if t.starts_with("build/claimed/") => {
            let claim: BuildClaim = serde_json::from_slice(data)?;
            log::info!(
                "Build claimed: {} by {}",
                claim.drv_hash,
                claim.builder_peer_id,
            );
            handle_build_claim(&mut state, claim);
        }
        t if t.starts_with("build/result/") => {
            let result: BuildResult = serde_json::from_slice(data)?;
            log::info!(
                "Build result: {} -> {:?}",
                result.drv_hash,
                result.outcome,
            );
            handle_build_result(&mut state, result).await?;
        }
        t if t.starts_with("build/logs/") => {
            let drv_hash = &t["build/logs/".len()..];
            handle_log_chunk(drv_hash, data).await?;
        }
        _ => {
            log::warn!("Unknown topic: {topic}");
        }
    }
}
```

---

## NAT Traversal

NAT traversal is critical for a practical distributed build system. Builders
may be behind residential NATs, corporate firewalls, or cloud security groups.
AOS uses a layered strategy where each layer handles progressively harder NAT
scenarios.

### Layer 1: QUIC Transport (UDP)

QUIC operates over UDP, which traverses NATs more reliably than TCP. Many NATs
maintain UDP mappings for longer periods, and UDP hole punching has a higher
success rate than TCP simultaneous open. By using QUIC as the primary transport,
a significant fraction of NAT scenarios are handled without any additional
protocol support.

QUIC also provides TLS 1.3 encryption and stream multiplexing, so there is no
need for a separate encryption layer (Noise) or multiplexer (Yamux) on QUIC
connections.

### Layer 2: AutoNAT (Reachability Detection)

AutoNAT allows a peer to determine whether it is publicly reachable. The peer
asks other peers to attempt an inbound connection to its advertised addresses.
If those probes succeed, the peer knows it is publicly reachable and advertises
its addresses in the DHT with confidence. If the probes fail, the peer knows it
is behind a NAT and should activate relay-based connectivity.

```rust
use libp2p::autonat;

let autonat_config = autonat::Config {
    // How often to re-check reachability.
    retry_interval: Duration::from_secs(60),
    // How long to wait for a probe response.
    timeout: Duration::from_secs(30),
    // Number of peers to ask for probes.
    boot_delay: Duration::from_secs(15),
    ..Default::default()
};

let autonat_behaviour = autonat::Behaviour::new(local_peer_id, autonat_config);
```

Handling AutoNAT status changes:

```rust
SwarmEvent::Behaviour(AosBehaviourEvent::Autonat(autonat::Event::StatusChanged {
    old,
    new,
})) => {
    log::info!("NAT status changed: {old:?} -> {new:?}");
    match new {
        autonat::NatStatus::Public(addr) => {
            log::info!("Publicly reachable at {addr}");
            swarm.add_external_address(addr);
        }
        autonat::NatStatus::Private => {
            log::info!("Behind NAT, activating relay listeners");
            activate_relay_reservations(&mut swarm).await?;
        }
        autonat::NatStatus::Unknown => {
            log::info!("NAT status unknown, will retry");
        }
    }
}
```

### Layer 3: Circuit Relay (Indirect Connectivity)

When a peer determines it is behind NAT (via AutoNAT), it makes a reservation
on one or more relay peers. A relay peer is any publicly reachable peer that
has opted into relaying -- there is no dedicated relay infrastructure. The
NATed peer then advertises its relay address (e.g.,
`/ip4/1.2.3.4/udp/4001/quic-v1/p2p/QmRelay/p2p-circuit/p2p/QmNatted`) in
the DHT. Other peers can reach it by connecting through the relay.

Relay connections have higher latency and limited bandwidth compared to direct
connections, so they are used as a fallback and as a stepping stone for hole
punching (Layer 4).

```rust
/// Listen on relay addresses when behind NAT.
async fn activate_relay_reservations(
    swarm: &mut Swarm<AosBehaviour>,
) -> anyhow::Result<()> {
    // Find publicly reachable peers to use as relays.
    // In practice, choose peers with high uptime and low latency.
    let relay_candidates = find_relay_candidates(swarm);

    for relay_peer_id in relay_candidates.iter().take(3) {
        let relay_addr: Multiaddr = format!(
            "/p2p/{relay_peer_id}/p2p-circuit"
        ).parse()?;

        match swarm.listen_on(relay_addr.clone()) {
            Ok(_) => log::info!("Listening via relay {relay_peer_id}"),
            Err(e) => log::warn!("Failed to listen on relay {relay_peer_id}: {e}"),
        }
    }

    Ok(())
}
```

For a peer to act as a relay, it must include `relay::Behaviour` (the server
side) in its `NetworkBehaviour`. Publicly reachable peers should enable this
by default to strengthen the mesh:

```rust
use libp2p::relay;

// Server-side relay behaviour (for publicly reachable peers).
let relay_server = relay::Behaviour::new(
    local_peer_id,
    relay::Config {
        max_reservations: 128,
        max_circuits: 64,
        max_circuits_per_peer: 4,
        reservation_duration: Duration::from_secs(3600),
        max_circuit_duration: Duration::from_secs(300),
        max_circuit_bytes: 1 << 20, // 1 MiB per circuit
        ..Default::default()
    },
);
```

### Layer 4: DCUtR (Direct Connection Upgrade through Relay)

DCUtR is the final layer. After two peers establish a relay connection, they
attempt to upgrade to a direct connection via coordinated hole punching. The
protocol works as follows:

1. Peer A connects to Peer B through a relay.
2. Peer A sends a `CONNECT` message to Peer B (via the relay) containing its
   observed addresses and locally bound addresses.
3. Peer B responds with its own addresses.
4. Both peers simultaneously send UDP packets to each other's addresses,
   punching holes in their respective NATs.
5. If hole punching succeeds, the relay connection is dropped in favor of the
   direct connection.

DCUtR succeeds for the majority of NAT types (full cone, restricted cone,
port-restricted cone). It fails only for symmetric NATs, which are uncommon in
residential and cloud environments. For symmetric NATs, the relay connection
remains as the permanent transport.

```rust
use libp2p::dcutr;

// DCUtR is enabled automatically when relay_client is present.
// The swarm builder handles this. No additional configuration
// is needed beyond including relay_client in the behaviour.

// The event indicates a successful upgrade:
SwarmEvent::Behaviour(AosBehaviourEvent::RelayClient(
    relay::client::Event::ReservationReqAccepted { relay_peer_id, .. }
)) => {
    log::info!("Relay reservation accepted by {relay_peer_id}");
}
```

### NAT Traversal Decision Flow

The following summarizes the decision logic at startup and when NAT status
changes:

```
Startup
  |
  +-> Listen on QUIC (UDP :4001)
  +-> Connect to seed peers
  +-> Bootstrap Kademlia
  +-> AutoNAT begins probing
  |
  +-> AutoNAT result: Public
  |     +-> Advertise direct addresses in DHT
  |     +-> Enable relay server (help others traverse NAT)
  |     +-> Done: fully reachable
  |
  +-> AutoNAT result: Private (behind NAT)
        +-> Find relay candidates (publicly reachable peers)
        +-> Make relay reservations (up to 3 relays for redundancy)
        +-> Advertise relay addresses in DHT
        +-> On each inbound relay connection:
              +-> DCUtR attempts hole punch
              +-> If successful: use direct connection, drop relay
              +-> If failed: keep relay connection
```

---

## Connection Management

### Connection Limits

Connection limits prevent resource exhaustion from peers opening too many
connections:

```rust
use libp2p::connection_limits;

let connection_limits = connection_limits::Behaviour::new(
    connection_limits::ConnectionLimits::default()
        .with_max_established_incoming(Some(50))
        .with_max_established_outgoing(Some(50))
        .with_max_established_per_peer(Some(5))
        .with_max_pending_incoming(Some(20))
        .with_max_pending_outgoing(Some(20)),
);
```

These limits are configurable in the daemon config file. Nodes that serve many
HTTP clients may increase the inbound limit. Lightweight nodes that only perform
builds may decrease both limits.

### Idle Connection Timeout

Connections without activity are closed after 60 seconds. This is set in the
swarm configuration:

```rust
.with_swarm_config(|cfg| {
    cfg.with_idle_connection_timeout(Duration::from_secs(60))
})
```

GossipSub heartbeats (every 5 seconds) count as activity. Peers subscribed to
the same GossipSub topics remain connected indefinitely because the heartbeat
keeps the connection alive. Peers that share no topics and have no active
streams will be disconnected after the timeout.

### Keep-Alive Semantics

The practical effect is a two-tier connectivity model:

- **Mesh peers** (same GossipSub topics): permanent connections maintained by
  heartbeats. Daemons subscribe to universe+system-scoped topics (`build/wanted/{universe}/{system}`,
  `build/claimed/{universe}/{system}`, `build/result/{universe}/{system}`) for their configured
  universes and architectures, so they stay connected as long as the processes run.

- **DHT-only peers** (no shared topics): transient connections for Kademlia
  queries. These connections are opened on demand, used for routing table
  maintenance, and closed after the idle timeout.

### Peer Scoring

GossipSub v1.1 includes a peer scoring system that penalizes misbehaving peers:

```rust
use libp2p::gossipsub::{PeerScoreParams, PeerScoreThresholds, TopicScoreParams};

let mut peer_score_params = PeerScoreParams::default();

// Per-topic scoring: reward peers that actively participate.
let topic_params = TopicScoreParams {
    // Weight of this topic in overall score.
    topic_weight: 1.0,
    // Reward for being in the mesh.
    mesh_message_deliveries_weight: 1.0,
    mesh_message_deliveries_threshold: 1.0,
    mesh_message_deliveries_decay: 0.9,
    mesh_message_deliveries_cap: 100.0,
    // Penalize peers that don't forward messages.
    mesh_failure_penalty_weight: -1.0,
    mesh_failure_penalty_decay: 0.5,
    // Penalize peers that send invalid messages.
    invalid_message_deliveries_weight: -10.0,
    invalid_message_deliveries_decay: 0.3,
    ..Default::default()
};

// Apply scoring to universe+system-scoped topics for each configured universe and system.
for universe in &config.universes {
    for prefix in ["build/wanted", "build/claimed", "build/result"] {
        for system in &config.systems {
            let topic_hash = gossipsub::IdentTopic::new(format!("{prefix}/{universe}/{system}")).hash();
            peer_score_params.topics.insert(topic_hash, topic_params.clone());
        }
    }
}

let thresholds = PeerScoreThresholds {
    // Below this score, a peer is removed from the mesh.
    gossip_threshold: -100.0,
    // Below this score, a peer's messages are not forwarded.
    publish_threshold: -200.0,
    // Below this score, a peer is disconnected.
    graylist_threshold: -500.0,
    ..Default::default()
};

swarm.behaviour_mut().gossipsub.with_peer_score(
    peer_score_params,
    thresholds,
)?;
```

Peers that consistently fail to forward messages, send invalid data, or abuse
the mesh will see their score decay below the gossip threshold, causing them to
be pruned from the mesh overlay. This prevents freeloading and protects the
mesh from misbehaving nodes.

---

## Security

Security in the AOS mesh is enforced at two layers: transport-level identity
verification and application-level UCAN authorization. Together they ensure
that only authenticated, authorized peers can participate in build coordination.

### Transport Layer: TLS 1.3 / Noise (PeerId Verification)

All connections are encrypted at the transport layer:

- **QUIC connections** use TLS 1.3 with the peer's Ed25519 identity key.
  The libp2p QUIC implementation derives a self-signed X.509 certificate from
  the peer's identity key and validates the remote peer's certificate against
  its expected PeerId during the TLS handshake.

- **Relay connections** (which use TCP+Yamux under the hood for the relay hop)
  are encrypted with the Noise XX handshake pattern, also using the peer's
  Ed25519 identity key.

In both cases, the peer's identity is cryptographically verified during
connection establishment. A man-in-the-middle cannot impersonate a peer
without possessing its private key. Every peer has a unique PeerId derived from
the SHA-256 hash of its Ed25519 public key, so there is no anonymous
participation in the mesh.

The transport layer answers the question "who is this peer?" but not "is this
peer allowed to participate?" -- that is handled by the application layer.

### Application Layer: UCAN Verification via `/aos/auth/1.0.0`

After the libp2p transport handshake authenticates the remote PeerId, the AOS
auth protocol runs as an application-level handshake before the peer is admitted
to GossipSub and Kademlia. The protocol is negotiated as `/aos/auth/1.0.0` on
the libp2p stream multiplexer.

The handshake proceeds as follows:

1. The connecting peer opens a `/aos/auth/1.0.0` stream.
2. It sends its UCAN chain (the leaf UCAN plus any proof UCANs needed for
   delegation verification).
3. The receiving peer validates the UCAN: checks the signature chain, verifies
   the `iss` field matches the remote PeerId, confirms the UCAN has not expired,
   and checks that the granted capabilities are sufficient for the peer type
   (daemon or client).
4. The receiving peer responds with `AUTH_OK` or `AUTH_DENIED`.
5. If `AUTH_OK`, the peer is added to the GossipSub mesh and Kademlia routing
   table normally. If `AUTH_DENIED`, the connection is closed.

Daemons present UCANs with full capabilities (`build/submit`, `build/claim`,
`store/serve`, `store/fetch`, `admin/manage`). Clients present UCANs with
limited capabilities (e.g., `build/submit`, `build/observe`). The receiving
peer checks that the UCAN capabilities match the peer's intended role.

### GossipSub Message Validation

Beyond the connection-time handshake, every GossipSub message carries a UCAN
in its envelope. The GossipSub validation callback rejects messages with
invalid, expired, or insufficient-capability UCANs:

```rust
/// GossipSub validation callback that checks the UCAN in each message.
fn validate_ucan_message(
    peer_id: &PeerId,
    message: &gossipsub::Message,
    ucan_verifier: &UcanVerifier,
) -> gossipsub::MessageAcceptance {
    let envelope: MessageEnvelope = match serde_json::from_slice(&message.data) {
        Ok(env) => env,
        Err(_) => return gossipsub::MessageAcceptance::Reject,
    };

    // Verify the UCAN: valid signature chain, not expired, issuer matches
    // PeerId, and capabilities permit this message type.
    match ucan_verifier.verify(&envelope.ucan, peer_id, &envelope.required_capability()) {
        Ok(true) => gossipsub::MessageAcceptance::Accept,
        Ok(false) => {
            log::warn!("UCAN validation failed for peer {peer_id}");
            gossipsub::MessageAcceptance::Reject
        }
        Err(e) => {
            log::error!("UCAN verification error: {e}");
            gossipsub::MessageAcceptance::Ignore
        }
    }
}
```

Rejected messages feed into GossipSub peer scoring
(`invalid_message_deliveries_weight`). A peer that repeatedly sends messages
with bad UCANs will have its score decay below the gossip threshold, causing it
to be pruned from the mesh overlay.

### Connection Gating: Emergency Revocation

For emergency revocation of compromised or misbehaving peers, the mesh uses
`libp2p-allow-block-list`. When a UCAN is revoked (e.g., via a revocation list
update or operator action), the peer's PeerId is added to the block list. This
immediately terminates existing connections and prevents new ones:

```rust
// Emergency block: immediately disconnect and refuse future connections.
swarm.behaviour_mut().allow_block_list.block_peer(compromised_peer_id);
```

Revocation events can propagate through the mesh via a dedicated GossipSub
topic or out-of-band (e.g., a signed revocation list fetched periodically).

### Open Mesh Mode (Development)

For local development and testing, UCAN verification can be disabled entirely
by setting `mesh.auth = "open"` in the daemon configuration. In open mesh mode:

- The `/aos/auth/1.0.0` handshake is skipped; all peers are admitted after
  transport-level PeerId verification.
- The GossipSub validation callback accepts all messages unconditionally.
- The block list is still functional (operators can still block specific peers).

Open mesh mode MUST NOT be used in production. The daemon logs a warning at
startup when it is enabled:

```toml
[mesh]
# "ucan" (default) or "open" (development only, skips UCAN verification)
auth = "open"
```

---

## Summary

The AOS mesh uses six libp2p protocols working together:

| Protocol | Role |
|----------|------|
| mDNS | Zero-config LAN peer discovery |
| Kademlia | WAN peer discovery and distributed routing |
| GossipSub | Build job coordination via pub/sub (signed messages + UCAN validation) |
| `/aos/auth/1.0.0` | Application-level UCAN verification before mesh admission |
| Identify | Address exchange, feeds Kademlia routing table |
| AutoNAT + Relay + DCUtR | Layered NAT traversal |

Two peer types participate: **daemons** (long-lived, full capability) and
**clients** (ephemeral or long-lived, limited capability). Both authenticate
via transport-level PeerId verification and application-level UCAN handshake.

The result is a self-organizing mesh that works across LAN, WAN, and NAT
boundaries without dedicated infrastructure. Builders behind NAT participate
through relay connections that are transparently upgraded to direct connections
via hole punching. The mesh is resilient to node failures -- there are no
single points of failure, no special coordinator nodes, and no required
infrastructure beyond the peers themselves.
