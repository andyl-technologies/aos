# Daemon Architecture

The AOS daemon (`aos daemon`) is a single binary that participates in the
libp2p mesh, manages local storage, executes jobs, and serves content to peers.
Every node runs the same binary; configuration determines what each node does.

## Responsibilities

A running daemon:

- Joins the libp2p mesh (QUIC transport, mDNS + Kademlia discovery)
- Subscribes to cluster GossipSub topics (`jobs/announce`, `load/announce`,
  `control/announce`)
- Serves stream protocols (`/aos/store/manifest/1.0.0`,
  `/aos/store/chunk/1.0.0`, `/aos/job/exec/1.0.0`, `/aos/job/log/1.0.0`)
- Manages the local chunk store (pack files + LMDB index)
- Manages FUSE view mounts
- Publishes DHT records (provider records, profile, job heartbeats)
- Runs the ControlSignal reconciliation loop
- Publishes periodic LoadReport

## Main Event Loop

The daemon runs a single tokio `select!` loop over:

- **Swarm events** -- GossipSub messages, stream requests, DHT queries
- **Job execution** -- container lifecycle (claim, exec, announce; see [containers.md](containers.md))
- **Control reconciliation** -- periodic merge of ControlSignal CRDT state
- **Load reporting** -- periodic LoadReport publish to cluster topic
- **GC** -- periodic garbage collection of unreferenced chunks

## Configuration

Single TOML file:

```toml
[cluster]
id = "my-cluster"
seed_peers = ["/ip4/.../p2p/QmSeed1"]

[identity]
key_file = "/etc/aos/peer.key"
ucan_file = "/etc/aos/peer.ucan"

[store]
chunk_dir = "/var/lib/aos/chunks"

[jobs]
max_jobs = 8
system = "x86_64-linux"
features = ["kvm"]

[views]
# Named views with their projection and mode
```

What varies by configuration:

| `[jobs]` present | `[views]` present | Effective role |
|---|---|---|
| yes | yes | Full node. Executes jobs, mounts views, serves content. |
| yes | no | Builder. Executes jobs, serves content. No local views. |
| no | yes | Cache/view node. Mounts views, serves content. Does not build. |
| no | no | Relay. Participates in mesh routing only. |

## Module Listing

```
aos-daemon/src/
  main.rs           -- CLI entry, config loading, tokio runtime setup
  mesh.rs           -- libp2p swarm setup, AosBehaviour (Kademlia + GossipSub + request-response)
  jobs.rs           -- JobPost handling, claiming, exec, container lifecycle
  store.rs          -- chunk store management (pack files + LMDB), manifest/chunk serving
  fuse.rs           -- FUSE view management, mount/unmount lifecycle
  control.rs        -- ControlSignal reconciliation loop (CRDT merge)
  load.rs           -- LoadReport computation and publishing
  containers.rs     -- container orchestration (nspawn setup, build-init, profile activation, output registration)
  gc.rs             -- garbage collection (unreferenced chunks, expired DHT records)
  config.rs         -- TOML config parsing and validation
```

## Startup Sequence

1. Load config and identity (generate keypair on first run)
2. Open chunk store (LMDB index + pack files)
3. Build swarm (QUIC transport, mDNS, Kademlia, GossipSub)
4. Subscribe to cluster topics (`jobs/announce`, `load/announce`,
   `control/announce`)
5. Register stream protocol handlers (`/aos/store/manifest/1.0.0`,
   `/aos/store/chunk/1.0.0`, `/aos/job/exec/1.0.0`, `/aos/job/log/1.0.0`)
6. Mount FUSE views (if `[views]` configured)
7. Publish profile to DHT (`aos:profile:{peer_ident}`)
8. Enter main event loop

## Shutdown Sequence

1. Stop accepting new jobs (unsubscribe from `jobs/announce`)
2. Wait for in-flight jobs to complete (with configurable timeout)
3. Unmount FUSE views
4. Remove DHT records (`aos:profile:{peer_ident}`)
5. Disconnect from mesh
