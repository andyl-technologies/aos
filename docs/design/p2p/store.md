# P2P Store: Binary Cache, NAR Transfer, and Content-Addressed Storage

## Overview

Store synchronization has two directions:

1. **Inputs (peers -> daemon)**: Daemon fetches missing build inputs from peers before executing.
2. **Outputs (daemon -> peers)**: Daemon announces build results to the network after successful execution.

NAR transfer happens directly between peers via libp2p. There are zero external
dependencies -- no S3, no MinIO, no centralized storage. Durability comes from
replication across peers in the network.

## Content-Addressed Storage Model

Nix store paths are content-addressed by hash:

```
/nix/store/{hash}-{name}
  e.g. /nix/store/abc123-gcc-14.2.0
```

Each peer stores NARs and narinfo metadata locally in its own Nix store. The
Kademlia DHT tracks which peers hold which store paths, so any peer can
discover and fetch paths from others.

The store hash uniquely identifies a store path. The NAR hash identifies the
content of that path when serialized as a Nix Archive. These are distinct: the
store hash is derived from the derivation inputs (input-addressed) or content
(content-addressed), while the NAR hash is a straight hash of the serialized
archive bytes.

## Provider Records (Kademlia DHT)

When a peer has a store path, it publishes a **provider record** to the DHT:

```
Provider Record:
  key: store_hash (e.g. "abc123")
  provider: peer_id
```

This says "I have this store path, ask me for it." Provider records expire
after a configurable TTL (default: 24 hours) and must be re-published
periodically by peers that still hold the path.

## Fetch Protocol: /aos/nar-fetch/1.0.0

When a daemon needs a store path it does not have:

1. Query DHT: `GET_PROVIDERS("abc123")` returns `[daemon_A, daemon_B, daemon_C]`.
2. Open libp2p stream to closest/fastest provider: `/aos/nar-fetch/1.0.0`.
3. Send request: `{store_hash: "abc123", compression: "zstd"}`.
4. Provider streams the NAR data directly.

```
Daemon C                            Daemon A (has the path)
  |                                    |
  |  DHT: GET_PROVIDERS("abc123")      |
  |  -> [daemon_A, daemon_B]           |
  |                                    |
  |  OPEN /aos/nar-fetch/1.0.0        |
  |  {hash: "abc123", comp: "zstd"}   |
  |------------------------------------+
  |                                    |
  |  <---- narinfo metadata            |
  |  <---- compressed NAR bytes        |  (streamed)
  |  <---- EOF                         |
  |                                    |
  |  nix-store --import < nar_data     |
```

The protocol is a simple request-response over a libp2p stream:

1. **Request frame**: length-prefixed JSON with `store_hash` and optional
   `compression` field (`"zstd"`, `"xz"`, or `"none"`).
2. **Response header**: length-prefixed JSON with narinfo metadata (store path,
   NAR hash, NAR size, decompressed size, references, signatures).
3. **Response body**: raw compressed NAR bytes streamed until EOF.

The receiver validates the NAR hash against the narinfo before importing into
the local store. If validation fails, the stream is reset and another provider
is tried.

## Output Publishing

After a successful build, the daemon:

1. Queries outputs: `nix-store -q --outputs {drv_path}`
2. Queries runtime closure: `nix-store -qR {output_path}`
3. For each path in the closure, publishes a provider record to the DHT
   announcing that this peer holds the path.
4. Signs the narinfo with the daemon's signing key.

The NAR data stays in the local Nix store. Other peers fetch it on demand via
the `/aos/nar-fetch/1.0.0` protocol.

## Binary Cache HTTP Interface

Daemons with `[http]` enabled serve the Nix binary cache HTTP protocol,
querying peers via libp2p:

- `GET /{view}/{hash}.narinfo` -- DHT lookup for providers, fetch narinfo from a peer, optional re-signing.
- `GET /{view}/nar/{filename}` -- DHT lookup, stream NAR from a peer to the HTTP client.
- `GET /{view}/nix-cache-info` -- static response with store dir, priority, capabilities.

This allows other tools to use the daemon's URL as their substituter. The daemon
participates in the DHT and may also hold store paths of its own -- it bridges
the HTTP binary cache protocol and the P2P network.

## Advantages

- **Locality**: If daemon A just built gcc and daemon B needs gcc as input,
  B fetches directly from A -- no round-trip to external storage.
- **Bandwidth**: Peers on the same LAN transfer at LAN speed, not internet
  speed.
- **Zero external dependencies**: Fully self-contained mesh. No object storage
  to provision, pay for, or maintain.
- **Parallel fetching**: Can fetch different paths from different providers
  concurrently (future optimization: chunk-level parallelism within a single
  NAR).

## Query Missing Paths

Before building, the daemon determines which inputs it needs to fetch:

```rust
async fn fetch_missing_inputs(drv_path: &str) -> Result<()> {
    // Query the derivation's input closure
    let closure = nix_store_query(drv_path, &["-qR"])?;

    // Check local store
    let missing: Vec<_> = closure
        .iter()
        .filter(|path| !nix_store_is_valid(path))
        .collect();

    // Fetch missing paths from P2P network
    for path in missing {
        let hash = extract_store_hash(path);
        fetch_from_peers(&hash).await?;
    }
    Ok(())
}
```

The `nix_store_is_valid` check is a local operation (`nix-store --check-validity`)
that returns immediately. The fetch operations can be parallelized with a
bounded concurrency limit to avoid overwhelming the network:

```rust
async fn fetch_missing_inputs_parallel(drv_path: &str, max_concurrent: usize) -> Result<()> {
    let closure = nix_store_query(drv_path, &["-qR"])?;
    let missing: Vec<_> = closure
        .iter()
        .filter(|path| !nix_store_is_valid(path))
        .collect();

    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut handles = Vec::new();

    for path in missing {
        let sem = semaphore.clone();
        let path = path.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await?;
            let hash = extract_store_hash(&path);
            fetch_from_peers(&hash).await?;
            Ok::<_, anyhow::Error>(())
        }));
    }

    for handle in handles {
        handle.await??;
    }
    Ok(())
}
```

## Narinfo Signing

Each daemon has a signing key pair. Narinfo is signed before publishing:

- **Key format**: ed25519, same as Nix's native signing format. The private key
  is stored on each daemon (typically at `/etc/nix/signing-key.sec`). The
  public key is distributed to all peers via configuration.
- **Trust**: Daemons configure `trusted-public-keys` to accept signatures from
  known peers.
- **Multiple signatures**: A narinfo can have signatures from multiple daemons.
  The first daemon signs when it builds the path. A second daemon that
  fetches and re-serves the path can add its own signature. This provides
  redundant trust without requiring a central signing authority.

Narinfo format follows the Nix standard:

```
StorePath: /nix/store/abc123-gcc-14.2.0
URL: nar/def456.nar.zst
Compression: zstd
FileHash: sha256:def456...
FileSize: 52428800
NarHash: sha256:789abc...
NarSize: 104857600
References: xyz789-glibc-2.39 pqr012-linux-headers-6.6
Sig: daemon-a.example.com:base64-ed25519-signature...
Sig: daemon-b.example.com:base64-ed25519-signature...
```

## Garbage Collection

Each peer manages its own local Nix store independently:

- **GC roots per build**: Each active build registers its derivation and output
  paths as GC roots (symlinks in `/nix/var/nix/gcroots/`). When the build
  completes and outputs are announced to the network, the roots are removed.
- **Periodic GC**: A background task runs `nix-store --gc` when available disk
  space drops below a configurable threshold (e.g. 20% free).
- **Capacity advertisement**: Daemon capability messages include available disk
  space. The scheduler uses this to avoid assigning builds to daemons that are
  low on space and might need to GC mid-build.
- **Provider record expiry**: When a peer GCs a store path, it stops
  re-publishing the provider record for that path. The record expires from the
  DHT after the TTL (default: 24 hours), and other peers will no longer attempt
  to fetch from that peer.

```rust
async fn maybe_gc_local_store(min_free_pct: f64) -> Result<()> {
    let stat = statvfs("/nix/store")?;
    let free_pct = stat.f_bavail as f64 / stat.f_blocks as f64;

    if free_pct < min_free_pct {
        Command::new("nix-store")
            .args(["--gc", "--max-freed", "10G"])
            .status()
            .await?;
    }
    Ok(())
}
```

## Durability Tradeoffs

In a purely peer-to-peer system, durability depends on replication across peers.
There is no external durable store -- if all peers holding a given store path go
offline or garbage-collect it, that path is no longer available from the cache.

This is an acceptable tradeoff for a build system:

- **Everything can be rebuilt from source.** The system is hermetic and
  deterministic. Any store path can be reproduced by re-running its derivation.
  Losing a cached path means paying the cost of a rebuild, not losing data
  permanently.
- **Popular paths are naturally replicated.** Paths like gcc, glibc, and
  coreutils are fetched by many peers, so they exist across many local stores.
  Rarely-used paths may exist on only one or two peers, but those are also
  typically cheap to rebuild.
- **Cold start is expected.** A new cluster starts with no cached paths and
  builds everything from scratch. This is the normal bootstrap process and
  takes the same time regardless of whether a cache existed previously.
- **Pinning for critical paths.** Peers can be configured to pin specific store
  paths (by adding them as GC roots), preventing local GC from reclaiming them.
  Dedicated "cache peer" nodes can pin large sets of paths to improve
  availability without introducing external storage dependencies.
