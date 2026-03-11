# Sync: Generic CRDT-Based State Synchronization

A single sync primitive for synchronizing closure roots across all peers
in a universe. Rather than building separate sync mechanisms for profiles,
registries, shells, and configuration, one path-namespaced LWW-Map CRDT
handles everything.

Every entry in the sync namespace is a closure root (Nix store hash) with
LWW-CRDT metadata. A merkle tree over the namespace enables efficient
anti-entropy between peers. Content transfer uses the existing
WANT_MANIFEST/WANT_CHUNK chunk protocol. UCAN path permissions provide
hierarchical access control.

## Sync Namespace

The namespace is a path hierarchy under `sync/{universe}/`:

```
sync/{universe}/
  ├── profiles/
  │   ├── dylan              → closure root (profile derivation)
  │   └── alice              → closure root
  ├── registries/
  │   ├── aos-core           → closure root (registry store path)
  │   └── company-internal   → closure root
  ├── shells/
  │   ├── mydev              → closure root (container state ref)
  │   └── ci-job-42          → closure root
  ├── config                 → closure root (universe config derivation)
  └── pins/
      └── gcc-14             → closure root
```

Every entry is the same type -- a closure root with CRDT metadata. The
sync protocol doesn't care what the closure contains.

## Entry Structure

CRDT sync state is persisted in `state/sync.mdb` -- a dedicated LMDB
environment separate from the chunk index (`chunks/index.mdb`) and per-view
access tracking (`views/{name}/access.mdb`). This isolation ensures that
moderate sync writes on delta reception don't contend with bursty chunk
ingestion or hot FUSE access tracking.

```rust
struct SyncEntry {
    store_hash: String,       // closure root being synced
    timestamp: u64,           // LWW ordering
    alive: bool,              // false = tombstone (removal)
    author: PeerId,           // who made this change
}

type SyncState = BTreeMap<String, SyncEntry>;  // path → entry
```

Merge rule: for each path, the entry with the highest timestamp wins. On
tie, `alive=true` wins (add bias).

## Merkle Tree

The path hierarchy IS the merkle tree structure. Each node's hash is
derived from its children:

```
root = H(H(profiles/) || H(registries/) || H(shells/) || H(config) || H(pins/))

leaf = H(path || store_hash || timestamp || alive || author)
```

Two peers compare root hashes. If equal, consistent. If not, walk the
tree to find divergent subtrees. O(log n) rounds, O(branching factor)
hashes per round.

### Anti-entropy walk

```
Peer A root: aaa111
Peer B root: bbb222    ← different

Exchange level 1:
  A: profiles/=xxx, registries/=yyy, shells/=zzz
  B: profiles/=xxx, registries/=yyy, shells/=ZZZ
                                          ^^^
  Only shells/ differs. Descend.

Exchange level 2 (shells/):
  A: mydev=mmm, ci-job-42=nnn
  B: mydev=mmm, ci-job-42=nnn, ci-job-43=ppp

  B has ci-job-43 that A doesn't. Send entry.
  A merges. Roots now match.
```

## Protocol: `/aos/sync/1.0.0`

Three message types:

```rust
enum SyncMessage {
    // Real-time: individual CRDT operations
    Delta {
        path: String,
        entry: SyncEntry,
        ucan: String,           // proves write access to this path
    },

    // Anti-entropy: merkle tree comparison
    MerkleRequest {
        prefix: String,         // subtree to compare
        depth: u32,             // levels of hashes to return
    },
    MerkleResponse {
        nodes: Vec<(String, Hash)>,
    },

    // Consistency: state announcement
    StateAnnounce {
        root_hash: Hash,
        vector_clock: VectorClock,
        entry_count: u64,
    },
}
```

### Real-time sync via GossipSub

Deltas are published on GossipSub for real-time propagation:

```
Topic: sync/{universe}

Message: Delta {
    path: "profiles/dylan",
    entry: {store_hash: "abc123", ts: 42, alive: true, author: QmDylan},
    ucan: "eyJ..."
}
```

All peers in the universe receive deltas instantly via GossipSub fan-out.
The GossipSub validation callback checks UCAN path coverage before
accepting.

### Anti-entropy via `/aos/sync/1.0.0` stream

For catch-up when a peer comes online or missed GossipSub messages:

1. Peer opens `/aos/sync/1.0.0` stream to another peer
2. Exchange `StateAnnounce` messages (root hash + vector clock)
3. If roots differ, perform merkle walk:
   - Send `MerkleRequest{prefix: "", depth: 1}` for top-level hashes
   - Compare children, descend into differing subtrees
   - Exchange missing or differing entries
4. LWW merge on each received entry
5. Fetch content via existing WANT_MANIFEST/WANT_CHUNK

The sync protocol only transfers CRDT metadata (paths, hashes,
timestamps). Actual closure content is fetched via the chunk transfer
protocol. Clean separation.

### Consistency milestones

Peers periodically broadcast `StateAnnounce` on GossipSub:

```
Topic: sync/{universe}/announce

Message: {
    peer_id: "QmHost3",
    root_hash: "abc123",
    vector_clock: {a: 5, b: 3, c: 5},
    entry_count: 847,
}
```

A consistency milestone is reached when all active peers report the same
root hash.

```rust
fn check_consistency(
    announcements: &HashMap<PeerId, StateAnnounce>,
) -> ConsistencyStatus {
    let roots: HashSet<_> = announcements
        .values()
        .map(|a| &a.root_hash)
        .collect();
    match roots.len() {
        1 => ConsistencyStatus::Consistent {
            root: roots.into_iter().next().unwrap().clone(),
            peers: announcements.len(),
        },
        _ => ConsistencyStatus::Divergent {
            groups: group_by_root(announcements),
        },
    }
}
```

CLI:

```
$ aos sync status staging
PATH                          ROOT     PEERS   CONSISTENT
sync/staging/                 abc123   10/10   ✓ (milestone #47)
sync/staging/profiles/        def456   10/10   ✓
sync/staging/registries/      ghi789   9/10    ✗ (QmHost7 behind)

$ aos sync wait staging/registries --timeout 60s
Waiting... QmHost7 syncing... done (3.2s)
All 10 peers consistent at root ghi789
```

## UCAN Path Permissions

UCAN `with` fields use path prefixes for hierarchical access control:

```
aos://staging/sync/*                    → full access to entire namespace
aos://staging/sync/profiles/dylan/*     → dylan's profile subtree only
aos://staging/sync/registries/*         → all registries
aos://staging/sync/config               → universe config (exact path)
```

Permission inheritance follows the path hierarchy:

- Write to `profiles/dylan` implies write to `profiles/dylan/packages`
- Write to `profiles/` implies write to `profiles/dylan` and
  `profiles/alice`
- No upward inheritance: `profiles/dylan` does NOT grant
  `profiles/alice`

Validation on every delta:

```rust
fn validate_sync_delta(
    delta: &Delta,
    ucan_verifier: &UcanVerifier,
    sender: &PeerId,
) -> bool {
    ucan_verifier.verify_path_access(
        &delta.ucan,
        sender,
        &format!("aos://{universe}/sync/{}", delta.path),
        Permission::Write,
    )
}
```

## Use Cases

Every use case maps to a path in the sync namespace with a closure root:

| Use case | Sync path | Closure root contains |
|---|---|---|
| User profile | `profiles/{user}` | Packages + config + activation scripts |
| Registry pointer | `registries/{name}` | Symlink tree to packages + .drv files |
| Shell/container ref | `shells/{name}` | Container metadata (host, ZFS, status) |
| Universe config | `config` | Registry list, trusted builders, policies |
| Pinned closure | `pins/{name}` | Any store path to pin across universe |
| Package set | `packages/{name}` | Package roots for a named set |
| Deployment target | `deploy/{env}` | System configuration derivation |

All use the same sync protocol, same merkle validation, same UCAN path
model, same chunk transfer for content.

## Merge Semantics

### LWW-Map merge

```rust
fn merge(local: &mut SyncState, remote: &SyncState) {
    for (path, remote_entry) in remote {
        match local.get(path) {
            Some(local_entry) => {
                if remote_entry.timestamp > local_entry.timestamp
                    || (remote_entry.timestamp == local_entry.timestamp
                        && remote_entry.alive
                        && !local_entry.alive)
                {
                    local.insert(path.clone(), remote_entry.clone());
                }
            }
            None => {
                local.insert(path.clone(), remote_entry.clone());
            }
        }
    }
}
```

Properties:

- **Commutative**: merge(A, B) = merge(B, A)
- **Associative**: merge(merge(A, B), C) = merge(A, merge(B, C))
- **Idempotent**: merge(A, A) = A
- **Convergent**: all peers reach the same state regardless of message
  order

### Concurrent modifications

Machine A adds curl, Machine B adds vim simultaneously -- both survive
(different paths, both merge in).

Machine A removes curl (t=50), Machine B updates curl (t=51) -- B's
update wins (higher timestamp).

Machine A and B both set `profiles/dylan` to different values at same
timestamp -- add-bias tiebreak, then the next write from either side
will resolve.

## Content Fetch

The sync protocol carries only metadata (paths + store hashes). Content
(the actual package binaries, configs, etc.) is fetched via the existing
chunk transfer protocol:

1. CRDT delta arrives: `profiles/dylan -> store_hash abc123`
2. Peer checks: do I have `abc123` in my chunk store?
3. If not: `WANT_MANIFEST(universe, abc123)` -> manifest ->
   `WANT_CHUNK` for missing chunks
4. Store path reconstructed from chunks, rooted locally

This reuses everything from chunks.md and store.md. No new content
transfer mechanism.

## Fetch Eagerness

Configurable per-path or per-subtree:

```toml
[views.staging.sync]
fetch = "eager"                    # default: fetch content immediately on CRDT add

[views.staging.sync.overrides]
"shells/*" = "lazy"                # container refs: fetch only when accessed
"pins/*" = "eager"                 # pinned closures: always pre-fetch
"profiles/*" = "eager"             # profiles: pre-fetch for fast login
"registries/*" = "manifest-only"   # registries: fetch manifest, chunks on demand
```

## Relationship to Other Docs

- **chunks.md** -- Content transfer uses WANT_MANIFEST/WANT_CHUNK for
  closure data
- **auth.md** -- UCAN path permissions for sync namespace access control
- **mesh.md** -- GossipSub carries CRDT deltas; Kademlia provides peer
  discovery for anti-entropy
- **daemon.md** -- Daemon runs the sync protocol as part of its main
  event loop
- **views.md** -- Views are local materializations of sync state; GC
  operates on local state
- **builds.md** -- Build results can be synced by adding entries to the
  sync namespace
- **package.md** -- Registries and profiles are closure roots in the
  sync namespace
- **crates.md** -- Sync logic lives in `aos-p2p` crate (shared by
  daemon and client)
