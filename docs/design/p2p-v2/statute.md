# Statute: BFT Key-Value Store

Statute is a Byzantine fault tolerant key-value store built over libp2p. It
provides a global, UCAN-authorized, schema-validated mutable namespace with
consensus-backed history. Statute is the governance and configuration layer
of the AOS distributed system.

## Overview

Statute is a chained HotStuff BFT consensus protocol maintaining a
merkle-trie KV state. Writes are authorized via UCAN delegation chains rooted
at the chain's genesis key. Values are validated against CUE schemas stored
inline in the state itself. The schema and permissions model is
self-describing: the root `/_schema` key defines the structure of all keys
(including `_schema` and `_permissions` themselves). All validators
independently compute the same state -- deterministic validation ensures
consensus never diverges.

### What Statute Replaces

Several DHT records in the current design are mutable state that would benefit
from consensus, history, and schema validation. Statute replaces:

| Current DHT Record | Statute Key Pattern | Why |
|---|---|---|
| `aos:cluster:{id}:config` (ClusterConfig) | `/clusters/{id}/config` | Cluster config needs versioning, rollback protection, and schema validation. DHT has no version field -- stale configs can overwrite current ones. |
| UCAN revocations (`aos:auth:token:{hash}:revoke`) | `/_revocations/{token_hash}` | Revocations need consensus -- a partitioned peer shouldn't miss a revocation. DHT TTLs can expire prematurely. |
| Validator/governance state | `/_validators/{chain_id}` | Dynamic validator set changes need consensus by definition. |

Provider records (store objects, cluster membership, job
executors) remain in the DHT -- they are ephemeral, per-peer, and don't need
consensus or history. Statute is for **authoritative mutable state**, not
ephemeral advertisements.

### Design Principles

- **Global namespace.** Keys are Unix-style paths with leading slashes (e.g.,
  `/clusters/prod/config`). No per-pubkey namespacing. Access control is via
  UCAN and inline `_permissions`, not key ownership.
- **Self-describing schema.** The root `/_schema` key defines the shape of the
  entire key space, including what `_schema` and `_permissions` values must
  look like. A key not described in the schema hierarchy is rejected.
- **Inline metadata.** Schema and permissions are stored inline alongside data
  using underscore-prefixed reserved keys (`_schema`, `_permissions`). They
  live at the same path level as the data they govern, not in a separate
  namespace.
- **Cascading permissions.** ALL ancestor `_permissions` must allow access, like
  Unix directory traversal permissions. There is no way to grant access at a
  child without the parent also allowing it.
- **UCAN authorization.** Every write requires a UCAN chain that proves the
  signer's identity. The chain walks to the genesis key. Permission checks use
  the identity extracted from the UCAN, not UCAN capabilities directly.
- **CUE schema validation.** Schemas cascade via CUE unification (`&`). A child
  `_schema` can tighten constraints but never loosen them relative to its
  parent.
- **BFT consensus.** Chained HotStuff with 3f+1 validators, tolerating f
  Byzantine faults. Linear message complexity O(n) per round.
- **Merkle-trie state.** The full KV state is a sparse merkle trie with a
  blake3 root hash committed in each block. Any value can be verified via a
  merkle proof against a finalized block.

## Data Model

### Keys

Keys are UTF-8 path strings with `/` as the separator and a leading slash:

```
/clusters/prod/config
/clusters/prod/config/intermediates/ops-admin
/groups/admins/members
/_revocations/abc123def456
/_validators/aos-chain
```

**Reserved metadata keys.** Keys whose final path segment starts with `_` are
reserved for metadata. Data keys cannot have a final segment starting with `_`.
The two reserved metadata keys are:

- `_schema` -- CUE schema governing sibling and descendant keys at this level.
- `_permissions` -- Relation-based access control governing this level.

These appear inline at any level of the tree:

```
/_schema                          root schema (self-describing)
/_permissions                     root permissions
/clusters/_schema                 cluster-level schema refinement
/clusters/_permissions            cluster-level permissions
/clusters/prod/_schema            per-cluster schema refinement
/clusters/prod/_permissions       per-cluster permissions
```

### Values

Values are CUE-encoded (a superset of JSON). Every write is validated against
the cascaded schema for its key path. Keys not described in the schema
hierarchy are rejected.

### Operations

| Operation | Description |
|---|---|
| Write | Set a key's value. Validated against cascaded schema. Permission-checked against cascaded `_permissions`. |
| Delete | Remove a key (tombstone). Permission-checked with `delete` action. |

There is no separate "schema write" operation. Writing to a `_schema` or
`_permissions` key is a normal write, permission-checked against the PARENT's
`_permissions` (see Permissions Model below).

## Self-Describing Schema Model

### Root Schema (`/_schema`)

The root `/_schema` key defines the shape of the entire Statute key space. It
is self-describing: it contains a `_schema` field that defines what ALL
`_schema` values must look like, and a `_permissions` field that defines what
ALL `_permissions` values must look like.

```cue
// /_schema — the complete tree definition
{
    _inherit: "default"

    // --- Metadata schemas (self-describing) ---
    _schema: {
        _inherit: *"default" | "final"
        ...
    }
    _permissions: {
        relations: [string]: {
            subjects: [...{
                type: "peer" | "group" | "inherit"
                id?:       string
                ref?:      string
                through?:  string
                relation?: string
            }]
        }
        rules: {
            read?:   {any_of: [...string]}
            write?:  {any_of: [...string]}
            delete?: {any_of: [...string]}
        }
    }

    // --- Cluster config (final — locked structure) ---
    clusters: {
        _inherit: "final"
        [_id=string]: {
            config: {
                cluster_id: _id
                root_public_key: =~"^[a-f0-9]{64}$"
                min_hold_duration: =~"^[0-9]+(s|m|h|d)$" | *"1h"
                intermediates: [...{
                    cert_id:      string
                    public_key:   =~"^[a-f0-9]{64}$"
                    name:         string
                    capabilities: [...string]
                    not_before:   int
                    not_after:    int
                }]
            }
        }
    }

    // --- Groups (default — children can extend) ---
    groups: {
        [string]: {
            members: [...=~"^peer:Qm"]
            ...
        }
    }

    // --- Nodes (enrolled node configuration) ---
    nodes: {
        [=~"^peer:Qm"]: {
            enrolled_at: int
            enrolled_by: string
            clusters: [...string]
        }
    }

    // --- Revocations ---
    _revocations: {
        [=~"^[a-f0-9]{64}$"]: {
            revoked_at: int
            issuer:     =~"^peer:Qm"
        }
    }
}
```

### How the Schema Defines the Key Space

The shape of `/_schema` defines which keys can exist. Each field in the schema
corresponds to a key segment. For example, the `clusters` field in the root
schema means `/clusters/...` keys are valid. A write to `/foo/bar` would be
rejected because `foo` is not a field in the root schema.

CUE's open struct (`...`) allows arbitrary additional fields. The `groups`
schema uses `[string]` pattern constraints to allow any group name while still
constraining the shape of each group's value.

### Schema Cascade and Inheritance

When validating a write to `/clusters/prod/config`, the validator collects ALL
`_schema` values along the path and unifies them:

```
/_schema                          root schema
/clusters/_schema                 cluster-level refinement (if it exists)
/clusters/prod/_schema            per-cluster refinement (if it exists)
```

All matching schemas are unified via CUE `&` (intersection). The result is the
effective schema for that key. A child can tighten constraints but never loosen
them -- CUE unification guarantees this.

### Inheritance Modes

Each `_schema` value has an `_inherit` field controlling how children can
refine it:

- **`"default"`** (the default) -- child `_schema` is unified with parent via
  CUE `&`. The child can add new fields and tighten existing constraints, but
  cannot remove fields or loosen constraints.
- **`"final"`** -- child cannot redefine any field present in the parent. The
  child can only add new keys not already defined by the parent.

For example, the `clusters` schema has `_inherit: "final"`, meaning no child
`_schema` under `/clusters/` can change the structure of cluster config. The
`groups` schema has `_inherit: "default"`, so `/groups/admins/_schema` could
add additional required fields beyond `members`.

### Schema Properties

CUE is chosen because:

- **Deterministic evaluation.** All validators compute the same validation
  result. No randomness, no side effects, no I/O.
- **Superset of JSON.** Values are plain JSON and validate naturally.
- **Rich constraints.** Regex, numeric ranges, enums, cross-field references,
  list comprehensions.
- **Schema composition.** CUE schemas unify -- composing multiple schemas
  computes the intersection of constraints. This is the foundation of the
  cascade model.
- **Backward compatibility checking.** CUE's subsumption operator can verify
  that a new schema accepts all values the old schema accepted.

## Permissions Model

### Inline Permissions

Permissions are stored inline at `_permissions` keys alongside the data they
govern:

```
/_permissions                     root-level permissions
/clusters/_permissions            cluster-level permissions
/clusters/prod/_permissions       per-cluster permissions
/groups/_permissions               who can manage groups
```

### Permission Structure

Each `_permissions` value defines relations and rules:

```cue
{
    relations: {
        admin: {
            subjects: [
                {type: "peer", id: "QmAdmin123..."},
                {type: "group", ref: "/groups/admins/members"},
            ]
        }
        writer: {
            subjects: [
                {type: "inherit", through: "admin"},
                {type: "group", ref: "/groups/operators/members"},
            ]
        }
        reader: {
            subjects: [
                {type: "inherit", through: "writer"},
                {type: "peer", id: "*"},  // public read
            ]
        }
    }
    rules: {
        read:   {any_of: ["reader"]}
        write:  {any_of: ["writer"]}
        delete: {any_of: ["admin"]}
    }
}
```

Subject types:

- **`peer`** -- a specific peer identity (from UCAN). `id: "*"` matches any
  authenticated peer.
- **`group`** -- members of a group. `ref` points to a Statute key containing a
  list of peer identifiers (e.g., `/groups/admins/members`).
- **`inherit`** -- inherits subjects from another relation in the same
  `_permissions`. `through: "admin"` means "anyone who is an admin is also
  implicitly in this relation."

### Permission Cascade

**All ancestor `_permissions` must allow access.** This works like Unix
directory traversal permissions: to write `/clusters/prod/config`, the identity
must be allowed by:

1. `/_permissions` (root) -- must allow `write` (or `read` for reads)
2. `/clusters/_permissions` -- must allow `write`
3. `/clusters/prod/_permissions` -- must allow `write`

If any ancestor denies access, the operation is rejected. A child `_permissions`
can restrict access further but can never grant access that a parent denies.

If a `_permissions` key does not exist at a given level, that level is
considered open (does not restrict). The root `/_permissions` MUST exist (set
in the genesis block).

### Permissions for Metadata Keys

Writing a `_schema` or `_permissions` key requires permission from the
**parent's** `_permissions`, not the key's own level. For example:

- Writing `/clusters/prod/_permissions` requires `write` permission from
  `/clusters/_permissions` (the parent level).
- Writing `/clusters/_schema` requires `write` permission from `/_permissions`
  (the root level).
- Writing `/_permissions` itself requires `write` permission from
  `/_permissions` -- effectively, only root admins can change root permissions.

This prevents a user who has write access to a subtree from escalating their
own permissions.

### Groups

Groups are ordinary Statute keys at `/groups/*/members`. Group membership is a
list of peer identifiers:

```cue
// /groups/admins/members
["peer:QmAdmin1...", "peer:QmAdmin2..."]
```

Managing group membership is a normal write to `/groups/{name}/members`,
permission-checked against `/groups/_permissions`. This means group management
is governed by the same permissions model as everything else -- no special
group management API.

Permissions reference groups via `{type: "group", ref: "/groups/admins/members"}`.
The validator resolves the group membership by reading the referenced key from
the current state.

## UCAN Authorization

### Identity Extraction

UCANs are used for **identity verification**, not capability-based
authorization. The UCAN chain proves that the signer is authorized to act as a
specific identity, and that identity chain walks to the genesis key. The actual
permission check is performed against `_permissions`, not UCAN capabilities.

```
Genesis key
  +-- UCAN --> ops-admin (identity: peer:QmOpsAdmin)
  |     +-- UCAN --> peer-1 (identity: peer:QmPeer1)
  |     +-- UCAN --> ci-bot (identity: peer:QmCiBot)
  +-- UCAN --> schema-admin (identity: peer:QmSchemaAdmin)
```

The validation pipeline extracts the peer identity from the UCAN chain, then
checks that identity against the `_permissions` cascade.

### Revocation

UCAN revocations are stored in Statute at `/_revocations/{token_hash}`.
During transaction validation, the validator checks the chain's own state for
revocations. This is circular but safe: the revocation write is validated
against its own UCAN chain (the issuer must have a valid identity). Once
committed, all subsequent blocks enforce the revocation.

Revocations are governed by `/_schema._revocations` in the root schema and
permission-checked against `/_permissions`.

## Consensus: Chained HotStuff

### Why HotStuff

| Protocol | Message Complexity | BFT | View Change |
|---|---|---|---|
| PBFT | O(n^2) | Yes | Complex (O(n^2)) |
| Tendermint | O(n) | Yes | Moderate |
| Raft | O(n) | No (crash only) | Simple |
| **HotStuff** | **O(n)** | **Yes** | **Simple (O(n))** |

HotStuff provides BFT with linear message complexity and a simple view change
protocol. It tolerates f < n/3 Byzantine validators in a set of 3f+1.

### Block Structure

Blocks, transactions, QCs, and votes are all MetaObjects in `objects.mdb/meta_db`
(see "Blocks, Transactions, and QCs as MetaObjects" below). The protobuf
definitions below remain as the wire format for gossipsub/stream serialization,
but on-disk storage uses the MetaObject representation.

```protobuf
message Block {
    uint64 height = 1;
    bytes prev_hash = 2;             // blake3 of previous block
    bytes state_root = 3;            // StoreRef: root tree hash in objects.mdb (see "Values as Store Objects")
    repeated Transaction txs = 4;    // ordered transactions
    uint64 timestamp = 5;
    bytes proposer = 6;              // validator PeerId
    QuorumCert justify = 7;          // QC from previous phase
    bytes signature = 8;             // proposer signs the block
}

message QuorumCert {
    uint64 height = 1;
    bytes block_hash = 2;            // blake3 of the block
    repeated Vote votes = 3;         // 2f+1 validator votes
}

message Vote {
    bytes validator = 1;             // validator PeerId
    bytes block_hash = 2;
    bytes signature = 3;             // validator signs (height, block_hash)
}
```

### Pipelined Phases

Each round, a leader proposes a block. Three consecutive QCs finalize a block:

```
Round 1: Leader_1 proposes Block_1
         Validators vote -> QC_1

Round 2: Leader_2 proposes Block_2 (carrying QC_1)
         Block_1 is LOCKED (pre-committed)
         Validators vote -> QC_2

Round 3: Leader_3 proposes Block_3 (carrying QC_2)
         Block_1 is DECIDED (finalized)
         Block_2 is LOCKED
```

A block is finalized when it has 3 consecutive QCs in its ancestor chain.
Leaders rotate round-robin. If a leader fails (timeout), validators move to
the next view with a single O(n) message round.

### Performance

With <5ms network latency:

| Metric | Value |
|---|---|
| Block time | ~500ms-1s |
| Finality | ~1.5-3s (3 pipelined rounds) |
| Throughput | ~1000-10000 tx/block |
| Validator set | 4-100+ nodes |
| Message complexity | O(n) per round |

## Transaction Model

Transactions are MetaObjects in `objects.mdb/meta_db` (see "Blocks,
Transactions, and QCs as MetaObjects" below). The protobuf definitions below
remain as the wire format for gossipsub/stream serialization, but on-disk
storage uses the MetaObject representation.

```protobuf
message Transaction {
    string key = 1;                  // leading-slash path (e.g., "/clusters/prod/config")
    oneof operation {
        WriteOp write = 2;
        DeleteOp delete = 3;
    }
    uint64 nonce = 5;                // per-signer monotonic (replay protection)
    bytes public_key = 6;            // signer's ed25519 public key
    bytes signature = 7;             // signs (key, operation, nonce)
    string ucan = 8;                 // UCAN proof chain (identity verification)
}

message WriteOp {
    bytes value = 1;                 // CUE-encoded content (validated against cascaded schema)
}

message DeleteOp {}                  // tombstone
```

Note: there is no `SchemaOp`. Writing to a `_schema` or `_permissions` key
uses a normal `WriteOp` -- the key path determines that it is a metadata write,
and permission checking uses the parent's `_permissions`.

### Validation Pipeline

Every validator runs the same deterministic validation for each transaction:

1. **Reserved key check.** If the key is a data key (not `_schema` or
   `_permissions`), reject if the final path segment starts with `_`.
2. **Signature.** Verify ed25519 signature over `(key, operation, nonce)`.
3. **Nonce.** Verify `nonce == last_nonce[public_key] + 1`.
4. **UCAN identity verification.**
   a. Verify the UCAN chain walks to the genesis key.
   b. Extract the signer's peer identity from the chain.
   c. Check that no intermediate in the chain is revoked (checked against
      `/_revocations/` in the current state).
5. **Permission cascade.**
   a. Determine the required action (`read`, `write`, or `delete`).
   b. For metadata keys (`_schema`, `_permissions`), the permission check
      uses the parent's `_permissions`.
   c. Walk all ancestor `_permissions` from root to the target key's level.
   d. At each level where `_permissions` exists, verify the identity is in a
      relation that grants the required action.
   e. Reject if ANY ancestor denies access.
6. **Schema cascade (WriteOp only).**
   a. Collect all `_schema` values along the ancestor path from root to the
      target key.
   b. Unify them via CUE `&` (respecting `_inherit` modes).
   c. Validate the written value against the unified schema.
   d. Reject if validation fails.
   e. If the key is itself a `_schema` key, validate the value against
      `/_schema._schema` (the self-describing meta-schema).
   f. If the key is a `_permissions` key, validate the value against
      `/_schema._permissions`.
7. **Apply.** Update the merkle trie.

All steps are deterministic. All validators compute the same result.

## State: Sparse Merkle Trie

The KV state is a sparse merkle trie keyed by `blake3(key)`:

```
State root (blake3)
  +-- Internal: hash(left || right)
  |   +-- Leaf: /clusters/prod/config -> { ... }
  |   +-- Leaf: /clusters/staging/config -> { ... }
  +-- Internal: hash(left || right)
      +-- Leaf: /_schema -> { _schema: { ... }, clusters: { ... }, ... }
      +-- Leaf: /_revocations/abc123 -> { revoked_at: ... }
```

Properties:
- **O(log n) proof size.** Merkle proof for any key is ~32 bytes x trie depth.
- **Efficient updates.** Insert/update touches O(log n) nodes.
- **State root in block header.** Committed per block -- all validators agree.
- **Light client verification.** Verify a value exists by checking a merkle
  proof against the state root in a finalized block.

## Values as Store Objects

Every value in the Statute KV store is a store object in `objects.mdb`. The
Statute state trie maps keys to `StoreRef` values — blake3 hashes pointing
into the shared object store (tree_db/blob_db).

```
Statute trie (in statute.mdb/blocks_db):
  key → StoreRef (blake3 hash)

Object store (in objects.mdb):
  tree_db: tree_hash → TreeObject
  blob_db: blob_hash → BlobRef
```

### Why

This unification means:

- **No separate state storage.** Statute values live in `objects.mdb` alongside
  all other store content. No `state_db` in `statute.mdb`.
- **Statute sync = store sync.** Catching up on the Statute chain = downloading
  blocks (which contain state_root StoreRefs) + fetching the referenced store
  objects via the normal resolve/chunk protocol. Same dedup, same closure hints.
- **Directory keys are tree objects.** A key prefix like `/clusters/prod/` is a
  tree object in `objects.mdb`. Reading a directory returns a StoreRef to the
  tree — the entire subtree is a store object.
- **Value dedup.** Two identical Statute values (e.g., two clusters with the
  same config) share one store object.
- **CoW updates.** Updating a key creates new tree/blob objects along the path
  (copy-on-write). Unchanged subtrees share objects with the previous state.
  This is exactly how git commits work.

### Write Path

```
Write "/clusters/prod/config" = { min_hold_duration: "2h" }

1. Serialize the value as a blob → blob_hash in objects.mdb/blob_db
2. Create/update tree objects along the path:
   / → clusters → prod → config (new blob)
3. Copy-on-write: new tree objects for /, /clusters, /clusters/prod
   (unchanged siblings share existing tree objects)
4. New state_root = new root tree hash
5. Record in block: Block { state_root: new_root_hash, ... }
```

### Read Path

```
Read "/clusters/prod/config" at state_root R

1. Look up R in objects.mdb/tree_db → root TreeObject
2. Find "clusters" entry → tree_hash
3. Look up tree_hash → TreeObject for /clusters/
4. Find "prod" entry → tree_hash
5. Look up → TreeObject for /clusters/prod/
6. Find "config" entry → blob_hash
7. Look up blob_hash in blob_db → BlobRef → chunks → value
```

This is the same tree traversal as FUSE path resolution. The `statute`
workflow step is just a local store lookup.

### Block Structure (Revised)

Blocks are MetaObjects in `objects.mdb/meta_db`. The protobuf definition
below remains as the wire format for gossipsub/stream serialization, but
on-disk storage uses the MetaObject representation (see "Blocks, Transactions,
and QCs as MetaObjects" below).

```protobuf
message Block {
    uint64 height = 1;
    bytes prev_hash = 2;             // blake3 of previous block
    bytes state_root = 3;            // StoreRef: root tree hash in objects.mdb
    repeated Transaction txs = 4;
    uint64 timestamp = 5;
    bytes proposer = 6;
    QuorumCert justify = 7;
    bytes signature = 8;
}
```

The `state_root` is a tree hash in `objects.mdb`. The entire Statute state
at any block height is a git-compatible merkle tree, fetchable and verifiable
via the standard store protocol.

### Sync and Catch-Up

Statute sync uses the store protocol:

```
1. Download blocks via /aos/statute/sync/1.0.0 (block headers + txs)
2. Each block has state_root (a StoreRef in objects.mdb)
3. Fetch state via normal store protocol:
   /aos/store/object/1.0.0 → get the root tree + structural objects
   /aos/store/chunk/1.0.0 → get changed blobs
4. CoW sharing: a state that differs by one key from the previous block
   shares ~99% of tree objects. Only changed nodes are transferred.
```

### Revised Storage Layout

```
statute.mdb:
  blocks_db:   height (u64) → meta_hash (blake3)    ← index into objects.mdb
  nonces_db:   public_key → last_nonce
  index_db:    key → [heights modified]

objects.mdb:                                          ← shared with store
  tree_db:     tree_hash → TreeObject                 ← state trie nodes
  blob_db:     blob_hash → BlobRef                    ← state values + tx data
  meta_db:     meta_hash → MetaObject                 ← blocks, txs, QCs, votes, git commits, tags
```

`blocks_db` is now just a height-to-hash index. The actual block data
(including all transactions, QCs, and state) lives in `objects.mdb`.

## Blocks, Transactions, and QCs as MetaObjects

The entire Statute chain is composed of store objects. Blocks, transactions,
quorum certificates, and votes are all MetaObjects in `objects.mdb/meta_db`.
Combined with values as tree/blob objects, this means **every piece of Statute
data lives in the shared object store**. StatuteBlock, StatuteTransaction, and
StatuteQC are MetaObject types stored in meta_db. See
[git-store.md](git-store.md) for the unified MetaObject model.

### Transaction

```
MetaObject {
    fields: [
        { key: "type",       text: "statute_tx" },
        { key: "key",        text: "/clusters/prod/config" },
        { key: "value",      ref: <blob_hash of the new value> },
        { key: "prev_value", ref: <blob_hash of the previous value> },
        { key: "author",     text: "peer:QmAlice" },
        { key: "nonce",      integer: 42 },
        { key: "ucan",       ref: <blob_hash of the serialized UCAN chain> },
        { key: "signature",  ref: <blob_hash of the ed25519 signature> },
    ]
}
```

The `value` and `prev_value` refs point to blob objects containing the
serialized CUE values. The `ucan` and `signature` refs point to blobs
containing the authorization proof and cryptographic signature.

### Quorum Certificate

```
MetaObject {
    fields: [
        { key: "type",       text: "quorum_cert" },
        { key: "height",     integer: 100 },
        { key: "block",      ref: <block_meta_hash> },
        { key: "vote",       ref: <vote_1_meta_hash> },
        { key: "vote",       ref: <vote_2_meta_hash> },
        { key: "vote",       ref: <vote_3_meta_hash> },
    ]
}
```

### Vote

```
MetaObject {
    fields: [
        { key: "type",       text: "vote" },
        { key: "validator",  text: "peer:QmBob" },
        { key: "block",      ref: <block_meta_hash> },
        { key: "signature",  ref: <blob_hash of the vote signature> },
    ]
}
```

### Block

```
MetaObject {
    fields: [
        { key: "type",       text: "block" },
        { key: "height",     integer: 100 },
        { key: "parent",     ref: <previous_block_meta_hash> },
        { key: "state_root", ref: <root_tree_hash in objects.mdb> },
        { key: "proposer",   text: "peer:QmBob" },
        { key: "timestamp",  integer: 1710288000 },
        { key: "tx",         ref: <tx_1_meta_hash> },
        { key: "tx",         ref: <tx_2_meta_hash> },
        { key: "justify",    ref: <qc_meta_hash> },
        { key: "signature",  ref: <blob_hash of proposer signature> },
    ]
}
```

The `parent` ref forms the block chain. The `state_root` ref points to the
root tree object of the Statute state at this block height. The `tx` refs
(repeated key) point to the transaction MetaObjects included in this block.
The `justify` ref points to the QC from the previous HotStuff phase.

### Closure Properties

Pinning a block MetaObject pins its entire closure:

```
Block (meta)
  → parent (meta) → parent → ... (entire chain history)
  → state_root (tree) → subtrees → blobs → chunks (full state snapshot)
  → tx refs (meta) → value/prev_value blobs (transaction data)
  → justify (meta) → vote refs (meta) → signatures (blobs)
```

This means:
- **Statute sync = store fetch.** Downloading a block = fetching a MetaObject
  and its closure via the normal resolve/chunk protocol.
- **Block dedup.** If two validators independently produce the same block
  (same transactions, same state), the MetaObject hash is identical.
- **History pruning follows GC.** Pin the latest block → its closure protects
  the entire chain back through history. Old blocks that are no longer
  reachable (pruned history) become GC-eligible.
- **Content-addressed blocks.** A block's identity IS its MetaObject hash.
  Same block content = same hash on every validator.

### The Git Analogy

| Git | Statute |
|---|---|
| Commit (MetaObject) | Block (MetaObject) |
| Tree (directory snapshot) | State root (tree in objects.mdb) |
| Blob (file content) | Value (blob in objects.mdb) |
| Parent ref (commit chain) | Parent ref (block chain) |
| Tag (MetaObject) | QC (MetaObject) |

Statute IS git applied to a BFT KV store. Blocks are commits. The state is
a tree. Transactions are diffs. The chain is a linear history (with potential
forks during epoch transitions, resolved by consensus).

### Revised Storage

```
statute.mdb:
  blocks_db:   height (u64) → meta_hash (blake3)    ← index into objects.mdb
  nonces_db:   public_key (blake3) → last_nonce (u64)
  index_db:    key (string) → [heights modified]

objects.mdb:                                          ← shared with store
  tree_db:     tree_hash → TreeObject                 ← state trie nodes
  blob_db:     blob_hash → BlobRef                    ← state values + tx data
  meta_db:     meta_hash → MetaObject                 ← blocks, txs, QCs, votes
```

`blocks_db` is now just a height-to-hash index. The actual block data
(including all transactions, QCs, and state) lives in `objects.mdb`.

## Validator Set

### Genesis

The genesis block defines the initial validator set, the genesis public key
(root of trust for UCAN chains), and the initial `/_schema` and
`/_permissions`:

```protobuf
message GenesisBlock {
    bytes chain_id = 1;              // unique chain identifier (blake3)
    bytes genesis_public_key = 2;   // root of trust for UCAN authorization
    repeated Validator validators = 3;
    uint64 timestamp = 4;
    map<string, bytes> initial_state = 5; // must include /_schema and /_permissions
}

message Validator {
    bytes public_key = 1;
    uint64 voting_power = 2;         // for weighted voting (1 = equal weight)
}
```

The `initial_state` MUST contain at least:
- `/_schema` -- the root schema defining the key space.
- `/_permissions` -- the root permissions (typically granting the genesis key
  full admin access).

### Dynamic Membership

The validator set is governed by a special key prefix `/_validators/`:

```
/_validators/{chain_id}/set = {
    validators: [
        { public_key: "...", voting_power: 1 },
        { public_key: "...", voting_power: 1 },
    ]
    epoch: 42
}
```

Changes to `/_validators/` are permission-checked against `/_permissions` --
typically only root admins can modify the validator set. Changes take effect at
the next epoch boundary (configurable: every N blocks or every T seconds).

### Epoch-Based Reconfiguration

Each validator set configuration is an **epoch**. When validators become
unreachable (network partition, crash), the remaining validators can
reconfigure by kicking unresponsive members and starting a new epoch.

**Safety guarantee:** only the partition with >50% of total voting power can
reconfigure. Since voting power sums to 100%, at most one partition can ever
form a new epoch. No split-brain.

#### Suspicion

Each validator tracks participation from others. If validator V hasn't voted
in `suspicion_rounds` consecutive rounds (default 10), V is marked
**suspected**:

```
Validator states:
  ACTIVE     → participating normally
  SUSPECTED  → missed suspicion_rounds consecutive rounds
  KICKED     → removed by reconfiguration vote
```

#### Kick

After a configurable halt timeout (default 5 minutes of no committed blocks
with suspected validators), any validator can propose a `ReconfigurationTx`:

```protobuf
message ReconfigurationTx {
    uint64 new_epoch = 1;
    repeated bytes kick_validators = 2;     // validators to remove
    repeated bytes add_validators = 3;      // validators to add (for rejoin)
    bytes proposer = 4;
    bytes signature = 5;
}
```

The vote rule differs from normal blocks: **requires >50% of TOTAL voting
power from the CURRENT epoch** (not 2f+1 from remaining). This ensures only
the majority side of a partition can reconfigure.

```
Example: 7 validators (equal weight), partition [A,B,C,D] | [E,F,G]
  Side A: 4/7 = 57% of total power → can reconfigure (>50%)
  Side B: 3/7 = 43% of total power → cannot reconfigure
```

Once approved, the reconfiguration is committed as a special block marking
the epoch transition. The new epoch begins with the reduced validator set
and recalculated f.

```
Epoch 1: validators=[A,B,C,D,E,F,G], f=2, quorum=5
  → E,F,G unreachable for 5 min
  → A proposes kick [E,F,G]
  → A,B,C,D vote (4/7 > 50%)
Epoch 2: validators=[A,B,C,D], f=1, quorum=3
  → chain resumes
```

Old-epoch blocks are rejected after the transition. A kicked validator still
in the partition will produce blocks that all epoch-2 validators reject.

#### Join (Rejoin)

When a kicked validator comes back online:

1. It syncs blocks from the current epoch and discovers it was kicked.
2. It requests to rejoin via a `ReconfigurationTx` with `add_validators`.
3. Current validators vote (2f+1 from current epoch — normal BFT quorum).
4. If approved, a new epoch begins including the rejoined validator.

```
Epoch 2: validators=[A,B,C,D], f=1, quorum=3
  → E comes back online, syncs blocks
  → E requests rejoin
  → A,B,C vote (3/4 = quorum)
Epoch 3: validators=[A,B,C,D,E], f=1, quorum=4
```

#### Automatic vs Manual

Two modes, controlled by the reconfiguration config in `/_validators/`:

**Automatic:** the daemon proposes kick/join transactions based on
configured thresholds. Kicks happen after `halt_timeout` of chain halt.
Rejoins are accepted automatically if `auto_rejoin` is true.

**Manual:** operator triggers via CLI:
```
aos statute kick <validator_peer_id>
aos statute join <validator_peer_id>
```

Manual commands submit a `ReconfigurationTx` that still requires >50%
voting power approval from the current epoch.

#### Edge Cases

**Even split** (e.g., 3|3 with 6 validators): neither side has >50%. Chain
halts until partition heals. This is correct — with f=1, losing 3 validators
exceeds Byzantine tolerance. Operator intervention required.

**Weighted voting power:** validators with higher weight shift the >50%
threshold. A single high-weight validator can tip the balance.

**Cascade kicks:** if the remaining validators after a kick also partition,
the new epoch's smaller set has a lower quorum. At f=0 (minimum), any single
Byzantine validator breaks safety — this is a degraded state and should
trigger alerts.

**Minimum validator count:** `min_validators` (default 4) prevents
auto-kick from reducing the set below a safe floor. Below this, auto-kick
is disabled and operator intervention is required.

#### Epoch State

The epoch configuration is stored in Statute:

```cue
// /_validators/{chain_id}
{
    epoch: uint
    validators: [...{
        public_key: string
        peer_id: string
        voting_power: uint | *1
        status: "active" | "suspected" | "kicked"
    }]
    reconfiguration: {
        suspicion_rounds: uint | *10
        halt_timeout: string | *"5m"
        min_voting_power: float & >0.5 & <=1.0 | *0.51
        min_validators: uint | *4
        auto_rejoin: bool | *true
    }
}
```

## libp2p Integration

### GossipSub

| Topic | Message | Description |
|---|---|---|
| `aos/statute/transactions` | `Transaction` | Client transaction submission (mempool) |

### Stream Protocols

| Protocol | Request | Response | Description |
|---|---|---|---|
| `/aos/statute/consensus/1.0.0` | HotStuff messages | HotStuff messages | Validator consensus (propose, vote, new-view) |
| `/aos/statute/sync/1.0.0` | `BlockSyncRequest` | stream of `Block` | Block sync for catching-up nodes |
| `/aos/statute/read/1.0.0` | `StatuteReadRequest` | `StatuteReadResponse` | State queries with merkle proofs |
| `/aos/statute/write/1.0.0` | `Transaction` | stream of `StatuteWriteResponse` | Submit transaction, stream status updates |

### DHT

| Key | Value | Description |
|---|---|---|
| `aos:statute:validators` | Provider record | Active validator advertisement |
| `aos:statute:head` | Block hash | Latest finalized block (hint for new joiners) |

## State Queries

```protobuf
// Stream protocol: /aos/statute/read/1.0.0
// Query a value with merkle proof. Client-facing read API.

message StatuteReadRequest {
    string key = 1;                  // key to look up (leading-slash path)
    optional uint64 at_height = 2;   // historical query (empty = latest)
    bool include_proof = 3;          // include merkle proof
    bool include_schema = 4;         // include effective (cascaded) CUE schema
    bool include_permissions = 5;    // include effective (cascaded) permissions
    bool include_history = 6;        // include modification history
}

message StatuteReadResponse {
    bytes value = 1;                 // CUE-encoded value (empty = not found)
    uint64 height = 2;              // block height of the state
    bytes state_root = 3;           // for proof verification
    repeated bytes proof = 4;       // merkle proof path
    optional string schema = 5;    // effective CUE schema (cascaded)
    optional string permissions = 6; // effective permissions (cascaded)
    repeated HistoryEntry history = 7;
}

message HistoryEntry {
    uint64 height = 1;              // block height when this value was set
    bytes value = 2;                // value at that height
    bytes public_key = 3;          // who wrote it
}
```

```protobuf
// Stream protocol: /aos/statute/write/1.0.0
// Submit a transaction and stream status: accepted → included → finalized (or rejected).
// Client-facing write API.

message StatuteWriteResponse {
    enum Status {
        ACCEPTED = 0;             // transaction accepted into mempool
        INCLUDED = 1;             // transaction included in a proposed block
        FINALIZED = 2;            // block containing transaction is finalized
        REJECTED = 3;             // transaction rejected (see error)
    }
    Status status = 1;
    uint64 height = 2;            // block height (set when INCLUDED or FINALIZED)
    bytes block_hash = 3;         // block hash (set when INCLUDED or FINALIZED)
    optional StreamError error = 4; // set when REJECTED
}
```

Light clients verify responses by checking the merkle proof against the state
root in a finalized block (which has a QC signed by 2f+1 validators).

## Storage

Each validator stores:

```
/var/lib/aos/db/
  statute.mdb:
    blocks_db:     height (u64) → meta_hash (blake3)    ← index into objects.mdb
    nonces_db:     public_key (blake3) → last_nonce (u64)
    index_db:      key (string) → [heights where modified]

  objects.mdb:                                            ← shared with store
    tree_db:       tree_hash → TreeObject                 ← state trie nodes
    blob_db:       blob_hash → BlobRef                    ← state values + tx data
    meta_db:       meta_hash → MetaObject                 ← blocks, txs, QCs, votes, git commits, tags
```

The blocks_db is an append-only height-to-hash index. The actual block data
(including all transactions, QCs, and state) lives in `objects.mdb` as
MetaObjects (see "Blocks, Transactions, and QCs as MetaObjects" above).
Statute state values are stored as tree and blob objects (see "Values as
Store Objects" above). Historical state at any block height is accessible by
traversing the block MetaObject's `state_root` ref. CoW sharing means old
state roots reference the same tree objects as current state where unchanged.

## AOS Integration

### ClusterConfig in Statute

Instead of a DHT record at `aos:cluster:{id}:config`, cluster configuration
is stored in Statute:

```
/clusters/{cluster_id}/config = {
    cluster_id: "prod"
    root_public_key: "abc123..."
    min_hold_duration: "1h"
    intermediates: [
        {
            cert_id: "ops-admin"
            public_key: "def456..."
            name: "ops-admin"
            capabilities: ["/aos/job/claim", "/aos/store/read", ...]
            not_before: 1710000000000000
            not_after: 1741536000000000
        }
    ]
}
```

The cluster config structure is locked (`_inherit: "final"`) in the root
schema. No child `_schema` can alter the required fields. The `cluster_id`
field is constrained to match the key segment via CUE's `[_id=string]`
pattern.

Benefits over DHT:
- **Versioned.** Every change is a block with a height. Rollback detection is
  trivial (reject configs with lower height than current).
- **Schema-validated.** The cascaded CUE schema validates every config update.
  Malformed configs are rejected before consensus.
- **Permission-controlled.** `/clusters/_permissions` governs who can create or
  modify clusters. Per-cluster `_permissions` can delegate management of
  individual clusters.
- **Auditable.** Full history of who changed what, when, with what UCAN.
- **Consistent.** All nodes see the same config at the same block height.
  No DHT propagation delay or stale record issues.

### Node Configuration

Enrolled node configuration is managed in Statute at `/nodes/{peer_id}/`:

```cue
// /nodes/{peer_id}
{
    enrolled_at: int
    enrolled_by: string              // PeerId of the enrolling operator
    clusters: [...string]            // cluster IDs this node belongs to
}

// /nodes/{peer_id}/clusters/{cluster_id}/ucan
{
    chain: string                    // serialized UCAN chain
    issued_at: int
    expires_at: int                  // 0 = unlimited
}

// /nodes/{peer_id}/clusters/{cluster_id}/config
{
    features?: [...string]
    labels?: [string]: string
    taints?: [...{
        key: string
        value: string
        effect: "NoSchedule" | "PreferNoSchedule" | "NoExecute"
    }]
    limits?: {
        max_jobs?: uint
    }
}
```

Each node watches its own `/nodes/{peer_id}/` subtree in Statute. When a
Statute block commits a change to this subtree, the node applies it:
cluster joins/leaves, UCAN rotations, feature/label/taint updates.

This replaces the re-enrollment protocol — all post-enrollment changes are
normal Statute writes with full UCAN authorization, schema validation, and
audit history.

### Groups in Statute

Groups are managed as ordinary keys under `/groups/`:

```
/groups/admins/members = ["peer:QmAdmin1...", "peer:QmAdmin2..."]
/groups/operators/members = ["peer:QmOp1...", "peer:QmOp2..."]
```

Group membership is referenced by `_permissions` entries via
`{type: "group", ref: "/groups/admins/members"}`. The validator resolves group
membership by reading the referenced key from the current state at validation
time.

Access to manage groups is controlled by `/groups/_permissions` -- no special
group management API is needed.

### UCAN Revocations in Statute

Revocation records move from DHT (`aos:auth:token:{hash}:revoke`) to Statute
(`/_revocations/{token_hash}`). Benefits:
- **Consensus-backed.** A revocation is final once committed. No DHT TTL
  expiry or propagation delay.
- **Queryable.** Light clients can verify revocation status with a merkle
  proof.
- **No TTL management.** DHT revocation records needed TTLs matching token
  expiry. In Statute, revocations persist until explicitly cleaned up.
- **Schema-validated.** The root schema constrains revocation keys to hex
  hashes and requires `revoked_at` and `issuer` fields.

### Workflow State

Workflows are managed via workflow mounts — path-independent mount points
that can be placed anywhere in the Statute tree. A workflow mount at any
path manages its own runs, transitions, and argument keys. There are no
static workflow paths in Statute.

See [mounts.md](mounts.md) for the reactive workflow mount model, which
replaces explicit workflow submission with reactive evaluation triggered
by Statute state changes.

### Replica Sets

Service deployment is defined via replica set configurations in Statute:

```cue
// /clusters/{id}/services/{name}
{
    replicas: uint & >=0
    spec_hash: #StoreRef             // RunSpec job spec (auto-pinned)
    update_strategy: "rolling" | "recreate"
    max_surge?: uint | *1
    max_unavailable?: uint | *1
    node_selector?: {
        system?: string
        features?: [...string]
        labels?: [string]: string
    }
}
```

Peers read replica set configs from Statute and independently reconcile: count
running instances, start or stop to match the desired replica count. Each
instance is a separate job submitted through the normal claim protocol — no
special locking needed. The `spec_hash` references the RunSpec store object,
which is automatically pinned as long as the replica set config exists.

Changes to the replica set config (scaling, rolling update) are Statute writes
— consensus-backed, schema-validated, auditable.

### Build Registry

Build results are recorded for audit and deduplication:

```cue
// /builds/{output_hash}
{
    drv_hash: #StoreRef
    output_hash: #StoreRef
    builder: string
    cluster_id: string
    built_at: int
    duration_ms: int
    nar_size: int
}
```

### Daemon Integration

The AOS daemon optionally runs a Statute validator (or read-only follower):

```toml
[statute]
chain_id = "aos-main"
role = "validator"                 # validator, follower, or none
genesis_file = "/etc/aos/statute-genesis.json"
data_dir = "/var/lib/aos/db"

[statute.validator]
key_file = "/etc/aos/statute-validator.key"
block_time = "1s"
```

Daemons that are followers (not validators) receive blocks via the sync
protocol and maintain a read-only copy of the state. They can serve queries
but don't participate in consensus.

## Security

### BFT Safety

With 3f+1 validators and f < n/3 Byzantine:
- No two conflicting values can be finalized for the same key at the same height.
- All honest validators converge to the same state.

### UCAN Security

- Writes without a valid UCAN chain are rejected by all validators.
- The genesis key is the root of trust -- it never appears in transactions
  (only in UCAN delegation chains).
- Revocations are checked against in-chain state, providing consensus-backed
  revocation enforcement.

### Permission Security

- Permissions cascade -- a child can never grant more access than its parent.
- Metadata keys (`_schema`, `_permissions`) are controlled by the parent's
  permissions, preventing privilege escalation.
- Group membership is resolved from Statute state at validation time, ensuring
  consistency across validators.

### Schema Security

- Schema validation is deterministic -- consensus never diverges due to schema
  evaluation differences.
- The root schema is self-describing, preventing invalid schema definitions.
- Schema inheritance (`_inherit: "final"`) locks critical structure definitions
  against modification by child schemas.
- CUE unification guarantees children can only tighten, never loosen.

### Light Client Security

- Any value can be verified with a merkle proof against a finalized block.
- The block has a QC with 2f+1 validator signatures.
- A light client needs only the validator set and a finalized block header to
  verify any state query.

## Automatic Store Pinning

Statute automatically pins store objects referenced in its state. Any value
matching the `#StoreRef` or `#TreeRef` CUE types found anywhere in the
latest Statute state is pinned, including its full closure.

```cue
#StoreRef: string & =~"^[a-f0-9]{64}$"  // blake3 hash of a store object
#TreeRef:  string & =~"^[a-f0-9]{64}$"  // blake3 hash of a tree/blob/meta object
```

The GC scanner:
1. Walks the entire Statute state trie
2. Finds all values matching `#StoreRef` or `#TreeRef` patterns
3. For each store hash: pins it + walks its closure (store_db refs → tree_db → blob_db → chunk_db)
4. For each tree/blob/meta hash: pins the object + recursively follows refs (meta object DAG traversal)

This means:
- Workflow specs are pinned while their state key exists
- Replica set service images are pinned while the config key exists
- Git refs pin their entire commit history closure
- Removing a Statute key releases the pin
- No explicit pin/unpin API needed — the Statute state IS the pin set

## Relationship to Other Docs

- [auth.md](auth.md) -- UCAN model shared between Statute and the P2P protocol.
- [daemon.md](daemon.md) -- `[statute]` configuration section.
- [protocol.md](protocol.md) -- protocol index (Statute protocols listed).
- [permissions.md](permissions.md) -- detailed permissions model (Statute implements inline `_permissions`).
- [workflow-templates.md](workflow-templates.md) -- workflow templates stored in Statute, CUE composition, instance tracking.
- [../../tla/Statute.tla](../../tla/Statute.tla) -- TLA+ formal specification: HotStuff consensus, epoch reconfiguration, KV state transitions, partition safety.
