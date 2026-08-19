# 06 — Storage, replication, retention, and garbage collection

Campaign storage has one semantic model across a local directory and a future
S3-compatible object backend: immutable objects addressed by content, Merkle
roots that make reachability explicit, and a small set of compare-and-swap refs.

## 06.1 Three storage classes

| Class | Examples | Replication |
| --- | --- | --- |
| Canonical semantic state | Scenario, policy, configuration, choice opportunity, branch point/request/edge, selection, proposal, attempt, observation, finding, snapshot | Always eligible; required to understand campaign |
| Durable acceleration | Exact checkpoint manifests/chunks, compacted projections, coverage indexes | Policy-controlled; never identity-changing |
| Ephemeral operation | Leases, worker IDs, PIDs, sockets, local hot templates, RSS, host paths | Never replicated as campaign state |

- **[CSTORE-1]** A campaign MUST remain semantically readable when every
  ephemeral object and every unpinned acceleration object is absent.
- **[CSTORE-2]** Canonical objects MUST contain type-domain and schema-version
  tags so equal payload bytes under different meanings cannot collide.

## 06.2 Object store interface

```rust,illustrative
pub trait CampaignObjectStore {
    fn has(&self, id: ObjectId) -> Result<bool, StoreError>;
    fn get(&self, id: ObjectId) -> Result<ObjectReader, StoreError>;
    fn put(&self, expected: ObjectId, bytes: ObjectReader)
        -> Result<PutOutcome, StoreError>;
    fn compare_and_swap_ref(
        &self,
        name: CampaignRefName,
        expected: Option<CampaignSnapshotId>,
        next: CampaignSnapshotId,
    ) -> Result<RefCasOutcome, StoreError>;
}
```

The actual trait may use asynchronous streams, but semantic behavior is fixed:

- `put` authenticates bytes against `expected`;
- publishing the same object repeatedly is idempotent;
- unequal content cannot occupy one key;
- `get` verifies the returned content before decoding;
- object reachability follows encoded references, never backend listing;
- the campaign ref advances only after all required objects exist.

- **[CSTORE-3]** Backend consistency differences MUST NOT change canonical
  object identity or ref-update semantics. A backend without conditional ref
  update cannot host writable campaign refs.
- **[CSTORE-4]** Store errors MUST distinguish missing, corrupt, unauthorized,
  incompatible, conditional-write conflict, quota, and unavailable outcomes.

## 06.3 Local filesystem backend

The first backend uses:

```text
<store>/
  objects/<hash-prefix>/<hash>
  refs/campaigns/<escaped-name>
  refs/locks/<escaped-name>          local CAS serialization only
  leases/<attempt-hash-prefix>/<attempt-hash>
  staging/<unique-operation>/
```

Objects are written to a same-filesystem staging file, flushed according to the
declared durability mode, authenticated, and atomically renamed into the object
path. Existing equal objects are reused. Campaign refs are tiny files updated
under an advisory lock with expected-value verification and atomic replacement.

The local backend may use reflinks, sparse files, `copy_file_range`, or other
filesystem accelerations for materialization, but object identity is always
verified from canonical bytes.

- **[CSTORE-5]** A crash at any point in local publication MUST leave either the
  old ref or a complete new ref. Staging debris is unreachable and reclaimable.
- **[CSTORE-6]** A reflink or sparse-copy optimization MUST have a byte-hash
  validation gate and a forced fallback path producing the same object IDs.

## 06.4 S3-compatible backend

The object mapping is deliberately direct:

```text
objects/blake3/<object-id>
refs/campaigns/<escaped-name>
```

Immutable objects use conditional create where available and validate metadata
plus payload digest. A ref update uses `If-Match`/ETag or an equivalent strong
conditional write. Multipart upload may stream large objects; the object is not
referenced until completion and content authentication.

The backend does not rely on rename, directory listing, last-writer-wins ref
updates, or bucket event ordering. Garbage collection starts from refs and walks
Merkle references.

- **[CSTORE-7]** S3 object metadata is an optimization. Canonical type, version,
  length, and child references MUST be recoverable from authenticated object
  bytes.
- **[CSTORE-8]** Multipart upload IDs, part ETags, region, bucket, endpoint, and
  credentials MUST NOT enter content identity.

## 06.5 Canonical object envelope

```text
magic
object kind
schema version
canonical payload length
reference count
sorted child object IDs
canonical payload
checksum/digest authentication
```

Strings use defined UTF-8 normalization, maps use canonical key order, integer
widths and byte order are explicit, and decoders reject trailing bytes,
duplicates, unknown required fields, unreasonable lengths, and unsorted
canonical collections.

- **[CSTORE-9]** Every decoder MUST validate limits before allocation and must
  reject a child reference whose declared type is incompatible with the parent
  field.

## 06.6 Campaign ref and snapshot publication

Publishing a new snapshot is:

1. persist new facts and artifacts;
2. persist new or updated Merkle collection nodes;
3. persist the immutable `CampaignSnapshot`;
4. read and verify the current named ref;
5. CAS the ref from expected parent to new snapshot;
6. on conflict, load the winner and perform the policy-specific merge/rebase.

A lost CAS loses no published fact. The objects remain reachable from their
content IDs and can be included by a retry or later repair.

- **[CSTORE-10]** A campaign ref is the only durable mutable user-visible object
  for that campaign. Store implementations MUST NOT require separately mutable
  authoritative frontier, statistics, or finding databases.

## 06.7 Merkle collections and projections

Large sets and maps use bounded fanout persistent Merkle structures. Updating
one entry writes only nodes along the changed path. Roots identify exact
collection contents and support difference walking without enumerating equal
subtrees.

Projection objects include their input fact roots and policy/version. A reader
validates those identities before using the projection. Full recomputation gates
sample projections and compare canonical roots.

- **[CSTORE-11]** Projection compaction and Merkle tree rebalancing MUST preserve
  logical canonical collection identity or publish a distinct representation
  identity with an equality proof. Authoring/insertion order MUST NOT affect the
  logical root.

## 06.8 Replication

Replication exchanges snapshot IDs and walks missing Merkle objects:

```text
source advertises CampaignSnapshotId
destination fetches snapshot envelope
destination compares child roots
equal roots stop traversal
missing subtrees/objects transfer by content ID
every object authenticates before admission
destination CAS-advances or creates its local ref
```

Supported replication closures are:

| Mode | Required objects |
| --- | --- |
| `metadata` | Policy, scenario references, graph, exploration, observations, reports, findings metadata |
| `findings` | Metadata plus reproduction artifacts and minimized schedules |
| `debug` | Findings plus explicitly pinned exact pre/post-failure closures |
| `executable` | Metadata plus selected frontier/hot-hub exact closures and required immutable images |
| `mirror` | Every object reachable under retention policy |

A metadata replica can inspect a campaign without downloading guest RAM or disk
chunks. Fetching a finding or configuration later lazily pulls its closure.

- **[CSTORE-12]** A partial replica MUST report absent optional acceleration
  objects distinctly from corrupt or incomplete required semantic objects.
- **[CSTORE-13]** Replication MUST never trust the remote's claimed object type
  or hash without local authentication.

## 06.9 Merge and convergence

The following structures merge by content-addressed union:

- temporal graph nodes, branch points, and edges;
- branch requests, proposals, and attempts;
- canonical observations keyed by attempt;
- coverage and novelty facts;
- corpus and findings;
- budget grants and historical commands.

User-current state such as active policy, desired running/paused state, and
current pin set follows explicit snapshot ancestry and conflict rules. Two
competing policy activations do not silently last-write-win; the operator or a
declared merge policy creates a snapshot naming the chosen active policy while
retaining both historical facts.

Two planners may independently issue different valid proposals from partial
knowledge in a future coordinatorless mode. Both proposals are safe to retain,
but proposals for an identical branch-point value converge on one semantic edge
without discarding either cause. This does not satisfy strict campaign
reproducibility. The initial and strict implementations use one logical planner
ref sequence.

- **[CSTORE-14]** Merging campaign stores MUST NOT merge or synthesize VM state.
  It unions facts and graph objects; identical configuration IDs deduplicate.
- **[CSTORE-15]** Two non-identical canonical observations for one `AttemptId`
  are a determinism conflict and MUST be retained for diagnosis rather than
  arbitrarily selected.

## 06.10 Pinning and retention

Pins have reason and scope:

```text
user pin
finding reproduction pin
campaign corpus pin
active continuation ancestor pin
hot-hub preference
genesis/provenance pin
temporary transfer pin
```

Only the first four and genesis are semantic retention roots. Hot-hub preference
is operational and can disappear. A pin may require metadata only, thin replay,
or an exact closure. Findings default to self-contained replay artifacts; policy
may additionally pin exact checkpoints for fast debugging.

- **[CSTORE-16]** Pin removal creates a new immutable pin-set root and never
  deletes synchronously. Garbage collection is a separate reachability pass
  with a reviewable plan.

## 06.11 Garbage collection

GC roots include:

- all live campaign refs and intentionally retained historical snapshots;
- explicit user/finding/corpus/configuration pins;
- genesis and immutable scenario/image closures;
- in-progress publication and transfer roots;
- unexpired attempt execution protection roots.

The collector produces a plan listing retained, unreachable, missing, and
policy-evictable objects. It first evicts cache-only exact materializations while
preserving semantic configurations and thin derivations. Object deletion occurs
only after a grace period or explicit execution of the plan.

- **[CSTORE-17]** GC MUST never infer liveness from access time, local cache
  temperature, or object-store listing alone.
- **[CSTORE-18]** Removing an exact materialization MUST preserve configuration,
  schedule, parent chain, and reproduction artifacts. Status reports the
  increased future restore cost.

## 06.12 Sensitive state

Exact closures may contain secrets from guest RAM, disks, application logs, or
captured traffic. Content hashes also reveal equality. Campaign storage is not
implicitly public merely because objects are content-addressed.

- **[CSTORE-19]** Backends MUST support deployment-level access control and
  encryption at rest/in transit. Export commands MUST report the sensitive
  closure classes included before transfer.
- **[CSTORE-20]** Encryption envelope randomness and storage keys MUST remain
  outside plaintext content identity so authorized replicas can verify canonical
  object hashes after decryption.

## 06.13 Streaming and future remote realization

An exact closure is a manifest over independently authenticated objects and
extents. That makes the same representation usable for object-store archival
and for a later worker transfer without adding a second migration format. A
destination fetches the small manifest and provenance closure first, determines
which objects already exist locally, and transfers only missing RAM, disk, and
device objects. Common base images and ancestor checkpoints cross a network
once; sibling deltas reuse them by content ID.

The initial implementation may require every execution-required object before
restore. A future backend may prefetch by recorded working-set hints or block a
restored process on a missing verified extent, similar to a post-copy pager. Such
blocking is operational: it cannot expose unverified bytes, advance virtual
time, or alter scheduler order. The durable closure and its object identities
remain identical whether transfer is eager, streamed, pre-copy, or demand-led.

Upload can likewise stream from a frozen exact-capture source into bounded
extent buffers while computing object and whole-artifact authentication. A
campaign ref is not advanced until its required closure is complete, even if a
destination begins speculative prefetch earlier.

- **[CSTORE-21]** A transfer protocol MUST address immutable objects or declared
  byte ranges by authenticated identity, resume idempotently, and reject an
  extent before use when its length or digest differs.
- **[CSTORE-22]** Remote fetch timing, cache hits, range-request order, and page
  stalls MUST NOT enter modeled time, configuration identity, or campaign
  guidance. Any future demand pager must pause modeled execution while required
  state is unavailable.
