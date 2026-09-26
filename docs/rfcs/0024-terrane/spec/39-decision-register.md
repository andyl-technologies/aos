# 39 — Decision register

This file records the load-bearing design decisions behind Terrane: the
choices that shaped the rest of the specification, the reasons they were
made, the alternatives that were weighed, and the requirements each decision
affects. A reader who disagrees with the system can find here where the fork
in the road was taken and why; a future revision can revisit a decision with
the original reasoning in front of it. This file is informative
([`00-conventions.md`](00-conventions.md)); the normative force lives in the
requirement IDs each entry names.

Each entry has a fixed shape:

```text
- **[D-n] <one-line title>**
  - **Status:** Decided | Open
  - **Decision:** what was chosen.
  - **Rationale:** why.
  - **Alternatives considered:** what else was on the table and why it lost.
  - **Affects:** the requirement IDs and files this decision shapes.
```

IDs are stable. A superseded decision is marked so in place and a new `D-n`
is added rather than editing history.

## Authority and storage

- **[D-1] The bucket is the only authority; there is no database.**
  - **Status:** Decided
  - **Decision:** Every durable thing, including refs, lives in an object
    store. Mutability is confined to refs and uses the store's conditional
    writes. No transactional key-value store, no cache service, no event
    store sits beside the bucket.
  - **Rationale:** Immutable content-addressed objects need no coordination
    at all, and the only mutable state is a few hundred bytes per ref. A
    conditional write is enough for that. Removing the database removes the
    open-pack lease machinery, refcount drift, root sets that live only in a
    cache, and the operational surface of three or four stateful services.
    A stateless gateway in front of a bucket scales by adding replicas.
  - **Alternatives considered:** A regional transactional key-value store
    for object metadata, chunk locations, and refcounts. It offers exact
    counters and multi-key atomicity, but it also becomes a hard dependency
    on every read path, and the whole-namespace Merkle root gives stronger
    atomicity (one compare-and-swap covers any number of keys) than the
    multi-key transaction it replaces. Rejected.
  - **Affects:** [`13-bucket-layout.md`](13-bucket-layout.md),
    [`09-refs-and-commits.md`](09-refs-and-commits.md),
    [`17-garbage-collection.md`](17-garbage-collection.md), `INV`.

- **[D-2] Writers own their packs; there are no shared open packs.**
  - **Status:** Decided
  - **Decision:** Each writer seals its own packs, however small, and a pack
    is visible only once complete. Compaction merges small packs later.
  - **Rationale:** Shared open packs require pending rows, leases, replica
    liveness, and a reaper for the case where a replica dies mid-pack. None
    of that is needed if a pack is the writer's private artifact until it is
    sealed. Small packs are an efficiency cost that compaction pays back
    asynchronously.
  - **Alternatives considered:** Loose per-chunk objects for small commits
    (millions of tiny objects, list cost); replica-owned open packs with
    quorum mirroring (the machinery above). Rejected.
  - **Affects:** [`12-pack-format.md`](12-pack-format.md),
    [`17-garbage-collection.md`](17-garbage-collection.md), `PACK`.

- **[D-3] An object's identity is the hash of its manifest.**
  - **Status:** Decided
  - **Decision:** An object is identified by the hash of its encoded
    manifest (the ordered chunk list, sizes, and declared content hashes),
    not by a hash over its plaintext. Plaintext hashes are attributes.
  - **Rationale:** Hashing the plaintext forces every commit to re-read
    every byte of every object, including objects whose chunks all already
    existed, because chunk boundaries do not align with any tree-hash block
    size. Hashing the manifest makes commit cost proportional to new data.
    Plaintext BLAKE3 and SHA-256 remain available as attributes for
    protocols that key on them.
  - **Alternatives considered:** BLAKE3 over the plaintext as identity
    (forces the re-read); a tree hash aligned to chunk boundaries (would tie
    identity to chunking parameters). Rejected.
  - **Affects:** [`04-content-model.md`](04-content-model.md) `OBJ`,
    [`10-derived-data.md`](10-derived-data.md).

- **[D-4] BLAKE3 is the primary digest; SHA-256 is carried as an attribute.**
  - **Status:** Decided
  - **Decision:** Every identity domain uses BLAKE3. Where a public protocol
    keys content by SHA-256 or another digest, that digest is a derived
    attribute and an index tree, computed once per object.
  - **Rationale:** BLAKE3 is several times faster than SHA-256 in software,
    parallelizes, and is what content-defined chunking wants at the rate of
    gigabytes per second per core. Per-chunk SHA-256 would dominate the
    write path. The attribute mechanism makes any second digest cheap and
    complete without a second identity.
  - **Alternatives considered:** SHA-256 as primary for protocol
    compatibility (write-path cost); dual identity (two names for one thing,
    ambiguous references). Rejected.
  - **Affects:** `OBJ`, `DRV`, [`33-migrations.md`](33-migrations.md).

## Trees

- **[D-5] Trees are prolly trees keyed by path relative to their root, with
  `tree` entries for grafting.**
  - **Status:** Decided
  - **Decision:** A tree is a history-independent, content-defined B-tree
    over bytewise-sorted relative paths. Composition across roots uses an
    entry that references another root, so grafting is O(1) and never
    rewrites keys.
  - **Rationale:** History independence means identical content always has
    identical nodes, so diff and merge skip equal subtrees by hash and the
    cost is proportional to the difference. Full-path keys make a directory
    listing a contiguous range scan. Relative keys plus `tree` entries make
    composition by reference cheap, which per-directory trees would give but
    at the cost of unbounded node size in flat directories.
  - **Alternatives considered:** git-style per-directory tree objects (a
    flat directory with millions of entries is one object rewritten on every
    touch); hash-keyed maps such as HAMTs (no ordered range scans, so no
    cheap `readdir`); Merkle search trees (interior values make bulk
    construction and range scans less cache-friendly for very large maps);
    absolute-path keys without `tree` entries (grafting becomes O(n) key
    rewriting). Rejected in favor of the hybrid.
  - **Affects:** `TREE`, `ALG`, [`06-tree-format.md`](06-tree-format.md),
    [`07-tree-algebra.md`](07-tree-algebra.md).

- **[D-6] Merge never fails; conflicts are values.**
  - **Status:** Decided
  - **Decision:** A three-way merge produces a tree in which each entry is
    either resolved or a conflict value holding the candidates. Policies
    resolve conflict values; a tree with unresolved conflicts is a valid,
    committable, flagged tree.
  - **Rationale:** For a cache namespace, the right answer to two writers
    binding one key is usually a policy ("prefer the trusted side", "prefer
    newer provenance"), not a failed operation. Making conflicts values lets
    folds proceed, lets resolution be a separate commit, and makes the merge
    itself a pure function.
  - **Alternatives considered:** Fail the merge on conflict (blocks folds,
    forces retries at the wrong layer); last-writer-wins by default (silent
    data loss). Rejected.
  - **Affects:** `ALG`, [`07-tree-algebra.md`](07-tree-algebra.md),
    [`20-consistency.md`](20-consistency.md).

- **[D-7] The git ref model is adopted; the git object encoding is rejected.**
  - **Status:** Decided
  - **Decision:** Branches, tags, reflogs, commits with parents, merge
    bases, remotes, and partial-clone semantics are adopted with git's
    vocabulary and layout under `refs/`. Git's blob, tree, packfile, and
    loose-object encodings are not used at rest. A git-readable projection
    is a surface.
  - **Rationale:** The ref model is a good model and a familiar one, and a
    commit graph is needed anyway for merge bases. The object encoding, by
    contrast, has no chunk-level dedup, no ranged reads, delta chains that
    defeat random access, and a hash with a header that costs a full-file
    pass. Everything a git reader needs can be derived from a tree by range
    scans and memoized by content.
  - **Alternatives considered:** Byte-compatible git repositories in the
    bucket (all of the costs above); a bespoke ref model (no gain, less
    familiarity). Rejected.
  - **Affects:** `REF`, [`09-refs-and-commits.md`](09-refs-and-commits.md),
    [`13-bucket-layout.md`](13-bucket-layout.md), `GIT`.

- **[D-8] One writer per ref by default; multi-writer is opt-in.**
  - **Status:** Decided
  - **Decision:** A ref carries a writer epoch. The default mode fences a
    single writer per ref; concurrent writers fork and fold. Multi-writer on
    one ref requires an explicit merge policy.
  - **Rationale:** Single-writer refs make `fsync`-as-commit a clean
    contract (no conflict can surface from a durability call) and make
    zombie writers impossible. The fork-and-fold path costs one ref and one
    O(delta) merge, which is what a concurrent writer would have paid anyway.
  - **Alternatives considered:** Multi-writer by default with automatic
    rebase (surprising failures inside `fsync`); server-side locks (a
    coordination service). Rejected.
  - **Affects:** `REF`, `CONS`, [`20-consistency.md`](20-consistency.md).

## Garbage collection and redundancy

- **[D-9] Mark-and-sweep with a grace window; no reference counts.**
  - **Status:** Decided
  - **Decision:** Roots are refs and retained reflog entries. Mark walks
    trees from roots, skipping subtrees already marked. Sweep deletes only
    unmarked objects older than a grace window strictly longer than the
    maximum permitted commit duration, and does so in two steps via
    tombstones.
  - **Rationale:** Reference counts need a transactional counter store
    ([D-1]) and drift under failure. Every database-free system converges on
    mark-and-sweep with a grace period because the write ordering (packs,
    then indexes, then ref) plus "never delete anything young" is sufficient
    for concurrent-upload safety. Prolly trees make marking proportional to
    distinct content.
  - **Alternatives considered:** Refcounts in the index (needs atomic
    updates across writers); TTL-only eviction (no reachability guarantee).
    Rejected.
  - **Affects:** `GC`, [`17-garbage-collection.md`](17-garbage-collection.md),
    [`09-refs-and-commits.md`](09-refs-and-commits.md).

- **[D-10] Contiguous stripes with parity, not interleaved striping.**
  - **Status:** Decided
  - **Decision:** The `striped` combinator cuts a pack into k contiguous
    byte ranges plus m parity shards. A ranged read normally touches one
    child; parity is read only on failure.
  - **Rationale:** Interleaved striping spreads every ranged read across all
    children, which defeats presigned single-range reads and makes latency
    the maximum over children. Contiguous stripes keep the single-range read
    path intact and still give reconstruction and parallel whole-pack fetch.
  - **Alternatives considered:** Interleaved RAID-style striping (the costs
    above); replication only (write amplification without the option of
    parity for cold tiers). Rejected.
  - **Affects:** `RED`, [`15-redundancy.md`](15-redundancy.md).

## Distribution

- **[D-11] Tier lists are cost-routed, not fixed-order.**
  - **Status:** Decided
  - **Decision:** Every store carries a locality label and a learned cost
    vector. The `tiered` combinator orders candidates per request by expected
    cost, with hysteresis. Configuration expresses membership, not order.
  - **Rationale:** A fixed order is right on one host and wrong in every
    other zone. Learning costs from real requests handles regions, zones,
    peers, egress price, and degraded children with one mechanism and no
    topology file to keep current.
  - **Alternatives considered:** Static ordered lists (wrong somewhere);
    explicit topology configuration (goes stale). Rejected in favor of
    measured costs with decay.
  - **Affects:** `TOPO`, [`19-tiering-and-topology.md`](19-tiering-and-topology.md),
    `RISK-12`.

- **[D-12] The commit is the consistency boundary; `fsync` binds to commit
  only in `sync` mode.**
  - **Status:** Decided
  - **Decision:** Inside a writable exposure, semantics are those of the
    local filesystem holding the upper. Nothing distributed happens until a
    commit. Writer modes select when commits happen; `sync` mode makes
    `fsync` and friends perform a commit and return after the root's
    durability policy is met.
  - **Rationale:** This keeps the hot path local and the semantics
    interpretable: exactly one distributed event, with git's meaning.
    `fsync` is the one POSIX verb that means "make durable", so it is the
    only honest binding for a commit, and it is opt-in because most
    workloads want cheap local durability and explicit commits.
  - **Alternatives considered:** Per-write replication (a distributed POSIX
    filesystem, a different project); commit on every `close` (surprising
    latency, no POSIX meaning). Rejected.
  - **Affects:** `CONS`, [`20-consistency.md`](20-consistency.md),
    `reference/errno-mapping.md`.

## Security

- **[D-13] Capability tokens and one enforcement point; no authorization
  database.**
  - **Status:** Decided
  - **Decision:** Principals hold signed, offline-attenuable capability
    tokens carrying grants over ref and root patterns. The `guard` combinator
    is the single place authorization runs. Access-control lists are
    properties on roots, versioned with the tree. Group membership comes from
    identity-provider claims.
  - **Rationale:** Authority in Terrane is already per root, so grants on
    roots are the natural unit and inherit like every other property.
    Offline attenuation lets an orchestrator hand a job a token for exactly
    its branch without a token service in the loop. Storing policy in the
    tree makes every permission change a diffable commit. A relation-graph
    service would be a hard dependency on every request.
  - **Alternatives considered:** A relation-graph authorization service
    (dependency, latency, second source of truth); per-file access-control
    lists (roots are the unit; make a root when a boundary is needed).
    Rejected.
  - **Affects:** `AUTH`, [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md),
    `PROP`.

## Exposure

- **[D-14] Surfaces are the only exposure abstraction; there is no facade
  layer.**
  - **Status:** Decided
  - **Decision:** FUSE, EROFS, block, virtiofs, the wire protocol, the Nix
    cache, REAPI, OCI, git, and HTTP browse are all surfaces implementing
    one interface over the repository. A running instance is a list of
    `view × surface × endpoint` exposures. Plugins are either in-process
    behind features or out-of-process SDK clients.
  - **Rationale:** Every one of these is "show a tree through a protocol".
    One interface with a declared schema removes a gateway abstraction, a
    separate realizer abstraction, and any special case for mounts, and it
    gives every protocol trust filtering and authorization for free by
    construction. Out-of-process plugins need no plugin interface because
    the SDK protocol is already the full API.
  - **Alternatives considered:** Separate facade and realizer layers
    (duplicated policy paths); dynamically loaded plugins (a privilege
    surface, an ABI to maintain). Rejected.
  - **Affects:** `SURF`, [`26-surfaces.md`](26-surfaces.md),
    `reference/surface-registry.md`.

- **[D-15] Rulesets are a closed vocabulary, never code.**
  - **Status:** Decided
  - **Decision:** Routing rulesets are ordered match-to-action rules over a
    registered set of matchers and actions, encoded as canonical objects. A
    new heuristic is a new registered matcher, added by revision of this
    specification.
  - **Rationale:** Rules are evaluated by a component that touches sealed
    objects and mounts. Shipping code into it would be a privilege
    escalation surface. The closed vocabulary is small, compiles to a prefix
    trie, and covers the known needs (substitution, prefetch, binding,
    tagging, guarding). Most families reduce to tree transforms at checkout.
  - **Alternatives considered:** An embedded scripting language (privilege,
    non-determinism); bytecode (same, with an ABI). Rejected.
  - **Affects:** `RULE`, [`31-routing-rulesets.md`](31-routing-rulesets.md).

## Engineering

- **[D-16] One binary with roles; separate processes and identities per
  role.**
  - **Status:** Decided
  - **Decision:** The `terrane` binary implements every role. Roles run as
    separate processes with separate service identities, privileges, and
    network access. A host, a gateway, a nested cache, and a developer
    machine differ only by configuration.
  - **Rationale:** The store trait composes, so the difference between
    deployments is a store expression and an exposure list, not a program.
    One binary keeps that honest. Separate processes per role keep the
    privilege separation that a mounter, a networkless sealer, and a
    network-facing gateway each need.
  - **Alternatives considered:** Separate binaries per role (duplicated
    configuration and drift); one process with all roles (a root-equivalent
    daemon with network access). Rejected.
  - **Affects:** `CRATE-15`, [`37-crate-structure.md`](37-crate-structure.md).

- **[D-17] The identity code is `no_std`.**
  - **Status:** Decided
  - **Decision:** Every byte that contributes to an identity is produced by
    `terrane-core`, which has no I/O, no clock, and no platform dependency.
  - **Rationale:** Identities must agree between a native host, an edge
    worker, and any future implementation. Placing the boundary exactly at
    identity means the golden vectors test the one crate that matters, and
    that crate can run anywhere.
  - **Alternatives considered:** A single `std` library with a wasm target
    (platform dependencies leak into identity code over time). Rejected.
  - **Affects:** `CRATE-1` through `CRATE-5`, `EDGE-14`.

- **[D-18] The block backend and the block surface are read-only in 1.0.**
  - **Status:** Decided
  - **Decision:** The raw block-device backend stores packs and refs and
    serves reads; the block surface exposes a deterministic EROFS layout
    lazily. Neither accepts guest writes into the shared tree in this
    version; a guest's writes go to a separate copy-on-write device or to a
    virtiofs upper.
  - **Rationale:** Committing a guest's block-level writes means mounting
    and diffing its filesystem on the host, which is more work and less lazy
    than an upper directory, and no current workload needs it. Leaving it
    out keeps 1.0's write model uniform: every write path ends in an upper
    that is walked at commit.
  - **Alternatives considered:** Block-level commit via a copy-on-write
    device diff (deferred, not precluded). Open for a later version.
  - **Affects:** `BLK`, `VBLK`, [`16-blockdev-backend.md`](16-blockdev-backend.md),
    [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md),
    `RISK-4`.

- **[D-19] The specification stands alone.**
  - **Status:** Decided
  - **Decision:** This document set names no host operating system, product,
    or prior internal system in its normative files, defines its own
    identity domains and encoding profile, and treats public protocols as
    surfaces. Adoption by a system happens in documents outside this
    directory that link inward.
  - **Rationale:** Terrane is a storage system in the way a filesystem is:
    it should be adoptable by more than one system and lifted into its own
    repository without edits. Every host-specific assumption that leaks into
    the specification is a future incompatibility.
  - **Alternatives considered:** A specification written in terms of one
    adopting system's services and formats (faster to write, not portable).
    Rejected.
  - **Affects:** `CONV-2`, `CONV-3`, every file.

- **[D-20] Naming.**
  - **Status:** Decided
  - **Decision:** The system is **Terrane**. The crates are `terrane-core`,
    `terrane`, `terrane-fs`, `terrane-edge`, and `terrane-cli`. The binary is
    `terrane`. Roles are `serve`, `mount`, `fuse-worker`, `publish`, `gc`,
    and `job`.
  - **Rationale:** A terrane is a crustal fragment that accretes onto a
    continent, which is the merge model: branches accrete onto a baseline
    without copying. The plain crate and binary names follow from [D-19].
    Adopting systems prefix their own glue crates; they do not rename these.
  - **Alternatives considered:** Names describing the two original halves
    separately (a store and a warehouse), abandoned once stores composed
    into one program; a host-system-prefixed binary name, abandoned with
    [D-19].
  - **Affects:** `CRATE-15`, [`37-crate-structure.md`](37-crate-structure.md).

## Open decisions

- **[D-21] Tenancy scope of chunk deduplication.**
  - **Status:** Open
  - **Decision:** Not yet made. Either global chunk dedup with per-domain
    namespaces, or per-domain buckets with no cross-domain dedup.
  - **Rationale:** Global dedup saves the most bytes and is what a public
    baseline wants; per-domain buckets remove the existence oracle entirely
    and match strict disclosure requirements. The disclosure-domain property
    ([`24-disclosure-domains.md`](24-disclosure-domains.md)) can express
    both; the open question is the default and the operational guidance.
  - **Alternatives considered:** Both are live. See `RISK-6`.
  - **Affects:** `DOM`, `THREAT`.

- **[D-22] Realizer priority in the first implementation.**
  - **Status:** Open
  - **Decision:** Not yet made. Whether the FUSE surface or the EROFS surface
    is built first.
  - **Rationale:** FUSE with passthrough covers both lazy and resident
    trees and is required for laziness; EROFS is the steady-state fast path
    for resident trees. FUSE first is the recommended sequence because it
    covers every case, with EROFS as an optimization.
  - **Alternatives considered:** EROFS first (fast path sooner, no laziness
    until FUSE lands).
  - **Affects:** `FUSE`, `EROFS`.
