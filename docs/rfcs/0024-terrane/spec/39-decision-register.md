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
    vector. The `routed` combinator orders candidates per request by expected
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

- **[D-23] Single-responsibility interfaces and unambiguous vocabulary,
  fixed before code exists.**
  - **Status:** Decided
  - **Decision:** The store interface is split into `ContentStore` and
    `RefStore`, and "authority" is defined as the child that implements
    `RefStore` rather than by a prose rule. `guard` performs authorization
    only; upload validation is an invariant of every `put` (STORE-33) and
    presigned reads belong to the `serve` role (PROTO-55). Everything
    computed from a tree is a **derivation** with one memo table and one
    verification rule; index trees and realization roots are its named
    kinds, and a ruleset compiles to a recipe rather than running as an
    engine. Overloaded words were split: "profile" is now identity profile,
    chunk profile, profile pair, or trust preset; "epoch" fences writers
    only, merged indexes have generations, and garbage collection has
    cycles. The realizer process role is `realize`, the `mount` surface is
    folded into `erofs`, and the routing combinator is `routed`.
  - **Rationale:** Each of these was a place where the specification said
    two things with one word or asked one component to do two jobs. Fixing
    them costs nothing before implementation and grows expensive after,
    because names become module boundaries and type names. A reader who
    can tell a cache from an authority by its type, and a fencing epoch
    from an index generation by its name, needs fewer rules to remember.
  - **Alternatives considered:** Keeping one `Store` trait with an
    "authority" flag (rejected: the flag is a rule, the split is a type);
    keeping `guard` as the place that also validates and presigns
    (rejected: the single enforcement point should enforce exactly one
    thing, and the threat model gets simpler); three separate memo
    mechanisms (rejected: identical semantics under three names).
  - **Affects:** `STORE-10`, `STORE-16`, `STORE-22` to `STORE-24`,
    `STORE-32`, `STORE-33`, `PROTO-55`, `AUTH-31`, `AUTH-33`, `DRV-21` to
    `DRV-23`, `ALG-30`, `RULE-21`, `RULE-22`, `REF-9`, `OBJ-8`, `CDC-2`,
    `CDC-3`, `PROV-12`, `PACK-17`, `BKT-4`, `GC-15`, `GC-22`, `GC-23`,
    `EROFS-14`, `CRATE-15`, and the glossary.

- **[D-24] Normalize prolly boundaries by stored bytes and split before overflow.**
  - **Status:** Decided
  - **Decision:** Scale the existing base threshold by the current item's
    stored encoded length divided by eight, with exact integer arithmetic
    and saturation at `2^32`. Split before an item that would exceed the
    64 KiB item-byte cap, recompute prefix compression after a split, and
    reject an item that cannot fit alone. Assess the mean target only at
    fixture levels with at least 100 complete nodes, while reporting all
    smaller samples and enforcing the hard cap everywhere. Keep every
    requirement ID stable.
  - **Rationale:** The original per-item comparison made the expected size
    depend on entry width. A reference spike over ten million entries
    measured complete leaf means of 27,674, 27,980, and 39,292 bytes for
    sequential, shared-prefix, and hash-like keys, rather than the stated
    8-16 KiB target. Closing after overflow also produced nodes above the
    hard bound, including 65,693 item bytes in an internal node. Normalizing
    by bytes restores the intended size hazard, and splitting before
    overflow preserves the decoder limit. Both decisions depend only on
    sorted content and preserve history independence. This correction occurs
    before the identity format is frozen. Small internal levels can contain
    one ordinary probabilistic cut; measured singleton means of 4,982 and
    6,431 bytes do not estimate a distribution. Requiring 100 complete nodes
    avoids treating those samples as a failed mean target while retaining
    their measurements and size checks.
  - **Alternatives considered:** Raising the decoder cap (rejected: leaves
    entry-width-dependent variance and enlarges untrusted allocations);
    weakening the target to fit the old measurements (rejected: hides the
    failed assumption); floating-point exponential normalization (rejected:
    introduces unnecessary cross-implementation rounding choices).
  - **Affects:** TREE-21 to TREE-24, TREE-27, TREE-29, RISK-5, and
    `reference/golden-vectors.md` §node-boundaries.

- **[D-25] Give every gate an explicit owner ID, including risk experiments.**
  - **Status:** Decided
  - **Decision:** Replace prose-only registry ownership with existing
    invariant, performance-methodology, or tracked-risk IDs. TEST-16 permits
    a tracked-risk owner for experiments defined in the informative risk
    register. Keep every gate name and requirement ID stable.
  - **Rationale:** Twenty-three registry rows named only prose, despite
    TEST-16 requiring a citing requirement ID in every row. The five risk
    experiments cannot cite a normative requirement because the risk
    register is deliberately informative. Recognizing its stable RISK IDs
    preserves the distinction without pretending an experiment is an
    implemented feature. Performance rows already fall under PERF-11 and
    TEST-15; invariant rows already have their own stable owners.
  - **Alternatives considered:** Accepting nonempty prose as ownership
    (rejected: makes ownership validation meaningless); moving tracked
    uncertainties into normative requirements (rejected: contradicts the
    conventions for the informative risk register).
  - **Affects:** TEST-16 and the gate registry in file 36.

- **[D-26] Fix the default FastCDC scan and dictionary identity before the
  T1 format freeze.**
  - **Status:** Decided
  - **Decision:** Derive two sparse Gear masks from the target size and
    normalization level, with set positions evenly spanning bits 16 through
    47. Start scanning at the minimum size with a fresh fingerprint for each
    chunk, compare after consuming each candidate byte, and force a cut at
    the maximum or EOF. For `cdc-1m`, use the exact masks and 16 MiB boundary
    vector in `reference/golden-vectors.md`. The 48-byte parameter describes
    the effective mask span, not a separate rolling buffer. Codec `0x02`
    carries the `terrane-chunk-v1` identity of dictionary plaintext; the
    `zstd-dictionary` attribute record carries that identity as its value
    and retains its own canonical `terrane-attr-v1` identity. Keep CDC and
    OBJ requirement IDs stable.
  - **Rationale:** CDC-1 named FastCDC and a seeded Gear table but did not
    specify the scan start, byte/cut offset convention, mask placement, or
    fingerprint reset. Those omissions let two implementations cut different
    chunks under the same profile. The [FastCDC paper](https://www.usenix.org/system/files/conference/atc16/atc16-paper-xia.pdf)
    uses a shift-and-add Gear recurrence with a skipped minimum region and
    two sparse masks; its 8 KiB mask constants do not define this profile's
    1 MiB choices. The exact derived masks preserve its 48-byte effective
    span and make the profile portable. CDC-9 previously hashed bare
    dictionary bytes under the attribute-record domain, contradicting OBJ-4
    and the canonical `AttrRecord` in the CDDL. Storing dictionary bytes as
    a chunk and referring to its ID from the attribute record preserves
    both domain meanings and ordinary content verification.
  - **Alternatives considered:** Reuse the paper's fixed 8 KiB masks
    (rejected: their cut odds do not describe `cdc-1m`); use contiguous low
    mask bits (rejected: loses the stated 48-byte effective span); identify
    bare bytes under `terrane-attr-v1` (rejected: conflicts with the
    canonical attribute-record preimage).
  - **Affects:** CDC-1, CDC-2, CDC-9, CDC-16, OBJ-4, and the gear,
    boundary, dictionary, and chunk-body references.

- **[D-27] Resolve the commit profile pair against its canonical CDDL.**
  - **Status:** Decided
  - **Decision:** Keep the CDDL `profile-pair` map unchanged: it records the
    tree-format version and chunk profile, plus its existing optional
    fields. The identity profile is fixed by the store's `store-profile`
    under OBJ-8 and is not repeated in each commit. Correct REF-9, its
    schematic commit description, and the glossary without renumbering any
    requirement.
  - **Rationale:** REF-9 said a commit records the identity profile, but
    the normative `profile-pair` CDDL has no such field. A reader cannot
    encode the prose claim without inventing a new key and changing commit
    identities. The store already binds one identity profile to its
    content, so the CDDL and OBJ-8 yield one unambiguous profile choice.
  - **Alternatives considered:** Add an identity-profile key to every
    commit (rejected: redundant with the store invariant and changes the
    canonical commit preimage); leave the prose conflict in place
    (rejected: implementations could assign incompatible commit identities).
  - **Affects:** REF-9, OBJ-8, `reference/terrane-v1.cddl` §`profile-pair`,
    and the glossary.

- **[D-28] Classify invalid read ranges within the closed store outcomes.**
  - **Status:** Decided
  - **Decision:** The store outcome `invalid` covers malformed requests and
    out-of-bounds ranges as well as rejected uploads. An invalid upload
    carries its failing rule ID; an out-of-bounds range carries a `range`
    diagnostic. The existing wire mapping of a range beyond pack end to
    `OUT_OF_RANGE` remains unchanged. Do not add another store outcome.
  - **Rationale:** STORE-4 requires exact ranged reads and STORE-30 closes
    the outcome set, but the original `invalid` description applied only
    to uploads. An out-of-bounds range cannot truthfully be `ok`, `absent`,
    or `unsupported`, while the wire error table already specifies its
    result. The broader `invalid` meaning completes the store taxonomy
    before the T1 trait freeze.
  - **Alternatives considered:** Add a store `out-of-range` outcome
    (rejected: expands the closed taxonomy); return `absent` (rejected:
    the content exists); return `unsupported` (rejected: ranged reads are
    supported, but the requested range is invalid).
  - **Affects:** STORE-4, STORE-30, and `reference/errno-mapping.md`'s
    range-beyond-pack-end mapping.

- **[D-29] Identify corrupt refs within the store error taxonomy.**
  - **Status:** Decided
  - **Decision:** Keep one `corrupt` outcome, with a typed subject that is
    either an immutable identity or a ref name. Ref records and reflog
    gaps that fail verification report the ref-name subject. Preserve the
    existing quarantine or discard behavior for bad stored data.
  - **Rationale:** REF-5 and REF-23 require malformed refs and sequence
    gaps to fail, while STORE-30 forbids an outcome outside its table.
    The original `corrupt(id)` description only named immutable content;
    classifying a valid request for bad stored ref data as `invalid` would
    blame the caller. A typed subject gives the same closed outcome a
    truthful diagnostic before the T1 store-trait freeze.
  - **Alternatives considered:** Add `corrupt-ref` (rejected: expands the
    closed taxonomy); return `invalid` (rejected: the request is valid).
  - **Affects:** REF-5, REF-23, STORE-30, and the store error table.

- **[D-30] Separate index-tree byte keys from filesystem path keys.**
  - **Status:** Decided
  - **Decision:** TREE-1/2/4/6 path-component and ancestor rules apply to
    ordinary trees. Index trees use opaque, nonempty byte keys formed as
    DRV-12 specifies; NUL and slash are ordinary key bytes. They retain
    unsigned-byte order and the 4 096-byte total key limit. A commit is
    rejected if a configured indexed value would make a longer key.
  - **Rationale:** DRV-12 concatenates canonical attribute-value bytes and
    an object hash. Those bytes may contain NUL, slash, or components over
    255 bytes; TREE-32 also forbids directory entries in an index tree.
    Applying the path grammar and ancestor rule there would make common
    valid index keys impossible. This correction keeps the same node CBOR
    encoding and requirement IDs before the T1 tree-format freeze.
  - **Alternatives considered:** Escape index bytes into path components
    (rejected: changes the DRV-12 key identity and ordering); synthesize
    directory entries (rejected: violates TREE-32).
  - **Affects:** TREE-1, TREE-2, TREE-4, TREE-6, TREE-32, DRV-12, and
    tree key validation.

- **[D-31] Make the feature matrix target-compatible and milestone-scoped.**
  - **Status:** Decided
  - **Decision:** CRATE-29 tests no-default features, every individual
    supported feature, and all mutually compatible features on each target
    supported by the current implementation milestone. Target-restricted
    features must be explicitly excluded or rejected on incompatible
    targets. A newly supported target enters the matrix before its
    milestone exits. An installed compiler target alone does not declare
    product support.
  - **Rationale:** The original wording required every feature alone and
    all features together on every supported target, while CRATE-8 calls
    `tokio` a native binding and `wasm` a WebAssembly-host binding. Their
    all-features combination cannot be a valid I/O consumer, and native
    filesystem surfaces cannot run in a WebAssembly host. The matrix must
    prove each supported configuration without requiring an invalid one
    to build or silently omitting an introduced target.
  - **Alternatives considered:** Require all-features on every target
    (rejected: contradicts native-only and WebAssembly-only features);
    omit target-limited features from the gate entirely (rejected: leaves
    feature declarations unchecked).
  - **Affects:** CRATE-8, CRATE-29, `gate:feature-matrix`, and the
    T1/B-edge target transition.

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
