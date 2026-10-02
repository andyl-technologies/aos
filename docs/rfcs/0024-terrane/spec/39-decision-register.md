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

- **[D-32] Align commit identity prose with the signed canonical record.**
  - **Status:** Decided
  - **Decision:** A commit identity hashes its complete canonical record,
    including key 8 when a signature is present. The signature preimage
    continues to omit key 8. Correct OBJ-21 without changing the CDDL,
    golden vectors, identity domains, or requirement IDs.
  - **Rationale:** OBJ-21 excluded signatures from identity, but the CDDL
    explicitly includes key 8 in the identity preimage, and the normative
    commit, ref, reflog, and attribute vectors use that signed-record hash.
    Keeping the canonical format and vectors avoids incompatible commit
    names and separates content addressing from signature calculation.
  - **Alternatives considered:** Hash the unsigned signature preimage
    (rejected: contradicts the CDDL identity rule and changes dependent
    golden vectors); leave the contradictory prose (rejected: readers
    could compute different identities for one stored commit).
  - **Affects:** OBJ-21, PROV-3, and the commit identity/signature preimage
    distinction in the CDDL and golden vectors.

- **[D-33] Encode deletion conflicts within the existing entry schema.**
  - **Status:** Decided
  - **Decision:** Conflict candidates are the ordered sides, with the base
    carried separately. A whiteout candidate represents an absent side.
    Correct ALG-17 to agree with TREE-31 and the canonical CDDL.
  - **Rationale:** The prose's three optional candidates contradicted the
    CDDL's complete entries and separate nullable base. Whiteouts already
    encode deletion without adding a new entry type or changing vectors.
  - **Affects:** ALG-17 and TREE-31; requirement IDs and CDDL stay stable.

- **[D-34] State probabilistic prolly complexity accurately.**
  - **Status:** Decided
  - **Decision:** Mutation and comparison costs are expected bounds;
    boundary resynchronization can take O(n) on adversarial inputs. Require
    localized rechunking and unchanged-subtree reuse explicitly.
  - **Rationale:** TREE-22's threshold depends on accumulated node size.
    A point edit can therefore shift later boundaries, contradicting the
    strict path-only rewrite claim in ALG-1. Exact canonical boundaries and
    history independence take precedence over an impossible worst-case
    bound. This does not permit unconditional whole-tree rebuilding.
  - **Affects:** ALG-1, ALG-12, ALG-15, ALG-27 and the complexity summary;
    TREE-21 to TREE-24 and encoded identities remain unchanged.

- **[D-35] Delegate schema interpretation at backend admission.**
  - **Status:** Decided
  - **Decision:** The first admitting store invokes a configured pure
    format validator for meta schemas before publishing bytes. Format code
    owns interpretation; backend code owns validation invocation, identity
    verification, and visibility. Dedup shortcuts require equivalent
    admission context, including final versus non-final chunk position.
  - **Rationale:** STORE-33 requires schema validation at the backend while
    ARCH-2 forbids the store from interpreting manifests, nodes, or commits.
    A configured validator satisfies both; an unchecked caller assertion or
    validation only in a combinator does not.
  - **Affects:** ARCH-2, STORE-33 and CDC-12 to CDC-18; no encoded format or
    requirement ID changes.

- **[D-36] Reconcile property bindings and registry types.**
  - **Status:** Decided
  - **Decision:** Encode an explicit inheritance flag using the reserved
    text-map wrapper `{"inherit": bool, "value": property-value}`; bare
    values retain their bytes and mean true. Use named text keys for quota
    fields, as required by the property-value CDDL. Follow DOM-5 reference
    ordering at graft admission and DOM-2 for effective overrides. Clarify
    class.magic and conditional ELF/shebang attribute requirements, and
    exclude the primary manifest hash from secondary hash requirements.
  - **Rationale:** The prose lacked an inheritance encoding; integer quota
    keys contradicted the CDDL; PROP-27 allowed disclosure forbidden by
    DOM-5; classifier names did not identify required attributes; and the
    primary hash has no derived attribute. These fixes preserve the existing
    CDDL, canonical bare-property bytes, and all golden vectors.
  - **Affects:** PROP-1, PROP-18, PROP-19, PROP-27, PROP-28, DOM-2, DOM-5,
    and the property registry. Requirement IDs remain unchanged.

- **[D-37] Reconcile pack envelopes and dictionary identity fields.**
  - **Status:** Decided
  - **Decision:** Data pack bodies include their codec envelope; meta
    bodies are canonical raw bytes. Raw data stored length includes the
    codec byte; plaintext length excludes it. The v1 two-byte dictionary
    field is reserved zero; codec 2's 32-byte chunk identity is authoritative.
    Require intact embedded-index recovery; unsupported unframed scanning
    fails explicitly and quarantines the damaged pack.
  - **Rationale:** Raw-length prose contradicted the codec-first body
    format, the small dictionary field had no registry or mapping to CDC-9,
    and raw bodies cannot be safely scanned without framing. Preserve
    fixed index widths and the authoritative registered dictionary domain.
  - **Affects:** PACK-4, PACK-7 to PACK-9, CDC-7, CDC-9 and the binary CDDL
    comments. No existing golden bytes or requirement IDs change.

- **[D-38] Report root metadata separately in tree diffs.**
  - **Status:** Decided
  - **Decision:** Preserve ALG-13's three entry change kinds and add a
    separate before/after root-property report.
  - **Rationale:** TREE-33 makes properties part of root identity and diff,
    but TREE-3 gives the implied root no entry. Inventing a root path entry
    would contradict the namespace model.
  - **Affects:** ALG-13, TREE-3 and TREE-33; no encoded format changes.

- **[D-39] Preserve structural conflicts as conditional directories.**
  - **Status:** Decided
  - **Decision:** A conflict containing a directory candidate may be an
    ancestor of retained descendants. They remain conditional on selecting
    a directory side; selecting a nondirectory removes them. Ordinary
    nondirectory ancestors remain invalid.
  - **Rationale:** A directory-versus-file merge can conflict at the parent
    while the directory side changes a child. Rejecting the resulting tree
    contradicts ALG-17. Conditional descendants preserve existing entry
    encodings and require explicit conflict-aware handling.
  - **Affects:** TREE-4, TREE-31, ALG-16 to ALG-19; no CDDL or golden byte
    changes, and conflict-free tree validation remains unchanged.

- **[D-40] Separate unresolved root metadata from entry conflicts.**
  - **Status:** Decided
  - **Decision:** Merge root properties per key with three-way equality.
    Explicit side preference may resolve concurrent changes; otherwise
    return a typed conflict with all three property maps for caller resolution.
    ALG-17's nonfailure rule and ALG-18's `error` restriction apply to entries.
  - **Rationale:** The implied root has no entry, and property types have
    no conflict-value encoding. Fabricating one violates PROP-1 and TREE-3;
    silently choosing a side loses concurrent metadata changes.
  - **Affects:** ALG-16 to ALG-18, TREE-3, TREE-33 and PROP-1; existing
    canonical encodings and requirement IDs remain unchanged.

- **[D-41] Rebuild locations without inventing deleted-pack state.**
  - **Status:** Decided
  - **Decision:** Reconstruct content locations from immutable per-pack
    indexes, and reconcile state using durable GC trash records, deletion
    confirmations, and the preceding generation's retained tombstones.
    Use authoritative publication metadata for generations.
  - **Rationale:** Per-pack indexes contain neither tombstones nor generation
    fields. Recreating that state from their bytes alone is impossible and
    would resurrect content forbidden by PACK-18. The registered GC and
    generation records provide the missing durable facts without a database.
  - **Affects:** PACK-17 to PACK-20, BKT-4, GC-15 and GC-20; no wire or
    on-disk layout changes, and requirement IDs remain stable.

- **[D-42] Reuse merge subtrees subject to canonical boundary compatibility.**
  - **Status:** Decided
  - **Decision:** Select a side's entire range when base equals the other
    side, without comparing those entries. Reuse its immutable subtree when
    canonical cuts fit the result; otherwise rechunk the affected edge
    regions and resume sharing at compatible boundaries.
  - **Rationale:** A TREE-22 split-before cut depends on the following item's
    stored size. A neighboring merge change can invalidate that cut even
    when the selected subtree is unchanged. Unconditional physical splicing
    would violate canonical boundaries and history independence. This keeps
    ALG-15's semantic shortcut and requires measurable compatible reuse.
  - **Affects:** ALG-15 and TREE-21 to TREE-24; canonical encoding rules and
    requirement IDs remain unchanged.

- **[D-43] Preserve effective trust when removing a root boundary.**
  - **Status:** Decided
  - **Decision:** Flatten must preserve the effective trust conjunction or
    refuse an incompatible property context, in addition to comparing
    domain, store, and ACL boundaries.
  - **Rationale:** A graft's target can require a narrower trust selector
    than its parent. Discarding that context while inlining its entries
    exposes previously invisible entries, violating PROV-14 and PROV-15
    and ALG-6's observable namespace equivalence.
  - **Affects:** ALG-6, ALG-7 and PROV-14 to PROV-15; no encoding changes
    or new property types, and requirement IDs remain stable.

- **[D-44] Match golden descriptor coverage to immutable identity.**
  - **Status:** Decided
  - **Decision:** TEST-2 requires descriptors for registered immutable
    media types and encoding vectors for mutable and wire records. Formats
    introduced later add their vectors with their conformance gates.
  - **Rationale:** Mutable refs, capabilities, and store capability records
    do not have immutable-content identity domains. Fabricating descriptors
    for them contradicts OBJ-2 and the identity registry.
  - **Affects:** TEST-2; existing golden bytes and requirement IDs remain
    unchanged. Missing pack and canonical internal-node vectors are still
    required, rather than excused by this correction.

- **[D-45] Separate derived value determinism from producer provenance.**
  - **Status:** Decided
  - **Decision:** Equal plaintext and function versions produce equal
    attribute values and function metadata. Records retain their distinct
    producers, remain immutable, and coexist across function versions.
  - **Rationale:** DRV-1 requires producer provenance in each record while
    DRV-2 required different producers to produce identical record bytes.
    Those requirements contradict each other; removing provenance would
    break PROV-9 and attribute trust selectors.
  - **Affects:** DRV-1, DRV-2, DRV-8 and PROV-9; no CDDL or existing golden
    byte changes, and requirement IDs remain unchanged.

- **[D-46] Resolve entry introductions without self-referential hashes.**
  - **Status:** Decided
  - **Decision:** Add optional profile-pair key 7 for signed, ordered
    root/path receipts. `current` means the externally calculated containing
    commit identity; sources name verified commit/root/path witnesses.
    Attribute origins and explicit reintroduction sources remain separate.
    Source commits are provenance GC roots independently of parent edges.
    Selector memos include immutable view and verified evidence context.
    Signing key identifiers name the terminal public key in lowercase hex.
  - **Rationale:** Embedding a new commit's hash in an entry changes the
    tree and consequently that same commit's hash, making PROV-7 and
    TREE-16 impossible to construct. Parent history alone cannot preserve
    a graft's introduction from an unrelated history. Memos keyed only by
    introduction and selector conflate different acceptance histories.
  - **Affects:** TREE-16, PROV-7 to PROV-10, PROV-11, PROV-16, PROV-18,
    PROV-20, GC-5 and profile-pair CDDL. This draft format correction keeps
    every existing encoding and golden vector unchanged when key 7 is
    absent; decoders explicitly recognize the extension before the format
    freeze. Requirement IDs remain stable.

- **[D-47] Register pack kinds for every stored metadata domain.**
  - **Status:** Decided
  - **Decision:** Assign pack kinds 7, 8 and 9 to derived attribute
    records, policy objects and recipe memos, respectively. Meta packs
    accept kinds 1 through 9; all existing kind assignments stay fixed.
  - **Rationale:** DRV-3 requires attribute records in meta packs, while
    PACK-13 excluded their registered identity domain. Policy objects and
    recipe memos had the same missing storage representation. Mapping them
    to another kind would violate PACK-6's domain separation.
  - **Affects:** PACK-6, PACK-13, DRV-1, DRV-3, DRV-21 and pack-kind CDDL.
    This draft correction registers previously unrepresentable metadata
    before the format freeze; existing encodings, identities and golden
    vectors remain unchanged. Requirement IDs remain stable.

- **[D-48] Make filesystem coordination and conflict mutability explicit.**
  - **Status:** Decided
  - **Decision:** Conflict refs use CAS as REF-3 and the key registry
    require. Register filesystem-only stable lock inodes and unpublished
    same-directory staging names separately from logical bucket keys.
  - **Rationale:** The layout called conflict refs create-once, preventing
    their required resolution. BKT-13 and BKT-14 require temporary writes
    and exclusion while BKT-1 otherwise prohibited their filesystem names.
  - **Affects:** REF-3, BKT-1 to BKT-3, BKT-13 and BKT-14. Logical bucket
    keys and encoded records remain unchanged; requirement IDs stay stable.

- **[D-49] Exclude the filesystem current-directory ref segment.**
  - **Status:** Decided
  - **Decision:** REF-1 rejects a segment equal to `.` as well as its
    existing consecutive-dot restriction. Other dotted names stay valid.
  - **Rationale:** A `.` segment aliases another key on a filesystem,
    contradicting BKT-3's identical layout and REF-1's distinct names.
  - **Affects:** REF-1 and BKT-3; no encoding or golden changes and no
    requirement renumbering.

- **[D-50] Publish index generations through an authoritative pointer.**
  - **Status:** Decided
  - **Decision:** Optional CAPABILITIES key 9 selects the current index
    generation after its manifest is durably stored. Publication uses CAS,
    never decreases the generation, and survives startup probes unchanged.
    Manifest shard entries omit both filter fields when no filter exists.
  - **Rationale:** STORE-11 forbids authoritative LIST, but the layout had
    no way to discover a published generation after reopening. Requiring
    filter fields also prevented publishing a shard without a filter.
  - **Affects:** BKT-4, BKT-10, STORE-11, PACK-17 and their CDDL records.
    This draft correction precedes the format freeze and preserves existing
    encodings when key 9 is absent and filter fields are present.
    Requirement IDs remain stable.

- **[D-51] Include required hard-link rewrites in the graft delta.**
  - **Status:** Decided
  - **Decision:** Graft replacement accounts for removed inline entries
    and surviving aliases whose canonical hard-link member was removed.
    Unrelated entries remain excluded from the mutation scan.
  - **Rationale:** TREE-11 stores the smallest member key in every alias.
    Removing that member necessarily changes all remaining aliases, which
    contradicts an unconditional O(log n) graft bound independent of them.
  - **Affects:** ALG-1, ALG-2 and TREE-11. No encoding or identity changes;
    requirement IDs remain stable.

- **[D-52] Inventory published pack containers in generation manifests.**
  - **Status:** Decided
  - **Decision:** Optional manifest key 5 records ordered pack ids with
    whole-pack and detached-index identities and sizes. Inventory entries
    require both artifacts to be durable, verified and mutually consistent.
    The content interface names all registered stored identity domains.
  - **Rationale:** STORE-1 to STORE-3 require whole-pack content operations,
    but packs use random-id keys and cannot be nested in pack bodies. Without
    an authoritative mapping, lookup by pack hash would require LIST, which
    STORE-11 prohibits. Attribute, policy and memo domains were also missing
    from the interface's descriptive domain list despite OBJ-2 and DRV-3.
  - **Affects:** STORE-1 to STORE-5, STORE-11, BKT-4, PACK-10, PACK-14 and
    generation-manifest CDDL. This pre-freeze draft correction preserves
    existing manifest bytes when key 5 is absent and every existing kind
    assignment and bucket key. Requirement IDs remain stable.

- **[D-53] Read collector metadata from meta packs.**
  - **Status:** Decided
  - **Decision:** GC-9 prohibits reading data-pack chunk bodies during mark;
    verified meta objects may be read from meta packs, and a data pack's
    membership comes from its detached index.
  - **Rationale:** PACK-13 stores metadata in separate meta packs. An absolute
    ban on reading any pack contradicts GC-5's required commit, tree, manifest,
    and attribute traversal. Metadata reads preserve the intended avoidance
    of reading file content during collection.
  - **Affects:** GC-5, GC-9 and PACK-13. No identity, encoding, or bucket-key
    change; requirement IDs remain stable.

- **[D-54] Carry the collector epoch in tombstone records.**
  - **Status:** Decided
  - **Decision:** Tombstone key 5 carries the collector fencing epoch and is
    mandatory for new collection tombstones.
  - **Rationale:** GC-23 requires every checkpoint and tombstone to carry its
    epoch, but the Tombstone CDDL omitted that field. Fencing cannot depend on
    an unrecorded or inferred epoch.
  - **Affects:** GC-15, GC-23 and Tombstone CDDL. This correction precedes the
    T1 encoding freeze; keys 1 to 4 and requirement IDs remain stable.

- **[D-55] Register the planned SDK checkout surface.**
  - **Status:** Decided
  - **Decision:** Register `sdk` with a `directory-path` endpoint, the
    `surface-sdk` feature, and `gate:sdk-checkout`. It realizes an authorized
    view through the repository into a new private directory. The snapshot
    requires an explicitly pinned exposure; follow mode is rejected.
  - **Rationale:** T1 requires an SDK checkout surface, but SURF-9's closed
    registry omitted that name. A private bypass would contradict CRATE-24
    and SURF-1 to SURF-3.
  - **Affects:** CRATE-22 to CRATE-28, SURF-1 to SURF-3 and SURF-9. This
    pre-freeze draft addition preserves existing surface names and IDs.

- **[D-56] Register resumable collector checkpoints.**
  - **Status:** Decided
  - **Decision:** Define version-one root, mark and state records. Immutable
    mark revisions are selected by a fenced CAS state with their hashes,
    pending frontier, and least restrictive expanded commit contexts.
  - **Rationale:** GC-7 requires incremental checkpoints, but a single
    create-once shard key cannot publish successive durable checkpoints.
    GC-24's resume safety also needs the unexpanded frontier and retention
    contexts, not only hashes already marked.
  - **Affects:** GC-4 to GC-7, GC-23, GC-24 and their CDDL/key registry. New
    keys remain under `gc/<cycle>/`; existing keys and IDs remain stable.
    This draft correction precedes T1's encoding and bucket-key freeze.

- **[D-57] Distinguish a rejected CAS from an indeterminate storage result.**
  - **Status:** Decided
  - **Decision:** Prepublication failures and compare mismatches preserve the
    ref against this writer. An unavailable result from the final atomic CAS
    may have applied; stop the writer session, preserve the error, and require
    an authoritative re-read before another advance. A failed re-read is not
    absence and an uncertain durability result is not an acknowledgement.
  - **Rationale:** REF-12 promised an unchanged ref on every failure, while
    STORE-30 permits backend failures. An atomic rename may succeed before
    its directory sync fails, and a remote CAS may apply before its response
    is lost. Rollback or a poison marker can suffer the same storage failure;
    neither can prove universal rollback. Atomicity still holds, but outcome
    certainty cannot be inferred from an unavailable response.
  - **Affects:** REF-12, STORE-7 and STORE-30. The closed error taxonomy,
    record bytes, ordering, mismatch semantics and requirement IDs remain
    unchanged. This correction precedes T1's store-interface freeze.

- **[D-58] Bind historical authorization context into commits.**
  - **Status:** Decided
  - **Decision:** Profile-pair key 8 carries the original ref, registered
    surface, locality and sorted affected root/domain pairs. New authored
    commits require it; legacy draft records retain explicit trusted-context
    verification. Historical verification uses the original context, while
    current fork, tag, read and commit operations use their current grants.
  - **Rationale:** Embedded capabilities can restrict ref, surface, locality,
    root and domain, but the prior commit schema omitted these request fields.
    Substituting a destination ref or current locality breaks legitimate
    historical verification and can fabricate the scope of original authority.
    Signatures bind the context; canonical tree witnesses and current ACL
    checks still establish the facts claimed by it.
  - **Affects:** PROV-2 to PROV-4, AUTH-19, AUTH-26, REF-31 and profile-pair
    CDDL. Key 8 is optional for legacy decoding, preserving existing bytes.
    This correction precedes T1's identity and encoding freeze.

- **[D-59] Authenticate side-only attribute producers without hash cycles.**
  - **Status:** Decided
  - **Decision:** Optional AttrRecord key 6 binds the exact unsigned record
    to the terminal key of its already sealed producer commit, using the
    registered detached-signature preimage. Trust requires the verified
    producer commit and a canonical witness for that same object's reachability.
    Legacy unsigned records need matching verified inline origin evidence.
  - **Rationale:** DRV-4 makes inline attributes optional, while PROV-9 and
    attr-by require authenticated producer evidence. A producer hash alone
    is forgeable and requiring the future record hash inside its producer
    commit would create a cycle. The detached signature is evidence independent
    of content introduction; recomputation verifies value, not authorship.
  - **Affects:** DRV-1, DRV-2, DRV-4, DRV-10, PROV-9, PROV-11 and PROV-16.
    Existing keys 1 through 5 remain byte-identical when key 6 is absent;
    signed and unsigned variants remain distinct immutable records. This
    correction precedes T1's encoding freeze.

- **[D-60] Specify checkpoint integrity hashes.**
  - **Status:** Decided
  - **Decision:** GcState checkpoint pointers are raw BLAKE3-256 of the
    selected canonical GcMark record bytes, verified on resume.
  - **Rationale:** D-56 introduced digest pointers but omitted their preimage.
    A GcMark is a collector record, not a binary Index immutable; using the
    index identity domain would misidentify its format.
  - **Affects:** GC-7, GC-24 and GcState CDDL semantics. No field, existing
    identity domain or requirement ID changes; this precedes T1's freeze.

- **[D-61] Preserve implicit private ownership across root edits.**
  - **Status:** Decided
  - **Decision:** An edit materializes the previous effective private label
    as an ordinary explicit domain property before encoding its new root.
    Unrelated roots still receive distinct implicit private defaults.
  - **Rationale:** Hashing a changed root changes its implicit label; treating
    that as a new incomparable owner makes ordinary private edits unusable.
    Preserving the already effective property keeps the boundary unchanged
    without a stable-ID field, a hash cycle or cross-domain deduplication.
  - **Affects:** DOM-1 to DOM-4 and PROP inheritance. No new encoding or key;
    this clarification precedes T1's freeze.

- **[D-62] Retain provenance metadata without retaining unrelated old data.**
  - **Status:** Decided
  - **Decision:** Witness-only traversal keeps the metadata dependencies used
    by verified entry/attribute history. Pending bit 3 and GcState key 9
    distinguish witness-only and full expansion; ordinary commit cutoffs
    remain in key 7. Retention-witness roots preserve excluded log policy
    evidence for later collections.
  - **Rationale:** Dropping old parent metadata can destroy live introduction
    proofs. Treating every proof commit as an unbounded full root instead
    retains unrelated old chunks. A marked digest alone also cannot prove
    that its children were expanded in both modes after a crash.
  - **Affects:** GC-3, GC-5 to GC-7, GC-24, GC-28, PROV-7, PROV-9 and
    PROV-10. These collector record additions precede T1's encoding freeze;
    existing identity domains and requirement IDs remain stable.

- **[D-63] Separate immutable target selection from live read policy.**
  - **Status:** Decided
  - **Decision:** A commit-target view stays on its exact immutable commit.
    Separate current-authority lookups still enforce live ACL, revocation
    and deletion policy, using a trusted instance binding or the verified
    original authoring ref as the default authority.
  - **Rationale:** SURF-6's blanket ban on any ref lookup conflicted with
    AUTH-30's immediate ACL revocation. Historical immutable ACLs are proof
    of prior policy, not a substitute for current authority. Policy lookup
    must not move a pinned target to a new head.
  - **Affects:** SURF-6, AUTH-26, AUTH-30 and PROV-23. No target, record or
    selector grammar changes; this precedes T2's surface freeze.

- **[D-64] Identify annotated tag signers by their terminal public key.**
  - **Status:** Decided
  - **Decision:** A new SnapshotEnvelope names the lowercase hexadecimal
    terminal Ed25519 public key and signs its canonical keys 1 through 4 map.
    Verification binds that key to the tagging capability and expected name
    and commit; no extra signature prefix is introduced.
  - **Rationale:** The prior signer identifier was unspecified. An issuer
    rotation key ID cannot identify an attenuated subject key. The terminal
    identifier matches signed-by-key and the existing CDDL preimage.
  - **Affects:** REF-20 and SnapshotEnvelope. Existing field numbers and
    preimage layout remain unchanged; this precedes T1's encoding freeze.

- **[D-65] Select immutable reflog proposals instead of reserving a sequence.**
  - **Status:** Decided
  - **Decision:** New branch records carry a secure-random 32-byte candidate
    ID. A create-once sibling key `logs/<ref>/<seq>:<candidate-id>` stores the
    whole proposal and complete predecessor. Whole head CAS selects committed
    history, after exact candidate/expect/new checks. Reads follow selected
    predecessors without LIST; restarted attempts receive fresh IDs. Wire
    RefValue and RefLogEntry carry their complete canonical records.
  - **Rationale:** A sequence-only create-once append abandoned before CAS
    permanently occupies the next slot, contradicting REF-13 retry progress.
    Completing or deleting it needs authority and fencing not present in the
    old record. A commit-only selector still collides across policies,
    predecessors and reasons. Random proposal IDs avoid self-hash cycles,
    and the colon sibling filename coexists with old files without colliding
    with descendant ref names. Full wire records preserve STORE-7/10.
  - **Retention:** Only selected history supplies content roots. Required
    selected-chain/snapshot metadata remains readable even when content
    retention expires; never-selected proposals do not become content roots.
    Fresh candidates prevent old proposal reuse from bypassing the original
    commit deadline; they do not refresh the age of deduplicated content.
  - **Affects:** REF-4, REF-12, REF-13, REF-21 to REF-23, REF-28, STORE-8, BKT-1 to
    BKT-3, GC-4 and record/key/wire schemas. Optional legacy record fields
    retain existing bytes; proposal IDs are not immutable content identities.
    This draft correction precedes T1's record/key and T3's wire freezes.

- **[D-66] Distinguish initial draft corrections from released revisions.**
  - **Status:** Decided
  - **Decision:** Before the initial format freeze and first conforming
    release, an explicit D-n-backed correction may advance the draft number
    without replacing the affected version-one media type. Unaffected legacy
    bytes retain their interpretation and identities. Implementation freezes
    remain binding regardless of draft status; released formats follow the
    existing media-type and specification-version revision rules.
  - **Rationale:** The initial implementation exposed missing fields and
    contradictory draft requirements before any frozen or conforming release.
    Requiring a separate released-format version for each such correction
    would falsely imply multiple supported releases. Silent draft changes
    would instead erase the compatibility obligation. Recording each change
    and preserving unaffected bytes makes the distinction explicit.
  - **Affects:** README versioning and the pre-freeze corrections recorded
    in D-35 through D-65. No existing requirement ID or identity is changed.

- **[D-67] Inventory authoritative ref names before publication.**
  - **Status:** Decided
  - **Decision:** Optional `CAPABILITIES` key 10 is a complete, sorted,
    unique, monotone list of registered ref names. New buckets initialize
    it empty under authoritative fresh creation. A name is durably registered
    before its first ref write; probes and other capability CAS operations
    preserve it. Legacy absence is unknown completeness and disables GC and
    domain deletion until an authoritative exclusive migration establishes
    a complete inventory.
  - **Rationale:** GC and domain deletion must discover every authority root,
    while STORE-11/BKT-8 forbid assuming complete bucket LIST results. A
    caller-provided subset cannot prove absence. Monotone registration makes
    a failed first write harmless and avoids deletion races from dropping
    names. Comparing inventory and whole ref records under backend exclusion
    prevents authorization of deletion from a stale subset.
  - **Affects:** BKT-17, GC-1, GC-2, DOM-20 and Capabilities CDDL. Existing
    absent-field bytes remain readable with explicitly unknown completeness.
    This correction precedes T1's encoding and store-trait freeze.

- **[D-68] Match fork authorization to the unchanged-tree fork commit.**
  - **Status:** Decided
  - **Decision:** The fork verb table describes ALG-32's fresh commit with
    the source's unchanged tree and the source commit as its parent. The
    principal needs `fork` on the source and `commit` on the destination,
    as AUTH-23 already requires. No tree node is read or rewritten by fork.
  - **Rationale:** The previous verb table said the first commit was the
    source commit itself, contradicting ALG-32's parent requirement and
    losing the new branch's authoring context. AUTH-23 already supplies the
    necessary destination write authority, without granting source writes.
  - **Affects:** ALG-32 and AUTH-22 to AUTH-24. Encodings, verb bit values
    and requirement IDs remain unchanged.

- **[D-69] Separate ordinary reflog selection from storage retention.**
  - **Status:** Decided
  - **Decision:** `retain` selects GC, lease, TTL or forever content retention.
    GC uses `reflog_retain` duration or newest committed sequence count.
    A counted record contributes its new commit, not an extra previous value.
    Count contexts use `false` parent cutoffs: ordinary parents are metadata
    witnesses, while independently selected snapshot roots expand fully.
    Existing timestamp and null cutoffs retain their encodings and meaning.
  - **Rationale:** REF-22 named a duration/count property but GC-3 treated
    `retain=gc` as if it contained a duration. Ignoring either property loses
    an explicit policy. Timestamps are advisory and cannot represent sequence
    rank; unbounded parent traversal would silently turn count retention into
    complete-history content retention. Separate full roots and witness edges
    preserve exact counted content and the proofs needed to verify it.
  - **Affects:** REF-22, GC-3, GC-5, GC-6, GC-28, GcRoot/Pending/State cutoff
    unions and the registered reflog-count reason. Existing unaffected bytes
    remain valid. This correction precedes T1's encoding freeze.

- **[D-70] Bind tag publication to source authority without a commit session.**
  - **Status:** Decided
  - **Decision:** A guarded tag publication carries the exact authorized
    source ref snapshot and its epoch. A fresh tag has sequence one and records
    that observed source epoch, not an unspecified principal-wide counter.
    Source `tag` authority permits both unannotated and annotated creation;
    terminal-key signatures bind the exact new tag name and selected commit.
    Current source authority and applicable target caveats are revalidated.
    Existing-tag replacement/deletion still requires REF-2's admin authority.
  - **Rationale:** REF-19 referred to a principal-wide epoch that no authority
    or schema defines. Requiring a commit writer session would deny legitimate
    tag-only grants, contradicting AUTH-22. Requiring admin for every new
    annotation similarly adds a restriction absent from REF-20. An exact
    guarded source snapshot supplies a defined authority fence while retaining
    the token's actual grants and caveats.
  - **Affects:** REF-19, REF-20, AUTH-22 and the tag verb table. Stored field
    numbers, epoch width and SnapshotEnvelope signature bytes remain unchanged.

- **[D-71] Distinguish GC placement retirement from identity quarantine.**
  - **Status:** Decided
  - **Decision:** Merged-record state zero remains live and state one remains
    GC retirement of a placement. State two records an identity quarantine
    that ordinary put, per-pack fallback and rebuild cannot clear. A verified
    fresh upload may replace a state-one selected row with a fresh live pack,
    while the old pack remains excluded through its durable GC evidence.
    Quarantine survives deletion of its recorded pack until explicit verified
    repair. All other state values remain reserved.
  - **Rationale:** Treating GC retirement as identity corruption permanently
    rejects valid content uploaded after collection. Treating quarantine as
    ordinary retirement lets an upload or fallback silently readmit invalid
    derived data. Distinct states preserve both fresh verified readmission and
    sticky quarantine, without resurrecting an old physical placement or
    making unrelated members unavailable.
  - **Affects:** PACK-18, PACK-20, merged-record state registration, GC-15 and
    DRV-2. Existing live and GC-tombstone bytes retain their meaning; the new
    state is registered before T1's encoding freeze under D-66.

- **[D-72] Bind algebra recipes to effective ownership and verified policy.**
  - **Status:** Decided
  - **Decision:** Register exact graft, overlay and merge argument schemas,
    root-bound effective domain pairs, the verified-path and inert-any trust
    profiles, versioned provenance-context tuples, and deterministic fold
    preprocessing. Serialized ownership or trust evidence is never authority;
    replay binds independently resolved ownership and freshly verified signed
    histories before materialization.
  - **Rationale:** ALG-28 identified a composite only by an operation and
    root hashes, while inherited ownership and path-scoped trust can change
    the result for identical roots. The generic argument map did not specify
    these semantic inputs or distinguish recorded evidence from executable
    authority. Explicit bindings make recipes reproducible without inventing
    ownership from a new digest or accepting caller-manufactured receipts.
  - **Affects:** ALG-28, ALG-36 to ALG-39, PROV-11 to PROV-14, DOM-2 and the
    recipe CDDL. Existing no-domain overlay and ordinary merge bytes retain
    their interpretation and identities. Context version one and four-field
    fold preprocessing remain unchanged where no additional evidence is
    needed. This correction precedes T1's initial encoding freeze.

- **[D-73] Bind physical pack retirement to an active incarnation.**
  - **Status:** Decided
  - **Decision:** Register complete active `[pack-id, cycle, epoch]` bindings
    in authoritative index manifest key 6. Publish the binding before trash;
    restore clears it with the serving index change. Re-exclusion requires a
    fresh cycle, tombstone and backend-derived deletion window. Final deletion
    checks the current exact binding and durable trash evidence while fenced
    against restore. All inventory and member paths honor the same exclusion.
  - **Rationale:** A crash after restore can leave an old mature tombstone.
    Reusing it during a later retirement deletes the pack before the new
    recovery window expires. Tombstoning selected members alone also leaves
    whole-pack/index inventory fallbacks able to serve the old physical pack.
    An explicit current incarnation separates stale historical trash from
    active exclusion without making GC retirement an identity quarantine.
  - **Affects:** GC-15 to GC-17, GC-29, BKT-4, PACK-18 and index manifest CDDL.
    Existing manifest fields and unaffected identities retain their meanings;
    an absent legacy field means unknown exclusion completeness, never known
    empty. This correction precedes T1's initial encoding freeze.

- **[D-74] Preserve disclosures without retaining private source graphs.**
  - **Status:** Decided
  - **Decision:** Register embedded source-authority certificates for explicit
    current reintroductions of file content, directory markers and symlink
    bytes. Bind each certificate to the complete unsigned destination commit
    with every typed certificate signature zeroed, then sign the real commit.
    Verify all candidate origins before activating exact entry or parent audit
    boundaries. Retain scoped historical authority keys independently of
    source storage and persist proof-sensitive collector contexts.
  - **Rationale:** Requiring full private source commits and trees to verify a
    public reintroduction contradicts domain isolation, offline reopening and
    private-domain erasure. Those records can expose unrelated sibling paths,
    attributes, messages and tokens. A scoped authority attests the selected
    source fact without claiming independently verified private signatures or
    complete private ancestry. Whole-commit projection avoids signature cycles
    and prevents certificate reuse on an altered destination record.
  - **Affects:** PROV-7, PROV-10, PROV-13, PROV-18, PROV-20, PROV-22,
    PROV-26 to PROV-30, DOM-7, DOM-24, GC-5, GC-7, GC-30, receipt and collector
    CDDL, and the non-object purpose registry. Legacy receipt and context-free
    collector bytes retain their meaning and identities. Special entry kinds
    remain subject to their existing disclosure requirements. This correction
    precedes T1's initial encoding freeze under D-66.

- **[D-75] Authorize affected root units independently of Merkle propagation.**
  - **Status:** Decided
  - **Decision:** Define affected roots against the canonical first parent,
    retaining root-unit grant and ACL semantics. Propagating a changed child
    digest through otherwise unchanged graft descriptors does not require
    writes to ancestor or sibling roots. Authenticate signed root claims and
    every actual changed root/domain against original and current authority.
    Removed roots retain prior policy witnesses; a fully certified audit-only
    first parent requires complete fresh materialization and view-root scope.
  - **Rationale:** PROV-4 named affected root paths without distinguishing an
    actual permission unit from a structural ancestor digest change. Requiring
    every candidate root denies a writer granted only a real nested root;
    authorizing an ordinary entry spelling instead invents a permission
    boundary that AUTH-29 forbids. Exact changes, witnessed root claims and
    independently checked current authority avoid both failure modes. This
    also preserves D-61's unchanged effective ownership and D-74's prohibition
    on inferring absence or unchangedness from discarded private evidence.
  - **Affects:** PROV-4, PROV-31, AUTH-19, AUTH-24, AUTH-26, AUTH-28 to AUTH-30,
    DOM-1 and commit-context interpretation. Field numbers, byte shapes,
    canonical ordering and unaffected identities remain unchanged; broader
    valid historical root contexts remain verifiable. This clarification
    precedes T1's initial freeze and preserves ALG-32's copied-tree fork cost.

- **[D-76] Preserve original ACL administration and bootstrap authority.**
  - **Status:** Decided
  - **Decision:** Verify original and current administrative authority
    independently for ACL changes and descendant delegation. Existing roots
    use prior canonical policies and actual ancestors. Initial view roots use
    the trusted original bootstrap ACL, retained for the physical authoring
    authority, canonical ref and writer epoch. Matching or narrowing bootstrap
    grants remains valid with `commit` alone. Descendant comparisons use their
    governing ancestor, and ordinary store changes retain placement and commit
    checks without an invented administrative requirement.
  - **Rationale:** Current administrative credentials cannot repair a signed
    ACL edit made without original authority. Conversely, requiring `admin`
    for every initial ACL denies legitimate initialization already permitted
    by its bootstrap policy. Mutable current configuration and candidate
    self-grants cannot prove the original baseline, and token issuers may span
    multiple physical authorities. An explicit trusted original-context seam
    preserves both verification and destination-only disclosure reopening.
  - **Affects:** AUTH-25, AUTH-26, AUTH-28, PROP-5, PROP-16, PROV-4 and
    PROV-31. Requirement IDs, gate names, signed fields, canonical bytes and
    identities remain unchanged. Historical token verification remains
    separate from current ACL intersection under D-58. This clarification
    precedes T1's initial freeze.

- **[D-77] Preserve nested ref names in the portable layout.**
  - **Status:** Decided
  - **Decision:** Use layout version 2 with `:record` ref/sidecar leaves and
    `:legacy` migrated numbered-log leaves in both object and filesystem stores.
    Preserve public ref grammar, record encodings and unsuffixed ref inventories.
    Keep version-1 compatibility read-only; require complete authoritative source
    evidence and external quiescent write fencing before any migration. Ordinary
    opens never silently upgrade. Implementations may refuse migration until
    its complete evidence and provider fencing are available.
  - **Rationale:** REF-1 permits both `a` and `a/b`, but an unsuffixed ref file
    obstructs the directory needed by its descendant. A numbered legacy log
    similarly obstructs a valid decimal ref segment. The actual filesystem
    regression reproduces the collision. Colon suffixes cannot alias ref
    segments, preserve BKT-3's identical logical keys and avoid narrowing the
    namespace. A version CAS cannot fence an already-open object-store writer's
    independent old ref ETag, and ref inventory alone cannot prove every legacy
    log or sidecar relocated. Exclusive migration and durable exact-byte recovery
    avoid competing authorities and incomplete cleanup.
  - **Affects:** REF-1, REF-4, BKT-1 to BKT-3, BKT-5, BKT-6, BKT-10,
    BKT-13, BKT-14 and BKT-17. Requirement IDs and gate names remain stable.
    The layout-version field changes for new namespaces; immutable identities,
    token patterns, candidate keys and ref/log record bytes are unchanged.
    This correction precedes T1's initial freeze.

- **[D-78] Retain physical incarnations and recoverable deletion intent.**
  - **Status:** Decided
  - **Decision:** Register protected creation journals with secure fresh
    incarnation nonces and durable Pending-before-mutation ordering. Qualify
    local trash age with a full same-instance monotonic wait after exact
    committed observation. Retain immutable deletion intent, index witnesses
    and exact journal ownership so partial unlink recovery can finish under
    current lease and complete current-root authorization. Synchronize the
    expected nofollow regular object through one descriptor; keep restore
    cancellation ordered before serving-generation changes.
  - **Rationale:** Equal bytes, reused inodes, filesystem timestamps and
    Tombstone fields do not prove a recovery window for a current physical
    incarnation. Invalidating age before unlink without durable operation
    ownership strands extant files after a crash. Secure versions, a
    conservative elapsed wait and exact recoverable intent prevent early
    deletion while preserving eventual reclamation and single-operation
    restore. Physical intent never substitutes for current marks or resolves
    the concurrent publication/dedup race on its own.
  - **Affects:** GC-10 to GC-16, GC-22 to GC-24, GC-29, BKT-13, BKT-14,
    the control-key registry, collector CDDL and configured filesystem binding.
    Requirement IDs, gates, immutable identities, existing Tombstone bytes and
    D-73 exclusions remain unchanged. This correction precedes T1's initial
    encoding and store-trait freeze. Native journal integration and complete
    current-root/publication fencing remain required before physical gates
    can qualify.

- **[D-79] Select complete publication and current collection authority.**
  - **Status:** Decided
  - **Decision:** Select whole logical ref, catalog, lease and retained-history
    transactions through contiguous immutable create-once publication slots.
    Retain exact committed history across ref absence; use optional reflog
    key 7 for an absent-name recreation's committed predecessor. Register
    actual local/remote backend bindings, complete trusted Guard snapshots,
    privately checked source lineage and exact current collection fences.
    Select Guard changes and lease transitions through the same protocol.
    Preserve cold unchanged-root forks by checking actually consumed evidence
    and carrying unaffected lineage through qualified unrelated changes.
    Keep publication control and physical deletion authority outside portable
    local payload; copied selected history includes a nonauthoritative origin
    stamp and requires genuine fresh destination registration. Stage a complete
    portable snapshot and atomically select it before individual cache updates
    or physical loss, preserving readable copies after interrupted projection.
  - **Rationale:** A missing ref does not identify its last committed proposal,
    and selecting by LIST or maximum sequence can promote abandoned writes.
    Independent ref, catalog or lease updates can admit deduplicated content
    while a collector still holds old marks. Mutable ETags and cache bytes
    cannot close that cross-key race. A global snapshot hash also invalidates
    unaffected cold-fork evidence after unrelated trusted-key additions;
    omitting actual Guard inputs instead silently retains stale authority.
    Immutable selection, exhaustive consumed dependencies and current effect
    checks address these gaps without inventing a database or trusting public
    records as private capabilities. External control preserves ordinary
    payload copies without importing physical age or signing authority. A
    portable snapshot also avoids treating a half-flushed ref/history cache
    pair as a committed copied view; fresh-copy genesis clears source leases.
  - **Affects:** REF-4 to REF-7, REF-12, REF-21 to REF-23, BKT-1 to BKT-5,
    BKT-10, BKT-14, BKT-17, GC-1 to GC-7, GC-22 to GC-24, GC-29, ALG-29, ALG-32
    and STORE-13. Requirement IDs, gates, immutable identity domains,
    existing signed Commit bytes and local original records remain stable.
    CAPABILITIES key 11 and RefLogRecord key 7 are optional additions;
    new protected schemas and control placement are registered before T1's
    initial freeze. Existing publication activation requires an external
    quiescent fence. Implementation, golden vectors and genuine native
    qualification remain required; these schemas alone prove no runtime gate.

- **[D-80] Distinguish record byte witnesses from authority.**
  - **Status:** Decided
  - **Decision:** Retain every existing golden byte unchanged; document
    the legacy commit's encoding and primitive-signature scope. Add
    independently encoded layout-version-2, generation-exclusion,
    CreationJournal and DeleteOperation witnesses with explicit positive
    and negative outcomes. Bind deletion decoding to an independently fixed
    canonical operation key and retain distinct physical and lease epochs.
  - **Rationale:** TEST-2 requires vectors for newly implemented formats,
    while the reference lacked D-77 and D-78 record witnesses. A structurally
    valid Invalidated journal is not deletion authority, and a canonical
    record with an invalid identity length or null required field must be
    rejected. Legacy signed bytes without D-75/D-76 context cannot prove
    authoring authority. Explicit claim scopes avoid conflating byte
    reproduction with current-root, descriptor or elapsed-time checks.
  - **Affects:** TEST-1 to TEST-3 and the golden-vector reference. Existing
    encodings, identities, requirement IDs and gate names remain unchanged.
    Physical deletion and current-authority qualification are still governed
    by their original requirements.

- **[D-81] Preserve the recorded seed of a named chunk profile.**
  - **Status:** Decided
  - **Decision:** Interpret `cdc-1m` as the registered fixed sizes, mask span
    and normalization with the exact 32-byte seed stored in its profile
    record. Correct the registry's zero-seed restatement and distinguish the
    golden vectors' all-zero seed from a constraint on stored profiles.
    Preserve every golden byte, gear-table value and boundary offset.
  - **Rationale:** CDC-2 and the `store-profile` CDDL carry the actual seed,
    and complete Guard snapshots retain that same seeded profile. Replacing
    it with an implicit zero seed changes chunk boundaries and can invalidate
    existing stored profiles. The registry's fixed-zero cell and vector
    introduction contradicted the owning requirement; the zero-seed witnesses
    establish one reproducible profile instance, not all permitted instances.
  - **Affects:** CDC-1 to CDC-3, the chunk-profile registry and golden-vector
    introduction. Requirement IDs, gate names, encodings, immutable identity
    domains and all existing golden values remain unchanged. A recorded seed
    remains immutable under CDC-3. This correction precedes T1's initial
    identity and encoding freeze.

- **[D-82] Permanently own remote physical keys and reconcile future residue.**
  - **Status:** Decided
  - **Decision:** Register complete monotone MANIFEST-key-7 pack burns,
    permanent recoverable PublicationState-key-7 owner selectors, proof case 3,
    immutable v2 sweep/copied-retirement authorization/operation and repeatable
    reconciliation passes at existing keys. Each owner covers ALL present/future
    versions and deletion markers, not a frozen handle list. No Done phase or
    completed pass discharges ownership. Retain local D-78-v1 bytes/semantics.
    First ownership requires complete current roots/history/serving/control,
    live lease/exclusion and genuine FULL same-instance G/D: ordinary sweep
    observes pack/index plus trash; copied retirement observes NEW barrier.
    Initial nonburned tombstoning retains GC-14. Later marked members require
    verified eligible fresh unburned placements with no live dependency through
    the excluded keys. After ownership, fresh secure-ID placements are the
    only restore/admission path. Every new request and selected progress uses
    the actual current whole live lease. Already-owned residue is an explicit
    GC-10/12/15/16 recovery exception, not fresh sweep or invented artifact age.
    Fair recurring reconciliation retains the owner even after empty passes.
    Copies retain visibility only. A distinct genuine destination preparation,
    CURRENT placement fence and NEW trash barrier permit FULL G/D even when
    old pack/index/witness are missing. They mint no foreign provenance or
    lineage. The final new destination owner covers future same-key residue
    and ALL canonical stale trash cycles. Local/remote copied-burn-v2 is
    additive; ordinary local D-78-v1 bytes and effects stay unchanged.
  - **Rationale:** A finite delayed pre-burn create may finish after deletion.
    Immutable permanent ownership keeps its old keys forever unservable, so
    that residue cannot threaten live fresh placements. Dynamic genuine
    version observations and fair later passes permit eventual all-version
    reclamation without an unprovable universal outstanding-create drain or
    frozen all-version list. An absence observation cannot prove no future
    residue and MUST NOT end ownership. Ordinary lease renewal/unrelated
    publication must not restart valid artifact waits; final current fences
    remain mandatory. Retiring metadata or reusing keys would break safety;
    forgetting reconciliation after one pass would break eventual GC. Ordinary
    quiescent copy can lose either/both old artifacts and deliberately does
    not import private authorization. Requiring their witness/age would strand
    residue forever; genuine new destination barrier/authority is the explicit
    alternative, not absence or copied-marker permission.
  - **Affects:** GC-4, GC-7, GC-10, GC-12, GC-14 to GC-16, GC-22 to GC-24,
    GC-26, GC-29, BKT-2, BKT-4 to BKT-9, BKT-14, BKT-17, STORE-13,
    PACK-2, PACK-15, PACK-18, PACK-20; MANIFEST/PublicationState optional key 7,
    proof case 3 and disjoint sweep/copied-retirement-v2 alternatives. Existing
    IDs, keys,
    identity domains, Tombstone bytes and local-v1 bodies remain unchanged.
    This additive registration precedes T1 encoding/key freeze; actual provider
    eventual-observation/deletion/finite-effects qualification and implementation
    remain pending, not established by a format or simulator gate.

- **[D-83] Distinguish advisory sidecars from commit-bearing GC roots.**
  - **Status:** Decided
  - **Decision:** Apply GC-1's content-root requirement to commit-bearing
    refs, including `refs/derived/`. Preserve the exact inventoried names
    and whole selected bytes of opaque `refs/notes/` sidecars in current
    publication and collection fences, without decoding them as `RefRecord`
    or treating byte patterns as content edges. Present sidecars alone do
    not make exhaustive collection unsupported; missing advisory targets
    use the existing discard or rebuild behavior.
  - **Rationale:** GC-1's unqualified "every ref" contradicted REF-3 and
    the key registry's opaque advisory sidecar records. `GcRoots` carries
    commit digests, while profiles and completeness records need not name
    any commit. Interpreting arbitrary sidecar bytes as a commit would
    invent reachability; refusing collection whenever one is present would
    strand garbage during normal operation. DRV-19 and DRV-20 already make
    memos collectible with their result and independent of correctness.
    Keeping whole selected values in the fences preserves concurrent
    publication checks without converting advisory data into authority.
  - **Affects:** REF-3, GC-1 and the bucket-key registry. Requirement IDs,
    gate names, keys, CDDL, encoded bytes and identity domains remain
    unchanged. This correction precedes T1's initial format freeze. Native
    inventory, marking and current-fence regressions remain required.

- **[D-84] Publish independent D-79 format witnesses before conformance.**
  - **Status:** Decided
  - **Decision:** Add complete diagnostic inputs and independently encoded
    canonical byte vectors for original registration/bootstrap/association,
    local and remote imports, issuer/disclosure rows, seeded profiles,
    trusted configuration/registries/Guard snapshots, root/view policy,
    backend bindings/activation and empty retained history. Treat them as
    format examples with no immutable descriptor or content identity. Extend
    them with exact raw import/trust/pin digests, structural consumed lineage,
    whole retained heads, state/pointers/proofs and next transactions. Label
    missing-inventory genesis/checkpoint bodies as negative decoder witnesses
    and construct their wire inputs without the rejecting record encoders.
    Keep all existing reference bytes unchanged. Remaining D-79 formats
    require their own witnesses before complete format conformance is claimed.
  - **Rationale:** D-79 registered new control and publication encodings,
    but the normative golden reference did not yet contain their inputs
    and exact bytes. Hand-transcribed implementation tests alone leave
    TEST-2's publication requirement unmet. An independent primitive CBOR
    encoder and explicit models make these witnesses reproducible without
    relying on the codecs they test. Represented record fields cannot
    establish native authority or replace current preservation checks.
  - **Affects:** TEST-1 to TEST-3 and the golden-vector reference. Requirement
    IDs, gate names, schemas, encodings and identity domains remain unchanged.
    This additive reference correction precedes T1's initial encoding freeze
    and establishes no native publication, collection or cold-fork claim.

- **[D-85] Publish independent two-entry pack reference witnesses.**
  - **Status:** Decided
  - **Decision:** Add complete input fields and independently reproduced
    bytes for a data pack containing two raw chunks and its header-prefixed
    detached index. Publish their registered domain-separated identities,
    the plaintext chunk identities, physical offsets and sorted records.
    Add explicit negative pack wires for an incorrect index CRC and a
    nonzero reserved index field whose CRC has been recomputed correctly.
    Preserve all existing golden bytes and format definitions.
  - **Rationale:** TEST-2 requires a pack with a two-entry index, but the
    reference omitted that format's complete wire vector. Independent
    little-endian field assembly and CRC32C avoid treating encoder output
    as its own oracle. Negative witnesses isolate CRC and reserved-field
    rejection. Container identities remain distinct from the fixture's
    random-ID field and do not enter tree or commit identities under OBJ-23.
  - **Affects:** TEST-1 to TEST-3, PACK-1, PACK-3 to PACK-7, PACK-15 and the
    golden-vector reference. Requirement IDs, schemas, identity domains
    and existing bytes remain unchanged. This additive reference correction
    precedes T1's initial format freeze and claims no native writer entropy,
    serving verification or complete golden-corpus qualification.

- **[D-86] Clarify selected side-evidence carrying witnesses and paths.**
  - **Status:** Decided
  - **Decision:** Clarify that the selected evidence tuple's producer-location
    is the checked tree/object witness. Signed side records name their actual
    producer; unsigned legacy records may name a carrying commit whose
    authenticated inline attribute origins resolve that producer. Both witness
    and producer contexts remain independently verified under PROV-9. State
    that these paths name complete nonempty entries, rather than the empty
    suffix permitted by the generic key-bytes type, and that row and side names
    agree and value bytes contain one complete canonical CBOR value.
  - **Rationale:** The previous schema comment implied that every witness
    location named the producer itself, conflicting with PROV-9's existing
    unsigned inline-history route. Syntax checking cannot authenticate that
    route or infer whether the separately addressed record is signed. The
    generic key type also serves tree suffixes and did not express the complete
    file-entry path semantics of selected side evidence. Explicit relationships
    let borrowed schema validation reject malformed tuples while preserving
    genuine checked legacy witnesses.
  - **Affects:** PROV-9, TEST-3, CRATE-4 and the selected-side-evidence reference
    comments. Requirement IDs, tuple fields, versions, identity domains and
    existing encoded bytes remain unchanged. This clarification precedes T1's
    initial encoding freeze and creates no verification or publication authority.

- **[D-87] Publish independent collection-record format witnesses.**
  - **Status:** Decided
  - **Decision:** Add 20 independently encoded golden witnesses for GcLease,
    GcRoots, GcMark, GcState, Tombstone and IndexGenerationManifest. Include
    every root reason and phase, absent and explicit-empty generation inputs,
    proof-context fieldwise order and five explicit negative decoder inputs.
    Reconstruct membership hints directly from GC-7's registered bit rule.
  - **Rationale:** TEST-2 requires vectors when a format is implemented, but
    these existing collection records lacked complete published byte/model
    witnesses. Independent CBOR primitives avoid using record encoders as
    their own oracle. Digest fields are ordinary wire models, not proof of
    authenticated history, checkpoint integrity or current effect authority.
  - **Affects:** TEST-1 to TEST-3, GC-7, GC-30 and the golden-vector reference.
    Requirement IDs, schemas, identity domains and existing bytes remain
    unchanged. These non-content-addressed records receive no immutable
    descriptor. The additive correction precedes T1's initial format freeze;
    qualification of this section does not qualify the complete golden corpus
    or native collection, grace, recovery or physical effects.

- **[D-88] Publish complete immutable descriptors and a canonical internal tree.**
  - **Status:** Decided
  - **Decision:** Add eleven descriptor witnesses with their complete immutable
    payload bytes and four node witnesses, including a level-one internal root.
    The first child closes at an independently computed TREE-21/TREE-22 cut;
    the second is the final tail. Preserve the existing hello leaf separately.
    Compare exact descriptor fields and identities, independently constructed
    node fields and the actual canonical builder's root and subtree summaries.
  - **Rationale:** TEST-2 requires every registered immutable descriptor and an
    internal node, but the reference did not contain complete witnesses for
    them. Two tiny single-entry children do not reproduce the canonical
    boundary rule. A fixed extended attribute produces a genuine profile cut
    while keeping all fields and payloads completely described. Independent
    primitive writers and public models avoid using the codecs as their own
    oracle. Deferred filter and memo payloads exercise descriptor fields only.
  - **Affects:** TEST-1 to TEST-3, OBJ-3, OBJ-4, OBJ-6, TREE-17, TREE-20 to TREE-23,
    the golden-vector reference. Requirement IDs, schemas, identity domains
    and existing bytes remain unchanged. This additive correction precedes
    T1's initial encoding freeze and does not qualify the complete golden
    corpus, deferred features or native publication authority.

- **[D-89] Publish canonical composition recipe wire witnesses.**
  - **Status:** Decided
  - **Decision:** Add seventeen recipe witnesses: twelve positive graft,
    overlay and merge field models, and five explicit structural rejections.
    Preserve operand and policy order, complete graft-entry bytes, replacement
    and optional empty domain records. Record recipe hashes separately from
    immutable-content descriptors. Include the existing inert trust profile
    as wire data without asserting executable trusted/newer authority.
  - **Rationale:** TEST-2 requires examples for implemented wire formats, but
    the reference lacked these composition encodings. Independent CBOR
    primitives and raw domain-separated hashes reproduce every field; public
    model tests compare encoded bytes, decoded fields and recipe hashes.
    Structural negative inputs bypass the rejecting recipe encoder.
  - **Affects:** TEST-1 to TEST-3, ALG-28, ALG-36 to ALG-38, the golden-vector
    reference. Requirement IDs, registered schemas, identity domains and all
    existing bytes remain unchanged. This additive correction precedes T1's
    initial encoding freeze and does not qualify complete golden coverage,
    ownership resolution, verified merge evaluation or materialization.

- **[D-90] Publish complete namespace and derived-attribute field witnesses.**
  - **Status:** Decided
  - **Decision:** Add 69 entry/root-property witnesses and 110 derived-attribute
    witnesses. Include all seven entry kinds, optional metadata presence,
    every registered root property, nested selectors, 19 attribute values,
    42 complete records and 87 structural negative inputs. Publish only
    whole positive node and attribute-record identities, with exact unsigned
    attribute signature preimages. Preserve every existing reference byte.
  - **Rationale:** TEST-2 requires vectors for implemented formats, but these
    encodings lacked complete independently constructed field models.
    Primitive CBOR assembly and raw registered-domain hashes reproduce the
    bytes without invoking their owning codecs. Separately constructed
    public models compare complete encoded and decoded fields; primitive
    negative inputs bypass rejecting encoders. An assumed future property
    is excluded from the reference under CONV-3. Unknown function versions
    remain inert retained metadata under DRV-8. Opaque provenance, grants,
    executable metadata and signatures establish no verified authority.
  - **Affects:** TEST-1 to TEST-3, TREE-1 to TREE-8, TREE-14, PROP-4, DRV-1,
    DRV-2, DRV-6, DRV-8 and the golden-vector reference. Requirement IDs,
    registered schemas, identity domains and existing bytes remain unchanged.
    This additive correction precedes T1's initial format freeze and does
    not qualify the complete corpus, derived computation, tree operations,
    policy enforcement or native publication.

- **[D-91] Complete envelope and merged-shard field witnesses.**
  - **Status:** Decided
  - **Decision:** Add eight complete chunk envelopes, 38 complete merged
    index shards and 39 independently assembled structural rejection inputs.
    Ordinary positive envelopes use the registered `cdc-1m` maximum; two
    overhead controls explicitly use a local 100-byte structural size oracle.
    Assign plaintext chunk identities to envelope inputs and index-domain
    identities to positive shards. Preserve every previous reference byte.
  - **Rationale:** TEST-2 requires vectors for implemented formats, but the
    envelope and merged-shard codecs lacked complete independent field models.
    Primitive little-endian assembly and RFC 8878 sized raw-block frames
    reproduce the wire bytes without invoking their owning codecs or a
    decompressor. Independently constructed public models compare all encoded
    and decoded fields. Ordinary size contexts also accommodate the dictionary
    plaintext. Embedded shard hashes, pack IDs and state bytes are opaque
    fields; structural checks establish no placements, authority or state
    effects. Envelope checks establish no native dictionary verification.
  - **Affects:** TEST-1 to TEST-3, CDC-7, CDC-9, PACK-17 to PACK-20 format
    fields and the golden-vector reference. Requirement IDs, wire schemas,
    identity domains and existing bytes remain unchanged. This additive
    correction precedes T1's initial format freeze and does not qualify the
    complete corpus, codec runtime, index publication or native operations.

- **[D-92] Publish complete retirement record field witnesses.**
  - **Status:** Decided
  - **Decision:** Add 27 positive and seven negative witnesses for the existing
    D-82 retirement record formats. Include disjoint authorization alternatives,
    preparation and operation phases, pass observations and coverage, owner
    selections, fences and their complete nested records. Preserve every prior
    reference byte. These non-content-addressed records receive no immutable
    descriptor or content identity.
  - **Rationale:** TEST-2 requires published vectors for implemented mutable
    and non-content-addressed formats. Independent CBOR primitives and raw
    registered hashes reproduce these bytes and embedded record relationships;
    independently constructed public models compare all decoded fields.
    Malformed wire inputs bypass the rejecting encoders. Represented nonce,
    placement, ownership and elapsed fields are untrusted data and establish
    no current authority, completed wait or physical permission.
  - **Affects:** TEST-1 to TEST-3 and the golden-vector reference. Requirement
    IDs, registered schemas, identity domains and existing bytes remain
    unchanged. This additive correction precedes T1's initial encoding freeze
    and does not qualify complete golden coverage or native operations.

- **[D-93] Publish selector and private-evidence field witnesses.**
  - **Status:** Decided
  - **Decision:** Add 86 independent witnesses, including 32 structural
    negatives, for selector ASTs, both trust-context versions, selected
    side-evidence tuples, disclosure statement preimages and complete target
    normalization. Preserve every previous reference byte. Encoder-only
    projections have no owning typed decoder; raw target-binding digests
    describe field relationships without immutable descriptors or identities.
  - **Rationale:** TEST-2 requires published vectors for implemented formats.
    Primitive CBOR construction reproduces every field and byte independently
    of the owning encoding seams. Separately constructed AST arenas and
    complete ordinary models compare decoded fields where a typed decoder
    exists; other projections receive complete primitive-field inspection.
    Exact bounded reference comparison rejects missing, duplicate, split,
    tampered and whitespace-altered sections. Signature and token fields are
    opaque data; syntax and hash relationships establish no trust, provenance
    evaluation, verified history or disclosure authority.
  - **Affects:** TEST-1 to TEST-3 and the golden-vector reference. Requirement
    IDs, registered schemas, identity domains and existing bytes remain
    unchanged. This additive correction precedes T1's initial encoding freeze
    and does not qualify complete golden coverage or native publication.

- **[D-94] Publish complete modern Commit and ref field witnesses.**
  - **Status:** Decided
  - **Decision:** Add 33 complete Commit, eight RefRecord, ten RefLogRecord
    and 96 independently constructed structural rejection witnesses. Include
    optional fields, registered recipe alternatives, complete token/context
    metadata, snapshot annotations, CAS expectations and retained predecessors.
    Only complete positive Commit records receive immutable identities.
    Publish exact unsigned Commit and annotation preimages without assigning
    content identities to mutable records, preimages or malformed inputs.
  - **Rationale:** TEST-2 requires vectors for implemented formats. Independent
    primitive CBOR tables reproduce complete wires and preimages; separately
    constructed public models compare every decoded field. The graft witness
    contains the actual canonical Tree target and independently compares its
    complete typed recipe. Exact bounded reference comparison rejects missing,
    duplicate, split, tampered and whitespace-altered sections. Signature,
    token, context and selector fields remain unverified data; structural
    comparison establishes no signed authority, backend state or publication.
  - **Affects:** TEST-1 to TEST-3, REF-9, REF-20, PROV-1, PROV-3 and the
    golden-vector reference. Requirement IDs, schemas, identity domains and
    every prior reference byte remain unchanged. This additive correction
    precedes T1's initial encoding freeze and does not qualify the complete
    corpus, policy verification or native ref operations.

- **[D-95] Publish complete local reconciliation record witnesses.**
  - **Status:** Decided
  - **Decision:** Add 12 complete positive local-v1 reconciliation records,
    68 independently assembled structural negatives and 11 exact decoder-bound
    or late-validation inputs. Preserve every previous reference byte. These
    non-content-addressed records receive no immutable descriptor or identity.
  - **Rationale:** TEST-2 requires published vectors for implemented formats.
    Independent CBOR primitives reproduce the existing five-field map and
    complete nested tuples; separately constructed public models compare all
    decoded fields. Malformed inputs bypass the rejecting encoder. Full
    borrowed validation precedes retention of the fence key. Current fence
    cycles may differ from original exclusion cycles; the existing registered
    grammar supplies the key constraint without a new size limit. Represented
    digests, incarnations and index identities establish no verified evidence,
    current authority or permission for physical effects.
  - **Affects:** TEST-1 to TEST-3, the GC-29 record-format prerequisite and
    the golden-vector reference. Requirement IDs, schemas, identity domains
    and existing bytes remain unchanged. This additive correction precedes
    T1's initial encoding freeze and does not qualify the complete corpus,
    native reconciliation or deletion operations.

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
