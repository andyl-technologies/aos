# 35 — Distributed and continuous exploration: a horizontally-scaled, persistent campaign

This file specifies how Crucible's exploration — state-space search and
coverage-guided fuzzing ([`22-advanced-features.md`](22-advanced-features.md)) —
runs **across a fleet of explorer hosts** and **persists across CI runs**, so a
campaign accumulates coverage, corpus, and failures over its whole lifetime
rather than starting from nothing each invocation. It is the realization of
[G-6] (reproduce-then-explore) at the only scale that finds the deep
order-dependent bugs distributed systems actually have: not one laptop for an
hour, but the whole fleet, indefinitely, with every machine-hour of exploration
compounding the last.

The single most important fact about this file — stated here and defended
throughout — is that **it adds no new execution path and no new state
representation**. Distribution is the *existing* content-addressed temporal
graph ([`07-temporal-graph.md`](07-temporal-graph.md)) and corpus
([`22-advanced-features.md`](22-advanced-features.md) §22.7.2) **shared across
machines**; continuity is that same graph **persisted across runs**. A node, a
checkpoint, a finding, a corpus entry, a coverage fingerprint — each is the same
object it already was; the only thing that changes is *where* it lives (one of
many hosts, instead of one) and *how long* it lives (across runs, instead of
one). Crucible's correctness check — the replay oracle ([INV-2]) plus the
single-VM fingerprint ([DET-3]) — is unchanged and unweakened; this file adds
two new equivalence gates that prove the *distribution and persistence
themselves* introduce no divergence.

Requirement IDs in this file use the prefix **DCE** (Distributed/Continuous
Exploration). The canonical gates this file is bound by are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1:
`gate:content-address`, `gate:replay-oracle`, `gate:e2e-determinism`,
`gate:harness-lint`, and `gate:adversarial-determinism`. This file additionally
**introduces two new canonical gates** — `gate:fleet-equivalence` and
`gate:campaign-continuity` — that [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
§1.1 adds to the catalog verbatim (the request is [DCE-30], §35.10).

The code blocks in this file are illustrative sketches per
[`00-conventions.md`](00-conventions.md): they show intended types and call
order so the spec is concrete, but the authoritative statement is always the
prose requirement. A sketch that disagrees with a requirement is a defect in the
sketch.

## 35.1 Position in the dependency ladder (read this first)

This file sits **above** the entire advanced-features ladder of
[`22-advanced-features.md`](22-advanced-features.md) §22.1, not beside it. It is
a pure consumer of every rung below it, and it consumes them *unchanged*:

```text
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ 7. distributed + continuous campaign  ← share graph across hosts; persist │ DCE §35  (this file)
  │                                          across runs; CLAIM/LEASE the      │
  │                                          shared frontier                   │
  │ 6. coverage-guided fuzzing             ← samples/mutates schedule+faults   │ ADV §22.7
  │ 5. state-space search                  ← enumerates Decisions at frontiers │ ADV §22.5
  │ 4. coverage feedback                   ← black-box TCG basic blocks (12)   │ ADV §22.6
  │ 3. fork                                ← instantiate a non-tip Config      │ ADV §22.3
  │ 2. complete, ORACLE-VALIDATED save/restore (07 §6, INV-2)                 │ ADV §22.4
  │ 1. exact hermetic determinism          (04, INV-1; the bedrock)           │ — (04, 09–13)
  └─────────────────────────────────────────────────────────────────────────┘
        rung 7 is built ONLY after rungs 1–6 pass their gates (G-5)
        rung 7 adds NO new execution path, NO new state representation
```

The load-bearing consequence: because rung 7 introduces nothing new to execute
or to store, the fleet store and the persistent campaign are **the same graph,
just shared and durable**. There is no "distributed execution engine" — there is
one `instantiate` (05) producing one kind of node into one kind of store, and
the store happens to be reachable from many hosts and to outlive the process.
This is the same discipline [ADV-2] imposes on every advanced feature, applied
to scale and time.

- **[DCE-1]** Distributed and continuous exploration MUST be built only on top
  of the full advanced-features ladder ([ADV-1], [G-5], [PLAN-4]): exact
  determinism, oracle-validated save/restore, fork, state-space search, coverage,
  and coverage-guided fuzzing MUST each have passed their phase gates before any
  distribution or continuity task is sequenced. Distribution and continuity MUST
  NOT be a workaround for an un-green lower rung. *Gate:* `gate:e2e-determinism`,
  `gate:replay-oracle`. *Spec:* §35.1; cross-ref 22 §22.1, [G-5], [PLAN-4].

- **[DCE-2]** Distributed and continuous exploration MUST add **no new execution
  path and no new state representation**: every node, checkpoint, finding,
  corpus entry, and coverage projection a fleet or a persistent campaign produces
  MUST be the *same* object the single-host, single-run exploration produces
  (05 [EXEC-25], 07 [TEMP-30], [ADV-2]) — realized by the one `instantiate`
  (05 [EXEC-14]), stored in the one content-addressed `DagStore`
  (07 §7), keyed by the one content address (05 [EXEC-4], 07 [TEMP-4]). Sharing a
  graph across hosts and persisting it across runs MUST NOT introduce a second
  execution path, a second store schema, or a node identity that depends on host
  or run. *Gate:* `gate:content-address`, `gate:replay-oracle`. *Spec:* §35.1;
  cross-ref 05 §9, 07 §10, 22 §22.9.

## 35.2 The distribution model: a shared content-addressed graph, work-stolen

### 35.2.1 Identity is content, not location

The fleet is a set of explorer hosts that all read and write **one shared
content-addressed `DagStore` backend**. This is exactly the remote backend the
temporal graph already anticipates ([`07-temporal-graph.md`](07-temporal-graph.md)
§7, [TEMP-22]: "the store interface MUST be backend-agnostic so future remote
backends … can be added behind the same trait without changing keys, which are
pure functions of content"). Distribution is that anticipated backend made real,
not a new mechanism.

Because a node's key is `hash(parent_id, schedule_delta)` (07 [TEMP-4]) and a
finding's artifact is the content-addressed `(def, seed, schedule)` bundle
([ADV-28], 06 §7.1), **the same node, the same finding, the same corpus entry is
the same object on any host**. Two hosts that independently expand the same
frontier node compute the same key and `put` byte-identical content; the store's
idempotent, deduplicating `put` (07 [TEMP-21], [INV-6]) collapses them to one
object. Identity travels with content, never with the host that produced it
([INV-9]: nothing host-specific enters identity).

```text
  host A                          shared DagStore                  host B
  ──────                          ───────────────                  ──────
  expand frontier node n   ──put(content)──►  key = hash(...)  ◄──put(content)── expand n
                                   │ idempotent, dedup (07 §7, INV-6)
                                   ▼
                          ONE object: key is a pure function of content
                          (07 TEMP-4) — same node on A and on B, byte-identical
```

- **[DCE-3]** The fleet MUST share a single content-addressed `DagStore` backend
  (07 §7) exposing the unchanged `put`/`get`/`exists` interface with BLAKE3
  content keys ([TEMP-21], [TEMP-22]). The backend MAY be remote (object storage,
  a shared team store) but the keys MUST remain pure functions of content, so a
  node/finding/corpus-entry is the **same object on every host**. No host-specific
  or location-specific datum MAY enter any content key ([INV-6], [INV-9]). *Gate:*
  `gate:content-address`. *Spec:* §35.2.1; cross-ref 07 §7, [TEMP-22].

- **[DCE-4]** Two hosts that expand the same frontier node MUST produce a
  byte-identical node that the store's idempotent `put` (07 [TEMP-21]) deduplicates
  to one object; the result MUST NOT depend on which host produced it first or on
  the wall-clock order of the two puts ([INV-9]). Concurrent `put` of equal
  content MUST be convergent and idempotent (§35.5). *Gate:* `gate:content-address`,
  `gate:fleet-equivalence`. *Spec:* §35.2.1; cross-ref 07 §7, §35.5.

### 35.2.2 Work distribution: CLAIM/LEASE work-stealing over the shared frontier

The search/fuzz frontier (the work-list of [`22-advanced-features.md`](22-advanced-features.md)
§22.5.1) is **the shared graph itself**: the set of frontier checkpoints not yet
expanded. Distributing work means deciding *which host expands which frontier
node*. Crucible does this by **content-addressed CLAIM/LEASE work-stealing**, not
static partitioning.

Static partitioning (host *i* owns subtree *i*) is wrong here because the search
tree is **deeply unbalanced**: symmetry reduction and partial-order reduction
(07 §9, [ADV-19]) prune whole subtrees unpredictably, so a host handed a
"balanced-looking" partition can finish in seconds while a peer grinds for hours.
Work-stealing over the shared frontier load-balances automatically: an idle host
claims the next unclaimed frontier node, expands it, and `put`s the children
back, where they become claimable frontier in turn.

A **claim** is a short-lived **lease** keyed by the frontier node's content
address: a host writes a claim record (host id, lease expiry) for a node it is
about to expand, signalling peers to prefer other nodes. A lease is a *hint*, not
a lock (§35.4): it expires, and an expired or lost claim simply means the node
becomes claimable again. Crucially, re-expanding a node whose claim was lost
**re-derives a byte-identical node** that the store dedups on `put` (§35.2.1) —
so lost or duplicated work is *repeated*, never *wrong*.

```text
  CLAIM/LEASE work-stealing loop (per host, fully content-addressed):
  ──────────────────────────────────────────────────────────────────────────
  repeat under the campaign budget:
    1. pick an unclaimed (or lease-expired) frontier node n            (§35.2.3 affinity hint)
    2. write a claim: claim[n] = (host_id, expiry = now + ttl)         (a LEASE, not a lock §35.4)
    3. instantiate(n) (05 §5) from the cheapest cached ancestor; enumerate
       its genuine Decisions (22 §22.5.1); step each child; put children to the store
    4. admit children to the shared frontier (deduped by content address, 07 §1)
    5. renew or release the lease; on crash/partition the lease just EXPIRES
  a lost/expired claim ⇒ some peer re-expands n ⇒ byte-identical node ⇒ dedup on put
       (lost work is REPEATED, never WRONG — §35.2.1, §35.4)
```

- **[DCE-5]** Fleet work distribution MUST be **content-addressed CLAIM/LEASE
  work-stealing over the shared frontier**, NOT static partitioning. Each host
  MUST pick an unclaimed (or lease-expired) frontier checkpoint, record a claim
  keyed by that checkpoint's content address, expand it via `instantiate` + genuine
  `Decision` enumeration (22 §22.5.1, [ADV-14]), and `put` its children back as new
  shared frontier (07 §1). Static per-host subtree partitioning MUST NOT be used,
  because symmetry/partial-order reduction (07 §9) makes the tree unbalanced and a
  static split strands work. *Gate:* `gate:fleet-equivalence`. *Spec:* §35.2.2;
  cross-ref 22 §22.5, 07 §9.

- **[DCE-6]** A claim MUST be a short-lived **lease** (a TTL-bounded hint that a
  host is expanding a node), NOT a durable lock. A lost, crashed, or expired claim
  MUST make its node claimable again; a peer re-expanding that node MUST re-derive
  a **byte-identical** node (05 [EXEC-4], 07 [TEMP-4]) that the store deduplicates on
  `put` ([TEMP-21]). Lost or duplicated claims MUST therefore cost only **repeated
  work**, never produce a wrong or divergent node, and MUST NOT be able to deadlock
  the fleet (§35.4). *Gate:* `gate:fleet-equivalence`, `gate:content-address`.
  *Spec:* §35.2.2; cross-ref §35.4, 07 [TEMP-21].

### 35.2.3 Soft hash-affinity is a cache hint only

To keep a host's local cache (its fat checkpoints, 07 §4) warm, a host MAY
*prefer* frontier nodes whose nearest cached ancestor it already holds — a soft
**hash-affinity**: among claimable nodes, bias toward those that fork cheaply
from state this host has materialized. This is a **performance hint only**. It
MUST NOT determine correctness, MUST NOT statically bind any node to any host,
and MUST NOT change which findings are discoverable: a node a host "prefers" is
still claimable by any peer, and a node no host prefers is still expanded.
Affinity changes only *which host tends to expand cheaply*, never *what gets
expanded* or *what a node denotes*.

- **[DCE-7]** A host MAY apply **soft hash-affinity** when choosing among
  claimable frontier nodes (prefer nodes that fork cheaply from its locally-cached
  fat ancestors, 07 §4), as a cache-warmth performance hint ONLY. Affinity MUST
  NOT statically bind a node to a host, MUST NOT remove any node from another
  host's claimable set, and MUST NOT affect any node's denoted state, any finding's
  artifact, or the discoverable finding-set (§35.3). A fleet run with affinity off
  and a fleet run with affinity on MUST discover the same finding-set with
  byte-identical artifacts (discovery order MAY differ). *Gate:*
  `gate:fleet-equivalence`. *Spec:* §35.2.3; cross-ref 07 §4, §35.3.

### 35.2.4 Dedup at four layers

The fleet does redundant work by design (work-stealing repeats lost claims), so
deduplication is what keeps redundancy cheap rather than wasteful. Crucible
deduplicates at four layers, all of them mechanisms it *already has*, now read
across hosts:

```text
  dedup layer                       mechanism (already in the design)            ref
  ────────────────────────────────  ───────────────────────────────────────────  ──────
  1. exists()-gated expansion       skip expanding a node already in the store    07 §7
  2. shared coverage-map admission  CAS-merge novelty: keep iff NEW coverage      22 §22.6, §35.3
  3. symmetry / partial-order red.  prune via shared coverage_fingerprint         07 §9, ADV-19
  4. claim-set anti-redundancy      prefer unclaimed nodes (avoid two hosts on n) §35.2.2
```

1. **`exists()`-gated expansion.** Before expanding a frontier node, a host
   checks `store.exists(child_key)` (07 §7) and skips children already present —
   another host already produced them.
2. **Shared coverage-map compare-and-merge admission.** A mutant/node is admitted
   to the corpus only if it reaches coverage no shared-map entry reaches
   ([ADV-26], §35.3); the map is the shared novelty oracle, so two hosts that find
   the same new edge admit it once.
3. **Symmetry and partial-order reduction over shared fingerprints.** The
   canonical-relabeling and independence reductions (07 §9, [ADV-19]) operate on
   the shared `coverage_fingerprint` (07 §2), so a representative pruned on one
   host is pruned fleet-wide.
4. **Claim-set anti-redundancy.** Preferring unclaimed nodes (§35.2.2) keeps two
   hosts from expanding the same node *concurrently* in the common case; the lease
   is the cheap signal that makes the common case non-redundant without a lock.

- **[DCE-8]** The fleet MUST deduplicate redundant work at four layers, each an
  existing mechanism read across hosts: (1) **`exists()`-gated expansion** — skip a
  node already present in the shared store (07 §7); (2) **shared coverage-map
  compare-and-merge admission** — admit a node/mutant iff it reaches coverage no
  shared-map entry reaches ([ADV-26], §35.3); (3) **symmetry/partial-order
  reduction over shared fingerprints** — prune representatives fleet-wide using the
  shared `coverage_fingerprint` (07 §9, §2, [ADV-19]); and (4) **claim-set
  anti-redundancy** — prefer unclaimed nodes so two hosts rarely expand one node
  concurrently (§35.2.2). None of these MAY change a node's denoted state; they only
  avoid *re-storing* or *re-expanding* what already exists. *Gate:*
  `gate:content-address`, `gate:fleet-equivalence`. *Spec:* §35.2.4; cross-ref 07
  §7/§9, 22 §22.6.

## 35.3 Continuous operation: a persistent campaign

### 35.3.1 The campaign store and the one mutable head

A **campaign** is a long-lived exploration that persists across CI runs. It is
backed by a `DagStore` instance (07 §7) — the same content-addressed store, now
durable across runs — plus a small **campaign manifest**: a CAS-advanced head
pointer naming the campaign's roots.

The manifest is the **only mutable, non-content-addressed object in the entire
system**. Everything else — every node, delta, finding, corpus entry, coverage
projection — is immutable and content-addressed (07 [TEMP-4], [INV-6]). The
manifest is a tiny ref that points at:

```text
  CampaignManifest (the ONLY mutable, non-content-addressed object):
  ──────────────────────────────────────────────────────────────────────────
    corpus_root        : ContentHash   // root of the retained corpus set (22 §22.7.2)
    coverage_map_root  : ContentHash   // root of the accumulated coverage map (§35.3.2)
    findings_root      : ContentHash   // root of the findings ledger (artifacts §35.3.3)
    genesis_pin        : ContentHash   // the baked genesis checkpoint pin (07 §3, PERF-11)
    provenance         : ProvenanceTriple  // (crucible_ver, qemu_build+series, abi_vers) §35.5/§35.6
  advanced by COMPARE-AND-SWAP on the head (§35.5); a lost CAS loses only
  bookkeeping — the nodes it would have named are independently re-discoverable.
```

The corpus, coverage-map, and findings roots are content hashes of immutable
objects; the genesis pin is the content hash of the baked checkpoint; and the
provenance triple is immutable manifest data. The manifest is a ~few-hundred-byte
mutable ref over an otherwise immutable graph. Advancing the campaign is a
**compare-and-swap** on this head (§35.5). The head path itself may be protected
by an advisory lock while it is read or advanced; no separate durable campaign
lock object is required. A lost CAS update (two runs advancing the head
concurrently) loses only the bookkeeping of *which* roots were named — the
underlying nodes, findings, and corpus entries are already in the
content-addressed store and are independently re-discoverable, so a lost head
update never loses a finding (§35.4, §35.5).

- **[DCE-9]** A campaign MUST be a persistent `DagStore` instance (07 §7) plus a
  small **campaign manifest**: a mutable head pointer naming the campaign's
  `corpus_root`, `coverage_map_root`, `findings_root`, `genesis_pin`, and
  `provenance` triple (§35.6). The corpus, coverage-map, and findings roots MUST
  each be a content hash of an immutable object. The manifest head MUST be the
  **only mutable, non-content-addressed object** in Crucible; implementations may
  serialize CAS by advisory-locking the head path itself, but MUST NOT add a
  second durable mutable campaign object. Everything the head names MUST be
  immutable and content-addressed (07 [TEMP-4], [INV-6]). *Gate:*
  `gate:content-address`, `gate:campaign-continuity`.
  *Spec:* §35.3.1; cross-ref 07 §7, §35.5.

- **[DCE-10]** The campaign head MUST be advanced by **compare-and-swap** (§35.5).
  A lost CAS (concurrent advance) MUST lose only the *naming* of roots, never a
  finding, corpus entry, or coverage edge: the named objects are already in the
  content-addressed store and MUST be independently re-discoverable, so the worst
  case of a lost head update is re-doing the bookkeeping, never losing exploration
  value. *Gate:* `gate:campaign-continuity`. *Spec:* §35.3.1; cross-ref §35.4, §35.5.

### 35.3.2 Seeding run N+1 and the monotone coverage ratchet

Run N+1 of a campaign **seeds from the prior corpus**: it loads the corpus the
manifest's `corpus_root` names and resumes coverage-guided fuzzing from it
([ADV-26], §22.7.2). This is correct *because each corpus entry is a
self-contained reproduction artifact* ([ADV-28], [ADV-26]): a `(def, seed,
schedule)` bundle that replays bit-identically with no reference to the run that
produced it (06 [SPAT-27], [INV-1]). Seeding is therefore not "resuming a
process" — it is "starting fresh fuzzing from a corpus of known-interesting
inputs," and the corpus is portable across runs precisely because it is
content-addressed and self-validating.

The **accumulated coverage map** (the manifest's `coverage_map_root`) makes
novelty *monotone across the campaign lifetime*: an input is novel iff it reaches
coverage the *accumulated* map (every prior run's coverage, unioned) does not.
Because the map only ever grows (§35.5, it is a grow-only union), coverage across
the campaign is **monotone non-decreasing**: a later run can only add coverage,
never lose it. This is the **continuous coverage ratchet** — the campaign-lifetime
analogue of the no-regression throughput ratchet ([PERF-13]) — and it is what
makes a long-running campaign *compound*: machine-hour 10,000 explores the
frontier that machine-hours 1–9,999 left, not the genesis frontier again.

> **The ratchet, forward-referenced.** The performance face of this property —
> that accumulated coverage is monotone non-decreasing across runs and that fleet
> throughput scales near-linearly to store-bandwidth saturation — is owned by
> [`25-performance-targets.md`](25-performance-targets.md) (PERF; see §35.8). This
> file states the *mechanism* (grow-only accumulated coverage map + corpus
> seeding); 25 states the *measured contract* and the perf-bench coverage of it.

- **[DCE-11]** Run N+1 of a campaign MUST seed from the corpus the manifest's
  `corpus_root` names ([ADV-26], §22.7.2). Seeding MUST be correct because each
  corpus entry is a self-contained reproduction artifact ([ADV-28]) that replays
  bit-identically with no reference to the producing run (06 [SPAT-27], [INV-1]);
  seeding MUST NOT require resuming any live process state. A corpus entry seeded
  into run N+1 MUST reproduce byte-identically to its production in run N. *Gate:*
  `gate:campaign-continuity`, `gate:replay-oracle`. *Spec:* §35.3.2; cross-ref 22
  §22.7.2, [ADV-28].

- **[DCE-12]** The campaign's accumulated coverage map (`coverage_map_root`) MUST
  make novelty monotone across the campaign lifetime: an input is novel iff it
  reaches coverage the **accumulated** map does not, and the map MUST be
  **grow-only** (§35.5), so accumulated coverage is **monotone non-decreasing**
  across runs — the **continuous coverage ratchet**. A later run MUST NOT be able to
  reduce accumulated coverage. The performance contract of this ratchet is owned by
  [`25-performance-targets.md`](25-performance-targets.md) (§35.8). *Gate:*
  `gate:campaign-continuity`. *Spec:* §35.3.2; forward-ref 25; cross-ref 22 §22.6.

### 35.3.3 The findings ledger

A campaign accumulates **failures across runs**: the manifest's `findings_root`
names a **findings ledger** — the content-addressed set of every interesting
finding's reproduction artifact ([ADV-28]) the campaign has ever produced. A
finding discovered in run 3 is still in the ledger in run 4,000; because each
entry is the self-contained `(def, seed, schedule)` artifact, any historical
finding reproduces on demand, on one laptop, from the ledger alone (§35.4
oracle-on-use). The ledger is grow-only and deduplicated by content (two runs
that rediscover the same failure store one artifact).

- **[DCE-13]** A campaign MUST accumulate failures across runs in a
  content-addressed **findings ledger** (`findings_root`): the grow-only,
  content-deduplicated set of every interesting finding's self-contained
  reproduction artifact ([ADV-28], 22 §22.8). Any historical finding MUST reproduce
  bit-identically from its ledger entry alone, on any host, with no fleet and no
  campaign store (§35.4.1, [ADV-28]). Two runs that rediscover the same failure
  MUST store one artifact (content dedup, [INV-6]). *Gate:*
  `gate:campaign-continuity`, `gate:replay-oracle`. *Spec:* §35.3.3; cross-ref 22
  §22.8, [INV-6].

### 35.3.4 Bounding storage over a campaign lifetime

An unbounded campaign would store an unbounded graph. Crucible bounds storage
with the temporal graph's existing GC (07 §8) plus two campaign-lifetime
policies, none of which can lose a finding or a corpus entry's *value*:

- **Campaign-scoped GC roots.** The GC roots (07 §8) for a persistent campaign
  are the manifest's roots: `corpus_root`, `findings_root`, `coverage_map_root`,
  and `genesis_pin`. Everything reachable from those is retained; abandoned
  search subtrees not pinned by a root are swept (07 [TEMP-25]).
- **Fat→thin eviction (value preserved).** Fat checkpoints (07 §4) are evicted to
  thin under storage pressure: eviction reclaims only the *materialization*, never
  the node — the thin form `(parent, schedule_delta)` is the source of truth and
  realizes by replay (07 [TEMP-11], [TEMP-26]). **Value is preserved; only the
  cache of it is reclaimed.**
- **Deterministic seeded corpus retention under a cap.** The corpus is capped; when
  it exceeds the cap, entries are evicted by the deterministic, seeded pruning of
  [ADV-26] (drop entries subsumed by others / lowest coverage-novelty), so two
  runs over the same campaign prune identically. Retention is bit-reproducible, so
  the corpus a campaign keeps is a deterministic function of its history, not of
  which host happened to prune.

- **[DCE-14]** A campaign MUST bound storage using the temporal-graph GC (07 §8)
  with the campaign manifest's roots (`corpus_root`, `findings_root`,
  `coverage_map_root`, `genesis_pin`) as the GC roots: everything reachable is
  retained, abandoned unpinned subtrees are swept (07 [TEMP-25], [TEMP-26]). GC MUST
  operate on the cache, never on identity or value (07 [TEMP-26]). *Gate:*
  `gate:campaign-continuity`, `gate:content-address`. *Spec:* §35.3.4; cross-ref 07
  §8.

- **[DCE-15]** Storage bounding MUST preserve value: **fat→thin eviction** (07
  [TEMP-26]) MUST reclaim only a checkpoint's materialization, never its node —
  the thin form remains the source of truth and realizes by replay (07 [TEMP-11]);
  and **corpus retention under a cap** MUST evict only by the deterministic, seeded
  pruning of [ADV-26], so the retained corpus is a bit-reproducible function of
  campaign history, identical across hosts and reruns. Eviction MUST NOT drop a
  finding from the ledger or change any node's denoted state. *Gate:*
  `gate:campaign-continuity`, `gate:replay-oracle`. *Spec:* §35.3.4; cross-ref 07
  [TEMP-26], 22 §22.7.2.

## 35.4 The determinism distinction (load-bearing)

This section is the spine of the file. Distribution and continuity make a
**precise, two-part claim** about determinism, and conflating the two parts is
the single most dangerous misreading of this design. State them separately:

> **Claim A — Reproduction is deterministic and host-independent (MUST hold).**
> Every node, checkpoint, and finding is the same content-addressed object on any
> host (§35.2.1), carries a self-contained `(def, seed, schedule)` artifact
> ([ADV-28]), and **reproduces bit-identically on one laptop with no fleet, no
> shared store, and no campaign** ([INV-1], [HARN-28]). This is non-negotiable.
>
> **Claim B — Distribution and scheduling MAY be nondeterministic (and that is
> fine).** Which host claims which node, in what wall-clock order, with what fleet
> size, under what work-stealing decisions — all of this MAY vary run to run. It
> changes only the **order** in which findings are discovered, never **any node's
> state** and never **any finding's artifact**.

The two claims are compatible because of the discipline of [INV-1]: a run is
`reduce(ScenarioDef, Schedule)`, a pure function of `(def, seed, schedule)`.
Distribution metadata — host id, claim order, lease timing, fleet size,
wall-clock — is *not* in that tuple. So distribution can be as nondeterministic
as the network is, and reduction is still pure: the fleet decides *what to
explore next* (order), never *what a thing is* (state/artifact).

### 35.4.1 Claim A: reproduction MUST hold, with no fleet or store

- **[DCE-16]** **Reproduction MUST be deterministic and host-independent.** Every
  node, checkpoint, and finding produced by any fleet or any campaign MUST be the
  same content-addressed object on any host (§35.2.1) and MUST carry a
  self-contained `(def, seed, schedule)` reproduction artifact ([ADV-28]) that
  reproduces it **bit-identically on a single host with no fleet, no shared store,
  and no campaign** ([INV-1], [HARN-28], [TEMP-23]). A finding that requires the
  fleet or the campaign store to reproduce is a defect. *Gate:* `gate:replay-oracle`,
  `gate:e2e-determinism`, `gate:fleet-equivalence`. *Spec:* §35.4.1; cross-ref 22
  §22.8.1, [ADV-28], [HARN-28].

### 35.4.2 Claim B: distribution/scheduling MAY be nondeterministic — order only

- **[DCE-17]** **Distribution and scheduling MAY be nondeterministic.** Which host
  claims which node, the wall-clock order of claims, the fleet size, and every
  work-stealing/affinity decision (§35.2) MAY vary across runs. This nondeterminism
  MUST affect only the **order** in which findings are discovered, never any node's
  denoted state and never any finding's artifact ([INV-1]). A campaign's discovered
  finding-set MAY be reached in a different order on different runs while every
  finding's artifact is byte-identical. *Gate:* `gate:fleet-equivalence`. *Spec:*
  §35.4.2; cross-ref §35.4.3.

### 35.4.3 The guardrail: distribution metadata MUST NOT flow into identity

The boundary between Claim A and Claim B is enforced by one rule: **distribution
metadata MUST NOT flow into `reduce`, any `Decision`, any content identity, or
any artifact.** Host id, claim order, lease timing, fleet size, and wall-clock
are *coordination* data; they may drive *which host does what when*, but they MUST
NOT enter the pure tuple `(def, seed, schedule)` or anything derived from it.

This is the same `[INV-9]`/`[INV-1]` discipline the engine already enforces, now
extended to the fleet/campaign control plane. It is checked two ways: at runtime
by `gate:fleet-equivalence` (§35.4.4) and at compile time by an **extension of
the harness-lint** (`gate:harness-lint`, [HARN-24]) that bans distribution
metadata — host id, lease/claim timestamps, fleet size, peer count — on any path
that influences `reduce`, a `Decision`, a content key, or an artifact, exactly as
the base lint bans wall-clock and thread-RNG in the engine.

```text
  the guardrail (what MUST NOT flow where):
  ──────────────────────────────────────────────────────────────────────────
   ALLOWED to read distribution metadata:   claim/lease scheduling, affinity hint,
                                            telemetry, progress reporting
   FORBIDDEN to read distribution metadata: reduce() · any Decision (05 §3) ·
                                            any content key (07 TEMP-4) · any artifact (ADV-28)
   enforced: gate:harness-lint extension (compile-time ban) + gate:fleet-equivalence (runtime)
```

- **[DCE-18]** Distribution metadata — host id, claim/lease order, lease
  timestamps, fleet size, peer count, wall-clock — MUST NOT flow into `reduce`
  ([INV-1]), any `Decision` (05 §3), any content identity (05 [EXEC-4], 07
  [TEMP-4]), or any reproduction artifact ([ADV-28]). It MAY drive only
  coordination (claim scheduling, affinity, telemetry). This boundary is the
  load-bearing seam between Claim A ([DCE-16]) and Claim B ([DCE-17]). *Gate:*
  `gate:harness-lint`, `gate:fleet-equivalence`. *Spec:* §35.4.3; routes [INV-1],
  [INV-9].

- **[DCE-19]** `gate:harness-lint` ([HARN-24]) MUST be **extended** to ban
  distribution metadata (host id, lease/claim timestamps, fleet size, peer count)
  on any path that influences `reduce`, a `Decision`, a content key, or an
  artifact, exactly as it bans host wall-clock and thread-RNG in the engine
  ([HARN-24], [HARN-25]). A determinism leak the lint misses MUST still be caught at
  runtime by `gate:fleet-equivalence` (§35.4.4) and localized by divergence
  bisection (24 §5), per the defense-in-depth of [HARN-26]. *Gate:*
  `gate:harness-lint`, `gate:fleet-equivalence`, `gate:divergence-bisect`. *Spec:*
  §35.4.3; routes [INV-9]; cross-ref [HARN-24], [HARN-26].

### 35.4.4 Single-host ≡ fleet equivalence (`gate:fleet-equivalence`)

The runtime proof of the whole §35.4 claim is a new canonical gate,
**`gate:fleet-equivalence`**: an exhaustive single-host search and a fleet search
over the **same `(family, seed, total budget)`** MUST discover the **same
reachable finding-set** with **byte-identical artifacts**; only the *discovery
order* may differ. This is the distributed analogue of [PERF-5]'s "serial run ≡
parallel run" bit-identity, lifted from one host's cores to many hosts.

The gate runs against the in-process double (24 §3) for breadth (a "fleet" of
`SimDouble` workers sharing an in-memory store, under the adversarial host
conditions of `gate:adversarial-determinism`, §7) and a small real-QEMU slice for
fidelity. It compares the discovered finding-sets as **content-addressed sets**
(order-insensitive) and asserts each finding's artifact is byte-identical between
the single-host and fleet runs.

```text
  gate:fleet-equivalence:
  ──────────────────────────────────────────────────────────────────────────
   given (family, seed, total_budget):
     single = exhaustive single-host search                  → finding-set S1 (artifacts)
     fleet  = same budget, K work-stealing hosts (SimDouble) → finding-set SF (artifacts)
   ASSERT  set(S1) == set(SF)              (content-addressed, ORDER-INSENSITIVE)
   ASSERT  for each finding, artifact(S1) == artifact(SF)   (BYTE-IDENTICAL)
   discovery ORDER may differ; finding-set and artifacts may NOT
   run under adversarial host conditions (24 §7); mismatch → divergence bisection (24 §5)
```

- **[DCE-20]** Crucible MUST define and maintain **`gate:fleet-equivalence`**: for
  a fixed `(family, seed, total budget)`, an exhaustive single-host search and a
  fleet (multi-host, work-stealing) search MUST discover the **same reachable
  finding-set**, compared as content-addressed sets (order-insensitive), with
  **byte-identical artifacts** per finding ([ADV-28]). Discovery order MAY differ;
  the finding-set and artifacts MUST NOT. The gate MUST run against the in-process
  double (24 §3) under the adversarial host conditions of
  `gate:adversarial-determinism` (24 §7) for breadth and a real-QEMU slice for
  fidelity, and MUST localize any mismatch via divergence bisection (24 §5). *Gate:*
  `gate:fleet-equivalence`, `gate:adversarial-determinism`. *Spec:* §35.4.4;
  cross-ref [PERF-5], 24 §3/§7, §35.10.

- **[DCE-21]** `gate:fleet-equivalence` MUST be a **pure check** under [HARN-2]:
  given the same source tree and seed corpus it MUST produce the same pass/fail
  verdict on any machine, MUST NOT depend on wall-clock, host core/host count, or
  network timing, and a flake MUST be treated as a determinism leak (a Claim-B
  datum reaching a Claim-A path) to root-cause, never quarantined ([HARN-2]). *Gate:*
  `gate:fleet-equivalence`. *Spec:* §35.4.4; routes [INV-1], [INV-9]; cross-ref
  [HARN-2].

## 35.5 Store consistency under concurrency

The fleet writes the shared store concurrently and persists it across runs, so
consistency under concurrency is a first-class concern. Crucible's answer is that
**almost everything is trivially convergent because it is content-addressed**,
and the two things that are not are handled by a CAS ref and a CRDT — with **no
distributed consensus on the hot path**.

### 35.5.1 Content-addressed objects are trivially convergent

For content-addressed objects (every node, delta, finding, corpus entry), concurrent
`put` is trivially convergent: equal content → equal key → idempotent
(07 [TEMP-21], [INV-6]). Two hosts that `put` the same node produce one object;
two hosts that `put` different nodes produce two objects with different keys.
There is no write conflict possible — the key *is* the content, so concurrent
writers cannot disagree about what a key holds. This is why the hot path (expand,
`put` children, admit to frontier) needs no locking and no consensus.

- **[DCE-22]** Concurrent `put` of content-addressed objects (nodes, deltas,
  findings, corpus entries) MUST be trivially convergent and idempotent: equal
  content yields equal key and one stored object; unequal content yields distinct
  keys (07 [TEMP-21], [INV-6]). The hot path (expand → `put` children → admit to
  frontier) MUST require **no locking and no distributed consensus** — content
  addressing makes write conflicts impossible. *Gate:* `gate:content-address`,
  `gate:fleet-equivalence`. *Spec:* §35.5.1; cross-ref 07 §7, §35.5.4.

### 35.5.2 The manifest head: a CAS-advanced ref

The only mutable object — the campaign manifest head (§35.3.1) — is advanced by
**compare-and-swap**: a run reads the current head, computes a new head naming
its added roots, and CAS-swaps. If a peer advanced the head first, the CAS fails,
the run re-reads and merges (union the coverage-map roots, union the
findings/corpus roots), and retries. A lost CAS loses only the *naming* — the
nodes/findings it would have named are already in the store and re-discoverable
(§35.4, [DCE-10]) — so the manifest is a convenience index over an immutable
graph, never a single point of data loss.

- **[DCE-23]** The campaign manifest head MUST be advanced by **compare-and-swap**
  with read-merge-retry on conflict (merge by unioning the coverage-map,
  findings, and corpus roots). A lost CAS MUST lose only bookkeeping, never a
  stored node/finding/corpus entry, which remain content-addressed and
  re-discoverable ([DCE-10]). The manifest MUST be the only object requiring a CAS;
  no other write path may. *Gate:* `gate:campaign-continuity`. *Spec:* §35.5.2;
  cross-ref §35.3.1, [DCE-10].

### 35.5.3 The coverage map: a grow-only union CRDT

The accumulated coverage map (§35.3.2) is written concurrently by every host and
must converge. It is a **grow-only set (union) CRDT**: coverage edges/blocks only
ever get *added*, and the merge of two maps is their union, which is commutative,
associative, and idempotent. So concurrent merges from any number of hosts, in
any order, converge to the same accumulated map — no coordination, no consensus,
no lost coverage. This is also exactly what makes the coverage ratchet
([DCE-12]) monotone: a union can only grow.

- **[DCE-24]** The accumulated coverage map MUST be a **grow-only union CRDT**:
  coverage is only ever added, and merge is set union (commutative, associative,
  idempotent), so concurrent merges from any number of hosts in any order converge
  to the same accumulated map with no coordination and no lost coverage. This
  convergence MUST be the mechanism of the monotone coverage ratchet ([DCE-12]).
  *Gate:* `gate:campaign-continuity`, `gate:content-address`. *Spec:* §35.5.3;
  cross-ref [DCE-12].

### 35.5.4 Claims are leases, not durable locks — no consensus on the hot path

Claims are **TTL leases, not durable locks** (§35.2.2). A partition or crash that
strands a claim simply lets the lease expire; the node becomes claimable and a
peer re-expands it to a byte-identical node (§35.2.1). The system therefore
**degrades to repeated deduped work, never to corruption or deadlock**: there is
no lock to be held by a dead host, no consensus round to stall on, and no write
that another writer can corrupt (content addressing, §35.5.1). The whole hot path
is consensus-free; only the manifest head uses a single CAS (§35.5.2), which is
off the hot path (advanced at run boundaries, not per node).

- **[DCE-25]** Claims MUST be **TTL leases, not durable locks**: a partition,
  crash, or lost claim MUST degrade only to **repeated deduped work** (§35.2.1),
  never to store corruption or deadlock. There MUST be **no distributed consensus
  on the hot path** (expand/put/admit); the only coordinated write is the manifest
  head's CAS (§35.5.2), which is off the hot path (run-boundary, not per-node). A
  dead host MUST NOT be able to block the fleet. *Gate:* `gate:fleet-equivalence`,
  `gate:campaign-continuity`. *Spec:* §35.5.4; cross-ref §35.2.2, §35.5.2.

## 35.6 Provenance gating and the ratchet seam

### 35.6.1 A campaign is keyed to the provenance triple

A campaign is keyed to the **provenance triple** of [PKG-36]/[PKG-38]: the
Crucible software version, the QEMU build identity + applied series hash, and the
three ABI versions (shmem, guest↔host channel, RPC). This triple is recorded in
the manifest (§35.3.1) and in every reproduction artifact ([PKG-38], [HARN-28]).

Seeding (§35.3.2) **refuses cross-provenance corpus reuse**: a corpus entry
produced under one provenance triple MUST NOT be seeded into a campaign with a
different triple, because a QEMU/ABI bump can change the instruction stream and so
a "reproducible" corpus entry from the old binary is not reproducible under the
new one ([PKG-37]: "a determinism run reproduces only against the *exact* QEMU
build that produced it", [PKG-38] refuses mismatched replay). A provenance change
therefore **forks a fresh campaign lineage**: the new campaign starts a new
manifest (new accumulated coverage, new corpus, new genesis pin), and the old
lineage's findings remain reproducible against the old binary (the ledger pins its
provenance per entry).

```text
  provenance gating on seed:
  ──────────────────────────────────────────────────────────────────────────
   manifest.provenance == run.provenance  →  seed prior corpus (§35.3.2) — same lineage
   manifest.provenance != run.provenance  →  REFUSE reuse; FORK a fresh campaign lineage
        (new accumulated coverage, new corpus, new genesis pin; old ledger stays
         reproducible against the old QEMU build — PKG-37/PKG-38)
```

- **[DCE-26]** A campaign MUST be keyed to the **provenance triple** of [PKG-36]
  (Crucible version, QEMU build identity + series hash, the three ABI versions),
  recorded in the manifest (§35.3.1) and in every artifact ([PKG-38]). Seeding
  ([DCE-11]) MUST **refuse cross-provenance corpus reuse**: a corpus entry produced
  under one provenance triple MUST NOT be seeded into a campaign with a different
  triple, since a QEMU/ABI bump may change the instruction stream ([PKG-37],
  [PKG-38]). *Gate:* `gate:campaign-continuity`, `gate:e2e-determinism`. *Spec:*
  §35.6.1; cross-ref 26 §26.10, [PKG-36], [PKG-38].

- **[DCE-27]** A provenance change (a QEMU/ABI/version bump, a re-gated packaging
  event [PKG-16]) MUST **fork a fresh campaign lineage**: a new manifest with new
  accumulated coverage, corpus, and genesis pin. The prior lineage's findings MUST
  remain reproducible against the binary that produced them (each ledger entry pins
  its own provenance, [DCE-13], [PKG-38]). A campaign MUST NOT silently mix corpora
  or coverage across provenance boundaries. *Gate:* `gate:campaign-continuity`.
  *Spec:* §35.6.1; cross-ref [PKG-16], [PKG-38], §35.3.3.

### 35.6.2 The ratchet seam: same interface, future shared substrate

The fleet-visible content-addressed store is the **same seam** at which a future
RFC-0007 (`ratchet`) shared substrate would slot in. Per [PKG-33]/[PKG-34], the
store Crucible needs now is the self-contained `crucible-cas` crate — a
content-addressed store plus a dependency-gated invalidation primitive — behind a
**narrow interface** (`put`/`get`/`has` by content hash). The fleet's shared
backend (§35.2.1) and the campaign's persistent store (§35.3.1) are *both* that
same `crucible-cas` interface, now backed by a remote/durable implementation
(07 [TEMP-22]). A future RFC-0007 shared content-addressed store would replace
`crucible-cas`'s internals behind that unchanged interface ([PKG-35]), gated by
re-running `gate:content-address` and `gate:replay-oracle` with no behavioral
change.

Crucible ships **standalone** ([NG-7]): the seam is **documented text, not a
dependency**. The fleet and campaign require no RFC-0007 code; they require only
the `crucible-cas` interface, which a remote backend satisfies today. RFC-0007
(`ratchet`) MAY be named here as an AOS sibling; nothing in this file depends on
it landing.

- **[DCE-28]** The fleet's shared store (§35.2.1) and the campaign's persistent
  store (§35.3.1) MUST both be the **same narrow `crucible-cas` interface**
  ([PKG-33], [PKG-34]) — `put`/`get`/`exists`/`has` by content hash — backed by a
  remote/durable implementation behind the backend-agnostic trait (07 [TEMP-22]).
  This interface MUST be the documented seam at which a future RFC-0007 (`ratchet`)
  shared substrate would slot in ([PKG-35]), replacing internals behind the
  unchanged interface and re-gated by `gate:content-address` and
  `gate:replay-oracle`. *Gate:* `gate:content-address`, `gate:replay-oracle`.
  *Spec:* §35.6.2; cross-ref 26 §26.9, [PKG-34], [PKG-35].

- **[DCE-29]** Crucible MUST ship **standalone** ([NG-7]): the fleet and the
  persistent campaign MUST take no build- or run-time dependency on any RFC-0007
  (`ratchet`) crate or artifact, and all gates MUST pass with no RFC-0007 code in
  the tree ([PKG-32]). The ratchet seam (§35.6.2) MUST be documented text (a
  module-doc merge marker per [PKG-34]), never a dependency. RFC-0007 (`ratchet`)
  MAY be named as an AOS sibling. *Gate:* `gate:e2e-determinism`,
  `gate:content-address`. *Spec:* §35.6.2; routes [NG-7]; cross-ref 26 §26.9.

## 35.7 Packaging: from-source fleet store, wired as a fleet check

Per [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md), the
fleet store and the distributed/continuous capability are AOS components built
from source. The shared/durable store backend is a from-source AOS package
(no host tools, no nixpkgs, [PKG-1]); the capability is wired as an **AOS
VM/fleet check** in the `lib/testing` VM/fleet harness class (the same class
`gate:e2e-determinism` uses, [PKG-29]), and runs **TCG-only** with no
`requiredSystemFeatures = [ "kvm" ]` ([PKG-30], [G-1]). This is a forward-ref:
[`26-packaging-aos-integration.md`](26-packaging-aos-integration.md) owns the
packaging detail; this file states only that the fleet store is an AOS
from-source component and the capability is a fleet check.

- **[DCE-31]** The fleet/campaign store backend MUST be an AOS package built
  **hermetically from source** ([PKG-1]) — no host tools, no nixpkgs, AOS-built
  dependencies only — and the distributed/continuous capability MUST be wired as
  an AOS **VM/fleet check** (the `lib/testing` fleet harness, [PKG-29]) running
  **TCG-only** without `requiredSystemFeatures = [ "kvm" ]` ([PKG-30], [G-1]). The
  packaging detail is owned by [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md).
  *Gate:* `gate:fleet-equivalence`, `gate:e2e-determinism`. *Spec:* §35.7;
  forward-ref 26; routes [G-1], [G-7].

## 35.8 Performance (forward-ref to 25)

The performance contract for distribution and continuity is **owned by
[`25-performance-targets.md`](25-performance-targets.md)** (PERF); this file
states the shape and forward-references the numbers:

- **Fleet throughput scales near-linearly** with the number of explorer hosts,
  up to **store-bandwidth saturation**: total exploration ≈ `hosts × per-host
  lookahead P` (the per-host parallelism `P` of [PERF-3], multiplied across the
  fleet), because hosts coordinate only through the shared content-addressed store
  and the consensus-free hot path (§35.5). The bound is the shared store's
  read/write bandwidth, not coordination overhead.
- **The continuous coverage ratchet** ([DCE-12]) is the campaign-lifetime
  monotone-non-decreasing-coverage property; its measured contract (and the
  perf-bench coverage of fleet throughput) is the no-regression ratchet of 25
  ([PERF-13] family, extended to the campaign).

- **[DCE-32]** The performance contract for fleet throughput (near-linear scaling
  to store-bandwidth saturation, total ≈ `hosts × per-host lookahead P`) and the
  continuous coverage ratchet ([DCE-12]) MUST be owned and gated by
  [`25-performance-targets.md`](25-performance-targets.md) (PERF, `gate:perf-bench`).
  This file MUST NOT restate those numbers; it states only the mechanism (§35.2,
  §35.5) that makes near-linear scaling possible (consensus-free hot path, shared
  content-addressed store). *Gate:* `gate:fleet-equivalence`. *Spec:* §35.8;
  forward-ref 25; routes [G-9].

## 35.9 Risks

- **Store consistency.** *Risk:* concurrent writers across a fleet and across runs
  corrupt or lose data. *Mitigation:* content addressing makes the hot path
  consensus-free and conflict-free (§35.5.1); the one mutable object is a
  CAS-advanced ref whose loss is only bookkeeping (§35.5.2, [DCE-10]); coverage is
  a grow-only union CRDT that converges without coordination (§35.5.3). No
  distributed consensus on the hot path; degrade to repeated deduped work, never
  corruption (§35.5.4). *Gate:* `gate:content-address`, `gate:campaign-continuity`.

- **Corpus poisoning across runs.** *Risk:* a malformed, stale, or
  wrong-provenance corpus entry seeds run N+1 and corrupts exploration.
  *Mitigation:* corpus entries are **self-validating artifacts** (each is a
  content-addressed, oracle-validated `(def, seed, schedule)` bundle, [ADV-28],
  [ADV-26]) that fail loudly on a tampered hash; **provenance gating** refuses
  cross-provenance reuse (§35.6.1, [DCE-26]); and **oracle-on-use** revalidates a
  seeded entry on first use (replay oracle, 07 §6, [ADV-11]). A poisoned entry
  cannot silently corrupt — it either reproduces bit-identically or is rejected.
  *Gate:* `gate:replay-oracle`, `gate:campaign-continuity`.

- **Cost.** *Risk:* a fleet plus durable storage is expensive; redundant
  work-stealing wastes machine-hours. *Mitigation:* the four dedup layers
  (§35.2.4) keep redundancy cheap; idle fast-forward and CoW forks keep per-node
  cost low (22 §22.7.2, [PERF-16]); storage is bounded by GC + fat→thin eviction +
  capped corpus retention (§35.3.4); and throughput scales near-linearly so cost
  buys proportional coverage (§35.8). *Gate:* `gate:perf-bench` (owned by 25).

- **The ratchet-substrate gate.** *Risk:* the fleet/campaign accidentally takes a
  hard dependency on RFC-0007 (`ratchet`) before it lands. *Mitigation:* the seam
  is the unchanged `crucible-cas` interface (§35.6.2); Crucible ships standalone
  with no RFC-0007 code ([DCE-29], [NG-7], [PKG-32]); the merge is gated by
  re-running `gate:content-address` and `gate:replay-oracle` unchanged ([PKG-35]).
  *Gate:* `gate:e2e-determinism`, `gate:content-address`.

- **Determinism leak (the §35.4 boundary failing).** *Risk:* distribution metadata
  (host id, claim order, fleet size, wall-clock) leaks into `reduce`, a `Decision`,
  a content key, or an artifact, making a finding depend on the fleet.
  *Mitigation:* the guardrail of §35.4.3 ([DCE-18]); caught at compile time by the
  **harness-lint extension** ([DCE-19]) and at runtime by **`gate:fleet-equivalence`**
  ([DCE-20]), localized by divergence bisection (24 §5) — the defense-in-depth of
  [HARN-26]. *Gate:* `gate:fleet-equivalence`, `gate:harness-lint`,
  `gate:divergence-bisect`.

- **Straggler / pruning skew.** *Risk:* one host stalls (a slow node, a deep
  unbalanced subtree) and the fleet waits; or hosts prune the corpus differently
  and diverge. *Mitigation:* **work-stealing** (§35.2.2) load-balances around
  stragglers automatically — an idle host claims the stalled host's next frontier
  node when its lease expires (§35.5.4); corpus retention is **deterministic and
  seeded** ([DCE-15]) so pruning is identical across hosts and reruns. *Gate:*
  `gate:fleet-equivalence`, `gate:campaign-continuity`.

## 35.10 The two new canonical gates (coordinate with 24)

This file introduces two gates that are **canonical**: they are the named CI
checks that enforce this file's contract, exactly as the determinism gates
enforce the determinism contract. Per [HARN-1], every gate referenced in this RFC
MUST appear in the canonical catalog in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.1
verbatim. This file therefore *requests* that the catalog add both.

- **`gate:fleet-equivalence`** — layer/phase guarded: **cross-layer, Phase ≥ L3
  (after search/fuzzing and the replay oracle exist)**; primary
  requirements: **DCE-16, DCE-17, DCE-20**; one-line criterion: *single-host and
  fleet search over the same `(family, seed, budget)` discover the same
  content-addressed finding-set with byte-identical artifacts; discovery order may
  differ.* It is a byte-identity (set-and-artifact) gate, not a regression gate.

- **`gate:campaign-continuity`** — layer/phase guarded: **cross-layer, Phase ≥ L3
  (after the persistent store and seeding exist)**; primary requirements:
  **DCE-11, DCE-12, DCE-26**; one-line criterion: *seeding run N+1 from run N's
  campaign reproduces each corpus entry bit-identically, accumulated coverage is
  monotone non-decreasing across runs, and cross-provenance reuse is refused.* It
  is a byte-identity + monotonicity gate.

- **[DCE-30]** `gate:fleet-equivalence` and `gate:campaign-continuity` MUST be
  added to the canonical gate catalog in
  [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.1
  verbatim (with the layer/phase, primary requirements, and one-line criteria of
  §35.10) and wired into the phase plan
  ([`32-implementation-plan.md`](32-implementation-plan.md)) **after** the
  search/fuzzing and replay-oracle gates they build on ([DCE-1], [G-5]). The
  doc-lint ([`28-engineering-standards.md`](28-engineering-standards.md)) that flags
  referenced-but-undefined gates MUST be satisfied by this addition; until 24's
  catalog lists them, this reference is the source of the request. *Gate:*
  `gate:fleet-equivalence`, `gate:campaign-continuity`. *Spec:* §35.10; routes
  [HARN-1], references [HARN-2].

## 35.11 The unifying view

The closing point of this file is the same one that makes the advanced features
reliable (22 §22.9): **distribution and continuity are operations on the one
content-addressed graph — now shared across hosts and persisted across runs — via
the one `instantiate`, with no new execution path and no new state
representation.** The fleet is the graph reachable from many machines; the
campaign is the graph that outlives the process; the manifest head is the one
mutable ref over an otherwise-immutable graph; and the determinism distinction
(§35.4) is the discipline that lets distribution be as nondeterministic as the
network while reproduction stays bit-identical on one laptop.

```text
  distribution  = the SAME content-addressed DagStore (07 §7), reachable from many hosts;
                  CLAIM/LEASE work-stealing over the shared frontier; lost work repeated, never wrong
  continuity    = the SAME DagStore, persisted across runs; one CAS-advanced manifest head;
                  seed run N+1 from prior corpus; grow-only coverage map → monotone ratchet
  the boundary  = distribution metadata (host id, claim order, wall-clock, fleet size) MUST NOT
                  flow into reduce / Decision / identity / artifact (§35.4) — Claim A vs Claim B
  the proof     = gate:fleet-equivalence (single-host ≡ fleet) + gate:campaign-continuity
                  (seed-reproducibility + monotone coverage + provenance gating)
  ──────────────────────────────────────────────────────────────────────────────────────────
  ALL of the above: the existing graph (07), shared + durable. NO new execution path (05 EXEC-14),
  NO new state representation (07 TEMP-30). Crucible ships standalone (NG-7); ratchet seam is text.
```

- **[DCE-33]** Distribution (fleet) and continuity (persistent campaign) MUST be
  operations on the single content-addressed temporal graph (07) via the single
  `instantiate` (05), sharing the graph across hosts and persisting it across runs,
  with **no new execution path** (05 [EXEC-14]) and **no new state representation**
  (07 [TEMP-30], 05 [EXEC-25]). Their correctness MUST be the existing replay
  oracle ([INV-2]) plus single-VM fingerprint ([DET-3]), and their distribution-
  and persistence-specific correctness MUST be the two new gates
  `gate:fleet-equivalence` ([DCE-20]) and `gate:campaign-continuity` ([DCE-11],
  [DCE-12]). *Gate:* `gate:fleet-equivalence`, `gate:campaign-continuity`,
  `gate:replay-oracle`, `gate:content-address`. *Spec:* §35.11; cross-ref 22 §22.9,
  07 §10, 05 §9.

## 35.12 Summary

```text
DEPENDENCY (§35.1): sits ABOVE the whole advanced-features ladder (22 §22.1); adds NO new
  execution path and NO new state representation — the existing graph, shared + durable.

DISTRIBUTION (§35.2): one shared content-addressed DagStore (07 §7, TEMP-22); identity is
  content not location (same node/finding on any host). CLAIM/LEASE work-stealing over the
  shared frontier (NOT static partitioning — symmetry/POR makes the tree unbalanced). Soft
  hash-affinity = cache hint only. Lost claim ⇒ re-expand to a byte-identical node, deduped
  on put — lost work REPEATED, never WRONG. Dedup at 4 layers (exists-gate, coverage-map
  admission, symmetry/POR over shared fingerprints, claim anti-redundancy).

CONTINUITY (§35.3): persistent DagStore + a small CAS-advanced campaign manifest (the ONLY
  mutable, non-content-addressed object) naming corpus/coverage/findings roots + genesis pin.
  Seed run N+1 from prior corpus (each entry self-contained, replays bit-identically).
  Accumulated grow-only coverage map → novelty monotone → the continuous coverage RATCHET.
  Findings ledger accumulates failures across runs. Storage bounded by GC + fat→thin eviction
  (value preserved) + deterministic seeded corpus retention under a cap.

DETERMINISM DISTINCTION (§35.4, load-bearing): TWO claims. (A) Reproduction is deterministic
  and host-independent — reproduces on one laptop, no fleet/store (MUST hold). (B) Distribution/
  scheduling MAY be nondeterministic — changes discovery ORDER only, never state or artifact.
  Guardrail: distribution metadata MUST NOT flow into reduce/Decision/identity/artifact.
  gate:fleet-equivalence: single-host ≡ fleet (same finding-set, byte-identical artifacts).

STORE CONSISTENCY (§35.5): content-addressed objects trivially convergent under concurrent
  put. Only mutable objects: manifest head (CAS, lost update = lost bookkeeping only) and
  coverage map (grow-only union CRDT, converges). Claims are TTL leases, not locks: partition/
  crash → repeated deduped work, never corruption/deadlock. NO consensus on the hot path.

PROVENANCE + RATCHET SEAM (§35.6): campaign keyed to the provenance triple (26); seeding
  refuses cross-provenance reuse (a QEMU/ABI bump forks a fresh lineage). The shared store is
  the SAME crucible-cas seam where a future RFC-0007 ratchet substrate slots in — documented
  text, not a dependency; Crucible ships standalone (NG-7).

FORWARD-REFS: perf (25) — fleet throughput near-linear to store-bandwidth saturation,
  total ≈ hosts × per-host lookahead P; continuous coverage ratchet. Packaging (26) — fleet
  store is an AOS from-source component, wired as an AOS VM/fleet check, TCG-only.

NEW CANONICAL GATES (§35.10): gate:fleet-equivalence, gate:campaign-continuity (added to 24 §1.1).
```

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is distributed/continuous exploration, tracked by [PLAN-3].
> They are sequenced strictly **after** the advanced-features (search,
> fuzzing), replay-oracle, and content-address foundations they depend on
> ([DCE-1], [G-5], [PLAN-4]).

- [x] **T-DCE-1** Implement the shared content-addressed `DagStore` backend (a
  remote/durable implementation of the unchanged 07 §7 `put`/`get`/`exists`
  interface behind `crucible-cas`), proving location-independent identity (same
  node/finding is the same object on any host) and idempotent, convergent
  concurrent `put`. — satisfies [DCE-2], [DCE-3], [DCE-4], [DCE-22], [DCE-28]; spec §35.2.1,
  §35.5.1; cross-ref 07 §7, [TEMP-22].
  - Completed by `checks.crucible.phase7.crucibleSharedDagStore`: `crucible-cas`
    exports `SharedDagStore` behind the unchanged `DagStore::put`/`DagStore::get`/
    `DagStore::has` interface, using content-derived BLAKE3 keys, the shared
    two-level object layout, exclusive temporary files, atomic hard-link publish,
    and content-mismatch rejection. The `crucible-fleet-store probe` now proves
    location-independent identity across two store roots and idempotent convergent
    publication from 16 concurrent writers with a single final object. The
    TCG-only `checks.fleet.crucible-distributed-continuous-exploration` surface
    consumes this source proof plus the AOS-built `pkgs.crucible-fleet-store`
    package; the full `gate:fleet-equivalence` proof consumes this shared store
    as its fleet substrate.
- [x] **T-DCE-2** Implement content-addressed CLAIM/LEASE work-stealing over the
  shared frontier (TTL leases, not static partitioning; lost/expired claim
  re-expands to a byte-identical deduped node), with soft hash-affinity as a
  cache-warmth hint only. — satisfies [DCE-5], [DCE-6], [DCE-7]; spec §35.2.2,
  §35.2.3; cross-ref 22 §22.5, 07 §9.
  - Completed by `checks.crucible.phase7.crucibleFrontierLeases`: `crucible-cas`
    now exposes `SharedFrontier`, `FrontierClaimRequest`, `FrontierLease`, and
    `SoftHashAffinity`. Frontier membership and claim paths are keyed only by the
    frontier node content address; host id and expiry live only inside TTL claim
    records. The packaged `crucible-fleet-store probe` admits shared frontier
    nodes, proves affinity reorders the claimable set without filtering it,
    records a TTL lease, falls back to another claimable node instead of static
    partitioning, reclaims both an expired node lease and an abandoned claim-lock
    sidecar, then re-puts the same bytes through `SharedDagStore` to prove
    byte-identical dedup. Four-layer dedup, full fleet search equivalence, and
    divergence localization are checked by the phase7 fleet-equivalence gate.
- [x] **T-DCE-3** Implement the four dedup layers (exists()-gated expansion, shared
  coverage-map compare-and-merge admission, symmetry/partial-order reduction over
  shared fingerprints, claim-set anti-redundancy). — satisfies [DCE-8]; spec
  §35.2.4; cross-ref 07 §7/§9, 22 §22.6.
  - Completed by `checks.crucible.phase7.crucibleFourLayerDedup`: `crucible-cas`
    now exposes `SharedDedupIndex`, `ExpansionDedupDecision`, `CoverageAdmission`,
    and `ReductionAdmission`. The packaged `crucible-fleet-store probe` proves
    exists-gated expansion skips a child already in `SharedDagStore`, shared
    coverage-map admission admits only entries that add new coverage and repairs an
    interrupted fingerprint-before-entry admission, shared reduction fingerprints
    retain one representative and prune covered candidates, and claim-set
    anti-redundancy sends a second host to an unleased frontier node.
    The single-host-vs-fleet equivalence gate consumes these four dedup layers
    before comparing content-addressed finding sets and artifact bytes.
- [x] **T-DCE-4** Implement the persistent campaign store + the CAS-advanced
  campaign manifest (the only mutable, non-content-addressed object) naming
  corpus/coverage/findings roots, genesis pin, and provenance, with read-merge-retry
  CAS and lost-update-loses-only-bookkeeping. — satisfies [DCE-9], [DCE-10],
  [DCE-23]; spec §35.3.1, §35.5.2.
  - Completed by `checks.crucible.phase7.crucibleCampaignManifest`: `crucible-cas`
    now exposes `SharedCampaignStore`, `CampaignManifest`, `CampaignProvenance`,
    `CampaignHead`, and `CampaignCasOutcome`. Campaign manifests are persisted as
    immutable `SharedDagStore` objects, while `campaign-head` is the single durable
    mutable ref; head CAS is serialized by an advisory lock on that same file and
    recorded as an append-only checksummed head log so a torn final entry preserves
    the previous valid head.
    The packaged `crucible-fleet-store probe` proves manifest identity is
    content-addressed across store roots, stale CAS attempts retain their proposed
    manifest objects, and read-merge-retry writes immutable merge-root records for
    corpus, coverage, and findings before advancing a manifest without changing
    genesis pin or provenance.
    `gate:campaign-continuity` composes this manifest proof with campaign
    seeding, storage bounding, and provenance gating.
- [x] **T-DCE-5** Implement seeding run N+1 from the prior corpus (each entry a
  self-contained artifact replaying bit-identically) and the grow-only accumulated
  coverage map (union CRDT) driving the monotone continuous coverage ratchet, plus
  the cross-run findings ledger. — satisfies [DCE-11], [DCE-12], [DCE-13], [DCE-24];
  spec §35.3.2, §35.3.3, §35.5.3; cross-ref 22 §22.7.2.
  - Completed by `checks.crucible.phase7.crucibleCampaignSeeding`: `crucible-cas`
    now exposes self-contained `CampaignReplayArtifact` objects, `CampaignCorpusSeed`
    loading for run N+1, typed accumulated coverage-map roots with grow-only union
    merge, and grow-only content-deduplicated findings ledgers. The packaged
    `crucible-fleet-store probe` proves prior-corpus seeding replays each artifact
    bit-identically without live process state, accumulated coverage novelty is
    evaluated against the campaign-lifetime map, coverage-root merge is
    commutative/idempotent grow-only union, and findings ledger entries replay from
    their stored artifacts while rediscovery deduplicates by content. Fleet
    equivalence is checked by `gate:fleet-equivalence`; `gate:campaign-continuity`
    composes the run-to-run seed and accumulated coverage proof.
- [x] **T-DCE-6** Implement campaign storage bounding: GC rooted at the manifest's
  roots, fat→thin eviction (value preserved), and deterministic seeded corpus
  retention under a cap (bit-reproducible across hosts and reruns). — satisfies
  [DCE-14], [DCE-15]; spec §35.3.4; cross-ref 07 §8, 22 §22.7.2.
  - Completed by `checks.crucible.phase7.crucibleCampaignStorageBounding`:
    `crucible-cas` now exposes manifest-root campaign GC planning and candidate
    sweeping, a typed source/cap/seed corpus-retention root accepted only through
    an explicit retention-policy CAS path, and a cache-only fat→thin eviction
    proof surface. Raw CAS still rejects corpus shrink, zero-cap retention, policy
    mismatch, and direct unbounding of an already-retained corpus. The packaged
    `crucible-fleet-store probe` proves abandoned
    unpinned campaign objects sweep outside the manifest root closure, retained
    corpus artifacts and all findings ledger artifacts remain reachable, fat
    checkpoint eviction preserves the denoted value through the parent/schedule
    delta thin source, and the retained corpus root is reproducible across hosts
    and reruns from the same campaign history. The temporal graph remains the
    authoritative implementation for checkpoint GC and value-preserving
    fat→thin realization through `TemporalGraph::garbage_collect`,
    `TemporalGraph::garbage_collect_store`, and
    `TemporalGraph::evict_fat_checkpoint_to_thin`. Fleet equivalence is checked
    by `gate:fleet-equivalence`; `gate:campaign-continuity` composes the retained
    corpus, coverage, and findings roots with provenance-keyed seeding.
- [x] **T-DCE-7** Enforce the determinism distinction guardrail: distribution
  metadata MUST NOT flow into reduce/Decision/identity/artifact; extend
  `gate:harness-lint` to ban host id / lease timestamps / fleet size / peer count on
  any reduce/Decision/key/artifact path. — satisfies [DCE-16], [DCE-17], [DCE-18],
  [DCE-19]; spec §35.4; routes [INV-1], [INV-9].
  - Completed by `checks.crucible.phase7.crucibleDeterminismGuardrail`: the
    `gate:harness-lint` custom static tier now rejects distribution metadata
    (`host_id`, lease owner aliases, lease timestamps/ticks, fleet size, peer
    count, claim order, and wall-clock aliases) in functions touching `reduce`,
    `Decision`, content key/identity, or reproduction artifact paths.
    Claim/lease/affinity/telemetry/progress coordination remains allowed, the
    phase7 `gate:fleet-equivalence` wrapper depends on this guard, and the fleet
    surface records the guard result before advertising distributed continuous
    exploration. `gate:campaign-continuity` depends on the same distinction when
    refusing cross-provenance seed reuse.
- [ ] **T-DCE-8** Implement `gate:fleet-equivalence` (single-host exhaustive search
  vs fleet work-stealing search over the same (family, seed, budget) discover the
  same content-addressed finding-set with byte-identical artifacts; order may
  differ), running against the SimDouble fleet under adversarial host conditions and
  a real-QEMU slice, with divergence-bisection localization. — satisfies [DCE-20],
  [DCE-21], [DCE-25], [DCE-33]; spec §35.4.4, §35.5.4; cross-ref 24 §3/§7.
  - Completed by `checks.crucible.phase7.gates.fleetEquivalence`: the Crucible
    model now exposes `TemporalGraph::search_with_work_stealing_fleet`,
    `FleetWorkStealingConfig`, `FleetWorkStealingSearchRun`, and
    `FleetEquivalenceReport`. The gate test runs single-host exhaustive search
    and deterministic shared-worklist fleet search over the same scenario family,
    seed, and budget, requires both runs to exhaust the same content-addressed
    graph, then compares order-insensitive content-addressed finding sets and
    byte-identical reproduction artifacts while preserving discovery order only as
    diagnostics. The test also drives one `SimDouble` lane per logical fleet host
    under the shared `canonical_host_adversary_matrix` fixture and requires
    profile-independent host-schedule witnesses. Negative controls drop a fleet
    finding and cap the budget before exhaustion, verifying divergence-bisection
    handoff through `SearchReplayOracleBisectionRequest`. The root TCG-only fleet
    wrapper consumes this gate result before advertising distributed continuous
    exploration, and the gate is dependency-ordered after
    `checks.crucible.phase2.gates.singleVmFingerprint` as its real-QEMU fidelity
    slice.
- [x] **T-DCE-9** Implement `gate:campaign-continuity` (seed-reproducibility of
  corpus entries across runs, monotone-non-decreasing accumulated coverage, and
  cross-provenance reuse refused / fresh-lineage fork), plus provenance gating of
  seeding keyed to the provenance triple. — satisfies [DCE-26], [DCE-27]; spec
  §35.6.1; cross-ref 26 §26.10.
  - Completed by `checks.crucible.phase7.gates.campaignContinuity`:
    `crucible-cas` now exposes provenance-keyed seeding through
    `SharedCampaignStore::seed_next_run_for_provenance`,
    `CampaignContinuitySeedDecision`, `CampaignFreshLineageRoots`, and
    `CampaignFreshLineageBaselineEvent`. The gate seeds run N+1 from the prior
    corpus only when the campaign and run provenance triples match, proving every
    seed artifact replays bit-identically; it advances the campaign with grow-only
    corpus, coverage, and findings roots and rejects coverage regression. Changed
    provenance refuses corpus reuse, persists a fresh manifest with new corpus,
    coverage, findings, and genesis roots, records a content-addressed
    fresh-lineage baseline event, installs the fresh manifest as the campaign head,
    and leaves prior ledger findings reproducible.
- [x] **T-DCE-10** Add `gate:fleet-equivalence` and `gate:campaign-continuity` to
  the canonical gate catalog (24 §1.1) verbatim and wire them into the phase plan
  after the search/fuzzing + replay-oracle gates; document the ratchet seam
  (crucible-cas interface, RFC-0007 future home) as text with Crucible standalone;
  wire the fleet store as an AOS from-source VM/fleet check (TCG-only). — satisfies
  [DCE-1], [DCE-28], [DCE-29], [DCE-30], [DCE-31], [DCE-32]; spec §35.6.2,
  §35.7, §35.8, §35.10; cross-ref 24 §1.1, 25, 26 §26.9.
  - Completed by `checks.crucible.phase7.crucibleDceIntegration`: RFC 24 now
    carries the §35.10 `gate:fleet-equivalence` and `gate:campaign-continuity`
    rows with their explicit DCE requirements and one-line criteria; the harness
    phase plan and gate-target mapping expose both implemented gates after the
    replay/search/fuzzing ladder; the `crucible-cas` ratchet seam remains documented
    text with no RFC-0007 dependency; and `pkgs.crucible-fleet-store` is wired into
    `checks.fleet.crucible-distributed-continuous-exploration` as a from-source,
    TCG-only AOS fleet surface.
