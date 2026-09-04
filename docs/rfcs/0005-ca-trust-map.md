# RFC-0005: The `store/` realisation graph - content-addressed closure validation

- **Status:** **Implemented.** The signed `store/` realisation graph is
  published by `apr` and enforced over complete closures by `apm`.
- **Date:** 2026-06-12
- **PR:** [#98](https://github.com/andyl-technologies/aos/pull/98)
- **Audience:** anyone working on `crates/aos-package/` (the `apr`
  publish pipeline and the `apm` download/verify pipeline) or the
  registry docs under `docs/registry/`.

## Problem

A registry's trust root is the signed git tag: tag → commit → tree
authenticates every committed file transitively
(`docs/registry/signing-and-trust.md`). The tree names store paths by
their **input-addressed (IA) hashes** - the 32-char nixbase32 store-path
hashes in `packages/<x>/<name>.toml` (`store_path`, `references`) and in
the per-root `closures/<hash>` adjacency lists.

An IA hash is a promise about *how a path was built*, not *what bits it
contains*. The hash is fixed before the build runs, so two different
NARs - one honest, one tampered with after signing - can both legally
claim the same IA store path. The signature therefore roots the **shape**
of the dependency graph but not its **content**:

- The package root is covered: its TOML carries `nar_hash`, inside the
  signed tree, and `apm` verifies it.
- Every **non-root closure member** is not. The installer plans the
  closure from `closures/<root>`, then learns each member's NAR hash
  from a **cache-served narinfo** (`fetch_narinfos`,
  `crates/aos-package/src/download.rs`). Narinfos are not part of the
  signed tree - they come from whatever `[[caches]]` endpoint answered.
  A compromised cache (or CDN, or bucket) can serve a tampered NAR with
  a matching tampered narinfo for any dependency, and the registry
  signature never notices.

The graph edges break exactly at the IA boundary: the signed tree says
"curl depends on `r4q1m2kp8v3x` (zlib)", but nothing signed says which
*bits* `r4q1m2kp8v3x` is allowed to be.

## Design

Replace the registry's two parallel per-path indexes - `closures/`
(dependency **shape**) and the originally-proposed `ca/` (content
**addresses**) - with a single committed **realisation graph** under
`store/`. One file per IA store path records, for every blessed build of
that path: its exact NAR bytes, its content address (the CA realisation),
and its dependency edges. Because the graph is in the signed tree, it is
signed-by-extension like everything else; because every closure member
has a record, validating a closure becomes a pure membership check
against signed data, and the cache is demoted to an untrusted byte
transport - which is what it should have been all along.

The node is a **realisation**, exactly as in Nix's CA-derivations work: a
realisation maps a build to its content-addressed output and pins which
realisation of each dependency it composed against (Nix's
`dependentRealisations`). That pin **is** a dependency edge - so the
realisation graph *is* the closure graph, with content addresses on the
nodes and CA pins on the edges. There is no second structure to keep in
sync. The git signature plays the role of the realisation signature.

The same graph serves both store models from one registry:

- an **input-addressed** consumer reads each node's `nar:` bytes, walks
  the IA edges, and ignores content addresses (today's behaviour);
- a **content-addressed** consumer picks one blessed realisation of the
  root and follows its pinned edges, materialising the corresponding CA
  closure.

### 2.1 Layout

```
<repo root>/
├── registry.toml                 ← [registry] + content_addressed = true|false
├── keys.toml
├── packages/<x>/<name>.toml      ← package metadata (no nar_hash / references)
└── store/
    ├── r4/r4q1m2kp8v3x           ← one file per IA store path,
    ├── h7/h7j3k8l2m9n4             sharded git-style by the first two
    └── ...                         nixbase32 chars of the IA hash
```

One file per input-addressed store path, named by the IA hash, sharded
into `store/<first-2-of-ia>/<ia-hash>` (the same 2/30 split git uses for
loose objects). Properties:

- **No migration, ever, and no buckets to merge.** Each path is its own
  file; a publish or a re-bless touches exactly the files it changes, so
  concurrent publishes never conflict and lookup is a direct
  filename-from-hash open. The 2-char shard keeps a nixpkgs-scale
  registry from putting 100k entries in one directory.
- **Dedup preserved.** A path that many closures share (glibc) is **one**
  file, referenced by edges - not re-inlined per closure. The shape graph
  and the content addresses live together without duplicating either.

An absent `store/<prefix>/<ia>` file means "this path is not published
here"; an absent `store/` directory entirely means "this registry
predates the realisation graph" (legacy; see §2.8).

### 2.2 File format

Each file is UTF-8 text: a sequence of **realisation records**, one per
blessed build. A record is a header line followed by its dependency-edge
lines:

```
ca:sha256:<ca-hash> nar:sha256:<nar-hash>:<size>
  ia:sha256:<dep-ia>/ca:sha256:<dep-ca>
  ia:sha256:<dep-ia>/ca:sha256:<dep-ca>
ca:sha256:<ca-hash2> nar:sha256:<nar-hash2>:<size2>
  ia:sha256:<dep-ia>/ca:sha256:<dep-ca>
```

A path served only from input-addressed stores carries no content
address: the header is just the NAR, and the edges are bare IA hashes:

```
nar:sha256:<nar-hash>:<size>
  ia:sha256:<dep-ia>
  ia:sha256:<dep-ia>
```

Grammar and lexical rules:

- A line whose first token is `ca:` or `nar:` **starts a new
  realisation**; a line whose first token is `ia:` is a **dependency
  edge of the current realisation**. The token prefix disambiguates, so
  indentation is conventional (readability), not significant - tabs or
  spaces both work.
- Blank and whitespace-only lines and trailing whitespace are ignored;
  `#` begins a comment to end of line.
- A header is `[ca:sha256:<ca>] nar:sha256:<h>:<size>` - the `ca:` token
  present in content-addressed mode, absent in IA-only mode.
- An edge is `ia:sha256:<dep-ia>[/ca:sha256:<dep-ca>]` - the `/ca:` pin
  present only when the dependency has more than one blessed realisation
  (otherwise the consumer resolves it to the dependency's sole `ca:`).
- All hashes are nixbase32 SHA-256 (`sha256:` form); the IA hash of the
  path itself is the filename, not repeated in the body.

Records and edges are written in a stable sorted order so a re-bless or
revocation is a readable diff. `.gitattributes` deliberately gets **no**
`store/** -diff` entry: a change to what bytes the registry vouches for
is its highest-value security-review surface and must show up as a
readable diff in `git log -p` and in PR review.

### 2.3 Cardinalities - IA → 0..N NARs, 0..M realisations

A single IA path maps to:

- **0..N blessed NARs** (`nar:` headers). One when the build is
  byte-reproducible; more than one when it is not - each independent
  build is a separately blessed byte-set. (At least one once published.)
- **0..M content-addressed realisations** (`ca:` headers). **Zero** for a
  pure-IA registry or a path not yet CA-blessed; one when reproducible;
  more than one otherwise.

Because a CA hash is computed *from* the content **plus the
dependencies' CA hashes**, non-determinism does not produce a lone
alternate hash - it produces a whole alternate **subtree**: a divergence
at any node propagates upward to every transitive parent that
incorporates it. So *N* blessed builds of a root are *N* consistent CA
assignments over the closure DAG. The realisation-node model encodes this
without blowup, because dedup is per *realisation* `(IA, CA)`, not per IA:
two assignments share every sub-path they agree on and only allocate new
nodes along the divergent spine.

Worked example - `app → {libfoo, libbar}`, `libfoo → zlib`,
`libbar → zlib`, with `libfoo` non-reproducible (realisations `f1`, `f2`)
and everything else reproducible:

```
store/z1/z1ib5s6y7w8i        (zlib, reproducible leaf)
  ca:sha256:<z1> nar:sha256:<…>:65536

store/b4/b4r1q2w3e4r5        (libbar, reproducible)
  ca:sha256:<b1> nar:sha256:<…>:98304
    ia:sha256:z1ib5s6y7w8i/ca:sha256:<z1>

store/f0/f00a3k8m1n5p        (libfoo, NON-reproducible - two realisations)
  ca:sha256:<f1> nar:sha256:<…>:131072
    ia:sha256:z1ib5s6y7w8i/ca:sha256:<z1>
  ca:sha256:<f2> nar:sha256:<…>:131008
    ia:sha256:z1ib5s6y7w8i/ca:sha256:<z1>

store/ap/ap0k7m9n2p4q        (app - forks on which libfoo it used)
  ca:sha256:<a1> nar:sha256:<…>:204800
    ia:sha256:f00a3k8m1n5p/ca:sha256:<f1>
    ia:sha256:b4r1q2w3e4r5/ca:sha256:<b1>
  ca:sha256:<a2> nar:sha256:<…>:204864
    ia:sha256:f00a3k8m1n5p/ca:sha256:<f2>
    ia:sha256:b4r1q2w3e4r5/ca:sha256:<b1>
```

Two trees (`a1`-rooted, `a2`-rooted) share the single `zlib` and `libbar`
nodes and fork only at `libfoo` and above. The pin on each `app` edge is
what makes "which `libfoo`?" unambiguous; `libbar`'s edge needs no pin
because `libbar` has one realisation.

### 2.4 Content addresses - the `ca:` form

A `ca:` hash is what `nix store make-content-addressed` computes: the NAR
hash *modulo self-references*, with each dependency reference rewritten to
that dependency's CA store path. Because the rewrite consumes the
dependencies' CA paths, the parent's CA hash is well-defined only relative
to a specific dependency assignment - which is exactly what the edge pins
record. Composition is therefore **structural**: a realisation plus its
pinned edges name a unique, internally-consistent CA tree, and the
ambiguity Nix solves with `dependentRealisations` is solved here by the
graph edges themselves.

The producer computes these by delegating to Nix
(`nix store make-content-addressed --json` over the closure root, one
invocation resolving a consistent assignment for the whole closure) - no
reimplementation of Nix's CA path formula to keep byte-exact. See §2.5.

The security goal - exact bits rooted at the tag signature - is achieved
by the `nar:` headers alone; `ca:` adds content-addressed-store interop on
top, and a consumer never has to trust the cache in either mode because a
node's CA is a pure function of its (signed) bytes and its dependencies'
(signed) CA hashes.

### 2.5 Publish flow (`apr`)

`apr publish` introspects the closure once (replacing the old separate
`closures/` walk): for every member it records the NAR SHA-256 and size
from the local store, and - when the registry is `content_addressed`
(default, §2.7) - the member's CA hash and pinned edges from a single
`nix store make-content-addressed --json` pass. It writes/updates each
member's `store/<prefix>/<ia>` file:

- New path → write the record.
- Existing path, identical realisation → no-op.
- Existing path, **different** content for an existing realisation key →
  refuse by default with a clear diagnostic; `--bless` adds the new
  realisation alongside the old. An unexpected mismatch at publish time is
  exactly the signal this design exists to catch, so it is never merged
  silently.

`apr store` owns explicit graph maintenance:

- `apr store bless <store-path> [--recursive]` - add a realisation
  computed from local bytes (the multi-builder reproduction workflow).
- `apr store revoke <ia-hash> [--realisation <ca>]` - remove a blessed
  realisation (or the whole record).
- `apr store verify [--deep]` - check graph health and closure coverage;
  `--deep` recomputes local NAR hashes and requires blessed matches.
- `apr store backfill [--bless]` - record every published closure from the
  local store in one pass, so an existing registry becomes fully mapped in
  one signed commit.

### 2.6 Validation flow (`apm`)

After the registry sync has verified the tag/commit chain, the consumer
resolves the root and walks the realisation graph. The store mode
(auto-detected from the local Nix store, overridable per registry)
selects the projection:

**Input-addressed mode** (default today):

1. Plan the closure by walking `store/` IA edges from the root.
2. For every member from a registry that publishes a `store/` graph, the
   member's record must exist and carry a `nar:` header - checked over the
   **whole closure** before download, including members already in the
   local store, so a stripped or partial graph fails loudly rather than
   slipping through on an upgrade.
3. Download each compressed NAR from any `[[caches]]` mirror; decompress
   with a hard output cap of the largest blessed `size` for that path
   (bounds zstd-bomb exposure on not-yet-verified input).
4. SHA-256 the uncompressed NAR; accept iff it matches one of the
   member's blessed `nar:` headers. Reject the whole closure on any miss.

**Content-addressed mode:**

1. Require the root IA to have ≥1 realisation (else not CA-installable -
   fall back to IA or fail).
2. Pick one root realisation; follow its pinned edges to select exactly
   one internally-consistent tree (shared reproducible nodes are reached
   by multiple parents but resolve to one realisation each).
3. Verify each node's `nar:` bytes as above, then that rewriting its
   references to the pinned dependency CA paths reproduces the node's
   blessed `ca:`.

Cache-served narinfos are **advisory** in both modes: used for the NAR
URL, compression kind, and download planning, never as a trust source. A
registry that publishes no `store/` graph falls back, with a warning, to
verifying downloaded members against the cache-served narinfo `NarHash` -
the same unauthenticated check apm applied before this RFC. Enforcement is
**per source registry**: a path is judged against the graph of the
registry that resolved it, never a cross-registry union, so a legacy
registry in the same transaction cannot disable enforcement for a mapped
one.

### 2.7 `content_addressed` config

`registry.toml` gains `[registry] content_addressed` (default **true**):

- **true** - `apr publish`/`backfill` fill `ca:` headers and pinned edges
  for every member; `apr store verify` requires CA coverage; the registry
  serves both store models.
- **false** - the producer writes IA-only records (`nar:` headers, bare
  edges); the graph is the closure-plus-bytes with no content addresses, a
  pure input-addressed registry. `apr publish --no-ca` forces IA-only for
  a single publish regardless of the registry default.

One file format covers both; the difference is only whether the `ca:`
column is filled.

### 2.8 Package TOML changes and migration

With the realisation graph total over the closure, the per-platform
package TOML sheds the fields the graph now owns:

| Field | Disposition |
|---|---|
| `nar_hash`, `nar_size` | **Removed.** The graph is the single authority for blessed bytes - multi-realisation capable, and no second signed source that can disagree. |
| `references` | **Removed.** It is the root node's edge set; the graph holds the dependency shape. |
| `store_path`, `closure_size`, `source_drv`, `source_nar_hash`, sysroot `images` | **Unchanged.** `store_path` still anchors the package to its IA hash (and thus its `store/` record); sources and images sit outside the runtime closure the graph covers and keep their own hashes. |

The registry is pre-1.0 and self-hosted, so the cutover is short, but
parsers must not hard-break on published trees:

1. **Parse-tolerant first.** Consumer-side parsing treats `nar_hash`,
   `nar_size`, and `references` as optional and backfills the in-memory
   metadata from `store/` when absent. Already-published registries keep
   working.
2. **Producer cutover.** `apr publish` writes `store/` records and stops
   emitting the removed TOML fields. `apr store backfill` maps an existing
   registry in one signed commit.
3. **Consumer enforcement.** Per §2.6: when a path's source registry
   publishes a `store/` graph, missing records/`nar:` headers are a hard
   failure over the whole closure; a registry with no `store/` directory
   falls back to the unauthenticated narinfo `NarHash` with a warning.

## What this does NOT do

- It does not *require* AOS to run a Nix CA store. The graph carries CA
  addresses so a CA-store consumer *can* use them, but the default install
  path remains input-addressed; `content_addressed = false` drops the CA
  column entirely.
- It does not authenticate narinfos. They become advisory; the signed
  graph makes their integrity irrelevant.
- It does not bind IA hashes to *derivations* (no `drv → output` edge).
  The node key is the store-path hash because that is what the tree
  already speaks. The `source_drv` TOML field remains the join point if
  true CA-derivation interop lands later.

## Open questions

1. **CA-store consumer materialisation.** The producer fills CA addresses
   and the consumer validates them; actually realising a CA store path on
   install (vs. importing the IA path) depends on a CA-enabled local Nix
   and is the remaining consumer increment.
2. **Realisation selection policy** when a root has multiple CA
   realisations - deterministic tiebreak vs. operator preference.

## Implementation plan (this PR)

1. `registry/store.rs`: the realisation-graph model, text parser/writer,
   sharded path layout, `StoreMap` loader, producer upsert/remove
   (replaces `registry/ca.rs` and `registry/closures.rs`).
2. Rewire `registry/mod.rs`, `resolve.rs` (walk `store/` edges; drop the
   `references` BFS and per-root closure files), and `verify.rs` (blessed
   verification + per-registry `TrustContext` + whole-closure totality)
   onto the graph.
3. Producer: `write_store_files` (NAR + optional CA), `apr store`
   subcommand, `content_addressed` config, drop `references`/`nar_hash`
   emission, narinfo emitter + `apr cache`/`validate` read the graph.
4. Sync: `extract_store` (presence-preserving, sharded), drop
   `closures/`/`ca/` extraction.
5. Docs: `repo-layout.md`, `signing-and-trust.md`,
   `nix-cache-compatibility.md`, `publishing.md`.
