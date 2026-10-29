# Store realisation graph

A registry release authenticates package metadata through its signed tag,
commit, and tree. The `store/` realisation graph extends that authentication
from the *shape* of every closure to the exact *bytes* of every closure
member, so the binary cache that serves NARs is only a transport. The
on-disk format is summarized in [`repository-layout.md`](repository-layout.md)
§5; this page explains why it is shaped the way it is and how producer and
consumer use it.

## Why input-addressed hashes are not enough

Package TOML names store paths by their input-addressed (IA) hash. An IA hash
is fixed before the build runs; it promises how a path was built, not which
bits it contains. Two different NARs, one honest and one altered after
signing, can both claim the same IA path.

Before the graph existed, only the package root's NAR hash was in the signed
tree. Every other closure member's NAR hash came from a cache-served narinfo.
A compromised cache, CDN, or bucket could serve a tampered dependency with a
matching tampered narinfo, and the registry signature would not notice.

The graph closes that gap by recording, inside the signed tree, the NAR hash
and size of every blessed build of every published path.

## Model

Each file `store/<first-2>/<ia-hash>` holds one or more *realisation*
records, mirroring Nix's CA-derivation realisations. A realisation names an
exact NAR, optionally a content address, and its dependency edges. An edge
may pin the dependency's content address, the equivalent of Nix's
`dependentRealisations`. The realisation graph is therefore also the closure
graph: there is no separate `closures/` index to keep consistent.

One file per IA path keeps a publish or revocation confined to the files it
changes, so concurrent publishes do not conflict and lookup is a direct
open by hash. The two-character shard keeps very large registries from
placing every record in one directory. A path shared by many closures
(for example glibc) is one file referenced by edges.

Records and edges are serialized in sorted order so changes are readable
diffs. Registries deliberately carry no `store/** -diff` git attribute: a
change to which bytes the registry vouches for is its most important review
surface.

### Cardinality

One IA path maps to:

- **1..N blessed NARs.** One for a reproducible build; more when independent
  builds produced different bytes and each was blessed.
- **0..M content addresses.** None in an IA-only record.

A content address depends on the dependencies' content addresses, so a
divergent dependency produces a divergent parent subtree, not a lone
alternative hash. Deduplication is per realisation, so two alternatives share
every node they agree on. For `app -> {libfoo, libbar}`, `libfoo -> zlib`,
`libbar -> zlib` with `libfoo` non-reproducible:

```text
store/z1/z1ib5s6y7w8i            zlib, one realisation
  ca:sha256:<z1> nar:sha256:<...>:65536

store/b4/b4r1q2w3e4r5            libbar, one realisation
  ca:sha256:<b1> nar:sha256:<...>:98304
    ia:sha256:z1ib5s6y7w8i/ca:sha256:<z1>

store/f0/f00a3k8m1n5p            libfoo, two realisations
  ca:sha256:<f1> nar:sha256:<...>:131072
    ia:sha256:z1ib5s6y7w8i/ca:sha256:<z1>
  ca:sha256:<f2> nar:sha256:<...>:131008
    ia:sha256:z1ib5s6y7w8i/ca:sha256:<z1>

store/ap/ap0k7m9n2p4q            app, forks on which libfoo it used
  ca:sha256:<a1> nar:sha256:<...>:204800
    ia:sha256:f00a3k8m1n5p/ca:sha256:<f1>
    ia:sha256:b4r1q2w3e4r5/ca:sha256:<b1>
  ca:sha256:<a2> nar:sha256:<...>:204864
    ia:sha256:f00a3k8m1n5p/ca:sha256:<f2>
    ia:sha256:b4r1q2w3e4r5/ca:sha256:<b1>
```

Hashes in records are 52-character nixbase32 SHA-256 digests; the
illustrative values above are abbreviated.

### Content addresses

A `ca:` value is the hash `nix store make-content-addressed` computes: the
NAR modulo self-references, with each reference rewritten to its
dependency's content-addressed path. AOS delegates the computation to Nix
rather than reimplementing the path formula. The `nar:` headers alone provide
the security property; content addresses add interoperability with
content-addressed stores.

`[registry] content_addressed` (default `true`) controls whether the
producer computes them; `apr publish --no-ca` skips them for one publish.
Nix reports a rewrite only for the paths it was asked about, so in practice
a published root's record carries its `ca:` while closure members and
dependency pins stay input-addressed unless that member is itself published
as a root.

## Producer

`apr publish` walks the root's runtime closure once
(`crates/registry/aos-registry-authoring/src/registry_ops/store_paths.rs`)
and upserts a realisation for every member
(`crates/registry/aos-registry-client/src/registry/store.rs`):

| Existing record | Result |
| --- | --- |
| None | Record created |
| Identical realisation | Unchanged |
| Same NAR bytes, different `ca:` or edges | New realisation added alongside |
| Different NAR bytes | Publish fails with both hashes, unless `--bless` adds the new realisation |

A mismatch at publish time is exactly the event the graph exists to catch, so
it is never merged silently. `apr store` maintains the graph directly:

| Command | Effect |
| --- | --- |
| `apr store bless <path>` | Records the local bytes of a path's whole closure |
| `apr store revoke <path-or-hash> [--realisation <ca>]` | Removes one or all realisations; a security event that produces a signed, reviewable diff |
| `apr store verify [--deep]` | Checks graph health and closure coverage; `--deep` recomputes local NAR hashes and requires blessed matches |
| `apr store backfill [--bless]` | Records every published closure from the local store in one signed commit |

Package TOML no longer carries `nar_hash`, `nar_size`, or `references`; the
graph is the single authority for blessed bytes and dependency shape.
`store_path` still anchors the package to its record. Sources and image
artifacts sit outside the runtime closure and keep their own hashes.

## Consumer

Registry sync extracts `store/` from the verified tree, and `StoreMap`
distinguishes "this registry publishes no graph" from "the graph has no
record for this hash". Consumers parse TOML that still carries the legacy
fields and, when they are absent, fill in-memory metadata from the graph.

`apm install` and `apm upgrade` then:

1. Resolve each closure by walking graph edges from the root.
2. Attribute every member to the registries that resolved it in a
   `TrustContext`. A member is *enforced* when any attributing registry
   publishes a graph; a legacy registry that also carries the hash cannot
   turn enforcement off.
3. Check totality over the whole closure before downloading, including
   members already in the local store, so a stripped graph fails even when the
   gap is on a local path.
4. Download compressed NARs from any configured cache, decompress with an
   output cap equal to the largest blessed size for that path, and accept the
   NAR only if its SHA-256 and size match a blessed realisation
   (`verify_nar_blessed`, `crates/packages/aos-package-manager/src/verify.rs`).

Narinfos remain advisory: they supply the URL, compression, and planning
data, never the expected hash for an enforced member. A member whose
registries publish no graph falls back, with a warning, to the narinfo
`NarHash`.

The consumer verifies and imports input-addressed paths. It does not select
content-addressed realisations or materialize content-addressed store paths;
the `ca:` column is recorded for content-addressed consumers but not used by
`apm` today.

## Related reading

- [`signing-and-trust.md`](signing-and-trust.md) for the tag
  and roster trust chain the graph inherits.
- [`nix-cache.md`](nix-cache.md)
  for how stock Nix substitution relates to the graph.
