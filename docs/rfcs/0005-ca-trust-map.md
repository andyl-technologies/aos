# RFC-0005: The `ca/` trust map — content-addressed closure validation

- **Status:** Proposed (implementation in the same PR)
- **Date:** 2026-06-12
- **PR:** [#98](https://github.com/andyl-technologies/aos/pull/98)
- **Audience:** anyone working on `crates/aos-package/` (the `apr`
  publish pipeline and the `apm` download/verify pipeline) or the
  registry docs under `docs/registry/`.

## Problem

A registry's trust root is the signed git tag: tag → commit → tree
authenticates every committed file transitively
(`docs/registry/signing-and-trust.md`). The tree names store paths by
their **input-addressed (IA) hashes** — the 32-char nixbase32 store-path
hashes that appear in `packages/<x>/<name>.toml` (`store_path`,
`references`) and as every node of the `closures/<hash>` adjacency
lists (`docs/registry/repo-layout.md` §4–§5).

An IA hash is a promise about *how a path was built*, not *what bits it
contains*. The hash is fixed before the build runs, so two different
NARs — one honest, one tampered with after signing — can both legally
claim the same IA store path. The signature therefore roots the **shape**
of the dependency graph but not its **content**:

- The package root is covered: its TOML carries `nar_hash` (uncompressed
  NAR SHA-256) and `download_hash` (compressed artifact SHA-256), both
  inside the signed tree, and `apm` verifies them
  (`crates/aos-package/src/verify.rs`, used from `upgrade.rs` and
  `download.rs`).
- Every **non-root closure member** is not. The installer plans the
  closure from `closures/<root>`, then learns each member's NAR hash
  from a **cache-served narinfo** (`fetch_narinfos`,
  `crates/aos-package/src/download.rs`). Narinfos are not part of the
  signed tree — they come from whatever `[[caches]]` endpoint answered.
  A compromised cache (or CDN, or bucket) can serve a tampered NAR with
  a matching tampered narinfo for any dependency, and the registry
  signature never notices.

The graph edges break exactly at the IA boundary: the signed tree says
"curl depends on `r4q1m2kp8v3x` (zlib)", but nothing signed says which
*bits* `r4q1m2kp8v3x` is allowed to be.

## Design

Add a committed **trust map** from IA store-path hashes to one or more
**blessed content addresses**, stored in a new top-level `ca/`
directory of the registry tree. Because the map is in the tree, it is
signed-by-extension like everything else; because every closure member
has an entry, validating a closure becomes a pure membership check
against signed data, and the cache is demoted to an untrusted byte
transport — which is what it should have been all along.

This is the same shape as the Nix CA-derivations *realisation* concept
(the experimental trust map from a derivation output to a
content-addressed path, signed by a builder). The registry plays the
role of the realisation publisher, and the git signature plays the role
of the realisation signature.

### 2.1 Layout — fixed 1024-bucket files

```
<repo root>/
├── registry.toml
├── keys.toml
├── packages/<x>/<name>.toml
├── closures/<hash>
└── ca/
    ├── 0a            ← all entries whose IA hash starts with "0a"
    ├── 0b
    └── ...            (up to 32 × 32 = 1024 bucket files)
```

Buckets are named by the **first two nixbase32 characters** of the IA
store-path hash. Properties:

- **No migration, ever.** Nixbase32 store hashes are uniform over the
  alphabet, so buckets stay balanced: at 10k mapped paths a bucket
  averages ~10 lines; at 100k, ~100 lines (≈7 KB); at 1M, ~1000 lines
  (≈70 KB). One scheme spans today's bootstrap-chain registry and a
  nixpkgs-scale one.
- **Cheap lookup.** Validating a closure of N members reads at most
  min(N, 1024) bucket files, and the client knows which ones directly
  from the hashes in the closure file.
- **Cheap publish.** A publish only appends lines for paths not already
  mapped. After the registry warms up, most of a new package's closure
  already has entries, so a publish touches a handful of buckets.

Buckets are created on demand; an absent bucket file means "no entries
in this bucket".

### 2.2 File format — sorted adjacency lines

Each bucket file is UTF-8, LF-terminated lines, **sorted by IA hash**,
one line per mapped store path:

```
<ia-hash> <entry> [<entry> ...]
```

- `<ia-hash>` — the 32-char nixbase32 store-path hash, the same key
  used for `closures/` filenames and `references` values.
- `<entry>` — a type-tagged content address. Multiple entries mean
  multiple **blessed** realisations of the same IA path (non-reproducible
  rebuilds, independent builders). Order is not significant; writers
  keep entries sorted for stable diffs.

Lines starting with `#` and blank lines are ignored (same lexical rules
as `closures/` files, `ClosureMeta::parse`).

Entry types, dispatched on the first `:`-separated segment:

```
nar:sha256:<52-char-nixbase32>:<nar-size-bytes>
ca:fixed:r:sha256:<52-char-nixbase32>            (reserved, see §2.3)
```

Unknown entry types are skipped by consumers (forward compatibility),
but a line whose entries are *all* unknown types fails validation for
that path — silently treating "nothing I can check" as "checked" would
defeat the map.

Example bucket `ca/r4`:

```
r4q1m2kp8v3x nar:sha256:1b8m6vizwgzrbq6ks7yk3pnjnj91xbcrz0v6dyqgxqkj3ka2lkfy:1048576
r4z9w2n3p7c5 nar:sha256:0c7n5whyvfyqap5jr6xj21mimi80wabqy9v5cxpfwpji2j91kjcx:393216 nar:sha256:1d9p7xjzxhzscr7l18zl4qpkpk02ydhs01w7czrhyrlk4lb3mlgz:393218
```

(The second line shows a path blessed twice — two builders produced
byte-different but both-accepted outputs.)

Sorted lines keep git diffs minimal (a blessing is a one-line or
one-token change) and make concurrent-publish merge conflicts within a
bucket trivially resolvable.

`.gitattributes` deliberately does **not** get a `ca/** -diff` entry
(unlike `closures/**`). Blessing changes are the registry's
highest-value security-review surface: adding or removing a blessed
hash must show up as a readable one-line diff in `git log -p` and in PR
review.

### 2.3 Which content-address function?

There are two candidate functions, and they compose differently. The
map's value format is type-tagged precisely so we can ship the simple
one now without foreclosing the other.

**`nar:` — plain NAR hash of the path as built (this RFC ships this).**
IA paths embed their own store path in self-references, and that name
is fixed before the build, so the literal NAR bytes are already a
complete, deterministic content address of an IA path. It is also
exactly what a client can verify with zero extra machinery: hash the
NAR it was going to download anyway, compare. No rewriting, no
cross-path coupling — each path's check is independent, so multiple
blessed entries for a dependency never affect the parent's check.

**`ca:` — the experimental Nix CA-store form (reserved).** What
`nix store make-content-addressed` computes: NAR hash *modulo
self-references*, with dependency references rewritten to their CA
paths. This is the interop format for the Nix content-addressed store
proposal, but it has a composition subtlety: a parent's CA hash is a
function of *which* CA realisation of each dependency it was rewritten
against. The moment one IA hash carries two blessed entries, the
parent's CA hash is only meaningful relative to a specific dependency
assignment — Nix models this with `dependentRealisations` pinning. A
future RFC that activates `ca:` entries must either carry that pinning
in the entry format or require unique blessing within any closure being
validated. Nothing in this RFC's layout changes when that happens; it
is purely additive entries.

The security goal — exact bits rooted at the tag signature — is fully
achieved by `nar:` entries alone.

### 2.4 Validation flow (`apm`)

For every closure install/upgrade, after the registry sync has verified
the tag/commit chain:

1. Resolve the root and plan the closure from `closures/<root>` as
   today.
2. For each member (root included), load its blessed entry set from
   `ca/<prefix>`. **A member with no entry fails the whole closure** —
   the map is total over published closures, and a gap means the
   registry is malformed or downgrade-stripped.
3. Download the compressed NAR from any `[[caches]]` mirror.
   Decompress with a hard output cap of the largest blessed
   `nar-size` for that path (this bounds zstd-bomb exposure while
   decompressing not-yet-verified input).
4. SHA-256 the uncompressed NAR stream; accept iff
   `nar:sha256:<hash>:<size>` is in the blessed set. Reject the whole
   closure on any miss.

Cache-served narinfos are demoted to **advisory**: still used for the
NAR URL, compression kind, and download planning, never as a trust
source. The narinfo `NarHash` may be cross-checked early to fail fast,
but disagreement with `ca/` always resolves in favor of `ca/`.

Validation is per-member-independent under `nar:` entries, so download
parallelism is unchanged.

### 2.5 Publish flow (`apr`)

`apr publish` already walks the closure to write `closures/<root>`
(`write_closure_files`, `crates/aos-package/src/registry_ops.rs`). It
gains one step in the same walk: for every member, compute the NAR
SHA-256 and size from the local store (the publisher has the bytes —
it is about to upload them), and upsert
`nar:sha256:<hash>:<size>` into `ca/<prefix>`:

- New path → insert a sorted line.
- Existing path, same entry → no-op.
- Existing path, **different** entry → refuse by default with a clear
  diagnostic; `--bless` appends the new entry alongside the old. An
  unexpected hash mismatch during publish is exactly the signal this
  design exists to catch, so it must never be silently merged.

A separate `apr ca` subcommand owns explicit map maintenance:

- `apr ca bless <store-path>` — add an entry computed from local bytes
  (the multi-builder reproduction workflow).
- `apr ca revoke <ia-hash> <entry>` — remove a blessed entry.
- `apr ca verify [--root <hash>]` — recheck local/cached NARs against
  the map.

### 2.6 Trust semantics

The map is **append-mostly; removal is revocation.** Adding an entry
means another builder reproduced (or legitimately diverged on) the
path. Removing one means "we no longer trust these bits" and gets the
same ceremony as a `keys.toml` retirement: a signed commit with a
reviewable one-token diff, named in the commit message. Consumers treat
a revoked entry like any unknown hash — the bytes simply stop
validating on the next sync.

Anti-rollback for the map itself comes for free from the existing
signed-fast-forward / version-floor machinery
(`docs/registry/signing-and-trust.md`): an attacker cannot serve an
older tree that still blesses revoked bits without also rolling back
the tag, which continuity enforcement rejects.

### 2.7 Package TOML changes — `nar_hash` and friends

With `ca/` total over the closure, the per-platform package TOML sheds
the fields whose job it was doing partially:

| Field | Disposition |
|---|---|
| `nar_hash` | **Removed.** Redundant with the root's `ca/` entry, and worse: single-valued (cannot express multiple blessed rebuilds) and a second signed source that can disagree with the first. One authority. |
| `nar_size` | **Removed.** Sizes pair 1:1 with blessed hashes (different bits → different size), so they live inside each `nar:` entry. |
| `download_hash`, `download_size` | **Removed from the documented schema.** (Implementation note: these appeared in `repo-layout.md`'s TARGET example but were never read or written by the code — the removal is doc-only.) They describe one particular compressed artifact, which is cache-/compression-specific. Post-download verification against the blessed NAR hash subsumes them; the decompression cap (§2.4) covers the unverified-input window they would pre-check. They remain available, unauthenticated, in narinfos for planning and early-fail. |
| `store_path`, `references`, `closure_size`, `source_drv`, `source_nar_hash` | **Unchanged.** (`references` overlaps with the `closures/` root line and could fold away later, but that is graph shape, not content trust — out of scope here.) |

The narinfo emitter (`docs/registry/nix-cache-compatibility.md` §6)
reads `NarHash`/`NarSize` from `ca/` instead of the TOML; where a path
has multiple blessed entries, the emitter publishes the one matching
the artifact the cache actually stores.

### 2.8 Migration

The registry is pre-1.0 and self-hosted, so the cutover is short, but
parsers must not hard-break on published trees:

1. **Parse-tolerant first.** Consumer-side TOML parsing treats the
   removed fields as optional and ignores them when present
   (`registry/parse.rs`). Already-published registries keep working.
2. **Producer cutover.** `apr publish` writes `ca/` entries and stops
   emitting the removed TOML fields. `apr ca backfill` walks all
   published closures and generates entries from the origin's NARs, so
   an existing registry becomes fully mapped in one signed commit.
3. **Consumer enforcement.** Enforcement is **per source registry**: a
   path is judged against the `ca/` map of the registry that resolved it,
   never a cross-registry union. When that registry publishes a map, a
   missing blessed entry for any closure member is a hard failure — checked
   over the *whole* closure (including members already in the local store),
   so a *partial* map is rejected even on an upgrade where the gap falls on
   an already-present path (a partial map is indistinguishable from a
   stripping attack). A registry with no `ca/` directory at all falls back,
   with a warning, to verifying every downloaded member against the
   cache-served narinfo `NarHash` — the same unauthenticated check apm
   applied before this RFC. A mixed transaction (one mapped registry, one
   legacy) enforces the mapped registry's paths regardless of the legacy
   one.

## What this does NOT do

- It does not switch AOS to the Nix CA store. Store paths, the cache
  layout, and `closures/` are untouched; `ca/` is a parallel index.
- It does not authenticate narinfos. They become advisory; the signed
  map makes their integrity irrelevant.
- It does not bind IA hashes to *derivations* (no `drv → output`
  edge). The key is the store-path hash because that is what the tree
  already speaks. If true CA-derivation interop lands later, the
  `source_drv` field already in the TOML provides the join point.

## Open questions

1. **`ca:` entry activation.** Dependent-realisation pinning vs.
   unique-blessing-per-closure, deferred to the RFC that needs it
   (§2.3).
2. **Bucket-internal compression of repeated prefixes** (e.g. elide
   the `nar:sha256:` tag when it's the only type in use) — rejected
   for now; explicitness wins at these file sizes.
3. **Folding `references` out of the package TOML** in favor of the
   closure root line (§2.7) — separate cleanup, separate PR.

## Implementation plan (this PR)

1. `ca/` read model in `crates/aos-package/src/registry/` (bucket
   loading, line parsing, entry types) + types in `types.rs`.
2. Publish-side writing in `registry_ops.rs` (closure walk upsert,
   refuse-on-mismatch, `--bless`), `apr ca` subcommand
   (`bless`/`revoke`/`verify`/`backfill`).
3. Verify-side enforcement in `download.rs`/`upgrade.rs` (blessed-set
   membership, decompression cap, narinfo demotion).
4. TOML field removal per §2.7–§2.8 (tolerant parse, emit stop,
   narinfo emitter reads `ca/`).
5. Docs: update `docs/registry/repo-layout.md` (new §, tree diagram),
   `signing-and-trust.md`, `nix-cache-compatibility.md`.
