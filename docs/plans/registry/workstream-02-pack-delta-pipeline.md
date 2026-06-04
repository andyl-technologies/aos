# Workstream 02 — Pack & Delta Pipeline

> **Status:** Plan (target). Grounded by
> [`design-brief.md`](./design-brief.md) §9–§10. This workstream replaces the
> current **git-bundle** transport (`bundle-list.toml` manifest + `git bundle
> create/verify/unbundle`) with a **git-native pack/thin-delta pipeline** served
> over dumb HTTP. Anything describing bundles, `creation_token`, snapshot/skip/
> sequential bundle classification, or `bundle-list.toml` is **removed** from the
> target (see brief §15).
>
> **Scope:** the producer side of pack generation (full packs at `X.Y.0`, the
> guaranteed thin-delta scheme, `pack-objects` tuning, the zstd transport trick,
> the optional trained dictionary) plus the client-side completion primitives
> (`index-pack --fix-thin`, `zstd -d`). Channel/rollout selection of *which*
> release to fetch is [workstream-03](./workstream-03-channels-rollouts.md); the
> full client resolution walk + retention is
> [workstream-05](./workstream-05-consumer.md); the sha256 bare repo and
> `info/alternates` object layout this rides on is
> [workstream-01](./workstream-01-object-store.md).

---

## 1. Goal

Produce, per release, exactly the pack/delta artifacts the brief guarantees, so
that:

- a **stock dumb-HTTP git client** can clone via conventionally-named full packs
  (`pack-<sha256>.pack` + `.idx`) plus loose objects — no thin packs needed; and
- an **AOS client** can fetch a cheap **thin** `delta-<from-semver>.pack`,
  decompress it (`zstd -d`), and complete it locally
  (`git index-pack --fix-thin`).

The governing philosophy (brief §3): **make publishing as expensive as possible
so consumption is as cheap as possible.** The producer spends CPU once on tight
delta search and `zstd --ultra`; every consumer downloads less and reconstructs
fast.

---

## 2. CURRENT state (as-is) — what we replace

The current transport is a git-**bundle** pipeline. Cited code in
[`crates/aos-package/src/registry/bundle.rs`](../../../crates/aos-package/src/registry/bundle.rs):

| Concern | Current implementation | `path:line` |
|---|---|---|
| Artifact format | git **bundles** (`*.bundle`), refs + prereqs baked in | `bundle.rs:3-5` |
| Bundle taxonomy | `Snapshot` / `SequentialDelta` / `SkipDelta` enum | `bundle.rs:22-31` |
| Manifest | `bundle-list.toml` parsed by the **consumer** | `bundle.rs:59-92`, `124-178` |
| Ordering key | `creation_token: u64` (calendar) | `bundle.rs:36-45`, `170-171` |
| Tag scheme | calendar `vYYYY.MM[.P]`, classified by dot-segment count | `bundle.rs:238-243` |
| Integrity | SHA-256 of bundle file + `git bundle verify` | `bundle.rs:305-346` |
| Apply | `git bundle unbundle` into a bare cache repo | `bundle.rs:349-404` |
| Producer | **stub** — `apr bundle` = `git bundle create`; no manifest writer, no upload (brief §2) | — |
| Selection | `latest_snapshot` / `skip_delta_from` / `sequential_deltas_between` over `creation_token` | `bundle.rs:189-224` |

Everything in the table above is **deleted or rewritten** in the target. The
only primitive that survives unchanged is "SHA-256 the artifact file before
trusting it" — and in the target that role is largely carried by git's own
object-format hashing (`index-pack` validates the pack) plus the signed-tag
trust chain, so file-level SHA-256 is no longer a manifest field.

### Why bundles are wrong for this design

- A bundle **carries refs and prerequisites** in a self-describing header. The
  target moves refs out of artifacts entirely: channels are branches, releases
  are signed tag objects, and the 256 partition tags live at `/channel/*` (brief
  §5). A bundle's ref payload would duplicate (and could contradict) that.
- Bundles can't be composed with the dumb-HTTP object store / `info/alternates`
  layout (workstream-01). The target wants packs that drop straight into
  `/release/<…>/objects/pack/` and loose objects that land in the single root
  `/objects/` and satisfy any stock client.
- The `creation_token` ordering the bundle manifest depends on is removed (brief
  §15). The target orders by **semver + git ancestry**.

---

## 3. TARGET artifacts per release

A release's **pack** artifacts live under its per-release object dir
(workstream-01). This dir is **pack-only**: it holds `info/packs` + the `pack/`
tree, and **no** loose `<xx>/<62-hex>` objects and **no** per-release
`info/alternates`. All loose objects (this release's NEW objects included) live
in the single **root** `/objects/<xx>/<62-hex>` (D):

```
/objects/<xx>/<62-hex>                      ← ALL loose objects (every release), ROOT only

/release/<major>/<minor>/<patch[-pre][+build]>/objects/
  info/packs                                ← lists self-contained pack-<sha>.pack ONLY
  pack/
    pack-<sha256>.pack   (+ .idx)           ← FULL pack; present only at X.Y.0
    pack-<sha256>.pack.zst                  ← zstd-wrapped full pack (transport)
    delta-<from-semver>.pack                ← THIN delta; AOS-only; NOT in info/packs
    delta-<from-semver>.pack.zst            ← zstd-wrapped thin delta (transport)
                                            ← NO loose <xx>/<62-hex> here; NO info/alternates
```

Rules (brief §9, §10, §12):

- **Full packs** are named `pack-<sha256>.pack` (+ `.idx`) and **listed in
  `info/packs`** so stock dumb git uses them. We drop any semantic `full.pack`
  name — no duplicate.
- **Thin deltas** are named `delta-<from-semver>.pack` and are **NOT listed in
  `info/packs`** (a stock dumb client cannot apply a thin pack). AOS clients
  discover them by the `delta-<semver>` filename convention.
- `.idx` is shipped **only** for self-contained full packs. Thin deltas are
  `.pack[.zst]` only — the client's `--fix-thin` builds the index.
- The `.zst` variants are the **transport** form (§7). The plain `.pack`/`.idx`
  remain present so a zstd-unaware stock client still works off the full pack.

---

## 4. The guaranteed delta scheme (the walkable graph)

The producer **commits** to emitting exactly these artifacts, so clients can
plan a walk without probing (brief §9). `X`, `Y`, `Z` are semver
major/minor/patch.

| Release kind | Full pack? | Delta packs emitted |
|---|---|---|
| **`X.Y.0`** (any major or minor) | **yes** `pack-<sha256>` | (see below) |
| `X.0.0` (major) | yes | `delta-<(X-1).0.0>` (from last major) |
| `X.Y.0`, `Y>0` (minor) | yes | `delta-<X.(Y-1).0>` (last minor) + `delta-<X.0.0>` (current major) |
| `X.Y.Z`, `Z>0` (patch) | **no** | `delta-<X.Y.(Z-1)>`, `delta-<X.Y.(Z-2)>`, `delta-<X.Y.(Z-3)>` (last 3 patches, where they exist) + `delta-<X.Y.0>` (current minor) |

Notes:

- **Patch releases have no full pack.** A stock dumb clone of a patch pulls the
  minor-base full pack (discovered via the relative `info/alternates` release
  index) plus the patch's loose new objects from the root `/objects/` — graceful
  degradation, no thin packs (brief §9, §12).
- The patch fan of "last 3 patches + minor base" is co-designed with the client
  **retention** rule (brief §9): a client on `X.Y.Z` keeps object trees for at
  least `X.0.0`, `X.Y.0`, and `X.Y.Z`, so a usable delta base is always present.

### Example: the delta graph for a `1.x` line

The figure lists, under each release, the **deduplicated** delta set it actually
emits (the names clients plan against). Where a patch's `Z-k` lookback slot would
land on (or before) the minor base `1.1.0`, that slot **collapses into the minor
base** — it is not emitted twice. Full packs exist only at `X.Y.0`.

```
  full pack             full pack                                    full pack
     │                     │                                             │
  1.0.0 ────────────────▶ 1.1.0 ──▶ 1.1.1 ──▶ 1.1.2 ──▶ 1.1.3 ───────▶ 1.2.0
     │                     │          │         │         │              │
  (full only,          full pack +  {d-1.1.0} {d-1.1.1, {d-1.1.2,    full pack +
   first major:        {d-1.0.0}              d-1.1.0}  d-1.1.1,     {d-1.1.0,
   no delta)           (minor base                      d-1.1.0}     d-1.0.0}
                        == major)

  Per-patch derivation (last-3-patches + minor base, deduped):
    1.1.1 (Z=1): Z-1=1.1.0; minor base=1.1.0      → collapse → {d-1.1.0}
    1.1.2 (Z=2): Z-1=1.1.1, Z-2=1.1.0; base=1.1.0 → Z-2 collapses → {d-1.1.1, d-1.1.0}
    1.1.3 (Z=3): Z-1=1.1.2, Z-2=1.1.1, Z-3=1.1.0; → Z-3 collapses → {d-1.1.2, d-1.1.1, d-1.1.0}
                 base=1.1.0
```

Reading 1.1.2 (a patch, `Z=2`): the lookback slots are `Z-1=1.1.1` and
`Z-2=1.1.0`, plus the minor base `1.1.0`. The `Z-2` slot lands exactly on the
minor base, so it collapses — the actual artifacts are `{delta-1.1.1,
delta-1.1.0}`. Reading 1.2.0 (a minor): full pack + `delta-1.1.0` (last minor) +
`delta-1.0.0` (current major).

### Client resolution (summary; full walk in workstream-05)

Current `C` → target `T`: prefer a `delta-<B>.pack` at `T` whose base `B` the
client retains; else walk releases backward until a usable delta or a full pack
is found; else fetch a full pack; else fall back to **loose objects** over dumb
HTTP (always correct). Cross-major jumps degrade to "minor-base full pack +
walk" (brief §9).

---

## 5. Producer: delta packs (thin)

A thin delta carries only objects in `<to>` not in `<from>`, and is permitted to
emit deltas whose base object lives in `<from>` (hence "thin" — the base is
absent from the pack). The producer reads a rev range on stdin (brief §10):

```sh
# Generate delta-<from>.pack: objects in <to-commit> not in <from-commit>,
# deltas may reference <from>'s objects (THIN).
printf '%s\n^%s\n' "$TO_COMMIT" "$FROM_COMMIT" \
  | git -C "$REPO" pack-objects --revs --thin --stdout \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 \
      --compression=0 \
  > "delta-${FROM_SEMVER}.pack"
```

- `--revs` reads the `"<to>\n^<from>\n"` range from stdin and packs the
  difference.
- `--thin` allows base objects to be omitted (they exist in `<from>`, which the
  client already has).
- `--stdout` writes the pack to stdout; the producer names it
  `delta-<from-semver>.pack`. **No `.idx` is shipped** for thin deltas.
- The client **must** complete it (§8): `git index-pack --fix-thin` re-attaches
  the missing bases from the local object store and writes the `.idx`.

The producer may try **multiple delta bases** for the same `<to>` and ship the
smallest result (brief §10) — but it must still ship the *named* deltas the
scheme in §4 guarantees, because clients plan against those names. "Try multiple
bases, ship the smallest" applies to *intra-pack* delta-base selection, not to
substituting a different `from-semver` filename.

---

## 6. Producer: full packs (non-thin)

A full pack at `X.Y.0` is self-contained: every object it references is inside
it. It is named by its content sha256 and listed in `info/packs`.

```sh
# Generate a self-contained full pack over the release commit.
git -C "$REPO" rev-parse "$RELEASE_COMMIT^{commit}" \
  | git -C "$REPO" pack-objects --revs \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 \
      --compression=0 \
      "$OUT_DIR/pack"                        # writes pack/pack-<sha256>.pack + .idx
```

- **`--revs`, no `--thin`** → a complete, self-contained pack (brief §10).
- The base-name argument (`"$OUT_DIR/pack"`) makes `git pack-objects` write
  `pack-<sha256>.pack` and `pack-<sha256>.idx`, where `<sha256>` is the pack
  content hash — exactly the dumb-HTTP convention stock git expects, so the
  semantic `full.pack` name is dropped (brief §12).
- For the X.Y.0 **boundary**, pack the full set reachable from the release
  commit so the pack stands alone; the parallel `delta-<prior X.Y.0>` (§4)
  covers the same surface for AOS clients that already hold the base.

After writing, **list it** in the per-release `objects/info/packs` and
regenerate the root `objects/info/alternates`/`info/refs` (workstream-01). The
`info/alternates` entries are **relative** paths
`../release/<M>/<m>/<patch…>/objects/` (newest→oldest, one `../`), so it is
host-independent and serves **pack discovery + the release index** — not object
completeness, since all loose objects are centralized at the root.

---

## 7. The zstd transport trick

**Problem:** git's pack format hard-codes **zlib (DEFLATE) per object**. Wrapping
a `--compression=9` pack in zstd is near-useless — the bytes are already entropy-
coded by DEFLATE, so zstd finds almost nothing to compress (brief §10).

**Solution (the working trick):** emit the pack with `--compression=0` and then
zstd the whole file at maximum effort.

```sh
# 1. Produce the pack with zlib level 0 = "stored": valid zlib framing,
#    NO entropy coding — BUT git's per-object DELTA ENCODING is still applied.
git -C "$REPO" pack-objects ... --compression=0 ...        # → foo.pack

# 2. Let zstd do the entropy coding over the delta-encoded stream.
zstd --ultra -22 --long=27 -o foo.pack.zst foo.pack
```

Why this wins:

- `--compression=0` ("stored") keeps the pack **git-valid** (correct zlib
  framing) while skipping zlib's weak entropy coder. Crucially git's **delta
  encoding still runs** — the expensive, high-value transform is preserved.
- `zstd --ultra -22 --long=27` then applies a far stronger entropy coder + long-
  range matcher over the delta-encoded stream, **beating zlib-9** on the same
  content.
- The pack inside the `.zst` is byte-for-byte a valid git pack, so the client
  path is simply `zstd -d | git index-pack`.

**Transport:** serve `.pack.zst` (both full and thin). Client:

```sh
# Thin delta:
zstd -d --long=27 -o delta.pack delta-<from>.pack.zst
git -C "$REPO" index-pack --fix-thin delta.pack            # completes + writes .idx

# Full pack:
zstd -d --long=27 -o pack-<sha>.pack pack-<sha>.pack.zst
git -C "$REPO" index-pack pack-<sha>.pack                  # writes .idx
```

> **`--long=27`** (128 MiB window) must match between compressor and
> decompressor or `zstd -d` will refuse the long-distance matches. Pin it on
> both sides (open question: brief §16.2 — final level/window defaults).

### Optional: trained dictionary per release line

A zstd **trained dictionary** computed across a release line's many *small*
delta packs is an optional further win (brief §10, §16.2). Small packs compress
poorly standalone because zstd has no history to prime from; a shared dictionary
front-loads that history.

```sh
# Train once per release line over its accumulated delta packs:
zstd --train release-1.x/objects/pack/delta-*.pack \
     -o release-1.x/objects/pack/zstd-dict-1.x

# Compress/decompress small deltas with the dictionary:
zstd --ultra -22 -D zstd-dict-1.x -o delta-<from>.pack.zst delta-<from>.pack
zstd -d        -D zstd-dict-1.x -o delta-<from>.pack       delta-<from>.pack.zst
```

The dictionary is served alongside the line's packs; the client fetches it once
and reuses it for every delta on that line. This is **optional** and gated on the
open question — full packs (large) gain little from a dictionary; the win is on
the patch-delta fan.

---

## 8. Expensive-producer tuning

The producer is allowed to be slow; the consumer must be fast (brief §3, §10).

| Flag | Value | Rationale |
|---|---|---|
| `--no-reuse-object` | on | Re-encode every object; ignore existing pack layout. |
| `--no-reuse-delta` | on | Recompute every delta from scratch — don't inherit prior (possibly weak) deltas. |
| `--window=<large>` | **≈350** | Delta-search window. **The free lever** — bigger = better deltas, only producer CPU/RAM cost. |
| `--depth=<moderate>` | **≈50** | Max delta-chain length. **Cap this** — deep chains cost the *consumer* CPU to reconstruct. Do **not** crank it like `--window`. |
| `--threads=0` | all cores | Parallelize the search across all available CPUs. |
| `--compression=0` | "stored" | Skip zlib entropy coding so the zstd trick (§7) can do it better; keeps delta encoding. |

**Asymmetry to remember:** `--window` is cheap for consumers (it only affects how
hard the producer searched); `--depth` is *paid by consumers* every reconstruct.
That's why the brief says "window is the free lever; cap depth."

The producer may additionally try multiple delta bases per object and ship the
smallest pack (§5).

---

## 9. Client completion primitives

These are the only client-side pack operations this workstream owns (the *walk*
that decides which delta to fetch is workstream-05):

| Step | Command | Notes |
|---|---|---|
| Decompress | `zstd -d --long=27 [-D dict] -o X.pack X.pack.zst` | Window/dict must match producer. |
| Complete thin | `git index-pack --fix-thin X.pack` | Re-attaches bases from local store; writes `X.idx`. **Required** for every `delta-*.pack`. |
| Index full | `git index-pack X.pack` | Self-contained; just writes the `.idx`. |
| Fallback | loose-object fetch over dumb HTTP | Always correct; used when no usable pack/delta (brief §9, §12). |

`--fix-thin` **requires** the delta's base objects to already be in the local
object store — which the retention rule (§4, workstream-05) guarantees. If a base
is missing, the client must fall back (walk to an earlier delta or a full pack,
or fetch loose objects), never error out.

---

## 10. Producer pipeline ordering (within a publish)

This workstream is the **pack/delta stage** of the end-to-end publish (full
pipeline in [`docs/registry/publishing.md`](../../registry/publishing.md) and
brief §10/§4/§6):

```
  commit ──▶ sign tag (ws-04) ──▶ ┌─────────────────────────────────────┐
                                  │ PACK/DELTA STAGE (this workstream)   │
                                  │  1. if X.Y.0: full pack (§6)         │
                                  │  2. scheme deltas (§4, §5)           │
                                  │  3. --compression=0 on all (§7)      │
                                  │  4. zstd --ultra (+ optional dict)   │
                                  │  5. write .pack[.zst]/.idx into      │
                                  │     /release/<…>/objects/pack/;      │
                                  │     loose objects → root /objects/   │
                                  │  6. list full pack in info/packs     │
                                  │     (NOT thin deltas)                │
                                  └─────────────────────────────────────┘
            ──▶ update-server-info (ws-01) ──▶ advance partitions (ws-03) ──▶ upload
```

Atomicity: write all immutable artifacts (root loose objects, per-release packs,
`.zst`) **before** the low-TTL index files (`info/packs`, `info/alternates`,
`info/refs`) are flipped, so a CDN never advertises a pack that isn't fully
uploaded (brief §4 TTL policy; workstream-01 for the index writes).

---

## 11. Implementation tasks

New module replacing `bundle.rs`'s producer/transport role (suggested
`crates/aos-package/src/registry/pack.rs`):

1. **Delete the bundle transport path.** Remove `BundleType`, `BundleEntry`,
   `BundleManifest`, `classify_delta`, `download_bundle`, `verify_bundle`,
   `unbundle`, and the `bundle-list.toml` parser
   ([`bundle.rs:22-243`, `251-404`](../../../crates/aos-package/src/registry/bundle.rs)).
   Keep `ensure_git_repo` (`bundle.rs:349-371`) and `resolve_tag`
   (`bundle.rs:407-421`) — they're format-agnostic and still useful.
2. **`fn full_pack(repo, release_commit, out_dir)`** — runs the §6
   `pack-objects --revs` invocation, names by content sha256, returns the pack
   path for `info/packs` listing.
3. **`fn thin_delta(repo, from_commit, to_commit, from_semver, out_dir)`** — runs
   the §5 `pack-objects --revs --thin --stdout`, writes
   `delta-<from-semver>.pack`.
4. **`fn scheme_deltas(release: &Semver) -> Vec<FromSemver>`** — pure function
   returning the §4 guaranteed delta set for a given release (major/minor/patch
   fan, deduplicated). Unit-testable in isolation.
5. **`fn zstd_compress(path, opts)` / `fn zstd_decompress(path, opts)`** — the §7
   `--ultra -22 --long=27` (+ optional `-D dict`) wrappers.
6. **`fn index_pack_fix_thin(repo, pack)` / `fn index_pack(repo, pack)`** — client
   completion (§9).
7. **`fn train_dictionary(release_line, packs)`** — optional (§7); gated behind a
   flag pending brief §16.2.

### Test plan

- **`scheme_deltas`** table tests on **semver** (not `creation_token`/calendar):
  `1.0.0` → `[(prior major).0.0]` (or empty if first); `1.1.0` →
  `[1.0.0 (last minor), 1.0.0 (current major)]` dedup → `[1.0.0]`; `1.1.2` →
  `[1.1.1, 1.1.0, 1.1.0]` dedup → `[1.1.1, 1.1.0]`. Mirror the *intent* of the old
  `delta_classification` tests
  ([`bundle.rs:533-559`](../../../crates/aos-package/src/registry/bundle.rs)) but
  on semver ancestry.
- **Round-trip**: `full_pack` → `zstd_compress` → `zstd_decompress` →
  `index_pack` reproduces a clonable store; `thin_delta` → `zstd` → `zstd -d` →
  `index_pack --fix-thin` against a store holding the base reproduces the target
  commit.
- **Stock-git compat**: a `git clone` (dumb HTTP, sha256) of an `X.Y.0` release
  using only `info/packs`-listed full packs + loose objects succeeds without ever
  touching a `delta-*.pack`.
- **Size assertion**: `--compression=0` + `zstd --ultra` produces a smaller
  `.pack.zst` than `--compression=9` + `zstd` on the same release (validates §7).

---

## 12. Cross-references

- [`design-brief.md`](./design-brief.md) — §9 (delta scheme), §10 (pack
  generation + zstd), §12 (stock-git compat), §16.2 (open: window/depth/zstd
  defaults + dictionary).
- [`workstream-01-object-store.md`](./workstream-01-object-store.md) — sha256 bare
  repo, `info/packs`, relative `info/alternates`, `update-server-info`,
  root loose-object store + per-release pack-only object dirs.
- [`workstream-03-channels-rollouts.md`](./workstream-03-channels-rollouts.md) —
  which release a partition targets (the `<to>` of a delta).
- [`workstream-04-signing-trust.md`](./workstream-04-signing-trust.md) — signed
  tags whose commits the packs cover.
- [`workstream-05-consumer.md`](./workstream-05-consumer.md) — the full client
  delta-walk + retention rule this scheme is co-designed with.
- [`gap-analysis.md`](./gap-analysis.md) — bundle → pack/delta gap enumeration.
- [`open-questions.md`](./open-questions.md) — §16 risks/migration.
- [`README.md`](./README.md) — plan overview and sequencing.
- Reference set: [`packs-and-deltas.md`](../../registry/packs-and-deltas.md)
  (target reference), [`http-layout.md`](../../registry/http-layout.md),
  [`publishing.md`](../../registry/publishing.md),
  [`versioning-and-channels.md`](../../registry/versioning-and-channels.md),
  [`signing-and-trust.md`](../../registry/signing-and-trust.md),
  [`nix-cache-compatibility.md`](../../registry/nix-cache-compatibility.md),
  [`apt-comparison.md`](../../registry/apt-comparison.md),
  [`architecture.md`](../../registry/architecture.md),
  [`current-state.md`](../../registry/current-state.md),
  [`README.md`](../../registry/README.md).
- Current code (to remove/refactor):
  [`crates/aos-package/src/registry/bundle.rs`](../../../crates/aos-package/src/registry/bundle.rs).
