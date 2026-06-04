# Packs & Deltas

> **Scope:** the binary-efficiency layer of the AOS registry — how the git
> object store (the package metadata *tree*) is packaged for transport. Covers
> the **full pack** anchored at every `X.Y.0` release, the **guaranteed, walkable
> thin-delta graph** the producer commits to, **client resolution** (which delta
> or pack to fetch) and **client retention** (which object trees to keep), the
> **`git pack-objects` / `index-pack --fix-thin`** mechanics, the
> **expensive-producer** tuning levers, and the **zstd** compression trick.
>
> This is the transport that carries the registry's **git objects** (the
> package-TOML tree) over dumb HTTP. It is **not** the NAR/blob substitution path
> (see [nix-cache-compatibility.md](./nix-cache-compatibility.md)).
>
> **CURRENT vs TARGET:** sections labeled **CURRENT** describe code that exists
> today, cited as `path:line`. Sections labeled **TARGET** describe the design in
> [`design-brief.md`](../plans/registry/design-brief.md) §9–§10 (with §4, §8 for
> the object-store context) that is not yet implemented.

**Related reference docs:**
[README](./README.md) ·
[architecture](./architecture.md) ·
[current-state](./current-state.md) ·
[http-layout](./http-layout.md) ·
[versioning-and-channels](./versioning-and-channels.md) ·
[signing-and-trust](./signing-and-trust.md) ·
[publishing](./publishing.md) ·
[nix-cache-compatibility](./nix-cache-compatibility.md) ·
[apt-comparison](./apt-comparison.md)

**Related plan docs:**
[plan README](../plans/registry/README.md) ·
[design brief](../plans/registry/design-brief.md) ·
[gap analysis](../plans/registry/gap-analysis.md) ·
[workstream-01 object store](../plans/registry/workstream-01-object-store.md) ·
[workstream-02 pack/delta pipeline](../plans/registry/workstream-02-pack-delta-pipeline.md) ·
[workstream-05 consumer](../plans/registry/workstream-05-consumer.md) ·
[open questions](../plans/registry/open-questions.md)

---

## 1. Where packs sit in the architecture

The registry is a **bare git repository (sha256 object format) served as static
files over dumb HTTP** (see [architecture.md](./architecture.md) and
[http-layout.md](./http-layout.md)). The package metadata *is* the git tree
content; a channel is a branch, a release is a signed tag. Three layers of object
availability ride on top of that store, in increasing efficiency and decreasing
universality:

| Layer | Artifact | Who reads it | Guarantee |
|---|---|---|---|
| **Loose objects** | `/objects/<xx>/<62-hex>` (central root only — every release) | any dumb-HTTP git client | **always complete** — correctness fallback |
| **Full pack** | `pack-<sha256>.pack` (+ `.idx`) at `X.Y.0` anchors | stock git (listed in `info/packs`) + AOS | self-contained |
| **Thin delta pack** | `delta-<from-semver>.pack` (`.zst`) | **AOS only** (not listed in `info/packs`) | needs base; cheapest |

The design philosophy is **asymmetric cost**: *make publishing as expensive as
possible so consumption is as cheap as possible*. The producer pays once (large
delta windows, multiple base attempts, `zstd --ultra -22`); every consumer
benefits with a small, fast fetch. Loose objects guarantee that even a stock
`git clone` from a sha256-capable client always succeeds, with packs and deltas
as pure speed layers on top.

> **No git bundles (TARGET).** Bundles carry refs and prerequisites; in the
> target the ref namespace is replaced by signed tag objects, so the transport
> is bare `*.pack`/`*.pack.zst` files. Today's code still ships bundles — see
> [§7](#7-current-the-bundle-model-being-replaced) for the as-is.

---

## 2. TARGET: full packs at every `X.Y.0` anchor

Every **major or minor** release — any version whose patch component is `0`
(`X.Y.0`) — ships a **self-contained full pack**:

```
/releases/<major>/<minor>/0/objects/pack/pack-<sha256>.pack
/releases/<major>/<minor>/0/objects/pack/pack-<sha256>.idx
```

- The pack is named `pack-<sha256>.pack` (git's conventional name) and **listed
  in that release's `objects/info/packs`**, so a stock dumb-HTTP git client
  discovers and uses it. We use **only** this name — there is no separate
  semantic `full.pack` alias.
- The `.idx` **is** shipped for full packs (they are self-contained, so the index
  can be precomputed by the producer).
- A full pack is built **non-thin** — it references no objects outside itself.

Patch releases (`X.Y.Z`, `Z>0`) deliberately ship **no full pack**; a stock
client reconstructs them from the minor-base full pack plus the patch's new loose
objects (from the central root `/objects/`, see
[§6](#6-graceful-degradation-for-stock-git)).

---

## 3. TARGET: the guaranteed delta graph

The producer **commits to producing exactly** the delta packs below for each
release class. Because the set is guaranteed, a client can *plan* a fetch knowing
which deltas will exist. All deltas are **thin** (`delta-<from-semver>.pack`,
not listed in `info/packs`, completed on the client with `--fix-thin`).

| Release class | Full pack? | Delta packs shipped |
|---|---|---|
| **Major** `X.0.0` | yes (`X.Y.0` rule, `Y=0`) | `delta-<(X-1).0.0>.pack` (last major) |
| **Minor** `X.Y.0` (`Y>0`) | yes | `delta-<X.(Y-1).0>.pack` (last minor) **and** `delta-<X.0.0>.pack` (current major) |
| **Patch** `X.Y.Z` (`Z>0`) | **no** | `delta-<X.Y.(Z-1)>.pack`, `delta-<X.Y.(Z-2)>.pack`, `delta-<X.Y.(Z-3)>.pack` (last 3 patches, where they exist) **and** `delta-<X.Y.0>.pack` (current minor) |

The `<from-semver>` in each filename is the delta's **base** — the release whose
objects the thin pack is allowed to reference. The delta carries only the objects
introduced **between** the base release commit and this release commit.

### 3.1 Why this exact shape

Each rule pairs with a client retention guarantee (see [§5](#5-target-client-retention))
so a usable base is **always** present locally:

- A client on the **current major** can land on any new major in one delta
  (`delta-<(X-1).0.0>`).
- A client on the **previous minor** *or* the **current major** can land on a new
  minor in one delta (`delta-<X.(Y-1).0>` or `delta-<X.0.0>`).
- A client on the **last few patches** *or* the **minor base** can land on a new
  patch in one delta — patches churn fastest, so they get the widest fan-in
  (3 prior patches + the minor anchor).

```
                        major delta (last major)
   (X-1).0.0  ───────────────────────────────────────────▶  X.0.0
                                                              │  ▲
                          minor delta (current major)         │  │
   X.0.0  ──────────────────────────────────────────────▶  X.Y.0
                          minor delta (last minor)            │
   X.(Y-1).0  ──────────────────────────────────────────▶  X.Y.0
                                                              │  full pack here
                          patch delta (current minor)         ▼
   X.Y.0  ──────────────────────────────────────────────▶  X.Y.Z
   X.Y.(Z-1) ───┐                                            ▲
   X.Y.(Z-2) ───┼─ last 3 patch deltas ────────────────────▶┘   (no full pack)
   X.Y.(Z-3) ───┘
```

A full pack sits at every `X.Y.0` node; patch nodes are reachable only by delta
or by the loose-object fallback.

---

## 4. TARGET: client resolution

Given a client currently on release **C** that wants to advance to target **T**,
resolution walks from cheapest to most-universal:

1. **Retained-base delta.** Prefer a `delta-<B>.pack` published *at T* whose base
   `B` the client **retains** (per [§5](#5-target-client-retention)). One fetch,
   one `--fix-thin`. This is the common case and is guaranteed to exist when
   `C` is a retained base of `T` under the [§3](#3-target-the-guaranteed-delta-graph)
   graph.
2. **Walk back.** If no delta at `T` has a base the client retains, walk releases
   **backward** from `T`, fetching the chain of deltas (or stopping at) the first
   release the client can reach — accumulating thin packs and completing each with
   `--fix-thin`.
3. **Full pack.** If the walk reaches an `X.Y.0` anchor the client does not yet
   have, fetch that anchor's `pack-<sha256>.pack` (self-contained), then any
   remaining deltas forward to `T`.
4. **Loose fallback.** If no pack path resolves, fetch the needed **loose
   objects** over dumb HTTP from the central root `/objects/<xx>/<62-hex>`, where
   the loose objects for **every** release live. (`objects/info/alternates` lists
   every per-release `objects/` dir newest→oldest and doubles as the full release
   index — but it serves **pack discovery + the release index**, not object
   completeness, since loose objects are centralized.) This is **always correct**
   for any sha256-capable git client.

**Cross-major jumps** degrade to *“minor-base full pack + walk”*: fetch the
target major/minor's full pack, then apply forward patch deltas to reach `T`,
rather than chaining many small deltas across a major boundary.

```
 want T, have C
   │
   ├─ delta-<B>.pack at T with B retained? ── yes ─▶ fetch 1 delta, --fix-thin ─▶ done
   │                                          no
   ├─ walk back from T collecting deltas ── reaches retained release? ─▶ apply chain ─▶ done
   │                                          no
   ├─ reach an X.Y.0 anchor? ── yes ─▶ fetch full pack-<sha256>.pack, then forward deltas ─▶ done
   │                            no
   └─ fetch loose objects from root /objects/ (always correct) ─▶ done
```

---

## 5. TARGET: client retention

To keep a delta base always present, a client on `X.Y.Z` retains the object trees
for **at least**:

| Retained tree | Why |
|---|---|
| `X.0.0` (current major) | base for the next minor's `delta-<X.0.0>` and cross-major full-pack anchor |
| `X.Y.0` (current minor) | base for the next patch's `delta-<X.Y.0>` and the minor full-pack anchor |
| `X.Y.Z` (current patch) | base for the next patch's `delta-<X.Y.(Z-1)>` chain |

Retention is **co-designed** with the delta graph: every guaranteed delta names a
base that one of these three retained trees provides. A client may retain more
(e.g. the last few patches to widen its delta options) but never fewer, or it
loses the single-delta fast path and falls back to walk-back / full-pack.

---

## 6. Graceful degradation for stock git

A **stock dumb clone** (a sha256-capable `git clone <url>`) never sees thin
deltas — they are not listed in `info/packs` and a dumb client cannot apply a
thin pack. Instead:

- Cloning a **`X.Y.0`** release uses its self-contained `pack-<sha256>.pack`
  directly (listed in `info/packs`).
- Cloning a **patch `X.Y.Z`** pulls the **minor-base full pack** (discovered via
  the minor release's `objects/info/alternates`) **plus** the patch's **new loose
  objects** from the central root `/objects/<xx>/<62-hex>` (all loose objects, for
  every release, live there). No thin packs needed; correctness is guaranteed by
  the loose objects.

The AOS-only thin deltas are a strict efficiency add-on that never breaks the
stock surface. See
[http-layout.md](./http-layout.md) for the dumb-HTTP compatibility contract.

### 6.1 The relative `info/alternates` file

Pack discovery and the release index both ride on a single
`objects/info/alternates` whose entries are **relative** paths to each
per-release `objects/` dir, newest→oldest:

```
../releases/1/1/0/objects/
../releases/1/0/0/objects/
```

Git resolves a relative alternate against the **repo's `objects/` URL**, so each
`../` strips the `objects` segment to reach the repo root — therefore the correct
depth is **one** `../`, not two. The file is **host-independent**: it bakes in no
hostname and is byte-identical across CDN, mirror, and `localhost`. The dumb-HTTP
walker reads `http-alternates` first and **falls back to `alternates`**, so a
single relative `info/alternates` works for **HTTP and local-FS** alike.

Because loose objects are **centralized** at the root `/objects/`, alternates no
longer carry object completeness — they serve **pack discovery** (where each
release's `objects/pack/` lives) and the **release index** (the enumerable list
of releases). Object correctness is the root `/objects/` store's job.

---

## 7. CURRENT: the bundle model being replaced

Today's code does **not** produce packs or deltas. It distributes the registry as
**git bundles** plus a `bundle-list.toml` manifest. This section documents the
as-is so the migration is explicit; none of it survives into the target (brief
§15).

**Producer (`apr bundle`).** `registry_ops::bundle`
(`crates/aos-package/src/registry_ops.rs:1718`) shells out to `git bundle create`:

- snapshot: `git bundle create <out>/<reg>-<tag>.bundle <tag>`
  (`registry_ops.rs:1748-1752`)
- delta: `git bundle create <out>/<reg>-<from>..<tag>.bundle <from>..<tag>`
  (`registry_ops.rs:1740-1745`)

There is **no manifest writer and no upload** — the `update_manifest` flag is
ignored (`_update_manifest`, `registry_ops.rs:1723`). The CLI surface is
`RegistryCommand::Bundle { output, tag, delta_from, update_manifest, registry }`
(`crates/aos-package/src/lib.rs:543`, dispatched at `lib.rs:1118`).

**Consumer.** `registry::bundle::fetch` (`bundle.rs:100`) downloads bundles, runs
`git bundle verify` for pack integrity + prerequisites (`bundle.rs:325-336`), and
`git bundle unbundle`s into the local bare repo (`bundle.rs:376-388`).
`pick_bundles` (`crates/aos-package/src/update.rs:292`, called from
`update.rs:207`) selects a minimal bundle set from a `BundleManifest` given the
host's `RegistryState` and `TrackingMode`.

**Why it's replaced.** Bundles carry refs and prerequisites and require a
parsed-by-consumer manifest. The target moves refs into signed tag objects and
the object index into git's native `info/packs` + `info/alternates`, leaving bare
`*.pack` files. The `BundleType::Snapshot`/delta distinction maps onto
full-pack/thin-delta; `pick_bundles` maps onto §4 client resolution.

| CURRENT (bundles) | TARGET (packs/deltas) |
|---|---|
| `git bundle create <tag>` | `git pack-objects --revs` (full, non-thin) |
| `git bundle create <from>..<tag>` | `git pack-objects --revs --thin` (delta) |
| `git bundle verify` + `unbundle` | `git index-pack --fix-thin` |
| `bundle-list.toml` manifest | `info/packs` + `info/alternates` (git-native) |
| `pick_bundles` over manifest | §4 client resolution over the §3 graph |
| `creation_token` ordering | semver + git ancestry |

---

## 8. TARGET: pack generation (producer)

All generation is plain `git pack-objects` reading a revision list on stdin; no
bundles, no smart-HTTP server.

**Write layout.** The producer writes **loose objects to the central root
`/objects/`** (every release's loose objects land there, never under
`/releases/`). Packs go under each release's pack-only
`/releases/<M>/<m>/<patch...>/objects/pack/`, which holds `info/packs`,
`pack/pack-<sha256>.pack(.idx)`, and `pack/delta-<from>.pack` — and **no** loose
`<xx>/<..>` objects and **no** per-release `info/alternates`.

### 8.1 Deltas (thin)

```sh
# objects in <to> not in <from>; deltas MAY reference <from>'s objects
printf '%s\n^%s\n' "<to-commit>" "<from-commit>" \
  | git pack-objects --revs --thin --stdout \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 \
      > delta-<from-semver>.pack
```

`--thin` lets the pack delta-encode new objects against objects in `<from>` that
are **not** included in the pack — making it small, at the cost of being
incomplete until the client supplies the base. `--revs` with the `^<from>`
exclusion is what selects “objects in `<to>` not in `<from>`”.

### 8.2 Full packs (non-thin)

```sh
# self-contained pack over the release commit's full closure
echo "<release-commit>" \
  | git pack-objects --revs --no-reuse-object --no-reuse-delta \
        --window=350 --depth=50 --threads=0 --compression=0 \
        pack/pack
# → pack/pack-<sha256>.pack + pack/pack-<sha256>.idx
```

A full pack is built **without** `--thin`, so it references nothing outside
itself. `--compression=0` keeps the pack git-valid while leaving the bytes
uncompressed so the zstd trick ([§9](#9-target-the-zstd-trick)) can entropy-code
the whole stream. Emit it directly as `pack-<sha256>.pack` (+ `.idx`) into the
release's `objects/pack/` and add it to `objects/info/packs`.

### 8.3 Client completion

Thin deltas ship as `.pack` (or `.pack.zst`) **only** — no `.idx`. The client
builds the index and stitches in the base while indexing:

```sh
git index-pack --fix-thin --stdin < delta-<from-semver>.pack
# (with the <from> base already present locally; --fix-thin appends the
#  referenced base objects so the resulting pack is self-contained + indexed)
```

### 8.4 Expensive-producer tuning

The producer deliberately spends CPU so consumers don't have to:

| Flag | Purpose | Note |
|---|---|---|
| `--no-reuse-object` | recompress every object from scratch | ignore prior pack encodings |
| `--no-reuse-delta` | recompute every delta from scratch | find better bases than git's cache |
| `--window=350` | how many candidate objects to compare for delta bases | **the free lever** — large is fine, producer-side cost only |
| `--depth=50` | max delta chain length | **moderate / capped** — deep chains cost the **consumer** CPU to reconstruct |
| `--threads=0` | use all cores | producer-side only |

> **Cap depth, not window.** Window is producer-only effort; depth directly taxes
> consumer reconstruction. Keep `--window` large and `--depth` moderate. The
> producer **may also try multiple delta bases** for a release and ship the
> smallest resulting pack.

---

## 9. TARGET: the zstd trick

Git's pack format **hard-codes zlib per object**, so naively running `zstd` over a
normally-compressed (`--compression=9`) pack is near-useless — the bytes are
already DEFLATEd and won't compress further. The working trick decouples git's
**delta encoding** from its **entropy coding**:

```sh
# 1) pack with delta encoding but NO entropy coding (level 0 = "stored",
#    valid zlib framing, but git's delta encoding is STILL applied)
printf '%s\n^%s\n' "<to>" "<from>" \
  | git pack-objects --revs --thin --stdout --compression=0 \
      --no-reuse-object --no-reuse-delta --window=350 --depth=50 --threads=0 \
      > delta-<from>.pack

# 2) let zstd do the entropy coding over the delta-encoded stream
zstd --ultra -22 --long=27 delta-<from>.pack -o delta-<from>.pack.zst
```

- `--compression=0` keeps the pack **git-valid** (proper zlib framing) while
  emitting *stored* (uncompressed) object payloads — git's inter-object **delta
  encoding is preserved**.
- `zstd --ultra -22 --long=27` then entropy-codes the whole delta-encoded `.pack`,
  beating zlib-9 because it operates over the full stream with a large window
  instead of zlib's per-object DEFLATE.

**Serve `.pack.zst`. The client reverses it before indexing:**

```sh
zstd -d < delta-<from>.pack.zst | git index-pack --fix-thin --stdin
```

The intermediate `.pack` is always valid git, so a client that can't or won't
handle `.zst` can fetch the plain `.pack` (or fall back to loose objects).

> **Optional: trained dictionary.** A zstd **trained dictionary** across a release
> line's many small delta packs is a further win (the small packs share a lot of
> structure). Whether to ship a per-release-line dictionary is an
> [open question](../plans/registry/open-questions.md) (brief §16.2).

### 9.1 What ships per release

| Release class | `pack-<sha>.pack` + `.idx` | `delta-<base>.pack[.zst]` (no `.idx`) | In `info/packs`? |
|---|---|---|---|
| `X.0.0` major | yes | `delta-<(X-1).0.0>` | full pack only |
| `X.Y.0` minor | yes | `delta-<X.(Y-1).0>`, `delta-<X.0.0>` | full pack only |
| `X.Y.Z` patch | **no** | `delta-<X.Y.(Z-1..3)>`, `delta-<X.Y.0>` | none (deltas never listed) |

The `.idx` is shipped **only** for self-contained full packs. Thin delta packs
are `.pack[.zst]` only; the client's `--fix-thin` builds their index. Both full
packs and thin deltas are produced with `--compression=0` so the
[zstd trick](#9-target-the-zstd-trick) can entropy-code the delta-encoded stream.

---

## 10. End-to-end summary

```
PRODUCER (pays once, expensively)              CONSUMER (cheap, every host)
┌──────────────────────────────────┐          ┌────────────────────────────────────┐
│ commit metadata tree             │          │ resolve C → T (§4)                  │
│ tag + sign release (semver)      │          │  prefer retained-base delta         │
│ pack-objects:                    │   HTTP   │  else walk back / full pack         │
│  full   (--revs, non-thin)       │  ──────▶ │  else loose from root /objects/     │
│  deltas (--revs --thin,          │   .pack  │ fetch .pack.zst                     │
│          --compression=0)        │   .zst   │  zstd -d | index-pack --fix-thin    │
│ zstd --ultra -22 the .pack       │          │ retain X.0.0 / X.Y.0 / X.Y.Z (§5)   │
│ write info/packs + info/alternates│          │ verify signed tag chain (separate)  │
└──────────────────────────────────┘          └────────────────────────────────────┘
```

For the full producer pipeline (commit → sign → pack/delta/zstd →
`update-server-info` → advance partitions → upload) see
[publishing.md](./publishing.md). For where these files live on the origin and
their CDN TTLs see [http-layout.md](./http-layout.md). For how a client picks a
release (bucket → channel tag → semver tag) before it ever resolves a pack, see
[versioning-and-channels.md](./versioning-and-channels.md). For the signature
chain that authenticates the release a pack reconstructs see
[signing-and-trust.md](./signing-and-trust.md).
