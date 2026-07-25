# Packs & Deltas

> **Scope:** the binary-efficiency layer of the AOS registry — how the git
> object store (the package metadata *tree*) is packaged for transport. Covers
> the **full pack** anchored at every `X.Y.0` release, the **guaranteed, walkable
> thin-delta graph** the producer commits to, **client resolution** (which delta
> or pack to fetch) and **client retention** (which object trees to keep), the
> libgit2 full-pack generation, pure-Rust thin-pack generation, local pack
> indexing, and **zstd** compression for thin-delta transport.
>
> This is the transport that carries the registry's **git objects** (the
> package-TOML tree) over dumb HTTP. It is **not** the NAR/blob substitution path
> (see [nix-cache-compatibility.md](./nix-cache-compatibility.md)).
>
> **Implementation status:** `registry::pack` implements the producer pack
> primitives, and `registry::fetch` implements the consumer delta/full/fallback
> resolution layer described here. The reference still uses **TARGET** on design
> sections where it is explaining the protocol contract rather than a single
> Rust function.

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
| **Thin delta pack** | `delta-<from-semver>.pack.zst` | **AOS only** (not listed in `info/packs`) | needs base; cheapest |

The design philosophy is **asymmetric cost**: *make publishing as expensive as
possible so consumption is as cheap as possible*. The producer pays once (large
delta windows, multiple base attempts, `zstd --ultra -22`); every consumer
benefits with a small, fast fetch. Loose objects guarantee that even a stock
`git clone` from a sha256-capable client always succeeds, with packs and deltas
as pure speed layers on top.

> **No separate ref-bearing transport envelope.** The ref namespace is signed
> tag objects, so the transport payload is bare full-pack `*.pack`/`*.idx` files,
> thin-delta `*.pack.zst` files, plus the root loose-object store.

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
- The `.idx` **is** shipped for full packs so stock dumb Git can consume the pack.
  AOS clients regenerate and verify the index locally when they fetch the pack.
- A full pack is built **non-thin** — it references no objects outside itself.

Patch releases (`X.Y.Z`, `Z>0`) deliberately ship **no full pack**; a stock
client reconstructs them from the minor-base full pack plus the patch's new loose
objects (from the central root `/objects/`, see
[§6](#6-graceful-degradation-for-stock-git)).

---

## 3. TARGET: the guaranteed delta graph

The producer **commits to producing exactly** the delta packs below for each
release class. Because the set is guaranteed, a client can *plan* a fetch knowing
which deltas will exist. All deltas are **thin** (`delta-<from-semver>.pack.zst`,
not listed in `info/packs`, decompressed and completed on the client).

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

## 7. CURRENT implementation status

`crates/aos-package/src/registry/pack.rs` implements the core pack primitives:

- release-kind classification and the guaranteed delta-base scheme;
- libgit2 full-pack generation plus producer-side `.idx` emission;
- pure-Rust thin-delta generation for the guaranteed delta graph;
- zstd compression/decompression wrappers for thin-delta transport;
- libgit2 pack indexing for full packs and completed thin packs.

`registry::objectstore` implements the complementary static-object layout:
sha256 object-format checks, release object-dir mapping, root loose-object path
validation, relative alternates, and `git update-server-info`.

`crates/aos-package/src/registry/fetch.rs` implements the consumer resolution
layer: retained-base delta selection, target-anchor full-pack fallback, and a
final `git fetch` fallback for the dumb-HTTP loose-object correctness floor.
Channel sync calls this resolver after the signed tag chain and semver floor
check succeed, then persists the `{X.0.0, X.Y.0, X.Y.Z}` retained set.

The producer pack helpers remain available as focused building blocks, and
`apr release` now uses them inside the ordered producer pipeline that signs the
release, writes packs/deltas, refreshes indexes, advances channels, and uploads
the static origin.

The production VM perf check is:

```sh
nix-build -A checks.vm.apm.registry-validation-pack-delta-perf
```

It reports `REGISTRY_PERF_METRIC` lines for full-pack generation, thin-delta
generation, zstd compression, and consumer reconstruction against a synthetic
multi-package sha256 registry. It passed on a remote KVM builder on 2026-06-08
with output
`/nix/store/c6lg01w5ks8f2h4ginav0wfdhlf12az9-aos-vm-test-apm-registry-validation-pack-delta-perf-0`
and the following serial-log metrics:

```text
REGISTRY_PERF_METRIC full_pack_bytes=11276
REGISTRY_PERF_METRIC full_pack_ns=86438382
REGISTRY_PERF_METRIC thin_delta_bytes=11295
REGISTRY_PERF_METRIC thin_delta_ns=49235341
REGISTRY_PERF_METRIC zstd_delta_bytes=7191
REGISTRY_PERF_METRIC zstd_ns=1748206
REGISTRY_PERF_METRIC reconstruct_ns=2568679
```

A lower-level opt-in Rust harness lives in
[`crates/aos-package/tests/registry_perf.rs`](../../crates/aos-package/tests/registry_perf.rs)
for local debugging and parameter experiments.

---

## 8. CURRENT: pack generation (producer)

Generation is libgit2-native for full packs and Rust-native for thin packs; no
separate transport envelope and no smart-HTTP server are involved.

**Write layout.** The producer writes **loose objects to the central root
`/objects/`** (every release's loose objects land there, never under
`/releases/`). Packs go under each release's pack-only
`/releases/<M>/<m>/<patch...>/objects/pack/`, which holds
`pack/pack-<sha256>.pack(.idx)` and `pack/delta-<from>.pack.zst` — and **no**
loose `<xx>/<..>` objects and **no** per-release `info/alternates`.

### 8.1 Deltas (thin)

`registry::thinpack` writes a thin pack equivalent to
`git pack-objects --thin` over `to ^from`: objects in `<to>` but not `<from>`,
with deltas allowed to reference base-release objects that are **not** included
in the pack. It tries whole-object, same-path, and bounded windowed delta-base
strategies, zstd-probes the candidates, and keeps the smallest transport result.
The artifact published by `apr release` is `delta-<from-semver>.pack.zst`.

### 8.2 Full packs (non-thin)

`registry::pack::full_pack` uses libgit2's `PackBuilder` over the release
commit's reachable object graph, then libgit2's `Indexer` writes
`pack-<sha256>.pack` plus `pack-<sha256>.idx`. A full pack is non-thin: it
references nothing outside itself. `apr release` emits it directly into the
release's `objects/pack/` and adds it to `objects/info/packs`.

### 8.3 Client completion

Thin deltas ship as `.pack.zst` **only** — no `.idx`. The client decompresses the
transport artifact, builds the index, and stitches in the base while indexing:

```sh
zstd -d delta-<from-semver>.pack.zst
# then index the resulting delta-<from-semver>.pack with libgit2's pack writer
# while the <from> base is already present locally.
```

### 8.4 Expensive-producer tuning

The old plan described literal `git pack-objects` tuning flags. In the libgit2
implementation those flags are no longer the public contract; the contract is the
artifact shape above plus producer-side effort to keep thin deltas small.

`registry::thinpack` keeps delta chains shallow enough for cheap local
reconstruction and spends producer CPU comparing candidate encodings. Future
tuning should adjust those Rust strategies directly instead of documenting
unimplemented `pack-objects` flags as current behavior.

---

## 9. CURRENT: thin-delta zstd transport

Git's pack format **hard-codes zlib per object**, so naively running `zstd` over
a normally-compressed pack is near-useless. The working trick still applies to
thin deltas: `registry::thinpack` emits stored zlib entries, equivalent to
`pack-objects --compression=0`, and `zstd --ultra -22 --long=27` entropy-codes
the whole delta-encoded stream.

- Stored zlib entries keep the pack **git-valid** (proper zlib framing) while
  emitting *stored* (uncompressed) object payloads — git's inter-object **delta
  encoding is preserved**.
- `zstd --ultra -22 --long=27` then entropy-codes the whole delta-encoded `.pack`,
  beating zlib-9 because it operates over the full stream with a large window
  instead of zlib's per-object DEFLATE.

**Serve `.pack.zst`. The client reverses it before indexing:**

```sh
zstd -d delta-<from>.pack.zst
# AOS then completes and indexes delta-<from>.pack with libgit2's pack writer.
```

The intermediate `.pack` is always valid git. The static origin currently serves
the compressed thin-delta transport form; clients that cannot handle it fall back
to a full pack or the loose-object floor.

> **Optional: trained dictionary.** A zstd **trained dictionary** across a release
> line's many small delta packs is a further win (the small packs share a lot of
> structure). Whether to ship a per-release-line dictionary is an
> [open question](../plans/registry/open-questions.md) (brief §16.2).

### 9.1 What ships per release

| Release class | `pack-<sha>.pack` + `.idx` | `delta-<base>.pack.zst` (no `.idx`) | In `info/packs`? |
|---|---|---|---|
| `X.0.0` major | yes | `delta-<(X-1).0.0>` | full pack only |
| `X.Y.0` minor | yes | `delta-<X.(Y-1).0>`, `delta-<X.0.0>` | full pack only |
| `X.Y.Z` patch | **no** | `delta-<X.Y.(Z-1..3)>`, `delta-<X.Y.0>` | none (deltas never listed) |

The `.idx` is shipped **only** for self-contained full packs, primarily for
stock dumb Git. Thin delta packs are `.pack.zst` only; the client's local pack
indexing builds their index. The `--compression=0`/zstd trick is current for thin
deltas; full packs are libgit2-generated plain `.pack` files.

---

## 10. End-to-end summary

```
PRODUCER (pays once, expensively)              CONSUMER (cheap, every host)
┌──────────────────────────────────┐          ┌────────────────────────────────────┐
│ commit metadata tree             │          │ resolve C → T (§4)                  │
│ tag + sign release (semver)      │          │  prefer retained-base delta         │
│ libgit2 full pack + .idx         │   HTTP   │  else walk back / full pack         │
│ thinpack delta + zstd            │  ──────▶ │  else loose from root /objects/     │
│                                  │   .pack  │ fetch .pack.zst                     │
│                                  │   .zst   │  zstd -d | local pack indexing      │
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
