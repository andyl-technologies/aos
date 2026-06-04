# Workstream 01 — sha256 Bare Repo & Dumb-HTTP Object Store

> **Status:** Plan (target). Grounded in
> [`design-brief.md`](./design-brief.md) §4, §8, §12 (authoritative for target
> intent). Current-code citations use `path:line` against the tree at the time of
> writing.
>
> **Scope of this workstream:** stand up the *foundation layer* — a **bare git
> repository in sha256 object format**, published as static files over **dumb
> HTTP**. This is the substrate that every later workstream rides on:
> [WS-02 packs/deltas](./workstream-02-pack-delta-pipeline.md),
> [WS-03 channels/rollouts](./workstream-03-channels-rollouts.md),
> [WS-04 signing/trust](./workstream-04-signing-trust.md), and
> [WS-05 consumer](./workstream-05-consumer.md). This workstream **owns** the
> object/ref topology, `HEAD`, `info/refs`, `update-server-info`,
> `objects/info/alternates`, the per-release pack-only dirs, and the
> stock-git dumb-HTTP compatibility surface. It does **not** own pack/delta
> generation, channel partition tags, or signature verification (those are
> WS-02/03/04 respectively, and only referenced here).

**Related reference docs (target state):**
[architecture](../../registry/architecture.md) ·
[http-layout](../../registry/http-layout.md) ·
[current-state](../../registry/current-state.md) ·
[versioning-and-channels](../../registry/versioning-and-channels.md) ·
[packs-and-deltas](../../registry/packs-and-deltas.md) ·
[signing-and-trust](../../registry/signing-and-trust.md) ·
[publishing](../../registry/publishing.md) ·
[nix-cache-compatibility](../../registry/nix-cache-compatibility.md)

**Sibling plans:**
[plan README](./README.md) ·
[design-brief](./design-brief.md) ·
[gap-analysis](./gap-analysis.md) ·
[WS-02 pack/delta](./workstream-02-pack-delta-pipeline.md) ·
[WS-03 channels/rollouts](./workstream-03-channels-rollouts.md) ·
[WS-04 signing/trust](./workstream-04-signing-trust.md) ·
[WS-05 consumer](./workstream-05-consumer.md) ·
[open-questions](./open-questions.md)

---

## 1. Goal & success criteria

Build the object-store layer so that:

1. A registry is a **bare git repo created with `git init --bare
   --object-format=sha256`** — every object id is a 64-hex-char sha256.
2. The repo is served verbatim as static files and a **stock `git clone
   <url>`** (with a sha256-capable git) works: `HEAD`, `info/refs`, loose
   objects, and conventionally-named full packs are all in place.
3. **All loose objects are centralized at the root `/objects/`** under
   `objects/<xx>/<62-hex>` — every release's loose objects live there, and that
   single store is the guaranteed completeness fallback. The per-release
   `/release/*/objects/` dirs are **pack-only**.
4. The per-release pack-only dirs are stitched in via a **relative**
   **`objects/info/alternates`** (newest → oldest), which doubles as the full
   release index and as **pack discovery** (packs are a pure efficiency layer,
   WS-02). The file is **host-independent** (byte-identical across CDN, mirror,
   and localhost).
5. A single producer step (the publish pipeline; WS-02/03 own the full flow)
   regenerates `info/refs` + `objects/info/packs` + `HEAD` via
   **`git update-server-info`** and rewrites `objects/info/alternates` on every
   publish.

**Success = a CI test** that builds a multi-release repo, serves the directory
over a trivial static HTTP server, and `git clone`s it with stock git into a
byte-identical working tree — plus an AOS-side fetch that discovers per-release
packs through the relative `info/alternates`.

**Out of scope here:** thin/full pack and zstd generation (WS-02), the 256
channel partition tags and frontier branch head (WS-03), tag signing and
name-binding verification (WS-04), consumer delta-walk/retention (WS-05). This
doc references their *hooks* but does not implement them.

---

## 2. CURRENT vs TARGET

### 2.1 CURRENT (as-is code)

| Concern | Today | Citation |
|---|---|---|
| Repo init | `git init` (non-bare, **sha1**, default format) | `registry_ops.rs:438` |
| Bundle scratch repo | `git init --bare` (sha1) | `bundle.rs:359`, `git.rs:150` |
| Object format | sha1 implicit everywhere; no `--object-format` flag anywhere | `grep --object-format` → none |
| Distribution | git **bundles** + `bundle-list.toml` (consumer-parsed) | `registry/bundle.rs` |
| Object store layout | single flat `.git/objects`; no per-release dirs, no `info/alternates` | — |
| Dumb-HTTP surface | none generated (`update-server-info` not called anywhere) | `grep update-server-info` → none |
| Registry root | a `registry.toml` (`RegistryRootConfig`) parsed at repo root | `types.rs:565-573`, `registry_ops.rs:391-402` |
| Versions | calendar tags ordered by `creation_token` | `types.rs:259` (`last_creation_token`), `state.rs version_to_token` |

The current registry is **content** (nested package TOMLs + `closures/<hash>`)
shipped as **git bundles**. `PackageMeta` (`types.rs:43-77`) is the in-memory
projection; `RegistryRootConfig`/`CacheEntry` (`types.rs:567`, `types.rs:585`)
read a root `registry.toml` for mirror/cache URLs. None of that is the *target*
transport. See [current-state](../../registry/current-state.md) for the full
as-is.

### 2.2 TARGET (this workstream)

| Concern | Target | Brief |
|---|---|---|
| Repo init | `git init --bare --object-format=sha256` | §8 |
| Object id | 64-hex sha256; loose path `objects/<xx>/<62-hex>` | §8 |
| Distribution | static files over dumb HTTP (no bundles) | §3, §10 |
| Loose objects | **centralized at root `/objects/`**; per-release dirs are pack-only | §8 |
| Pack discovery / release index | relative `objects/info/alternates`, newest → oldest | §4, §8 |
| Dumb-HTTP surface | `HEAD` + `info/refs` + `objects/info/packs` (via `update-server-info`) | §8, §12 |
| Loose-object guarantee | **all** loose objects live at root `/objects/`; packs are efficiency only | §8 |
| Removed | `registry.toml` root, `bundle-list.toml`, git bundles, `creation_token` | §15 |

> **Removed (do not reintroduce — brief §15):** `registry.toml` as a registry
> root, `bundle-list.toml`, git **bundles**, `[latest]`/`[components]`/
> `[capabilities]`, percentage rollouts, `creation_token`/calendar versioning,
> by-hash `[[bundles]]`/`[[deltas]]`. The cache/NAR-substituter location is
> **client-side configuration** (the consumer's local registry config) or the
> origin itself — it is **not** advertised in signed tags and **not** a file at
> the repo root. Signed tags carry **no structured payload**: a signed tag is a
> pure signed pointer (standard git tag fields + Ed25519 signature + optional
> freeform message), so there is no tag-embedded `[[caches]]` (WS-04).
> `RegistryRootConfig` (`types.rs:567`) is retired by WS-04; this workstream
> only stops *writing* it.

---

## 3. Target HTTP / object layout (canonical)

This is the canonical layout from brief §4 — reproduced verbatim because this
workstream is responsible for producing every path under `/objects/**`,
`/release/**`, `HEAD`, and `info/refs`. (`/channel/**` is shown for context but
is owned by [WS-03](./workstream-03-channels-rollouts.md).)

```
/                                  ← bare git repo root (dumb HTTP)
  HEAD                             ← "ref: refs/heads/<default-channel>" (e.g. stable)   [low TTL]
  info/refs                        ← update-server-info: refs/heads/<channels> + refs/tags/<semvers> [low TTL]
  objects/
    info/packs                     ← lists self-contained pack-<sha>.pack only           [low TTL]
    info/alternates                ← relative "../release/*/objects/" dirs, newest→oldest [low TTL]
                                       (pack discovery + the full release index;
                                        host-independent, byte-identical everywhere)
    <xx>/<62-hex>                  ← ALL loose objects (every release), sha256 2/62 split [immutable, high TTL]
  channel/                         ← OWNED BY WS-03 (256 signed partition tags)
    <name>/
      00 .. ff
  release/
    <major>/<minor>/<patch[-prerelease][+build]>/                                        [long TTL, immutable]
      objects/                     ← PACK-ONLY (no loose <xx>/<..>, no info/alternates)
        info/packs
        pack/pack-<sha256>.pack (+ .idx)     ← self-contained "full" pack (WS-02)
        pack/delta-<from-semver>.pack         ← THIN deltas (WS-02); NOT in info/packs
```

### 3.1 Release-path mapping rule

A release `<major>.<minor>.<patch[-prerelease][+build]>` maps to
`/release/<major>/<minor>/<third-segment>/objects/` where the **third segment is
everything after `major.minor`** (brief §7):

| Semver | Release object dir |
|---|---|
| `1.0.0` | `/release/1/0/0/objects/` |
| `1.1.2` | `/release/1/1/2/objects/` |
| `1.1.0-alpha.1` | `/release/1/1/0-alpha.1/objects/` |
| `1.0.0-beta+exp.sha.5114f85` | `/release/1/0/0-beta+exp.sha.5114f85/objects/` |

Versions are **semver, no `v` prefix** (brief §7). Note the current code stores
calendar tags like `v2026.03` (`types.rs:909`, `types.rs:932`) — that scheme and
the `v` prefix are gone in the target.

### 3.2 CDN TTL policy (brief §4)

| Path glob | TTL | Why |
|---|---|---|
| `/channel/**` | **low** (MUST) | fast rollout updates |
| `/objects/info/**` and per-release `objects/info/**` | **low** (MUST) | `packs`, `alternates`, `info/refs`, `HEAD` change on publish |
| `/release/**` (objects, packs) | **long** (MAY) | releases immutable after publish |
| `/objects/<xx>/**` (loose), packs | **very high** (MAY) | content-addressed, immutable |

This workstream only *emits* the files; mapping globs to a CDN config is a
deployment concern documented in [publishing](../../registry/publishing.md).

---

## 4. Implementation steps

The work decomposes into a small set of object-store primitives, packaged as a
new module `crates/aos-package/src/registry/objectstore.rs` plus targeted edits
to existing init/commit paths.

### Step 1 — sha256 bare-repo init

**TARGET:** create the canonical registry as a bare sha256 repo.

```sh
git init --bare --object-format=sha256 <repo-dir>
# HEAD must point at the default channel branch, NOT master/main:
git --git-dir=<repo-dir> symbolic-ref HEAD refs/heads/stable
```

- `git init` at `registry_ops.rs:438` (non-bare, sha1) is replaced by the bare
  sha256 form for the **canonical published repo**. (A working clone the
  publisher edits in may stay non-bare; the *published* artifact is bare.)
- The bundle scratch-repo inits at `bundle.rs:359` and `git.rs:150` are part of
  the **retired bundle path** (brief §15) and are removed by WS-02, not edited
  here.
- Add a guard: refuse to operate on a repo whose `git rev-parse
  --show-object-format` is not `sha256` (prevents silently mixing sha1 history).

> **Open question (brief §16.1):** stock sha256 dumb-HTTP clone must be tested
> against target git client versions — there is **no capability negotiation** in
> the dumb protocol, so the client git must natively support sha256. Tracked in
> [open-questions](./open-questions.md).

### Step 2 — loose objects to root; per-release pack-only dirs

All loose objects are **centralized at the root `/objects/`**. When a release
commit is finalized, its **new loose objects** are written to the root
`/objects/<xx>/<62-hex>` (every release shares that one store). The
`/release/<…>/objects/` dir is **pack-only**: it holds `info/packs` and the
release's `pack/pack-<sha256>.pack(.idx)` + `pack/delta-<from>.pack` (WS-02),
and contains **no loose `<xx>/<..>` objects** and **no per-release
`info/alternates`**.

The producer therefore:

- writes the release's new loose objects (objects in `<to>` not in `<from>`, the
  same revset WS-02 uses for deltas) into the **root** `/objects/`;
- writes that release's packs under `/release/<…>/objects/pack/`.

The invariant is: **every loose object lives at the root `/objects/`** (a single
complete loose store), while each release dir holds only that release's packs.
The relative root `info/alternates` (Step 5) enumerates the pack-only release
dirs for pack discovery and as the release index.

### Step 3 — loose-object completeness guarantee

Brief §8: **ALL objects exist loose**. Even when WS-02 emits packs, the
producer must guarantee a loose copy of every object exists somewhere in the
union store. Implementation:

```sh
# After packing, explode any pack-only objects back to loose form so dumb
# clients (which cannot apply thin packs, and may not fetch full packs) always
# resolve via loose objects:
git --git-dir=<repo> unpack-objects -r < some.pack   # or keep loose alongside
```

The completeness check (a test, §6) walks `info/refs` tips and asserts every
reachable object is retrievable **loose** from the root `/objects/` store.

### Step 4 — generate dumb-HTTP shim (`HEAD` + `info/refs`)

**TARGET:** on every publish, regenerate the dumb-HTTP metadata.

```sh
git --git-dir=<repo> update-server-info
```

`update-server-info` writes `info/refs` (all `refs/heads/*` + `refs/tags/*`,
each `\t`-separated `<oid>\t<ref>`) and `objects/info/packs`. The publisher
**must** call it after refs change (new release tags, advanced frontier branch
head) and after packs change (WS-02). `HEAD` is set once by Step 1's
`symbolic-ref` and only changes when the default channel changes.

There is **no current call to `update-server-info`** anywhere
(`grep` → none) — this is net-new.

### Step 5 — write `objects/info/alternates`

**TARGET:** loose objects are centralized at the root, so `info/alternates` is
not for object completeness — it is the glue for **pack discovery** and the
**release index**.

- Content: one **relative** path per line, each pointing at a
  `/release/<…>/objects/` directory, ordered **newest → oldest** by semver
  precedence. Git resolves relative alternates against the repo's `objects/`
  URL, so each `../` strips the `objects` segment to reach the repo root —
  therefore the correct depth is **one `../`** (not two):

```
# objects/info/alternates  (newest → oldest)
../release/1/2/0/objects/
../release/1/1/2/objects/
../release/1/1/0/objects/
../release/1/0/0/objects/
```

- The file is **host-independent**: byte-identical across CDN, mirror, and
  localhost, because the paths are relative and no hostname is baked in.
- Git's dumb-HTTP walker reads `objects/info/http-alternates` first then falls
  back to `objects/info/alternates`, so a single **relative** `info/alternates`
  works for **both HTTP and local-FS** access — no separate `http-alternates`
  file is needed. (Loose objects live at the root, so these alternates serve
  pack discovery + the release index, not object completeness.)
- This file **doubles as the full release index** — a consumer (or human) reads
  it to enumerate every published release without a separate manifest. This is
  what replaces the old `bundle-list.toml` (brief §15).
- The per-release dirs are **pack-only**, so there is **no** per-release
  `info/alternates`; the single root `info/alternates` enumerates them all.

### Step 6 — atomic publish ordering

To keep the served repo always-consistent for concurrent clients, the publisher
writes in **content-before-pointer** order:

```
1. write new loose objects to root /objects/; write packs under /release/<new>/objects/pack/  (immutable, safe to publish early)
2. write/refresh per-release objects/info/packs
3. git update-server-info        → root info/refs, objects/info/packs
4. rewrite root objects/info/alternates (prepend new release)
5. (WS-03) advance channel partition tags + frontier branch head
6. upload, then bust low-TTL caches for info/** and channel/**
```

Objects are immutable and content-addressed, so a client that races step 3
against step 4 either sees the old ref set (and old alternates) or the new — it
never sees a ref pointing at an object it cannot fetch, **as long as objects are
uploaded before refs**. The full pipeline (steps 5–6) is owned by
[publishing](../../registry/publishing.md) / WS-02/03; this workstream owns
steps 1–4.

---

## 5. Stock-git dumb-HTTP compatibility surface

This workstream is responsible for the **transparent-clone** property (brief
§12). A stock dumb-HTTP git client (sha256-capable) must be able to
`git clone <url>` and check out a channel branch or release tag.

| Requirement (brief §12) | What this workstream emits |
|---|---|
| Valid bare dumb-HTTP repo | `HEAD`, `info/refs`, `objects/info/packs` via `update-server-info` |
| `HEAD` = default channel | `symbolic-ref HEAD refs/heads/<default-channel>` (e.g. `stable`) |
| Channels are branches | `refs/heads/<channel>` present in `info/refs` (head set by WS-03) |
| Releases are tags | `refs/tags/<semver>` present in `info/refs` (signed by WS-04) |
| Full packs are stock-usable | named `pack-<sha256>.pack` (+ `.idx`), **listed in `objects/info/packs`** (WS-02 emits; this WS lists) |
| Thin deltas hidden from stock | `delta-<semver>.pack` **NOT** in `info/packs` (a stock dumb client can't apply a thin pack) |
| Loose objects guarantee correctness | every reachable object retrievable loose from the root `/objects/` store |
| Relative pack discovery | `objects/info/alternates` (one `../`, host-independent) lists pack-only release dirs |
| sha256 transport | `--object-format=sha256`; **no capability negotiation** in dumb protocol — client git must support sha256 |

**Graceful degradation (brief §9, §12):** a stock dumb clone of a *patch*
release pulls the **minor-base full pack** (reached via the relative
`info/alternates`) plus the loose objects from the root `/objects/` store — no
thin packs needed. The 256 channel partition tags live **outside** the ref
namespace at `/channel/*` (WS-03), so they never pollute a stock client's
`refs/tags/*`.

```
stock git clone <url>
  → GET HEAD                       (ref: refs/heads/stable)
  → GET info/refs                  (refs/heads/* + refs/tags/*)
  → GET objects/info/packs         (pack-<sha>.pack list)
  → GET objects/info/alternates    (relative, one "../")
       → follow ../release/X/Y/0/objects/  (full pack, pack-only dir)
  → GET objects/<xx>/<62-hex>      (loose objects from the root store)
  → checkout works.  delta-*.pack never touched.
```

---

## 6. Tests

All tests must use **AOS-built tooling** per CLAUDE.md (`pkgs.git`, no nixpkgs;
no host tools). The static HTTP server should be an AOS-built minimal server
(e.g. reuse the cache server crate or `pkgs.socat`/an AOS http server) — never a
host binary.

### 6.1 Eval / unit (Rust, `crates/aos-package`)

| Test | Asserts |
|---|---|
| `objectstore::release_path_mapping` | semver → `/release/M/m/<third>/objects/` for the §3.1 table (incl. `-prerelease+build`) |
| `objectstore::alternates_ordering` | release dirs emitted **newest → oldest** by semver precedence |
| `objectstore::alternates_relative` | every line is a relative path with **one `../`** resolving to a real release `objects/` dir; host-independent (no hostname) |
| `objectstore::object_format_guard` | refuse a repo whose `rev-parse --show-object-format` ≠ `sha256` |
| `objectstore::loose_path_split` | sha256 oid → `<first-2>/<last-62>` loose path |

### 6.2 Integration (build → serve → clone)

A scripted test (CI check, analogous to `nix-build -A checks.eval`):

1. `git init --bare --object-format=sha256` a scratch repo; create 4 releases
   (`1.0.0`, `1.1.0`, `1.1.2`, `1.2.0`) with distinct file trees; tag each.
2. Place each release's new loose objects under the root `/objects/`; write each
   release's packs under `/release/<…>/objects/pack/` with per-release
   `info/packs`; write the root `info/{packs,alternates}` (relative, one `../`);
   run `update-server-info`; set `HEAD → refs/heads/stable`.
3. Serve the directory with an AOS static HTTP server.
4. **Stock clone:** `git clone <url> out` with sha256-capable git; assert the
   checkout of `refs/heads/stable` and of each `refs/tags/<semver>` matches the
   source tree byte-for-byte.
5. **Pack discovery via alternates:** assert the relative `info/alternates`
   resolves each `../release/<…>/objects/` pack-only dir (one `../`), and that
   the file is byte-identical when served from a different host/CDN prefix.
6. **Loose-completeness:** with `objects/info/packs` emptied, assert a dumb
   fetch still completes via the root `/objects/` loose store only.

### 6.3 Negative tests

- A repo missing `info/refs` (no `update-server-info`) fails a dumb clone —
  asserts the shim is actually required and that we generate it.
- `delta-<semver>.pack` present but **absent from `info/packs`** → a stock dumb
  clone ignores it and still succeeds (proves thin packs don't break stock).

---

## 7. New modules & commands

### 7.1 New module

`crates/aos-package/src/registry/objectstore.rs` — owns:

- `fn init_bare_sha256(dir, default_channel) -> Result<()>` — `git init --bare
  --object-format=sha256` + `symbolic-ref HEAD`.
- `fn release_object_dir(version: &semver::Version) -> PathBuf` — §3.1 mapping.
- `fn write_release_objects(repo, version, revspec)` — Step 2: loose objects to
  root `/objects/`, packs to `/release/<…>/objects/pack/`.
- `fn ensure_loose_completeness(repo)` — Step 3.
- `fn refresh_server_info(repo)` — wraps `git update-server-info` (Step 4).
- `fn write_alternates(repo, releases_newest_first)` — Step 5: relative
  `objects/info/alternates`, one `../`, host-independent.
- `fn assert_sha256(repo)` — object-format guard.

This sits **below** the pack/delta module (WS-02) and the channel/tag module
(WS-03), which call into it. It reuses the existing `git(dir, args)` helper
pattern (`registry_ops.rs:79`) and the `git_allow_fail` variant
(`registry_ops.rs:94`) for the format guard.

### 7.2 Command surface

No new top-level `apr` subcommand is introduced *by this workstream alone* — the
object-store primitives are invoked by the publish pipeline. Per
[design-brief §16.4](./design-brief.md) (open question), a single
`apr release` / `apr publish` may wrap the whole pipeline (commit → tag/sign →
pack/delta/zstd → `update-server-info` → advance partitions → upload); this
workstream contributes the `update-server-info` + `info/alternates` steps to
that command. The existing `apr bundle` (= `git bundle create`) and the
`bundle.rs` writer are **removed** as part of retiring bundles (brief §15, done
in WS-02).

`apr` also gains an internal/debug verb (or `apr doctor`-style check) that runs
`assert_sha256` + the loose-completeness walk against a published repo, reusing
§6's logic for operator validation.

---

## 8. Risks & open items

1. **Per-release object placement mechanic (§4 Step 2):** `GIT_OBJECT_DIRECTORY`
   redirection vs post-hoc loose-object move. Redirection is cleaner but must not
   let git GC/repack relocate objects out of their release dir. Decide and lock
   in WS-02 (since packing interacts with placement).
2. **sha256 client support (brief §16.1):** no dumb-protocol capability
   negotiation; the consumer's git must support sha256. Needs a tested
   floor-version matrix → [open-questions](./open-questions.md).
3. **`info/alternates` depth & probe cost:** as the release count grows, the
   newest→oldest list grows; a client may probe many pack-only dirs for an old
   release's pack. Newest-first ordering and the root loose-object store
   mitigate (loose objects are always one fetch from the root), but very long
   histories may want periodic root-level repacking (efficiency only; never
   correctness).
4. **Single relative `info/alternates` (brief §16.6):** the dumb-HTTP walker
   reads `http-alternates` first then falls back to `alternates`, so a single
   **relative** `info/alternates` (one `../`, host-independent) covers both HTTP
   and local-FS access — no separate `http-alternates` file is maintained.
5. **Retiring `RegistryRootConfig`/`registry.toml` (`types.rs:567`):** the
   cache/NAR-substituter location becomes **client-side** config (or the origin
   itself) — it is **not** moved into signed tags, which carry no structured
   payload (WS-04). This WS stops *writing* `registry.toml`
   (`registry_ops.rs:443-450`); WS-04 removes the type. Coordinate so no path
   reads a now-absent root config.
6. **Atomicity across a CDN (§4 Step 6):** content-before-pointer ordering holds
   at the origin, but CDN edge caches with mixed TTLs can briefly serve a new
   `info/refs` with a stale `info/alternates`. Loose objects + immutable content
   make this self-healing, but cache-bust ordering must be specified in
   [publishing](../../registry/publishing.md).

---

## 9. Definition of done

- [ ] `objectstore.rs` implements all §7.1 functions; the `git init` path
      (`registry_ops.rs:438`) emits a **sha256 bare** canonical repo with
      `HEAD → refs/heads/<default-channel>`.
- [ ] Publish regenerates `info/refs` + `objects/info/packs` via
      `update-server-info`, and rewrites the relative `objects/info/alternates`
      (one `../`, newest → oldest) on every release.
- [ ] Every reachable object is retrievable **loose** from the root `/objects/`
      store (completeness guarantee); all loose objects are centralized there.
- [ ] Per-release dirs exist at `/release/<M>/<m>/<third>/objects/` per §3.1 and
      are **pack-only** (`info/packs` + `pack/`; no loose objects, no
      per-release `info/alternates`).
- [ ] §6 eval tests + the serve→stock-clone integration test pass with
      AOS-built git over a static HTTP server.
- [ ] No `registry.toml` root, no `bundle-list.toml`, no git bundles emitted
      (brief §15); thin `delta-*.pack`s are absent from `info/packs`.
