# Workstream 01 — sha256 Bare Repo & Dumb-HTTP Object Store

> **Status:** Plan (target). Grounded in
> [`design-brief.md`](./design-brief.md) §4, §8, §12 (authoritative for target
> intent). Current-code citations use `path:line` against the tree at the time of
> writing.
>
> **As-built status note:** this workstream is now archival planning context. The
> object-store implementation has landed locally; use
> [`../../registry/current-state.md`](../../registry/current-state.md) and
> [`TODO.md`](./TODO.md) for current facts. Follow-up production validation is
> tracked in [`validation-runbook.md`](./validation-runbook.md).
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
   `/releases/*/objects/` dirs are **pack-only**.
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
| Repo init | `git init` (non-bare, **sha1**, default format) | `registry_ops.rs:438` (`create`, `fn` at :421) |
| Bundle scratch repo | `git init --bare` (sha1) | `bundle.rs:358` (`ensure_git_repo`, `fn` at :349), `git.rs:157` (`ensure_repo`, `fn` at :147) |
| Object format | sha1 implicit everywhere; no `--object-format` flag anywhere | `grep --object-format` → none |
| Distribution | git **bundles** + `bundle-list.toml` (consumer-parsed) | `registry/bundle.rs` |
| Object store layout | single flat `.git/objects`; no per-release dirs, no `info/alternates` | — |
| Dumb-HTTP surface | none generated (`update-server-info` not called anywhere) | `grep update-server-info` → none |
| Registry root | a `registry.toml` (`RegistryRootConfig`) parsed at repo root | `types.rs:564-570`, `registry_ops.rs:392-402` (`read_registry_toml`) |
| Versions | calendar tags ordered by `creation_token` | `types.rs:256` (`last_creation_token`), `registry/state.rs:131` (`version_to_token`) |

The current registry is **content** (nested package TOMLs + `closures/<hash>`)
shipped as **git bundles**. `PackageMeta` (`types.rs:44-74`) is the in-memory
projection; `RegistryRootConfig`/`CacheEntry` (`types.rs:564`, `types.rs:582`)
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
| Committed tree (not served) | root `registry.toml` (`[registry]` + `[[caches]]`, pubkey removed) + `keys.toml` + `packages/` + `closures/` + `.gitattributes` ([repo-layout.md](../../registry/repo-layout.md)) | §14 |
| Removed | the *signed-HTTP-root* `registry.toml`, `bundle-list.toml`, git bundles, `creation_token` | §15 |

Signed tags carry **no structured payload** (a signed tag is a pure signed
pointer — standard git tag fields + Ed25519 signature + optional freeform
message). The cache/NAR-substituter location lives in the committed git-repo-root
`registry.toml` `[[caches]]` (`RegistryRootConfig.caches: Vec<CacheEntry>`,
`types.rs:564-570`; `CacheEntry` at `types.rs:582`),
authenticated via the signed tag — **not** advertised in a signed tag, and not
*solely* client-side; the consumer's local `registries.d/<name>.toml` is an
optional override/supplement (HIGHER priority wins; brief §14). That git-repo-root
`registry.toml` is **kept** as a committed tree file (§3.3); only the intermediate
*signed-HTTP-root* `registry.toml` is removed (brief §15). The **signing pubkey**
(`RegistrySigningConfig.public_key`, `types.rs:594-596`, reached via the
`signing: Option<RegistrySigningConfig>` field of `RegistryRootConfig` at
`types.rs:569`) is removed from `registry.toml` (key trust moves to the new
committed `keys.toml` + client-side TOFU;
[repo-layout.md](../../registry/repo-layout.md) §2–§3).
Superseded concepts live only in
archival plan context and design-brief §15; use
[current-state](../../registry/current-state.md) and [TODO.md](./TODO.md) for
live status.

---

## 3. Target HTTP / object layout (canonical)

This is the canonical layout from brief §4 — reproduced verbatim because this
workstream is responsible for producing every path under `/objects/**`,
`/releases/**`, `HEAD`, and `info/refs`. (`/channels/**` is shown for context but
is owned by [WS-03](./workstream-03-channels-rollouts.md).)

```
/                                  ← bare git repo root (dumb HTTP)
  HEAD                             ← "ref: refs/heads/<default-channel>" (e.g. stable)   [low TTL]
  info/refs                        ← update-server-info: refs/heads/<channels> + refs/tags/<semvers> [low TTL]
  objects/
    info/packs                     ← lists self-contained pack-<sha>.pack only           [low TTL]
    info/alternates                ← relative "../releases/*/objects/" dirs, newest→oldest [low TTL]
                                       (pack discovery + the full release index;
                                        host-independent, byte-identical everywhere)
    <xx>/<62-hex>                  ← ALL loose objects (every release), sha256 2/62 split [immutable, high TTL]
  channels/                         ← OWNED BY WS-03 (256 signed partition tags)
    <name>/
      00 .. ff
  releases/
    <major>/<minor>/<patch[-prerelease][+build]>/                                        [long TTL, immutable]
      objects/                     ← PACK-ONLY (no loose <xx>/<..>, no info/alternates)
        info/packs
        pack/pack-<sha256>.pack (+ .idx)     ← self-contained "full" pack (WS-02)
        pack/delta-<from-semver>.pack         ← THIN deltas (WS-02); NOT in info/packs
```

### 3.1 Release-path mapping rule

A release `<major>.<minor>.<patch[-prerelease][+build]>` maps to
`/releases/<major>/<minor>/<third-segment>/objects/` where the **third segment is
everything after `major.minor`** (brief §7):

| Semver | Release object dir |
|---|---|
| `1.0.0` | `/releases/1/0/0/objects/` |
| `1.1.2` | `/releases/1/1/2/objects/` |
| `1.1.0-alpha.1` | `/releases/1/1/0-alpha.1/objects/` |
| `1.0.0-beta+exp.sha.5114f85` | `/releases/1/0/0-beta+exp.sha.5114f85/objects/` |

Versions are **semver, no `v` prefix** (brief §7) — modeled by `semver::Version`
(the existing `parse_tag_as_semver(tag: &str) -> Option<semver::Version>` at
`update.rs:456` already produces this type; there is no bespoke `Semver`/`FromSemver`
type in the repo). Note the current code stores calendar tags like `v2026.03`
(e.g. `cfg.tag = Some("v2026.03".into())` at `types.rs:902` and `:935`, and the
`version_to_token("v2026.02.3")` tests at `registry/state.rs:197-227`) — that
scheme and the `v` prefix are gone in the target.

### 3.2 CDN TTL policy (brief §4)

| Path glob | TTL | Why |
|---|---|---|
| `/channels/**` | **low** (MUST) | fast rollout updates |
| `/objects/info/**` and per-release `objects/info/**` | **low** (MUST) | `packs`, `alternates`, `info/refs`, `HEAD` change on publish |
| `/releases/**` (objects, packs) | **long** (MAY) | releases immutable after publish |
| `/objects/<xx>/**` (loose), packs | **very high** (MAY) | content-addressed, immutable |

This workstream only *emits* the files; mapping globs to a CDN config is a
deployment concern documented in [publishing](../../registry/publishing.md).

### 3.3 Committed git tree (vs. the served object store)

The layout above (§3) is the **served object store** — the dumb-HTTP encoding of
git objects (`/objects/**`, `/channels/**`, `/releases/**`, `HEAD`, `info/refs`).
It is **distinct** from the **committed git tree**: the files a commit *contains*,
what you'd see on `git checkout`. Those files are never served as literal HTTP
paths — they are encoded inside the git objects this workstream produces, and the
consumer reconstructs them after assembling objects (brief §14). The committed
tree is:

```
<repo root>/                          ← a commit's tree (what `git checkout` yields)
  registry.toml                       ← [registry] name/description + [[caches]] only (pubkey REMOVED)
  keys.toml                           ← trust roster: active signing key(s) + revoked list
  .gitattributes                      ← "closures/** -diff"
  packages/<first-letter>/<name>.toml ← per-package metadata, sharded by first letter
  closures/<hash>                     ← dependency adjacency list
```

The whole tree is authenticated transitively by the **signed tag**
(tag → commit → tree → file), so every file is signed-by-extension **without**
anything being placed in the tag (tags are pure pointers; brief §14). The full
structure, field semantics, and CURRENT-vs-TARGET deltas live in the reference
doc [repo-layout.md](../../registry/repo-layout.md) — this workstream only
*produces the objects* that encode this tree; it does not define the tree's
content.

> **Two `registry.toml` files, not the same thing (brief §14/§15).** The
> git-repo-**root** `registry.toml` above is a **committed tree file**
> (`RegistryRootConfig`, `types.rs:564-570`) — `[registry]` + `[[caches]]`, with
> the signing pubkey **removed** (drop the `signing: Option<RegistrySigningConfig>`
> field at `types.rs:569`; a key in a file authenticated by that key is
> circular for bootstrap; trust lives in `keys.toml` + client-side TOFU). It is
> **not** the removed intermediate *signed-HTTP-root* `registry.toml` (the mutable
> origin file with `[latest]`/`[channels]`/`[components]`/`[capabilities]`/
> `[[bundles]]`/`[signature]`), which is retired entirely (brief §15). Caches live
> in this committed `[[caches]]` (authenticated via the tag), **not** in signed
> tags; the consumer's client-side `registries.d/<name>.toml` is an optional
> override/supplement (HIGHER priority wins). See
> [repo-layout.md](../../registry/repo-layout.md) §2–§3.

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

- `git(&dir, &["init"])` at `registry_ops.rs:438` (inside `pub async fn create`,
  `fn` at `:421`; non-bare, sha1) is replaced by the bare sha256 form for the
  **canonical published repo**. (A working clone the publisher edits in may stay
  non-bare; the *published* artifact is bare.)
- The bundle scratch-repo inits at `bundle.rs:358` (`ensure_git_repo`, `fn` at
  `:349`) and `git.rs:157` (`ensure_repo`, `fn` at `:147`) — both `["init",
  "--bare"]` (sha1) — are part of
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
`/releases/<…>/objects/` dir is **pack-only**: it holds `info/packs` and the
release's `pack/pack-<sha256>.pack(.idx)` + `pack/delta-<from>.pack` (WS-02),
and contains **no loose `<xx>/<..>` objects** and **no per-release
`info/alternates`**.

The producer therefore:

- writes the release's new loose objects (objects in `<to>` not in `<from>`, the
  same revset WS-02 uses for deltas) into the **root** `/objects/`;
- writes that release's packs under `/releases/<…>/objects/pack/`.

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
  `/releases/<…>/objects/` directory, ordered **newest → oldest** by semver
  precedence. Git resolves relative alternates against the repo's `objects/`
  URL, so each `../` strips the `objects` segment to reach the repo root —
  therefore the correct depth is **one `../`** (not two):

```
# objects/info/alternates  (newest → oldest)
../releases/1/2/0/objects/
../releases/1/1/2/objects/
../releases/1/1/0/objects/
../releases/1/0/0/objects/
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
1. write new loose objects to root /objects/; write packs under /releases/<new>/objects/pack/  (immutable, safe to publish early)
2. write/refresh per-release objects/info/packs
3. git update-server-info        → root info/refs, objects/info/packs
4. rewrite root objects/info/alternates (prepend new release)
5. (WS-03) advance channel partition tags + frontier branch head
6. upload, then bust low-TTL caches for info/** and channels/**
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
namespace at `/channels/*` (WS-03), so they never pollute a stock client's
`refs/tags/*`.

```
stock git clone <url>
  → GET HEAD                       (ref: refs/heads/stable)
  → GET info/refs                  (refs/heads/* + refs/tags/*)
  → GET objects/info/packs         (pack-<sha>.pack list)
  → GET objects/info/alternates    (relative, one "../")
       → follow ../releases/X/Y/0/objects/  (full pack, pack-only dir)
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

All in `#[cfg(test)] mod tests` inside `registry/objectstore.rs` (same pattern as
the `version_to_token_*` tests in `registry/state.rs:197-227`):

| `#[test] fn` | Exercises | Asserts |
|---|---|---|
| `test_release_object_dir_mapping` | `release_object_dir` | semver → `M/m/<third>/objects` for the §3.1 table (incl. `1.1.0-alpha.1`, `1.0.0-beta+exp.sha.5114f85`) |
| `test_alternates_ordering` | `write_alternates` | release dirs emitted **newest → oldest** by `semver::Version` precedence (unsorted input is re-sorted) |
| `test_alternates_relative_one_dotdot` | `write_alternates` | every line is relative with **one `../`** resolving to a real release `objects/` dir; host-independent (no hostname, byte-identical) |
| `test_assert_sha256_rejects_sha1` | `assert_sha256` + `init_bare_sha256` | a `git init` (sha1) repo → `Err`; an `init_bare_sha256` repo → `Ok` |
| `test_loose_object_path_split` | `loose_object_path` | 64-hex oid → `<first-2>/<last-62>`; a non-64-hex / non-hex input → `Err` |

### 6.2 Integration (build → serve → clone)

A scripted test (CI check, analogous to `nix-build -A checks.eval`):

1. `git init --bare --object-format=sha256` a scratch repo; create 4 releases
   (`1.0.0`, `1.1.0`, `1.1.2`, `1.2.0`) with distinct file trees; tag each.
2. Place each release's new loose objects under the root `/objects/`; write each
   release's packs under `/releases/<…>/objects/pack/` with per-release
   `info/packs`; write the root `info/{packs,alternates}` (relative, one `../`);
   run `update-server-info`; set `HEAD → refs/heads/stable`.
3. Serve the directory with an AOS static HTTP server.
4. **Stock clone:** `git clone <url> out` with sha256-capable git; assert the
   checkout of `refs/heads/stable` and of each `refs/tags/<semver>` matches the
   source tree byte-for-byte.
5. **Pack discovery via alternates:** assert the relative `info/alternates`
   resolves each `../releases/<…>/objects/` pack-only dir (one `../`), and that
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

**New module** `crates/aos-package/src/registry/objectstore.rs` (registered in
`crates/aos-package/src/registry/mod.rs` alongside the existing `bundle`,
`git`, `state`, `closures`, `parse` submodules). It owns the following functions
(real types — `&Path`, `semver::Version`, `anyhow::Result`):

```rust
/// Step 1 — `git init --bare --object-format=sha256` + `symbolic-ref HEAD`.
pub fn init_bare_sha256(dir: &Path, default_channel: &str) -> Result<()>;

/// §3.1 mapping — pure, total, no I/O. `1.1.0-alpha.1` → `1/1/0-alpha.1/objects`.
/// The third segment is everything after `major.minor` (pre-release + build).
pub fn release_object_dir(version: &semver::Version) -> PathBuf;

/// sha256 oid (64 hex) → `<first-2>/<last-62>` loose path. Pure.
pub fn loose_object_path(oid: &str) -> Result<PathBuf>;

/// Step 2 — write the `<from>..<to>` new loose objects to the root `/objects/`,
/// and this release's packs under `release_object_dir(version)/pack/`.
/// `revspec` is the same revset WS-02 uses for deltas (objects in `to` not `from`).
pub fn write_release_objects(repo: &Path, version: &semver::Version, revspec: &str) -> Result<()>;

/// Step 3 — explode pack-only objects back to loose form so every reachable
/// object resolves loose from the root `/objects/`.
pub fn ensure_loose_completeness(repo: &Path) -> Result<()>;

/// Step 4 — wraps `git update-server-info` (regenerates `info/refs` +
/// `objects/info/packs`).
pub fn refresh_server_info(repo: &Path) -> Result<()>;

/// Step 5 — write the relative, host-independent `objects/info/alternates`
/// (one `../` per line, newest → oldest). Sorts internally by semver precedence.
pub fn write_alternates(repo: &Path, releases_newest_first: &[semver::Version]) -> Result<()>;

/// Object-format guard — `Err` unless `git rev-parse --show-object-format`
/// is exactly `sha256`. Uses `git_try` (not `git`) so a non-repo / missing-flag
/// failure becomes a typed error rather than a `bail!`.
pub fn assert_sha256(repo: &Path) -> Result<()>;
```

This sits **below** the pack/delta module (WS-02) and the channel/tag module
(WS-03), which call into it. It reuses the existing `git(dir: &Path, args:
&[&str]) -> Result<String>` helper (`registry_ops.rs:79`) and the
allow-fail variant `git_try(dir: &Path, args: &[&str]) -> Result<(bool, String,
String)>` (`registry_ops.rs:96`, currently `#[allow(dead_code)]` — this module
becomes its first live consumer) for the `assert_sha256` format guard. Both
helpers are file-private in `registry_ops.rs`; either move them into
`registry/git.rs` (which already has a parallel `git(repo_dir)` builder around
`:150`) and re-export, or duplicate the two small wrappers into `objectstore.rs`.

### 7.2 Command surface

No new top-level `apr` subcommand is introduced *by this workstream alone* — the
object-store primitives are invoked by the publish pipeline. Per
[design-brief §16.4](./design-brief.md) (open question), a single
`apr release` / `apr publish` may wrap the whole pipeline (commit → tag/sign →
pack/delta/zstd → `update-server-info` → advance partitions → upload); this
workstream contributes the `update-server-info` + `info/alternates` steps to
that command. The `apr` subcommands are the `RegistryCommand` enum
(`crates/aos-package/src/lib.rs:349`, dispatched in its `run`/`execute` arm at
`lib.rs:1215+`). The existing `RegistryCommand::Bundle` variant (`lib.rs:620`,
dispatched at `:1231` → `registry_ops::bundle` at `registry_ops.rs:1706`,
= `git bundle create`) and the `bundle.rs` writer are **removed** as part of
retiring bundles (brief §15, done in WS-02); the `RegistryCommand::Create`
variant (`lib.rs:352`, dispatched at `:1020` → `registry_ops::create` at `:421`,
whose `git(&dir, &["init"])` at `:438` is the sha1 init) is the one this WS
re-points at `objectstore::init_bare_sha256`.

`apr` also gains an internal/debug verb (or `apr doctor`-style check) that runs
`objectstore::assert_sha256` + the loose-completeness walk against a published
repo, reusing §6's logic for operator validation. Concretely, add a
`RegistryCommand::Doctor { registry: Option<String> }` variant to the enum at
`lib.rs:349` with a dispatch arm next to `Create`/`Bundle`, calling
`objectstore::assert_sha256` then `objectstore::ensure_loose_completeness` in a
read-only check mode.

**Existing tests/consumers this WS breaks when bundles retire (coordinate with
WS-02):** the `pick_bundles_*` tests in `update.rs:655-779` and `sync_bundle`
(`update.rs:209`) / `pick_bundles` (`update.rs:319`) consume the bundle manifest
and become dead once `BundleManifest`/`bundle.rs` is removed; the
`download_bundle`/`verify_bundle` paths (`registry/bundle.rs:251`, `:305`) and
`classify_delta` (`:238`) go with them. The monotonic-token machinery
(`state::check_monotonic` at `registry/state.rs:104`, `version_to_token` at
`:131`, and their `check_monotonic_*` / `version_to_token_*` tests at
`registry/state.rs:197-270`) is tied to `creation_token`, which the target drops
in favor of `semver::Version` precedence — those tests must be removed or
re-pointed at semver ordering, not the calendar-token encoding.

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
5. **`registry.toml` clarification (`types.rs:564-570`):** the git-repo-root
   `registry.toml` (`RegistryRootConfig`) is **kept** as a committed tree file
   (`[registry]` + `[[caches]]`), authenticated via the signed tag — see §3.3 and
   [repo-layout.md](../../registry/repo-layout.md). The cache/NAR-substituter
   location stays in its `[[caches]]` (`Vec<CacheEntry>`, `types.rs:582`) — not
   moved into signed tags, which carry no payload; the client-side
   `registries.d/<name>.toml` only *supplements* it. What is removed: the
   intermediate *signed-HTTP-root* `registry.toml` (brief §15) and the **signing
   pubkey** field (`RegistrySigningConfig.public_key`, `types.rs:594-596`, the
   `signing` field of `RegistryRootConfig` at `types.rs:569`; moves to the new
   committed `keys.toml` + TOFU; WS-04). This WS continues to *write* the root
   `registry.toml` (`registry_ops.rs:443-450`, inside `pub async fn create` at
   `:421`) minus the pubkey; coordinate the key-field removal and `keys.toml`
   introduction with WS-04.
6. **Atomicity across a CDN (§4 Step 6):** content-before-pointer ordering holds
   at the origin, but CDN edge caches with mixed TTLs can briefly serve a new
   `info/refs` with a stale `info/alternates`. Loose objects + immutable content
   make this self-healing, but cache-bust ordering must be specified in
   [publishing](../../registry/publishing.md).

---

## 9. Definition of done

- [ ] `objectstore.rs` implements all §7.1 functions; the `git init` path
      (`registry_ops.rs:438`, in `pub async fn create` at `:421`) emits a
      **sha256 bare** canonical repo with `HEAD → refs/heads/<default-channel>`.
- [ ] Publish regenerates `info/refs` + `objects/info/packs` via
      `update-server-info`, and rewrites the relative `objects/info/alternates`
      (one `../`, newest → oldest) on every release.
- [ ] Every reachable object is retrievable **loose** from the root `/objects/`
      store (completeness guarantee); all loose objects are centralized there.
- [ ] Per-release dirs exist at `/releases/<M>/<m>/<third>/objects/` per §3.1 and
      are **pack-only** (`info/packs` + `pack/`; no loose objects, no
      per-release `info/alternates`).
- [ ] §6 eval tests + the serve→stock-clone integration test pass with
      AOS-built git over a static HTTP server.
- [ ] No *signed-HTTP-root* `registry.toml`, no `bundle-list.toml`, no git bundles
      emitted (brief §15); the **committed** git-repo-root `registry.toml`
      (`[registry]` + `[[caches]]`, pubkey removed) + `keys.toml` remain tree files
      ([repo-layout.md](../../registry/repo-layout.md)); thin `delta-*.pack`s are
      absent from `info/packs`.
