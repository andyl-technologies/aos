# AOS Registry — Gap Analysis (current code → git-native target)

> **Status:** Plan-grade gap analysis. Grounding source is
> [`design-brief.md`](./design-brief.md) (§2, §3, §15 in particular). When this
> doc disagrees with the brief on *target intent*, the brief wins; when it
> disagrees with the code on *current state*, the code wins — every CURRENT
> claim below is cited as `path:line`.
>
> **Audience:** implementers and architects sequencing the registry redesign.
>
> This doc enumerates the delta between today's **git-bundle /
> `bundle-list.toml` / `creation_token` / `registry.toml`** registry and the
> **git-native, sha256-over-dumb-HTTP** target, then maps every gap to one of the
> five workstreams.

---

## 1. How to read this doc

Each gap is labelled **CURRENT** (what the code does today, with a `path:line`
cite) versus **TARGET** (what the brief mandates), then routed to a workstream:

| WS | Doc | Scope |
|----|-----|-------|
| WS-01 | [workstream-01-object-store.md](./workstream-01-object-store.md) | sha256 bare repo, dumb-HTTP layout, `info/refs`/`HEAD`/`info/alternates`/`update-server-info`, centralized root `/objects/` + pack-only per-release dirs |
| WS-02 | [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md) | `pack-objects` thin/full, the delta-scheme graph, zstd, expensive-producer tuning |
| WS-03 | [workstream-03-channels-rollouts.md](./workstream-03-channels-rollouts.md) | 256 signed partition tags, channels-as-branches/frontier, bucket selection, publisher rollout control |
| WS-04 | [workstream-04-signing-trust.md](./workstream-04-signing-trust.md) | signed **tag objects** (pure signed pointers), name-binding, sha256, anti-rollback/fix-forward, the new committed **`keys.toml`** trust roster (pubkey moves out of `registry.toml`) |
| WS-05 | [workstream-05-consumer.md](./workstream-05-consumer.md) | consumer resolution (bucket → channel tag → semver tag → commit), delta walk, retention, verification, the Nix-cache superset |

The detailed as-is narrative lives in
[current-state.md](../../registry/current-state.md); the target reference set is
[architecture.md](../../registry/architecture.md),
[http-layout.md](../../registry/http-layout.md),
[versioning-and-channels.md](../../registry/versioning-and-channels.md),
[packs-and-deltas.md](../../registry/packs-and-deltas.md),
[signing-and-trust.md](../../registry/signing-and-trust.md),
[publishing.md](../../registry/publishing.md), and
[nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md). For
migration/risk see [open-questions.md](./open-questions.md); for sequencing see
[the plan README](./README.md).

---

## 2. Executive summary

Today's registry is a git repo of nested package TOMLs distributed as **git
bundles** indexed by a consumer-parsed **`bundle-list.toml`**, ordered by a
calendar **`creation_token`**, with a `registry.toml` config root and an SSH
Ed25519 **commit** signature. The target is a **bare sha256 git repo served as
static files over dumb HTTP**, where:

- distribution is **centralized loose objects at the root `/objects/` + per-release
  pack-only dirs (packs + thin `delta-*.pack`s)** discovered via `objects/info/packs`
  and a relative `objects/info/alternates` — **no bundles, no `bundle-list.toml`**;
- versions are **semver** (no `v`) ordered by **git ancestry** — **no
  `creation_token`**;
- rollout is **256 signed partition tag objects** under `/channels/<name>/00..ff`
  with the channel **branch head = frontier** — **no percentage rollout**;
- the trust anchor moves from a signed **commit** to signed **tag objects**
  with **name-binding** verification (`tag → tag → commit`);
- there is a **producer publish pipeline** (commit → sign → pack/delta/zstd →
  `update-server-info` → advance partitions → upload) where today there is only
  a `git bundle create` stub and **no upload path at all**.

What survives unchanged: the **package-TOML tree content** and the **Ed25519 /
SSH signing primitive** (`security.rs`). Everything about *distribution* and
*rollout* is replaced. The asymmetric-cost philosophy (brief §3) inverts the
current cheap-producer / consumer-parses-a-manifest model into an
expensive-producer / trivial-consumer one.

```
 CURRENT                                     TARGET
 ┌───────────────────────────┐              ┌───────────────────────────────┐
 │ signed-HTTP-root          │              │ (gone — committed-tree files) │
 │   registry.toml           │   ───────►   │ registry.toml (caches) + KEPT │
 │ registry.toml signing.pub │              │ keys.toml (trust roster) NEW  │
 │ bundle-list.toml          │   ───────►   │ objects/info/packs            │
 │   [[bundles]] by token    │              │ objects/info/alternates       │
 │ *.bundle (git bundles)    │              │ loose objects + pack-<sha>    │
 │ creation_token ordering   │              │ + thin delta-<from>.pack      │
 │ signed COMMIT             │              │ semver + git ancestry         │
 │ no rollout model           │              │ signed TAG objects, /channels/ │
 │ pick_bundles() consumer    │              │ <name>/00..ff (256 partitions)│
 │ NO upload                  │              │ full publish pipeline         │
 └───────────────────────────┘              └───────────────────────────────┘
```

---

## 3. Gap inventory

### 3.1 Object store & dumb-HTTP layout → **WS-01**

| Aspect | CURRENT | TARGET |
|--------|---------|--------|
| Repo identity | A working git clone of package TOMLs at `~/.local/share/apm/registries/<name>/`; the consumer keeps a *bare* cache repo created on demand only to unbundle into. | A **published bare sha256 repo** that *is* the distribution surface (brief §3, §8). |
| Object format | Default sha1 — no `--object-format`: producer `git init` (`registry_ops.rs:438`), consumer `git init --bare` (`bundle.rs:359`). | **sha256** everywhere; loose object path = first 2 / remaining 62 hex of the 64-char hash (brief §8). |
| Dumb-HTTP shim | None produced. The repo is never `update-server-info`'d; there is no `HEAD`/`info/refs`/`objects/info/*` publish step anywhere. | `HEAD` (symref → default channel), `info/refs` (via `git update-server-info` on every publish), `objects/info/packs`, `objects/info/alternates` (brief §4, §8, §12). |
| Loose object location | None — a bundle carries the whole pack; the consumer unbundles into one flat object store (`unbundle`, `bundle.rs:376`). | **ALL** loose objects (every release) are centralized at the single root `/objects/<xx>/<62hex>` (brief §4, §7, §8). |
| Per-release object dirs | None. | `/releases/<major>/<minor>/<patch[-pre][+build]>/objects/` are **pack-only**: `info/packs` + `pack/pack-<sha256>.pack(.idx)` + `pack/delta-<from>.pack`, with **no** loose `<xx>/<…>` objects and **no** per-release `info/alternates` (brief §4, §7). |
| Distributed object index | `bundle-list.toml` (`BundleManifest`, `bundle.rs:48-53`). | Root `objects/info/alternates` with **relative** entries `../releases/<M>/<m>/<patch…>/objects/` (one `../`), newest→oldest; host-independent and byte-identical across CDN/mirror/localhost. Serves **pack discovery + the release index** (loose completeness lives at the root, brief §8). |
| Loose-object completeness | Not guaranteed — only packed objects inside bundles. | **ALL objects exist loose** under the root `/objects/<xx>/<…>` as the correctness fallback; packs are an efficiency layer (brief §8). |
| CDN TTL policy | Not modeled. | `/channels/**`, `/objects/info/**`, per-release `objects/info/**` → low TTL; `/releases/**` + other `/objects/**` → immutable/high TTL (brief §4). |

**Concrete code that disappears or is repurposed:** `ensure_git_repo`
(`bundle.rs:349`) becomes "init a sha256 bare repo + lay out dirs"; the consumer
no longer `unbundle`s (`bundle.rs:376`) but fetches loose objects/packs over
dumb HTTP.

---

### 3.2 Pack & delta pipeline → **WS-02**

| Aspect | CURRENT | TARGET |
|--------|---------|--------|
| Transport unit | **git bundle** (`git bundle create`, `registry_ops.rs:1739-1751`). Bundles carry refs + prerequisites. | **packs**: self-contained `pack-<sha256>.pack` (+ `.idx`) at every `X.Y.0`, and **thin** `delta-<from-semver>.pack` for incrementals (brief §9, §10). |
| Producer pack generation | Just `git bundle create <dest> <rev\|range>` (`registry_ops.rs:1739-1751`). No `pack-objects`, no tuning, no zstd. | `git pack-objects --revs` (full) and `git pack-objects --revs --thin` reading `"<to>\n^<from>\n"` (delta); expensive flags `--no-reuse-object --no-reuse-delta --window=350 --depth=50 --threads=0` (brief §10). |
| Delta classification | Heuristic on tag *segment count* in `classify_delta` (`bundle.rs:238-243`), yielding `SequentialDelta` / `SkipDelta` (`bundle.rs:23-31`). | A **guaranteed, walkable delta graph** keyed on semver: every `X.0.0` ships `delta-<(X-1).0.0>`; every `X.Y.0 (Y>0)` ships `delta-<X.(Y-1).0>` + `delta-<X.0.0>`; every `X.Y.Z (Z>0)` ships the last-3-patch deltas + `delta-<X.Y.0>` (brief §9). |
| Compression | git default zlib inside the bundle; `.nar.zst` is the *artifact* convention (`registry_ops.rs:1290`), not the pack. | The **zstd trick**: `git pack-objects --compression=0` (delta-encoded, no entropy coding) then `zstd --ultra -22 --long=27` the whole `.pack`; serve `.pack.zst`; optional trained dictionary per release line (brief §10). |
| `.idx` shipping | Implicit in the bundle. | `.idx` only for **full** packs; thin deltas are `.pack[.zst]` only — the client builds the idx with `git index-pack --fix-thin` (brief §10). |
| `info/packs` listing | n/a. | Lists **self-contained full packs only**; thin `delta-*.pack`s are **NOT** listed (a stock dumb client can't apply a thin pack) (brief §10, §12). |

**Concrete code that disappears:** `BundleType` (`bundle.rs:23`), `classify_delta`
(`bundle.rs:238`), `verify_bundle`'s `git bundle verify` step (`bundle.rs:326`),
and `unbundle` (`bundle.rs:376`) — all replaced by `pack-objects` /
`index-pack --fix-thin`.

---

### 3.3 Versioning, channels & rollout → **WS-03**

| Aspect | CURRENT | TARGET |
|--------|---------|--------|
| Version scheme | Calendar tags `vYYYY.MM[.P]` encoded to a monotonic **`creation_token`** (`state.rs version_to_token:131`, `token_to_version:173`). | **Standard semver, no `v` prefix** (`1.1.2`, `1.0.0-beta+exp.sha.5114f85`); precedence by semver rules + git ancestry (brief §7). The whole `creation_token` scheme is **removed** (brief §15). |
| Ordering source | `entries.sort_by_key(creation_token)` (`bundle.rs:171`); `entries_since` / `latest_snapshot` / `skip_delta_from` / `sequential_deltas_between` (`bundle.rs:181-224`) all key off the token. | git **ancestry** + semver precedence; no scalar token. |
| Channel model | A git **branch** the consumer tracks via `TrackingMode::Branch` (`types.rs:282-302`) — but there is no rollout structure on top. | A channel = **branch** (`refs/heads/<channel>`, head = **frontier**) **plus 256 signed partition tag objects** `/channels/<name>/00..ff` (brief §5, §6). |
| Rollout mechanism | **None.** No partitions, no percentage, no `[channels.<name>.rollout]`. `pick_bundles` just picks the newest reachable bundle (`update.rs:292-391`). | **Publisher-controlled 256-partition rollout**: to roll to N/256, point N partition tags at the new semver tag and leave the rest on the prior release (brief §6). |
| Consumer bucket | None. | Deterministic, **persisted** bucket: the low byte of `sha256(machine_id)` (i.e. mod 256), written once; probe-forward `(bucket+1) mod 256` if a partition is missing (brief §6). |
| Frontier | n/a. | `refs/heads/<channel>` head = the commit of the newest release **any** partition targets; stock `git pull <channel>` always gets the frontier (brief §6). |
| Anti-rollback | `check_monotonic(old_token, latest_token)` on `creation_token` (`state.rs:104`, called from `update.rs:263-266`). | A **monotonic semver floor** per consumer; a bad rollout is **fix-forward** (publish newer, advance partitions), never partition-decrement (brief §6). |

**Concrete code that disappears:** `version_to_token` / `token_to_version` /
`check_monotonic` (`state.rs`), the `last_creation_token` plumbing
(`update.rs:256-271`), the segment-counting `extract_minor_base`
(`update.rs:456-464`), and all of `pick_bundles`' token strategies
(`update.rs:344-390`).

---

### 3.4 Signing & trust → **WS-04**

| Aspect | CURRENT | TARGET |
|--------|---------|--------|
| Signed object | The **commit**: `apr sign` = `git commit --amend --no-edit -S` (`registry_ops.rs:1770`); verified with `git verify-commit` + a temp `allowed_signers` file (`verify_commit_signature`, `security.rs:199-229`). | The **tag objects**: both channel partition tags and release semver tags are annotated tags as **pure signed pointers** — standard git tag fields (object, type, tag name, tagger) + an SSH Ed25519 signature + an optional freeform human message; **no structured payload** (brief §11). |
| Primitive | SSH-format Ed25519; `parse_signing_key` `name:Ed25519:<base64>` (`security.rs:306-326`); TOFU + `trusted-keys.d/<registry>.pub`. **Survives unchanged.** | Same primitive, reused for tag-object signatures (brief §11). |
| Tag verification | **Absent** — there is `verify_commit_signature` but **no** `verify-tag` path; `apr tag` (`registry_ops.rs:1696-1714`) creates an *unsigned* annotated tag (`git tag -a … -m`) only when `--message` is given, else a lightweight tag (`git tag <name>`) (`registry_ops.rs:1706-1710`), and ignores `_key` (`registry_ops.rs:1700`). | `git verify-tag` of the whole **`tag → tag → commit`** chain (channel partition tag → semver tag → commit) (brief §5, §11). |
| Name-binding | None. | Verify signature **and** the embedded tag-name field equals the expected path name (channel name under `/channels/*`, semver under `/releases/*`), binding a tag object to its serving path to prevent cross-serving (brief §5). |
| Tag-message body | Free-text `-m` message (`registry_ops.rs:1707`). | **No structured payload** — an optional freeform human message only. A signed tag is a pure signed pointer; there is no tag-message TOML, no `[meta]`/`schema`/`valid_until`, no in-band `[[caches]]` (brief §11). |
| Freshness / rotation | None. | **No in-band `valid_until`.** Freshness = low CDN TTL on `/channels` (and `info/refs`, `objects/info`) + the consumer's own max-staleness policy + the monotonic anti-rollback floor. Trade-off: weaker than an in-band signed expiry against a frozen-but-validly-signed mirror (brief §11). |
| Branch trust | n/a. | Branch refs are **unsigned convenience pointers**, never in the trust chain (brief §5, §11). |
| Trust roster | **None as a file.** The single trusted pubkey lives in `registry.toml`'s `[registry.signing].public_key` (`RegistrySigningConfig`, `types.rs:593-596`, on `RegistryRootConfig`, `types.rs:563-570`); the consumer also TOFU-pins `trusted-keys.d/<registry>.pub` (`security.rs`). | A **new committed tree file `keys.toml`** — the trust roster: active signing key(s) + a revoked list, authenticated transitively by the signed tag (tag → commit → tree → file). The signing **pubkey is removed from `registry.toml`** (a key inside a file authenticated *by* that key is circular for bootstrap) (brief §14; [repo-layout.md §2-§3](../../registry/repo-layout.md)). |
| Bootstrap trust | TOFU-pinned `trusted-keys.d/<registry>.pub` **plus** the in-tree `signing.public_key`. | **TOFU only** for the anchor (`trusted-keys.d/<registry>.pub`); `keys.toml` does **not** bootstrap trust — it governs **rotation** (publish `keys.toml` listing old+new keys in a tag signed by the currently-trusted key; consumer pins the new key) and **revocation** (list the bad key, signed by a key the consumer trusts that is **not** the revoked one → a dedicated offline **root/anchor** key signs `keys.toml` while a separate **operational** key signs day-to-day tags, TUF-style, or keep ≥2 overlapping active keys). Root-vs-single is an open choice (brief §16). |

**Concrete code to extend/replace:** add a `verify_tag_signature` alongside
`verify_commit_signature` (`security.rs:199`); make `apr tag` / `apr sign`
produce **signed tag objects (pure signed pointers, optional freeform message)**
instead of an unsigned annotated tag + a signed commit; **drop
`RegistrySigningConfig` / `signing.public_key` from `RegistryRootConfig`**
(`types.rs:563-570,593-596`) and read the active/revoked keys from the new
committed `keys.toml` instead. NAR safety is independent of all this: an
authenticated-but-wrong cache pointer cannot serve bad bytes — NARs are
content-addressed and SHA-256-verified on download — so the trust that matters is
the tag/commit chain that `keys.toml` governs, not the cache list.

---

### 3.5 Producer pipeline & config root → orchestrated in [publishing.md](../../registry/publishing.md)

| Aspect | CURRENT | TARGET |
|--------|---------|--------|
| Config root | `registry.toml` written at `create` (`registry_ops.rs:443-450`), read by `read_registry_toml` (`registry_ops.rs:392-402`), caches resolved via `resolve_mirrors` (`registry_ops.rs:405-414`). Carries `[registry]` + `[[caches]]` + `[registry.signing].public_key` (`RegistryRootConfig`, `types.rs:563-570`). | **The git-repo-root `registry.toml` is KEPT** as a committed tree file — `[registry]` name/description + `[[caches]]` only — authenticated transitively by the signed tag. The **signing pubkey is removed** from it (→ `keys.toml`, §3.4). Only the intermediate *signed-HTTP-root* `registry.toml` (`[latest]`/`[channels]`/`[components]`/`[capabilities]`/`[[bundles]]`/`[signature]`) is removed (brief §14, §15; [repo-layout.md §2](../../registry/repo-layout.md)). The origin MAY additionally serve `nix-cache-info`/`<storehash>.narinfo`/`nar` as a stock-nix superset, narinfo signing reusing the one Ed25519 key (brief §13). |
| Manifest writer | **Stub** — `apr bundle` (`registry_ops.rs:1718-1755`) only `git bundle create`s; `_update_manifest` is ignored (`registry_ops.rs:1723`); **no `bundle-list.toml` writer exists**. | A real publish pipeline writes loose objects to the root `/objects/`, emits per-release packs/deltas under `/releases/*/objects/pack/`, regenerates `objects/info/packs` + the relative `objects/info/alternates`, runs `update-server-info`, advances partitions, and uploads (brief §10, §4, §6). |
| Upload | **None at all** — `apr push` / `apr pull` (`registry_ops.rs:1410-1462`) push the *git working repo*; there is **no static-artifact upload** of bundles/objects to a CDN/origin. | An **upload backend** ships the static tree (loose objects, packs, refs shims, channel partition files) to the origin; pluggability is an open question (brief §16.4). |
| Atomicity / concurrency | Not modeled. | Publish must be atomic w.r.t. the CDN: write new immutable objects first, then mutate the low-TTL `info/*` + `/channels/*` — see [publishing.md](../../registry/publishing.md). |

---

### 3.6 Consumer (`apm update`) → **WS-05**

| Aspect | CURRENT | TARGET |
|--------|---------|--------|
| Transport selection | `Transport::HttpBundle` vs `Transport::Git` (`types.rs:270-322`); `sync_bundle` fetches `bundle-list.toml` then runs `pick_bundles` (`update.rs:193-391`). | A single **dumb-HTTP git fetch** path: bucket → channel partition tag → semver tag → commit, then delta-walk or full-pack or loose-object fetch (brief §9; [WS-05](./workstream-05-consumer.md)). |
| Selection logic | `pick_bundles` token strategies: skip delta → sequential deltas → latest snapshot (`update.rs:367-390`). | **Delta resolution + retention**: prefer a `delta-<B>.pack` at target T whose base B the client retains; else walk releases backward; else a full pack; else loose objects (always correct). Retention keeps the `X.0.0`, `X.Y.0`, `X.Y.Z` trees (brief §9). |
| Integrity | `verify_bundle` = sha256 of the bundle file + `git bundle verify` (`bundle.rs:305-346`). | `git index-pack --fix-thin` (completes thin packs) + signed-tag-chain verification + name-binding (brief §5, §10). |
| State | `last_commit` + `last_creation_token` + `last_update` (`update.rs:270-272`). | `last_commit` + **semver floor** + persisted **bucket**; no token. |
| Nix cache | `nar_hash` / `nar_size` baked into package TOMLs (`registry_ops.rs:633-651`); validated against caches read from `registry.toml` (`validate`, `registry_ops.rs:1210-1326`). | Caches **stay in the committed git-repo-root `registry.toml`** (`[[caches]]`, authenticated via the signed tag); the consumer's client-side `registries.d/<name>.toml` is an **optional override/supplement** (higher priority wins, `resolve_mirrors` sorts descending). NAR bytes are content-addressed + SHA-256-verified, so an authenticated-but-wrong pointer can't serve bad bytes. The origin MAY serve `nix-cache-info`/`<storehash>.narinfo`/`nar`, a strict superset of the Nix binary cache, narinfo signing reusing the one Ed25519 key (brief §13, §14; [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md), [repo-layout.md §2](../../registry/repo-layout.md)). |

---

## 4. Removed concepts (do **not** carry forward)

Per brief §15, the target **must not** reintroduce any of these — several are
load-bearing in today's code and must be deleted, not merely bypassed:

| Removed concept | Where it lives today | Replacement |
|-----------------|----------------------|-------------|
| signed-**HTTP-root** `registry.toml` (mutable origin file: `[latest]`/`[channels]`/`[components]`/`[capabilities]`/`[[bundles]]`/`[signature]`) | intermediate-design concept (never in code) | committed-tree files (registry.toml + keys.toml) authenticated by the signed tag (tag → commit → tree → file) — see **Kept** note below |
| `[registry.signing].public_key` inside `registry.toml` | `RegistrySigningConfig` on `RegistryRootConfig` (`types.rs:563-570,593-596`) | **`keys.toml`** trust roster (active + revoked) + TOFU `trusted-keys.d/<registry>.pub` anchor |
| tag-message TOML / `[meta]` / `schema` / `valid_until` / in-band `[[caches]]` | target concepts (never in code) | signed tags are pure signed pointers (optional freeform message); freshness via CDN TTL + consumer policy + anti-rollback floor |
| `bundle-list.toml` | `bundle.rs:48-225` | `objects/info/packs` + relative `objects/info/alternates` |
| git **bundles** | `registry_ops.rs:1718-1755`, `bundle.rs:376` | loose objects + `pack-<sha>.pack` + thin `delta-*.pack` |
| `[latest]` / `[components]` / `[capabilities]` | config concepts (not in code) | ref namespace (branches/tags) + object store |
| percentage rollout / `[channels.<name>.rollout]` / baseline+candidate | never implemented (brief §15) | 256 signed partition tag objects `/channels/<name>/00..ff` |
| calendar versioning + `creation_token` | `state.rs:131-187`, `bundle.rs:34-224`, `update.rs:256-390` | semver (no `v`) + git ancestry |
| by-hash `[[bundles]]` / `[[deltas]]` index | `bundle.rs:59-92` | git object store + relative `info/alternates` |
| `previous_tag` / per-version `previous` framing | `registry_ops.rs:626-628,735-739` | semver precedence + the delta-scheme graph |

> **Kept (not removed) — do not over-delete:** the **git-repo-root `registry.toml`**
> (the existing `RegistryRootConfig`, `types.rs:563-570`) survives as a committed tree
> file carrying `[registry]` + `[[caches]]`, authenticated via the signed tag. Only its
> `[registry.signing].public_key` moves out (→ `keys.toml`). Do **not** conflate it with
> the removed signed-HTTP-root `registry.toml` above. The `[[caches]]` list is **not**
> moved client-side — it stays in the tree; the consumer's `registries.d/<name>.toml` is
> an optional override. See [repo-layout.md §2-§3](../../registry/repo-layout.md) and
> brief §14.

---

## 5. Surviving primitives (reuse, don't rebuild)

| Primitive | Where | Role in target |
|-----------|-------|----------------|
| Package-TOML tree content | `build_package_toml` (`registry_ops.rs:595-781`) | Unchanged — it is the git **tree content** the objects encode (brief §2). |
| Closure adjacency files | `write_closure_files` (`registry_ops.rs:305-352`) | Unchanged tree content; rides inside the object store. |
| `registry.toml` `[[caches]]` + `resolve_mirrors` | `RegistryRootConfig` (`types.rs:563-570`), `CacheEntry` (`types.rs:582-586`), `resolve_mirrors` (`registry_ops.rs:405-414`) | Reused — `[registry]` + `[[caches]]` stay as a committed tree file authenticated by the tag; only `signing.public_key` is dropped (→ `keys.toml`, WS-04). |
| Ed25519/SSH signing | `parse_signing_key` (`security.rs:306`), `verify_commit_signature` (`security.rs:199`), TOFU + `trusted-keys.d` | Reused for **tag-object** signatures; add a tag-verify path + name-binding (WS-04). |
| `git` subprocess plumbing | `git()` (`registry_ops.rs:79-92`) | Reused; new callers run `pack-objects`, `index-pack`, `update-server-info`, signed `tag -s`. |
| Transfer engine (sha256-verified GET) | `TransferRequest::get(..).with_hash` (`bundle.rs:276-282`) | Reused to fetch loose objects/packs over dumb HTTP. |

---

## 6. Gap → workstream traceability matrix

| # | Gap (CURRENT → TARGET) | Brief § | Workstream |
|---|------------------------|---------|------------|
| G1 | sha1 default → **sha256** `git init --object-format=sha256` | §8 | WS-01 |
| G2 | no dumb-HTTP shim → `HEAD` / `info/refs` / `update-server-info` | §4,§8,§12 | WS-01 |
| G3 | flat unbundle store → **per-release `/releases/.../objects/`** dirs | §4,§7 | WS-01 |
| G4 | `bundle-list.toml` index → `objects/info/packs` + relative **`info/alternates`** | §8 | WS-01 |
| G5 | no loose-object guarantee → **all objects loose, centralized at root `/objects/`** | §4,§7,§8 | WS-01 |
| G6 | no CDN TTL model → explicit per-path TTL policy | §4 | WS-01 |
| G7 | `git bundle create` → `git pack-objects` full/thin | §10 | WS-02 |
| G8 | `classify_delta` heuristic → **guaranteed delta-scheme graph** | §9 | WS-02 |
| G9 | zlib-in-bundle → **`--compression=0` + `zstd --ultra -22 --long=27`** | §10 | WS-02 |
| G10 | bundle carries idx → `.idx` only for full packs; thin = `--fix-thin` | §10 | WS-02 |
| G11 | n/a → `info/packs` lists **full packs only** | §10,§12 | WS-02 |
| G12 | `creation_token` → **semver (no `v`) + git ancestry** | §7 | WS-03 |
| G13 | bare branch tracking → branch **frontier head** | §5,§6 | WS-03 |
| G14 | no rollout → **256 signed partition tags `/channels/<name>/00..ff`** | §6 | WS-03 |
| G15 | no bucket → deterministic persisted low byte of `sha256(machine_id)` (i.e. mod 256) | §6 | WS-03 |
| G16 | token monotonic check → **semver floor + fix-forward** | §6 | WS-03 |
| G17 | signed **commit** → signed **tag objects** | §11 | WS-04 |
| G18 | no `verify-tag` → `verify-tag` over `tag → tag → commit` | §5,§11 | WS-04 |
| G19 | no name-binding → **name-binding** (tag-name == path name) | §5 | WS-04 |
| G20 | unsigned tag → **signed pure-pointer tag** (optional freeform msg, no payload) | §11 | WS-04 |
| G21 | no freshness → **CDN TTL + consumer max-staleness + anti-rollback floor** (no in-band `valid_until`) | §11 | WS-04 |
| G21b | no trust-roster file → **new committed `keys.toml`** (active keys + revoked), tag-authenticated; rotation/revocation + TOFU anchor | §14 | WS-04 |
| G21c | `signing.public_key` in `registry.toml` → **moved out** to `keys.toml` (circular-bootstrap fix) | §14 | WS-04 |
| G22 | `pick_bundles` token strategies → **delta walk + retention** | §9 | WS-05 |
| G23 | bundle verify → `index-pack --fix-thin` + signed-chain verify | §5,§10 | WS-05 |
| G24 | `registry.toml` caches / `validate` → **caches stay in committed `registry.toml`** (tag-authenticated) + optional client-side override + origin nix-cache superset | §13,§14 | WS-05 |
| G25 | `apr bundle` stub + **no upload** → full publish + upload pipeline | §10,§4,§6 | WS-01/02/03 |
| G26 | signed-**HTTP-root** `registry.toml` (intermediate design) → **removed**; git-repo-root `registry.toml` **kept** as a committed tree file | §14,§15 | WS-04 |

---

## 7. Sequencing notes & risks

- **WS-01 is the foundation.** A valid sha256 dumb-HTTP bare repo
  (objects + `info/refs` + `HEAD` + `info/alternates`) must exist before packs,
  channels, or signing can be layered on. It also de-risks the biggest unknown:
  the **sha256 dumb-HTTP clone against real client git versions** (brief §16.1),
  since dumb HTTP has no capability negotiation.
- **WS-02 and WS-03 are largely independent** once WS-01 lands: packs/deltas
  ride in the object store; channels/partitions ride in the ref + `/channels`
  namespaces. They re-converge in the **publish pipeline**
  ([publishing.md](../../registry/publishing.md)).
- **WS-04 is a focused extension** of the surviving signing primitive — the main
  new code is `verify_tag_signature` + name-binding over pure signed-pointer tags;
  the Ed25519/TOFU machinery (`security.rs`) is reused as-is.
- **WS-05 is a near-rewrite** of `sync_bundle` / `pick_bundles`
  (`update.rs:193-391`): the token strategies, `BundleManifest`, and the
  `unbundle` path all go away, replaced by dumb-HTTP fetch + delta walk +
  retention + signed-chain verification.
- **Clean break vs shim** for existing `creation_token`/bundle registries is an
  open question (brief §16.7); track it in
  [open-questions.md](./open-questions.md). The recommended default is a clean
  break — the on-disk and on-wire formats share almost nothing — with
  [current-state.md](../../registry/current-state.md) retained as the historical
  description of the old code.
- **Risk: producer cost.** The expensive-producer flags (`--window=350`,
  multiple delta bases, `zstd --ultra -22`) make publishing genuinely slow; that
  is intentional (asymmetric cost, brief §3) but must be budgeted in CI and
  reflected in the pipeline design.

---

## 8. Cross-references

- Plan set: [README](./README.md) · [design-brief](./design-brief.md) ·
  [open-questions](./open-questions.md) ·
  [WS-01](./workstream-01-object-store.md) ·
  [WS-02](./workstream-02-pack-delta-pipeline.md) ·
  [WS-03](./workstream-03-channels-rollouts.md) ·
  [WS-04](./workstream-04-signing-trust.md) ·
  [WS-05](./workstream-05-consumer.md)
- Reference set: [README](../../registry/README.md) ·
  [architecture](../../registry/architecture.md) ·
  [current-state](../../registry/current-state.md) ·
  [repo-layout](../../registry/repo-layout.md) ·
  [http-layout](../../registry/http-layout.md) ·
  [versioning-and-channels](../../registry/versioning-and-channels.md) ·
  [packs-and-deltas](../../registry/packs-and-deltas.md) ·
  [signing-and-trust](../../registry/signing-and-trust.md) ·
  [publishing](../../registry/publishing.md) ·
  [nix-cache-compatibility](../../registry/nix-cache-compatibility.md) ·
  [apt-comparison](../../registry/apt-comparison.md)
