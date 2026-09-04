# AOS Registry — Design Brief & Decision Log

> **Status:** Design capture (current). This is the authoritative grounding source
> for the `docs/registry/` reference set and the `docs/plans/registry/` plan set.
> When a doc disagrees with the code, the code wins for *current state*; this brief
> wins for *target intent*.
>
> **Important:** the target architecture is a **git-native registry served over
> dumb HTTP**. An earlier capture briefly explored a single signed `registry.toml`
> root with git-bundle deltas; that approach has been **superseded** and the docs
> are being rewritten to the model below. Anything describing `registry.toml`,
> `bundle-list.toml`, git *bundles*, a `[latest]` table, `[components]`,
> `[capabilities]`, calendar `creation_token` ordering, or percentage-based
> rollouts is **removed** from the target. If those terms appear in this plan set,
> treat them as pre-cutover historical context unless
> [`../../registry/current-state.md`](../../registry/current-state.md) or
> [`TODO.md`](./TODO.md) explicitly says they are still live.
>
> **Superseding security policy:** this capture's one-key registry/narinfo
> design predates RFC-0017. Production publication uses separate registry and
> cache signing roles. Follow
> [`../../maintainers/trust-model.md`](../../maintainers/trust-model.md) and
> [`../../registry/signing-and-trust.md`](../../registry/signing-and-trust.md)
> for current policy.
>
> **Audience:** implementers, architects, engineers, and the doc-authoring agents.

---

## 1. Glossary

- **AOS / `apm` / `apr`** — ANDYL OS; the package-management CLI (`apm` ⇒ implicit
  `package`); the registry CLI (`apr` ⇒ implicit `package registry`). Same binary,
  argv[0] dispatch (`crates/aos/src/main.rs`).
- **Registry (target)** — a **bare git repository, sha256 object format, served as
  static files over dumb HTTP**. The package metadata *is* the git tree content.
- **Channel** — a named release line (e.g. `stable`, `testing`). Modeled as a git
  **branch** (`refs/heads/<channel>`) whose head is the rollout **frontier**, and
  as **256 signed partition tag objects** (`/channels/<name>/00..ff`) for rollout.
- **Partition / bucket** — one of exactly **256** channel partitions, one byte (`00`–`ff`). A
  consumer deterministically self-selects one bucket. The publisher advances
  partitions independently to control rollout.
- **Release** — an immutable semver version (e.g. `1.1.0`, `1.0.0-beta+exp.sha.5114f85`,
  **no `v` prefix**). A signed git **tag** (`refs/tags/<semver>`) → commit, with its
  object store under `/releases/<major>/<minor>/<patch…>/`.
- **Signed tag object** — an annotated git tag carrying an SSH-format **Ed25519**
  signature. It carries **no structured payload** (no TOML, no `[[caches]]`, no
  `valid_until`) — only the standard git tag fields plus an optional freeform
  human message. Channel partition tags and release tags are signed.
  `tag → tag → commit` chains are used (channel partition → semver → commit).
- **Full pack** — a self-contained `pack-<sha256>.pack` (+ `.idx`) at every
  major/minor (`X.Y.0`) release.
- **Delta pack** — a **thin** `delta-<from-semver>.pack` carrying only objects
  introduced between two release commits; completed on the client with
  `git index-pack --fix-thin`.
- **Frontier** — the newest release any channel partition targets; the value of the
  channel's branch head.
- **Dumb HTTP** — git's static-file transport (`HEAD`, `info/refs`, loose objects,
  `objects/info/packs`, `objects/info/alternates`).

---

## 2. Current state (as-is) — historical summary

This section is retained as the pre-cutover baseline used to write the plan. It
does **not** describe the current implementation after the registry PR work. For
as-built status, use
[`../../registry/current-state.md`](../../registry/current-state.md) and
[`TODO.md`](./TODO.md). At the time this brief was written:

- A registry is a git repo of **nested** package TOMLs (`PackageToml` in
  `crates/aos-package/src/registry/parse.rs:14-70`, written by `build_package_toml`
  `registry_ops.rs:595-781`) plus `closures/<hash>` adjacency files;
  `PackageMeta` (`types.rs:43-77`) is the flattened in-memory projection.
- Distribution is via **git bundles** + a `bundle-list.toml` manifest the *consumer*
  parses (`registry/bundle.rs`); the producer side was a stub (`apr bundle` =
  `git bundle create`; no manifest writer; no upload).
- Versions are **calendar tags** (`vYYYY.MM[.P]`) ordered by `creation_token`
  (`state.rs version_to_token`); tracking modes are commit/branch/tag/semver
  (`types.rs TrackingMode`); selection is `pick_bundles` (`update.rs`).
- Signing already uses **SSH-format Ed25519** git signatures (`apr sign` =
  `git commit -S`; verified via `git verify-commit` + allowed_signers in
  `security.rs`), with TOFU + `trusted-keys.d/<registry>.pub`.

The **target** keeps the Ed25519/SSH signing primitive and the package-TOML tree
content, and replaces *everything about distribution and rollout* with the
git-native model below.

---

## 3. Target architecture — overview

The registry is a **bare git repository (sha256) published as static files**, which
makes it simultaneously:

- a **superset of git dumb HTTP** — a stock `git clone <url>` works (channels are
  branches, releases are tags), using loose objects + conventionally-named full
  packs; and
- a **superset of the Nix binary cache** — the origin MAY serve a Nix binary cache
  (`nix-cache-info`/narinfo/`nar`); the cache/substituter location lives in the
  committed repo-root `registry.toml` `[[caches]]` (a tree file authenticated
  transitively by the signed tag), with the consumer's client-side `registries.d`
  as an optional override (or the origin itself), never advertised in the signed
  tag itself.

The AOS client additionally uses the `/channels` partition tags (signed, bucketed
rollout) and the thin `delta-*.pack`s (cheap incremental fetch). These ride
*alongside* the standard git surface without conflicting.

Design philosophy: **make publishing as expensive as possible so consumption is as
cheap as possible** (asymmetric cost — the producer pays once, every consumer
benefits).

---

## 4. HTTP / object layout & CDN cache policy

```
/                                  ← bare git repo root (dumb HTTP)
  HEAD                             ← "ref: refs/heads/<default-channel>" (e.g. stable)   [low TTL]
  info/refs                        ← update-server-info: refs/heads/<channels> + refs/tags/<semvers> [low TTL]
  objects/                         ← THE single object store
    info/packs                     ← typically empty (full packs live per-release)        [low TTL]
    info/alternates                ← RELATIVE "../releases/<…>/objects/" entries (one ../), [low TTL]
                                       newest→oldest; host-independent; pack discovery + release index
    <xx>/<62-hex>                  ← ALL loose objects (every release), sha256 2/62 split  [immutable, high TTL]
  channels/
    <name>/                                                                              [low TTL]
      00 .. ff                     ← 256 SIGNED tag objects (one byte; tag name == <name>),
                                       each → a semver tag (rollout partitions)
  releases/
    <major>/<minor>/<patch[-prerelease][+build]>/                                        [long TTL, immutable]
      objects/                              ← PACKS ONLY (no loose objects here)
        info/packs                           ← lists this release's pack-<sha256>.pack
        pack/pack-<sha256>.pack (+ .idx)     ← self-contained "full" pack at X.Y.0 anchors
        pack/delta-<from-semver>.pack         ← THIN deltas; AOS-only; NOT listed in info/packs
```

CDN policy (explicit requirements):
- `/channels/**` — **MUST** be low TTL (fast rollout updates).
- `/releases/**` — **MAY** be long TTL (releases are immutable after publish).
- `/objects/info/**` and per-release `objects/info/packs` — **MUST** be low TTL
  (`packs`, `alternates`, `info/refs`, `HEAD` change on publish).
- All other `/objects/**` (loose objects, packs) — immutable; **MAY** have very
  high TTL.

---

## 5. Ref model — three layers

| Path / ref | What | Signed? | Consumer |
|---|---|---|---|
| `HEAD` | symref → `refs/heads/<default-channel>` | no | stock + AOS |
| `refs/heads/<channel>` | **channels are branches**; head = **frontier** (newest release any partition targets) | no (ref pointer) | stock git convenience |
| `refs/tags/<semver>` | release: signed tag → commit | **yes** | stock (`verify-tag`) + AOS |
| `/channels/<name>/<00..ff>` | 256 signed partition tag objects (name == channel) → semver tag | **yes** | AOS rollout only |

**Trust chain:** AOS verification is `signed partition tag → signed semver tag →
commit`, checking both the signature **and** the embedded tag-name field against the
expected name (channel name under `/channels/*`, semver under `/releases/*`) — this
binds a tag object to its serving path and prevents cross-serving. Branch refs are
**unsigned convenience pointers**, never part of the trust chain; stock-git users can
still `git verify-tag <semver>` because the release tags are the signed objects.

---

## 6. Channels & rollouts

- A channel exposes exactly **256** partition files `/channels/<name>/00..ff` (one byte), each an
  independently-signed tag object (tag name == channel name) pointing at a semver
  tag. There **must always be 256**; if one is missing a client **may** use another
  (deterministic probe-forward `(bucket+1) mod 256`).
- **Consumer bucket selection** is deterministic and persisted (e.g.
  the low byte of `sha256(machine_id)` — i.e. `mod 256` — written once) so a host does not flap between buckets.
- **Publisher-controlled rollout:** to roll a new release to N/256 of the fleet, point
  N partitions at the new semver tag and leave the rest on the prior release. This
  *answers "where does the rest of the fleet go"* explicitly — the un-advanced
  partitions still name the prior release. Advance partitions as confidence grows;
  completion = all 256 point at the new release.
- **Branch head = frontier:** `refs/heads/<channel>` points at the commit of the
  newest release any partition targets (the rollout target). Implication: stock
  `git pull <channel>` always gets the frontier (no rollout protection) — acceptable,
  because rollout is an AOS-fleet concept, not a git-clone concept.
- **Anti-rollback:** a consumer keeps a monotonic floor (never moves to a release
  older than its current one). Aborting a bad rollout is **fix-forward** (publish a
  newer release and point partitions at it), never partition-decrement (the floor
  would block that anyway).

---

## 7. Releases & versioning

- Versions are **standard semver, no `v` prefix**: `1.1.2`, `1.1.0-alpha.1`,
  `1.0.0-beta+exp.sha.5114f85`. Ordering and precedence follow semver rules
  (the calendar/`creation_token` scheme is gone from the target).
- A release is a signed tag `refs/tags/<semver>` → commit. Its object store lives at
  `/releases/<major>/<minor>/<patch…>/` where the third segment is everything after
  `major.minor` (e.g. `1.0.0-beta+exp.sha.5114f85` → `/releases/1/0/0-beta+exp.sha.5114f85/`).
- Releases are **immutable** once published (long CDN TTL).

---

## 8. Object store & dumb-HTTP details

- **sha256 for all git operations** (`git init --object-format=sha256`); loose object
  path is the first 2 / remaining 62 hex chars of the 64-char sha256.
- **`info/refs` + `HEAD`** make the repo a valid dumb-HTTP bare repo; regenerated via
  `git update-server-info` on every publish.
- **`objects/info/alternates`** lists every `/releases/*/objects/` dir as a
  **relative** path (`../releases/<…>/objects/`), newest→oldest. Git resolves relative
  alternates against the repo's `objects/` URL, so the file is **byte-identical across
  every endpoint** (CDN, mirror, localhost) — no hostname is baked in. The relative
  depth is **one** `../` (resolved relative to `objects/`, where `../` strips the
  `objects` segment to reach the repo root), **not two**. Use `info/alternates` (works
  for both dumb-HTTP and local-filesystem access; the dumb-HTTP walker reads
  `http-alternates` then falls back to `alternates`), not absolute `http-alternates`
  URLs.
- **ALL loose objects are centralized** at the root `/objects/<xx>/<…>` (every
  release) — the guaranteed completeness fallback. The per-release
  `/releases/*/objects/` dirs are **pack-only**; the alternates therefore serve **pack
  discovery + the release index**, not object completeness.

---

## 9. Packs & the delta scheme

**Guaranteed, walkable delta graph** (the producer commits to producing exactly
these, so clients can plan):

- **Every `X.Y.0` (major or minor)** release ships a self-contained **full pack**
  `pack-<sha256>.pack` (+ `.idx`).
- **Every major `X.0.0`** additionally ships `delta-<(X-1).0.0>.pack` (from the last
  major).
- **Every minor `X.Y.0` (Y>0)** additionally ships `delta-<X.(Y-1).0>.pack` (last
  minor) and `delta-<X.0.0>.pack` (current major).
- **Every patch `X.Y.Z` (Z>0)** ships `delta-<X.Y.(Z-1)>.pack`,
  `delta-<X.Y.(Z-2)>.pack`, `delta-<X.Y.(Z-3)>.pack` (last 3 patches, where they
  exist) and `delta-<X.Y.0>.pack` (current minor). Patch releases have **no** full pack.

**Client resolution** (current C → target T): prefer a `delta-<B>.pack` at T whose
base B the client retains; else walk releases backward until a usable delta or a full
pack is found; else fetch a full pack; else fall back to **loose objects** over dumb
HTTP (always correct). Cross-major jumps degrade to "minor-base full pack + walk".

**Client retention:** a client on `X.Y.Z` keeps object trees for at least `X.0.0`
(current major), `X.Y.0` (current minor), and `X.Y.Z` (current patch). This is
co-designed with the delta scheme so a delta base is always present.

**Graceful degradation for stock git:** a stock dumb clone of a patch release pulls
the minor-base full pack (via `info/alternates`) plus the patch's new objects from the
central root `/objects/` loose store — no thin packs needed.

---

## 10. Pack generation (producer) & zstd

- **No git bundles** (those carry refs/prereqs; refs are replaced by signed tag
  objects).
- **Deltas:** `git pack-objects --revs --thin` reading `"<to>\n^<from>\n"` →
  objects in `<to>` not `<from>`, deltas may reference `<from>`'s objects. Client
  completes with `git index-pack --fix-thin`.
- **Full packs:** `git pack-objects --revs` (non-thin) over the release commit →
  emit directly as `pack-<sha256>.pack` + `.idx`.
- **Expensive-producer flags:** `--no-reuse-object --no-reuse-delta --window=<large,
  e.g. 350> --depth=<moderate, e.g. 50> --threads=0`. Window is the free lever; cap
  **depth** because deep delta chains cost the *consumer* CPU to reconstruct. The
  producer may also try multiple delta bases and ship the smallest.
- **zstd (the working trick):** git's pack format hard-codes zlib per object, so
  zstd-ing a `--compression=9` pack is near-useless (already DEFLATEd). Instead emit
  `git pack-objects --compression=0` (level-0 = "stored", valid zlib framing, **no**
  entropy coding, but git's **delta encoding is still applied**), then
  `zstd --ultra -22 --long=27` the whole `.pack`. zstd then does the entropy coding
  over the delta-encoded stream, beating zlib-9, while the pack stays git-valid.
  Serve `.pack.zst`; client `zstd -d | git index-pack --fix-thin`. A zstd **trained
  dictionary** across a release line's small delta packs is an optional further win.
- Ship `.idx` only for self-contained **full** packs; thin delta packs are
  `.pack[.zst]` only (the client's `--fix-thin` builds the idx).

---

## 11. Signing & trust

- **Signed tag objects** (SSH-format Ed25519, reusing the existing `apr sign` /
  `security.rs` primitives and `parse_signing_key` `name:Ed25519:<base64>` format,
  TOFU + `trusted-keys.d`). Both channel partition tags and release tags are signed.
- **Name-binding verification** (per §5): signature valid **and** embedded tag-name
  field == expected path name; verify the whole `tag → tag → commit` chain.
- **One Ed25519 key** continues to serve git signing; the Nix-cache narinfo `Sig:`
  (if the origin also serves NARs) can reuse the same key (separate signature object).
- **Tags carry no in-band metadata** — no `valid_until` (or any TOML). **Freshness**
  is a transport + consumer concern: low CDN TTL on `/channels` (and `info/refs`,
  `objects/info`), plus the consumer's own max-staleness policy and the monotonic
  anti-rollback floor. (Trade-off: weaker than an in-band signed expiry against a
  *frozen-but-validly-signed* mirror — tracked in open questions.)
- **Branch refs are unsigned**; trust derives from the signed tags only.

---

## 12. Stock git dumb-HTTP compatibility

The repo is a valid bare dumb-HTTP git repo; the AOS layer is additive. To be
transparently clonable, the origin serves the standard shim: `HEAD`, `info/refs`
(`update-server-info`), and a relative `objects/info/alternates`. Requirements/edges:

- **`full.pack` is named `pack-<sha256>.pack`** (+ `.idx`) and listed in the
  **release's** `objects/info/packs` (discovered via the root `info/alternates`) so
  stock dumb git uses it. (We drop the semantic `full.pack` name entirely — no
  duplicate.)
- **Thin `delta-*.pack`s are NOT listed in `info/packs`** (a stock dumb client can't
  apply a thin pack); AOS clients discover them by the `delta-<semver>` convention.
- **Channels are branches**, **releases are tags**, **`HEAD` = the default channel**
  (e.g. `stable`); the 256 partition tag objects live outside the ref namespace at
  `/channels/*` and are AOS-only.
- **Loose objects guarantee correctness** for any stock client; conventionally-named
  full packs restore speed.
- **sha256 + dumb HTTP** requires a client git that supports sha256 (no capability
  negotiation in dumb protocol).

---

## 13. Nix binary cache superset — AOT static on the CDN

The registry's Nix binary cache is **dumb static files on the HTTP CDN**, generated
**ahead-of-time at publish** — there is **no server** at serve-time. Like the git
objects/packs and the channel/release files, the cache artifacts are pre-built and
uploaded: `{cache-base}/nix-cache-info`, `{cache-base}/<storehash>.narinfo`,
`{cache-base}/nar/<…>.nar.zst`. A stock `nix` (or `apm`) consumes them as an ordinary
static binary cache — the strict superset — with zero dynamic serving. This is the
registry's core principle: **as much as possible done ahead of time, so serving scales
as dumb static distribution.**

- **Reuse, don't run.** AOS already has the narinfo formatting/signing **logic** —
  `aos-core/nar/info.rs` (`NarInfo` format/parse), `aos-server/narinfo.rs`
  (`format_narinfo`), `aos-server/sign.rs` (`NarInfoSigner`: Ed25519 fingerprint +
  `Sig`), `aos-server/compress.rs` (`compute_file_hash_size` for `FileHash`/`FileSize`).
  The **producer reuses these as a library** to *generate the static AOT files*. The
  live `aos-server` cache (a host serving its **own** Nix store, nix-serve-style) is a
  **different use case** — the registry never runs it.
- **Consumer is done.** `aos-package/download.rs` is already narinfo-driven (commit
  `7149acf6`) and consumes a dumb static narinfo cache as-is.
- **Pointer.** The cache base URL is the committed git-repo-root `registry.toml`
  `[[caches]]` (authenticated via the signed tag — §14), client-side `registries.d`
  override optional; never in the tag. Narinfo signing reuses the one Ed25519 key.

So the **producer work** (WS-06) is the **AOT generation + CDN upload** of the static
narinfo/`nar`/`nix-cache-info` files, reusing the existing format/sign logic — not a
greenfield emitter, and **not** a running server.

---

## 14. Tag payload, repo-tree config & trust files

**Signed tags carry no structured payload** — pure signed pointers: the standard git
tag fields (object, type, the `tag` NAME, tagger) + the Ed25519 signature + an optional
freeform human message. No TOML, `[meta]`, `schema`, `valid_until`, or `[[caches]]`.

Registry-level config instead lives as **committed files in the git tree**,
authenticated transitively by the signed tag (tag → commit → tree → file) — not in the
tag, and not (primarily) client-side:

- **`registry.toml`** (git-repo-**root**; the existing `RegistryRootConfig`): `[registry]`
  name/description + `[[caches]]`. The signing pubkey is **removed** from it (a key
  inside a file authenticated by that key is circular for bootstrap). This is the
  git-repo-root file, **not** the removed intermediate *signed-HTTP-root* `registry.toml`
  (§15).
- **`keys.toml`** (git-repo-root): the **trust roster** — active signing key(s) + a
  revoked list. Bootstrap trust is TOFU-pinned **client-side** (`trusted-keys.d/<registry>.pub`).
  The model is **≥2 overlapping active keys** — the git lineage (signed tag → commit →
  parent chain) provides the continuity, so no separate offline-root tier is needed.
  **Rotation** = publish `keys.toml` listing old + new keys (overlap window) in a tag
  signed by a currently-trusted key; consumers verify and pin the new key, then the old
  key is dropped on a later publish. **Planned retirement** = list the key under
  `revoked`, signed by one of the *other* overlapping active keys. **Compromise** is
  handled **out-of-band**: the consumer re-pins via `trusted-keys.d` (`apr trust`) — an
  in-repo key can't credibly revoke itself, and compromise is rare enough that the
  out-of-band path is acceptable. (Decided — was §16.)

The committed **tree** is therefore `registry.toml` + `keys.toml` +
`packages/<x>/<name>.toml` + `closures/<hash>` + `.gitattributes` — distinct from the
HTTP-served object store (`/objects`, `/channels`, `/releases`); see the reference doc
`repo-layout.md`. Freshness and cache/substituter selection stay out of the tag (§11, §13).

---

## 15. Removed from the target (do not document as target)

The intermediate design's **signed-HTTP-root `registry.toml`** (a mutable origin file
with `[latest]` / `[channels]` / `[components]` / `[capabilities]` / `[[bundles]]` /
`[signature]`) · `bundle-list.toml` · git **bundles** · the `[latest]` pointer ·
`[components]` · `[capabilities]` · the percentage-based rollout, the
`[channels.<name>.rollout]` sub-block, and `previous_tag`/baseline+candidate framing
(replaced by 256 partitions) · calendar versioning and `creation_token` ordering
(replaced by semver + git ancestry) · the by-hash `[[bundles]]`/`[[deltas]]` index
(replaced by the git object store + `info/alternates`) · the **tag-message TOML**
(`[meta]` / `schema` / `valid_until`) and tag-embedded **`[[caches]]`** (tags carry no
payload) · the **signing pubkey inside `registry.toml`** (key trust is `keys.toml` +
TOFU) · **per-release loose objects** (all loose objects are centralized in the root
`/objects/`; `/releases/*/objects/` are pack-only) · **absolute `http-alternates`**
URLs (replaced by **relative `info/alternates`** entries, host-independent).

> **Kept (not removed):** the **git-repo-root `registry.toml`** (`[registry]`
> name/description + `[[caches]]`, the existing `RegistryRootConfig`) is a committed
> tree file, authenticated via the signed tag — see §14 and `repo-layout.md`. Do not
> conflate it with the removed signed-HTTP-root file above.

---

## 16. Open questions / to confirm in implementation

1. sha256 dumb-HTTP clone tested against target git client versions (no capability
   negotiation).
2. Exact `pack-objects` window/depth and zstd level defaults (and whether to ship a
   trained dictionary per release line).
3. Bucket-selection input (`machine_id` source) and the probe-forward fallback order.
4. Whether `apr` grows a single `apr release`/`apr publish` command that does the
   whole pipeline (commit → tag/sign → pack/delta/zstd → update-server-info →
   advance partitions → upload) and whether upload backends are pluggable.
5. Consumer freshness/staleness policy now that there is no in-band `valid_until`
   (max-age before warn/refuse), and the frozen-but-validly-signed-mirror trade-off.
6. Confirm dumb-HTTP git follows a relative `info/alternates` (one `../`) across the
   target client versions, and whether any client needs `http-alternates` too.
7. Migration from the existing bundle/`creation_token` registries (clean break vs
   shim) — and whether the NAR cache superset (origin-served narinfo, located via
   the committed `registry.toml` `[[caches]]` with client-side `registries.d` as an
   optional override) ships in the same milestone or later.
8. **(Decided)** `keys.toml` trust model = **≥2 overlapping active keys** (rotation via
   overlap; the git lineage gives continuity, no offline-root tier). Planned retirement
   is an in-repo `revoked` entry signed by another overlapping key; **compromise** is
   handled **out-of-band** (consumer re-pins via `trusted-keys.d` / `apr trust`). Still
   open only: whether the roster is a standalone `keys.toml` or a `[keys]` block in
   `registry.toml` (leaning standalone `keys.toml`).

---

## 17. Document map (authoring specs)

Reference set (`docs/registry/`, target state) and plan set
(`docs/plans/registry/`, gap → target). Every doc: precise, structured, with tables /
ASCII diagrams / TOML & shell examples; label **CURRENT** vs **TARGET**; cite current
code as `path:line`; cross-link siblings.

**`docs/registry/`:**
- `README.md` — purpose, audience, glossary, doc index, one-paragraph overview.
- `architecture.md` — git-repo-over-dumb-HTTP; superset of git **and** Nix; the three
  ref layers; how `apm` and stock git both consume; asymmetric-cost philosophy (§3–5).
- `current-state.md` — the as-is code (§2); **light edit only** — keep it an accurate
  description of today's bundle/`creation_token` implementation, and update any
  forward-looking "target" sentences to point at this git-native model.
- `http-layout.md` — the full HTTP/object layout, CDN TTLs, object store, `info/refs`/
  `HEAD`/ relative `info/alternates` (centralized loose objects; pack-only release
  dirs), **and a "stock git dumb-HTTP compatibility" section** (§4, §8, §12).
- `repo-layout.md` — the committed git **tree** content (`registry.toml` with
  `[[caches]]`, `keys.toml`, `packages/<x>/<name>.toml`, `closures/<hash>`,
  `.gitattributes`) and the **tree ↔ HTTP** mapping; distinct from the served object
  store (§4, §8, §14).
- `versioning-and-channels.md` — semver (no `v`), channels-as-branches, frontier
  head, the 256-partition rollout, bucket selection, anti-rollback (§5–7).
- `packs-and-deltas.md` — pack-objects, thin vs full packs, the delta scheme graph,
  client resolution + retention, and zstd (§9–10).
- `signing-and-trust.md` — signed tag objects (no in-band payload), name-binding,
  `tag→tag→commit`, sha256, unsigned branch refs, freshness via CDN + consumer policy
  (no `valid_until`), anti-rollback, and the **`keys.toml` trust roster** (TOFU
  bootstrap, rotation/revocation, no pubkey in `registry.toml`) (§11, §5, §14).
- `publishing.md` — the producer pipeline end-to-end (commit → sign → pack/delta/zstd
  → update-server-info → advance partitions → upload), CDN/atomicity, concurrency
  (§10, §4, §6).
- `nix-cache-compatibility.md` — the Nix binary-cache superset; cache/substituter
  location is the **committed git-repo-root `registry.toml` `[[caches]]`** (or the
  origin), with client-side `registries.d` as an override — not a tag-embedded
  `[[caches]]` (§13, §14).
- `apt-comparison.md` — updated comparison: the design is now git-native + dumb-HTTP;
  keep the signed-flat-file/`pool`/phased-rollout lineage, map bundles/pdiff →
  git packs/thin-delta scheme, percentage rollout → 256 partitions.

**`docs/plans/registry/`:**
- `README.md` — plan overview, target summary, milestone roadmap, sequencing.
- `design-brief.md` — **this file**.
- `gap-analysis.md` — current code (bundles/`creation_token`/`registry.toml`-config)
  → git-native target; enumerate gaps, map to workstreams.
- `workstream-01-object-store.md` — sha256 bare repo, dumb-HTTP layout, `info/refs`/
  `HEAD`/ relative `info/alternates`/`update-server-info`, centralized root loose
  store, pack-only per-release object dirs.
- `workstream-02-pack-delta-pipeline.md` — pack-objects thin/full, the delta scheme,
  zstd, expensive-producer tuning.
- `workstream-03-channels-rollouts.md` — 256 signed partition tags, channels-as-
  branches/frontier, bucket selection, publisher rollout control.
- `workstream-04-signing-trust.md` — signed tag objects (no in-band payload),
  name-binding, sha256, freshness/anti-rollback/fix-forward (no `valid_until`).
- `workstream-05-consumer.md` — consumer resolution (bucket → channel tag → semver
  tag → commit), delta walk, retention, verification, and the Nix cache superset
  (committed `registry.toml` `[[caches]]`, client-side `registries.d` override /
  origin narinfo).
- `open-questions.md` — §16 plus risks and migration strategy.
