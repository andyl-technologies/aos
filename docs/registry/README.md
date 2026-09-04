# AOS Package Registry — Reference Documentation

This directory is the **reference documentation set** for the AOS package
registry: the **git-native metadata repository, served over dumb HTTP**, that
`apm` (the AOS package manager) consumes and that `apr` (the AOS Package
Registry CLI) publishes. These reference docs describe the **target design**;
where the current code differs, each doc labels **CURRENT** vs **TARGET** and
cites code as `path:line`. The companion implementation plan that turns the
current state into the target lives under
[`../plans/registry/`](../plans/registry/README.md).

> **Authoritative intent.** Every doc in this set is derived from, and must not
> contradict, the design brief:
> [`../plans/registry/design-brief.md`](../plans/registry/design-brief.md).
> Rule of precedence: **for current state, the code wins; for intent, the brief
> wins.**

---

## One-paragraph overview

An AOS registry is a **bare git repository in sha256 object format, published as
static files over dumb HTTP**. The package metadata *is* the git tree content,
so the registry is simultaneously a **superset of git's dumb-HTTP transport** (a
stock `git clone <url>` works — **channels are branches**, **releases are tags**)
and a **superset of the Nix binary cache** (the origin MAY serve
`nix-cache-info` / `<storehash>.narinfo` / `nar/`; the substituter location lives
in the committed `registry.toml` `[[caches]]`, with the consumer's client-side
`registries.d` as an optional override (or the origin itself), **never**
advertised in signed tags). Release lines are
**standard semver, no `v` prefix**; a **channel** (`stable`, `testing`) is a git
branch whose head is the rollout **frontier** plus **256 signed partition tag
objects** (`/channels/<name>/00..ff`) that drive bucketed, publisher-controlled
rollout. Distribution rides on a **guaranteed delta graph**: every `X.Y.0`
release ships a self-contained **full pack** plus `.idx`, and every release ships
a small set of **thin delta packs** (`delta-<from-semver>.pack.zst`) that the
client decompresses and indexes locally; **all objects also exist loose** as the
correctness fallback. Trust is rooted in an **out-of-band anchor** (baked into
the AOS image, or pinned) and evolves through a committed **`keys.toml` roster**
of SSH-format Ed25519 maintainer keys; releases are verified by a `signed
partition tag → signed semver tag → commit` chain (signed by **any active roster
key**) with **name-binding** (the embedded tag-name must match the serving path),
and rotation/revocation reaches machines **in-band** on their next sync. The
guiding philosophy is **asymmetric cost: make publishing as
expensive as possible so consumption is as cheap as possible** — the producer
pays once, every consumer benefits.

---

## Purpose & scope

This reference set answers, for the AOS registry's **target state**:

- *What is on the wire* — the HTTP/object layout under `/`, `/channels/**`, and
  `/releases/**`; the single root sha256 loose-object store; `info/refs`,
  `HEAD`, and the relative `objects/info/alternates`; and the CDN TTL policy.
- *How clients consume it* — stock `git clone` over dumb HTTP, and the AOS path
  (deterministic bucket → channel partition tag → semver tag → commit, then a
  delta-pack walk with loose-object fallback).
- *How it is versioned & rolled out* — semver releases, channels-as-branches
  with a frontier head, the 256-partition rollout, deterministic bucket
  selection, and anti-rollback / fix-forward.
- *How it is trusted* — an out-of-band anchor (image-baked or pinned) plus a
  committed `keys.toml` roster of Ed25519 maintainer keys, signed tag objects,
  any-active-key verification, name-binding, the `tag → tag → commit` chain,
  and required AOS-TUF metadata for moving-ref syncs (`tuf/root.json`,
  `targets.json`, `snapshot.json`, `timestamp.json`) with role thresholds,
  catalog hashes, and signed expiry.
- *How it is published* — the producer pipeline (commit → sign tag →
  pack/delta/zstd → `update-server-info` → advance partitions → upload), CDN
  atomicity and concurrency.
- *How it relates to prior art* — a structured comparison to the APT repository
  format, mapping flat-file indices/pdiff → git packs/thin-delta scheme and the percentage
  rollout → 256 partitions.

It does **not** specify the implementation tasks; those are enumerated in the
[plan set](../plans/registry/README.md).

---

## Audience map

| You are a… | Start here | Then read |
|---|---|---|
| **User** running `apm` / `apr` | [versioning-and-channels.md](versioning-and-channels.md), [publishing.md](publishing.md) | [signing-and-trust.md](signing-and-trust.md) |
| **Dev-shell user** wanting a Nix substituter | [nix-cache-compatibility.md](nix-cache-compatibility.md) | [http-layout.md](http-layout.md) |
| **Implementer** writing producer/consumer code | [current-state.md](current-state.md), [http-layout.md](http-layout.md) | [packs-and-deltas.md](packs-and-deltas.md), the [plan workstreams](../plans/registry/README.md) |
| **Architect** evaluating the design | [architecture.md](architecture.md), [apt-comparison.md](apt-comparison.md) | [signing-and-trust.md](signing-and-trust.md), [design brief](../plans/registry/design-brief.md) |
| **Security engineer** assessing trust | [signing-and-trust.md](signing-and-trust.md) | [publishing.md](publishing.md) |

---

## Document index

### Reference set (`docs/registry/`, target state)

| Document | What it covers |
|---|---|
| [README.md](README.md) | This file — purpose, audience map, glossary, doc index, one-paragraph overview. |
| [architecture.md](architecture.md) | Git-repo-over-dumb-HTTP; superset of git **and** Nix; the three ref layers; how `apm` and stock git both consume; the asymmetric-cost philosophy. |
| [current-state.md](current-state.md) | The as-built implementation, grounded in code (`crates/aos-package/`) — git-native sync, signed tags, channel partitions, release orchestration, static origin/cache upload, and object-store helpers. |
| [repo-layout.md](repo-layout.md) | The **committed git tree** a commit contains (`registry.toml` + `keys.toml` + `packages/` + `store/` realisation graph) and the tree↔HTTP mapping - distinct from the served object store. |
| [http-layout.md](http-layout.md) | The full HTTP/object layout, CDN TTLs, the single root sha256 loose-object store, `info/refs` / `HEAD` / relative `info/alternates`, and the stock git dumb-HTTP compatibility surface. |
| [versioning-and-channels.md](versioning-and-channels.md) | Semver (no `v` prefix), channels-as-branches, the frontier head, the 256-partition rollout, deterministic bucket selection, and anti-rollback. |
| [packs-and-deltas.md](packs-and-deltas.md) | libgit2 full packs, pure-Rust thin packs, the guaranteed delta-scheme graph, client resolution + retention, and zstd transport compression. |
| [signing-and-trust.md](signing-and-trust.md) | Signed tag objects (SSH Ed25519), name-binding, the `tag → tag → commit` chain, sha256, unsigned branch refs, AOS-TUF metadata freshness, and anti-rollback. |
| [publishing.md](publishing.md) | The producer pipeline end-to-end (commit → sign → pack/delta/zstd → `update-server-info` → advance partitions → upload), CDN atomicity, and concurrency. |
| [nix-cache-compatibility.md](nix-cache-compatibility.md) | The Nix binary-cache superset served by the origin (narinfo / `nix-cache-info` / `nar/`) with a client-side substituter config and Ed25519-signed narinfo. |
| [apt-comparison.md](apt-comparison.md) | A structured APT-format comparison: the signed-flat-file / `pool` / phased-rollout lineage mapped to the git-native + dumb-HTTP design. |

### Plan set (`docs/plans/registry/`, implementation)

| Document | What it covers |
|---|---|
| [README.md](../plans/registry/README.md) | Plan overview, target summary, milestone roadmap, sequencing. |
| [design-brief.md](../plans/registry/design-brief.md) | The captured design decision log (the authoritative grounding source). |
| [gap-analysis.md](../plans/registry/gap-analysis.md) | Current code → git-native target; gaps mapped to workstreams. |
| [workstream-01-object-store.md](../plans/registry/workstream-01-object-store.md) | sha256 bare repo, dumb-HTTP layout, `info/refs` / `HEAD` / relative `info/alternates` / `update-server-info`, the single root loose store and per-release pack-only dirs. |
| [workstream-02-pack-delta-pipeline.md](../plans/registry/workstream-02-pack-delta-pipeline.md) | Archival pack/delta plan; superseded in places by the libgit2 full-pack and Rust thinpack implementation. |
| [workstream-03-channels-rollouts.md](../plans/registry/workstream-03-channels-rollouts.md) | 256 signed partition tags, channels-as-branches / frontier, bucket selection, publisher rollout control. |
| [workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md) | Signed tag objects, name-binding, sha256, metadata freshness, anti-rollback / fix-forward. |
| [workstream-05-consumer.md](../plans/registry/workstream-05-consumer.md) | Consumer resolution (bucket → channel tag → semver tag → commit), delta walk, retention, verification, and the client-side Nix cache superset. |
| [open-questions.md](../plans/registry/open-questions.md) | Open decisions, risks, and migration strategy. |

---

## How the pieces fit (orientation diagram)

The registry is **one bare git repo published as static files**. Stock git and
the AOS client read the *same* origin; the AOS layer (`/channels` partition tags +
thin `delta-*.pack`s) is **additive** and rides alongside the standard git
surface without conflicting.

```
                          ┌──────────────────────────────────────────────┐
                          │       HTTP origin = bare git repo (sha256)    │
                          │              served as static files            │
                          │                                                │
  git clone <url> ───────▶│  /HEAD                ref: refs/heads/stable   │
  (dumb HTTP)             │  /info/refs           branches + semver tags    │
  channels=branches       │  /objects/<xx>/<62>   ALL loose objects (root) │
  releases=tags           │  /objects/info/packs  full packs only          │
                          │  /objects/info/alternates  packs + rel. index   │
                          │                                                │
  apm (AOS rollout) ─────▶│  /channels/<name>/00..ff 256 SIGNED partition tags│
  bucket→tag→tag→commit   │  /releases/<M>/<m>/<p>/objects/  PACK-ONLY store  │
  + thin delta packs      │     pack-<sha256>.pack + .idx  full at X.Y.0    │
                          │     delta-<from>.pack.zst       THIN, AOS-only  │
                          │                                                │
  nix (substituter) ─────▶│  origin MAY serve (client-side substituter cfg):│
  narinfo + NAR           │     nix-cache-info / <hash>.narinfo / nar/      │
                          └──────────────────────────────────────────────┘
                                          │
          trust roots in an OUT-OF-BAND anchor (image-baked / pinned),
          evolves via the committed keys.toml roster (any active key):
   signed partition tag ──▶ signed semver tag ──▶ commit (Merkle DAG)
   verified with NAME-BINDING (embedded tag name == serving path name)
```

> **CURRENT vs TARGET.** The current code now uses git-native sync for HTTP and
> native git origins, signed release/channel tag objects, sha256 object-store
> helpers, channel partition commands, persisted semver rollout state,
> AOS delta/full/fallback object resolution, static Nix-cache generation, static
> origin upload, and the `apr release` producer orchestrator. See
> [current-state.md](current-state.md) for the grounded as-built state and
> [architecture.md](architecture.md) for the target model.

---

## Glossary

| Term | Definition |
|---|---|
| **AOS** | ANDYL OS. The hermetic-from-source, Nix-based distribution this registry serves. |
| **`apm`** | The package-consumer CLI. It owns installation, profiles, queries, and consumer registry configuration through `apm registry`. |
| **`apr`** | The AOS Package Registry authoring CLI. It owns registry workspaces, signing, package publication, releases, and uploads. |
| **Registry (target)** | A **bare git repository in sha256 object format, served as static files over dumb HTTP**. The package metadata *is* the git tree content. |
| **Channel** | A named release line (e.g. `stable`, `testing`), modeled as a git **branch** (`refs/heads/<channel>`) whose head is the rollout **frontier**, and as **256 signed partition tag objects** (`/channels/<name>/00..ff`) for rollout. |
| **Partition / bucket** | One of exactly **256** channel partitions (`00`–`ff`). A consumer self-selects one bucket on first channel sync from a registry-local random salt, persists the bucket index, and reuses it thereafter. The publisher advances partitions independently to control rollout. |
| **Release** | An immutable **semver** version (e.g. `1.1.0`, `1.0.0-beta+exp.sha.5114f85`, **no `v` prefix**). A signed git **tag** (`refs/tags/<semver>`) → commit, with its object store under `/releases/<major>/<minor>/<patch…>/`. |
| **Frontier** | The newest release any channel partition targets; the value of the channel's branch head (`refs/heads/<channel>`). A stock `git pull <channel>` always gets the frontier. |
| **Signed tag object** | A **pure signed pointer**: an annotated git tag carrying the standard tag fields (object, type, the tag **name**, tagger) + an SSH-format **Ed25519** signature + an OPTIONAL freeform human message — **no structured TOML payload**. Both channel partition tags and release tags are signed; `tag → tag → commit` chains (channel partition → semver → commit) are used. |
| **Full pack** | A self-contained `pack-<sha256>.pack` plus `.idx` shipped at every major/minor (`X.Y.0`) release and listed in `objects/info/packs`; the `.idx` accelerates stock dumb Git, while AOS clients regenerate indexes locally rather than trusting it. |
| **Delta pack** | A **thin** `delta-<from-semver>.pack.zst` carrying only objects introduced between two release commits; AOS-only, **not** listed in `info/packs`, decompressed and completed on the client with libgit2 pack indexing. |
| **Dumb HTTP** | Git's static-file transport: `HEAD`, `info/refs`, loose objects, `objects/info/packs`, `objects/info/alternates` — no server-side smarts required. |
| **`info/alternates`** | `objects/info/alternates` whose entries are **relative** paths `"../releases/<M>/<m>/<patch…>/objects/"` (one `"../"`, newest→oldest). Git resolves relative alternates against the repo's `objects/` URL, so a single `"../"` reaches the repo root; the file is **host-independent** (byte-identical across CDN / mirror / localhost, no hostname baked in) and works for HTTP **and** local-FS (the dumb-HTTP walker reads `http-alternates` then falls back to `alternates`). Because all loose objects are centralized at the root `/objects/`, alternates serve **pack discovery + the release index**, not object completeness. |
| **Name-binding** | The verification rule that a tag object's signature is valid **and** its embedded tag-name field equals the expected serving-path name (channel name under `/channels/*`, semver under `/releases/*`) — binds a tag to its path and prevents cross-serving. |
| **Freshness** | Moving-ref syncs require committed AOS-TUF metadata under `tuf/`; `timestamp.json` is a short-lived signed pointer to the snapshot metadata and its expiry is enforced before catalog extraction. Explicit commit/tag/version pins still verify signatures, hashes, and metadata version floors when TUF exists, but can reproduce old immutable pre-TUF releases without failing solely on missing or expired timestamp metadata. Channel tracking also uses low CDN TTL, consumer max-staleness, and the monotonic anti-rollback floor for partition-pointer behavior. |
| **Anti-rollback** | A consumer keeps a monotonic floor and never moves to a release older than its current one. Aborting a bad rollout is **fix-forward** (publish a newer release, point partitions at it), never partition-decrement. |
| **NAR** | Nix ARchive — the serialized form of a store path; the actual build artifact, stored content-addressed and zstd-compressed (`<hash>.nar.zst`) under the cache location (see **Binary-cache location** below: the committed `registry.toml` `[[caches]]`, the consumer's client-side `registries.d` override, or the origin itself). |
| **Binary-cache location** | The NAR substituter is **not advertised in signed tags**. It lives in the committed git-repo-root `registry.toml` `[[caches]]` (authenticated transitively by the tag → commit → tree → file; see [repo-layout.md](repo-layout.md)), optionally overridden/supplemented by the consumer's client-side `registries.d/<name>.toml` (**higher priority wins**); a relative cache URL means the **origin itself**. An authenticated-but-wrong cache pointer still cannot serve bad bytes — NARs are content-addressed and SHA-256-verified. |
| **`keys.toml`** | A **committed tree file** — the **trust roster** listing the active signing key(s) (`id` + `key`) + a `revoked` list, authenticated via the signed tag. Clients **consume it during sync** as the authoritative git-signature trusted-key set; a tag is valid when signed by **any active roster key**. It does **not** bootstrap trust (a key in a file authenticated by that key is circular) — bootstrap is the out-of-band anchor (see **Baked trust anchor**). AOS-TUF `root.json` adds role membership and thresholds for the release metadata layer, anchored initially to the same out-of-band trusted keys and thereafter to the previous accepted root. **Rotation** = publish `keys.toml` listing old + new keys (overlap window) in a commit signed by a currently-trusted key; clients pin the new key on next sync. **Retirement/revocation** = `apr keys retire` lists the key under `revoked` (signed by another active key) and re-signs affected tags; it propagates **in-band**. See [repo-layout.md](repo-layout.md) and [signing-and-trust.md](signing-and-trust.md). |
| **narinfo / `nix-cache-info`** | The standard Nix binary-cache HTTP surface (`<storehash>.narinfo` per store path; the fixed `nix-cache-info` stub marking an origin as a cache) the origin **MAY** serve for stock `nix` substitution; a separate cache-role key signs narinfo. |
| **Baked trust anchor** | The out-of-band root of trust, delivered by the image rather than discovered on the network. The `aos.apm.registries` module ([modules/base/apm-registries.nix](../../modules/base/apm-registries.nix)) writes `/etc/apm/registries.d/<name>.toml` (with `[registry.signing] public_key` = the first trust key) and `/etc/apm/trusted-keys.d/<name>.pub` (all trust keys) into the image, so `apm` verifies first contact with **no** manual `apr trust pin`. Updating it is an image rebuild; day-to-day key rotation reaches deployed machines in-band via the `keys.toml` roster. |
| **No silent TOFU** | The registry sync path **does not** accept a signing key on first use. Bootstrap trust must arrive out-of-band — the baked anchor, an explicit `apr trust pin`, or the `[registry.signing] public_key` config anchor (consulted only when the store is empty). Signing is enforced by default (absent `[registry.signing]` verifies); `required = false` / `apm registry add --no-verify` is the only opt-out, intended for local dev registries. A `tofu_check` primitive still exists but is exercised only by tests. |
| **`APM_SYSTEM_CONFIG_DIR`** | Environment variable that redirects the `/etc/apm` system config root (and every path derived from it — `registries.d`, `trusted-keys.d`) in both profile scopes, when set to a non-empty absolute path. The supported way to point `apm`/`apr` at a writable fixture tree when developing on non-AOS hosts; relative/empty values are ignored. |

---

## Conventions used across these docs

- **CURRENT** marks behavior that exists in the code today, cited as `path:line`
  (relative to repo root, crate `crates/aos-package/` unless noted).
- **TARGET** marks the intended protocol/design contract from the
  [design brief](../plans/registry/design-brief.md). Some target sections are
  now implemented; check [current-state.md](current-state.md) for as-built
  status.
- All inter-doc links are **relative** so the set is browsable from a checkout or
  a static site.
- Where the code contradicts a brief current-state claim, the docs describe the
  code's actual behavior and the discrepancy is recorded in the relevant doc and
  in [`open-questions.md`](../plans/registry/open-questions.md).
