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
>
> **Superseded model.** An earlier capture explored a single signed
> `registry.toml` root with `bundle-list.toml`, git *bundles*, a `[latest]`
> pointer, `[components]`/`[capabilities]`, calendar `creation_token` ordering,
> and percentage-based rollouts. That approach is **removed** from the target.
> If you encounter those terms here, they belong only to
> [current-state.md](current-state.md) as a description of today's *code* — not
> the target. See design brief §15.

---

## One-paragraph overview

An AOS registry is a **bare git repository in sha256 object format, published as
static files over dumb HTTP**. The package metadata *is* the git tree content,
so the registry is simultaneously a **superset of git's dumb-HTTP transport** (a
stock `git clone <url>` works — **channels are branches**, **releases are tags**)
and a **superset of the Nix binary cache** (the origin MAY serve
`nix-cache-info` / `<storehash>.narinfo` / `nar/`; the substituter location is
the consumer's client-side registry config or the origin itself, **never**
advertised in signed tags). Release lines are
**standard semver, no `v` prefix**; a **channel** (`stable`, `testing`) is a git
branch whose head is the rollout **frontier** plus **256 signed partition tag
objects** (`/channel/<name>/00..ff`) that drive bucketed, publisher-controlled
rollout. Distribution rides on a **guaranteed delta graph**: every `X.Y.0`
release ships a self-contained **full pack** and every release ships a small set
of **thin delta packs** (`delta-<from-semver>.pack`) that the client completes
with `git index-pack --fix-thin`; **all objects also exist loose** as the
correctness fallback. Trust is rooted in **one SSH-format Ed25519 key** that
signs the git tag objects, verified by a `signed partition tag → signed semver
tag → commit` chain with **name-binding** (the embedded tag-name must match the
serving path). The guiding philosophy is **asymmetric cost: make publishing as
expensive as possible so consumption is as cheap as possible** — the producer
pays once, every consumer benefits.

---

## Purpose & scope

This reference set answers, for the AOS registry's **target state**:

- *What is on the wire* — the HTTP/object layout under `/`, `/channel/**`, and
  `/release/**`; the single root sha256 loose-object store; `info/refs`,
  `HEAD`, and the relative `objects/info/alternates`; and the CDN TTL policy.
- *How clients consume it* — stock `git clone` over dumb HTTP, and the AOS path
  (deterministic bucket → channel partition tag → semver tag → commit, then a
  delta-pack walk with loose-object fallback).
- *How it is versioned & rolled out* — semver releases, channels-as-branches
  with a frontier head, the 256-partition rollout, deterministic bucket
  selection, and anti-rollback / fix-forward.
- *How it is trusted* — one Ed25519 key, signed tag objects, name-binding,
  the `tag → tag → commit` chain, and freshness via low CDN TTL + consumer
  max-staleness policy + the monotonic anti-rollback floor (no in-band expiry).
- *How it is published* — the producer pipeline (commit → sign tag →
  pack/delta/zstd → `update-server-info` → advance partitions → upload), CDN
  atomicity and concurrency.
- *How it relates to prior art* — a structured comparison to the APT repository
  format, mapping bundles/pdiff → git packs/thin-delta scheme and the percentage
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
| [current-state.md](current-state.md) | The as-is implementation, grounded in code (`crates/aos-package/`) — today's bundle / `creation_token` / nested-TOML registry, including producer-side gaps. **Light edit only.** |
| [http-layout.md](http-layout.md) | The full HTTP/object layout, CDN TTLs, the single root sha256 loose-object store, `info/refs` / `HEAD` / relative `info/alternates`, and the stock git dumb-HTTP compatibility surface. |
| [versioning-and-channels.md](versioning-and-channels.md) | Semver (no `v` prefix), channels-as-branches, the frontier head, the 256-partition rollout, deterministic bucket selection, and anti-rollback. |
| [packs-and-deltas.md](packs-and-deltas.md) | `git pack-objects`, thin vs full packs, the guaranteed delta-scheme graph, client resolution + retention, and the `--compression=0` + zstd trick. |
| [signing-and-trust.md](signing-and-trust.md) | Signed tag objects (SSH Ed25519), name-binding, the `tag → tag → commit` chain, sha256, unsigned branch refs, freshness without in-band expiry, and anti-rollback. |
| [publishing.md](publishing.md) | The producer pipeline end-to-end (commit → sign → pack/delta/zstd → `update-server-info` → advance partitions → upload), CDN atomicity, and concurrency. |
| [nix-cache-compatibility.md](nix-cache-compatibility.md) | The Nix binary-cache superset served by the origin (narinfo / `nix-cache-info` / `nar/`) with a client-side substituter config and Ed25519-signed narinfo. |
| [apt-comparison.md](apt-comparison.md) | A structured APT-format comparison: the signed-flat-file / `pool` / phased-rollout lineage mapped to the git-native + dumb-HTTP design. |

### Plan set (`docs/plans/registry/`, implementation)

| Document | What it covers |
|---|---|
| [README.md](../plans/registry/README.md) | Plan overview, target summary, milestone roadmap, sequencing. |
| [design-brief.md](../plans/registry/design-brief.md) | The captured design decision log (the authoritative grounding source). |
| [gap-analysis.md](../plans/registry/gap-analysis.md) | Current code (bundles / `creation_token` / `registry.toml`-config) → git-native target; gaps mapped to workstreams. |
| [workstream-01-object-store.md](../plans/registry/workstream-01-object-store.md) | sha256 bare repo, dumb-HTTP layout, `info/refs` / `HEAD` / relative `info/alternates` / `update-server-info`, the single root loose store and per-release pack-only dirs. |
| [workstream-02-pack-delta-pipeline.md](../plans/registry/workstream-02-pack-delta-pipeline.md) | `pack-objects` thin/full, the delta scheme, zstd, expensive-producer tuning. |
| [workstream-03-channels-rollouts.md](../plans/registry/workstream-03-channels-rollouts.md) | 256 signed partition tags, channels-as-branches / frontier, bucket selection, publisher rollout control. |
| [workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md) | Signed tag objects, name-binding, sha256, freshness without in-band expiry, anti-rollback / fix-forward. |
| [workstream-05-consumer.md](../plans/registry/workstream-05-consumer.md) | Consumer resolution (bucket → channel tag → semver tag → commit), delta walk, retention, verification, and the client-side Nix cache superset. |
| [open-questions.md](../plans/registry/open-questions.md) | Open decisions, risks, and migration strategy. |

---

## How the pieces fit (orientation diagram)

The registry is **one bare git repo published as static files**. Stock git and
the AOS client read the *same* origin; the AOS layer (`/channel` partition tags +
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
  apm (AOS rollout) ─────▶│  /channel/<name>/00..ff 256 SIGNED partition tags│
  bucket→tag→tag→commit   │  /release/<M>/<m>/<p>/objects/  PACK-ONLY store  │
  + thin delta packs      │     pack-<sha256>.pack   full pack at X.Y.0     │
                          │     delta-<from>.pack    THIN, AOS-only         │
                          │                                                │
  nix (substituter) ─────▶│  origin MAY serve (client-side substituter cfg):│
  narinfo + NAR           │     nix-cache-info / <hash>.narinfo / nar/      │
                          └──────────────────────────────────────────────┘
                                          │
                  trust roots in ONE SSH-format Ed25519 key:
   signed partition tag ──▶ signed semver tag ──▶ commit (Merkle DAG)
   verified with NAME-BINDING (embedded tag name == serving path name)
```

> **CURRENT vs TARGET.** Today the registry is a git repo of **nested package
> TOMLs** distributed as **git bundles** with a `bundle-list.toml` manifest and
> **calendar `creation_token`** ordering; signing is SSH-format Ed25519 on the
> git **commit** (`apr sign` = `git commit -S`). The sha256 object store, the
> `/channel` partition tags, the thin delta packs, the semver scheme, and the
> origin-served Nix-cache superset are **TARGET**. See
> [current-state.md](current-state.md) for the grounded as-is and
> [architecture.md](architecture.md) for the target.

---

## Glossary

| Term | Definition |
|---|---|
| **AOS** | ANDYL OS. The hermetic-from-source, Nix-based distribution this registry serves. |
| **`apm`** | The package-management CLI front-end. The **same binary** as `aos`, dispatched by `argv[0]`: invoked as `apm …` it implicitly prepends `package …` (`crates/aos/src/main.rs:37`–`68`). |
| **`apr`** | The AOS Package Registry CLI. The same binary again; invoked as `apr …` it implicitly prepends `package registry …` (`crates/aos/src/main.rs:56`–`61`). The `apr` bin alias is declared in `crates/aos/Cargo.toml` (`[[bin]] name = "apr"`). |
| **Registry (target)** | A **bare git repository in sha256 object format, served as static files over dumb HTTP**. The package metadata *is* the git tree content. |
| **Channel** | A named release line (e.g. `stable`, `testing`), modeled as a git **branch** (`refs/heads/<channel>`) whose head is the rollout **frontier**, and as **256 signed partition tag objects** (`/channel/<name>/00..ff`) for rollout. |
| **Partition / bucket** | One of exactly **256** channel partitions (`00`–`ff`). A consumer deterministically self-selects one bucket (e.g. the low byte of `sha256(machine_id)` (i.e. mod 256), persisted). The publisher advances partitions independently to control rollout. |
| **Release** | An immutable **semver** version (e.g. `1.1.0`, `1.0.0-beta+exp.sha.5114f85`, **no `v` prefix**). A signed git **tag** (`refs/tags/<semver>`) → commit, with its object store under `/release/<major>/<minor>/<patch…>/`. |
| **Frontier** | The newest release any channel partition targets; the value of the channel's branch head (`refs/heads/<channel>`). A stock `git pull <channel>` always gets the frontier. |
| **Signed tag object** | A **pure signed pointer**: an annotated git tag carrying the standard tag fields (object, type, the tag **name**, tagger) + an SSH-format **Ed25519** signature + an OPTIONAL freeform human message — **no structured TOML payload**. Both channel partition tags and release tags are signed; `tag → tag → commit` chains (channel partition → semver → commit) are used. |
| **Full pack** | A self-contained `pack-<sha256>.pack` (+ `.idx`) shipped at every major/minor (`X.Y.0`) release; named so stock dumb git uses it and listed in `objects/info/packs`. |
| **Delta pack** | A **thin** `delta-<from-semver>.pack` carrying only objects introduced between two release commits; AOS-only, **not** listed in `info/packs`, completed on the client with `git index-pack --fix-thin`. |
| **Dumb HTTP** | Git's static-file transport: `HEAD`, `info/refs`, loose objects, `objects/info/packs`, `objects/info/alternates` — no server-side smarts required. |
| **`info/alternates`** | `objects/info/alternates` whose entries are **relative** paths `"../release/<M>/<m>/<patch…>/objects/"` (one `"../"`, newest→oldest). Git resolves relative alternates against the repo's `objects/` URL, so a single `"../"` reaches the repo root; the file is **host-independent** (byte-identical across CDN / mirror / localhost, no hostname baked in) and works for HTTP **and** local-FS (the dumb-HTTP walker reads `http-alternates` then falls back to `alternates`). Because all loose objects are centralized at the root `/objects/`, alternates serve **pack discovery + the release index**, not object completeness. |
| **Name-binding** | The verification rule that a tag object's signature is valid **and** its embedded tag-name field equals the expected serving-path name (channel name under `/channel/*`, semver under `/release/*`) — binds a tag to its path and prevents cross-serving. |
| **Freshness** | There is **no in-band signed expiry**. Freshness = a low CDN TTL on `/channel` (and `info/refs`, `objects/info`) + the consumer's own max-staleness policy + the monotonic anti-rollback floor. Trade-off: weaker than an in-band signed `valid_until` against a frozen-but-validly-signed mirror. |
| **Anti-rollback** | A consumer keeps a monotonic floor and never moves to a release older than its current one. Aborting a bad rollout is **fix-forward** (publish a newer release, point partitions at it), never partition-decrement. |
| **NAR** | Nix ARchive — the serialized form of a store path; the actual build artifact, stored content-addressed and zstd-compressed (`<hash>.nar.zst`) under the cache location (the origin itself, or wherever the consumer's client-side config points). |
| **Binary-cache location** | The NAR substituter is **not advertised in signed tags**. It is the **consumer's client-side registry config**, or the **origin itself** when the origin serves the cache surface. Makes the origin a (superset) Nix binary cache without embedding cache config in the trust chain. |
| **narinfo / `nix-cache-info`** | The standard Nix binary-cache HTTP surface (`<storehash>.narinfo` per store path; the fixed `nix-cache-info` stub marking an origin as a cache) the origin **MAY** serve for stock `nix` substitution; narinfo signing **reuses the one Ed25519 key**. |
| **TOFU** | Trust On First Use — a registry's Ed25519 signing key is pinned the first time it is seen unless already admin-provisioned in `trusted-keys.d/<registry>.pub`. |

---

## Conventions used across these docs

- **CURRENT** marks behavior that exists in the code today, cited as `path:line`
  (relative to repo root, crate `crates/aos-package/` unless noted).
- **TARGET** marks the intended design from the
  [design brief](../plans/registry/design-brief.md) that is not yet implemented.
- All inter-doc links are **relative** so the set is browsable from a checkout or
  a static site.
- Where the code contradicts a brief current-state claim, the docs describe the
  code's actual behavior and the discrepancy is recorded in the relevant doc and
  in [`open-questions.md`](../plans/registry/open-questions.md).
- Removed concepts (`registry.toml`, `bundle-list.toml`, git bundles, `[latest]`,
  `[components]`, `[capabilities]`, percentage rollouts, `creation_token`
  versioning, by-hash `[[bundles]]`/`[[deltas]]`) appear **only** in
  [current-state.md](current-state.md), as descriptions of today's code.
