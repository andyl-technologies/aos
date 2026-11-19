# AOS package registry

An AOS registry is a **bare git repository in sha256 object format, published as
static files over dumb HTTP**. The package metadata *is* the git tree content,
so the registry is simultaneously a **superset of git's dumb-HTTP transport** (a
stock `git clone <url>` works; **channels are branches**, **releases are tags**)
and a **superset of the Nix binary cache** (the origin may serve
`nix-cache-info`, `<storehash>.narinfo`, and `nar/`; the substituter location
lives in the committed `registry.toml` `[[caches]]`, with the consumer's
client-side `registries.d` as an optional override, and is never advertised in
signed tags). Release lines are **standard semver, no `v` prefix**; a
**channel** (`stable`, `testing`) is a git branch whose head is the rollout
**frontier** plus **256 signed partition tag objects**
(`/channels/<name>/00..ff`) that drive bucketed, publisher-controlled rollout.
Distribution rides on a **guaranteed delta graph**: every `X.Y.0` release ships
a self-contained **full pack** plus `.idx`, every release ships a small set of
**thin delta packs** (`delta-<from-semver>.pack.zst`) that the client
decompresses and indexes locally, and **all objects also exist loose** as the
correctness fallback. Trust is rooted in an **out-of-band anchor** (baked into
the AOS image, or pinned) and evolves through a committed **`keys.toml` roster**
of SSH-format Ed25519 maintainer keys; releases are verified by a
`signed partition tag -> signed semver tag -> commit` chain with
**name-binding**, and rotation and revocation reach machines in-band on their
next sync. The guiding philosophy is **asymmetric cost: make publishing as
expensive as possible so consumption is as cheap as possible**.

`apm` consumes registries and `apr` publishes them. Operator workflows live in
the [registry user guide](../../users/registry/README.md); this directory
describes how the registry works.

## Pages

| Page | What it covers |
|---|---|
| [architecture.md](architecture.md) | Git-repo-over-dumb-HTTP; the two supersets; the three ref layers; how `apm` and stock git both consume one origin; the asymmetric-cost philosophy. |
| [implementation.md](implementation.md) | Crate and module map: producer, consumer sync and trust assembly, registry state, and NAR downloads. |
| [repository-layout.md](repository-layout.md) | The committed git tree (`registry.toml`, `keys.toml`, `packages/`, the `store/` realisation graph) and the tree-to-HTTP mapping. |
| [http-layout.md](http-layout.md) | The HTTP/object layout, CDN TTLs, the root sha256 loose-object store, `info/refs` / `HEAD` / relative `info/alternates`, and stock git compatibility. |
| [versioning-and-channels.md](versioning-and-channels.md) | Semver, channels-as-branches, the frontier head, the 256-partition rollout, deterministic bucket selection, and anti-rollback. |
| [packs-and-deltas.md](packs-and-deltas.md) | libgit2 full packs, pure-Rust thin packs, the guaranteed delta graph, client resolution and retention, and zstd transport. |
| [signing-and-trust.md](signing-and-trust.md) | Signed tag objects, name-binding, the `tag -> tag -> commit` chain, the trust roster, AOS-TUF metadata freshness, and anti-rollback. |
| [publishing.md](publishing.md) | The producer pipeline end to end, CDN atomicity, and concurrency. |
| [release-stages.md](release-stages.md) | Unpublished release candidates: stage identity and revisions, inventory and resume, discovery boundaries, and retention. |
| [nix-cache.md](nix-cache.md) | The static Nix binary-cache superset, narinfo mapping, cache signing, and substituter configuration. |
| [web-surface.md](web-surface.md) | The registry's static no-JS pages and the in-browser verification SPA. |
| [apt-comparison.md](apt-comparison.md) | Design rationale: the APT repository lineage mapped onto the git-native design. |

The Hub, which indexes and serves registries for many organizations, is
described in [`../hub/`](../hub/README.md).

## Code map

| Crate | Role |
|---|---|
| `crates/registry/aos-registry-format` | Pure-Rust, no-IO, wasm32-clean reader: loose git objects, SSHSIG verification, signed tags, refs, committed TOML schemas, and cache stacks. |
| `crates/registry/aos-registry-client` | Consumer: git sync, trust store and roster pinning, channel resolution, object fetch resolution, registry state. |
| `crates/registry/aos-registry-authoring` | Producer (`apr`): registry operations, signing, packs and deltas, Nix-cache generation, static origin upload, web surface. |
| `crates/registry/aos-registry-web` | The registry web-surface SPA. |
| `crates/packages/aos-package-manager` | `apm` installation, NAR download, and profile management on top of the client. |

## How the pieces fit

The registry is **one bare git repo published as static files**. Stock git and
the AOS client read the *same* origin; the AOS layer (`/channels` partition tags
and thin `delta-*.pack`s) is **additive** and rides alongside the standard git
surface without conflicting.

```text
                          +------------------------------------------------+
                          |      HTTP origin = bare git repo (sha256)      |
                          |             served as static files             |
                          |                                                |
  git clone <url> ------->|  /HEAD                ref: refs/heads/stable   |
  (dumb HTTP)             |  /info/refs           branches + semver tags   |
  channels=branches       |  /objects/<xx>/<62>   ALL loose objects (root) |
  releases=tags           |  /objects/info/packs  full packs only          |
                          |  /objects/info/alternates  packs + rel. index  |
                          |                                                |
  apm (AOS rollout) ----->|  /channels/<name>/00..ff  256 SIGNED tags      |
  bucket->tag->tag->commit|  /releases/<M>/<m>/<p>/objects/  PACK-ONLY     |
  + thin delta packs      |     pack-<sha256>.pack + .idx  full at X.Y.0   |
                          |     delta-<from>.pack.zst      THIN, AOS-only  |
                          |                                                |
  nix (substituter) ----->|  origin MAY serve (client-side substituter):   |
  narinfo + NAR           |     nix-cache-info / <hash>.narinfo / nar/     |
                          +------------------------------------------------+
                                          |
          trust roots in an OUT-OF-BAND anchor (image-baked / pinned),
          evolves via the committed keys.toml roster (any active key):
   signed partition tag --> signed semver tag --> commit (Merkle DAG)
   verified with NAME-BINDING (embedded tag name == serving path name)
```

## Glossary

| Term | Definition |
|---|---|
| **`apm`** | The package-consumer CLI. It owns installation, profiles, queries, and consumer registry configuration through `apm registry`. |
| **`apr`** | The AOS Package Registry authoring CLI. It owns registry workspaces, signing, package publication, releases, and uploads. |
| **Registry** | A bare git repository in sha256 object format, served as static files over dumb HTTP. The package metadata *is* the git tree content. |
| **Channel** | A named release line (e.g. `stable`, `testing`), modeled as a git branch (`refs/heads/<channel>`) whose head is the rollout frontier, and as 256 signed partition tag objects (`/channels/<name>/00..ff`). |
| **Partition / bucket** | One of exactly 256 channel partitions (`00`-`ff`). A consumer selects one bucket on first channel sync from a registry-local random salt, persists the bucket index, and reuses it thereafter. The publisher advances partitions independently to control rollout. |
| **Release stage** | An unpublished candidate with a stable id, compare-and-swap revision, and immutable artifact inventory; distinct from a staging deployment and a published release. |
| **Release** | An immutable semver version (e.g. `1.1.0`, `1.0.0-beta+exp.sha.5114f85`, no `v` prefix): a signed git tag (`refs/tags/<semver>`) pointing at a commit, with its pack store under `/releases/<major>/<minor>/<patch...>/`. |
| **Frontier** | The newest release any channel partition targets; the value of the channel's branch head. A stock `git pull <channel>` always gets the frontier. |
| **Signed tag object** | A pure signed pointer: an annotated git tag carrying the standard tag fields, an SSH-format Ed25519 signature, and an optional freeform message, with no structured payload. |
| **Full pack** | A self-contained `pack-<sha256>.pack` plus `.idx` shipped at every `X.Y.0` release and listed in `objects/info/packs`. AOS clients regenerate indexes locally rather than trusting the served `.idx`. |
| **Delta pack** | A thin `delta-<from-semver>.pack.zst` carrying only objects introduced between two release commits; AOS-only, not listed in `info/packs`, decompressed and completed on the client with libgit2 pack indexing. |
| **`info/alternates`** | `objects/info/alternates` with relative `../releases/<M>/<m>/<patch...>/objects/` entries, newest to oldest. It is host-independent and serves pack discovery and the release index; all loose objects live in the root `/objects/`. |
| **Name-binding** | The rule that a tag object's signature is valid **and** its embedded tag name equals the name expected for its serving path, preventing cross-serving. |
| **Freshness** | Moving-ref syncs require committed AOS-TUF metadata under `tuf/`; `timestamp.json` is a short-lived signed pointer whose expiry is enforced before catalog extraction. Explicit pins still verify signatures, hashes, and metadata version floors. Channel tracking also uses low CDN TTLs, consumer max-staleness, and the anti-rollback floor. |
| **Anti-rollback** | A consumer keeps a monotonic floor and never moves to an older release. Aborting a bad rollout is fix-forward: publish a newer release and point partitions at it. |
| **`keys.toml`** | The committed trust roster of active signing keys and a revoked list, authenticated by the signed tag. Clients pin it during sync as the trusted-key set; it does not bootstrap trust. Rotation publishes old and new keys together in a commit signed by a currently trusted key; `apr keys retire` revokes in-band. |
| **Baked trust anchor** | The out-of-band root of trust delivered by the image: the `aos.apm.registries` module ([`modules/base/apm-registries.nix`](../../../modules/base/apm-registries.nix)) writes `/etc/apm/registries.d/<name>.toml` and `/etc/apm/trusted-keys.d/<name>.pub`, so `apm` verifies first contact with no manual `apr trust pin`. |
| **No silent TOFU** | Sync never accepts a signing key on first use. Bootstrap trust arrives out-of-band (baked anchor, `apr trust pin`, or the `[registry.signing] public_key` config anchor when the store is empty). `required = false` / `apm registry add --no-verify` is the only opt-out, intended for local development registries. |
| **`APM_SYSTEM_CONFIG_DIR`** | Redirects the `/etc/apm` system config root (and `registries.d`, `trusted-keys.d`) when set to a non-empty absolute path; used to point `apm` and `apr` at a writable fixture tree on non-AOS hosts. |
