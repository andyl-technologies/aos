# Publishing — the Producer Pipeline

> **Audience:** registry maintainers (producers), implementers of the `apr`
> tooling, and architects reasoning about the registry's atomicity and
> concurrency properties.
>
> **Scope:** the **TARGET** producer pipeline end to end — how a new release goes
> from a build commit to a fully published, signed, fetchable git-native
> registry over dumb HTTP, including pack/delta generation, `update-server-info`,
> partition (rollout) advancement, and upload with correct CDN TTLs. The
> consumer counterpart is [packs-and-deltas.md](./packs-and-deltas.md) (delta
> walk + retention) and [versioning-and-channels.md](./versioning-and-channels.md)
> (bucket selection).

Every claim is labelled **CURRENT** (verified against the code, cited as
`path:line`) or **TARGET** (the design intent from the
[design brief](../plans/registry/design-brief.md), authoritative §10, §4, §6).
The gap between them is the subject of
[workstream-02-pack-delta-pipeline.md](../plans/registry/workstream-02-pack-delta-pipeline.md)
and
[workstream-03-channels-rollouts.md](../plans/registry/workstream-03-channels-rollouts.md).

---

## 1. Mental model

**TARGET.** A registry is a **bare git repository in sha256 object format,
published as static files over dumb HTTP**
(see [architecture.md](./architecture.md) and
[http-layout.md](./http-layout.md)). Publishing is the asymmetric-cost half of
the design: *make publishing as expensive as possible so consumption is as cheap
as possible* (design brief §3). The producer pays once — building large-window
packs, thin deltas, and zstd-compressing — and every consumer benefits.

A publish has two strictly-ordered halves that must never be confused:

1. **Materialize immutable release objects.** Build the release commit, create
   and sign the semver tag, generate the full/delta packs, write loose objects to
   the **root** `/objects/`, and regenerate the per-release pack indices. Everything
   here is **content-addressed and immutable** — once a sha256 object exists it never
   changes meaning.
2. **Flip the mutable pointers.** Regenerate the repo-root `info/refs` / `HEAD` /
   `objects/info/alternates`, bump `refs/heads/<channel>` to the frontier,
   and advance the signed `/channels/<name>/<00..ff>` partition tags. These are the
   *only* mutable surfaces, and they are published **last**, after every object
   they can possibly reference already exists at the origin.

```
                      PRODUCER (TARGET)                          CONSUMER
   ┌────────────────────────────────────────────────┐
   │ 1  build release commit                          │
   │ 2  create + sign semver tag  (refs/tags/<semver>)│
   │ 3  libgit2 full packs + Rust thin deltas + zstd  │   immutable, content-addressed
   │ 4  write loose objects under root /objects/      │──────────────────────────┐
   │ 5  per-release pack index (info/packs)           │                          │
   ├──────────────────────────────────────────────────┤   pointers, flipped LAST │
   │ 6  root update-server-info (info/refs, HEAD)      │                          ▼
   │ 7  regen objects/info/alternates                 │                  ┌────────────────┐
   │ 8  bump refs/heads/<channel> → frontier          │                  │  HTTP / CDN     │
   │ 9  advance /channels/<name>/00..ff partition tags  │─────────────────▶│  origin (dumb   │
   │ 10 upload with per-path CDN TTLs                  │                  │  git static)    │
   └────────────────────────────────────────────────┘                  └────────────────┘
                                                                                 │
                                                            apm bucket → channel tag → semver
                                                            tag → commit → delta walk / fetch
```

**Invariant (TARGET).** Immutable release objects (steps 1–5) are uploaded and
visible **before** any pointer that can name them flips (steps 6–9). A reader
mid-publish therefore sees **either** the old frontier/partition state **or** the
new one — never a partition tag pointing at a commit whose objects are missing.

---

## 2. CURRENT state — the `apr` producer surface

**CURRENT.** `apr` is an independent registry-authoring executable with its own
parser. It shares producer libraries with `apm` and `aos`, but neither expands
nor dispatches through another command surface. All producer logic lives in
[`crates/aos-package/src/registry_ops.rs`](../../crates/aos-package/src/registry_ops.rs).
Today's tool operates on a *nested-TOML* registry (`packages/<x>/<name>.toml`)
plus the `store/` realisation graph (RFC-0005). The sha256 object-store scaffolding, signed release tags,
channel partition commands, `update-server-info`, root `objects/info/alternates`
refresh hooks, static Nix-cache generation/upload, and static git-origin upload
now exist.

The commands relevant to a release, in workflow order:

| Command | Function | What it actually does (CURRENT) |
|---|---|---|
| `apr create <name> [--remote URL] [--trust-key <registry:Ed25519:base64>] [--trust-key-id <id>] [--key <path> \| --key-id <id>]` | `create` (`registry_ops.rs`) | `git init --object-format=sha256`, set `HEAD` to `refs/heads/stable`, make `packages/`, write a default `registry.toml`, write schema-1 `keys.toml` (seeded by `--trust-key`), initial commit (signed with `--key`/`--key-id` when the roster is seeded), then refresh dumb-HTTP object indexes; optional `git remote add origin`. |
| `apr keys generate <id> [--registry <name>] [--add] [--no-commit] [--key \| --key-id]` | `generate_roster_key` (`registry_ops.rs:2922`) | Mints an Ed25519 keypair in-process (hermetic `sshkey` module, no `ssh-keygen`), writes the OpenSSH private key to `apm/keys/<registry>-<id>.key` (`0600`, refuses overwrite), records its path in `[registry.signing_keys]`, prints the public key + fingerprint; with `--add` appends it to `keys.toml` (signed commit unless `--no-commit`). `--add` on an empty roster errors → use `apr create --trust-key`. |
| `apr keys list/add/retire` | `run_keys` (`registry_ops.rs:2551`) | Maintains committed `keys.toml`: list active/revoked ids; add registry-bound active signing keys; retire active ids into `[[revoked]]` with an active survivor/vouching id and **re-sign** the channel/release tags whose only valid signer was the retired key (`--no-resign` to skip). `add`/`retire` modify `keys.toml`, so they require `--key`/`--key-id` and produce a **signed** commit; then commit + refresh dumb-HTTP object indexes unless `--no-commit` is passed. |
| `apr publish <store-path> […]` | `publish` (`registry_ops.rs`) | Introspect the path, write `packages/<x>/<name>.toml`, and record `store/<2-char>/<ia>` realisation files for every runtime-closure member - blessed NAR + dependency edges, plus the CA realisation and pins (via `nix store make-content-addressed`) when the registry is `content_addressed` - refusing on a content mismatch unless `--bless`. Image publication additionally enforces `[registry] require_signed_ukis = true`: the primary and slot UKIs must be signed, every signer must be active in committed `sb-certs.toml`, and the local public `sb-certs/db.pem` must verify the signatures. Then (unless `--no-commit`) it commits the touched paths and refreshes `objects/info/alternates` + `update-server-info`. |
| `apr commit <path>... --message <text> [--key <path> \| --key-id <id>]` | `commit_changes` (`registry_ops.rs`) | Commit an explicit set of registry-relative paths with the in-process SSH signer, refusing absolute/traversal paths and an already-staged index. A non-empty `keys.toml` roster requires an active maintainer key; only an empty-roster bootstrap may commit unsigned. The command refreshes the static object indexes after the commit. |
| `apr store bless/revoke/verify/backfill [--registry <name>] [--key \| --key-id]` | `run_store` (`registry_ops.rs`) | Maintains the `store/` realisation graph (RFC-0005): `bless` records a path's closure from the local Nix store; `revoke` removes a blessed realisation (a security event - signed, reviewable diff); `verify` checks graph health + closure coverage (`--deep` recomputes local NAR hashes); `backfill` records every published closure so an existing registry becomes fully covered in one signed commit. |
| `apr tag <name> [--message] (--key <path> \| --key-id <id>)` | `tag` (`registry_ops.rs`) | Resolves the signing key directly from `--key` or from committed `keys.toml` + local `[registry.signing_keys]`, then runs `git -c gpg.format=ssh -c user.signingkey=<key> tag -s <name> -m … HEAD`; semver tags also prepare a release object dir during the object-store refresh. |
| `apr sign <tag> (--key <path> \| --key-id <id>)` | `sign` (`registry_ops.rs`) | Re-signs an existing release tag as a signed tag object with `git tag -s -f`, then refreshes dumb-HTTP object indexes; it no longer signs commits. |
| `apr channel init/advance/status` | `run_channel` (`registry_ops.rs`) | Initializes or advances raw signed partition tag files under `channels/<name>/00..ff`, using the same `--key` / `--key-id` signing-key selection as release tags, updates `refs/heads/<channel>` to the frontier, and reports partition counts. |
| `apr cache generate [--output <dir>] [--key <key>] [--cache-url <url>] [--upload-url <backend>]... [--no-skip]` | `run_cache` (`registry_ops.rs`) | Generates `nix-cache-info`, signed `<storehash>.narinfo`, and `nar/*.nar.zst` for every registry-listed store path into the internal per-registry staging dir unless `--output` is supplied; fails closed when a path is absent locally; skips remotely present narinfos unless `--no-skip`; optionally uploads the generated files to repeatable `--upload-url` destinations via `aos-cache`, supports HTTP/S3/SFTP auth flags, and commits the root `registry.toml` `[[caches]]` pointer. |
| `apr cache gc [--registry <name>] [--max-age <days>] [--dry-run]` | `run_cache` (`registry_ops.rs`) | Removes old internal static-cache staging narinfo/NAR pairs, defaulting to `[registry.cache].max_age_days` or 30 days. |
| `apr origin upload --upload-url <backend>... [--cache-dir <dir>]` | `run_origin` (`registry_ops.rs`) | Refreshes static git indexes, then uploads the full dumb-HTTP origin surface in immutable-first / mutable-last order: `objects/**`, `releases/**`, optional static-cache `nar/**` and `*.narinfo`, then `HEAD`, `info/refs`, `objects/info/**`, `channels/**`, and `nix-cache-info`; uses the same backend auth flags and partial-failure semantics as static cache uploads. |
| `apr release <semver> [--store-path <path>] (--key <path> \| --key-id <id>) [--channel <name> (--init-channel \| --count N \| --partitions ...)] [--cache-url <url>] [--cache-key <key>] [--cache-priority N] [--upload-url <backend>]... [--no-skip] [--dry-run] [--resume]` | `release` / `release_registry_tree` (`registry_ops.rs`) | Runs the ordered producer pipeline: optionally publishes a store path into a committed metadata tree, generates static Nix-cache files into internal staging when publishing store roots, commits the cache pointer, creates/reuses the signed semver tag, generates full packs at `X.Y.0` anchors plus compressed guaranteed thin deltas, refreshes dumb-HTTP indexes, initializes/advances channel partitions, and uploads cache bytes plus the static origin in producer-safe order. A lock file prevents concurrent local publishers; `--dry-run` prints the plan without mutation and `--resume` skips already-present tag/pack artifacts that match HEAD. |
| `apr push [--branch] [--set-upstream] [--force]` | `push` (`registry_ops.rs:1398`) | `git push [-u origin] [branch] [--force]`. |

The signed-UKI gate is release policy, not a build-time default. Enable it in
the committed root only after its public certificate is active in
`sb-certs.toml` and the same certificate is installed locally as
`sb-certs/db.pem`. Releases containing no system images remain valid.

The current Secure Boot image module signs during the Nix build, so a key path
used there is copied into the local Nix store. That is acceptable only for
disposable development or staging identities on a controlled single-user
builder. Do not use that path for production keys. Production requires the
external signing/key-custody stage described by RFC-0006; until that stage is
implemented, the release gate verifies signed artifacts but does not make the
in-build signer a production-safe workflow.

### 2.1 CURRENT: transport/index refresh

The producer now refreshes the git-native static index after create, publish,
unpublish, tag, sign, and channel operations. The refresh path updates
`objects/info/alternates` and `info/refs` so a dumb-HTTP origin can be served as
static files. Pack generation helpers exist in `registry::pack`, static
Nix-cache generation/upload is exposed through `apr cache generate`, and full
static git-origin upload is exposed through `apr origin upload`. `apr release`
now sequences those pieces for the common producer path and leaves the focused
subcommands available for repair, inspection, and unusual workflows.

---

## 3. Inputs and outputs of one release

**TARGET.** A single release publish is parameterized by:

| Input | Meaning |
|---|---|
| `<semver>` | Standard semver, **no `v` prefix** (`1.2.0`, `1.0.0-beta+exp.sha.5114f85`). |
| release commit | The commit the semver tag points at (the new registry tree content). |
| `<channel>` | The release line being advanced (e.g. `stable`, `testing`). |
| partition plan | How many of the 256 partitions `00..ff` advance to `<semver>` this publish (rollout fraction). |
| signing key | One SSH-format Ed25519 key (reused from `apr sign` / `security.rs`). |

It produces, under [the HTTP/object layout](./http-layout.md):

```
/releases/<major>/<minor>/<patch[-prerelease][+build]>/
  objects/
    info/packs                       ← lists this release's self-contained pack(s)
    pack/pack-<sha256>.pack (+ .idx)    ← full pack (only at X.Y.0 anchors)
    pack/delta-<from-semver>.pack.zst   ← THIN deltas (AOS-only; NOT in info/packs)
                                        (PACK-ONLY: no loose <xx>/<…>, no info/alternates)
/objects/<xx>/<62-hex>                ← ALL loose objects (every release), centralized at root
refs/tags/<semver>                    ← signed tag → release commit          [via info/refs]
/channels/<name>/<00..ff>              ← signed partition tags advanced per the rollout plan
refs/heads/<channel>                  ← branch head bumped to the frontier
/objects/info/{packs,alternates}     ← repo-root indices regenerated
/info/refs, /HEAD                     ← regenerated via update-server-info
```

The third `/releases` path segment is **everything after `major.minor`** — e.g.
`1.0.0-beta+exp.sha.5114f85` → `/releases/1/0/0-beta+exp.sha.5114f85/`.

---

## 4. Step 1–2 — build commit, create + sign the semver tag

**TARGET.**

1. **Build the release commit.** The registry tree content (the package TOML
   tree, the same content model the current code already writes) is committed in
   the bare sha256 repo. All git operations use sha256
   (`git init --object-format=sha256`; design brief §8). The release commit is
   what `refs/tags/<semver>` will point at and what every pack is computed over.

2. **Create the annotated, signed semver tag.** An **annotated git tag** that is a
   **pure signed pointer** — the standard git tag fields (`object`, `type`, the tag
   **name**, `tagger`) plus an SSH-format Ed25519 signature on the tag *object*, plus
   an **optional freeform human message**. The tag carries **no structured payload**
   and no in-band `valid_until`. Cache locations and
   freshness are **not** advertised in the tag (see §1 and §4 of [signing-and-trust.md](./signing-and-trust.md)).

   The tag **name** is the bare semver (`1.2.0`), the signature lives on the tag
   *object*, and the embedded tag-name field is bound to the serving path during
   verification (see §10 and [signing-and-trust.md](./signing-and-trust.md)).
   The signing primitive is the existing SSH-format Ed25519 git signature reused
   from `apr sign` (`git`-resolved `user.signingkey` + `gpg.format = ssh`;
   `security.rs` `parse_signing_key` `name:Ed25519:<base64>`).

Release tags carry no in-band expiry, which fits releases being
immutable and carrying a long CDN TTL. Release freshness is carried by committed
AOS-TUF metadata: `tuf/timestamp.json` is a signed, short-lived pointer to the
snapshot hash. Moving-ref consumers enforce that timestamp before accepting the
package catalog; explicit commit/tag/version pins verify signatures, hashes, and
metadata version floors when TUF exists without expiring old immutable release
snapshots.
Channel partition freshness remains the low CDN TTL plus the consumer's
max-staleness policy and monotonic anti-rollback floor.

The Nix binary-cache / NAR substituter location lives in the committed repo-root
`registry.toml` `[[caches]]` (a tree file authenticated transitively by the signed
tag), with the consumer's client-side `registries.d/<name>.toml` as an optional
override/supplement — never embedded in the signed tag itself. The origin **MAY**
serve `nix-cache-info` / `<storehash>.narinfo` / `nar`
as the stock-Nix superset; a separate cache-role key signs narinfo.

---

## 5. Step 3 — pack generation (libgit2 + thinpack + zstd)

**TARGET.** Packs are an efficiency layer over the always-present loose object
store. The producer commits to the [guaranteed delta graph](./packs-and-deltas.md)
so consumers can plan their walk:

- **Every `X.Y.0` (major or minor)** ships a self-contained **full pack**.
- **Every patch `X.Y.Z` (Z>0)** ships thin deltas only (no full pack).
- The full set of guaranteed deltas per release class is specified in
  [packs-and-deltas.md](./packs-and-deltas.md).

### 5.1 Full pack (self-contained)

`registry::pack::full_pack` uses libgit2's `PackBuilder` over the release
commit's reachable object graph, then libgit2's `Indexer` writes the conventional
`pack-<sha256>.pack` and `pack-<sha256>.idx` pair.

- The full pack is non-thin and self-contained.
- The `.idx` ships **only** for full packs, so stock dumb Git can use the pack
  listed in `objects/info/packs`.
- AOS clients still regenerate and verify the index locally instead of trusting
  the server copy.

### 5.2 Thin delta pack

`registry::thinpack` writes a thin pack equivalent to `git pack-objects --thin`
over `to ^from`: objects in `<to>` but not `<from>`, with deltas allowed to
reference `<from>`'s objects. It tries multiple local strategies and keeps the
smallest zstd-probed candidate.

- The consumer completes the thin pack against the retained base with local
  libgit2 pack indexing.
- Thin deltas are **`.pack.zst` only** — no `.idx`, and they are **NOT** listed
  in `objects/info/packs` (a stock dumb client cannot apply a thin pack; AOS
  clients discover them by the `delta-<semver>` filename convention).

### 5.3 zstd (the working trick)

git's pack format hard-codes **zlib per object**, so zstd-ing a normally
compressed pack is near-useless (already DEFLATEd). The current zstd transport is
for thin deltas:

```sh
# 1. thinpack emits stored zlib framing, valid git pack,
#    NO entropy coding, with git-compatible delta encoding.
registry::thinpack::write_thin_pack(...)

# 2. zstd the whole .pack: zstd does the entropy coding over the delta-encoded stream.
zstd --ultra -22 --long=27 delta-<from>.pack  -o delta-<from>.pack.zst
```

zstd's entropy coding over the delta-encoded (but un-DEFLATEd) stream beats
zlib-9, and the underlying `.pack` stays git-valid. The consumer fetches
`.pack.zst`, runs `zstd -d`, then completes and indexes the pack locally. A zstd
**trained dictionary** across a release line's small delta packs remains an
optional future optimization.

> **Serve current forms.** Full packs ship as plain `.pack` plus `.idx`; thin
> deltas ship as `.pack.zst`. See [http-layout.md](./http-layout.md).

---

## 6. Step 4–5 — loose objects + per-release pack index

**TARGET.**

- **Write loose objects to the root.** **ALL** objects (every release) exist loose
  under the single root `/objects/<xx>/<62-hex>` (the sha256 2/62 split) — this is
  the guaranteed completeness fallback; packs are an optimization on top
  (design brief §8). Loose objects are **centralized at the root only**; the
  per-release `/releases/<major>/<minor>/<patch>/objects/` dirs are **pack-only**
  (they hold `info/packs` + `pack/*` and contain **no** loose `<xx>/<…>` objects and
  **no** per-release `info/alternates`).

- **Per-release pack index.** Regenerate the per-release `objects/info/packs`
  (listing this release's self-contained full pack only — never the thin deltas) for
  the release's pack dir. This makes the per-release directory a valid dumb-HTTP
  **pack source** that the root `info/alternates` chain can stitch together for pack
  discovery — object completeness itself comes from the centralized root
  `/objects/`.

Because release objects are content-addressed sha256, **writing the same object
twice is idempotent** — a re-run or a concurrent publisher writing the same bytes
is a no-op. This is what makes step 3/4 safe to retry freely (§11).

---

## 7. Step 6–7 — root `update-server-info` + `info/alternates`

**TARGET.** With every immutable object in place, regenerate the *repo-root*
mutable indices that make the whole thing a valid dumb-HTTP bare repo:

1. **`git update-server-info`** regenerates `/info/refs` (the full
   `refs/heads/<channels>` + `refs/tags/<semvers>` listing) and the root
   `/objects/info/packs`. A stock `git clone <url>` works off these
   (design brief §8, §12).

2. **`/HEAD`** is written as `ref: refs/heads/<default-channel>` (e.g.
   `ref: refs/heads/stable`) so a default clone lands on the default channel
   branch.

3. **`/objects/info/alternates`** is regenerated to list **every**
   `/releases/*/objects/` directory, **newest → oldest**, as **relative** paths.
   Each entry is `../releases/<M>/<m>/<patch…>/objects/` — git resolves relative
   alternates against the repo's `objects/` URL, so the single `../` strips the
   `objects` segment to reach the repo root (therefore the correct depth is **one**
   `../`, not two). The file is **host-independent** — byte-identical across
   CDN / mirror / localhost, with no hostname baked in. The dumb-HTTP walker reads
   `http-alternates` then falls back to `alternates`, so this one relative
   `info/alternates` works for **HTTP and local-FS** alike. Because loose objects
   are centralized at the root `/objects/`, the alternates now serve **pack
   discovery + the release index**, not object completeness (design brief §8).

```
# /objects/info/alternates  (newest → oldest, relative, host-independent)
../releases/1/2/0/objects/
../releases/1/1/3/objects/
../releases/1/1/0/objects/
../releases/1/0/0/objects/
…
```

These four files (`info/refs`, `HEAD`, `objects/info/packs`,
`objects/info/alternates`) are **mutable** and therefore **low TTL** (§9).

---

## 8. Step 8–9 — frontier branch head + partition rollout

**TARGET.** The ref/rollout model has three layers
(see [versioning-and-channels.md](./versioning-and-channels.md) and
[signing-and-trust.md](./signing-and-trust.md)):

| Path / ref | What | Signed? |
|---|---|---|
| `refs/heads/<channel>` | **channels are branches**; head = **frontier** (newest release any partition targets) | no (unsigned convenience pointer) |
| `refs/tags/<semver>` | release: signed tag → commit | **yes** |
| `/channels/<name>/<00..ff>` | 256 signed partition tag objects (tag name == channel) → semver tag | **yes** |

### 8.1 Bump the frontier branch head

`refs/heads/<channel>` is set to the commit of the **newest release any partition
targets** — the rollout *target* (frontier). Implication: a stock `git pull
<channel>` always gets the frontier (no rollout protection), which is acceptable
because rollout is an AOS-fleet concept, not a git-clone concept (design brief
§6). The branch ref is an **unsigned** pointer and is never part of the trust
chain.

### 8.2 Advance the 256 partition tags (publisher-controlled rollout)

A channel exposes **exactly 256** partition files `/channels/<name>/00..ff`, each an
**independently-signed** annotated tag object whose **tag name == the channel
name**, pointing at a semver tag. There must always be 256 present.

**To roll a new release to N/256 of the fleet:** point N partitions at the new
semver tag and **leave the rest on the prior release**. This is the explicit
answer to "where does the rest of the fleet go" — the un-advanced partitions
still name the prior release. Advance partitions as confidence grows; completion
= all 256 point at the new release (design brief §6).

```
  rollout fraction      /channels/stable/00..ff  →  semver tag
  ────────────────      ────────────────────────────────────
  0/256  (none yet)     00 01 02 … fd fe ff → 1.1.3
  4/256  (early ring)   00 01 02 03         → 1.2.0   (new)
                        04 05 … fd fe ff    → 1.1.3   (prior)
  256/256 (complete)    00 01 02 … fd fe ff → 1.2.0
```

Each advanced partition is a **fresh signed tag object** (`tag → tag → commit`:
channel partition tag → semver tag → release commit). The signature and the
embedded tag-name field (`== <channel>`) bind it to its `/channels/<name>/<bucket>`
serving path. See [signing-and-trust.md](./signing-and-trust.md).

**Aborting a bad rollout is fix-forward** (publish a newer release and point
partitions at it), never partition-decrement: the consumer's monotonic floor
(anti-rollback) would block a decrement anyway (design brief §6).

> Consumers self-select a bucket on first channel sync from a registry-local salt,
> persist the bucket index, and probe-forward `(bucket+1) mod 256`
> if their partition is missing — see
> [versioning-and-channels.md](./versioning-and-channels.md). The producer never
> chooses *which* hosts get a bucket; it only chooses *which buckets advance*.

---

## 9. Step 10 — upload with correct CDN TTLs

**TARGET.** Upload to the HTTP/CDN origin honoring the per-path cache policy
(design brief §4; [http-layout.md](./http-layout.md)). The ordering within the
upload (immutable first, pointers last) is the atomicity discipline of §11.

| Path | Mutability | CDN TTL |
|---|---|---|
| `/objects/<xx>/<…>` (loose), `/releases/**/pack/*` | immutable (content-addressed) | **very high** (`MAY`) |
| `/releases/**` (the whole subtree) | immutable after publish | **long** (`MAY`) |
| `/objects/info/**` (`packs`, `alternates`), per-release `objects/info/**` | mutable on publish | **low** (`MUST`) |
| `/info/refs`, `/HEAD` | mutable on publish | **low** (`MUST`) |
| `/channels/**` | mutable on rollout | **low** (`MUST`) — fast rollout updates |

The asymmetry is intentional: `/channels/**` and the `info/*` indices must turn
over quickly so a rollout or a new frontier is visible promptly, while the bulk
bytes (`/releases/**`, loose objects, packs) are immutable and may be cached
aggressively forever. If the CDN supports cache invalidation, invalidate the
low-TTL paths on publish; otherwise the short TTL bounds staleness.

---

## 10. Verification the producer must satisfy (name-binding)

**TARGET.** The producer signs so that the consumer's trust chain holds. AOS
verification is **`signed partition tag → signed semver tag → commit`**, checking
**both** the signature **and** the embedded tag-name field against the expected
name:

- under `/channels/<name>/*` the embedded tag name **must** equal `<name>` (the
  channel);
- under `/releases/*` (i.e. `refs/tags/<semver>`) the embedded tag name **must**
  equal the semver.

This **name-binding** is what binds a tag object to its serving path and prevents
cross-serving a tag from one path at another (design brief §5, §11). Concretely
the producer must ensure each partition tag it writes (a) is SSH-Ed25519 signed,
(b) names the channel in its tag-name field, and (c) points at a semver tag that
itself is signed and names that semver. Branch refs are **unsigned** and never
part of this chain — a stock-git user can still `git verify-tag <semver>` because
the release tags are the signed objects. Full detail lives in
[signing-and-trust.md](./signing-and-trust.md).

---

## 11. Concurrency & atomicity

**TARGET.** The HTTP origin is not git and has no native compare-and-swap, so the
safety property is imposed by **ordering** plus the **immutability** of release
objects.

### 11.1 The ordering invariant

```
  STEP   SURFACE                              MUTABILITY        SAFETY
  ────   ───────                              ──────────        ──────
  1–4    release commit, semver tag, packs,   immutable (CA)    idempotent;
         deltas, root /objects loose objects                    retry freely, any order
  5      per-release objects/info/packs       low-TTL index     regenerated from immutable set
  6–7    info/refs, HEAD,                      MUTABLE pointer   flipped only AFTER 1–5 exist
         objects/info/alternates
  8      refs/heads/<channel> (frontier)       MUTABLE pointer   flipped after release objects
  9      /channels/<name>/00..ff partition tags MUTABLE pointer   flipped LAST (rollout gate)
```

**Invariant:** every object a pointer can reference (commits, packs, deltas,
loose objects, the semver tag) is published in steps 1–5 **before** any pointer
flips in steps 6–9. Therefore a reader who fetches a partition tag, then resolves
`partition → semver → commit → objects`, can **always** complete the resolution —
the objects it names were already at the origin when the partition advanced.

A reader caught mid-publish sees **one** of two consistent states:

- **old state:** old partition tags + old frontier (the prior release, fully
  fetchable); or
- **new state:** new partition tags + new frontier (the new release, whose
  objects were uploaded first).

There is no torn state in which a partition points at a release whose objects are
absent.

### 11.2 Why immutability removes the need for a lock

Because release objects are **content-addressed sha256**, two producers
materializing the same release write byte-identical objects — uploading them is
idempotent and needs no coordination (design brief §8, §10). Coordination is only
required for the **mutable pointers** (steps 6–9). Two publishers advancing the
*same* channel must serialize their pointer flips (e.g. via the upstream git
remote's ref CAS on `refs/heads/<channel>` and `refs/tags/*`, or a
conditional-PUT / `If-Match` on the `/channels/**` objects at the origin); the
loser re-derives the frontier and re-applies its partition plan. The mechanism
for serializing the pointer flip is an open implementation question
([open-questions.md](../plans/registry/open-questions.md), design brief §16.4),
but the *correctness* of a partially-applied publish never depends on it: the
worst case is a stale-but-consistent pointer, never a dangling one.

### 11.3 Anti-rollback is the consumer's backstop

Even if a pointer flip races or a mirror is stale, the consumer keeps a
**monotonic floor** and never moves to a release older than its current one
(design brief §6). Aborting a bad rollout is therefore always **fix-forward**:
publish a newer release and advance partitions to it; never decrement a
partition. See [versioning-and-channels.md](./versioning-and-channels.md) and
[signing-and-trust.md](./signing-and-trust.md).

---

## 12. End-to-end walkthrough

### 12.1 CURRENT (what works today)

```sh
# One-time
apr create acme --remote git@github.com:acme/registry.git

# Per release — guarded wrapper
apr release 2026.06.0 \
    --store-path /nix/store/<hash>-curl-8.5.0 \
    --description "URL transfer tool" --license MIT --maintainer acme \
    --key-id initial \
    --channel stable --init-channel \
    --cache-key ./nix_cache_signing_key \
    --cache-url https://registry.example/cache \
    --s3-region us-east-1 \
    --s3-profile registry-prod \
    --s3-endpoint https://s3.example \
    --ssh-key /run/secrets/registry_sftp_key \
    --upload-url s3://registry-origin \
    --upload-url sftp://deploy@origin.example/srv/registry
apr push --set-upstream --branch stable        # plain git push              (registry_ops.rs:1398)
```

The same pieces remain available as focused repair/manual commands:
`apr publish`, `apr tag`, `apr channel init/advance`, `apr cache generate`, and
`apr origin upload`.

`apr cache generate` and `apr origin upload` accept the same backend-auth shape
as `aos cache` uploads:
`--token` / `AOS_TOKEN`, `--view` / `AOS_VIEW`, `--http-user`,
`--http-password` / `AOS_HTTP_PASSWORD`, repeatable `--header`,
`--s3-region` / `AWS_REGION`, `--s3-profile`, `--s3-endpoint`, `--ssh-key`,
`--ssh-password` / `AOS_SSH_PASSWORD`, and `--ssh-ask-pass`.

For persistent producer defaults, `registries.d/<name>.toml` may include
`[registry.signing_keys]` and `[registry.upload_auth]`.
`[registry.signing_keys]` maps committed active `keys.toml` ids to local private
key paths for `apr tag --key-id`, `apr sign --key-id`, and
`apr channel init/advance --key-id`. Direct `--key <private-key-path>` remains
available for one-off signing and is mutually exclusive with `--key-id`.
`[registry.upload_auth]` values are used as defaults; env/CLI values override
them; `view` falls back to `"default"` if neither config nor env/CLI sets it.
Its `upload_urls` list provides the default destinations for
`apr origin upload`, `apr cache generate`, and `apr release` when no
`--upload-url` flag is given. The section is managed by `apr origin config`:
setter flags replace stored values, `--unset <field>` clears them, and a bare
`apr origin config` shows what is stored — no hand-editing required.

```toml
[registry.signing_keys]
initial = "/run/secrets/acme_registry_initial"
next = "/run/secrets/acme_registry_next"

[registry.upload_auth]
upload_urls = ["s3://registry-bucket/"]
token = "..."
view = "prod"
http_user = "cache-user"
http_password = "..."
headers = ["X-Registry: core"]
s3_region = "us-west-2"
s3_profile = "registry-prod"
s3_endpoint = "https://s3.example"
ssh_key = "/run/secrets/registry_sftp_key"
ssh_password = "..."
ssh_ask_pass = false
```

`apr release` wraps the same focused operations into one guarded producer
workflow. Operators can still run the lower-level commands directly for
repair/resume work or for unusual staging topologies.

### 12.2 Release orchestrator

```
build release commit  →  create + sign semver tag (refs/tags/<semver>, pure signed pointer + optional message)
        │
        ▼  (immutable, content-addressed — idempotent, any order)
libgit2 full pack + .idx at X.Y.0  +  thinpack delta-<from>.pack.zst artifacts
        →  zstd --ultra -22 --long=27 each thin delta pack
        →  packs under /releases/X/Y/P/objects/pack/  ;  loose objects under root /objects/
        →  per-release pack index  (objects/info/packs: full pack only)
        │
        ▼  (mutable pointers — flipped LAST, after every object exists)
root git update-server-info  (info/refs, objects/info/packs)
write HEAD = ref: refs/heads/<default-channel>
regen /objects/info/alternates  (all /releases/*/objects, newest→oldest, relative one-"../")
bump refs/heads/<channel> → frontier
advance /channels/<name>/00..ff  (N partitions → new semver tag; rest stay on prior)  [signed; name-bound]
        │
        ▼
upload with CDN TTLs:  /releases/**, loose, packs = long/immutable
                       /objects/info/**, info/refs, HEAD, /channels/** = low TTL
```

`apr release` is the production wrapper for this pipeline. It supports a
committed-tree mode and an optional `--store-path` mode; the latter delegates to
`apr publish` first and therefore requires a real local Nix store path. When a
publishing release has store roots, `apr` stages the static cache internally,
commits the advertised `[[caches]]` pointer before signing the release tag, and
uploads cache payloads before mutable pointers. Uploads accept repeatable backend
URLs (`file://`, `http(s)://`, `s3://`, and `sftp://`/`ssh://`).
The mixed cache upload path is validated by
`checks.vm.apm.registry-validation-stock-nix-backend-array`; the static-origin
upload ordering and CDN metadata contract are validated by
`checks.vm.apm.registry-validation-origin-cdn-layout`. Both checks passed on a
remote KVM builder on 2026-06-08. The backend-array output was
`/nix/store/bwp2ayp8r199n32s2csndcv43qmi38xr-aos-vm-test-apm-registry-validation-stock-nix-backend-array-0`;
the CDN-layout output was
`/nix/store/xfzd1yim7sx5cq9gsg6nx8kvh1hi551s-aos-vm-test-apm-registry-validation-origin-cdn-layout-0`.

---

## 13. Cross-references

- [README.md](./README.md) — registry doc index and overview.
- [architecture.md](./architecture.md) — git-repo-over-dumb-HTTP; superset of git and Nix; asymmetric-cost philosophy.
- [current-state.md](./current-state.md) — current git-native implementation status.
- [http-layout.md](./http-layout.md) — the HTTP/object layout, CDN TTLs, `info/refs`/`HEAD`/`info/alternates`.
- [versioning-and-channels.md](./versioning-and-channels.md) — semver, channels-as-branches, frontier, the 256-partition rollout, bucket selection, anti-rollback.
- [packs-and-deltas.md](./packs-and-deltas.md) — the delta-scheme graph, client resolution + retention, libgit2 pack indexing, zstd.
- [signing-and-trust.md](./signing-and-trust.md) — signed tag objects (pure signed pointers), name-binding, `tag→tag→commit`, sha256, unsigned branch refs.
- [nix-cache-compatibility.md](./nix-cache-compatibility.md) — the Nix binary-cache superset located via the committed `registry.toml` `[[caches]]` (client-side `registries.d` as optional override).
- [apt-comparison.md](./apt-comparison.md) — git-native + dumb-HTTP vs APT signed-flat-file / `pool` / phased rollout.
- Plan: [design-brief.md](../plans/registry/design-brief.md) (§10, §4, §6 authoritative for this doc),
  [gap-analysis.md](../plans/registry/gap-analysis.md),
  [workstream-02-pack-delta-pipeline.md](../plans/registry/workstream-02-pack-delta-pipeline.md),
  [workstream-03-channels-rollouts.md](../plans/registry/workstream-03-channels-rollouts.md),
  [workstream-04-signing-trust.md](../plans/registry/workstream-04-signing-trust.md),
  [open-questions.md](../plans/registry/open-questions.md).
