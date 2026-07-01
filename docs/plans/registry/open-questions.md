# AOS Registry — Open Questions, Risks & Migration Strategy

> **Status:** Plan document. Derived from the
> [design brief](./design-brief.md) §16 (open questions) and §2 / §15 (current
> state and removed concepts), with risk and migration detail expanded for
> implementers. Where this doc describes **CURRENT** behavior it cites code as
> `path:line` (paths relative to the repo root; the registry crate is
> `crates/aos-package/`). Where it describes **TARGET** behavior it draws from
> the brief's §3–§14 decisions.
>
> **Target model in one line:** the registry is a **bare git repository (sha256
> object format) served as static files over dumb HTTP** — channels are
> *branches*, releases are signed *tags*, rollout is **256 signed partition tag
> objects** under `/channels/<name>/00..ff`, incremental fetch is **thin
> `delta-*.pack`s**, and an optional **Nix NAR cache superset** is served at the
> origin and located via the committed repo-root `registry.toml` `[[caches]]`
> (with the consumer's client-side `registries.d` as an optional override). A signed
> tag is a **pure signed pointer** carrying no structured payload. Superseded
> concepts now live only as pre-cutover history in this plan set; use
> [`../../registry/current-state.md`](../../registry/current-state.md) and
> [`TODO.md`](./TODO.md) for live status.
>
> **Audience:** implementers, architects, engineers, and reviewers who must sign
> off before the object store, the pack/delta pipeline, and the publish pipeline
> land.

This is the living register of *unresolved* decisions for the AOS registry
redesign. Everything here is deliberately **not** settled in the
[reference docs](../../registry/README.md); each item names the owning
workstream, the options on the table, a recommendation where the brief implies
one, and the blast radius if we get it wrong. The single largest cross-cutting
decision — **migration off the existing bundle / `creation_token` registries:
clean break vs. compat shim** — gets its own section ([§3](#3-migration-strategy--the-central-decision))
because it gates the sequencing of every other workstream. A second
milestone-shaping question — **does the Nix NAR cache superset ship in the same
milestone or later** — is settled in [§4](#4-does-the-nar-cache-superset-ship-this-milestone).

---

## 0. How to read this document

| Column / marker | Meaning |
|---|---|
| **CURRENT** | As-is behavior, grounded in code (`path:line`). |
| **TARGET** | The decided end-state from the [design brief](./design-brief.md). |
| **OPEN** | A genuinely unresolved choice. Must be closed before the owning workstream merges. |
| **Owner WS** | The workstream that must resolve and implement the decision. |

Workstream references (target names):

- [WS-01 — object store](./workstream-01-object-store.md) — sha256 bare repo, dumb-HTTP layout, `info/refs` / `HEAD` / `info/alternates` / `update-server-info`, root `/objects/` (loose) + per-release pack-only object dirs.
- [WS-02 — pack/delta pipeline](./workstream-02-pack-delta-pipeline.md) — archival pack/delta plan; current implementation uses libgit2 full packs, Rust thin packs, zstd, expensive-producer tuning.
- [WS-03 — channels & rollouts](./workstream-03-channels-rollouts.md) — 256 signed partition tags, channels-as-branches / frontier, bucket selection, publisher rollout control.
- [WS-04 — signing & trust](./workstream-04-signing-trust.md) — signed tag objects (pure signed pointers), name-binding, sha256, anti-rollback / fix-forward.
- [WS-05 — consumer](./workstream-05-consumer.md) — consumer resolution (bucket → channel tag → semver tag → commit), delta walk, retention, freshness/staleness policy, verification, and the client-side-configured Nix NAR cache superset.

See also the [gap analysis](./gap-analysis.md) for the full producer/consumer
gap enumeration and the [plan README](./README.md) for milestone sequencing.

---

## 1. The open questions (brief §16, expanded)

The numbering follows the design brief §16 exactly so the two documents stay in
lockstep. Each entry adds the owning workstream, the decision options, a default
recommendation, and the failure mode.

### Q1 — sha256 dumb-HTTP clone against target git client versions

| | |
|---|---|
| **Brief §16.1** | "sha256 dumb-HTTP clone tested against target git client versions (no capability negotiation)." |
| **Owner WS** | [WS-01](./workstream-01-object-store.md) (object store), informs [WS-05](./workstream-05-consumer.md) (consumer fetch) |
| **Status** | PARTIAL — the AOS consumer floor is pinned and enforced as Git 2.42.0+ with a runtime sha256 capability probe; a stock-git matrix harness exists, but the pinned-version/container run remains an empirical compatibility task. |

**Why it is open.** The dumb-HTTP transport has **no capability negotiation** —
the client never learns the server's object format; it must already be a sha256
git. The repo is created `git init --object-format=sha256` (design brief §8), so
a client built without sha256 support, or an older git that assumes sha1 loose
paths, cannot clone. The 2/62 hex split of a 64-char sha256 loose object path
(`/objects/<xx>/<62-hex>`) is *visually* indistinguishable from a sha1 2/38
split until the client tries to verify the object, at which point it fails
opaquely.

**What has landed.** The AOS shell-out consumer now pins Git 2.42.0 as the
minimum supported client floor for sha256 dumb-HTTP registries. Before fetching,
`apm update` checks `git --version` and runs a local
`git init --bare --object-format=sha256` probe, then fails with a clear
"requires a sha256-capable git" error rather than a low-level object-format
panic. The floor is recorded in
[http-layout.md](../../registry/http-layout.md) and
[signing-and-trust.md](../../registry/signing-and-trust.md). The Rust e2e suite
also has `stock_git_configured_version_matrix_syncs_sha256_dumb_http_registry`,
which reruns the sha256 dumb-HTTP consumer sync under each `git` binary listed in
`AOS_PACKAGE_TEST_GIT_MATRIX`.

**What remains.** WS-01 still needs the empirical stock-git compatibility matrix
to be run and recorded against pinned/containerized target production clients:
prove which `git clone <url>` / `git verify-tag <semver>` versions work against
the sha256 dumb-HTTP origin. That matrix can either confirm the 2.42.0 floor or
force an explicit floor change.

**Failure mode.** Loud but late: a stock `git clone` against the origin fails
for users on old gits with a confusing "unknown object format" / "bad object"
error far from the real cause (their git is too old). For the AOS consumer the
mitigation is the loose-object fallback (brief §8: "ALL objects exist loose …
the guaranteed completeness fallback") — but that fallback is still sha256 and
does not rescue a non-sha256 client.

### Q2 — pack generation tuning, zstd level, and trained dictionaries

| | |
|---|---|
| **Brief §16.2** | "Exact `pack-objects` window/depth and zstd level defaults (and whether to ship a trained dictionary per release line)." |
| **Owner WS** | [WS-02](./workstream-02-pack-delta-pipeline.md) |
| **Status** | RESOLVED DIFFERENTLY — libgit2/Rust thinpack replaced the literal `pack-objects` flag contract; zstd `--ultra -22 --long=27` remains current for thin-delta transport; trained dictionaries remain deferred. |

**Libgit2 transition note.** The original brief framed this as choosing exact
`git pack-objects` flags. The as-built producer no longer shells out to
`pack-objects`: full packs use libgit2 `PackBuilder` + `Indexer`, thin deltas
use the Rust `thinpack` module, and consumers index packs locally with libgit2.
The current tuning surface is therefore the Rust thinpack strategy set and zstd
settings, not `--window` / `--depth` CLI flags. See
[`../../registry/packs-and-deltas.md`](../../registry/packs-and-deltas.md).

**Historical target (superseded by the libgit2 implementation).** The producer
pays so the consumer does not (brief §3 asymmetric-cost philosophy). The original
plan proposed the following expensive-producer flags:

```
# Thin delta pack (objects in <to> not <from>; deltas may reference <from>):
printf '%s\n^%s\n' "$to" "$from" \
  | git pack-objects --revs --thin \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 \
      --compression=0 \
      pack/delta-"$from"

# Full pack at every X.Y.0 anchor (non-thin, self-contained):
printf '%s\n' "$commit" \
  | git pack-objects --revs \
      --no-reuse-object --no-reuse-delta \
      --window=350 --depth=50 --threads=0 \
      --compression=0 \
      pack/pack

# zstd the level-0 (delta-encoded, no entropy coding) pack:
zstd --ultra -22 --long=27 pack/delta-"$from".pack   # → .pack.zst
```

The **zstd trick** remains load-bearing for thin deltas: stored zlib entries
produce a valid-but-uncompressed pack (delta encoding still applied), and
`zstd --ultra -22 --long=27` does the entropy coding over the delta-encoded
stream. The client does `zstd -d`, then completes the pack with local libgit2
pack indexing.

**What remains open.**

1. **Thinpack strategy tuning.** Measure the Rust thinpack strategies on real
   release lines and tune the candidate set if producer CPU buys meaningful
   transport-size wins without pushing reconstruction cost onto consumers.
2. **zstd level / `--long` window.** `--ultra -22 --long=27` is the current
   thin-delta transport default; confirm the decompression-side memory budget on
   target clients.
3. **Trained dictionary per release line.** A zstd **trained dictionary** across
   a release line's small delta packs is "an optional further win" (brief §10).
   Open: is the size win worth the producer training step and the consumer
   dictionary-fetch round-trip? Recommend deferring — ship plain `--long`
   compression first, add a dictionary only if delta packs are dominated by
   cross-delta redundancy.

**Recommendation.** Keep the implemented libgit2/Rust thinpack path. Do not
reintroduce `git pack-objects` solely to match this archival plan. Add trained
dictionaries only if validation shows a real win.

**Failure mode.** Pure cost/size, never correctness (the loose-object and
full-pack fallbacks are always valid). Bad thinpack strategy choices show up as
slow local reconstruction or larger-than-necessary packs. Neither corrupts bytes.

### Q3 — Bucket-selection input and probe-forward fallback order

| | |
|---|---|
| **Brief §16.3** | "Bucket-selection input (`machine_id` source) and the probe-forward fallback order." |
| **Owner WS** | [WS-03](./workstream-03-channels-rollouts.md) (partition model), [WS-05](./workstream-05-consumer.md) (client selection) |
| **Status** | RESOLVED — consumers use a generated registry-local salt for first assignment, persist the bucket index, and probe forward without re-pinning. |

**What is decided (TARGET).** A channel exposes exactly **256** partition files
`/channels/<name>/00..ff`, each an independently-signed tag object whose tag name ==
the channel name, pointing at a semver tag (brief §6). The consumer self-selects
one bucket on first channel sync from a generated registry-local salt and
persists the resulting bucket index so a host does not flap between buckets
across promotions. The publisher rolls a release to N/256 of the fleet by
pointing N partitions at the new semver tag and leaving the rest on the prior
release; un-advanced partitions still name the prior release (brief §6 — this is
the explicit answer to "where does the rest of the fleet go"). Completion = all
256 partitions point at the new release.

**What is implemented.**

1. **Bucket source.** AOS does not read `/etc/machine-id` for channel rollout
   selection. When a registry has no persisted bucket yet, the consumer generates
   fresh random salt and hashes `registry_name || "\0" || salt`; the low byte is
   the rollout bucket.
2. **Persistence semantics.** The consumer persists the resulting **bucket
   index** (`00..ff` as `u8`) in `[registry.state]`. Existing persisted buckets
   continue to win unchanged, which is the migration path from earlier clients.
3. **Probe-forward fallback.** The client probes `(bucket+i) mod 256` for
   `i = 0..255`, uses the first present/verifiable partition for the current
   sync, and does **not** re-persist the probed bucket.

**Verification.** `registry::channel` tests cover deterministic registry+salt
selection, random salt shape, persisted-bucket migration, and full probe order.

**Recommendation.** Keep persisting only the bucket index, not the salt. That is
the simplest durable contract while the partition count remains fixed at 256.
This is operational, not a correctness gate — a wrong choice degrades to "rollout
fractions are uneven", never "a host gets bad bytes" (the anti-rollback floor,
brief §6, still protects every host).

### Q4 — Single `apr release` / `apr publish` command and pluggable upload

| | |
|---|---|
| **Brief §16.4** | "Whether `apr` grows a single `apr release`/`apr publish` command that does the whole pipeline (commit → tag/sign → pack/delta/zstd → update-server-info → advance partitions → upload) and whether upload backends are pluggable." |
| **Owner WS** | [WS-02](./workstream-02-pack-delta-pipeline.md) (pack/delta), [WS-03](./workstream-03-channels-rollouts.md) (advance partitions) |
| **Status** | RESOLVED IN CODE — `apr release` is the wrapper; repeatable backend URLs are supported through the shared static-upload backend layer. |

**Implemented decision.** The producer keeps the focused repair/inspection verbs
(`apr publish`, `apr tag`, `apr channel`, `apr cache generate`, and
`apr origin upload`) and adds one human-safe wrapper:

```
apr release <semver>
  [--store-path <path>]
  (--key <private-key-path> | --key-id <keys.toml-id>)
  [--channel <name> (--init-channel | --count N | --partitions 00,01,...)]
  [--cache-url <url>] [--cache-output <dir>] [--cache-key <key-file>]
  [--upload-url <file|http|s3|sftp URL>]...
  [--dry-run] [--resume]
```

`apr release` can release an already committed registry tree, or it can publish a
real local Nix store path first by delegating to `apr publish`. When `--cache-url`
is supplied, the cache pointer is committed before the semver tag is signed so
the release authenticates the pointer. Pack generation writes full packs at
`X.Y.0` anchors and compressed guaranteed thin deltas at the target release.
`--cache-output` runs static Nix-cache generation explicitly because it requires
the listed store paths to exist locally.

**Upload backend decision.** Upload is pluggable at the static-file backend layer:
repeat `--upload-url` for `file://`, generic `http(s)://`, `s3://`, and
`sftp://`/`ssh://` destinations. The uploader classifies paths and writes
immutable payloads first (`objects/**`, `releases/**`, static-cache NARs and
narinfos) and low-TTL mutable surfaces last (`HEAD`, `info/refs`,
`objects/info/**`, `channels/**`, `nix-cache-info`). Service-backed S3/SFTP
validation remains a separate TODO because it requires external services.

**Idempotency and coordination.** `--resume` skips a semver tag already pointing
at `HEAD` and skips already-present full/delta pack artifacts; otherwise existing
immutable artifacts fail closed with a clear "pass --resume" message. A local
publisher lock in the git dir prevents two local `apr release` processes from
interleaving. Multi-host publisher serialization and production CDN behavior are
still operational validation topics (see R2/R3 and the TODO).

### Q5 — Consumer freshness / max-staleness policy and key-rotation cadence

| | |
|---|---|
| **Brief §16.5** | "Consumer freshness / max-staleness policy and re-sign/key-rotation cadence." |
| **Owner WS** | [WS-05](./workstream-05-consumer.md) (staleness policy), [WS-04](./workstream-04-signing-trust.md) (key rotation), [WS-03](./workstream-03-channels-rollouts.md) (CDN TTL) |
| **Status** | PARTIAL — `apm` now has a channel max-staleness gate with a 14-day default and `max_staleness_seconds` override for failed refreshes and unchanged-but-valid signed channel targets; production default tuning and key-rotation cadence remain open. |

**What is decided (TARGET).** There is **no in-band `valid_until`** — signed tags
carry no structured payload, only a standard git tag (object, type, tag name,
tagger) + the Ed25519 signature + an optional freeform human message (brief §11,
§14). Freshness is therefore enforced **out of band**, by three independent
mechanisms:

- **Low CDN TTL** on the mutable surfaces — `/channels/**`, `info/refs`,
  `objects/info/packs` — so a correctly-behaving CDN/mirror re-fetches the
  frontier quickly (brief §11).
- **The consumer's own max-staleness policy** — `apm` records when it last
  observed a fresh frontier and **fails closed** (refuses to treat the channel as
  current) once that observation is older than a configured bound. This is the
  freeze defense that an in-band signed expiry used to provide, moved entirely to
  the client.
- **The monotonic anti-rollback floor** — a host never moves to a release older
  than its current floor (brief §6), so even a stale-but-validly-signed frontier
  cannot walk a host backward.

**The trade-off (frozen mirror).** This is **weaker than an in-band signed
expiry**. A mirror that is frozen but still serving *validly-signed* bytes is not
self-evidently stale: nothing in the signed object says "do not trust me after
date X". A consumer with no recent fresh-frontier observation (e.g. a host that
has been offline, or a mirror that froze before the host's first sync) has only
its **local** max-staleness clock to fall back on — it cannot distinguish a
legitimately quiet channel from a maliciously frozen one purely from the signed
material. The defense is real but lives in the consumer, not in the signature.

**Open sub-questions.**

1. **Policy validation.** The current default is 14 days, configurable per
   registry as `max_staleness_seconds`. First-sync failure, failed refreshes,
   unchanged-but-valid signed channel targets, and anti-rollback interactions
   have Rust coverage; the actual production default still needs fleet/CDN
   validation.
2. **Fresh-frontier bookkeeping.** The implementation persists the local
   freshness timestamp in `[registry.state].last_update`. First sync and semver
   advancement refresh it; unchanged but valid signed channel targets are
   accepted only while the previous timestamp is within `max_staleness_seconds`,
   and do not refresh the clock. This observation is not publisher-signed and
   cannot by itself distinguish a reachable frozen mirror from a legitimately
   quiet channel, so the configured window is an operator availability/security
   trade-off.
3. **Key rotation.** One Ed25519 key serves git signing (and, if NARs are served,
   narinfo `Sig:`) (brief §11). Rotating it means re-signing live channel
   partitions and accepting both keys via `allowed_signers` during the overlap
   window. Because there is no per-tag expiry, the only forcing function for
   re-sign is a rotation event itself. The **trust model is decided** (brief §14,
   §16.8): **≥2 overlapping active keys**, no offline-root / operational tier — the
   git lineage (signed tag → commit → parent chain) provides the continuity.
   `keys.toml` (a git-repo-root tree file) lists the active signing key(s) with **no
   role field** and a `revoked` list. Bootstrap is TOFU (`trusted-keys.d/<registry>.pub`),
   rotation is the overlap publish above, planned retirement is a `revoked` entry
   signed by one of the *other* overlapping active keys, and **compromise is handled
   out-of-band** (the consumer re-pins via `trusted-keys.d` / `apr trust`). The cadence
   itself (how often to rotate) is the only open knob here.
4. **Clock-skew tolerance** on the client when evaluating its own max-staleness
   bound against `now`.

**Recommendation.** Keep the 14-day default paired with a low CDN TTL on the
mutable surfaces; rely on the anti-rollback floor as the hard correctness gate and
the max-staleness clock as the freshness gate when refresh fails. Rotate the
Ed25519 key on a fixed cadence (or on suspicion of compromise) with
`allowed_signers` overlap; no routine re-sign otherwise. Document the freeze
trade-off prominently in
[signing-and-trust.md](../../registry/signing-and-trust.md) and the staleness
policy in [workstream-05-consumer.md](./workstream-05-consumer.md).

### Q6 — Relative `info/alternates` for both dumb-HTTP and local-FS resolution

| | |
|---|---|
| **Brief §16.6** | "Confirm a single relative `objects/info/alternates` serves both the dumb-HTTP walker and local-FS resolution." |
| **Owner WS** | [WS-01](./workstream-01-object-store.md) |
| **Status** | OPEN — confirm the relative-path depth and the HTTP-walker fallback. |

**What is decided (TARGET).** Loose objects are **centralized at the single root
`/objects/<xx>/<62hex>`** for every release (brief §8); the per-release
`/releases/<M>/<m>/<patch...>/objects/` dirs are **pack-only** (they hold
`info/packs` + `pack/pack-<sha256>.pack(.idx)` +
`pack/delta-<from>.pack.zst`, no
loose objects and no per-release `info/alternates`). Because loose objects are
centralized, `objects/info/alternates` no longer serves *object completeness* — it
serves **pack discovery + the release index** (brief §4, §8).

`objects/info/alternates` lists every per-release pack dir newest→oldest as a
**relative** path:

```
# /objects/info/alternates  — relative entries, newest→oldest, host-independent
# (one line per release pack dir)
../releases/1/1/2/objects/
../releases/1/1/0/objects/
../releases/1/0/0/objects/
```

Git resolves a relative alternate against the repo's `objects/` URL, so each
`../` strips the `objects` segment to reach the repo root — therefore the correct
depth is **one `../`** (e.g. `../releases/1/1/0/objects/`), *not* two. The file is
**host-independent**: byte-identical across CDN, mirror, and localhost, with no
hostname baked in. The dumb-HTTP walker reads `http-alternates` first then falls
back to `alternates`, so a single relative `info/alternates` works for **HTTP and
local-FS** alike.

**What is open.** Confirm empirically that the dumb-HTTP fetcher resolves the
relative `info/alternates` entries with the **one-`../`** depth against the target
git client versions (Q1's compatibility floor), and that the same file resolves
correctly for local-FS access. There is **no `http-alternates`** to maintain — the
relative `alternates` fallback is the single host-independent file.

**Recommendation.** Emit exactly one `objects/info/alternates` with one-`../`
relative entries, newest→oldest; do **not** also emit a hostname-bearing
`http-alternates`. Pin the resolution behavior in
[http-layout.md](../../registry/http-layout.md) once Q1's git-version floor is
established.

### Q7 — Migration (clean break vs. shim) and NAR-superset milestone

| | |
|---|---|
| **Brief §16.7** | "Migration from the existing bundle/`creation_token` registries (clean break vs shim) — and whether the NAR cache superset (origin-served narinfo, located via the committed `registry.toml` `[[caches]]` with client-side `registries.d` override) ships in the same milestone or later." |
| **Owner WS** | [WS-05](./workstream-05-consumer.md) (consumer cutover), [WS-03](./workstream-03-channels-rollouts.md) (channel/ref model), all producer WS |
| **Status** | OPEN — the two highest-leverage questions. Own their own sections below. |

This is two distinct decisions, each large enough for its own section:

- **Migration** off the bundle / `creation_token` registries →
  [§3](#3-migration-strategy--the-central-decision).
- **NAR-superset milestone timing** →
  [§4](#4-does-the-nar-cache-superset-ship-this-milestone).

### Q8 — NAR blob `URL:` key: colon-free static key

| | |
|---|---|
| **Source** | Not in brief §16 — a WS-06 deployment decision surfaced by [workstream-06-nix-cache.md](./workstream-06-nix-cache.md) §7 (F388 / F389). |
| **Owner WS** | [WS-06](./workstream-06-nix-cache.md) (narinfo emitter), informs [WS-05](./workstream-05-consumer.md) §8 (consumer cache resolution) |
| **Status** | RESOLVED — the static cache producer uses a colon-free `URL:` key. |

**What is decided.** The blob is served at `{cache}/nar/<key>.nar.zst`, where the
emitted narinfo `URL:` field carries the relative key verbatim and the consumer
fetches it via `join_cache_url(mirror, narinfo.url)` (`download.rs:65-71`,
`:184`). The producer-side `nar_url` helper now writes
`nar/{store_hash}-{nar_hash with ':' -> '-'}.{ext}`. For a NAR hash like
`sha256:<hex>`, the served static object and narinfo `URL:` are both
`nar/<storehash>-sha256-<hex>.nar.zst`.

**Why this is closed.** Colon-free keys are accepted by ordinary filesystems,
S3-compatible stores, SFTP paths, HTTP object keys, and CDN/edge layers that
might otherwise percent-encode or reject a literal `:`. Because the narinfo
`URL:` and uploaded object path are generated from the same helper, there is no
per-deployment `colon_safe` switch in the current target.

**Verification.** `aos-core` tests cover `nar_url` and static narinfo rendering;
`aos-package` tests cover upload preserving the narinfo `URL:` object path and
`download_nars` following the narinfo-supplied colon-free path through a static
`file://` cache.

**Failure mode.** Pure reachability, never corruption: a mismatched `URL:` vs.
served-key yields a 404 on NAR fetch, not bad bytes. `apm` still verifies the
compressed stream against the narinfo `FileHash` (`download.rs:191-204`) and a
stock `nix` host still verifies `NarHash`.

### DD-1 — Doc-debt: re-ground the CURRENT-state baseline against the master rebase

| | |
|---|---|
| **Type** | Documentation debt (not a design decision) — flagged here so the owning docs are corrected before WS-06 lands. |
| **Owner WS** | [WS-06](./workstream-06-nix-cache.md) (narinfo emitter), with [WS-05](./workstream-05-consumer.md) (consumer) |
| **Status** | **RESOLVED** — the CURRENT-state re-grounding is done: the narinfo *format / sign* **logic** already exists (verified in code below) and is **reusable as a library**, and WS-06 is re-scoped from "build a narinfo emitter from scratch" to "**AOT-generate and upload static cache files** by reusing that logic". The registry serves the cache as **dumb static files on the CDN** — it does **not** run a server. |

The master rebase pulled in **commit `7149acf6`** ("apm: narinfo-driven NAR
downloads + export-format import"). Re-grounding against the current tree (the
`aos-server` / `aos-cache` / `aos-core` narinfo stack plus the narinfo-driven
`aos-package` consumer) confirms two CURRENT-state facts that several plan/
reference docs still described as they were *before* the rebase. Both are now
re-grounded.

**The correct serving model (brief §13).** The registry's Nix binary cache is
**dumb static files on the HTTP CDN, generated ahead-of-time (AOT) at publish** —
there is **no server at serve-time**. The artifacts are pre-built and uploaded
(`{cache-base}/nix-cache-info`, `{cache-base}/<storehash>.narinfo`,
`{cache-base}/nar/<…>.nar.zst`) and a stock `nix` / `apm` consumes them as an
ordinary static binary cache (the strict superset). The narinfo **format + sign +
FileHash** code below is therefore relevant as a **reusable generation library** —
the producer calls it to *emit the static files at publish* — **not** as a running
handler the registry stands up. The live `aos-server` nix-cache routes
(`cache_info_handler` / `narinfo_handler` / `nar_handler`) are a *different use
case*: a host serving its **own** Nix store dynamically (nix-serve-style). **The
registry never runs that server.**

1. **`download_hash` / `download_size` were removed from the registry schema —
   narinfo `FileHash` / `FileSize` are authoritative and emit-time-computed.**
   Commit `7149acf6` dropped both fields from `PackageMeta` (now `types.rs:44-74`)
   and from the on-disk `PlatformEntry` (`registry/parse.rs:45-51`); the consumer
   reads `FileHash` / `FileSize` from the narinfo, not from the package TOML. The
   server **already computes them at emit time** from the compressed bytes:
   `format_narinfo` (`crates/aos-server/src/narinfo.rs:27`) emits `FileHash:` /
   `FileSize:` unconditionally — for `Compression::None` they coincide with
   `NarHash` / `NarSize`, and for zstd / xz they are computed by
   `compute_file_hash_size` (`crates/aos-server/src/compress.rs:143`,
   `narinfo.rs:48`). **Consequence for WS-06:** the §5.2 open question is *resolved
   to emit-time compute* — this is the option-2 behavior that already ships, not a
   thing to build; the emitter does **not** read `FileHash` / `FileSize` off
   `PackageMeta` (option 1 assumed fields that no longer exist). WS-06 §5.1 / §5.2 /
   §10 / §11 (the schema prereq, the builder reading `meta.download_hash`) and
   [current-state.md](../../registry/current-state.md) (lines documenting
   `download_hash` / `download_size` as package-TOML fields) are re-grounded to this.

2. **The narinfo format / sign / FileHash *logic* already exists and is reusable
   as a generation library — so WS-06 reuses it, it does not build an emitter from
   scratch (and it does not stand up a server).** The pieces the AOT producer will
   call to *emit static files at publish* all ship today:
   - **Shared narinfo type** — `NarInfo` (`crates/aos-core/src/nar/info.rs:5`) with
     `parse()` (`:19`) / `format()` (`:81`) and `store_hash()` / `basename()`
     helpers, shared between server and consumer. The producer reuses this type +
     `format()` to serialize the static `<storehash>.narinfo` files.
   - **narinfo formatting** — `format_narinfo(&DbPathInfo, store_dir,
     &CompressionConfig, Option<&NarInfoSigner>)` (`crates/aos-server/src/narinfo.rs:27`)
     writes the full narinfo body; `URL: nar/{store_hash}-{nar_hash colon→dash}.{ext}`
     (`narinfo.rs:37`), `References:`/`Deriver:` as basenames, `Sig:` lines. This is
     the format/sign **routine the producer reuses** to generate each static narinfo
     — not a handler the registry serves at request time.
   - **Ed25519 narinfo signing** — `NarInfoSigner` (`crates/aos-server/src/sign.rs`):
     `load(key_file)` (`:14`), `sign(fingerprint) → "name:base64"` (`:44`), and the
     exact Nix narinfo `fingerprint(store_path, nar_hash, nar_size, refs)` (`:57`),
     applied at `narinfo.rs:87-93`. This is the "one Ed25519 key, reused for the
     narinfo `Sig:`" the brief calls for — the producer reuses it to sign the static
     narinfo files at publish.
   - **FileHash / FileSize compute** — `compute_file_hash_size`
     (`crates/aos-server/src/compress.rs:143`, called at `narinfo.rs:48`) computes
     `FileHash:` / `FileSize:` over the compressed bytes (for `Compression::None`
     they coincide with `NarHash` / `NarSize`). The producer reuses this (or captures
     the values at build time) when generating each static narinfo.
   - **Live nix-cache routes are a *different use case*, NOT what the registry runs** —
     `crates/aos-server/src/routes.rs:80-89` (`cache_info_handler` `:123` emitting
     `Priority: 30` at `:145`, `narinfo_handler` `:157`, `nar_handler` `:223`) serve a
     host's **own** Nix store dynamically, nix-serve-style. The registry **does not run
     this server**; it reuses the format/sign *library* above to pre-generate dumb
     static files. They are cited here only as the home of the reusable code and to
     reconcile the `Priority` value (below), not as a serving surface the registry
     stands up.
   - **Cache backends** — `crates/aos-cache/src/backend/{s3,sftp,http,fs}.rs` have
     `has`/`get`/`put_narinfo`; the backends write `Priority: 40`
     (`backend/sftp.rs:143`, `backend/fs.rs:126`).
   - **Narinfo-driven consumer (DONE)** — `crates/aos-package/src/download.rs` (commit
     `7149acf6`) uses `aos_core::nar::info`; `fetch_narinfos` fetches the narinfo
     and `download_nars` consumes it; `DownloadRequest` carries the `NarInfo`;
     `FileHash` / `NarHash` / `References` / `Deriver` all come **from** the narinfo;
     `narinfo_url(mirror_url, store_path)` (`:74`). The consumer already reads a
     **dumb static** narinfo cache as-is — no consumer change is needed.

   So the "no `nix-cache-info` / narinfo emission" / "narinfo server: n/a ❌"
   statements in [current-state.md](../../registry/current-state.md) and the
   *greenfield-emitter* framing in
   [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) are stale:
   the narinfo **format/sign/FileHash logic** exists and is reusable. But do **not**
   over-correct into the opposite error — the registry does **not** "serve" narinfo
   via a running handler, and WS-06 is **not** merely "point `[[caches]]` at the
   existing cache server". The registry's cache is **dumb static AOT files**;
   `format_narinfo` / `NarInfoSigner` / `compute_file_hash_size` are the **generation
   library** the producer reuses. Reconcile the `Priority` value: the
   reusable formatting routine emits `Priority: 30` (`routes.rs:145`) — use **30** for
   the generated `nix-cache-info`, and note the `aos-cache` backends write
   `Priority: 40` (`backend/sftp.rs:143`, `backend/fs.rs:126`). WS-06 §4's
   `Priority: 41` example is re-grounded against `30`.

**The remaining gap is the PRODUCER — AOT generation + upload, not an emitter-server
and not pure integration.** The format/sign logic above is store-DB-backed
(`DbPathInfo`) for the live-host use case and is **decoupled** from the git registry:
the git registry (`packages/*.toml`: `store_path` / `nar_hash` / `references` /
closure) is the metadata layer. The real TARGET work for the git-native registry
(WS-06) is to **GENERATE the static cache files at publish and UPLOAD them to the
CDN**, reusing the existing format/sign code as a library. Concretely, at publish,
for each store path in the registry's package closures:

- generate the static `<storehash>.narinfo` (reuse `NarInfo` + `format_narinfo` +
  the `NarInfoSigner` `Sig:`),
- compute `FileHash` / `FileSize` (reuse `compute_file_hash_size`, or capture at
  build time),
- produce the `nar/<…>.nar.zst` blob,
- emit `nix-cache-info` (`Priority: 30`),
- and **upload all of these as static CDN files**,

plus commit the repo-root `registry.toml` `[[caches]]` pointer to the CDN cache base
(authenticated transitively by the signed tag; `registries.d` override optional). The
consumer side (`download.rs`) is already done; this producer AOT generation + upload
is **genuine remaining work** — it reuses the existing format/sign logic rather than
writing a greenfield emitter, but it is *not* "already done", *not* "integration
only", and *not* a running server. WS-06 is re-scoped accordingly (see §4 and the
[WS-06 narinfo field-mapping doc](./workstream-06-nix-cache.md)).

This was a *re-grounding* task, not a re-decision: the TARGET design (dumb static
AOT cache on the CDN, brief §13) is unchanged, and the CURRENT-state baseline is now
corrected to "the format/sign logic is a reusable library; the producer AOT
generation + upload is the WS-06 work" — avoiding **both** the earlier "client-side
only" error and the "a running `aos-server` cache serves it / it is already done"
error.

---

## 2. Risk register

Risks that are not phrased as a single "which option" question but that the
implementation must actively manage. Each names the mitigation and the owning
workstream.

| ID | Risk | Likelihood × Impact | Mitigation | Owner WS |
|---|---|---|---|---|
| **R1** | **sha256 dumb-HTTP client incompatibility** (Q1). Old / non-sha256 gits cannot clone or verify; no capability negotiation to detect this. | Med × Med | Pin a tested minimum git version; emit a clear "requires sha256 git" error in the consumer instead of a low-level object panic; rely on loose-object completeness for in-range clients. | WS-01, WS-05 |
| **R2** | **Torn publish.** A consumer reads a low-TTL surface (`info/refs`, `/channels/**`, `objects/info/packs`) that names an object/pack not yet uploaded. | Low × High | `apr release` and `apr origin upload` publish immutable objects/packs/cache payloads **first** and low-TTL index/partition surfaces **last**. Loose-object completeness means a partially-published frontier still resolves via the prior release. Real CDN/mirror behavior still needs validation. | WS-02, WS-03 |
| **R3** | **Concurrent publishers race the partition advance.** Two `apr release` runs advancing the same channel's 256 partitions can interleave into an inconsistent rollout fraction. | Med × Med | `apr release` has a local publisher lock in the git dir. Multi-host production publishers still need one external serialization point per channel; immutable-object steps are content-addressed and need no coordination. | WS-03 |
| **R4** | **Online signing key exposure.** Removing in-band `valid_until` removes the heartbeat-re-sign pressure that wanted the Ed25519 key online for quiet channels (Q5); the remaining online-key need is key rotation, which re-signs live partitions. | Low × High | No routine re-sign — freshness is the consumer's max-staleness clock, not a signed window; sign partitions only on rollout advance; for rotation use `allowed_signers` overlap, never the long-term key online beyond the rotation event. | WS-04, WS-03 |
| **R5** | **Delta depth too deep → consumer reconstruct cost** (Q2). A large `--depth` shifts CPU onto every consumer applying the delta chain. | Low × Med | Cap `--depth` (suggest 50); window is the free lever, not depth (brief §10); document the consumer-cost rationale. | WS-02 |
| **R6** | **Bucket flap / skew** (Q3). A host recomputes a different bucket across syncs, or cloned images share a baked-in host identifier. | Med × Low | Implemented: first assignment uses generated registry-local salt; persisted bucket index wins afterward; probe-forward does not re-pin. | WS-03, WS-05 |
| **R7** | **Cross-serving / name-confusion.** A signed tag object served at the wrong path (a release tag served as a channel partition, or vice-versa) tricks a consumer. | Low × High | Name-binding verification: signature valid **and** embedded tag-name field == expected path name (channel name under `/channels/*`, semver under `/releases/*`); verify the whole `tag → tag → commit` chain (brief §5, §11). | WS-04, WS-05 |
| **R8** | **Migration straddle bugs** (Q7 / §3). A half-migrated host or mirror serves/reads neither model cleanly — an old bundle-mode client hits a git-native origin, or vice-versa. | Med × High | The two models share **no wire surface** (§3.1), so there is no torn-format hazard. Implemented policy: git-native `HEAD` + `info/refs` wins; legacy-only `bundle-list.toml` origins fail with a clean-break error; bundle-mode clients are EOL at registry cutover. | WS-05 |
| **R9** | **Anti-rollback floor vs. fix-forward.** A consumer that does not keep a monotonic floor could be walked backward by a misconfigured partition; conversely an over-strict floor blocks a legitimate fix-forward. | Low × High | Consumer keeps a monotonic floor (never moves to a release older than current); aborting a bad rollout is **fix-forward** (publish newer, advance partitions), never partition-decrement (brief §6). | WS-05, WS-03 |
| **R10** | **Freeze defense vs. availability** (Q5). With no in-band `valid_until`, freshness rests on the consumer's max-staleness policy: too short breaks quiet channels; too long weakens the freeze defense; and a frozen-but-validly-signed mirror is not self-evidently stale to a host with no recent fresh-frontier observation. | Med × Med | Implemented locally: 14-day default `max_staleness_seconds` gate on failed channel refreshes and unchanged-but-valid signed targets + low CDN TTL on mutable surfaces; anti-rollback floor as the hard gate; still validate the default against real fleet/CDN behavior. | WS-05, WS-04, WS-03 |
| **R11** | **zstd `--long` window mismatch.** A pack compressed with `--long=27` requires the consumer to decompress with a matching window (~128 MiB); a constrained client OOMs. | Low × Med | Pin the `--long` window in spec; ensure the consumer always passes the matching `-d --long`; size it against the smallest supported host. | WS-02, WS-05 |

---

## 3. Migration strategy — the central decision

> This section is the expanded answer to the migration half of **Q7** and the
> migration half of this document's mandate. It does not *decide* the question
> (the brief leaves it open, §16.7) but it frames the two paths, their
> consequences, and a recommended sequence so the decision can be made with eyes
> open.

### 3.1 What is actually changing on the wire

The redesign is **not** a field-swap inside one format — it is a **wholesale
replacement of the distribution and rollout model**. Almost nothing on the old
wire survives. What *is* preserved is the package-TOML *tree content* and the
Ed25519/SSH signing primitive (brief §2: "the target keeps the Ed25519/SSH
signing primitive and the
package-TOML tree content, and replaces *everything about distribution and
rollout*").

| Layer | Retired bundle model | Git-native model | Survives? |
|---|---|---|---|
| Package metadata | nested package TOMLs (`PackageToml`, `crates/aos-package/src/registry/parse.rs:14`) + `closures/<hash>` adjacency | **same TOML tree content**, now living as git tree objects in a sha256 bare repo (brief §3, §8) | **Yes** (content), repackaged as git objects |
| Root / manifest | `bundle-list.toml` manifest | **removed** — replaced by git refs + signed tag objects + relative `objects/info/alternates` (brief §15) | **No** |
| Distribution unit | **git bundles** + `bundle-list.toml` | **removed** — full packs `pack-<sha256>.pack(.idx)` + thin `delta-<from>.pack.zst` over dumb HTTP (brief §9, §10, §15) | **No** |
| Versioning / ordering | **calendar tags** `vYYYY.MM[.P]` ordered by `creation_token` | **standard semver, no `v`**; ordering by semver + git ancestry (brief §7, §15) | **No** |
| Selection | bundle selection by manifest plus branch/tag/version tracking | bucket → `/channels/<name>/<00..ff>` signed partition tag → semver tag → commit, then delta walk (brief §5, §6, §9) | **No** |
| Rollout | none beyond tracking-mode selection | **256 signed partition tags**, publisher-advanced N/256 (brief §6) | **No** (new) |
| Signing | signed git **commit** + TOFU `trusted-keys.d` | signed git **tag objects** as **pure signed pointers** — no structured payload, just standard tag fields + Ed25519 signature + optional freeform message (channel partitions + release tags), SSH-Ed25519, name-binding, `tag→tag→commit` (brief §5, §11) | **Yes** (primitive), moved commit→tag |
| Nix NAR cache | `[[caches]]` consumer reads with fallback cache URL behavior | cache location lives in the committed repo-root `registry.toml` `[[caches]]` (authenticated transitively by the signed tag), with client-side `registries.d` as an optional override (or the origin itself) — **not** advertised in tags; origin MAY serve `nix-cache-info`/`<storehash>.narinfo`/`nar` as a superset, narinfo `Sig:` reusing the one Ed25519 key (brief §13, §14) | **Yes** (mechanism), committed `registry.toml` + client override |

The headline: there is **no shared root file to dual-write**. The old model's
root is `bundle-list.toml`; the new model has *no* root file at all — its "root"
is the set of git refs and signed tag objects. The two models therefore occupy
**disjoint wire surfaces**, which changes the migration calculus entirely (see
R8).

### 3.2 Option A — compatibility shim (dual-publish, dual-read)

The producer publishes **both** a legacy bundle/`bundle-list.toml` surface *and*
the new git-native surface for a transition window; consumers prefer the
git-native model and fall back to bundles.

```
Mirror during the shim window:
  {base}/HEAD, info/refs, objects/**, /channels/**, /releases/**   ← new clients (git-native)
  {base}/bundles/{name}/bundle-list.toml                          ← old clients (legacy fallback)
  {base}/bundles/{name}/*.bundle                                  ← legacy bundle blobs
```

- **Producer:** the new `apr release` writes the full git-native surface *and*
  keeps regenerating bundles + `bundle-list.toml`. This requires keeping (and
  finishing) a **`bundle-list.toml` writer that the active code no longer
  contains**. So the shim is *not* free; it forces building and testing a
  serializer plus `creation_token` producer encoding for a format we intend to
  retire.
- **Consumer:** `apm update` probes for git refs (`info/refs` present?); on a
  legacy-only mirror, a shim-era client would need a bundle fallback. The active
  git-native client instead fails legacy-only origins closed with the clean-break
  error described in Option B.

| Pros | Cons |
|---|---|
| Old clients keep working with zero coordination. | Must **build** a throwaway `bundle-list.toml` writer **and** a producer-side `creation_token` encoder — new code for a dying format. |
| Mirrors can be migrated lazily, one at a time. | Two entirely different distribution models to keep consistent — a skewed pair (frontier semver ≠ latest `creation_token`) is a new failure mode (R8). |
| No flag day; safe for fleets with mixed client versions. | Old-root clients get **none** of the new properties (signed partition rollout, name-binding, delta packs, anti-rollback floor) for the duration — the shim *weakens the security/rollout story* while it runs. |
| | Indefinite straddle risk if the EOL is never enforced. |

### 3.3 Option B — clean break with a capability gate

The bundle / `bundle-list.toml` / `creation_token` surface is removed; the
registry serves only the git-native model; consumers are cut over by version.

- **Producer:** `apr release` writes only the git-native surface. The dead
  bundle-manifest writer, `creation_token` producer encoding, and bundle
  selection path are **deleted**, not revived.
- **Consumer:** clients are upgraded to the git-native fetch path *before* any
  mirror drops bundles. The current consumer treats plain `http(s)://` origins
  as git-native dumb-HTTP registries and preflights `HEAD` plus `info/refs`.
  A legacy-only origin that exposes `bundle-list.toml` but not the git-native
  surface fails with a clear "legacy bundle-mode registry" / "no longer
  supports the bundle/creation_token registry model" error. If both surfaces are
  present during a temporary mirror straddle, the git-native surface wins and
  `bundle-list.toml` is ignored. Signed tags carry no structured payload (pure
  signed pointers, brief §11), so forward-compat for *future* git-native changes
  is carried by the layout/refs surface, not by a versioned field inside the
  signed tag.

| Pros | Cons |
|---|---|
| No throwaway serializer / encoder; the dead bundle path is deleted, not finished. | Requires a coordinated client rollout *before* mirror cutover (a flag day per registry). |
| Full target model (signed 256-partition rollout, name-binding, delta packs, anti-rollback, NAR superset) from day one for every client. | Old `apm` binaries break the moment a registry cuts over — bad for fleets that pin old clients. |
| One distribution model; no dual-surface consistency hazard (closes R8). | Needs a "minimum client version" gate communicated and enforced. |
| Simplest producer; fewest moving parts in the highest-risk new pipeline (WS-02). | |

### 3.4 Ratified path: clean break, gated by git-native preflight

This implementation ratifies the **clean break**. The two models share **no
distribution surface** — bundles vs. packs, `creation_token` vs. semver,
`bundle-list.toml` vs. git refs — so a true dual-*publish* shim would mean
building two complete producers, one of them (`bundle-list.toml` +
`creation_token` writer) brand-new code for a retired format. That cost is not
being paid.

The implemented policy:

1. **Use the git-native consumer only.** `apm update` probes plain `http(s)://`
   origins for `HEAD` and `info/refs`; origins with those files are consumed via
   the git-native path. A legacy-only mirror that still exposes
   `bundle-list.toml` is rejected with an actionable clean-break error. There is
   no active bundle-mode fallback in this client.
2. **Producer publishes only the git-native surface (WS-01/02/03).** Do **not**
   build the bundle/`bundle-list.toml`/`creation_token` writer. New registries are
   git-native only. Any legacy mirror keeps its already-published static
   `bundle-list.toml` + `*.bundle` files for old clients only and is not
   regenerated by the git-native producer.
3. **Verify the sha256 dumb-HTTP floor (Q1) before cutover.** A clean break to
   sha256 git is only safe once the minimum git/consumer version is pinned and
   the consumer fails closed with a clear message on too-old clients.
4. **Treat the cutover as the EOL boundary for bundle-mode clients per registry.**
   Operators must upgrade clients before pointing them at git-native origins.
   Old bundle-mode clients can keep using legacy mirrors until those mirrors are
   retired, but git-native registries do not promise a `bundle-list.toml`
   compatibility surface.

This converges on the clean break's single-model simplicity and full
security/rollout model. The residual exposure is that already-published legacy
mirrors lack the new rollout/anti-rollback protections, which is acceptable only
because those mirrors are end-of-life by construction.

### 3.5 Migration invariants (whatever path is chosen)

These must hold regardless of clean break vs. shim:

1. **Already-published legacy bundle blobs are never rewritten.** A legacy mirror
   keeps serving the same `*.bundle` / `bundle-list.toml` bytes; migration never
   mutates the old surface, it only adds (shim) or replaces-at-new-origin (clean
   break) the new one (§3.1).
2. **No indefinite straddle.** Any dual-detect / dual-publish window has a
   published EOL; the registry must not carry two distribution models forever
   (R8).
3. **The signed object is the trust root throughout.** The old model's signed
   *commit* and the new model's signed *tag objects* are both Ed25519/SSH over the
   same package-TOML history; migration never introduces an unsigned intermediary
   (brief §2, §5, §11).
4. **Monotonicity survives the model cutover.** A host moving from a `creation_token`-
   ordered legacy mirror to a semver-ordered git-native registry must not read the
   transition as a rollback. Because the two orderings are incomparable, the
   consumer's **anti-rollback floor must be re-seeded** (not naively compared) at
   cutover: record the new semver frontier as the floor on first git-native sync,
   rather than comparing it against a stale `creation_token` (brief §6 anti-
   rollback; R9).
5. **Name-binding is enforced from the first git-native fetch.** Every signed tag
   a migrating consumer accepts must pass the embedded-tag-name == expected-path
   check (channel name under `/channels/*`, semver under `/releases/*`) — there is no
   "trust this during migration" relaxation (brief §5, §11; R7).

---

## 4. Does the NAR-cache superset ship this milestone?

> This is the second half of **Q7** (brief §16.7): "whether the NAR cache
> superset (origin-served narinfo, located via the committed `registry.toml`
> `[[caches]]` with client-side `registries.d` override) ships in the
> same milestone or later." It is a milestone-sequencing question, not a
> wire-format question.

### 4.1 What the superset is

The Nix binary-cache surface is **orthogonal** to the git-object metadata layer
(brief §13). The cache location is **not advertised in signed tags** — tags carry
no structured payload. Instead it is the **consumer's client-side registry
config** (its local config) or the origin itself. The origin **MAY** serve the
standard Nix surface as a superset:

```
# served at the cache location (the origin, or whatever the client config names)
nix-cache-info
<storehash>.narinfo
nar/
```

This is "a strict superset for stock `nix` dev-shell substitution" (brief §13).
narinfo `Sig:` signing, if served, reuses the **one Ed25519 key** (brief §11,
§13). The consumer already separates this concern today: `download.rs:67
resolve_mirror` resolves the cache from its config and falls back to
`{registry}/nar`, and `download.rs:57 nar_url` builds the per-NAR URL — so the
*consumer plumbing exists*; what is new is the producer emitting the narinfo
surface at the origin. There is **no tag-embedded `[[caches]]`** to source from.

### 4.2 Why it can ship later (and probably should)

| Factor | Implication for sequencing |
|---|---|
| **Disjoint URL namespace.** The Nix surface (`nix-cache-info`, `*.narinfo`, `nar/`) never overlaps the git surface (`objects/`, `/channels/`, `/releases/`). | It is a **strict superset** — adding it later can never break an existing git-native consumer. It is pure additive scope. |
| **Different consumer.** The git layer serves `apm` (and stock `git clone`); the NAR layer serves **stock `nix`** dev-shell substitution. | The two have independent users; the AOS fleet does not need the NAR layer to receive releases. |
| **Independent signing reuse.** narinfo `Sig:` reuses the same Ed25519 key as a *separate* signature object (brief §11). No tag re-issue is involved — tags carry no cache pointer. | No new trust primitive; it slots in whenever the producer is ready. |
| **Producer cost.** Emitting narinfos for every store path in a release closure is a non-trivial producer step, and stock-`nix` acceptance (correct `References:` basename expansion, `Sig:`, `nix-cache-info`) needs golden-file testing against a real substituter. | This is incremental producer work that does not block the git-native MVP and benefits from being landed and tested in isolation. |

### 4.3 Recommendation

**Ship the git-native object store, pack/delta pipeline, channels/rollouts, and
signing (WS-01 through WS-05's consumer git path) as the first milestone. Ship
the NAR-cache superset as a fast-follow milestone**, because:

1. It is a strict superset in a disjoint namespace — deferring it costs the
   git-native fleet nothing.
2. Its risk profile (stock-`nix` narinfo acceptance, colon-in-filename through
   edges, `References:` expansion) is independent and benefits from dedicated
   golden-file testing rather than being rushed alongside the higher-risk
   pack/delta work.
3. The cache-resolution *consumer* hook already exists (`download.rs`), reading
   the cache from client-side config, so adding the producer narinfo surface later
   is low-coupling.

There is **no tag-schema coordination point** — because the cache location lives in
the committed `registry.toml` `[[caches]]` (client-side `registries.d` override, or
the origin), not a tag-embedded pointer, turning the
superset on later is a pure producer-plus-client-config change: no tag re-issue,
no schema bump, nothing reserved in the signed material. Document the cache surface
in
[nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md).

---

## 5. Decision tracking

A compact index for reviewers. "Blocks" = which workstream cannot merge until the
item is closed.

| # | Question / Risk | Owner WS | Blocks merge of | Default recommendation |
|---|---|---|---|---|
| Q1 | sha256 dumb-HTTP client floor | WS-01 | WS-01 object store, WS-05 fetch | Pin min git version; fail-closed consumer error |
| Q2 | libgit2/Rust pack tuning, zstd, dictionary | WS-02 | WS-02 pipeline | Keep libgit2 full packs + Rust thinpack; keep zstd `--ultra -22 --long=27`; defer dictionary |
| Q3 | Bucket-selection input + probe-forward order — **RESOLVED** | WS-03 / WS-05 | (none) | Registry-local salt; persist bucket index; probe `(bucket+i) mod 256` no re-pin |
| Q4 | `apr release` shape + pluggable upload | WS-02 / WS-03 | WS-02/03 (the pipeline) | Resolved: `apr release` wrapper over focused verbs; repeatable file/HTTP/S3/SFTP upload URLs; immutable-first / low-TTL-last ordering |
| Q5 | Consumer max-staleness policy + key-rotation cadence | WS-05 / WS-04 / WS-03 | WS-05 consumer, WS-04 trust | Partial: 14-day `max_staleness_seconds` gate on failed refreshes and unchanged valid targets; still validate production default and key cadence |
| Q6 | Relative `info/alternates` (one `../`, HTTP + local-FS) | WS-01 | WS-01 layout | One host-independent relative `info/alternates`, one-`../`; no `http-alternates` |
| Q7a | Migration: clean break vs. shim — **RESOLVED** | WS-05 / WS-01 / WS-03 | (none) | Clean break: git-native `HEAD` + `info/refs` wins; legacy-only `bundle-list.toml` origins fail with a clear error; bundle-mode clients are EOL at registry cutover (§3.4) |
| Q7b | NAR superset milestone timing | WS-05 | (none — fast-follow) | Defer to fast-follow; cache lives in committed `registry.toml` `[[caches]]` (client-side `registries.d` override / origin), nothing reserved in tags (§4.3) |
| Q8 | NAR blob `URL:` key — **RESOLVED** | WS-06 | (none) | Colon-free static key: `nar/{storehash}-sha256-{hex}.{ext}`; producer, upload, and consumer follow the narinfo `URL:` verbatim |
| DD-1 | Doc-debt: re-ground CURRENT-state after `7149acf6` — **RESOLVED** | WS-06 / WS-05 | (docs — gated WS-06 §5/§10/§11 accuracy; now re-grounded) | **Done.** Cache = **dumb static AOT files on the CDN, no server** (brief §13). The narinfo **format/sign logic** is a reusable library: `aos-core` `NarInfo`+`format()`, `aos-server` `format_narinfo`+`NarInfoSigner` Ed25519 `Sig:`+`Priority: 30`, `compute_file_hash_size` (`compress.rs:143`). **Consumer done** (narinfo-driven `download.rs`). **WS-06 = PRODUCER work**: at publish, *generate* the static `<storehash>.narinfo` / `nar/<…>.nar.zst` / `nix-cache-info` by **reusing** that format/sign code, and **upload** them to the CDN, plus the committed `registry.toml` `[[caches]]` pointer. Not a running server, not "integration only". |
| R2/R3 | Torn publish / publisher race | WS-02 / WS-03 | WS-02, WS-03 | Immutable-first / low-TTL-last implemented; local publisher lock implemented; production multi-host serialization still operational |
| R7 | Cross-serving / name-confusion | WS-04 / WS-05 | WS-04, WS-05 | Name-binding: embedded tag-name == path name; verify `tag→tag→commit` |
| R9 | Anti-rollback floor across cutover | WS-05 | WS-05 | Re-seed floor at git-native cutover; fix-forward only |

---

## 6. Related documents

**Plan set ([docs/plans/registry/](./README.md)):**

- [README](./README.md) — plan overview, milestones, sequencing.
- [design-brief.md](./design-brief.md) — authoritative intent; §16 is the source of this doc.
- [gap-analysis.md](./gap-analysis.md) — producer/consumer gap enumeration.
- [workstream-01-object-store.md](./workstream-01-object-store.md) — sha256 bare repo, dumb-HTTP layout, relative `info/alternates`, root `/objects/` + pack-only release dirs (Q1, Q6, R2).
- [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md) — archival pack/delta plan; current implementation uses libgit2 full packs, Rust thin packs, zstd (Q2, Q4, R2, R5, R11).
- [workstream-03-channels-rollouts.md](./workstream-03-channels-rollouts.md) — 256 partition tags, frontier, bucket selection (Q3, Q4, Q5, R3, R6, R9, R10).
- [workstream-04-signing-trust.md](./workstream-04-signing-trust.md) — signed tag objects (pure signed pointers), name-binding, key rotation (Q5, R4, R7, R10).
- [workstream-05-consumer.md](./workstream-05-consumer.md) — resolution, delta walk, retention, freshness/staleness policy, verification, client-side-configured NAR cache superset (Q1, Q3, Q5, Q7, R1, R6, R7, R8, R9, R10).

**Reference set ([docs/registry/](../../registry/README.md)) — target state:**

- [README](../../registry/README.md) ·
  [architecture.md](../../registry/architecture.md) ·
  [current-state.md](../../registry/current-state.md) ·
  [http-layout.md](../../registry/http-layout.md) ·
  [versioning-and-channels.md](../../registry/versioning-and-channels.md) ·
  [packs-and-deltas.md](../../registry/packs-and-deltas.md) ·
  [signing-and-trust.md](../../registry/signing-and-trust.md) ·
  [publishing.md](../../registry/publishing.md) ·
  [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) ·
  [apt-comparison.md](../../registry/apt-comparison.md)
