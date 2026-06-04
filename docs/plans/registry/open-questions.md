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
> objects** under `/channel/<name>/00..ff`, incremental fetch is **thin
> `delta-*.pack`s**, and an optional **Nix NAR cache superset** is advertised via
> a `[[caches]]` entry in the tag-message TOML. There is **no `registry.toml`
> root, no `bundle-list.toml`, no git bundles, no `creation_token`, no
> percentage rollout** (design brief §15).
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

- [WS-01 — object store](./workstream-01-object-store.md) — sha256 bare repo, dumb-HTTP layout, `info/refs` / `HEAD` / `http-alternates` / `update-server-info`, per-release object dirs.
- [WS-02 — pack/delta pipeline](./workstream-02-pack-delta-pipeline.md) — `pack-objects` thin/full, the delta scheme, zstd, expensive-producer tuning.
- [WS-03 — channels & rollouts](./workstream-03-channels-rollouts.md) — 256 signed partition tags, channels-as-branches / frontier, bucket selection, publisher rollout control.
- [WS-04 — signing & trust](./workstream-04-signing-trust.md) — signed tag objects, name-binding, sha256, `valid_until`, anti-rollback / fix-forward.
- [WS-05 — consumer](./workstream-05-consumer.md) — consumer resolution (bucket → channel tag → semver tag → commit), delta walk, retention, verification, and the Nix `[[caches]]` superset.

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
| **Status** | OPEN — empirical compatibility task, not a design choice. |

**Why it is open.** The dumb-HTTP transport has **no capability negotiation** —
the client never learns the server's object format; it must already be a sha256
git. The repo is created `git init --object-format=sha256` (design brief §8), so
a client built without sha256 support, or an older git that assumes sha1 loose
paths, cannot clone. The 2/62 hex split of a 64-char sha256 loose object path
(`/objects/<xx>/<62-hex>`) is *visually* indistinguishable from a sha1 2/38
split until the client tries to verify the object, at which point it fails
opaquely.

**What must happen.** WS-01 must establish a tested floor: the minimum git
version that can `git clone <url>` and `git verify-tag <semver>` against the
sha256 dumb-HTTP origin, for both stock git and the libgit2/`gix` (or shell-out)
path the AOS consumer uses. Pin that floor in
[http-layout.md](../../registry/http-layout.md) and
[signing-and-trust.md](../../registry/signing-and-trust.md), and gate the
consumer with a clear "this registry requires a sha256-capable git" error rather
than a low-level object-format panic.

**Failure mode.** Loud but late: a stock `git clone` against the origin fails
for users on old gits with a confusing "unknown object format" / "bad object"
error far from the real cause (their git is too old). For the AOS consumer the
mitigation is the loose-object fallback (brief §8: "ALL objects exist loose …
the guaranteed completeness fallback") — but that fallback is still sha256 and
does not rescue a non-sha256 client.

### Q2 — `pack-objects` window/depth, zstd level, and trained dictionaries

| | |
|---|---|
| **Brief §16.2** | "Exact `pack-objects` window/depth and zstd level defaults (and whether to ship a trained dictionary per release line)." |
| **Owner WS** | [WS-02](./workstream-02-pack-delta-pipeline.md) |
| **Status** | OPEN — tuning, with a correctness floor on `depth`. |

**What is decided (TARGET).** The producer pays so the consumer does not (brief
§3 asymmetric-cost philosophy). Pack generation uses the expensive-producer
flags (design brief §10):

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

The **zstd trick** is load-bearing and decided: git hard-codes zlib per object,
so `--compression=0` produces a valid-but-uncompressed pack (delta encoding still
applied), and `zstd --ultra -22 --long=27` does the entropy coding over the
delta-encoded stream, beating zlib-9 while the pack stays git-valid (brief §10).
The client does `zstd -d | git index-pack --fix-thin`.

**What is open.**

1. **Window.** `--window=350` is the suggested default. Window is "the free
   lever" (brief §10) — it costs only producer CPU/RAM — so it can be raised. The
   open task is to measure the marginal pack-size win per window step on a real
   release line and pin a default (and a per-line override) in
   [packs-and-deltas.md](../../registry/packs-and-deltas.md).
2. **Depth — has a correctness floor.** `--depth=50` is suggested but **capped
   deliberately**: deep delta chains cost the *consumer* CPU to reconstruct
   (brief §10). Depth is the one tuning knob that is not purely a producer cost;
   raising it trades consumer reconstruct latency for marginal size. Pin a
   conservative default and document the consumer-cost rationale.
3. **zstd level / `--long` window.** `--ultra -22 --long=27` is the suggested
   default; confirm the decompression-side `--long` window requirement is within
   the consumer's `zstd -d` memory budget (the `--long=27` window forces a
   matching `-d --long=27` on the client, costing ~128 MiB).
4. **Trained dictionary per release line.** A zstd **trained dictionary** across
   a release line's small delta packs is "an optional further win" (brief §10).
   Open: is the size win worth the producer training step and the consumer
   dictionary-fetch round-trip? Recommend deferring — ship plain `--long`
   compression first, add a dictionary only if delta packs are dominated by
   cross-delta redundancy.

**Recommendation.** Ship `--window=350 --depth=50 --threads=0 --compression=0` +
`zstd --ultra -22 --long=27` as the defaults; expose window/depth/zstd-level as
producer config; defer trained dictionaries to a WS-02 follow-on. The producer
"may also try multiple delta bases and ship the smallest" (brief §10) — make that
an opt-in, not a default, because it multiplies producer cost.

**Failure mode.** Pure cost/size, never correctness (the loose-object and
full-pack fallbacks are always valid). A bad depth choice shows up as slow
`git index-pack` on the consumer; a bad window choice shows up as larger-than-
necessary packs. Neither corrupts bytes.

### Q3 — Bucket-selection input and probe-forward fallback order

| | |
|---|---|
| **Brief §16.3** | "Bucket-selection input (`machine_id` source) and the probe-forward fallback order." |
| **Owner WS** | [WS-03](./workstream-03-channels-rollouts.md) (partition model), [WS-05](./workstream-05-consumer.md) (client selection) |
| **Status** | OPEN — both the hash input and the missing-partition fallback are undecided. |

**What is decided (TARGET).** A channel exposes exactly **256** partition files
`/channel/<name>/00..ff`, each an independently-signed tag object whose tag name ==
the channel name, pointing at a semver tag (brief §6). The consumer
**deterministically self-selects one bucket** and **persists** it (e.g.
the low byte of `sha256(machine_id)` (i.e. mod 256), written once) so a host does not flap between
buckets across promotions. The publisher rolls a release to N/256 of the fleet by
pointing N partitions at the new semver tag and leaving the rest on the prior
release; un-advanced partitions still name the prior release (brief §6 — this is
the explicit answer to "where does the rest of the fleet go"). Completion = all
256 partitions point at the new release.

**What is open.**

1. **`machine_id` source on AOS.** Which identifier seeds the low byte of
   `sha256(machine_id)` (i.e. mod 256)? Candidates: `/etc/machine-id`, systemd's machine-id, or a registry-local
   salt persisted on first use. The choice fixes whether two hosts that share a
   golden image (and thus a baked-in machine-id) collide into the same bucket —
   which would skew rollout. Recommend a **registry-local salt generated once on
   first sync** (not the image-baked machine-id) so cloned images re-randomize,
   *and* persist the resulting bucket so it never flaps (brief §6).
2. **Persistence semantics.** The bucket is "written once" (brief §6). Confirm:
   is it the *input* (`machine_id`/salt) that is persisted and the bucket
   recomputed, or the *bucket index* that is persisted directly? Persisting the
   bucket index directly is simplest and immune to a future hash-function change;
   persisting the input lets the partition count change later (it will not — it is
   fixed at 256, brief §6). Recommend persisting the **bucket index** (00–ff).
3. **Probe-forward fallback order.** "There **must always be 256**; if one is
   missing a client **may** use another (deterministic probe-forward
   `(bucket+1) mod 256`)" (brief §6). Open: how many probe steps before giving up,
   and does a probe-forward host pin to the probed bucket or retry its home bucket
   next sync? Recommend: probe `(bucket+i) mod 256` for `i = 1..255`, use the first
   present partition, but **do not** re-persist — keep the home bucket so the host
   returns to it once the missing partition is republished.

**Recommendation.** Seed from a registry-local salt; persist the resulting
bucket index 00–ff; probe-forward `(bucket+i) mod 256` without re-pinning. Spell the
exact pre-image and the probe loop in WS-03 / WS-05 so client and producer agree.
This is operational, not a correctness gate — a wrong choice degrades to "rollout
fractions are uneven", never "a host gets bad bytes" (the anti-rollback floor,
brief §6, still protects every host).

### Q4 — Single `apr release` / `apr publish` command and pluggable upload

| | |
|---|---|
| **Brief §16.4** | "Whether `apr` grows a single `apr release`/`apr publish` command that does the whole pipeline (commit → tag/sign → pack/delta/zstd → update-server-info → advance partitions → upload) and whether upload backends are pluggable." |
| **Owner WS** | [WS-02](./workstream-02-pack-delta-pipeline.md) (pack/delta), [WS-03](./workstream-03-channels-rollouts.md) (advance partitions) |
| **Status** | OPEN — the central producer-side build decision. |

**Why it is the crux.** The producer is the asymmetry: the consumer is rich, but
the producer side is a **stub today**. `apr bundle` is just `git bundle create`
with **no manifest writer** and an **unused dead parameter**
(`_update_manifest: bool` at `crates/aos-package/src/registry_ops.rs:1723`); there
is no upload, no delta classification, no `update-server-info` orchestration.
None of that survives into the target (git bundles are removed, brief §15), so
the producer is effectively a greenfield build. The brief's §4 / §6 / §10 publish
model only becomes real when one ordered sequence runs end-to-end:

```
apr release  (TARGET — performs the full ordered pipeline):
  1. apr publish  → write package-TOML tree → git commit (sha256)
  2. git tag -s <semver> → commit            (SSH-Ed25519 signed release tag)
  3. pack/delta/zstd from the release commit:
       - full pack-<sha256>.pack (+ .idx)  at every X.Y.0
       - thin delta-<from-semver>.pack[.zst] per the §9 delta scheme
  4. git update-server-info                  (regenerate info/refs, HEAD)
  5. write objects/info/http-alternates      (all /release/*/objects, newest→oldest)
  6. upload immutable content first          (loose objects, packs — any order)
  7. advance N of the 256 /channel/<name>/00..ff signed partition tags  (rollout)
  8. low-TTL surfaces last                    (/channel/**, info/refs, HEAD, packs)
```

**Open sub-questions.**

1. **Command surface.** One `apr release` that does everything, or composable
   verbs (`apr pack` → `apr delta` → `apr upload` → `apr advance`) that a release
   script chains? Composable verbs are more testable and let CI own ordering; a
   single command is the safer default for humans because the ordering
   (immutable-first, low-TTL surfaces last) is the *only* safe order.
2. **Pluggable upload backends.** S3, rsync, and plain HTTP PUT are all
   plausible. Unlike the superseded `registry.toml` flip, the git-native model
   has **no single root file to atomically swap** — the "commit point" is the set
   of low-TTL surfaces (`/channel/**`, `info/refs`, `HEAD`, `objects/info/packs`)
   that must be published *after* all immutable objects exist. The atomicity
   requirement is therefore "publish immutable objects → then publish the low-TTL
   index/partition surfaces", and it is **backend-independent** (no conditional
   PUT needed) *as long as the ordering holds* (see R2).
3. **Where pack/delta generation runs.** On the publishing host from the landed
   commit, or as a separate CI job that re-derives from the signed tag? The signed
   tag makes the second option safe (the commit is content-addressed and signed),
   but the first is simpler.
4. **Idempotency / resume.** Steps 3–6 (immutable objects) must be safely
   re-runnable after a partial failure — they are content-addressed, so re-upload
   is a no-op. Only steps 4/5/7/8 (index + partition advance) mutate shared state.

**Recommendation.** Build composable verbs underneath a single `apr release`
convenience wrapper; make upload a trait with S3/rsync/PUT impls; require all
backends to honor the immutable-first / low-TTL-last ordering and document that
the rollout-partition advance (step 7) is the *only* publisher-coordination point
(restrict concurrent publishers per channel, see R3). This is the heart of WS-02
/ WS-03 and gates the whole target design becoming operable.

### Q5 — `valid_until` window length and re-sign / key-rotation cadence

| | |
|---|---|
| **Brief §16.5** | "Release `valid_until` window length and re-sign/key-rotation cadence." |
| **Owner WS** | [WS-04](./workstream-04-signing-trust.md), [WS-03](./workstream-03-channels-rollouts.md) (channel `valid_until`) |
| **Status** | OPEN — policy + automation, no single right number. |

**What is decided (TARGET).** Both channel partition tags and release tags carry
a TOML message with a `[meta] valid_until` (brief §14). Its **meaning differs by
surface** (brief §11):

- **Channel partition tags** — `valid_until` is the **freshness** knob, paired
  with the low CDN TTL on `/channel/**`. A short window is *correct* here: it is
  the freeze defense against a stalled mirror serving a validly-signed-but-stale
  partition.
- **Release tags** — `valid_until` is a **generous signature-trust /
  key-rotation lifetime**. It **must not fight the long release TTL** (brief §11):
  releases are immutable and long-cached, so a release tag whose signature expires
  while the bytes are still being served would break consumers reconstructing an
  old base for a delta walk.

```toml
# /channel/stable/<00..ff> tag message  — short, freshness-paired
[meta]
schema      = 1
valid_until = "2026-06-11T00:00:00Z"   # ~days; paired with low /channel/** TTL

# /release/1/1/0 (refs/tags/1.1.0) tag message — generous
[meta]
schema      = 1
valid_until = "2027-06-04T00:00:00Z"   # generous; must outlast the release TTL
```

**The tension (channel partitions).** The channel window trades two failure
modes:

- **Too long** (e.g. 90 days): a freeze attack / stalled mirror can serve a stale
  partition for up to the window before clients fail closed.
- **Too short** (e.g. 1 day): every host in a low-velocity deployment breaks the
  moment publishing pauses (holidays, incidents, a quiet channel), turning a
  security feature into an availability footgun — and it demands a heartbeat
  re-signer whose key is online (reopens R4).

**Open sub-questions.**

1. **Default channel window** and whether it is per-registry / per-channel
   configurable.
2. **Release window length** — long enough to outlast the release CDN TTL *and*
   the client retention window (a client on `X.Y.Z` retains `X.0.0`, `X.Y.0`,
   `X.Y.Z` object trees, brief §9, and may need to verify an old base tag's
   signature mid-walk).
3. **Re-sign cadence.** Re-sign channel partitions on every rollout advance with
   `valid_until = now + N`; add a **heartbeat re-sign** for channels that publish
   less often than `N`. Release tags are re-signed only on **key rotation**, not
   routinely.
4. **Key rotation.** One Ed25519 key serves git signing (and, if NARs are served,
   narinfo `Sig:`) (brief §11). Rotating it means re-signing live channel
   partitions and — for releases still inside their `valid_until` — re-signing or
   accepting both keys via `allowed_signers` during overlap.
5. **Clock-skew tolerance** on the client when comparing `now` to `valid_until`.

**Recommendation.** Channel partitions: short, generous-enough default (suggest
~7–14 days), configurable, re-signed on every advance plus a scheduled heartbeat
(WS-03 follow-on, not a launch blocker). Release tags: window comfortably longer
than the longest expected retention/TTL (suggest ≥ 1 year), re-signed only on
rotation. Document both numbers in
[signing-and-trust.md](../../registry/signing-and-trust.md) and
[tag-metadata.md](../../registry/tag-metadata.md).

### Q6 — `info/alternates` readable mirror alongside `http-alternates`

| | |
|---|---|
| **Brief §16.6** | "Whether `info/alternates` (readable mirror) is worth maintaining alongside `http-alternates`." |
| **Owner WS** | [WS-01](./workstream-01-object-store.md) |
| **Status** | OPEN — low-stakes convenience choice. |

**What is decided (TARGET).** `objects/info/http-alternates` lists every
`/release/*/objects/` dir newest→oldest; git's dumb fetcher follows it to resolve
the distributed per-release object store as one logical store, and it **doubles
as the full release index** (brief §4, §8). `http-alternates` (not `alternates`)
is the one git's HTTP fetcher actually consumes for URL-reachable stores
(brief §8). `info/alternates` is described only as an **optional human/agent-
readable mirror** of the same list (brief §4, §8).

**What is open.** Whether to emit and maintain `info/alternates` at all. It is
not consumed by git over HTTP (that is `http-alternates`' job), so its only value
is a readable cross-check for humans and agents inspecting the origin.

**Recommendation.** Emit `info/alternates` opportunistically (it is a trivial
byproduct of generating `http-alternates`) but treat it as **non-authoritative**
— never let a consumer depend on it, and never let the two diverge silently. If
maintaining both proves to be a consistency footgun, drop `info/alternates` and
keep only `http-alternates`. Lowest-stakes item on this list.

### Q7 — Migration (clean break vs. shim) and NAR-superset milestone

| | |
|---|---|
| **Brief §16.7** | "Migration from the existing bundle/`creation_token` registries (clean break vs shim) — and whether the NAR cache superset (`[[caches]]` + narinfo) ships in the same milestone or later." |
| **Owner WS** | [WS-05](./workstream-05-consumer.md) (consumer cutover), [WS-03](./workstream-03-channels-rollouts.md) (channel/ref model), all producer WS |
| **Status** | OPEN — the two highest-leverage questions. Own their own sections below. |

This is two distinct decisions, each large enough for its own section:

- **Migration** off the bundle / `creation_token` registries →
  [§3](#3-migration-strategy--the-central-decision).
- **NAR-superset milestone timing** →
  [§4](#4-does-the-nar-cache-superset-ship-this-milestone).

---

## 2. Risk register

Risks that are not phrased as a single "which option" question but that the
implementation must actively manage. Each names the mitigation and the owning
workstream.

| ID | Risk | Likelihood × Impact | Mitigation | Owner WS |
|---|---|---|---|---|
| **R1** | **sha256 dumb-HTTP client incompatibility** (Q1). Old / non-sha256 gits cannot clone or verify; no capability negotiation to detect this. | Med × Med | Pin a tested minimum git version; emit a clear "requires sha256 git" error in the consumer instead of a low-level object panic; rely on loose-object completeness for in-range clients. | WS-01, WS-05 |
| **R2** | **Torn publish.** A consumer reads a low-TTL surface (`info/refs`, `/channel/**`, `objects/info/packs`) that names an object/pack not yet uploaded. | Low × High | Strict ordering: upload all immutable objects (loose + packs) **first**, regenerate/publish the low-TTL index and partition surfaces **last** (brief §4, §10). Loose-object completeness means a partially-published frontier still resolves via the prior release. | WS-02, WS-03 |
| **R3** | **Concurrent publishers race the partition advance.** Two `apr release` runs advancing the same channel's 256 partitions can interleave into an inconsistent rollout fraction. | Med × Med | Restrict to a single publisher per channel, or serialize the partition-advance step; the immutable-object steps are content-addressed and need no coordination. | WS-03 |
| **R4** | **Online signing key for channel heartbeat re-sign.** The short channel `valid_until` (Q5) wants the Ed25519 key available off the publish path to heartbeat-re-sign quiet channels. | Med × High | Prefer advance-time re-sign only at launch; if a heartbeat is needed, use a short-lived delegated key via `allowed_signers`, never the long-term commit/release key online. | WS-04, WS-03 |
| **R5** | **Delta depth too deep → consumer reconstruct cost** (Q2). A large `--depth` shifts CPU onto every consumer applying the delta chain. | Low × Med | Cap `--depth` (suggest 50); window is the free lever, not depth (brief §10); document the consumer-cost rationale. | WS-02 |
| **R6** | **Bucket flap / skew** (Q3). Image-baked machine-ids collide into one bucket; or a host recomputes a different bucket across syncs and flaps. | Med × Low | Seed from a registry-local salt re-randomized per clone; persist the bucket index once; probe-forward without re-pinning (brief §6). | WS-03, WS-05 |
| **R7** | **Cross-serving / name-confusion.** A signed tag object served at the wrong path (a release tag served as a channel partition, or vice-versa) tricks a consumer. | Low × High | Name-binding verification: signature valid **and** embedded tag-name field == expected path name (channel name under `/channel/*`, semver under `/release/*`); verify the whole `tag → tag → commit` chain (brief §5, §11). | WS-04, WS-05 |
| **R8** | **Migration straddle bugs** (Q7 / §3). A half-migrated host or mirror serves/reads neither model cleanly — an old bundle-mode client hits a git-native origin, or vice-versa. | Med × High | The two models share **no wire surface** (§3.1), so there is no torn-format hazard; gate the consumer by registry capability detection (git refs present?) and bound any dual-stack window with a hard EOL. | WS-05 |
| **R9** | **Anti-rollback floor vs. fix-forward.** A consumer that does not keep a monotonic floor could be walked backward by a misconfigured partition; conversely an over-strict floor blocks a legitimate fix-forward. | Low × High | Consumer keeps a monotonic floor (never moves to a release older than current); aborting a bad rollout is **fix-forward** (publish newer, advance partitions), never partition-decrement (brief §6). | WS-05, WS-03 |
| **R10** | **Freeze window vs. availability** (Q5). Channel `valid_until` too short breaks quiet channels; too long weakens the freeze defense; release `valid_until` too short can outlive its own served bytes. | Med × Med | Short channel window + heartbeat re-sign; release window comfortably longer than retention/TTL; document both trade-offs prominently. | WS-04, WS-03 |
| **R11** | **zstd `--long` window mismatch.** A pack compressed with `--long=27` requires the consumer to decompress with a matching window (~128 MiB); a constrained client OOMs. | Low × Med | Pin the `--long` window in spec; ensure the consumer always passes the matching `-d --long`; size it against the smallest supported host. | WS-02, WS-05 |

---

## 3. Migration strategy — the central decision

> This section is the expanded answer to the migration half of **Q7** and the
> migration half of this document's mandate. It does not *decide* the question
> (the brief leaves it open, §16.7) but it frames the two paths, their
> consequences, and a recommended sequence so the decision can be made with eyes
> open.

### 3.1 What is actually changing on the wire

The redesign is **not** a field-swap inside one format (as the superseded
`registry.toml` capture would have been) — it is a **wholesale replacement of the
distribution and rollout model**. Almost nothing on the old wire survives. What
*is* preserved is the package-TOML *tree content* and the Ed25519/SSH signing
primitive (brief §2: "the target keeps the Ed25519/SSH signing primitive and the
package-TOML tree content, and replaces *everything about distribution and
rollout*").

| Layer | CURRENT | TARGET | Survives? |
|---|---|---|---|
| Package metadata | nested package TOMLs (`PackageToml`, `crates/aos-package/src/registry/parse.rs:14`) + `closures/<hash>` adjacency | **same TOML tree content**, now living as git tree objects in a sha256 bare repo (brief §3, §8) | **Yes** (content), repackaged as git objects |
| Root / manifest | `bundle-list.toml` manifest the consumer parses (`registry/bundle.rs:49`, `BundleManifest`, **Deserialize-only**) | **removed** — replaced by git refs + signed tag objects + `objects/info/http-alternates` (brief §15) | **No** |
| Distribution unit | **git bundles** + `bundle-list.toml`; producer is a stub (`apr bundle` = `git bundle create`; dead `_update_manifest`, `registry_ops.rs:1723`) | **removed** — full packs `pack-<sha256>.pack` + thin `delta-<from>.pack[.zst]` over dumb HTTP (brief §9, §10, §15) | **No** |
| Versioning / ordering | **calendar tags** `vYYYY.MM[.P]` ordered by `creation_token` (`registry/state.rs:131 version_to_token`, `:104 check_monotonic`) | **standard semver, no `v`**; ordering by semver + git ancestry (brief §7, §15) | **No** |
| Selection | `pick_bundles` (`registry/update.rs:292`); tracking modes commit/branch/tag/semver (`types.rs TrackingMode`) | bucket → `/channel/<name>/<00..ff>` signed partition tag → semver tag → commit, then delta walk (brief §5, §6, §9) | **No** |
| Rollout | none beyond tracking-mode selection | **256 signed partition tags**, publisher-advanced N/256 (brief §6) | **No** (new) |
| Signing | signed git **commit** (`apr sign` = `git commit -S`; `git verify-commit`, `registry/git.rs:379`) + TOFU `trusted-keys.d` | signed git **tag objects** (channel partitions + release tags), SSH-Ed25519, name-binding, `tag→tag→commit` (brief §5, §11) | **Yes** (primitive), moved commit→tag |
| Nix NAR cache | `[[caches]]` consumer reads, fallback `{registry}/nar` (`download.rs:67 resolve_mirror`, `:57 nar_url`) | `[[caches]]` in **tag-message TOML** (may be relative), narinfo superset (brief §13, §14) | **Yes** (mechanism), moved into tag TOML |

The headline: there is **no shared root file to dual-write** (the situation the
superseded capture faced). The old model's root is `bundle-list.toml`; the new
model has *no* root file at all — its "root" is the set of git refs and signed
tag objects. The two models therefore occupy **disjoint wire surfaces**, which
changes the migration calculus entirely (see R8).

### 3.2 Option A — compatibility shim (dual-publish, dual-read)

The producer publishes **both** a legacy bundle/`bundle-list.toml` surface *and*
the new git-native surface for a transition window; consumers prefer the
git-native model and fall back to bundles.

```
Mirror during the shim window:
  {base}/HEAD, info/refs, objects/**, /channel/**, /release/**   ← new clients (git-native)
  {base}/bundles/{name}/bundle-list.toml                          ← old clients (legacy fallback)
  {base}/bundles/{name}/*.bundle                                  ← legacy bundle blobs
```

- **Producer:** the new `apr release` writes the full git-native surface *and*
  keeps regenerating bundles + `bundle-list.toml`. This requires keeping (and
  finishing) the **`bundle-list.toml` writer that does not exist today** — the
  manifest types are `Deserialize`-only and `apr bundle`'s `_update_manifest`
  parameter is **dead code** (`registry_ops.rs:1723`). So the shim is *not* free;
  it forces *building* a serializer for a format we intend to retire, plus the
  `creation_token` producer encoding (`version_to_token`, `state.rs:131`) that
  only ever existed on the consumer side.
- **Consumer:** `apm update` probes for git refs (`info/refs` present?); on a
  legacy-only mirror, falls back to the existing `BundleManifest::fetch` /
  `pick_bundles` path (`registry/bundle.rs`, `registry/update.rs:292`).

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
  `_update_manifest` parameter (`registry_ops.rs:1723`), `BundleManifest`
  (`registry/bundle.rs`), `version_to_token` / `check_monotonic`
  (`registry/state.rs`), and `pick_bundles` (`registry/update.rs:292`) are
  **deleted**, not revived.
- **Consumer:** clients are upgraded to the git-native fetch path *before* any
  mirror drops bundles. A consumer detects the model by probing `info/refs`; a
  too-old client refuses a git-native registry with a clear "upgrade `apm`"
  error. The tag-message `[meta] schema` integer (brief §14) provides
  forward-compat for *future* git-native schema bumps.

| Pros | Cons |
|---|---|
| No throwaway serializer / encoder; the dead bundle path is deleted, not finished. | Requires a coordinated client rollout *before* mirror cutover (a flag day per registry). |
| Full target model (signed 256-partition rollout, name-binding, delta packs, anti-rollback, NAR superset) from day one for every client. | Old `apm` binaries break the moment a registry cuts over — bad for fleets that pin old clients. |
| One distribution model; no dual-surface consistency hazard (closes R8). | Needs a "minimum client version" gate communicated and enforced. |
| Simplest producer; fewest moving parts in the highest-risk new pipeline (WS-02). | |

### 3.4 Recommended path: clean break, gated by a thin consumer dual-detect

The brief does not decide this, but its design pressure points hard at the
**clean break**. The decisive asymmetry vs. the superseded `registry.toml`
migration: there the two roots shared the *same* bundle/NAR blobs, so a dual-read
shim only needed a *reader*. Here the two models share **no distribution
surface** — bundles vs. packs, `creation_token` vs. semver, `bundle-list.toml` vs.
git refs — so a true dual-*publish* shim means *building two complete producers*,
one of them (`bundle-list.toml` + `creation_token` writer) brand-new code for a
format we are killing. That cost is not worth paying.

The synthesis the design implies:

1. **Ship the git-native consumer with model auto-detect first (WS-05).** Teach
   `apm` to probe `info/refs`: a registry that exposes git refs is consumed via
   the new path; a legacy-only mirror falls through to the existing
   `BundleManifest` / `pick_bundles` reader **that already ships today** (no new
   code). This is a *read-only* shim — it does **not** require a `bundle-list.toml`
   writer or a producer `creation_token` encoder. Roll this client out and let it
   propagate.
2. **Producer publishes only the git-native surface (WS-01/02/03).** Do **not**
   build the bundle/`bundle-list.toml`/`creation_token` writer. New registries are
   git-native only; any legacy mirror keeps its already-published static
   `bundle-list.toml` + `*.bundle` files (never regenerated), which the dual-detect
   client of step 1 still reads.
3. **Verify the sha256 dumb-HTTP floor (Q1) before cutover.** A clean break to
   sha256 git is only safe once the minimum git/consumer version is pinned and
   the consumer fails closed with a clear message on too-old clients.
4. **Announce a minimum-client version and an EOL date.** Once telemetry/policy
   shows old bundle-mode clients are drained, drop the legacy reader fallback in a
   later `apm` release. The dead bundle producer code is deleted from day one (it
   was never finished anyway).

This delivers the safety of a shim (no flag day; mixed clients coexist) **without
the cost of building a producer for a dying format**, and converges on the clean
break's single-model simplicity and full security/rollout model. The residual
exposure is that already-published legacy mirrors lack the new
rollout/anti-rollback protections — acceptable because those mirrors are
end-of-life by construction and the EOL date bounds the window.

> **Decision still required.** The above is a *recommendation derived from the
> brief's pressure*, not a ratified decision. WS-01 / WS-03 / WS-05 owners must
> confirm: (a) the `info/refs`-probe model-detection mechanism, (b) the
> minimum-client-version gate and EOL policy, and (c) whether step 1's legacy
> reader fallback is worth keeping vs. a coordinated hard cutover for a small,
> controlled fleet.

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
   check (channel name under `/channel/*`, semver under `/release/*`) — there is no
   "trust this during migration" relaxation (brief §5, §11; R7).

---

## 4. Does the NAR-cache superset ship this milestone?

> This is the second half of **Q7** (brief §16.7): "whether the NAR cache
> superset (`[[caches]]` + narinfo) ships in the same milestone or later." It is
> a milestone-sequencing question, not a wire-format question.

### 4.1 What the superset is

The Nix binary-cache surface is **orthogonal** to the git-object metadata layer
(brief §13). The registry advertises itself as a NAR substituter via a
**`[[caches]]`** entry in the tag-message TOML, whose `url` may be **relative**
(same origin) or absolute:

```toml
# tag-message TOML (channel partition or release tag) — brief §14
[meta]
schema      = 1
valid_until = "2026-06-11T00:00:00Z"

[[caches]]
url      = "./nar"     # relative (same origin) OR absolute
priority = 100
```

At the cache location lives the standard Nix surface — `nix-cache-info`,
`<storehash>.narinfo`, `nar/` — "a strict superset for stock `nix` dev-shell
substitution" (brief §13). narinfo `Sig:` signing, if served, reuses the **one
Ed25519 key** (brief §11, §13). The consumer already separates this concern
today: `download.rs:67 resolve_mirror` reads `[[caches]]` and falls back to
`{registry}/nar`, and `download.rs:57 nar_url` builds the per-NAR URL — so the
*consumer plumbing exists*; what is new is sourcing `[[caches]]` from the tag TOML
and the producer emitting the narinfo surface.

### 4.2 Why it can ship later (and probably should)

| Factor | Implication for sequencing |
|---|---|
| **Disjoint URL namespace.** The Nix surface (`nix-cache-info`, `*.narinfo`, `nar/`) never overlaps the git surface (`objects/`, `/channel/`, `/release/`). | It is a **strict superset** — adding it later can never break an existing git-native consumer. It is pure additive scope. |
| **Different consumer.** The git layer serves `apm` (and stock `git clone`); the NAR layer serves **stock `nix`** dev-shell substitution. | The two have independent users; the AOS fleet does not need the NAR layer to receive releases. |
| **Independent signing reuse.** narinfo `Sig:` reuses the same Ed25519 key as a *separate* signature object (brief §11). | No new trust primitive; it slots in whenever the producer is ready. |
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
3. The `[[caches]]` *consumer* hook already exists (`download.rs`), so adding the
   producer side later is low-coupling.

The one coordination point: the tag-message TOML schema **must reserve
`[[caches]]` from day one** (it is already in the canonical schema, brief §14) so
that turning the superset on later is a producer-only change — no tag re-issue, no
`[meta] schema` bump. Document this reservation in
[tag-metadata.md](../../registry/tag-metadata.md) and
[nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md).

---

## 5. Decision tracking

A compact index for reviewers. "Blocks" = which workstream cannot merge until the
item is closed.

| # | Question / Risk | Owner WS | Blocks merge of | Default recommendation |
|---|---|---|---|---|
| Q1 | sha256 dumb-HTTP client floor | WS-01 | WS-01 object store, WS-05 fetch | Pin min git version; fail-closed consumer error |
| Q2 | `pack-objects` window/depth, zstd, dictionary | WS-02 | WS-02 pipeline | `--window=350 --depth=50 --compression=0` + `zstd --ultra -22 --long=27`; defer dictionary |
| Q3 | Bucket-selection input + probe-forward order | WS-03 / WS-05 | WS-03 rollouts | Registry-local salt; persist bucket index; probe `(bucket+i) mod 256` no re-pin |
| Q4 | `apr release` shape + pluggable upload | WS-02 / WS-03 | WS-02/03 (the pipeline) | Composable verbs under one wrapper; immutable-first / low-TTL-last ordering |
| Q5 | `valid_until` window + re-sign cadence | WS-04 / WS-03 | WS-04 trust | Short channel window + heartbeat; generous release window; rotate-only re-sign |
| Q6 | `info/alternates` readable mirror | WS-01 | WS-01 layout | Emit opportunistically, non-authoritative; drop if it skews |
| Q7a | Migration: clean break vs. shim | WS-05 / WS-01 / WS-03 | WS-01, WS-02, WS-03, WS-05 | Clean break + thin read-only consumer dual-detect → EOL (§3.4) |
| Q7b | NAR superset milestone timing | WS-05 | (none — fast-follow) | Defer to fast-follow; reserve `[[caches]]` in tag TOML now (§4.3) |
| R2/R3 | Torn publish / publisher race | WS-02 / WS-03 | WS-02, WS-03 | Immutable-first / low-TTL-last; single publisher per channel |
| R7 | Cross-serving / name-confusion | WS-04 / WS-05 | WS-04, WS-05 | Name-binding: embedded tag-name == path name; verify `tag→tag→commit` |
| R9 | Anti-rollback floor across cutover | WS-05 | WS-05 | Re-seed floor at git-native cutover; fix-forward only |

---

## 6. Related documents

**Plan set ([docs/plans/registry/](./README.md)):**

- [README](./README.md) — plan overview, milestones, sequencing.
- [design-brief.md](./design-brief.md) — authoritative intent; §16 is the source of this doc.
- [gap-analysis.md](./gap-analysis.md) — producer/consumer gap enumeration.
- [workstream-01-object-store.md](./workstream-01-object-store.md) — sha256 bare repo, dumb-HTTP layout, `http-alternates` (Q1, Q6, R2).
- [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md) — pack-objects, thin/full packs, zstd (Q2, Q4, R2, R5, R11).
- [workstream-03-channels-rollouts.md](./workstream-03-channels-rollouts.md) — 256 partition tags, frontier, bucket selection (Q3, Q4, Q5, R3, R6, R9, R10).
- [workstream-04-signing-trust.md](./workstream-04-signing-trust.md) — signed tag objects, name-binding, `valid_until` (Q5, R4, R7, R10).
- [workstream-05-consumer.md](./workstream-05-consumer.md) — resolution, delta walk, retention, verification, `[[caches]]` superset (Q1, Q3, Q7, R1, R6, R7, R8, R9).

**Reference set ([docs/registry/](../../registry/README.md)) — target state:**

- [README](../../registry/README.md) ·
  [architecture.md](../../registry/architecture.md) ·
  [current-state.md](../../registry/current-state.md) ·
  [http-layout.md](../../registry/http-layout.md) ·
  [versioning-and-channels.md](../../registry/versioning-and-channels.md) ·
  [packs-and-deltas.md](../../registry/packs-and-deltas.md) ·
  [tag-metadata.md](../../registry/tag-metadata.md) ·
  [signing-and-trust.md](../../registry/signing-and-trust.md) ·
  [publishing.md](../../registry/publishing.md) ·
  [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) ·
  [apt-comparison.md](../../registry/apt-comparison.md)
