# AOS Registry — Gap Analysis

> **Status:** Implementation plan. Current-vs-target gap analysis for the AOS
> package registry. Every **CURRENT** claim is grounded in code (`path:line`);
> every **TARGET** is grounded in the
> [design brief](./design-brief.md) (§2.11, §4, §6). When code and the brief's
> as-is description disagree, this doc records the code's actual behavior and the
> [open-questions](./open-questions.md) doc carries the discrepancy.
>
> **Audience:** implementers, architects, engineers, and the reviewers who
> sequence the registry workstreams.

## Purpose & how to read this doc

This document enumerates **every producer/consumer gap** between the registry as
it exists today and the target design, then maps each gap to the
[workstream](./README.md) that closes it. It is the bridge between the
[design-brief](./design-brief.md) (intent) and the five workstream specs:

- [workstream-01-registry-root.md](./workstream-01-registry-root.md) — the
  `registry.toml` schema, its **serializer** (the missing writer), inline
  signing, and by-hash references.
- [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md) — the
  `apr release` ordering, bundle + manifest generation, `creation_token`
  computation, upload backends, and git-CAS + conditional-PUT publish.
- [workstream-03-nix-cache.md](./workstream-03-nix-cache.md) — narinfo +
  `nix-cache-info` emission, references-basename expansion, and per-narinfo
  Ed25519 signatures.
- [workstream-04-channels-rollouts.md](./workstream-04-channels-rollouts.md) —
  symbolic channels, phased rollouts, components, `valid_until`/freshness,
  capability flags.
- [workstream-05-consumer.md](./workstream-05-consumer.md) — consumer changes to
  read the `registry.toml` root, track channels, enforce expiry/freeze, fetch
  by-hash, and fail closed on omission.

For the as-is reference (no plan framing) see
[../../registry/current-state.md](../../registry/current-state.md); for the
target reference set see [../../registry/README.md](../../registry/README.md).

Each gap below is labelled **CURRENT** (grounded `path:line`) → **TARGET**
(grounded in the brief) → **Workstream** (where it is closed).

---

## 1. The core asymmetry in one sentence

The **consumer side is rich and complete**; the **producer side is a thin shell
over `git` and `git bundle create`** with no manifest writer, no token
computation, no delta classification, no upload, and no Nix-cache emission. The
target design closes that asymmetry and additively layers a Nix binary-cache
protocol over the same HTTP origin.

```
                  CONSUMER (rich)                       PRODUCER (stub)
   ┌──────────────────────────────────────┐  ┌──────────────────────────────────┐
   │ parse bundle-list.toml  (bundle.rs)   │  │ git init / commit  (registry_ops) │
   │ creation_token decode   (state.rs)    │  │ git bundle create  (apr bundle)   │
   │ classify snap/seq/skip  (bundle.rs)   │  │ git push (FF)      (apr push)     │
   │ pick minimal bundle set (update.rs)   │  │ git commit --amend -S (apr sign)  │
   │ semver / TrackingMode   (update.rs)   │  │ ──────────────────────────────────│
   │ verify commit signature (security.rs) │  │ ✗ no manifest WRITER              │
   │ TOFU / trusted-keys     (security.rs) │  │ ✗ no token COMPUTE                │
   │ NAR fetch + sha256      (download.rs) │  │ ✗ no delta CLASSIFY               │
   │ persist [registry.state](update.rs)   │  │ ✗ no UPLOAD                       │
   └──────────────────────────────────────┘  │ ✗ no narinfo / nix-cache-info     │
                                              │ ✗ no atomic root FLIP             │
                                              └──────────────────────────────────┘
```

The capability matrix from the brief (§2.11), reproduced with the code that
proves each cell:

| Capability | Consumer | Producer | Grounding |
|---|---|---|---|
| Parse `bundle-list.toml` | ✅ | — | `registry/bundle.rs:124` (`BundleManifest::parse`) |
| **Write** `bundle-list.toml` | n/a | ❌ | `ManifestToml`/`BundleEntryToml` are `#[derive(Deserialize)]` only — no `Serialize` (`registry/bundle.rs:59`, `:75`) |
| `creation_token` encode | ✅ (decode used) | ❌ | `version_to_token` defined `registry/state.rs:131`, but only `update.rs` calls it consumer-side |
| `creation_token` decode | ✅ | — | `token_to_version` `registry/state.rs:174` |
| Classify snapshot/sequential/skip | ✅ (read-time) | ❌ | `classify_delta` `registry/bundle.rs:238` runs only during parse |
| Select minimal bundle set | ✅ | n/a | `pick_bundles` (`update.rs`) |
| Upload bundles | — | ❌ | only NAR upload exists, in `aos-cache` |
| narinfo / `nix-cache-info` | n/a | ❌ | no emitter anywhere in the tree |
| Persist `[registry.state]` | ✅ | n/a | `RegistryState` + `sync_bundle` |
| Atomic "latest" pointer flip | n/a | ❌ | "latest" derived by `latest_snapshot()` / max token (`bundle.rs:189`) |

---

## 2. Producer-side gaps (the asymmetry, §2.11)

These are the gaps that make the producer a stub. Each entry: the **CURRENT**
behavior with code citation, the **TARGET** behavior from the brief, and the
**Workstream** that closes it.

### G-P1 — No `bundle-list.toml` / root writer

- **CURRENT.** The consumer can *parse* the manifest but nothing can *emit* one.
  The serde types backing the manifest are deserialize-only:
  `ManifestToml` (`registry/bundle.rs:59`), `ManifestHeader`
  (`registry/bundle.rs:66`), and `BundleEntryToml` (`registry/bundle.rs:75`) all
  derive `Deserialize` and **not** `Serialize`. `BundleManifest` itself
  (`registry/bundle.rs:48`) has no `to_string`/`write` path. The producer's
  `registry.toml` is created once, by hand, as a literal format string in
  `create` (`registry_ops.rs:444-450`) carrying only `[registry] name/description`
  — not the bundle index, not signing, not caches.
- **TARGET.** Collapse the root to a single signed `registry.toml` whose body
  *includes* the bundle/delta index (kill `bundle-list.toml`), serialized by a
  real writer (brief §4.3, §6 Tier-1 #2). The root carries `[meta]`
  (`schema` integer, `name`, `date`, `valid_until`), `pubkey`, `[latest]`,
  `[channels.<name>]`, `[components.<name>]`, a single by-hash `[[bundles]]` table
  (deltas folded in, distinguished by `type`), `[[caches]]`, and a `[signature]`
  block.
- **Workstream.** [workstream-01-registry-root.md](./workstream-01-registry-root.md).

### G-P2 — `apr bundle` is a bare `git bundle create`; `_update_manifest` is dead code

- **CURRENT.** `bundle` (`registry_ops.rs:1718`) creates one `.bundle` file with
  `git bundle create` into a local `bundles/` dir and prints success. It accepts
  an `_update_manifest: bool` parameter that is **never read** — the underscore
  prefix marks it as deliberately unused (`registry_ops.rs:1723`). It never
  computes a token, never classifies the delta type, and never writes any index.
  The snapshot/delta choice is purely a function of whether the caller passed
  `--delta-from` (`registry_ops.rs:1734`).
- **TARGET.** A real publish pipeline generates the bundles **and** the manifest
  entries (`creation_token`, `type`, `tag` for snapshots / `from_tag`+`to_tag` for
  deltas, `sha256`, `size`) for the just-landed commit (brief §4.4 step 2). Delta
  classification is computed, not implied by a flag.
- **Workstream.** [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md)
  (manifest entries land in the root defined by WS-01).

### G-P3 — No producer-side `creation_token` computation

- **CURRENT.** `version_to_token` (`registry/state.rs:131`) and `check_monotonic`
  (`registry/state.rs:104`) exist and are correct (`YYYY*1_000_000 + MM*10_000 +
  P`, month 1–12, patch ≤ 9999), but they are invoked **only on the consumer**
  (during `update`). No producer code path derives a token from a tag when
  emitting a bundle entry, because no producer code emits bundle entries at all
  (see G-P1).
- **TARGET.** The publish pipeline computes `creation_token` for each generated
  bundle from its target tag, and stamps it into the root's bundle table; the
  signed `[latest].creation_token` becomes the monotonic anti-rollback anchor (brief §4.3,
  §4.4).
- **Workstream.** [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md)
  (reuses the existing `version_to_token`).

### G-P4 — No automatic delta-type classification on the producer

- **CURRENT.** `classify_delta` (`registry/bundle.rs:238`) decides skip-vs-
  sequential from the dotted-segment count of the `from` tag, but it runs only at
  **parse time** on the consumer. The producer's `apr bundle` makes a snapshot
  unless `--delta-from <tag>` is passed manually (`registry_ops.rs:1734`); it
  never decides *which* deltas to cut or labels them.
- **TARGET.** The pipeline decides, for the landed tag, which snapshot/sequential/
  skip bundles to cut and labels each entry's `type` in the root (brief §4.4,
  §6 Tier-3 — borrow APT's explicit from/to/hash delta shape). The same
  classification rule used at read-time is applied at write-time.
- **Workstream.** [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md).

### G-P5 — No upload of bundles to a mirror/CDN/S3

- **CURRENT.** `apr bundle` writes bundles to a **local** `bundles/` directory
  only (`registry_ops.rs:1729-1730`). The only upload code in the tree lives in
  `aos-cache`, and it uploads **NARs**, not bundles or the root. `apr push`
  (`registry_ops.rs:1410`) pushes the **git repo**, not the HTTP artifacts.
- **TARGET.** The pipeline uploads immutable, content-addressed objects (nars,
  `*.narinfo`, `*.bundle`) first, then flips the root last via conditional PUT;
  upload backends should be pluggable (S3, rsync, plain PUT) (brief §4.4 steps
  3–4, §7 item 6).
- **Workstream.** [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md).

### G-P6 — No narinfo / `nix-cache-info` emission

- **CURRENT.** Nothing in the tree emits `*.narinfo` or `nix-cache-info`. The
  registry is **not** a Nix binary cache today (brief §3.2). The producer records
  every narinfo-equivalent field into the package TOML already
  (`build_package_toml`, `registry_ops.rs:595` — `store_path`, `nar_hash`,
  `nar_size`, `download_hash`, `download_size`, `references`, `source_drv`), but
  there is no projection of those into the Nix wire format and no per-narinfo
  `Sig:`.
- **TARGET.** A narinfo generator keyed by store-path hash, a `nix-cache-info`
  stub, co-located NAR blobs, **references-basename expansion** (`<hash>` →
  `<hash>-<name>`), and per-narinfo Ed25519 `Sig:` — a strict superset over the
  disjoint Nix URL namespace (brief §4.1, §4.2). The package TOML already holds
  the source fields; the work is the projection + basename expansion +
  signature.
- **Workstream.** [workstream-03-nix-cache.md](./workstream-03-nix-cache.md).

### G-P7 — No publish atomicity beyond git's FF rejection

- **CURRENT.** The only concurrency guard is git's fast-forward rejection on
  push: `apr push` is `git push [-u origin] [branch] [--force]`
  (`registry_ops.rs:1420-1433`). There is no lock service and no atomic flip of
  any HTTP root (there is no HTTP root index to flip — see G-P1). `apr sign` is
  `git commit --amend --no-edit -S` (`registry_ops.rs:1770`), which **rewrites
  HEAD** and must therefore run *before* push, not after.
- **TARGET.** Keep git ref CAS as the lock (FF-only push serializes publishes for
  free; losers `pull --rebase` + retry), then make the *winner* flip the
  `registry.toml` root **last**, atomically, via conditional PUT (S3
  `If-Match`/`If-None-Match` ETag CAS) so readers see old-root or new-root, never
  torn (brief §4.4). The strict publish order is: publish → sign → push (CAS) →
  generate → upload immutable objects → flip root.
- **Workstream.** [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md).

### G-P8 — No explicit "latest" pointer

- **CURRENT.** "Latest" is **derived**, not pointed to. The consumer computes it
  by scanning the manifest for the max `creation_token` snapshot
  (`latest_snapshot()`, `registry/bundle.rs:189`). A dumb-HTTP listing can hide
  newer entries and the consumer would silently use stale data.
- **TARGET.** "Latest" becomes an **explicit signed field** `[latest] { tag,
  creation_token, head }` in the root, flipped atomically as the publish's last step
  (brief §4.3, §4.4). With the authentic `[latest].head` commit SHA the consumer
  can **fail closed** on omission rather than degrade silently (brief §4.5).
- **Workstream.** [workstream-01-registry-root.md](./workstream-01-registry-root.md)
  (schema) + [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md)
  (atomic flip).

---

## 3. Producer-side gaps from the APT-improvements list (§6)

These are not in the original §2.11 asymmetry list but are required to reach the
target; the brief's §6 prioritizes them. None exist in code today.

### G-A1 — `valid_until` signed expiry (Tier 1)

- **CURRENT.** No expiry anywhere. `check_monotonic` (`registry/state.rs:104`)
  defends rollback by sequence but cannot detect a **freeze** (a mirror stuck on
  a validly-signed-but-old root) — there is no time-based field to check.
- **TARGET.** Add an APT-`Valid-Until`-style `valid_until` to the signed root;
  re-sign each publish with expiry = publish + N; clients reject an expired root
  (brief §4.5 "Freeze", §6 Tier-1 #1).
- **Workstream.** [workstream-04-channels-rollouts.md](./workstream-04-channels-rollouts.md)
  (field + re-sign cadence) — root schema slot in
  [workstream-01-registry-root.md](./workstream-01-registry-root.md); consumer
  enforcement in [workstream-05-consumer.md](./workstream-05-consumer.md).

### G-A2 — `by-hash` discipline for index references (Tier 1)

- **CURRENT.** The consumer addresses bundles by `entry.uri` under
  `{base}/bundles/{registry}/{uri}` (`download_bundle`, `registry/bundle.rs:259`)
  and verifies the bundle's `sha256` (`registry/bundle.rs:277`,
  `verify_bundle:305`), but the index it reads is `bundle-list.toml` — a mutable,
  named root. A client mid-publish can read a torn index.
- **TARGET.** The signed root references bundles/indices by their hashed key
  (APT `by-hash`) so a client that read root@T resolves a consistent set even
  after root@T+1 lands (brief §4.3, §6 Tier-1 #2). Mostly discipline atop the
  existing content-addressing.
- **Workstream.** [workstream-01-registry-root.md](./workstream-01-registry-root.md)
  (by-hash references in the root) + consumer fetch in
  [workstream-05-consumer.md](./workstream-05-consumer.md).

### G-A3 — Symbolic channels decoupled from tags (Tier 1)

- **CURRENT.** No channels. `TrackingMode { Commit, Branch, Tag,
  Version(VersionReq), Default }` (brief §2.5; `types.rs`) tracks concrete refs
  or a semver range; there is no symbolic `stable`/`testing` alias and no place
  in the root to define one (`create` writes only `[registry]`,
  `registry_ops.rs:444`).
- **TARGET.** `[channels.stable] { tag = "v2026.02.3", creation_token, rollout }`
  (subtable form, keyed by name) in the signed root; promotion is one atomic
  signed flip; clients track `channel = "stable"` (brief §4.3, §6 Tier-1 #3).
- **Workstream.** [workstream-04-channels-rollouts.md](./workstream-04-channels-rollouts.md)
  (producer + schema) + [workstream-05-consumer.md](./workstream-05-consumer.md)
  (a new tracking mode).

### G-A4 — Phased / staged rollouts (Tier 1)

- **CURRENT.** None. Bundle selection (`pick_bundles`) is all-or-nothing per
  tracking mode; there is no per-machine gating.
- **TARGET.** `rollout = N` (percent) on a channel target; clients gate on
  `sha256(machine_id : channel_name)` — the **channel name**, explicitly **not**
  the target tag, so cohorts stay stable across promotions (APT
  `Phased-Update-Percentage`) for canary / blast-radius control. A host in the
  held cohort stays at its current `last_creation_token` (no-op); there is no
  `previous_tag` field (brief §4.3, §6 Tier-1 #4; gating function is open — §7
  item 4).
- **Workstream.** [workstream-04-channels-rollouts.md](./workstream-04-channels-rollouts.md)
  + [workstream-05-consumer.md](./workstream-05-consumer.md).

### G-A5 — Components within a registry (Tier 2)

- **CURRENT.** None. Packages bucket by first letter only
  (`first_letter`/`packages/<x>/<name>.toml`, `registry_ops.rs:149`,
  `:527-531`); there is no trust/license/stability partition.
- **TARGET.** `[components.<name>]` subtables (keyed by name, each with a
  `description`; `main/contrib/non-free` analogue) in one signed root (brief §4.3,
  §6 Tier-2 #5).
- **Workstream.** [workstream-04-channels-rollouts.md](./workstream-04-channels-rollouts.md).

### G-A6 — Capability flags in the signed root (Tier 2)

- **CURRENT.** None. The consumer assumes a fixed protocol; the manifest carries
  a bare integer `version` (`ManifestHeader.version`, `registry/bundle.rs:67`),
  not feature flags.
- **TARGET.** `[meta.capabilities]` boolean feature flags in the root for graceful
  degradation + forward compat (APT `Acquire-By-Hash: yes`) (brief §4.3, §6
  Tier-2 #6).
- **Workstream.** [workstream-04-channels-rollouts.md](./workstream-04-channels-rollouts.md)
  (schema slot lives in WS-01's `[meta.capabilities]` table).

### G-A7 — Hash agility (Tier 2, largely already present)

- **CURRENT.** Hashes already carry explicit prefixes: `nar_hash` is the full
  `sha256:<hex>` string and NAR filenames literally contain the colon
  (`download.rs` `nar_url` → `{mirror}/{nar_hash}.nar.zst`, brief §2.8). Bundle
  `sha256` is hex without a prefix (`verify_bundle`, `registry/bundle.rs:316`).
- **TARGET.** Tolerate multiple algorithms via explicit prefixes everywhere so a
  future migration isn't a flag day (brief §6 Tier-2 #7). Mostly a
  forward-compatibility discipline; little code change.
- **Workstream.** [workstream-01-registry-root.md](./workstream-01-registry-root.md)
  (prefix discipline in the schema).

### G-A8 — Provides / file-index (Tier 2)

- **CURRENT.** None. No "which package ships `/usr/bin/foo`" index.
- **TARGET.** Optional `Contents-<arch>`-style file index — a discoverability win
  (brief §6 Tier-2 #8). Lowest priority.
- **Workstream.** Deferred; tracked in
  [open-questions.md](./open-questions.md). Not assigned to a Tier-1/2 workstream.

### G-A9 — Bundle mirror list with priority + failover (Tier 2)

- **CURRENT.** `[[caches]]` priority + failover exists **for NARs only**:
  `resolve_mirrors` reads `registry.toml` `[[caches]]`, sorts by
  `priority` descending (`registry_ops.rs:405-413`), and `validate`/`download`
  walk them in order. Bundles are fetched from a single `base_url`
  (`download_bundle`, `registry/bundle.rs:259`); there is no bundle-mirror list.
- **TARGET.** Extend the `[[caches]]` priority/failover model to **bundle**
  mirrors (brief §6 Tier-2 #9).
- **Workstream.** [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md)
  (root advertises bundle mirrors) + [workstream-05-consumer.md](./workstream-05-consumer.md)
  (consumer failover).

---

## 4. Consumer-side gaps (smaller — the consumer is already rich)

The consumer is mostly complete, but the **target root** and the **target
threat model** add new consumer behavior.

### G-C1 — Reads `bundle-list.toml`, not the signed `registry.toml` root

- **CURRENT.** The consumer fetches `{base}/bundles/{name}/bundle-list.toml`
  (`BundleManifest::fetch`, `registry/bundle.rs:100`) — a separate, unsigned
  index file. The `registry.toml` it knows about is the **local clone's**
  `[registry]/[[caches]]/signing` file (`RegistryRootConfig`, `types.rs:567`),
  read via `resolve_mirrors`/`read_registry_toml` (`registry_ops.rs:392`,
  `:405`), not an HTTP-served signed root carrying the bundle index.
- **TARGET.** Fetch the single signed `registry.toml` root over dumb HTTP; the
  bundle index lives **inside** it (brief §4.3). The consumer drops
  `bundle-list.toml` (or reads it only via a migration shim — §7 item 7).
- **Workstream.** [workstream-05-consumer.md](./workstream-05-consumer.md).

### G-C2 — No expiry / freeze check

- **CURRENT.** The consumer's only freshness/anti-rollback defense is
  `check_monotonic` on the `creation_token` (`registry/state.rs:104`). It cannot
  detect a frozen-but-valid root.
- **TARGET.** Reject an expired root by checking `valid_until` (brief §4.5).
- **Workstream.** [workstream-05-consumer.md](./workstream-05-consumer.md)
  (paired with the producer G-A1 in WS-04).

### G-C3 — No fail-closed on omission

- **CURRENT.** If a listing/mirror hides newer bundles, the consumer falls back
  to the latest snapshot it *can* see (`pick_bundles` default branch →
  `latest_snapshot()`, brief §2.6 step 4 / 6c) and proceeds — silent staleness.
- **TARGET.** With the signed `[latest].head`, the consumer **fails closed**
  (can't reach the signed target ⇒ error, not silent stale data); freeze
  degrades to DoS, not silent rollback (brief §4.5 "Omission").
- **Workstream.** [workstream-05-consumer.md](./workstream-05-consumer.md).

### G-C4 — No by-hash fetch of root-referenced objects

- **CURRENT.** Bundles are fetched by `uri` from a mutable path
  (`download_bundle`, `registry/bundle.rs:259`); the index itself is the mutable
  `bundle-list.toml`.
- **TARGET.** Fetch index-referenced objects by their hashed key so a mid-publish
  read never tears (brief §4.3; pairs with producer G-A2).
- **Workstream.** [workstream-05-consumer.md](./workstream-05-consumer.md).

### G-C5 — No channel / rollout tracking mode

- **CURRENT.** `TrackingMode` (brief §2.5) has no `Channel` variant and no
  rollout-bucket logic.
- **TARGET.** Track `channel = "stable"`, resolve it through the root's
  `[channels.<name>]`, and honor `rollout = N` via `sha256(machine_id : channel_name)`
  (hashed over the **channel name**, not the target tag, so cohorts stay stable
  across promotions; a held host stays at its current `last_creation_token`)
  (brief §4.3; pairs with producer G-A3/G-A4).
- **Workstream.** [workstream-05-consumer.md](./workstream-05-consumer.md).

### G-C6 — narinfo `Sig:` consumption is not required (clarification, not a gap to close in WS-05)

- **CURRENT.** `apm` authenticates NARs **transitively**: the Ed25519-signed git
  commit authenticates the tree → every TOML → every NAR sha256
  (`download.rs` verifies NARs by content hash, brief §2.8, §3.3). There is no
  per-NAR signature today and `apm` does not need one.
- **TARGET.** The per-narinfo `Sig:` exists **only** to satisfy stock `nix`
  without `require-sigs = false` (brief §4.2); `apm`'s trust still roots in the
  signed commit. So this is a **producer** emission gap (G-P6), not a new `apm`
  verification requirement.
- **Workstream.** Emission in
  [workstream-03-nix-cache.md](./workstream-03-nix-cache.md); no change to `apm`
  verification.

---

## 5. Things that are already correct (do NOT re-build)

The brief's §6 Tier-3 and §5 "parity or ahead" lists. These are grounded so a
reviewer does not mistake them for gaps:

| Already done | Grounding | Notes |
|---|---|---|
| Per-repo key pinning (TOFU + `trusted-keys.d`) | `security.rs` TOFU + `trusted_keys_dirs()` (`types.rs`); brief §2.10 | ≈ APT `signed-by=` |
| SSH-Ed25519 commit signature verification | `verify_commit_signature` (`security.rs` ~199) | brief §2.10 |
| Reproducible snapshots | git tags (`apr tag`, `registry_ops.rs:1696`) | ≈ snapshot.debian.org |
| Incremental updates (pdiff analogue) | snapshot/sequential/skip bundle deltas (`registry/bundle.rs`) | ≈ APT pdiff |
| Atomic publish lock | git FF CAS on push (`registry_ops.rs:1420`) | ≥ APT rsync mirror races |
| Downgrade / fork detection | `check_downgrade` (`security.rs` ~256), `check_monotonic` (`state.rs:104`) | FastForward/SameCommit/Downgrade/Diverged |
| NAR content-hash verification | `download.rs` sha256 (brief §2.8) | no per-NAR sig needed |
| `[[caches]]` priority/failover (NARs) | `resolve_mirrors` (`registry_ops.rs:405`) | extend to bundles (G-A9) |

The brief is explicit (§6 Tier-3): borrow only APT's *index-file shape* (explicit
from/to/hash per delta) for expressing deltas inside `registry.toml`; do **not**
re-add the Tier-3 capabilities.

---

## 6. Gap → workstream rollup

The single table an implementer can sequence against. **Severity:** S =
security/correctness, O = operational, C = compat/forward-looking.

| ID | Gap (short) | Side | Sev | Workstream |
|---|---|---|---|---|
| G-P1 | No root/manifest **writer** (serde is Deserialize-only) | Producer | S | [WS-01](./workstream-01-registry-root.md) |
| G-P2 | `apr bundle` bare; `_update_manifest` dead | Producer | O | [WS-02](./workstream-02-publish-pipeline.md) |
| G-P3 | No producer `creation_token` compute | Producer | S | [WS-02](./workstream-02-publish-pipeline.md) |
| G-P4 | No producer delta classification | Producer | O | [WS-02](./workstream-02-publish-pipeline.md) |
| G-P5 | No bundle/root **upload** | Producer | O | [WS-02](./workstream-02-publish-pipeline.md) |
| G-P6 | No narinfo / `nix-cache-info` emission | Producer | S | [WS-03](./workstream-03-nix-cache.md) |
| G-P7 | No atomic root flip beyond git FF | Producer | S | [WS-02](./workstream-02-publish-pipeline.md) |
| G-P8 | "Latest" derived, not a signed pointer | Producer | S | [WS-01](./workstream-01-registry-root.md) + [WS-02](./workstream-02-publish-pipeline.md) |
| G-A1 | `valid_until` signed expiry | Producer | S | [WS-04](./workstream-04-channels-rollouts.md) |
| G-A2 | `by-hash` index references | Both | S | [WS-01](./workstream-01-registry-root.md) + [WS-05](./workstream-05-consumer.md) |
| G-A3 | Symbolic channels | Both | O | [WS-04](./workstream-04-channels-rollouts.md) + [WS-05](./workstream-05-consumer.md) |
| G-A4 | Phased rollouts | Both | O | [WS-04](./workstream-04-channels-rollouts.md) + [WS-05](./workstream-05-consumer.md) |
| G-A5 | Components | Producer | C | [WS-04](./workstream-04-channels-rollouts.md) |
| G-A6 | Capability flags | Producer | C | [WS-04](./workstream-04-channels-rollouts.md) |
| G-A7 | Hash agility (prefixes) | Producer | C | [WS-01](./workstream-01-registry-root.md) |
| G-A8 | Provides / file-index | Producer | C | Deferred — [open-questions](./open-questions.md) |
| G-A9 | Bundle mirror list + failover | Both | O | [WS-02](./workstream-02-publish-pipeline.md) + [WS-05](./workstream-05-consumer.md) |
| G-C1 | Read signed `registry.toml` root | Consumer | S | [WS-05](./workstream-05-consumer.md) |
| G-C2 | Expiry / freeze check | Consumer | S | [WS-05](./workstream-05-consumer.md) |
| G-C3 | Fail-closed on omission | Consumer | S | [WS-05](./workstream-05-consumer.md) |
| G-C4 | By-hash fetch | Consumer | S | [WS-05](./workstream-05-consumer.md) |
| G-C5 | Channel / rollout tracking mode | Consumer | O | [WS-05](./workstream-05-consumer.md) |

**The four gaps that change the product** (brief §6 closing): G-A1 `valid_until`
(freeze defense), G-A2 `by-hash` (torn-publish safety) — both
security/correctness — and G-A3 channels, G-A4 rollouts — both operational.

### Suggested sequencing

1. **WS-01** first: the root schema + serializer is the keystone — G-P1 and G-P8
   block almost everything (no writer ⇒ no index ⇒ no atomic flip ⇒ no channels).
2. **WS-02** next: with a serializable root, the publish pipeline (G-P2/3/4/5/7)
   becomes implementable; it reuses the existing `version_to_token` and
   `classify_delta` logic at write-time.
3. **WS-03** can proceed in parallel with WS-02: narinfo/`nix-cache-info`
   emission (G-P6) is additive over a disjoint URL namespace and depends only on
   data already in the package TOMLs.
4. **WS-04** layers channels/rollouts/`valid_until`/capabilities (G-A1/3/4/5/6)
   onto the WS-01 root.
5. **WS-05** lands the consumer-side counterparts (G-C1–C5, the read sides of
   G-A2/3/4/9) once the producer emits the new root.

---

## 7. Discrepancies vs the brief (record for open-questions)

These are places where the **code** and the brief's prose differ in detail. The
code wins for current state per the brief's own rule (§0); the items are carried
into [open-questions.md](./open-questions.md).

- **Brief §2.10 vs code on `apr tag --key`.** The brief says `apr tag` "supports
  `--message`/`--key`". In code, `tag` (`registry_ops.rs:1696`) accepts a `_key:
  Option<&str>` that is **never used** (underscore-prefixed,
  `registry_ops.rs:1700`); only `--message` is honored
  (`registry_ops.rs:1706-1710`). Same for `sign`'s `_key`
  (`registry_ops.rs:1762`). Signing key selection is whatever git's
  `user.signingkey`/`gpg.format=ssh` config resolves, not a CLI argument.
- **Brief §2.11 / §2.4 manifest filename vs target.** The consumer hard-codes the
  filename `bundle-list.toml` in both `fetch` (`registry/bundle.rs:106`) and the
  module docs (`registry/bundle.rs:4`), while the target (§4.3) removes
  `bundle-list.toml` entirely and moves the index into `registry.toml`. The
  consumer change (G-C1) and any migration shim (§7 item 7) must reconcile this.
- **`RegistrySigningConfig.public_key` encoding.** The brief (§4.2) wants two
  published encodings derivable from one key (`aos-core:Ed25519:<base64>` for
  `apm`; `<name>:<base64>` for Nix). Today `RegistryRootConfig.signing` holds a
  single `public_key` (`types.rs:597`); WS-01/WS-03 must confirm whether one
  stored field yields both encodings or two are stored.
- **Package-TOML field names are asserted, not yet schema-frozen.** The brief
  §2.3/§7 item 1 flags this; the producer's `build_package_toml`
  (`registry_ops.rs:595-781`) is the authoritative current shape (e.g.
  `download_hash`/`download_size` default to the NAR's own hash/size,
  `registry_ops.rs:692-693`). The reference schema doc must be derived from this
  function, not from prose. Note this is a naming/freeze question, **not** a
  flat-vs-nested shape discrepancy: the on-disk package TOML is the **nested**
  `PackageToml` shape (`[package]` header + `[[versions]]` + `[versions.platforms.<platform>]`,
  written by `build_package_toml` and deserialized by `PackageToml` et al. in
  `registry/parse.rs:14-70`). `PackageMeta` (`types.rs:43-77`) is **not** the
  on-disk type — it is the flattened per-(package, platform) in-memory projection
  produced by `parse_package_toml` (`registry/parse.rs:133-178`), carrying
  flattened `platform`/`version`/`sysroot`/`previous`/`images`. The brief's nested
  sketch matches the code; there is no flat-vs-nested brief-vs-code discrepancy.
