# Bundles & Deltas

> **Scope:** the bundle distribution model for the AOS package registry — how the
> registry git repo is packaged into `git bundle` files, how those bundles are
> ordered by `creation_token`, how the consumer (`apm update`) selects a minimal
> bundle set with `pick_bundles`, and how it incrementally rebuilds its local
> cache. This is the transport that carries **metadata** (TOML) over dumb HTTP —
> it is **not** the NAR/blob path (see
> [nix-cache-compatibility.md](./nix-cache-compatibility.md)).
>
> **Labels:** **CURRENT** describes code that exists today (cited as
> `path:line`). **TARGET** describes the design the registry is moving toward,
> grounded in the
> [design brief](../plans/registry/design-brief.md) §2.4–§2.6 and §4.3.

**Related reading:**
[README](./README.md) ·
[architecture](./architecture.md) ·
[current-state](./current-state.md) ·
[http-layout](./http-layout.md) ·
[registry-toml](./registry-toml.md) ·
[nix-cache-compatibility](./nix-cache-compatibility.md) ·
[signing-and-trust](./signing-and-trust.md) ·
[publishing](./publishing.md) ·
[versioning-and-channels](./versioning-and-channels.md) ·
[apt-comparison](./apt-comparison.md)

---

## 1. Why bundles?

The registry is a **git repository of TOML metadata** (`packages/<x>/<name>.toml`
plus `closures/<hash>`). The lowest-common-denominator way to ship a git repo to
many static mirrors and CDNs — with no smart git server, no CGI, no
`git-http-backend` — is a [`git bundle`](https://git-scm.com/docs/git-bundle): a
single file that packs commits/trees/blobs (a full repo or a *delta* slice of
it) and can be served as a plain immutable object over dumb HTTP.

The consumer downloads bundles, verifies them, and `git bundle unbundle`s them
into a local bare repo, then extracts the `packages/` tree into its metadata
cache. Incremental updates are just *smaller* bundles (deltas) instead of a fresh
full snapshot.

```
   producer (apr)                    HTTP mirror / CDN              consumer (apm update)
 ┌────────────────┐   git push    ┌──────────────────────┐  GET  ┌─────────────────────┐
 │ registry.git   │──────────────▶│ bundles/<reg>/        │◀──────│  bundle::fetch      │
 │  packages/     │  + upload      │   bundle-list.toml    │       │  pick_bundles       │
 │  closures/     │   bundles      │   *.bundle            │       │  download + verify  │
 └────────────────┘               └──────────────────────┘       │  git bundle unbundle│
                                                                  │  extract packages/  │
                                                                  └─────────────────────┘
```

> **Transport selection (CURRENT).** Bundle transport is chosen when the
> registry URL is `http(s)://`. `git://`, `git+https://`, `git+ssh://` URLs use
> native git fetch instead (`registry/git.rs`); see
> [current-state.md](./current-state.md). Everything in this document concerns
> the **HTTP bundle** transport (`Transport::HttpBundle`, dispatched at
> `crates/aos-package/src/update.rs:115`).

---

## 2. Bundle kinds

Three bundle kinds exist
(`crates/aos-package/src/registry/bundle.rs:22`):

| Kind | Enum | Contents | Prerequisite |
|------|------|----------|--------------|
| **Snapshot** | `BundleType::Snapshot` | The **complete** registry state at one tag. Self-contained; no base required. | none |
| **Sequential delta** | `BundleType::SequentialDelta` | Changes from the **immediately preceding patch** (`vX.Y.N` → `vX.Y.N+1`). | the previous patch's commit must already be present |
| **Skip delta** | `BundleType::SkipDelta` | Changes from a **minor base** tag (`vYYYY.MM`, no patch component) to a later patch. Lets a client at the base jump straight to the head in one fetch. | the minor base commit must already be present |

A snapshot is large but unconditional. A delta is small but its prerequisite
commit objects must already exist in the consumer's repo — `git bundle verify`
enforces this (see §6).

### 2.1 The skip-delta idea

For a minor line that accrues many patches (`v2026.02`, `.1`, `.2`, … `.9`), a
client far behind would otherwise have to apply a long *chain* of sequential
deltas. A **skip delta** is published from the minor base directly to a later
patch, collapsing the whole chain into one fetch. Both forms can be published for
the same target; the consumer prefers the skip when it can use it (§5).

```
  snapshot v2026.02          seq Δ        seq Δ        seq Δ
  ●─────────────────────────▶○───────────▶○───────────▶○
  v2026.02                  .1            .2            .3
  └──────────────────────────────────────────────────▲
                     skip Δ  v2026.02 ───────────────┘ .3
```

---

## 3. The bundle manifest (`bundle-list.toml`)

**CURRENT.** A registry mirror serves a manifest at
`{base_url}/bundles/{registry_name}/bundle-list.toml`
(`crates/aos-package/src/registry/bundle.rs:100`). Individual bundles are at
`{base_url}/bundles/{registry_name}/{entry.uri}`
(`crates/aos-package/src/registry/bundle.rs:251`).

The manifest is parsed (deserialize-only — there is no writer in the tree; see
§8) into `BundleManifest { registry, version, entries }`
(`crates/aos-package/src/registry/bundle.rs:48`). Each parsed entry is a
`BundleEntry` (`crates/aos-package/src/registry/bundle.rs:34`):

| Field | Meaning |
|-------|---------|
| `uri` | bundle filename, relative to `bundles/{registry}/` |
| `creation_token` | monotonic ordering key (§4) |
| `sha256` | expected content hash (hex) |
| `size` | byte size |
| `bundle_type` | `Snapshot` / `SequentialDelta` / `SkipDelta` |
| `base_tag` | `Some(tag)` for deltas (the prerequisite), `None` for snapshots |
| `target_tag` | the tag this bundle brings the repo to |

### 3.1 Wire schema

The on-disk TOML uses `[manifest]` plus a single array of `[[bundles]]` (deltas
folded into the same array, distinguished by `type` — there is no separate
`[[deltas]]` array). Snapshots carry `tag`; deltas carry `from_tag` / `to_tag`.
The `type` field is the string `"snapshot"` or `"delta"` — **skip vs. sequential
is *not* on the wire**; it is derived at parse time (§4.2). The `uri` is an
object key/filename; its grammar is owned by
[http-layout.md §4](./http-layout.md) — this doc references it rather than
restating the variants. The `.delta` infix shown below reflects the **current
producer/consumer disagreement** on the delta filename (a known bug to fix); the
literal filename is convention only, with authority by-hash via `sha256`.

```toml
[manifest]
registry = "aos-core"
version = 1
generated = "2026-02-15T12:00:00Z"   # informational; ignored on parse

# A full snapshot.
[[bundles]]
tag = "v2026.02"
type = "snapshot"
uri = "aos-core-v2026.02.bundle"
creation_token = 2026020000
size = 153600
sha256 = "abc123…"

# A sequential delta: previous patch -> next patch.
[[bundles]]
from_tag = "v2026.02.1"
to_tag   = "v2026.02.2"
type = "delta"
uri = "aos-core-v2026.02.1..v2026.02.2.delta.bundle"
creation_token = 2026020002
size = 4096
sha256 = "789abc…"

# A skip delta: minor base -> later patch.
[[bundles]]
from_tag = "v2026.02"
to_tag   = "v2026.02.2"
type = "delta"
uri = "aos-core-v2026.02..v2026.02.2.delta.bundle"
creation_token = 2026020002
size = 6144
sha256 = "012def…"
```

Parse-time rules
(`crates/aos-package/src/registry/bundle.rs:124`):

- A `snapshot` missing `tag` is rejected.
- A `delta` missing `from_tag` or `to_tag` is rejected.
- An unknown `type` string is rejected (`unknown bundle type: …`).
- Entries are **sorted ascending by `creation_token`** after parse
  (`crates/aos-package/src/registry/bundle.rs:171`), so all downstream
  selection logic can assume a stable order.

> **TARGET.** The single signed root `registry.toml` absorbs the bundle index;
> `bundle-list.toml` is removed (design brief §4.3). The per-bundle fields move
> into delta/bundle tables in the root, referenced **by hash** (the APT
> `by-hash` discipline) so a client that read `registry.toml@T` resolves a
> consistent bundle set even after the root flips to `T+1`. The bundle *model*
> (snapshot / sequential / skip, `creation_token`, `from`/`to` tags) is
> unchanged — only the file that carries the index changes. See
> [registry-toml.md](./registry-toml.md) and [http-layout.md](./http-layout.md).

---

## 4. `creation_token` — derivation & ordering

The `creation_token` is a **monotonic integer derived from a calendar version
tag**, used to totally-order bundles independent of string tag comparison.

### 4.1 Encoding (`vYYYY.MM[.P]` ⇄ `u64`)

`version_to_token` (`crates/aos-package/src/registry/state.rs:131`):

```
token = year * 1_000_000 + month * 10_000 + patch
```

The arithmetic formula above is authoritative; positionally this is the layout
`YYYYMMPPPP` (patch ≤ 9999, a 4-digit patch field). Note the source doc-comment
at `crates/aos-package/src/registry/state.rs:125` labels it `YYYYMMPPP`, but the
patch field is actually four digits. Validation:

- The tag must be `vYYYY.MM` or `vYYYY.MM.P` (a leading `v` is optional);
  anything with fewer than 2 or more than 3 dotted parts is rejected.
- `month` must be in `1..=12`.
- `patch` must be `≤ 9999` (it occupies the low four decimal digits).
- A 2-part tag (`vYYYY.MM`, no patch) encodes `patch = 0`.

`token_to_version` (`crates/aos-package/src/registry/state.rs:173`) is the
inverse; a token whose patch is `0` renders as a **2-part base tag** (`v2026.02`),
otherwise the full 3-part tag (`v2026.02.3`).

| Tag | Token | Notes |
|-----|-------|-------|
| `v2026.02` | `2026020000` | minor base, patch 0 |
| `v2026.02.1` | `2026020001` | first patch |
| `v2026.02.3` | `2026020003` | |
| `v2026.12.99` | `2026120099` | |
| `v2026` | — | rejected (only 1 part) |
| `v2026.13` | — | rejected (month > 12) |

> **Producer note (CURRENT).** `version_to_token` lives in the codebase but is
> only exercised **consumer-side** today (round-trip via `token_to_version` and
> monotonic checks). No producer code computes `creation_token` when writing a
> manifest — the manifest writer does not exist yet (§8, design brief §2.11).

### 4.2 Sequential vs. skip classification (read-time)

The wire format only says `"delta"`. The consumer decides *which kind* of delta
it is from the **shape of `from_tag`** in
`classify_delta` (`crates/aos-package/src/registry/bundle.rs:238`):

```
strip leading 'v' from from_tag
count dot-separated segments
  ≤ 2 segments  (e.g. "v2026.02")    -> SkipDelta      (from a minor base)
  ≥ 3 segments  (e.g. "v2026.02.1")  -> SequentialDelta (patch to patch)
```

Only `from_tag` is inspected; the `_to` argument is unused. So a delta whose base
is a bare `vYYYY.MM` is always a skip; a delta whose base already carries a patch
is always sequential.

---

## 5. `pick_bundles` — the consumer selection algorithm

`pick_bundles` (`crates/aos-package/src/update.rs:292`) takes the parsed
manifest, the persisted `RegistryState`, and the resolved `TrackingMode`, and
returns the **ordered list of bundle entries to download and apply**. An empty
result means "already up to date."

Inputs:

- **`RegistryState`** (`crates/aos-package/src/types.rs:255`) — the consumer's
  cursor: `last_commit`, `last_creation_token`, `last_update`. Persisted under
  `[registry.state]` in the per-registry config file (§7).
- **`TrackingMode`** (`crates/aos-package/src/types.rs:282`) — `Commit`,
  `Branch`, `Tag`, `Version(semver::VersionReq)`, or `Default`. At most one of
  commit/branch/tag/version may be set in config
  (`RegistryConfig::tracking_mode`, `crates/aos-package/src/types.rs:352`).

### 5.1 Decision flow

```
pick_bundles(manifest, state, mode):

  ── tracking-mode short-circuits (pin to a specific tag) ─────────────────────
  Tag(tag)      ─▶ snapshot with target_tag == tag
                   else any entry with target_tag == tag
                   else ERROR "tag '<tag>' not found in bundle manifest"
  Commit(_)     ─▶ (bundle transport can't resolve arbitrary commits)
                   fall through to default logic
  Version(req)  ─▶ tag := find_best_version_tag_in_manifest(req)   # highest match
                   then snapshot with that target_tag
                   else newest delta with that target_tag (rev scan)
                   else ERROR "matched version tag … not available as bundle"
                   if no tag matches ─▶ ERROR "no tags matching version constraint"
  Branch(_) /
  Default       ─▶ fall through to incremental logic

  ── incremental logic (Default / Branch / Commit-fallthrough) ────────────────
  if state.last_creation_token is None                ─▶ [ latest_snapshot() ]   (1)
  newer := entries_since(current_token)
  if newer is empty                                   ─▶ [ ]   (up to date)      (2)

  latest_token := max creation_token in manifest
  base := extract_minor_base(token_to_version(current_token))   # "v2026.02"

  (3) if skip_delta_from(base) exists and its token > current_token
                                                      ─▶ [ skip_delta ]
  (4) else seq := sequential_deltas_between(current_token, latest_token)
          if seq non-empty                            ─▶ seq   (ordered chain)
  (5) else                                            ─▶ [ latest_snapshot() ]
```

### 5.2 Step notes

| Step | Behavior | Code |
|------|----------|------|
| Tag mode | Exact-tag snapshot preferred; falls back to any delta targeting the tag. Hard error if the tag is absent. | `update.rs:299` |
| Commit mode | Bundle transport cannot fetch an arbitrary commit — it falls through to the incremental path (fetch latest). | `update.rs:314` |
| Version mode | Highest semver-matching `target_tag`, snapshot preferred, else newest delta to it. | `update.rs:318`, `update.rs:400` |
| (1) cold start | No prior token ⇒ the latest snapshot. Errors if no snapshot exists. | `update.rs:344` |
| (2) up to date | `entries_since(current)` empty ⇒ `[]`. | `update.rs:355` |
| (3) skip delta | Minor base of the current version → newest skip delta from that base, if newer than current. | `update.rs:368` |
| (4) sequential | `current < token ≤ latest`, filtered to sequential deltas, returned in token order. | `update.rs:379` |
| (5) snapshot fallback | No usable delta path ⇒ latest snapshot (full re-sync). | `update.rs:387` |

Helper queries on `BundleManifest`
(`crates/aos-package/src/registry/bundle.rs:180`):

- `entries_since(token)` — entries with `creation_token > token`.
- `latest_snapshot()` — snapshot with the highest `creation_token`.
- `skip_delta_from(base_tag)` — newest skip delta whose `base_tag` matches.
- `sequential_deltas_between(from, to)` — sequential deltas with
  `from < token ≤ to`.

### 5.3 Version-mode semver normalization

Calendar tags are normalized into semver before matching
(`parse_tag_as_semver`, `crates/aos-package/src/update.rs:429`):

- strip a leading `v`;
- strip leading zeros per component (`02` → `2`);
- pad a 2-component tag to `.0` (`v2026.02` → `2026.2.0`);
- non-parseable tags are silently skipped.

`find_best_version_tag_in_manifest` (`crates/aos-package/src/update.rs:400`)
filters every `target_tag` by the `VersionReq` and returns the **highest**
match. Example: `~2026.2` over `{v2026.02, v2026.02.1, v2026.02.2}` selects
`v2026.02.2`.

> **Worked example (incremental skip).** Consumer at `last_creation_token =
> 2026020000` (`v2026.02`), manifest contains a snapshot `v2026.02`, sequentials
> `.1` and `.2`, and a skip `v2026.02 → v2026.02.2`. `extract_minor_base`
> yields `v2026.02`; `skip_delta_from("v2026.02")` returns the skip (token
> `2026020002 > 2026020000`) ⇒ result is the single skip delta, one download
> instead of two. (See `pick_bundles_uses_skip_delta`, `update.rs:657`.)

> ⚠️ **Sequential-chain contiguity is not verified (CURRENT).** The code comment
> at `crates/aos-package/src/update.rs:381` says it verifies the chain is
> contiguous (first delta's base matches current state), but the implementation
> returns `seq` without that check. If a mirror omits an intermediate
> sequential delta, the gap is only caught later by `git bundle verify` failing
> on the missing prerequisite (§6), not by `pick_bundles`. Recorded in open
> questions.

---

## 6. Download, verify, unbundle

For each selected entry, in order
(`sync_bundle`, `crates/aos-package/src/update.rs:233`):

1. **Download** to `bundles/{registry}/{entry.uri}` in the consumer cache via
   the transfer engine, which streams with inline SHA-256 verification against
   `entry.sha256` (`download_bundle`,
   `crates/aos-package/src/registry/bundle.rs:251`).
2. **Verify** (`verify_bundle`, `crates/aos-package/src/registry/bundle.rs:305`):
   - re-hash the file and compare to `entry.sha256` (defense in depth); and
   - run `git bundle verify` — checks pack integrity **and prerequisites**. A
     delta whose base commit is absent fails here, with guidance to re-run
     `apm update` or `apm update --force` for a full snapshot.
3. **Unbundle** (`unbundle`, `crates/aos-package/src/registry/bundle.rs:376`):
   `git bundle unbundle <file>` into the bare repo at
   `{cache}/{registry}/repo.git` (created on demand by `ensure_git_repo`,
   `crates/aos-package/src/registry/bundle.rs:349`).
4. Delete the bundle file (`update.rs:243`).

```
 for entry in pick_bundles(...):
     download  ──(sha256 stream-verify)──▶ repo.git/bundles/<uri>
     verify    ──(sha256 + git bundle verify: pack + prereqs)
     unbundle  ──(git bundle unbundle)──▶ repo.git
     rm        ──(cleanup .bundle)
 resolve_tag(last target_tag) ──▶ new_commit
 git archive <commit> packages/ | tar -x ──▶ packages/   (cache rebuilt)
```

> **Trust note.** Bundles are pinned by **SHA-256** from the manifest, and
> ultimately the metadata is authenticated transitively by the Ed25519-signed
> git commit (git is a Merkle DAG). Per-bundle signatures are **not** used. See
> [signing-and-trust.md](./signing-and-trust.md) and design brief §3.

---

## 7. Incremental update on the consumer

After all selected bundles are applied
(`sync_bundle`, `crates/aos-package/src/update.rs:248`):

1. **Resolve head.** `resolve_tag(repo, last_target_tag)` →
   `new_commit` (`crates/aos-package/src/registry/bundle.rs:407`).
2. **Rebuild the metadata cache.** `extract_packages_from_git`
   (`crates/aos-package/src/update.rs:469`) wipes `packages/` and re-extracts via
   `git archive <commit> packages/ | tar -x --strip-components=1`. The cache is
   regenerated from the new tree rather than mutated in place.
3. **Compute the new cursor.** `latest_token := max(creation_token)` over the
   applied bundles (`update.rs:256`).
4. **Downgrade guard.** `state::check_monotonic(old, new)` rejects
   `new_token ≤ old_token` (`crates/aos-package/src/registry/state.rs:104`) —
   a stale-mirror / rollback defense.
5. **Persist state.** Set `last_commit`, `last_creation_token`,
   `last_update` and save (§7.1).

```
RegistryState (before)            RegistryState (after)
 last_creation_token = 2026020000  ─▶ last_creation_token = 2026020002
 last_commit         = <old>       ─▶ last_commit         = <new HEAD sha>
 last_update         = <t0>        ─▶ last_update         = <now, ISO-8601>
```

> ⚠️ **`check_monotonic` is gated behind `latest_token > old_token` (CURRENT).**
> At `crates/aos-package/src/update.rs:263`, `check_monotonic` is only invoked
> *inside* `if latest_token > old_token`. Since the function's whole job is to
> reject `new ≤ old`, the guarded call can never observe the case it rejects —
> a manifest whose selected bundles are all `≤` the current token is already
> filtered to `[]` by `entries_since` in `pick_bundles` (§5.1 step 2), so no
> sync occurs and the check is moot. The encoded *intent* (reject downgrades)
> holds in practice, but the explicit `check_monotonic` call here is effectively
> dead. Recorded in open questions.

### 7.1 State persistence

`RegistryState` (`crates/aos-package/src/types.rs:255`) is stored under a
`[registry.state]` section in `registries.d/{name}.toml`. `save_state`
(`crates/aos-package/src/registry/state.rs:37`) rewrites **only** that section,
preserving every user-edited field (name, url, signing, tracking) above and
below it. `load_state` (`crates/aos-package/src/registry/state.rs:21`) reads it
back; absence ⇒ `None` ⇒ a cold-start sync.

```toml
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.signing]
required = true
public_key = "aos-core:Ed25519:base64key…"

[registry.state]              # written by `apm update`, preserved across edits
last_commit = "abc123def456"
last_creation_token = 2026020003
last_update = "2026-02-13T10:30:00Z"
```

---

## 8. Producer-side status (the asymmetry)

The consumer side of this model is fully implemented; the **producer side is a
stub** (design brief §2.11). Relevant to bundles/deltas specifically:

| Capability | Consumer | Producer | Evidence |
|------------|----------|----------|----------|
| Parse `bundle-list.toml` | ✅ | — | `bundle.rs:124` |
| **Write** `bundle-list.toml` | n/a | ❌ | manifest types are `Deserialize`-only (`bundle.rs:59`) |
| `creation_token` encode | ✅ (consumer-side use) | ❌ | `state.rs:131` exists but unused by a writer |
| Classify snapshot/seq/skip | ✅ (read-time) | ❌ | `classify_delta`, `bundle.rs:238` |
| Select minimal bundle set | ✅ `pick_bundles` | n/a | `update.rs:292` |

**CURRENT** `apr bundle` only runs `git bundle create` into a local `bundles/`
directory; it does not emit or update a manifest (its `_update_manifest`
parameter is unused dead code — design brief §2.11). There is no producer
`creation_token` computation, no automatic delta-type classification, and no
upload step for bundles.

> **TARGET.** A real publish pipeline (`apr release` / `apr publish-bundles`)
> generates bundles + the index from the landed signed commit, computes
> `creation_token`s, classifies deltas, uploads immutable content-addressed
> objects first, and flips the signed root last (design brief §4.3–§4.4). See
> [publishing.md](./publishing.md),
> [workstream-02-publish-pipeline](../plans/registry/workstream-02-publish-pipeline.md),
> and [workstream-01-registry-root](../plans/registry/workstream-01-registry-root.md).

---

## 9. Quick reference

| Symbol | Location | Role |
|--------|----------|------|
| `BundleType` | `registry/bundle.rs:22` | Snapshot / SequentialDelta / SkipDelta |
| `BundleEntry` | `registry/bundle.rs:34` | one manifest row (parsed) |
| `BundleManifest` | `registry/bundle.rs:48` | parsed `bundle-list.toml` |
| `classify_delta` | `registry/bundle.rs:238` | seq-vs-skip from `from_tag` shape |
| `entries_since` / `latest_snapshot` / `skip_delta_from` / `sequential_deltas_between` | `registry/bundle.rs:180` | manifest selection helpers |
| `download_bundle` / `verify_bundle` / `unbundle` / `resolve_tag` | `registry/bundle.rs:251` | transport + apply |
| `version_to_token` / `token_to_version` | `registry/state.rs:131` | calendar tag ⇄ token |
| `check_monotonic` | `registry/state.rs:104` | downgrade guard |
| `pick_bundles` | `update.rs:292` | selection algorithm |
| `sync_bundle` | `update.rs:193` | end-to-end consumer sync |
| `RegistryState` | `types.rs:255` | persisted consumer cursor |
| `TrackingMode` | `types.rs:282` | commit/branch/tag/version/default |
