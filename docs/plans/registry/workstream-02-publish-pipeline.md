# Workstream 02 — Producer Publish Pipeline

> **Plan document.** Part of the AOS Registry implementation plan. This
> workstream builds the **producer** side of the registry: the end-to-end
> `apr release` (a.k.a. `apr publish-bundles`) command that does
> **generate → upload → atomic-flip**, the missing bundle/manifest
> generation, producer-side `creation_token` computation, pluggable upload
> backends (S3 / rsync / plain PUT), and the git-CAS + conditional-PUT
> concurrency model.
>
> **Grounding:** intent comes from
> [`design-brief.md`](./design-brief.md) §4.4 (publishing & concurrency) and
> §2.11 (producer-side gaps). Current-state claims are cited against code as
> `path:line`. Where the code and the brief disagree, the code wins for
> *current state* and the discrepancy is logged in
> [`open-questions.md`](./open-questions.md).
>
> **Audience:** implementers building `apr`, architects reviewing the
> concurrency model, engineers operating a registry origin.

---

## Contents

- [1. Scope and goals](#1-scope-and-goals)
- [2. Current state (as-is)](#2-current-state-as-is)
- [3. Target pipeline overview](#3-target-pipeline-overview)
- [4. `apr release` command](#4-apr-release-command)
- [5. Producer-side `creation_token`](#5-producer-side-creation_token)
- [6. Bundle generation](#6-bundle-generation)
- [7. Pluggable upload backends](#7-pluggable-upload-backends)
- [8. Git CAS + atomic root flip](#8-git-cas--atomic-root-flip)
- [9. Failure, retry, and idempotency](#9-failure-retry-and-idempotency)
- [10. Implementation plan and sequencing](#10-implementation-plan-and-sequencing)
- [11. Testing](#11-testing)
- [12. Cross-references](#12-cross-references)

---

## 1. Scope and goals

This workstream turns the producer from a thin `git` + `git bundle create`
wrapper into a real publish pipeline. The deliverable is a single command that,
from a landed-and-signed registry commit, produces the full set of distribution
artifacts and flips the signed root atomically so that consumers never observe a
torn state.

**In scope**

- `apr release` / `apr publish-bundles`: orchestrate generate → upload → flip
  in the only safe order ([§4.4](./design-brief.md)).
- Producer-side `creation_token` computation from the release tag.
- Bundle generation: snapshot, sequential delta, skip delta, with automatic
  type classification (no more manual `--tag` / `--delta-from`).
- A `bundle-list.toml` / `registry.toml` **writer** (the serializer that does
  not exist today).
- Pluggable upload backends: S3 (with conditional PUT), rsync, plain HTTP PUT.
- Git ref CAS as the publish lock; conditional-PUT root flip as the last step.

**Out of scope (handled by sibling workstreams)**

- The `registry.toml` root **schema** and **inline signing** —
  [workstream-01](./workstream-01-registry-root.md). This workstream *calls*
  that serializer and *uploads* the result.
- narinfo / `nix-cache-info` emission —
  [workstream-03](./workstream-03-nix-cache.md). The pipeline uploads these
  objects but their generation lives there.
- Channels, rollouts, `valid_until` —
  [workstream-04](./workstream-04-channels-rollouts.md). The pipeline flips the
  root that carries them; the fields are defined there.
- Consumer reads of the new root —
  [workstream-05](./workstream-05-consumer.md).

---

## 2. Current state (as-is)

The producer is a collection of git pass-throughs. Each `apr` release-related
subcommand is a near-direct shell-out:

| `apr` command | Behavior today | Code |
|---|---|---|
| `apr tag <NAME>` | `git tag [-a -m <msg>]`; `--key` accepted but **ignored** (`_key`) | `registry_ops.rs:1696`–`1714` |
| `apr bundle` | `git bundle create` into a local `bundles/` dir; `--update-manifest` accepted but **ignored** (`_update_manifest`) | `registry_ops.rs:1718`–`1756` |
| `apr sign` | `git commit --amend --no-edit -S`; `--key` ignored (`_key`) | `registry_ops.rs:1759`–`1774` |
| `apr push` | `git push [-u origin] [branch] [--force]` | `registry_ops.rs:1410`–`1442` |
| `apr pull` | `git pull [--rebase]` | `registry_ops.rs:1445` |

**`apr bundle` in detail** (`registry_ops.rs:1718`): it creates the output
directory (`bundles/` by default), resolves the registry name, then either

- `delta_from = Some(from)` → `git bundle create <out>/<reg>-<from>..<tag>.bundle <from>..<tag>`, or
- otherwise → `git bundle create <out>/<reg>-<tag>.bundle <tag>` (tag defaults to `HEAD`).

The `_update_manifest: bool` parameter (`registry_ops.rs:1723`) is **dead
code** — declared on the CLI as `--update-manifest` (`lib.rs:553`), threaded
through, and never read. No manifest is written.

**Producer gaps confirmed against code** (brief §2.11):

| Gap | Confirmed by |
|---|---|
| No `bundle-list.toml` **writer** | `registry/bundle.rs` defines `ManifestToml` / `BundleEntryToml` as `Deserialize` only (`bundle.rs:59`, `:66`, `:75`); `use serde::Deserialize;` at `bundle.rs:11` (no `Serialize`). |
| No producer-side `creation_token` | `version_to_token` / `token_to_version` exist (`registry/state.rs:131`, `:173`) but are only called consumer-side. |
| No automatic delta classification on producer | `apr bundle` takes `--delta-from` manually; `classify_delta` is read-time only (in `bundle.rs`, consumer path). |
| No bundle upload | The only upload code is `aos-cache` (`backend/mod.rs` `CacheBackend` trait, `:23` `put_narinfo`, `:29` `put_nar`) — for **NARs**, not bundles. |
| No narinfo / `nix-cache-info` emission | (workstream-03). |
| No publish locks/atomicity beyond git FF | `apr push` is a bare `git push` (`registry_ops.rs:1435`). |
| No "latest" pointer | Derived consumer-side by scanning the manifest for max `creation_token`. |

The existing manifest URL the consumer expects is
`{base}/bundles/{name}/bundle-list.toml` (`bundle.rs:105`–`109`), with bundles
at `{base}/bundles/{name}/{uri}` (consumer `download_bundle`, brief §2.4).

### What already exists that this workstream reuses

- **`creation_token` codec** — `version_to_token` /`token_to_version` /
  `check_monotonic` (`registry/state.rs:104`, `:131`, `:173`). These are pure
  and already tested; the producer just needs to *call* them.
- **A backend abstraction with conditional-PUT-capable schemes** — the
  `aos-cache` `CacheBackend` trait and its `from_url` dispatcher
  (`backend/mod.rs:177`) already speak `file`, `http(s)`, `s3`, and `sftp`,
  with an `AuthOptions` struct (`backend/mod.rs:51`) carrying S3 region /
  profile / endpoint and SSH key / password. The S3 path uses
  `aos_net::Credential::AwsSigV4` (`backend/mod.rs:122`). This workstream
  generalizes (not forks) this abstraction for bundle/root objects.

---

## 3. Target pipeline overview

The pipeline is the §4.4 ordering made concrete. **"Latest" becomes an explicit
signed field** flipped atomically as the last step — never re-derived.

```
                 ┌──────────────────────────────────────────────┐
                 │  apr publish    (commit + sign + git push)    │
                 │  ── git ref CAS: only one winner lands HEAD ──│
                 └───────────────────────┬──────────────────────┘
                                         │ winner only
                                         ▼
        ┌────────────────────────────────────────────────────────┐
        │ 1. GENERATE   (from the *landed* commit, deterministic) │
        │    • compute creation_token from release tag            │
        │    • classify delta kind (snapshot / sequential / skip) │
        │    • git bundle create  →  *.bundle  (+ sha256, size)   │
        │    • narinfos + nix-cache-info        (workstream-03)    │
        │    • serialize registry.toml root     (workstream-01)    │
        └───────────────────────────────┬────────────────────────┘
                                         ▼
        ┌────────────────────────────────────────────────────────┐
        │ 2. UPLOAD IMMUTABLE OBJECTS FIRST  (idempotent, any     │
        │    order; content-addressed keys)                       │
        │    • nar/<…>.nar.zst    • *.narinfo    • *.bundle       │
        │    Re-uploading an existing key is a no-op.             │
        └───────────────────────────────┬────────────────────────┘
                                         ▼
        ┌────────────────────────────────────────────────────────┐
        │ 3. FLIP THE ROOT LAST, ATOMICALLY                       │
        │    • PUT registry.toml with conditional CAS             │
        │      (S3 If-Match / If-None-Match ETag)                 │
        │    • readers see old-root OR new-root, never torn —     │
        │      everything the new root references already exists  │
        └────────────────────────────────────────────────────────┘
```

The invariant that makes the flip safe: **the new root only references objects
that step 2 already uploaded.** A consumer that reads root@T resolves a
self-consistent set even if root@T+1 lands mid-fetch, because the by-hash keys
in root@T remain immutable and present (brief §4.3 by-hash discipline,
[workstream-01](./workstream-01-registry-root.md)).

---

## 4. `apr release` command

> **TARGET.** New command. Open question 6 in the brief asks "whether `apr`
> gains a real `apr publish-bundles` / `apr release` command that performs the
> §4.4 ordering end-to-end"; this workstream answers **yes** and specifies it.

### 4.1 Surface

`apr release` (alias `apr publish-bundles`) wraps the existing `tag` / `bundle`
/ `sign` / `push` primitives into one ordered operation. The primitives remain
available for advanced/manual flows.

```
apr release [OPTIONS]

  --tag <vYYYY.MM[.P]>     Release tag. Default: HEAD's nearest tag, else error.
  --channel <NAME>         Also point this channel at <tag> (workstream-04).
                           Repeatable.
  --upload <URL>           Upload backend target. Repeatable (multi-mirror).
                           Schemes: s3://, rsync://, https:// (PUT), file://.
  --base-tag <vYYYY.MM>    Force the skip-delta base. Default: auto (§6.2).
  --no-delta               Emit a snapshot only; skip delta bundles.
  --snapshot               Force a fresh snapshot in addition to deltas.
  --sign / --no-sign       Sign the commit before push (default: --sign).
  --valid-for <DURATION>   Root expiry window (workstream-04). e.g. 30d.
  --dry-run                Generate + report; do not upload or flip.
  --force                  Allow non-FF push (discouraged; see §8).
  --registry <NAME>        Registry to operate on.
```

### 4.2 Phases

```
apr release --tag v2026.06.3 --upload s3://aos-registry/

  Phase 0  preflight
    • resolve registry dir + name (registry_ops.rs::registry_dir / resolve_registry_name)
    • verify working tree clean; resolve --tag to a commit
    • compute new creation_token = version_to_token(tag)         (§5)
    • read current [latest].creation_token from the published root (or local state)
    • check_monotonic(old, new)  → abort on downgrade            (state.rs:104)

  Phase 1  land the commit  (git CAS — §8)
    • git commit (if needed) ; apr sign (-S)                     (registry_ops.rs:1770)
    • git push  (FF-only)     → CAS winner; loser: pull --rebase + retry

  Phase 2  generate          (deterministic, from landed commit — §6)
    • bundles → bundles/<reg>/<key>.bundle   (+ sha256, size)
    • narinfos + nix-cache-info              (workstream-03)
    • serialize registry.toml root           (workstream-01)

  Phase 3  upload immutable objects first    (§7)  — idempotent, any order
    • for each backend in --upload: put nar/*, *.narinfo, *.bundle

  Phase 4  flip root last, atomically        (§8)
    • for each backend: conditional PUT registry.toml (If-Match ETag)
    • on PUT precondition failure → re-read, re-derive, retry (§9)
```

`--dry-run` runs Phases 0 and 2 and prints the artifact set (keys, sizes,
hashes, the would-be root) without touching the remote — the producer
equivalent of the consumer's bundle-selection preview.

---

## 5. Producer-side `creation_token`

> **CURRENT:** the codec exists but is only invoked consumer-side
> (`registry/state.rs:131` / `:173`). **TARGET:** the producer computes the
> token at release time and writes it into every bundle entry and the
> `[latest]` pointer.

The encoding (verified at `registry/state.rs:131`–`165`) is:

```
creation_token = year * 1_000_000 + month * 10_000 + patch
```

with these rules, taken from the code:

| Rule | Source |
|---|---|
| Strip a leading `v`. | `state.rs:132` |
| Accept exactly 2 or 3 dotted parts (`vYYYY.MM` or `vYYYY.MM.P`); else error. | `state.rs:135` |
| Month must be `1..=12`. | `state.rs:149` |
| Patch defaults to `0` when absent; must be `<= 9999`. | `state.rs:153`, `:161` |
| Patch `0` decodes back to a 2-part base tag (`v2026.06`); non-zero to 3 parts. | `state.rs:179` |

Worked examples (matching the doc-comments at `state.rs:128`–`130` and
`:170`–`172`):

| Tag | `creation_token` |
|---|---|
| `v2026.06` | `2026060000` |
| `v2026.06.3` | `2026060003` |
| `v2026.02` | `2026020000` |
| `v2026.02.3` | `2026020003` |

> **Note — token vs. semver padding.** `version_to_token` works on the **raw tag
> string**, whereas the consumer's `parse_tag_as_semver` (brief §2.5, `update.rs`)
> strips leading zeros and pads to a `semver::Version`. The token codec keeps
> the zero-padded month in the *string* form (`v2026.06`) but the *numeric* token
> drops it (`2026060000`). The producer uses the **token** for ordering and the
> **tag string** for display; do not conflate the two.

**Producer responsibilities:**

1. Compute `new_token = version_to_token(--tag)` at Phase 0.
2. Run `check_monotonic(old_token, new_token)` (`state.rs:104`) against the
   currently-published `[latest].creation_token` (or local `[registry.state]` if no root
   is published yet) and **abort** on a downgrade before any artifact is
   generated. This is the producer-side mirror of the consumer's stale-mirror
   defense.
3. Stamp `creation_token` into every emitted bundle entry and into
   `[latest].creation_token` in the serialized root.

---

## 6. Bundle generation

> **CURRENT:** `apr bundle` (`registry_ops.rs:1718`) shells out to
> `git bundle create` with a manually-supplied `--tag` / `--delta-from`, and
> writes **no manifest**. **TARGET:** the pipeline classifies the delta kind
> automatically, emits all three bundle kinds as needed, and writes the manifest
> via the new serializer.**

### 6.1 Bundle kinds

The three kinds are already modeled on the consumer side
(`registry/bundle.rs:24` `BundleType { Snapshot, SequentialDelta, SkipDelta }`).
The producer must emit them with matching semantics:

| Kind | Rev-range | Purpose |
|---|---|---|
| **Snapshot** | `<tag>` (full history to tag) | Bootstrap a cold client; fallback when no usable delta chain exists. |
| **SequentialDelta** | `<prev-patch>..<tag>` | Smallest hop: from the immediately preceding patch. |
| **SkipDelta** | `<minor-base>..<tag>` | One hop from a minor base `vYYYY.MM` to a later patch, so a client several patches behind catches up in a single fetch. |

### 6.2 Automatic classification (producer)

The consumer classifies at read-time via
`classify_delta(from: &str, _to: &str) -> bool`
(brief §2.4, `bundle.rs:238`; the second argument is unused, and `bundle.rs:227`
is the doc comment, not the fn): a delta whose `from` tag has **≤ 2 dotted
parts** (a minor base `vYYYY.MM`) is a **SkipDelta** (`true`); otherwise
**SequentialDelta** (`false`). The producer must classify with the **same rule**
so that the manifest it writes and the manifest the consumer reads agree:

```
fn classify(from_tag: &str) -> BundleType {
    // ≤ 2 dotted parts (vYYYY.MM)  → skip-ahead base
    // 3 dotted parts  (vYYYY.MM.P) → sequential predecessor
    if dotted_parts(strip_v(from_tag)) <= 2 { BundleType::SkipDelta }
    else                                    { BundleType::SequentialDelta }
}
```

For a patch release `vYYYY.MM.P` the producer emits:

```
target = vYYYY.MM.P
  ├─ SequentialDelta  from vYYYY.MM.(P-1)  (the immediately preceding patch)
  ├─ SkipDelta        from vYYYY.MM        (the minor base — one hop for laggards)
  └─ Snapshot         vYYYY.MM.P           (cold-start / fallback; --snapshot or
                                            when no prior tag exists)
```

`--no-delta` suppresses the delta bundles; `--base-tag` overrides the
auto-chosen skip base; `--snapshot` forces a fresh snapshot alongside deltas.

### 6.3 Object keys and layout

Bundles continue to live under the consumer-expected prefix
(`bundle.rs:105`, brief §3):

```
{base}/bundles/{registry}/registry.toml            # TARGET signed root index
{base}/bundles/{registry}/bundle-list.toml         # CURRENT manifest (compat shim — §10)
{base}/bundles/{registry}/<key>.bundle             # the bundle objects
```

**Bundle key grammar (TARGET).** Today `apr bundle` names files by tag
(`<reg>-<tag>.bundle`, `<reg>-<from>..<tag>.bundle` — `registry_ops.rs:1736`,
`:1746`). The authoritative grammar lives in
[`http-layout.md` §4](../../registry/http-layout.md) (referenced, not restated
here):

- snapshot: `{name}-{tag}.bundle`
- delta:    `{name}-{from}..{to}.bundle`

The literal filename is **convention only**; authority is **by-hash** — the
`sha256` lives in the root's `[[bundles]]` entry, **not** embedded in the key. So
a mid-publish reader never tears: the root references the content hash, and the
filename is just a human-readable handle. This workstream produces keys that
match the [`http-layout.md` §4](../../registry/http-layout.md) grammar.

### 6.4 The missing manifest/root writer

The serializer that does not exist today
(`bundle.rs` types are `Deserialize`-only — `bundle.rs:11`) is delivered by
[workstream-01](./workstream-01-registry-root.md) for the **`registry.toml`**
root. This workstream:

1. Builds the in-memory bundle index — one `[[bundles]]` entry per emitted
   bundle with `uri` (the object key/filename), `creation_token`, `type`
   (`"snapshot"` | `"delta"`; skip-vs-sequential is **derived** via
   `classify_delta(from_tag)`, not a wire value), `tag` (snapshots) or
   `from_tag`/`to_tag` (deltas), `sha256` (always with the explicit algo prefix
   `sha256:<hex>`), and `size` (the fields the consumer reads at
   `bundle.rs:76`–`92`). There is **one** `[[bundles]]` array — deltas are folded
   in and distinguished by `type`, not a separate `[[deltas]]` array.
2. Sets `[latest]` = `{ tag, creation_token, head }` where `head` is the
   **landed commit SHA** (Phase 1), `creation_token` the §5 value (brief §4.3).
3. Calls the workstream-01 serializer to produce the inline-signed
   `registry.toml`.

**Migration shim:** for existing `bundle-list.toml` mirrors (brief open
question 7), the pipeline can *also* emit a legacy `bundle-list.toml` derived
from the same in-memory index, until the schema-version bump retires it. This
is the producer-side serializer the consumer's parser (`bundle.rs:124`) has
always assumed existed.

---

## 7. Pluggable upload backends

> **CURRENT:** no bundle upload exists; the only upload code is `aos-cache`'s
> `CacheBackend` for NARs (`backend/mod.rs:29` `put_nar`). **TARGET:** a small
> object-upload abstraction with S3 / rsync / plain-PUT / file backends,
> reusing the `aos-cache` auth and transport plumbing.**

### 7.1 The abstraction

Generalize the NAR-specific `CacheBackend` into an object-upload trait that the
publish pipeline drives. Minimum surface:

```rust
#[async_trait]
pub trait PublishBackend: Send + Sync {
    /// Upload an immutable, content-addressed object. Re-uploading an
    /// existing identical key is a no-op (idempotent).
    async fn put_object(&self, key: &str, data: &[u8]) -> Result<()>;

    /// Does this key already exist? (skip re-upload of immutable objects)
    async fn has_object(&self, key: &str) -> Result<bool>;

    /// Atomically replace `key`, conditioned on the prior ETag.
    /// `expected` = Some(etag) → If-Match; None → If-None-Match: * (create).
    /// Returns the new ETag. Errs with `PreconditionFailed` on CAS loss.
    async fn put_conditional(
        &self, key: &str, data: &[u8], expected: Option<&str>,
    ) -> Result<String>;

    /// Whether this backend supports conditional PUT (§8). file/rsync may not.
    fn supports_conditional(&self) -> bool { false }
}
```

A `from_url` dispatcher mirrors `aos-cache`'s (`backend/mod.rs:177`), reusing
`AuthOptions` (`backend/mod.rs:51`) and `aos_net` credentials.

### 7.2 Backend matrix

| Scheme | `put_object` | `put_conditional` | Notes |
|---|---|---|---|
| `s3://bucket/prefix` | `PutObject` (SigV4 — `backend/mod.rs:122`) | **`If-Match` / `If-None-Match` ETag CAS** | Native atomic flip. The admin fast-path (brief §4.3 — listing/CAS bonus, never required for correctness). |
| `https://host/path` | HTTP `PUT` | `If-Match` if origin honors it; else two-phase (§8.3) | "Plain PUT" LCD origin. Conditional support is origin-dependent. |
| `rsync://host/mod/path` | `rsync` of the object | **No** native CAS → two-phase rename (§8.3) | Static-mirror-friendly; matches APT rsync mirrors (brief §5). |
| `file:///abs/path` | write file | `rename(2)` (atomic on POSIX) | Local origin / testing. |

`--upload` is repeatable: a single `apr release` fans the same artifact set out
to multiple mirrors. Immutable objects (Phase 3) upload to all; the root flip
(Phase 4) is per-backend conditional.

### 7.3 Reuse, do not fork

- `s3://` and `sftp://` already work in `aos-cache` (`backend/mod.rs:193`,
  `:202`) — extend, don't duplicate. The S3 backend already carries region /
  profile / endpoint via `AuthOptions` (`backend/mod.rs:60`–`63`).
- Per the project hermeticity rules, **rsync is the AOS package** (`pkgs.rsync`)
  shelled out to, never a host binary — consistent with how the codebase shells
  out to `zstd` / `xz` in `aos-cache/src/compress.rs:27`.
- The transport engine is `aos_net::TransferEngine` (`backend/mod.rs:11`,
  `:170`); auth maps through `apply_auth_to_engine` (`backend/mod.rs:72`).

---

## 8. Git CAS + atomic root flip

> **TARGET** concurrency model, brief §4.4. **No separate lock service.** Two
> independent CAS primitives serialize publishes: the git ref update (for the
> metadata commit) and the conditional PUT (for the root flip).

### 8.1 Git ref CAS = the lock

`apr push` is FF-only `git push` (`registry_ops.rs:1435`). The remote's atomic
ref update is the lock: concurrent publishers race to fast-forward `HEAD`;
exactly one wins; losers get a **non-FF rejection**. There is no lock to
acquire or release.

```
Publisher A ──┐
              ├── git push (FF-only) ──► remote ref CAS ──► A wins, B rejected
Publisher B ──┘                                              │
                                                             ▼
                                              B: git pull --rebase ; retry release
```

**Loser recovery:** the pipeline catches the non-FF rejection, runs
`git pull --rebase` (`apr pull --rebase` exists — `registry_ops.rs:1453`), and
**re-runs `apr release` from Phase 0** — so the token monotonicity check and the
regenerated artifacts reflect the new `HEAD`. `--force` (`registry_ops.rs:1425`)
bypasses FF and is reserved for deliberate history surgery; it is **not** part of
the normal publish path.

### 8.2 Conditional-PUT root flip = the last step

After all immutable objects are uploaded (Phase 3), the root is flipped
**atomically and last** (Phase 4):

```
read current registry.toml ETag  (or None if first publish)
  │
  ▼
PUT registry.toml  with  If-Match: <etag>      (update)
                     or  If-None-Match: *       (create)
  │
  ├─ 200/204  → flip succeeded; [latest] now points at the new release
  └─ 412 Precondition Failed → another publisher flipped first:
        re-read root → re-derive (merge our bundle entries) → retry (§9)
```

Because the new root only references objects that already exist (Phase 3),
**readers see old-root or new-root, never a torn set** (brief §4.4). The S3
`If-Match` / `If-None-Match` ETag mechanism is the canonical implementation; it
is the same CAS discipline APT achieves only loosely via rsync mirror timing
(brief §5 — "git FF CAS ≥ APT rsync mirror races").

### 8.3 Backends without native conditional PUT

For `rsync://` / `file://` / non-conditional `https://`, emulate atomic replace
with **write-new-then-rename**:

```
PUT  registry.toml.<token>.tmp            # unique temp key
rename → registry.toml                    # atomic on POSIX / single rsync op
```

This is best-effort: it removes torn reads but not all lost-update races on a
backend with no compare-and-swap. **S3 conditional PUT remains the recommended
flip target;** dumb mirrors are populated by mirroring *from* the canonical S3/
git origin rather than being flip targets themselves (brief §4.3 — dumb HTTP is
the LCD for *reads*, not necessarily the CAS authority for writes). See
[`open-questions.md`](./open-questions.md).

### 8.4 Why "latest" is a flipped field, not a scan

Today "latest" is derived by scanning the manifest for the max `creation_token`
(brief §2.11). In the target, `[latest]` is an **explicit signed pointer**
(`tag`, `creation_token`, `head`) flipped atomically as the **last** step (brief §4.4,
§4.3). This is what gives the consumer a freshness/anti-rollback anchor a dumb
listing can't provide and lets it **fail closed** on omission (brief §4.5) —
see [workstream-05](./workstream-05-consumer.md).

---

## 9. Failure, retry, and idempotency

The pipeline is structured so every phase is safely retryable.

| Failure point | Effect | Recovery |
|---|---|---|
| Phase 0 monotonic check fails | Nothing generated/uploaded | Operator error: token not newer than published `[latest].creation_token` (`state.rs:104`). Fix tag / mirror. |
| Phase 1 non-FF push rejection | Commit not landed | `git pull --rebase` (`registry_ops.rs:1453`) → re-run from Phase 0 (§8.1). |
| Phase 3 upload interrupted | Some immutable objects present, root **still old** | Re-run Phase 3; `has_object` (§7.1) skips already-present keys. Root not yet flipped → consumers unaffected. |
| Phase 4 conditional PUT `412` | Root not flipped by us | Re-read root, merge our (already-uploaded) bundle entries into the latest index, re-serialize, retry the conditional PUT (§8.2). |
| Phase 4 partial multi-mirror | Some mirrors flipped, some not | Re-run; idempotent immutable objects + per-mirror conditional flip converge. |

**Key property:** because immutable objects are content-addressed and uploaded
**before** the flip, an aborted publish leaves only orphan-but-harmless objects
(garbage-collectable), never a root pointing at a missing object. The flip is
the single linearization point.

---

## 10. Implementation plan and sequencing

| Step | Deliverable | Depends on | Touches |
|---|---|---|---|
| 1 | Producer `creation_token`: call `version_to_token` + `check_monotonic` at release time; abort on downgrade | exists (`state.rs:104`, `:131`) | `registry_ops.rs` |
| 2 | Bundle generation with auto delta classification (snapshot / sequential / skip); by-hash key grammar | step 1; [ws-01](./workstream-01-registry-root.md) key grammar | `registry_ops.rs:1718` (replace `apr bundle` internals) |
| 3 | Manifest/index builder: in-memory bundle index → call ws-01 root serializer (+ optional `bundle-list.toml` compat shim) | [ws-01](./workstream-01-registry-root.md) serializer | new module in `aos-package` |
| 4 | `PublishBackend` trait + `from_url`; S3 conditional PUT, rsync/file two-phase, https PUT | reuse `aos-cache` `CacheBackend` (`backend/mod.rs`) | `aos-cache` (generalize) or new `aos-publish` |
| 5 | `apr release` orchestration: Phases 0–4, loser retry, conditional-flip retry | steps 1–4; [ws-03](./workstream-03-nix-cache.md) for narinfo objects | `registry_ops.rs`, `lib.rs` (CLI) |
| 6 | Wire `--channel` / `--valid-for` into the flipped root | [ws-04](./workstream-04-channels-rollouts.md) | `apr release` |

**Sequencing note:** steps 1–2 are unblocked today (the token codec and
`git bundle` shell-outs already exist). Step 3 blocks on the
[workstream-01](./workstream-01-registry-root.md) serializer. Step 5's full
artifact set additionally needs [workstream-03](./workstream-03-nix-cache.md)
(narinfos / `nix-cache-info`), but the bundle-only release path can ship after
steps 1–4.

**Dead-code cleanup:** retire the unused `_update_manifest` parameter
(`registry_ops.rs:1723`) and `_key` (`registry_ops.rs:1700`, `:1762`) by wiring
them to real behavior in steps 2–5, or remove the flags from the CLI
(`lib.rs:553`, `:535`).

---

## 11. Testing

Per the project's testing posture, prefer pure-eval unit tests for the codec /
classifier and integration tests for the upload/flip path using the `file://`
backend (no network).

- **`creation_token` round-trips** — extend the `state.rs` test module
  (`state.rs:186`) with producer call-sites; assert `version_to_token` /
  `token_to_version` agree with §5 examples and that `check_monotonic` rejects
  equal/older tokens.
- **Delta classification parity** — assert the producer's `classify` and the
  consumer's `classify_delta` (`bundle.rs:238`) agree on the same `from` tags,
  so a written manifest round-trips through the reader.
- **Manifest round-trip** — serialize an index, parse it back with
  `BundleManifest::parse` (`bundle.rs:124`); assert structural equality. This is
  the regression test that the new writer matches the existing reader.
- **Atomic flip** — with a `file://` backend: simulate two concurrent releases;
  assert exactly one conditional-PUT/rename wins and the loser retries to a
  consistent root; assert no reader observes a root referencing a missing
  object.
- **Idempotent re-upload** — re-run Phase 3; assert `has_object` skips present
  keys and the operation is a no-op.

---

## 12. Cross-references

**Plan (this set):**
[README](./README.md) ·
[design-brief](./design-brief.md) (§4.4, §2.11) ·
[gap-analysis](./gap-analysis.md) ·
[ws-01 registry root](./workstream-01-registry-root.md) (root schema, serializer, inline signing) ·
[ws-03 nix cache](./workstream-03-nix-cache.md) (narinfo / `nix-cache-info` objects) ·
[ws-04 channels & rollouts](./workstream-04-channels-rollouts.md) (`--channel`, `valid_until`) ·
[ws-05 consumer](./workstream-05-consumer.md) (reading the flipped root) ·
[open-questions](./open-questions.md)

**Reference (target state):**
[registry README](../../registry/README.md) ·
[architecture](../../registry/architecture.md) ·
[current-state](../../registry/current-state.md) ·
[http-layout](../../registry/http-layout.md) (object keys, by-hash) ·
[registry-toml](../../registry/registry-toml.md) (root schema) ·
[bundles-and-deltas](../../registry/bundles-and-deltas.md) (`creation_token`, snapshot/sequential/skip) ·
[nix-cache-compatibility](../../registry/nix-cache-compatibility.md) ·
[signing-and-trust](../../registry/signing-and-trust.md) ·
[publishing](../../registry/publishing.md) (producer workflow & concurrency) ·
[versioning-and-channels](../../registry/versioning-and-channels.md) ·
[apt-comparison](../../registry/apt-comparison.md)
