# Workstream 04 — Signing & Trust

> **Plan doc.** Implements the signing and trust layer of the git-native AOS
> registry: **signed tag objects** (SSH-format Ed25519, a pure signed pointer
> with no structured payload), **name-binding verification**, the
> **`tag → tag → commit`** trust chain, **sha256** object format, **freshness**
> via CDN TTL + consumer policy + monotonic floor, and
> **anti-rollback / fix-forward**, and the **`keys.toml` trust roster** (active +
> revoked keys) that governs key rotation/revocation. Grounded in §11, §5, and §14
> of the [design brief](./design-brief.md); reuses the existing TOFU +
> `trusted-keys.d` primitives. The committed-tree placement of `registry.toml` /
> `keys.toml` is detailed in [`repo-layout.md`](../../registry/repo-layout.md).
>
> **Historical labeling:** **CURRENT** describes the pre-cutover code that existed
> when this plan was written (cited as `path:line`); **TARGET** describes the
> git-native model this workstream builds.
>
> **As-built status note:** this workstream is now archival planning context. The
> signing/trust implementation has landed locally; use
> [`../../registry/current-state.md`](../../registry/current-state.md) and
> [`TODO.md`](./TODO.md) for current facts. Follow-up production validation is
> tracked in [`validation-runbook.md`](./validation-runbook.md). Older CURRENT
> citations below describe the pre-cutover tree.

---

## 1. Scope & relationship to the rest

This workstream owns *trust*: how a consumer decides that a release commit, and
the channel partition that points at it, are authentic and fresh. It does **not**
own object transport (see
[workstream-01-object-store.md](./workstream-01-object-store.md)), pack/delta
generation ([workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md)),
or the channel/rollout mechanics
([workstream-03-channels-rollouts.md](./workstream-03-channels-rollouts.md)) —
but it is the verification gate every one of those flows passes through. The
consumer-side resolution that *calls* this gate lives in
[workstream-05-consumer.md](./workstream-05-consumer.md).

Reference docs this workstream realizes:
[signing-and-trust.md](../../registry/signing-and-trust.md) and the trust columns
of [versioning-and-channels.md](../../registry/versioning-and-channels.md). A
signed tag carries no structured payload, so there is no tag-message schema to
verify.

| Concern | Workstream | This doc's role |
|---|---|---|
| sha256 bare repo, dumb HTTP, `info/alternates` | [01](./workstream-01-object-store.md) | requires sha256; verifies objects fetched over it |
| thin/full packs, zstd, delta graph | [02](./workstream-02-pack-delta-pipeline.md) | verifies the *commit* a delta resolves to |
| 256 partition tags, frontier branch, bucket | [03](./workstream-03-channels-rollouts.md) | signs + name-binds the 256 partition tags |
| consumer resolution & retention | [05](./workstream-05-consumer.md) | exposes the verify gate it calls |

---

## 2. CURRENT state (code-grounded)

Today's signing/trust primitives already exist and are **reusable as-is** for
the SSH/Ed25519 mechanics. What is missing is everything *tag*-shaped: tag
objects, name-binding, and the two-hop chain.

### 2.1 What exists

- **Key model & TOFU.** `crates/aos-package/src/security.rs:30-41` defines
  `TrustedKey { registry, algorithm, public_key, fingerprint, source }`;
  `security.rs:52-131` is the `KeyStore` over `trusted-keys.d/<registry>.pub`
  (first dir writable for TOFU, rest read-only pre-installed);
  `security.rs:159-187` is `tofu_check` returning
  `AlreadyTrusted | NewKey | KeyMismatch`.
- **Key wire format.** `parse_signing_key` (`security.rs:306-331`) parses
  `registry:algorithm:base64key`, **rejecting any algorithm but `Ed25519`**.
  `key_fingerprint` (`security.rs:338-347`) = first 8 hex of `sha256(key bytes)`.
- **Signature verification — but only commits.**
  `verify_commit_signature` (`security.rs:199-233`) writes a temporary
  `allowed_signers` file (`registry ssh-ed25519 <base64>`) and runs
  `git -c gpg.ssh.allowedSignersFile=… verify-commit <commit>`. There is **no**
  `verify-tag` path and **no** name-binding.
- **Downgrade detection.** `check_downgrade` (`security.rs:256-296`) uses
  `git merge-base --is-ancestor` to classify a transition as
  `FastForward | SameCommit | Downgrade | Diverged`. This is **commit-ancestry**
  anti-rollback, not the semver/floor anti-rollback the target adds on top.
- **Producer signing.** `apr sign` (`registry_ops.rs:1747-1762`) is
  `git commit --amend --no-edit -S` (`registry_ops.rs:1758`) — it signs the
  *commit*, not a tag.
  `apr tag` (`registry_ops.rs:1684-1702`) creates an annotated tag with
  `git tag -a <name> -m <msg>` **only when `--message` is given**, otherwise a
  lightweight `git tag <name>` — and in neither case does it **sign** (the
  `_key` arg, `registry_ops.rs:1688`, is unused). When a message is present it is
  free-form, which the TARGET keeps: a signed tag's message stays an optional
  freeform human note.

### 2.2 Gaps vs. TARGET

| # | Gap | CURRENT | TARGET |
|---|---|---|---|
| G1 | Sign **tag objects**, not commits | `apr sign` = `commit --amend -S` (`registry_ops.rs:1758`) | `git tag -s` on partition + release tags |
| G2 | **Verify tags** | only `verify-commit` (`security.rs:217-226`) | `verify-tag` + read tag object |
| G3 | **Name-binding** | none | embedded tag-name field == serving path name |
| G4 | **`tag → tag → commit`** chain | none | partition tag → semver tag → commit, each checked |
| G5 | **sha256** objects | repo is sha1 today | `git init --object-format=sha256` |
| G6 | **Freshness** enforcement | none | CDN TTL + consumer max-staleness policy + monotonic floor (no in-band expiry) |
| G7 | **Anti-rollback floor** | commit-ancestry only (`check_downgrade`) | persisted semver monotonic floor + fix-forward |
| G8 | Tags are **pure signed pointers** | unsigned, free-form message | `git tag -s`, no structured payload (optional freeform note only) |
| G9 | **Trust roster in tree** | pubkey lives in `registry.toml` (`RegistrySigningConfig.public_key`, `types.rs:594-595` — the `signing: Option<RegistrySigningConfig>` field of `RegistryRootConfig`, `types.rs:564-570`) | `keys.toml` (active + revoked); pubkey **removed** from `registry.toml`; TOFU unchanged |

---

## 3. TARGET — the trust model

### 3.1 What is signed, what is not

Per brief §5 there are three ref layers; **only the tag objects are signed**:

| Path / ref | Object | Signed? | In trust chain? |
|---|---|---|---|
| `HEAD` | symref → `refs/heads/<default-channel>` | no | no |
| `refs/heads/<channel>` | branch ptr → frontier commit | **no** | **no** (convenience pointer) |
| `refs/tags/<semver>` | annotated tag → commit | **yes** | yes (release tag) |
| `/channels/<name>/<00..ff>` | 256 annotated tags → semver tag | **yes** | yes (partition tags) |

Branch refs are **unsigned convenience pointers**: `refs/heads/<channel>` points
at the **frontier** (the commit of the newest release any partition targets), so
stock `git pull <channel>` gets the frontier with no rollout/signature
protection. That is acceptable because rollout is an AOS-fleet concept, not a
git-clone concept. AOS trust derives **only** from the signed tags.

### 3.2 The `tag → tag → commit` chain

```
/channels/stable/b7                      refs/tags/1.4.2                     commit
┌───────────────────────────┐  →obj→   ┌───────────────────────────┐  →obj→ ┌─────────┐
│ annotated tag object       │          │ annotated tag object       │        │ release  │
│  tag-name field: "stable"  │          │  tag-name field: "1.4.2"   │        │ commit   │
│  type: tag                 │          │  type: commit              │        │ (tree)   │
│  → refs/tags/1.4.2         │          │  → <commit-sha256>         │        └─────────┘
│  message: optional freeform│          │  message: optional freeform│
│  SSH Ed25519 signature     │          │  SSH Ed25519 signature     │
└───────────────────────────┘          └───────────────────────────┘
       ▲ HOP 1 (channel)                        ▲ HOP 2 (release)
```

Verification walks left→right and checks, at **each** hop:

1. **Signature** valid against the registry's trusted Ed25519 key (same key for
   both hops; reuse `verify_commit_signature`'s mechanism, retargeted to tags).
2. **Name-binding** (brief §5): the tag object's **embedded tag-name field**
   equals the *expected name for the serving path* — the **channel name** for a
   `/channels/<name>/<n>` object, the **semver** for a `refs/tags/<semver>`
   object. This binds a tag object to where it is served and prevents
   cross-serving (e.g. a valid `stable` partition tag re-served as `testing`).
3. **Type / target** matches the chain shape: HOP-1 tag must be `type tag`
   pointing at the HOP-2 semver tag; HOP-2 tag must be `type commit` pointing at
   the release commit.

A stock-git user skips HOP 1 entirely and runs `git verify-tag <semver>` — HOP 2
alone is the standard release-signature check, which still works.

### 3.3 Name-binding, precisely

`git tag -a/-s <name>` records `<name>` inside the tag object's `tag` header.
The serving path also names the tag:

| Object served at | Expected embedded tag-name |
|---|---|
| `/channels/stable/00 … /ff` | `stable` (the channel name — **all 256 share it**) |
| `/channels/testing/00 … /ff` | `testing` |
| `refs/tags/1.4.2` | `1.4.2` |
| `refs/tags/1.0.0-beta+exp.sha.5114f85` | `1.0.0-beta+exp.sha.5114f85` |

All 256 partition tags for a channel carry the **same** tag-name (the channel
name); they differ only by which **semver tag they target** and their
**signature object** (each is independently signed so partitions advance
independently — see
[workstream-03](./workstream-03-channels-rollouts.md)). The partition index
`00..ff` is a *path* coordinate, **not** part of the embedded name.

> **Attack this stops.** Without name-binding, a CDN/mirror operator could serve
> a genuine, validly-signed `stable` partition tag at the `/channels/testing/*`
> path, silently grafting stable's release onto testing consumers. Name-binding
> rejects it because the embedded name (`stable`) ≠ the path name (`testing`).

---

## 4. sha256 object format (G5)

The repo is initialized `git init --object-format=sha256` (brief §8). Loose
object path is the 2/62 split of the 64-hex digest. For *this* workstream the
implications are:

- `allowed_signers` / `verify-tag` is **format-agnostic** — the SSH signature
  covers the tag-object payload, so verification code does not special-case
  sha256. No change to `verify_commit_signature`'s mechanism is needed beyond
  retargeting it to tags.
- The **semver** carried in the embedded tag-name and the **commit sha256** the
  HOP-2 tag points at are what we bind to; we never trust a bare ref pointer.
- **Caveat (brief §12):** dumb HTTP has no capability negotiation, so the
  consumer's `git` must support sha256. Tracked in
  [open-questions.md](./open-questions.md) #1.

---

## 5. Freshness — no in-band `valid_until` (G6)

Signed tags carry **no** in-band expiry. There is no `valid_until` field (tags
have no structured payload at all — §3.1). Freshness is instead a composition of
three out-of-band mechanisms:

| Mechanism | Where it lives | What it does |
|---|---|---|
| **Low CDN TTL** | origin/CDN cache headers on `/channels`, `info/refs`, `objects/info` | bounds how stale a served rollout pointer / ref advertisement can be |
| **Consumer max-staleness policy** | consumer's local registry config | caps how old a fetched `/channels` pointer the consumer will *act on* |
| **Monotonic anti-rollback floor** | persisted consumer install state (§6.2) | refuses any candidate older than the highest semver ever run |

Enforcement:

- **Channel freshness** comes from the **low CDN TTL** on `/channels/**` (and
  `info/refs`, `objects/info`) plus the **consumer's own max-staleness policy**:
  a consumer that fetches a partition pointer older than its policy allows treats
  the rollout pointer as **stale** and does **not** advance to a new frontier (it
  may keep running its current pinned release). A live publisher re-signs and
  re-publishes partition tags on each rollout step, so a healthy fleet always
  fetches a fresh pointer through the low-TTL edge; a *stuck/abandoned* channel
  simply stops producing new pointers and the consumer holds.
- **Release immutability** needs no freshness signal: an immutable, long-cached
  release stays installable indefinitely. Trust in a release derives from its
  signature against a currently-trusted Ed25519 key (the trust roster and its
  rotation/revocation are handled via `keys.toml` + `trusted-keys.d` TOFU, §7.5
  / §8), not from an expiry stamp.

> **Trade-off (brief §11).** Without an in-band signed expiry, this freshness
> model is **weaker against a frozen-but-validly-signed mirror**: a mirror that
> serves a stale-but-genuinely-signed `/channels` pointer past its CDN TTL is
> only caught by the consumer's max-staleness policy and the monotonic floor,
> not by a signed `valid_until` the mirror cannot forge. The floor still blocks
> any *rollback*; the residual exposure is a mirror **pinning** a fleet to an old
> (but legitimately-signed and floor-passing) release.

---

## 6. Anti-rollback & fix-forward (G7)

Two layers, both required:

### 6.1 Commit-ancestry (have today)

`check_downgrade` (`security.rs:256-296`) classifies a commit transition via
`git merge-base --is-ancestor`. Reused unchanged to catch a `Downgrade` /
`Diverged` *commit* relationship once the chain has resolved to a commit.

### 6.2 Semver monotonic floor (TARGET, new)

A consumer persists a **monotonic floor**: the highest semver it has ever
successfully run. On every update it refuses to move to a release **older** than
its floor, even if a partition legitimately points there (brief §6).

```
                resolve bucket → partition tag → semver tag → candidate release
                                                                     │
              floor = highest semver ever run ────────────┐          │
                                                          ▼          ▼
                          candidate <  floor   →  REFUSE (anti-rollback)
                          candidate == floor    →  no-op
                          candidate >  floor    →  verify chain, advance, raise floor
```

- Floor uses **semver precedence** (brief §7), not commit ancestry, so it is
  robust across the delta graph and to a re-pointed partition.
- It composes with §6.1: a candidate must clear **both** the semver floor **and**
  the commit-ancestry check before install.

Implementation. The floor is a `semver::Version` persisted in registry install
state (`crates/aos-package/src/registry/state.rs`, alongside the existing token
state — coordinate location with [workstream-05](./workstream-05-consumer.md)).
The check is a new free function next to `check_monotonic` (`state.rs:104`, which
guards a `u64` token monotonically):

```rust
// crates/aos-package/src/registry/state.rs
use semver::Version;

/// Refuse a candidate older than the persisted floor. Mirrors the shape of
/// `check_monotonic` (state.rs:104) but over semver precedence, not the u64 token.
pub fn check_semver_floor(floor: &Version, candidate: &Version) -> Result<FloorDecision>;

pub enum FloorDecision { Refuse, NoOp, Advance }  // candidate < / == / > floor

/// Raise the persisted floor to `candidate` after a verified advance.
/// `RegistryState` (`types.rs:252`) gains an optional `semver_floor` field,
/// persisted by `save_state` (`state.rs:37`) and read by `load_state`
/// (`state.rs:21`).
pub fn raise_floor(state: &mut RegistryState, candidate: &Version);
```

`check_semver_floor` is **distinct** from `check_monotonic` (`state.rs:104`):
the token guard stays for the rollout-token monotonicity it already enforces
(called from `update.rs:292`), and the semver floor is layered on top in the
`verify_and_select` walk (§8). Tests in `state.rs` beside the existing
`check_monotonic_*` (`state.rs:255-269`): `#[test] fn semver_floor_refuses_older()`,
`#[test] fn semver_floor_noop_on_equal()`, `#[test] fn semver_floor_advances_and_raises()`.

### 6.3 Fix-forward, never partition-decrement

Aborting a bad rollout is **fix-forward** (brief §6): publish a *newer* release
and point partitions at it. Decrementing a partition back to an older release is
pointless — the consumer's floor blocks it anyway. The trust layer therefore
**never** needs to support rollback-by-pointer; it only ever raises the floor.

---

## 7. Producer changes (`apr`)

### 7.1 `apr sign` → sign **tag objects** (G1, G8)

CURRENT `apr sign` amends and signs the *commit* (`registry_ops.rs:1758`, inside
`sign` at `registry_ops.rs:1747-1762`).
TARGET signs the **release tag** and the **256 channel partition tags** with
SSH/Ed25519. Each tag is a **pure signed pointer** — standard git tag fields
(object, type, name, tagger) + the signature + an optional freeform human
message, with **no** structured payload. The git mechanics:

```sh
# Release tag (HOP-2): annotated, SSH-signed, name == semver. -m is an
# optional freeform human note (or omit for no message body).
git -c gpg.format=ssh -c user.signingkey=<key> \
    tag -s 1.4.2 -m "release 1.4.2" <commit-sha256>

# Channel partition tag (HOP-1): name == channel; targets the semver tag.
# Done once per partition the rollout advances (see workstream-03).
git -c gpg.format=ssh -c user.signingkey=<key> \
    tag -s -f stable -m "stable → 1.4.2" refs/tags/1.4.2
#   then publish that tag object's bytes to /channels/stable/<n>
```

- The signing key is one of the registry's **active** Ed25519 keys from the
  `keys.toml` roster (§7.5; a single-key registry uses its sole key, brief §11);
  `apr sign`'s today-unused `_key: Option<&str>` arg (`registry_ops.rs:1750`)
  becomes live and is renamed `key`. Concretely, the rewrite lives in
  `crates/aos-package/src/registry_ops.rs` and threads the key through a new
  signing helper:

  ```rust
  // crates/aos-package/src/registry_ops.rs
  /// Sign a tag object with an SSH/Ed25519 key. `tag_name` is the embedded
  /// name (channel name for HOP-1, semver for HOP-2); `target` is the ref the
  /// tag points at (a commit-ish for the release tag, `refs/tags/<semver>` for
  /// a partition tag); `signing_key` is the path to the SSH private key.
  fn sign_tag(
      dir: &Path,
      tag_name: &str,
      target: &str,
      message: Option<&str>,
      signing_key: &Path,
      force: bool,
  ) -> Result<()>;
  ```

  It shells out via the existing `git` helper (`registry_ops.rs:~70`) with
  `-c gpg.format=ssh -c user.signingkey=<signing_key>` and `tag -s` (plus `-f`
  when `force`). `apr sign` (`sign`, `registry_ops.rs:1747`) resolves the active
  key from `keys.toml` (§7.5) and calls `sign_tag` instead of
  `git commit --amend -S`.
- The tag carries **no structured payload** (optional freeform note only). The
  cache/substituter location lives in the committed repo-root `registry.toml`
  `[[caches]]` (authenticated transitively by the signed tag), with the consumer's
  client-side `registries.d` as an optional override (or the origin itself; §7.4) —
  never advertised in the signed tag itself.
- The publish step copies the signed tag *object bytes* to the 256
  `/channels/<name>/<n>` paths — the rollout coordinate is the path, the embedded
  name stays the channel name (§3.3).

### 7.2 `apr tag` → sign (G8)

CURRENT `apr tag` (`tag`, `registry_ops.rs:1684-1702`) writes an annotated tag
with a free-form `-m` message only when `--message` is given (`registry_ops.rs:1694-1698`,
otherwise a lightweight `git tag <name>`), and never signs (the `_key` arg,
`registry_ops.rs:1688`, is dead). TARGET routes tag creation through the §7.1
`sign_tag` path: `tag`'s `_key` becomes live, and the `Some(msg) => git tag -a`
/ `None => git tag` branch is replaced by a single `sign_tag(&dir, name, "HEAD",
message, &key, /*force=*/false)` call. The message stays an **optional freeform
human note** — no generated structured payload.

### 7.3 Drop `apr bundle` from the trust surface

`apr bundle` (`bundle`, `registry_ops.rs:1706-1744`) produces git **bundles**,
which are **removed** from the target (brief §15). Bundles carry their own
refs/prereqs and have no place in the signed-tag trust chain; trust derives from
tag objects, not bundle headers. Removing it also retires the `pick_bundles`
delta selector in `update.rs` (`pick_bundles`, `update.rs:319`; called at
`update.rs:224`) and its `pick_bundles_*` tests (`update.rs:655-769`) — tracked
in [workstream-02](./workstream-02-pack-delta-pipeline.md).

### 7.4 Cache config lives in the committed `registry.toml`, not tag-embedded

The Nix binary-cache / NAR substituter location is **not** advertised in signed
tags. It lives in the committed repo-root `registry.toml` `[[caches]]` (a tree
file authenticated transitively by the signed tag), with the consumer's
client-side `registries.d` as an optional override (or the **origin itself**).
The origin **MAY** serve the stock-nix
superset — `nix-cache-info`, `<storehash>.narinfo`, and `nar/` — and narinfo
signing **reuses** a registry signing key (a separate signature object; brief
§11/§13). The producer never embeds a `[[caches]]` table or any substituter URL
inside a tag.

### 7.5 Trust roster lives in `keys.toml`, not in `registry.toml` (G9)

The committed tree carries a dedicated **`keys.toml`** — the **trust roster**:
the **active signing key(s)** plus a **revoked** list (brief §14). It is a
committed tree file, authenticated transitively by the signed tag
(tag → commit → tree → file), and is distinct from the HTTP-served object store —
see the layout reference
[`repo-layout.md`](../../registry/repo-layout.md) §3 for the on-disk shape.

```toml
schema = 1

[[keys]]                       # currently-active signing key(s) — no role field
id   = "aos-core-2026"
key  = "aos-core:Ed25519:<base64>"   # the parse_signing_key wire format
[[keys]]                       # overlap: a second active key vouches for the first
id   = "aos-core-2026b"
key  = "aos-core:Ed25519:<base64>"

[[revoked]]                    # keys no longer trusted (planned retirement)
id     = "aos-core-2025"
reason = "rotated"
```

Producer-side implementation:

- **Emit `keys.toml`** at registry create / key-management time, writing it into
  the committed tree next to `registry.toml` (the same write site as the default
  `registry.toml` write in `create`, `registry_ops.rs:443-450`, immediately
  before the initial `git add -A`/`commit` at `registry_ops.rs:453-454`). The
  roster lives in a new module `crates/aos-package/src/registry/keys.rs` with
  serde types mirroring the roster shape:

  ```rust
  // crates/aos-package/src/registry/keys.rs  (new)
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct KeysToml {
      pub schema: u32,                       // = 1
      #[serde(default)]
      pub keys: Vec<RosterKey>,              // active signing key(s)
      #[serde(default)]
      pub revoked: Vec<RevokedKey>,
  }
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct RosterKey {
      pub id: String,
      pub key: String,                       // parse_signing_key wire format
  }
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct RevokedKey {
      pub id: String,
      #[serde(default)]
      pub reason: Option<String>,
  }

  pub fn read_keys_toml(dir: &Path) -> Result<Option<KeysToml>>;   // None if absent
  pub fn write_keys_toml(dir: &Path, roster: &KeysToml) -> Result<()>;
  ```

  Each `RosterKey.key` is validated through the existing
  `parse_signing_key` (`security.rs:306`), so a malformed roster entry is
  rejected at read time. The roster lists **active signing key(s)** with no role
  field; the model is **≥2 overlapping active keys** so a survivor can disown a
  retired key (brief §14). The git lineage (signed tag → commit → parent chain)
  supplies continuity, so there is no separate offline-root tier. Tests:
  `#[test] fn keys_toml_roundtrip()` (write → read → assert two `[[keys]]` + one
  `[[revoked]]`), `#[test] fn keys_toml_rejects_bad_key_format()` (a `key` that
  fails `parse_signing_key` errors), `#[test] fn keys_toml_absent_returns_none()`.
- **Remove the `signing` field and `RegistrySigningConfig` from the
  `registry.toml` types.** CURRENT `RegistryRootConfig` (`types.rs:564-570`)
  carries `signing: Option<RegistrySigningConfig>` (`types.rs:569`), and
  `RegistrySigningConfig` (`types.rs:594-595`) is just `pub public_key: String`
  — the `[registry.signing] public_key = "registry:Ed25519:..."` pubkey. The
  TARGET **drops** both the field and the struct (a key inside a file
  authenticated *by* that key is circular for bootstrap, brief §14):

  - delete the `signing` field from `RegistryRootConfig` (`types.rs:569`) and the
    `RegistrySigningConfig` struct (`types.rs:593-596`);
  - the default-`registry.toml` writer (`create`, `registry_ops.rs:443-450`)
    already emits only `[registry]` name/description — no change beyond not
    re-adding a `[registry.signing]` block;
  - the reader `read_registry_toml` (`registry_ops.rs:392-402`) deserializes
    `RegistryRootConfig` via `toml::from_str` (`registry_ops.rs:399`); once the
    field is gone, a stale `[registry.signing]` block in an old tree is ignored
    rather than parsed.

  Note this `RegistrySigningConfig` (the in-repo `registry.toml` struct) is
  **distinct** from the client-side `SigningConfig` (`types.rs:242-248`,
  `RegistryFile.registry.signing`, exercised by `parse_registry_file_toml` at
  `types.rs:770-789`) — that client-side `registries.d/<name>.toml` signing block
  is a separate, out-of-tree override and is **not** removed here. No existing
  test covers `RegistryRootConfig`/`RegistrySigningConfig`, so deletion breaks no
  test; a new `#[test] fn registry_root_config_has_no_signing_field()` should
  assert a `[registry.signing]` block in an in-repo `registry.toml` is ignored.
  Key trust now comes from `keys.toml` + client-side TOFU (§8.2). The
  git-repo-root `registry.toml` retains only `[registry]` name/description +
  `[[caches]]`.

### 7.6 Rotation & revocation (producer side)

- **Rotation** — publish `keys.toml` listing **both** the old and the new key (an
  overlap window) inside a tag signed by the **currently-trusted** key. A
  consumer that already trusts the old key verifies the tag, parses `keys.toml`,
  and pins the new key; a later publish drops the old key (§8.3).
- **Planned retirement** — list the retired key under `[[revoked]]` in a
  `keys.toml` **signed by one of the *other* overlapping active keys** — never by
  the key being retired. This is the **≥2 overlapping active keys** model (brief
  §14): a survivor disowns the retired key, and the git lineage gives continuity
  so no offline-root tier is needed.
- **Compromise** — handled **out-of-band**: the consumer re-pins via
  `trusted-keys.d` (`apr trust`). An in-repo key cannot credibly revoke itself,
  and compromise is rare enough that the out-of-band re-pin is the accepted
  fallback (brief §14).

---

## 8. Consumer verification — algorithm

This is the gate [workstream-05](./workstream-05-consumer.md) calls after
selecting a bucket. Inputs: `channel`, `bucket ∈ 00..ff`, the registry's trusted
key (via `KeyStore::lookup`, TOFU on first use), and the persisted semver floor.

```
verify_and_select(channel, bucket):
  key = KeyStore.lookup(channel-registry)        # security.rs:70  (TOFU if absent)
  ptag = fetch("/channels/{channel}/{bucket}")    # probe-forward (bucket+1)%256 if missing
  # --- HOP 1: channel partition tag ---
  assert verify_tag_signature(ptag, key)         # retargeted security.rs:199
  assert tag_name(ptag) == channel               # NAME-BINDING (brief §5)
  assert ptag.type == "tag"
  semver = ptag.target                           # refs/tags/<semver>
  assert ptag_age <= consumer.max_staleness      # channel FRESHNESS (else: stale → hold)
  # --- HOP 2: release tag ---
  rtag = fetch_tag(semver)
  assert verify_tag_signature(rtag, key)
  assert tag_name(rtag) == semver                # NAME-BINDING
  assert rtag.type == "commit"
  commit = rtag.target
  # --- anti-rollback ---
  assert semver >= floor                         # SEMVER FLOOR  (brief §6)
  assert check_downgrade(current_commit, commit) in {FastForward, SameCommit}  # security.rs:256
  # commit is now trusted; hand to delta/object resolution (ws-02/05)
  raise_floor(semver)
```

Concrete implementation. The chain walk and its primitives land in a new module
`crates/aos-package/src/registry/verify.rs`, reusing `security.rs` where noted:

```rust
// crates/aos-package/src/registry/verify.rs  (new)
use semver::Version;
use std::path::Path;
use anyhow::Result;

/// Parsed fields of a git tag object (read via `git cat-file tag <oid>`).
pub struct TagObject {
    pub name: String,            // the `tag <name>` header  (NAME-BINDING source)
    pub object: String,          // target oid (sha256)
    pub target_type: TagTarget,  // `type tag` (HOP-1) | `type commit` (HOP-2)
    pub tagger_when: i64,        // tagger unix time  (freshness source)
}
pub enum TagTarget { Tag, Commit }

/// Read a tag object's fields. Shells `git cat-file tag <oid>`.
pub fn read_tag_object(repo: &Path, oid: &str) -> Result<TagObject>;

/// Verify a tag object's SSH/Ed25519 signature. Retargets
/// `verify_commit_signature` (`security.rs:199`) to `git verify-tag`:
/// builds the same temp `allowed_signers` file from `expected_key`, then runs
/// `git -c gpg.ssh.allowedSignersFile=… verify-tag <oid>`.
pub fn verify_tag_signature(repo: &Path, oid: &str, expected_key: &str) -> Result<bool>;

/// HOP-1 → HOP-2 → commit walk (the pseudocode above). `floor` is the
/// persisted monotonic semver floor (§6.2).
pub fn verify_and_select(
    repo: &Path,
    channel: &str,
    bucket: u8,
    expected_key: &str,
    current_commit: &str,
    floor: &Version,
    max_staleness: std::time::Duration,
) -> Result<VerifiedRelease>;

pub struct VerifiedRelease {
    pub semver: Version,         // parsed via semver::Version::parse
    pub commit: String,          // trusted commit oid (sha256)
}
```

- **`verify_tag_signature`** is the §2.1 `verify_commit_signature`
  (`security.rs:199-233`) with `verify-commit` → `verify-tag`; the
  `allowed_signers` builder, temp-file handling, and `parse_signing_key` call
  (`security.rs:204`) are unchanged. It can be added beside it in `security.rs`
  and re-exported, or moved wholesale into `verify.rs`.
- **Name-binding** is `tag_object.name == expected` (channel name for HOP-1,
  the `semver.to_string()` for HOP-2) — a plain string compare on the
  `read_tag_object` `name` field, no new type.
- **Semver compare** uses `semver::Version` ordering directly (`semver >= floor`);
  the candidate semver comes from `Version::parse(&ptag.target_semver)`, mirroring
  `parse_tag_as_semver` (`update.rs:456-477`). The types `Semver`/`FromSemver` do
  **not** exist and are not introduced.
- **`check_downgrade`** (`security.rs:256`, returning `DowngradeStatus`) is called
  unchanged; the walk accepts only `FastForward | SameCommit`.

Named tests in `verify.rs`: `#[test] fn verify_and_select_accepts_signed_chain()`,
`#[test] fn name_binding_rejects_cross_served_partition()` (a valid `stable`
partition tag served at `testing` fails, §3.3), `#[test] fn hop_type_mismatch_rejected()`
(HOP-1 pointing at a commit instead of a tag fails), `#[test] fn semver_floor_refuses_older_candidate()`,
`#[test] fn stale_pointer_holds_not_errors()`.

Any failed `assert` aborts the update and **leaves the current release in
place** — never a partial or unverified install. A *stale* channel pointer (§5)
is not an error: the consumer holds on its current pinned release.

> **No-key case.** On first contact the `KeyStore` has no `<registry>.pub`;
> `tofu_check` (`security.rs:159`) returns `NewKey { needs_confirmation }`, the
> caller prompts, and on accept the key is persisted via `KeyStore::store`
> (`security.rs:97`). A later `KeyMismatch` (key rotated without provisioning)
> hard-fails verification — fix-forward is to provision the new key in
> `trusted-keys.d`.

### 8.1 Parse `keys.toml` from the verified tree

After the chain resolves to a commit (§8), the consumer reconstructs the tree and
reads **`keys.toml`** via `read_keys_toml` (§7.5, `registry/keys.rs`) — sourcing
the file bytes with `git -C <repo> show <commit>:keys.toml` (or a checked-out
working tree). It parses `[[keys]]` into `KeysToml.keys` (each `RosterKey { id,
key }`, the `key` validated through `parse_signing_key`'s
`registry:Ed25519:base64` form, `security.rs:306`) and `[[revoked]]` into
`KeysToml.revoked`. Because the tree is authenticated transitively by the signed
tag (tag → commit → tree → file, brief §14), `keys.toml` needs **no** standalone
signature object. Its shape is the
[`repo-layout.md`](../../registry/repo-layout.md) §3 roster.

### 8.2 TOFU bootstrap is unchanged — `keys.toml` does **not** bootstrap trust

Initial trust is still **TOFU-pinned client-side** in
`trusted-keys.d/<registry>.pub` (`KeyStore`, `security.rs:52-131`;
`tofu_check`, `security.rs:159`) — the existing primitives reused as-is (§2.1).
`keys.toml` is read **only after** a tag has already verified against a
TOFU-pinned key; it can never be the *first* source of trust, since a key inside a
tag-authenticated file is circular for bootstrap (brief §14). The no-key and
`KeyMismatch` flows above are unaffected.

### 8.3 Verify rotation / revocation

Once `keys.toml` is parsed from a tag verified against a currently-trusted key:

- **Rotation** — the verified roster lists old + new keys (overlap). The consumer
  **pins the new key** (persist alongside / into `trusted-keys.d` via
  `KeyStore::store`, `security.rs:97`), so a subsequent tag signed by only the new
  key still verifies. No `KeyMismatch` prompt is needed when the new key arrives
  inside a roster signed by the trusted old key.
- **Planned retirement** — a `[[revoked]]` entry is honoured **only when** the
  `keys.toml` carrying it verified against a trusted key that is itself **not** the
  revoked one — i.e. one of the **≥2 overlapping active keys**. The consumer then
  refuses any tag signed by a retired key. A `[[revoked]]` entry that could only
  be vouched for by the revoked key itself is **not** trusted.
- **Compromise** — an in-repo `[[revoked]]` entry cannot self-revoke a single
  compromised key, so compromise is handled **out-of-band**: the consumer re-pins
  the replacement key via `trusted-keys.d` (`apr trust`). This is the accepted
  fallback (brief §14), not an open question.

Implementation. Rotation/revocation lives in `registry/keys.rs` (§7.5) and
operates on the `KeysToml` parsed in §8.1, given the `id`/key the roster itself
verified against (`vouching_key`):

```rust
// crates/aos-package/src/registry/keys.rs
/// Pin every active `[[keys]]` entry into the writable trusted-keys dir via
/// KeyStore::store (security.rs:97), so a later tag signed by any of them
/// verifies without a KeyMismatch prompt.
pub fn pin_rotated_keys(store: &KeyStore, registry: &str, roster: &KeysToml) -> Result<()>;

/// A `[[revoked]]` entry is honoured only when the roster verified against a
/// key whose id is NOT in `revoked` — i.e. one of the ≥2 overlapping active
/// keys. Returns the set of revoked key ids the consumer must refuse.
pub fn effective_revocations(roster: &KeysToml, vouching_key_id: &str) -> Vec<String>;
```

`pin_rotated_keys` reuses `KeyStore::store` (`security.rs:97`); the post-pin
verify path is unchanged `verify_tag_signature`. Tests in `keys.rs`:
`#[test] fn rotation_pins_new_overlapping_key()`,
`#[test] fn revocation_honoured_when_vouched_by_survivor()`,
`#[test] fn revocation_ignored_when_only_self_vouched()` (a `[[revoked]]` entry
whose roster verified against the revoked key itself yields an empty
`effective_revocations`).

> **Why the cache list is not the trust boundary.** An authenticated-but-wrong
> `[[caches]]` pointer (from either `registry.toml` or client-side
> `registries.d/<name>.toml`) cannot serve bad bytes: NARs are content-addressed
> and SHA-256-verified on download in `download_one` — the narinfo `FileHash`
> drives `TransferRequest::get(&url).with_hash(HashAlgorithm::Sha256, expected_hex)`
> (`download.rs:199-204`), so a tampered NAR fails the hash check. (The earlier
> `fetch_narinfos`/`fetch_one_narinfo` at `download.rs:107-170` only fetches and
> parses the narinfo; the content-hash gate is the `with_hash` call in the
> download path.) The trust that matters is the **tag/commit** chain governed by
> `keys.toml` — see [`repo-layout.md`](../../registry/repo-layout.md) §3.

---

## 9. Reused vs. new code

| Capability | Source | Status |
|---|---|---|
| `registry:Ed25519:base64` parse | `parse_signing_key` (`security.rs:306`) | **reuse as-is** |
| TOFU decision | `tofu_check` (`security.rs:159`) | **reuse as-is** |
| `trusted-keys.d/<registry>.pub` store | `KeyStore` (`security.rs:52-131`) | **reuse as-is** |
| key fingerprint | `key_fingerprint` (`security.rs:338`) | **reuse as-is** |
| commit-ancestry downgrade | `check_downgrade` (`security.rs:256`) | **reuse** (compose with semver floor) |
| `allowed_signers` + verify | `verify_commit_signature` (`security.rs:199`) | **retarget** to `verify-tag` / tag bytes |
| sign tags (not commit) | `apr sign` (`registry_ops.rs:1747`) | **rewrite** → `git tag -s` (pure signed pointer) |
| sign tag, freeform message | `apr tag` (`registry_ops.rs:1684`) | **rewrite** → sign; optional freeform note |
| name-binding (embedded tag-name) | — | **new** |
| `tag → tag → commit` walk | — | **new** |
| semver monotonic floor | — | **new** (persisted alongside install state) |
| freshness (CDN TTL + max-staleness policy) | — | **new** (no in-band `valid_until`) |
| bundle signing | `apr bundle` (`registry_ops.rs:1706`) | **remove** (bundles dropped, brief §15) |
| emit/parse `keys.toml` roster | — | **new** `KeysToml` / `read_keys_toml` / `write_keys_toml` in `registry/keys.rs` (active keys + revoked; tree file, brief §14) |
| `signing.public_key` in `registry.toml` | `RegistrySigningConfig.public_key` (`types.rs:594-595`), the `signing` field of `RegistryRootConfig` (`types.rs:564-570`) | **remove** field + struct (key trust → `keys.toml` + TOFU) |
| rotation/revocation verify | — | **new** (≥2 overlapping active keys; §8.3) |

---

## 10. Tasks / sequencing

1. **sha256 repo** (G5) — `git init --object-format=sha256` at registry
   create (`create`, `registry_ops.rs:421`; the bare `git(&dir, &["init"])` is
   at `registry_ops.rs:438`). Coordinated with
   [workstream-01](./workstream-01-object-store.md).
2. **Pure signed tags** (G8) — tags carry no structured payload; the message is
   an optional freeform human note only. No TOML schema to generate or parse.
3. **Sign tag objects** (G1) — rewrite `apr sign`/`apr tag` to
   `git -c gpg.format=ssh tag -s`; activate the `_key` arg.
4. **Tag verification** (G2) — retarget `verify_commit_signature` to `verify-tag`
   / raw tag-object bytes; read the embedded tag-name and target.
5. **Name-binding** (G3) — assert embedded tag-name == expected serving-path name
   (channel name | semver) at both hops.
6. **Chain walk** (G4) — `verify_and_select` (§8): HOP-1 partition → HOP-2 semver
   → commit, signature + name + type/target at each hop.
7. **Freshness** (G6) — enforce channel freshness from low CDN TTL + the
   consumer's max-staleness policy; no in-band `valid_until`.
8. **Semver floor + fix-forward** (G7) — persist the monotonic floor, refuse
   `candidate < floor`, compose with `check_downgrade`; never decrement
   partitions.
9. **Remove `apr bundle`** from the trust path (brief §15).
10. **`keys.toml` roster** (G9) — emit `keys.toml` (active keys + revoked) into
    the committed tree at create/key-management (`registry/keys.rs`,
    `write_keys_toml`, written at the `create` write site `registry_ops.rs:443-450`);
    **remove the `signing` field of `RegistryRootConfig` (`types.rs:569`) and the
    `RegistrySigningConfig` struct (`types.rs:593-596`)**, leaving the default
    writer (`registry_ops.rs:443-450`) and reader (`read_registry_toml`,
    `registry_ops.rs:392-402`) emitting/parsing only `[registry]` + `[[caches]]`;
    parse `keys.toml` from the verified tree (§8.1). TOFU bootstrap
    (`trusted-keys.d`) is **unchanged** (§8.2).
11. **Rotation/revocation verify** (G9) — pin a rotated key from an
    overlap-window roster signed by the trusted key; honour `[[revoked]]` only
    when the roster verified against a non-revoked **overlapping active** key;
    compromise falls back to out-of-band `apr trust` re-pin (§8.3).

Dependency order: 1 → (2,3) → 4 → 5 → 6 → (7,8); 9 any time; 10 → 11
(10 depends on 4–6 for the verified tree it reads).

---

## 11. Risks / open questions

- **sha256 client support** over dumb HTTP (no negotiation) —
  [open-questions.md](./open-questions.md) #1.
- **Frozen-but-validly-signed mirror** exposure — without in-band signed expiry,
  a mirror can pin a fleet to an old (legitimately-signed, floor-passing) release
  past its CDN TTL; only the consumer's max-staleness policy and the monotonic
  floor mitigate this (§5). Key-rotation cadence — open-questions #5.
- **Key rotation UX:** the planned path is an overlap-window `keys.toml` roster
  signed by the trusted key (§7.6/§8.3) so a rotated key arrives pre-vouched
  rather than as a bare `tofu_check` → `KeyMismatch` (`security.rs:182`). The
  trust model is **decided**: **≥2 overlapping active keys** (no offline-root
  tier — git lineage gives continuity), with an explicit out-of-band `apr trust`
  re-pin as the **compromise** fallback (brief §14). The one remaining open point
  is cosmetic — standalone `keys.toml` vs a `[keys]` block in `registry.toml`
  (leaning standalone; brief §16.8).
- **Floor persistence location** and per-channel vs. global scope — coordinate
  with [workstream-05](./workstream-05-consumer.md) install state.
- **Narinfo `Sig:` reuse:** if the origin also serves NARs
  ([nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md)), the
  same Ed25519 signing key (from the `keys.toml` roster) signs narinfos as a
  separate signature object (brief §11/§13).

---

## See also

- Brief: [design-brief.md](./design-brief.md) §11 (signing & trust), §5 (ref model / name-binding), §14 (repo-tree config & trust files — decided: ≥2 overlapping active keys), §15 (removed), §16.8 (decided trust model)
- Plan: [README.md](./README.md) · [gap-analysis.md](./gap-analysis.md) ·
  [workstream-01-object-store.md](./workstream-01-object-store.md) ·
  [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md) ·
  [workstream-03-channels-rollouts.md](./workstream-03-channels-rollouts.md) ·
  [workstream-05-consumer.md](./workstream-05-consumer.md) ·
  [open-questions.md](./open-questions.md)
- Reference: [signing-and-trust.md](../../registry/signing-and-trust.md) ·
  [repo-layout.md](../../registry/repo-layout.md) (committed-tree placement of `registry.toml` / `keys.toml`) ·
  [versioning-and-channels.md](../../registry/versioning-and-channels.md) ·
  [http-layout.md](../../registry/http-layout.md) ·
  [architecture.md](../../registry/architecture.md) ·
  [current-state.md](../../registry/current-state.md) ·
  [packs-and-deltas.md](../../registry/packs-and-deltas.md) ·
  [publishing.md](../../registry/publishing.md) ·
  [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) ·
  [apt-comparison.md](../../registry/apt-comparison.md)
