# Workstream 04 — Signing & Trust

> **Plan doc.** Implements the signing and trust layer of the git-native AOS
> registry: **signed tag objects** (SSH-format Ed25519, a pure signed pointer
> with no structured payload), **name-binding verification**, the
> **`tag → tag → commit`** trust chain, **sha256** object format, **freshness**
> via CDN TTL + consumer policy + monotonic floor, and
> **anti-rollback / fix-forward**. Grounded in §11 and §5 of the
> [design brief](./design-brief.md); reuses the existing TOFU +
> `trusted-keys.d` primitives.
>
> **Labeling:** **CURRENT** describes today's code (cited as `path:line`);
> **TARGET** describes the git-native model this workstream builds.

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
- **Producer signing.** `apr sign` (`registry_ops.rs:1759-1774`) is
  `git commit --amend --no-edit -S` — it signs the *commit*, not a tag.
  `apr tag` (`registry_ops.rs:1696-1714`) creates an annotated tag with
  `git tag -a <name> -m <msg>` **only when `--message` is given**, otherwise a
  lightweight `git tag <name>` — and in neither case does it **sign** (the
  `_key` arg is unused). When a message is present it is free-form, which the
  TARGET keeps: a signed tag's message stays an optional freeform human note.

### 2.2 Gaps vs. TARGET

| # | Gap | CURRENT | TARGET |
|---|---|---|---|
| G1 | Sign **tag objects**, not commits | `apr sign` = `commit --amend -S` (`registry_ops.rs:1770`) | `git tag -s` on partition + release tags |
| G2 | **Verify tags** | only `verify-commit` (`security.rs:217-226`) | `verify-tag` + read tag object |
| G3 | **Name-binding** | none | embedded tag-name field == serving path name |
| G4 | **`tag → tag → commit`** chain | none | partition tag → semver tag → commit, each checked |
| G5 | **sha256** objects | repo is sha1 today | `git init --object-format=sha256` |
| G6 | **Freshness** enforcement | none | CDN TTL + consumer max-staleness policy + monotonic floor (no in-band expiry) |
| G7 | **Anti-rollback floor** | commit-ancestry only (`check_downgrade`) | persisted semver monotonic floor + fix-forward |
| G8 | Tags are **pure signed pointers** | unsigned, free-form message | `git tag -s`, no structured payload (optional freeform note only) |

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
  signature against a currently-trusted Ed25519 key (key rotation is handled via
  `trusted-keys.d`, §8), not from an expiry stamp.

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

### 6.3 Fix-forward, never partition-decrement

Aborting a bad rollout is **fix-forward** (brief §6): publish a *newer* release
and point partitions at it. Decrementing a partition back to an older release is
pointless — the consumer's floor blocks it anyway. The trust layer therefore
**never** needs to support rollback-by-pointer; it only ever raises the floor.

---

## 7. Producer changes (`apr`)

### 7.1 `apr sign` → sign **tag objects** (G1, G8)

CURRENT `apr sign` amends and signs the *commit* (`registry_ops.rs:1770`).
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

- The signing key is the registry's existing Ed25519 key (one key, brief §11);
  `apr sign`'s today-unused `_key` arg (`registry_ops.rs:1761`) becomes live.
- The tag carries **no structured payload** (optional freeform note only). The
  cache/substituter location is **client-side** consumer config or the origin
  itself (§7.4), never advertised in a signed tag.
- The publish step copies the signed tag *object bytes* to the 256
  `/channels/<name>/<n>` paths — the rollout coordinate is the path, the embedded
  name stays the channel name (§3.3).

### 7.2 `apr tag` → sign (G8)

CURRENT `apr tag` (`registry_ops.rs:1696-1714`) writes an annotated tag with a
free-form `-m` message only when `--message` is given (otherwise a lightweight
`git tag <name>`), and never signs. TARGET routes tag creation through the §7.1
signing path. The message stays an **optional freeform human note** — no
generated structured payload.

### 7.3 Drop `apr bundle` from the trust surface

`apr bundle` (`registry_ops.rs:1716-1756`) produces git **bundles**, which are
**removed** from the target (brief §15). Bundles carry their own refs/prereqs and
have no place in the signed-tag trust chain; trust derives from tag objects, not
bundle headers.

### 7.4 Cache config is client-side, not tag-embedded

The Nix binary-cache / NAR substituter location is **not** advertised in signed
tags. It is the **consumer's client-side configuration** (its local registry
config) or the **origin itself**. The origin **MAY** serve the stock-nix
superset — `nix-cache-info`, `<storehash>.narinfo`, and `nar/` — and narinfo
signing **reuses the one Ed25519 key** (a separate signature object; brief
§11/§13). The producer never embeds a `[[caches]]` table or any substituter URL
inside a tag.

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

Any failed `assert` aborts the update and **leaves the current release in
place** — never a partial or unverified install. A *stale* channel pointer (§5)
is not an error: the consumer holds on its current pinned release.

> **No-key case.** On first contact the `KeyStore` has no `<registry>.pub`;
> `tofu_check` (`security.rs:159`) returns `NewKey { needs_confirmation }`, the
> caller prompts, and on accept the key is persisted via `KeyStore::store`
> (`security.rs:97`). A later `KeyMismatch` (key rotated without provisioning)
> hard-fails verification — fix-forward is to provision the new key in
> `trusted-keys.d`.

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
| sign tags (not commit) | `apr sign` (`registry_ops.rs:1759`) | **rewrite** → `git tag -s` (pure signed pointer) |
| sign tag, freeform message | `apr tag` (`registry_ops.rs:1696`) | **rewrite** → sign; optional freeform note |
| name-binding (embedded tag-name) | — | **new** |
| `tag → tag → commit` walk | — | **new** |
| semver monotonic floor | — | **new** (persisted alongside install state) |
| freshness (CDN TTL + max-staleness policy) | — | **new** (no in-band `valid_until`) |
| bundle signing | `apr bundle` (`registry_ops.rs:1716`) | **remove** (bundles dropped, brief §15) |

---

## 10. Tasks / sequencing

1. **sha256 repo** (G5) — `git init --object-format=sha256` at registry
   create (`create`, `registry_ops.rs:421`). Coordinated with
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

Dependency order: 1 → (2,3) → 4 → 5 → 6 → (7,8); 9 any time.

---

## 11. Risks / open questions

- **sha256 client support** over dumb HTTP (no negotiation) —
  [open-questions.md](./open-questions.md) #1.
- **Frozen-but-validly-signed mirror** exposure — without in-band signed expiry,
  a mirror can pin a fleet to an old (legitimately-signed, floor-passing) release
  past its CDN TTL; only the consumer's max-staleness policy and the monotonic
  floor mitigate this (§5). Key-rotation cadence — open-questions #5.
- **Key rotation UX:** a rotated key surfaces as `tofu_check` → `KeyMismatch`
  (`security.rs:182`); decide between pre-provisioning into `trusted-keys.d` vs.
  an explicit `apr trust` re-pin flow.
- **Floor persistence location** and per-channel vs. global scope — coordinate
  with [workstream-05](./workstream-05-consumer.md) install state.
- **Narinfo `Sig:` reuse:** if the origin also serves NARs
  ([nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md)), the
  same one Ed25519 key signs narinfos as a separate signature object (brief
  §11/§13).

---

## See also

- Brief: [design-brief.md](./design-brief.md) §11 (signing & trust), §5 (ref model / name-binding)
- Plan: [README.md](./README.md) · [gap-analysis.md](./gap-analysis.md) ·
  [workstream-01-object-store.md](./workstream-01-object-store.md) ·
  [workstream-02-pack-delta-pipeline.md](./workstream-02-pack-delta-pipeline.md) ·
  [workstream-03-channels-rollouts.md](./workstream-03-channels-rollouts.md) ·
  [workstream-05-consumer.md](./workstream-05-consumer.md) ·
  [open-questions.md](./open-questions.md)
- Reference: [signing-and-trust.md](../../registry/signing-and-trust.md) ·
  [versioning-and-channels.md](../../registry/versioning-and-channels.md) ·
  [http-layout.md](../../registry/http-layout.md) ·
  [architecture.md](../../registry/architecture.md) ·
  [current-state.md](../../registry/current-state.md) ·
  [packs-and-deltas.md](../../registry/packs-and-deltas.md) ·
  [publishing.md](../../registry/publishing.md) ·
  [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) ·
  [apt-comparison.md](../../registry/apt-comparison.md)
