# `registry.toml` — The Signed Registry Root

> **Audience:** users, implementers, architects, engineers.
> **Status of this document:** reference / **TARGET** schema, with the **CURRENT**
> on-disk schema clearly labelled and grounded in code.
> **Grounding:** design brief §4.3 (single signed root) and §4.5 (trust / threat
> model). See [`docs/plans/registry/design-brief.md`](../plans/registry/design-brief.md).

`registry.toml` is the **single, inline-signed root** of an AOS package registry.
It is the one file a client is guaranteed to know the name of; everything else —
bundles, deltas, narinfos, NAR blobs — is discovered *through* it and referenced
**by content hash**. It is the AOS analogue of APT's `InRelease` file: a flat,
signed, dumb-HTTP-friendly index that pins every byte a client will subsequently
fetch.

Related reading:

- [`README.md`](./README.md) — registry overview and doc index.
- [`architecture.md`](./architecture.md) — the layered trust / metadata / blob model.
- [`current-state.md`](./current-state.md) — the as-is implementation and producer gaps.
- [`http-layout.md`](./http-layout.md) — wire layout, namespaces, object keys, by-hash.
- [`bundles-and-deltas.md`](./bundles-and-deltas.md) — bundle model, `creation_token`, delta selection.
- [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) — narinfo / `nix-cache-info` superset.
- [`signing-and-trust.md`](./signing-and-trust.md) — the one Ed25519 key, TOFU, threat model.
- [`publishing.md`](./publishing.md) — producer workflow, atomic root flip.
- [`versioning-and-channels.md`](./versioning-and-channels.md) — channels, rollouts, components.
- [`apt-comparison.md`](./apt-comparison.md) — why this shape is well-precedented.

---

## 1. Role in the system

```
                         the ONE file clients know by name
                                       │
                                       ▼
  apm / apr  ──fetch──►  {base}/registry.toml  (inline-signed)
                                       │
        ┌──────────────────────────────┼───────────────────────────────┐
        │ pubkey               [latest].head (authentic git commit SHA) │
        │ valid_until          [channels] → tags    [components]        │
        │ [[bundles]] table (snapshots + deltas), each pinned by sha256 │
        └──────────────────────────────┬───────────────────────────────┘
                                       │ by-hash references
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                         ▼
     bundles/<name>/*.bundle    nar/<hash>.nar.zst        *.narinfo (Nix)
     (git bundles of TOML)      (content-addressed blobs)  (strict superset)
```

The root provides four things a bare HTTP directory listing cannot:

1. **A freshness anchor** — `[latest]` carries the authentic git `head` commit, so
   a client can detect omission (a mirror hiding newer bundles) and **fail closed**
   instead of silently using stale data (brief §4.5, Omission).
2. **A freeze defense** — `valid_until` lets a client reject a validly-signed but
   stale root (brief §4.5, Freeze; §6 Tier 1).
3. **A torn-publish defense** — every bundle (snapshot or delta) is referenced **by-hash**, so a
   client that read `root@T` resolves a consistent set even if `root@T+1` lands
   mid-fetch (brief §4.3, §6 Tier 1 item 2).
4. **An atomic promotion point** — `[channels]` and `[latest]` are flipped in one
   signed file as the *last* publish step (brief §4.4).

---

## 2. CURRENT schema (as-is)

> **CURRENT.** This is what the code reads and writes today. It is a small subset
> of the TARGET below and contains **none** of the index, channel, rollout, or
> freshness machinery.

The deserialized type is `RegistryRootConfig` in
[`crates/aos-package/src/types.rs:566`](../../crates/aos-package/src/types.rs):

```rust
pub struct RegistryRootConfig {
    pub registry: RegistryRootMeta,         // name, description?      (types.rs:576)
    pub caches:   Vec<CacheEntry>,          // url, priority           (types.rs:584)
    pub signing:  Option<RegistrySigningConfig>, // public_key         (types.rs:596)
}
```

The file `apr` writes on `init`
([`registry_ops.rs:444`](../../crates/aos-package/src/registry_ops.rs)) is just:

```toml
[registry]
name = "aos-core"
description = ""
```

A fuller current-state example, with the optional sections populated by hand:

```toml
# CURRENT registry.toml — RegistryRootConfig (types.rs:566)

[registry]                         # RegistryRootMeta (types.rs:576)
name        = "aos-core"           # required
description = "ANDYL OS core packages"  # optional

[[caches]]                         # CacheEntry (types.rs:584); sorted by priority
url      = "https://cache.aos.dev"
priority = 10                      # default 100 (default_cache_priority, types.rs:591)

[[caches]]
url      = "https://mirror.example.net/aos"
priority = 50

[signing]                          # RegistrySigningConfig (types.rs:596)
public_key = "aos-core:Ed25519:MC4CAQAwBQYDK2VwBCIEI...base64..."
```

What the current schema **does not** have (the TARGET adds all of it):

| Capability                         | CURRENT | TARGET |
|------------------------------------|:-------:|:------:|
| `[registry]` name/description      | ✅      | ✅ (in `[meta]`) |
| `[[caches]]` mirror list + priority| ✅      | ✅ |
| `[signing].public_key`             | ✅      | ✅ (as `pubkey`) |
| `[meta].date` / `valid_until`      | ❌      | ✅ |
| `[meta].schema` version            | ❌      | ✅ |
| `[latest]` signed pointer          | ❌      | ✅ |
| `[channels]` + rollout             | ❌      | ✅ |
| `[components]`                     | ❌      | ✅ |
| `[capabilities]` flags             | ❌      | ✅ |
| `[[bundles]]` index (snapshots + deltas) | ❌ (lives in `bundle-list.toml`) | ✅ (moved in) |
| inline signature                   | ❌ (git commit signs the tree) | ✅ |

The bundle index today lives in a **separate** `bundle-list.toml`
(`BundleManifest`, `registry/bundle.rs`), which is **`Deserialize`-only** — there
is no writer. The TARGET collapses that file *into* `registry.toml` and makes the
root self-signing. See [`bundles-and-deltas.md`](./bundles-and-deltas.md) and
[`current-state.md`](./current-state.md) for the producer-gap detail.

---

## 3. TARGET schema (the signed root)

> **TARGET.** This is the design-brief §4.3 root. It is **not yet implemented**;
> the serializer, inline signing, and by-hash index are
> [workstream 01](../plans/registry/workstream-01-registry-root.md), channels/
> rollouts/freshness are
> [workstream 04](../plans/registry/workstream-04-channels-rollouts.md), and the
> consumer-side reader is
> [workstream 05](../plans/registry/workstream-05-consumer.md).

### 3.1 Table-by-table

| Table / key            | Type        | Purpose |
|------------------------|-------------|---------|
| `[meta].schema`        | int         | Schema version. Bump on incompatible change; enables graceful refusal. |
| `[meta].name`          | string      | Registry name (matches the on-disk registry name). |
| `[meta].date`          | RFC 3339    | When this root was signed. |
| `[meta].valid_until`   | RFC 3339    | **Freeze defense.** Client rejects an expired root (brief §4.5, §6 T1). |
| `pubkey`               | string      | Ed25519 public key; both publish encodings derivable (brief §4.2). |
| `[capabilities]`       | table/bools | Feature flags for forward-compat + graceful degradation (brief §6 T2 item 6). |
| `[latest]`             | table       | Signed freshness anchor: `tag`, `creation_token`, `head` (brief §4.3). |
| `[channels].<name>`    | table       | Symbolic alias → concrete `tag`, `creation_token`, optional `rollout` (brief §4.3, §6 T1 item 3–4). |
| `[components].<name>`  | table       | Optional intra-registry partition (trust/license/stability) (brief §6 T2). |
| `[[bundles]]`          | array-of-tbl| Unified bundle index (snapshots and deltas, `type`-distinguished), each pinned by `sha256` (by-hash). |
| `[[caches]]`           | array-of-tbl| NAR mirror list with `priority` (carried over from CURRENT). |
| `[signature]`          | table       | Inline Ed25519 signature over the canonical body (brief §4.3). |

### 3.2 `[latest]` — the freshness anchor

`[latest]` is the **explicit, signed** "what is newest" pointer. It replaces the
current consumer-side practice of *deriving* latest by scanning the manifest for
the maximum `creation_token` (brief §2.11, §4.4):

- `tag` — the calendar version tag, e.g. `v2026.05.3`.
- `creation_token` — the monotonic token for that tag (`year*1_000_000 + month*10_000 + patch`,
  patch ≤ 9999; the source doc-comment labels the positional mnemonic "YYYYMMPPP" but the
  patch field is 4 digits, so "YYYYMMPPPP (patch≤9999)"; see
  [`bundles-and-deltas.md`](./bundles-and-deltas.md) and `registry/state.rs`).
  Subject to `check_monotonic` anti-rollback on the consumer.
- `head` — the **authentic git commit SHA** the signed history resolves to. This is
  the anchor that makes omission attacks fail closed (brief §4.5).

### 3.3 `[channels]` + rollout

```toml
[channels.stable]
tag            = "v2026.05.3"
creation_token = 2026050003      # per-channel monotonic anti-rollback
rollout        = 100             # percent; omit or 100 = fully rolled out

[channels.testing]
tag            = "v2026.06.0"
creation_token = 2026060000
rollout        = 25              # phased: only ~25% of the fleet adopts (brief §6 T1 item 4)
```

Each `[channels].<name>` carries its own `creation_token`, giving every channel an
independent monotonic anti-rollback floor. A client that tracks `channel = "stable"`
resolves the channel's `tag` at update time; promotion is **one atomic signed flip**
of `[channels].stable.tag` (brief §4.4, §6 T1 item 3). `rollout = N` gates adoption on
`hash = sha256(machine_id : channel_name)` — keyed on the **channel name**, explicitly
**not** the target tag, so cohorts stay stable across promotions. A host in the held
(not-yet-rolled-out) cohort stays at its current `last_creation_token` (a no-op); there
is no `previous_tag` field. See
[`versioning-and-channels.md`](./versioning-and-channels.md).

### 3.4 `[[bundles]]` — the unified by-hash index

A **single** `[[bundles]]` array carries the bundle enumeration that the **CURRENT**
`bundle-list.toml` holds (`BundleEntryToml`: `uri`, `creation_token`, `sha256`, `size`,
`type`, `from_tag`, `to_tag` — `registry/bundle.rs`). There is **no separate
`[[deltas]]` array** — deltas are folded into `[[bundles]]` and distinguished by
`type = "delta"`. Moving the index into the signed root makes it **authenticated** and
**by-hash**: a client resolves bundles by their pinned `sha256`, so a torn publish never
yields an inconsistent set.

```toml
[[bundles]]                       # a full snapshot
uri    = "aos-core-v2026.05.3.bundle"   # object key under bundles/<name>/
type   = "snapshot"
tag    = "v2026.05.3"
creation_token = 2026050003
sha256 = "sha256:9f1c…"           # by-hash pin; download is verified against this
size   = 8123440

[[bundles]]                       # an incremental delta
uri    = "aos-core-v2026.05.0..v2026.05.3.bundle"
type   = "delta"
from_tag = "v2026.05.0"
to_tag   = "v2026.05.3"
creation_token = 2026050003
sha256 = "sha256:3ab0…"
size   = 41120
```

Per-entry fields:

- `uri` — the object key / filename (matches code field `BundleEntryToml.uri`).
- `type` — `"snapshot"` or `"delta"`. The finer skip-vs-sequential distinction for a
  delta is **derived** by `classify_delta(from_tag)` on the consumer (a `from` tag with
  ≤2 dotted parts ⇒ skip, else sequential; `registry/bundle.rs`) and is **not** a wire
  value.
- `tag` — present for snapshots (the target tag).
- `from_tag` / `to_tag` — present for deltas only.
- `creation_token` — the monotonic token (see §3.2).
- `sha256` — the by-hash pin; **always** carries an explicit algorithm prefix
  (`sha256:<hex>`). For **hash agility**, parsers must tolerate other prefixes for future
  migration — the algorithm is read from the prefix, never assumed. This applies to every
  hash in the root.
- `size` — byte length of the bundle object.

The `uri` filename grammar (snapshot vs delta object keys) is defined **authoritatively**
in [`http-layout.md` §4](./http-layout.md); this doc references it rather than restating
the variants. The literal filename is convention only — authority is by-hash (the
`sha256` above); do **not** embed the `sha256` in the key. The `pick_bundles` selection
that consumes this index is documented in
[`bundles-and-deltas.md`](./bundles-and-deltas.md).

### 3.5 `[signature]` — inline signing

The root is **inline-signed** so root + signature fetch atomically in one object
(no race between fetching the index and fetching its detached signature), exactly
like APT `InRelease`. The signature covers the canonical serialization of every
field above. The signing key is the **same** Ed25519 key that signs git commits
(brief §4.2); only the signed *message* differs. See
[`signing-and-trust.md`](./signing-and-trust.md) for canonicalization, the dual
key encodings, and how `apm` trust still roots transitively in the signed commit.

---

## 4. Full annotated TARGET example

```toml
# =====================================================================
# registry.toml — TARGET signed root (design brief §4.3 / §4.5)
# The ONE file clients fetch by name. Everything else is referenced
# from here BY HASH. This whole body is covered by [signature] below.
# =====================================================================

[meta]
schema      = 1                                  # schema version; bump on break
name        = "aos-core"                         # registry name
date        = "2026-06-03T17:04:00Z"             # when this root was signed
valid_until = "2026-06-10T17:04:00Z"             # FREEZE DEFENSE: reject if now > this

# Ed25519 public key. Both publish encodings derive from this one key
# (brief §4.2): "registry:Ed25519:<b64>" for apm TOFU, "<name>:<b64>"
# for Nix trusted-public-keys.
pubkey = "aos-core:Ed25519:MC4CAQAwBQYDK2VwBCIEIH7s…base64…"

[capabilities]                                   # forward-compat feature flags
by_hash       = true                             # index references are by-hash
channels      = true                             # [channels] present
rollouts      = true                             # rollout gating honored
nix_cache     = true                             # serves the Nix narinfo superset

# --- Freshness anchor: explicit, signed "newest". Replaces deriving
#     latest by scanning for max creation_token (brief §4.4). ---
[latest]
tag            = "v2026.05.3"
creation_token = 2026050003                      # year*1e6 + month*1e4 + patch (patch≤9999)
head           = "4f1a9c0b8e2d6a17c3f5b90d2e8a1f6c4b7d9e02"  # authentic git commit SHA

# --- Symbolic channels: promotion = one atomic signed flip of `tag`.
#     Each channel carries its own creation_token (anti-rollback floor).
#     `rollout` = phased adoption percentage (brief §6 T1 items 3–4). ---
[channels.stable]
tag            = "v2026.05.3"
creation_token = 2026050003
rollout        = 100

[channels.testing]
tag            = "v2026.06.0"
creation_token = 2026060000
rollout        = 25                              # only ~25% of fleet adopts

# --- Optional intra-registry partitions (APT main/contrib analogue). ---
[components.main]
description = "Fully-supported, freely-licensed packages"

[components.contrib]
description = "Community-maintained packages"

# --- NAR mirror list (carried from CURRENT [[caches]]). NAR blobs live
#     separately and are verified by content hash (see download.rs). ---
[[caches]]
url      = "https://cache.aos.dev"
priority = 10

[[caches]]
url      = "https://mirror.example.net/aos"
priority = 50

# --- Unified bundle index: snapshots AND deltas in ONE [[bundles]] array,
#     distinguished by `type`. Each pinned BY HASH (by-hash discipline).
#     `sha256` always carries an explicit "sha256:" algo prefix (hash agility:
#     parsers tolerate other prefixes). Filename grammar: http-layout.md §4. ---
[[bundles]]
uri    = "aos-core-v2026.05.3.bundle"            # object key: bundles/aos-core/<uri>
type   = "snapshot"
tag    = "v2026.05.3"
creation_token = 2026050003
sha256 = "sha256:9f1c4d…"                         # download verified against this
size   = 8123440

[[bundles]]
uri    = "aos-core-v2026.05.0.bundle"
type   = "snapshot"
tag    = "v2026.05.0"
creation_token = 2026050000
sha256 = "sha256:7be21a…"
size   = 8009122

[[bundles]]                                       # delta (skip is DERIVED via classify_delta)
uri    = "aos-core-v2026.05.0..v2026.05.3.bundle"
type   = "delta"
from_tag = "v2026.05.0"
to_tag   = "v2026.05.3"
creation_token = 2026050003
sha256 = "sha256:3ab0f1…"
size   = 41120

[[bundles]]                                       # delta (sequential is DERIVED via classify_delta)
uri    = "aos-core-v2026.05.2..v2026.05.3.bundle"
type   = "delta"
from_tag = "v2026.05.2"
to_tag   = "v2026.05.3"
creation_token = 2026050003
sha256 = "sha256:c0ffee…"
size   = 11890

# --- Inline signature over the canonical serialization of everything
#     above. Same Ed25519 key that signs git commits (brief §4.2). ---
[signature]
algorithm = "Ed25519"
keyid     = "aos-core"
value     = "MEUCIQ…base64-ed25519-signature…=="
```

---

## 5. Verification flow (consumer)

A client fetching the TARGET root performs, in order (brief §4.5;
[workstream 05](../plans/registry/workstream-05-consumer.md)):

```
1. fetch {base}/registry.toml
2. verify [signature] with the trusted/pinned pubkey   ──fail──► reject (tamper/MITM)
3. now() <= [meta].valid_until ?                       ──no────► reject (freeze)
4. check_monotonic([latest].creation_token vs persisted) ──stale► reject (rollback)
5. resolve [latest].head / channel tag to a bundle set
   from [[bundles]]                                     ──miss──► FAIL CLOSED (omission)
6. download each by its pinned sha256; verify hash      ──mismatch► reject (tamper)
```

Steps 3 and 4 are additive over the CURRENT model: today only the git commit
signature and per-bundle SHA-256 exist (`check_monotonic` runs on tokens, but
there is no `valid_until` and no signed `[latest].head` to anchor freshness —
brief §2.11). The fail-closed behavior in step 5 is the headline security
improvement: with a signed `[latest].head` a freeze degrades to a denial of
service rather than a silent rollback.

---

## 6. Migration (CURRENT → TARGET)

The shape change is a **schema bump** (`[meta].schema`), and migration strategy is
[open question §7.7](../plans/registry/open-questions.md): either a compatibility
shim that keeps emitting `bundle-list.toml` alongside the enriched `registry.toml`,
or a clean break. Concretely the move requires:

- Extending `RegistryRootConfig` ([`types.rs:566`](../../crates/aos-package/src/types.rs))
  with `[meta]` (date/valid_until/schema), `[latest]`, `[channels]`,
  `[components]`, `[capabilities]`, a unified `[[bundles]]` array (snapshots and
  deltas, `type`-distinguished), and `[signature]`;
  folding `[signing].public_key` into top-level `pubkey`.
- Adding a **serializer** for the bundle index (the CURRENT `BundleManifest` is
  `Deserialize`-only — brief §2.11) and an inline-signing step.
- Teaching the consumer to read the root's index instead of `bundle-list.toml`,
  and to enforce `valid_until` + `[latest].head` fail-closed.

See [`workstream-01-registry-root.md`](../plans/registry/workstream-01-registry-root.md)
for the full implementation plan.
