# Tag-Message Metadata — The Signed-Tag TOML Schema

> **Scope:** the **TOML message body** carried by every signed git tag object in
> an AOS registry — both the 256 channel **partition** tags (`/channel/<name>/00..ff`)
> and the per-release **semver** tags (`refs/tags/<semver>`). It supports exactly
> two tables: `[meta]` and `[[caches]]`. Nothing else.
>
> **Audience:** implementers wiring the tag-writer / tag-reader, architects
> evaluating the trust surface, and the doc-authoring agents.
>
> **CURRENT vs TARGET:** this document describes the **TARGET** git-native
> registry (design brief §14). The **CURRENT** code signs *commits*, not tags, and
> stores cache/mirror data in a separate `registry.toml` (`CacheEntry`,
> [`crates/aos-package/src/types.rs:585`](../../crates/aos-package/src/types.rs)) —
> there is no tag-message schema today. CURRENT facts are labelled and cited
> `path:line`; everything else is the target design.
>
> **Grounding:** [`docs/plans/registry/design-brief.md`](../plans/registry/design-brief.md) §14
> (this schema), §5 (ref model / name-binding), §11 (signing & `valid_until`).

**Related reference docs:** [README](./README.md) ·
[architecture](./architecture.md) · [current-state](./current-state.md) ·
[http-layout](./http-layout.md) ·
[versioning-and-channels](./versioning-and-channels.md) ·
[packs-and-deltas](./packs-and-deltas.md) ·
[signing-and-trust](./signing-and-trust.md) · [publishing](./publishing.md) ·
[nix-cache-compatibility](./nix-cache-compatibility.md) ·
[apt-comparison](./apt-comparison.md)

**Related plan docs:** [design-brief](../plans/registry/design-brief.md) ·
[gap-analysis](../plans/registry/gap-analysis.md) ·
[workstream-03-channels-rollouts](../plans/registry/workstream-03-channels-rollouts.md) ·
[workstream-04-signing-trust](../plans/registry/workstream-04-signing-trust.md) ·
[workstream-05-consumer](../plans/registry/workstream-05-consumer.md) ·
[open-questions](../plans/registry/open-questions.md)

---

## 1. Where this metadata lives

In the git-native registry, the **signature is on the tag object** and the tag
object's **message is TOML**. There is no `registry.toml` root, no
`bundle-list.toml`, and no detached metadata index — the ref namespace carries
pointers, the object store carries content, and each signed tag carries this
small TOML envelope.

```
                signed git tag object (annotated, SSH-format Ed25519)
                ┌──────────────────────────────────────────────────┐
                │ object  <sha256 of the pointed-to object>          │  ← git plumbing
                │ type    <tag|commit>                               │     header fields
                │ tag     <channel-name | semver>                    │  ← NAME-BINDING field
                │ tagger  <name> <email> <when>                      │
                │                                                    │
                │ ┌───────────────── MESSAGE (TOML) ──────────────┐ │
                │ │ [meta]                                         │ │  ← THIS DOCUMENT
                │ │ schema      = 1                                │ │
                │ │ valid_until = "2026-06-30T00:00:00Z"           │ │
                │ │                                                │ │
                │ │ [[caches]]                                     │ │
                │ │ url      = "./nar"                             │ │
                │ │ priority = 100                                 │ │
                │ └────────────────────────────────────────────────┘ │
                │                                                    │
                │ -----BEGIN SSH SIGNATURE-----  …  (Ed25519)        │  ← signature over the
                └──────────────────────────────────────────────────┘     ENTIRE tag object
```

The same schema is carried by **both** kinds of signed tag:

| Tag kind | Path / ref | `tag` name field | Points at | Where the schema rides |
|---|---|---|---|---|
| Channel partition | `/channel/<name>/<00..ff>` | `<name>` (the channel) | a semver tag | partition tag message |
| Release | `refs/tags/<semver>` | `<semver>` | the release commit | release tag message |

The `tag` name field is **not** part of this TOML schema — it is a native git tag
header. It is load-bearing for trust (§5, name-binding), and is documented here
only to make clear what the TOML body deliberately omits. See
[signing-and-trust](./signing-and-trust.md) for the full `tag → tag → commit`
chain.

---

## 2. The schema — exactly two tables

```toml
[meta]
schema      = 1                      # integer schema version
valid_until = "2026-06-30T00:00:00Z" # RFC 3339; semantics differ by tag kind (§4)

[[caches]]
url      = "./nar"                   # relative (same origin) OR absolute
priority = 100                       # higher = preferred
```

That is the complete, canonical shape (design brief §14). There are **no other
top-level tables**.

### 2.1 `[meta]`

| Key | Type | Required | Purpose |
|---|---|:---:|---|
| `schema` | integer | yes | Schema version of this TOML envelope. A consumer that does not understand `schema` **refuses gracefully** rather than misparsing. Bump on any incompatible change to the tables/keys here. |
| `valid_until` | RFC 3339 string | yes | An absolute UTC timestamp. **Channel** tags: a freshness knob (paired with low CDN TTL). **Release** tags: a generous signature-trust / key-rotation lifetime. Detailed semantics in §4. |

`[meta]` carries **only** these two keys. In particular it does **not** carry a
registry `name`, a `date`, a `pubkey`, a `head` commit SHA, or a freshness
sequence/`creation_token` — see §6 for why each is absent.

### 2.2 `[[caches]]`

An ordered list (array-of-tables) advertising NAR binary-cache locations, so a
host that already trusts this registry's key can substitute build artifacts. This
is the git-native replacement for the CURRENT `[[caches]]` block in
`registry.toml` (`CacheEntry`,
[`crates/aos-package/src/types.rs:585`](../../crates/aos-package/src/types.rs)):
the **shape is identical** (`url` + `priority`), but it now travels inside the
signed tag message instead of an unsigned root file.

| Key | Type | Default | Purpose |
|---|---|:---:|---|
| `url` | string | — (required) | Cache base URL. May be **relative** (e.g. `"./nar"`, resolved against the registry origin — a single self-hosting origin) or **absolute** (e.g. `"https://cache.aos.dev"`, an external mirror). |
| `priority` | integer | `100` | Selection preference; **higher is preferred** (`resolve_mirrors` sorts descending and `resolve_mirror` takes the first, [`registry_ops.rs:405`](../../crates/aos-package/src/registry_ops.rs), [`download.rs:75`](../../crates/aos-package/src/download.rs)). Matches the CURRENT `default_cache_priority` = 100 ([`types.rs:591`](../../crates/aos-package/src/types.rs)). |

Multiple `[[caches]]` entries are allowed and are consulted in priority order. A
**relative** `url` is the common case for the superset-of-a-Nix-cache deployment:
the same origin that serves the git objects also serves
`nix-cache-info` / `<storehash>.narinfo` / `nar/` at the relative location. See
[nix-cache-compatibility](./nix-cache-compatibility.md) and design brief §13.

`[[caches]]` is **optional**: a tag with no `[[caches]]` advertises no NAR cache
(the AOS metadata/object surface is unaffected).

---

## 3. Worked examples

### 3.1 A release tag (`refs/tags/1.2.0`)

```toml
# Message of the signed tag `1.2.0` → release commit.
# `valid_until` here is a GENEROUS key-rotation / signature-trust window
# (must NOT fight the long, immutable /release/** CDN TTL — design brief §11).

[meta]
schema      = 1
valid_until = "2027-06-04T00:00:00Z"   # ~12 months: generous (release-tag semantics)

[[caches]]
url      = "./nar"                      # relative → same origin serves the NAR superset
priority = 100
```

### 3.2 A channel partition tag (`/channel/stable/3f`)

```toml
# Message of the signed partition tag `stable` (one of 256: /channel/stable/00..ff)
# → a semver tag. `valid_until` here is a FRESHNESS knob, kept SHORT and paired
# with the low CDN TTL on /channel/** (design brief §4, §11).

[meta]
schema      = 1
valid_until = "2026-06-11T00:00:00Z"   # ~1 week: short (channel-tag semantics)

[[caches]]
url      = "https://cache.aos.dev"      # absolute → external mirror
priority = 1000

[[caches]]
url      = "./nar"                       # relative fallback on the origin
priority = 100
```

The external mirror (`priority = 1000`) is preferred over the relative `./nar`
fallback (`priority = 100`) because **higher priority wins** (§2.2).

Note the `tag` *name* differs between the two (a partition tag is named for its
channel, `stable`; the release tag is named for its semver, `1.2.0`) — but the
**TOML body schema is the same**. The name lives in the git tag header, not the
TOML.

---

## 4. `valid_until` semantics differ by tag kind

`valid_until` is a single RFC 3339 field, but it plays **two different roles**
depending on which kind of tag carries it (design brief §11). It is the producer's
job to set an appropriate window; it is the consumer's job to reject an expired
tag (fail closed).

| | Channel partition tag (`/channel/<name>/<00..ff>`) | Release tag (`refs/tags/<semver>`) |
|---|---|---|
| **Role** | **Freshness** knob | **Generous** signature-trust / key-rotation lifetime |
| **Typical window** | short (hours–days) | long (months–year) |
| **Paired CDN TTL** | **low** TTL on `/channel/**` (fast rollout) | **long** TTL on `/release/**` (immutable) |
| **What expiry means** | "this rollout pointer is stale; re-fetch the partition" — degrades a frozen mirror to a refusal, not a silent stale read | "this signature is past its trust horizon; the key may have rotated" — must **not** fight the long, immutable release TTL |
| **Re-sign cadence** | every publish / rollout advance | rare; only on a deliberate re-sign / key rotation of the release |

The asymmetry is intentional and follows the layout's CDN policy: channel pointers
are **mutable and frequently re-pointed**, so their tags carry a tight freshness
horizon that a frozen mirror cannot outlast; releases are **immutable forever**,
so their tags carry a long trust horizon that does not pointlessly expire a
perfectly good, cacheable release. A release `valid_until` that was as short as a
channel's would force needless re-signing of immutable artifacts and could expire a
release the CDN is still happily (and correctly) serving.

```
   /channel/stable/3f (low CDN TTL)        refs/tags/1.2.0  (long CDN TTL)
   valid_until = +1 week  ───────┐         valid_until = +12 months ───────┐
        freshness                │              key-rotation horizon        │
   "fail closed if a mirror      │         "trust this signature until      │
    freezes my rollout pointer"  ▼          we deliberately rotate keys"    ▼
```

Window-length defaults and re-sign / key-rotation cadence are an
[open question](../plans/registry/open-questions.md) (design brief §16.5).
Anti-rollback (the monotonic floor that prevents moving to an *older* release) is a
**separate** consumer mechanism, not driven by `valid_until` — see
[signing-and-trust](./signing-and-trust.md) and
[versioning-and-channels](./versioning-and-channels.md).

---

## 5. What the `tag` name field does (and why it isn't in the TOML)

The TOML body is deliberately silent about *which* channel or release it belongs
to. That binding is carried by git's native `tag` header field and checked at
verification time (design brief §5):

```
AOS trust chain:   signed partition tag  ──►  signed semver tag  ──►  commit
                   (tag header: <name>)       (tag header: <semver>)

Name-binding check (BOTH links):
  1. signature is valid under the trusted/pinned Ed25519 key, AND
  2. the tag-object `tag` header == the expected name for the serving path:
        under /channel/<name>/*   ⇒  header must equal <name>
        under /release/<semver>/* ⇒  header must equal <semver>
```

This binds a tag object to the path it is served from and prevents
**cross-serving** (replaying a validly-signed tag at the wrong path). Putting the
name *inside* the TOML body would be redundant and weaker: the git header is
covered by the same signature and is what git plumbing already exposes, so the name
check costs nothing extra and cannot drift from the object being verified.

---

## 6. What is deliberately NOT here

The tag message is intentionally minimal. Each absent concept lives in a more
authoritative place; duplicating it in the TOML would create a second, weaker
source of truth. (Several of these are **removed from the target entirely** —
design brief §15 — and must not be reintroduced.)

| Absent from the TOML | Where it actually lives | Why it is not in the message |
|---|---|---|
| **`pubkey` / `[signature]`** | the **tag object itself** (SSH-format Ed25519 sig over the whole object) | The signature is *on* the tag, not *in* its message; a key embedded in its own signed payload authenticates nothing. Trust roots in TOFU + `trusted-keys.d` ([signing-and-trust](./signing-and-trust.md)). |
| **`[latest]` / `head` commit SHA** | **refs** — `refs/heads/<channel>` head is the frontier; the partition tag points at a semver tag → commit | Pointers are refs; the ref namespace *is* the "what's newest" index. A `[latest]` table would be a redundant pointer-to-a-pointer. (Removed — §15.) |
| **`[channels]` / rollout config** | the **256 partition tag objects** under `/channel/<name>/00..ff` | Rollout is expressed by *which semver* each of the 256 signed partitions points at — structure, not a config field. (Percentage rollouts & `[channels]` removed — §15.) |
| **`[components]` / `[capabilities]`** | — (removed from the target) | Not part of the git-native model. (Removed — §15.) |
| **`[[bundles]]` / `[[deltas]]` index** | the **git object store** + `objects/info/http-alternates` + `delta-<from>.pack` naming | Objects are the store; packs/deltas are discovered by convention and `http-alternates`, not a by-hash table. (Removed — §15.) |
| **`name` / `date`** | tag header (`tag`, `tagger <when>`) | Native git tag headers already carry the name and the sign time; no need to restate them in TOML. |
| **`creation_token` / calendar version** | semver + git ancestry | Ordering is semver precedence + commit ancestry, not a monotonic token. (Removed — §15.) |

> **Design rule.** *The tag object carries the signature, the ref namespace
> carries pointers, and the object store carries everything else.* The TOML
> message exists only for the two things that have **no** natural home in git
> plumbing: a **schema version** (`schema`) and a **trust/freshness horizon**
> (`valid_until`), plus an **out-of-band hint** to the NAR cache (`[[caches]]`).

---

## 7. Producer & consumer handling

### 7.1 Producer (writing the message)

The message is supplied when the tag is created and signed. Conceptually
(see [publishing](./publishing.md) for the full pipeline):

```sh
# Render the TOML body (schema + valid_until + optional caches) to a file,
# then create an annotated, SSH-signed tag whose MESSAGE is that body.

git -c gpg.format=ssh -c user.signingkey="$KEY" \
    tag -s "$NAME" -F tag-message.toml "$TARGET"
#       │            │                  └ semver tag → commit  (release)
#       │            │                    OR semver tag        (channel partition)
#       │            └ message file = the [meta] + [[caches]] TOML
#       └ -s: SSH-format Ed25519 signature over the whole tag object
```

For a **release**, `$NAME` is the semver and `$TARGET` is the release commit; for a
**channel partition**, `$NAME` is the channel name and `$TARGET` is the semver tag
(producing the `tag → tag → commit` chain). The `valid_until` value is chosen per
§4 (short for partitions, generous for releases).

### 7.2 Consumer (reading the message)

```
1. fetch + verify the signed tag object under its serving path
2. name-binding: tag-object `tag` header == expected name (§5)  ──mismatch──► reject
3. parse the TOML message
4. understand [meta].schema ?                                   ──no────────► refuse gracefully
5. now() <= [meta].valid_until ?                               ──no────────► reject (stale/expired)
6. record [[caches]] (if any) for NAR substitution, resolving
   relative `url`s against the registry origin, in priority order
```

Steps 1–2 are the trust chain ([signing-and-trust](./signing-and-trust.md));
steps 3–6 consume this schema. A consumer that does not recognize `[meta].schema`
must fail closed rather than guess, which is the whole reason `schema` is the first
field a reader checks.

---

## 8. Summary

- Every signed tag — the 256 channel **partition** tags and the per-release
  **semver** tags — carries a **TOML message** with **exactly** `[meta]` and
  `[[caches]]`.
- `[meta]` = `schema` (int) + `valid_until` (RFC 3339). `[[caches]]` = `url`
  (relative or absolute) + `priority` (higher preferred, default 100), the
  git-native heir of the CURRENT `CacheEntry`
  ([`types.rs:585`](../../crates/aos-package/src/types.rs)).
- `valid_until` is **freshness** for channel tags (short, low CDN TTL) and a
  **generous** trust/key-rotation horizon for release tags (long, immutable TTL).
- The message **omits** `[latest]`, `[components]`, `[capabilities]`,
  `[[bundles]]`/`[[deltas]]`, `pubkey`, and `[signature]` by design: the signature
  is on the tag object, pointers are refs, and objects are the store (§6, design
  brief §15).
