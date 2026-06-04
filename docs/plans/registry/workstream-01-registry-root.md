# Workstream 01 — The Signed `registry.toml` Root

> **Plan doc.** Part of the [registry implementation plan](./README.md). Grounded
> in the [design brief](./design-brief.md) §4.3 (single signed root), with
> supporting decisions from §4.1 (strict-superset namespaces), §4.2 (one key),
> §4.4 (publish ordering), §4.5 (threat model), and §6 (APT improvements adopted).
>
> **Scope of this workstream:** turn the registry root from a thin, deserialize-only
> config into a *single, inline-signed, by-hash* index that is the trust anchor and
> freshness anchor for every consumer. Concretely: extend the schema types, build
> the **missing serializer/writer**, add inline Ed25519 signing of the root, and
> adopt by-hash references for everything the root points at.
>
> **Out of scope (other workstreams):** the end-to-end publish ordering and bundle
> generation ([workstream-02](./workstream-02-publish-pipeline.md)); narinfo /
> `nix-cache-info` emission ([workstream-03](./workstream-03-nix-cache.md));
> channels / rollouts / `valid_until` *consumer enforcement* and components
> ([workstream-04](./workstream-04-channels-rollouts.md)); consumer-side reading of
> the new root ([workstream-05](./workstream-05-consumer.md)). This workstream
> *defines* the `[channels]`, `[latest]`, and `valid_until` fields in the schema so
> the writer can emit them; the *behavior* around them lands in 04 and 05.

---

## 1. Why this workstream exists

The producer side of the registry is a stub (design brief §2.11). The single most
load-bearing gap is that **the registry root cannot be written by code** — only
read. Two distinct root concepts exist today and neither is a serialize-capable,
signed index:

| Today's "root" | Type | Direction | Where |
|---|---|---|---|
| `registry.toml` (in-repo config) | `RegistryRootConfig` | `Serialize + Deserialize` | `crates/aos-package/src/types.rs:566-599` |
| `bundle-list.toml` (HTTP manifest) | `BundleManifest` / `ManifestToml` | **`Deserialize` only** | `crates/aos-package/src/registry/bundle.rs:48-92` |

The design brief §4.3 collapses these into **one** signed `registry.toml` that:

1. **Is the only file a dumb-HTTP client must know how to find** (no directory
   listing required — see §4.3 "dumb HTTP is the lowest common denominator").
2. **Carries the bundle/delta enumeration inline** (kills `bundle-list.toml`).
3. **Is inline-signed** (root + signature is one atomic object, like APT
   `InRelease`), so a client fetches the trust anchor and its signature in one
   request with no race.
4. **References bundles and indices by hash** (APT `by-hash` discipline), so a
   client that read root@T resolves a consistent set even across a publish to
   root@T+1.

This workstream delivers the schema + serializer + signing + by-hash machinery
that makes (1)–(4) real. It is a prerequisite for
[workstream-02](./workstream-02-publish-pipeline.md) (which calls the serializer
as the *last* publish step) and [workstream-05](./workstream-05-consumer.md)
(which reads the new fields).

---

## 2. CURRENT state (grounded in code)

### 2.1 The in-repo `registry.toml` is anemic

`RegistryRootConfig` (`types.rs:566-573`) carries only three things:

```rust
pub struct RegistryRootConfig {
    pub registry: RegistryRootMeta,        // name + optional description
    pub caches: Vec<CacheEntry>,           // url + priority (default 100)
    pub signing: Option<RegistrySigningConfig>, // public_key only
}
```

`RegistryRootMeta` is `{ name, description }` (`types.rs:576-581`); `CacheEntry`
is `{ url, priority }` (`types.rs:584-589`); `RegistrySigningConfig` is
`{ public_key }` (`types.rs:596-599`). It already derives `Serialize` and
`Deserialize`, so the *type* can be written — but it contains **none** of the
target's index fields (no `[latest]`, no `valid_until`, no `[channels]`, no
bundle tables, no inline signature). There is no out-of-tree signature concept;
authenticity is inherited transitively from the signed git commit (design brief
§3, §2.10).

### 2.2 The bundle manifest is deserialize-only — the missing writer

`bundle.rs` defines the *parser* for `bundle-list.toml`:

- `ManifestToml` / `ManifestHeader` / `BundleEntryToml` are `#[derive(Debug,
  Deserialize)]` — **no `Serialize`** (`bundle.rs:59-92`).
- `BundleManifest::parse` (`bundle.rs:124-178`) reads TOML → typed entries, sorts
  by `creation_token`, and classifies deltas via `classify_delta`
  (`bundle.rs:238-243`).
- There is **no** `BundleManifest::write` / `to_toml` / serializer anywhere. A
  repository-wide search for a manifest writer returns nothing.

Consequently the producer cannot emit an index at all:

- `apr bundle` (`registry_ops.rs:1718-1756`) only shells out to `git bundle
  create` into a local `bundles/` dir. Its `_update_manifest: bool` parameter is
  **unused dead code** (`registry_ops.rs:1723`) — the leading underscore is the
  compiler telling you so.
- No producer-side `creation_token` computation: `version_to_token`
  (`registry/state.rs:131`) exists but is only called consumer-side.
- No `[latest]` pointer is written; "latest" is *derived* consumer-side by
  scanning for max `creation_token` (`latest_snapshot`, `bundle.rs:189-194`).

### 2.3 Signing is whole-commit, not root-inline

`apr sign` is `git commit --amend --no-edit -S` (`registry_ops.rs:1759-1774`); the
`_key` parameter is ignored. Verification is `verify_commit_signature`
(`security.rs:199`) which builds a temporary `allowed_signers` file and runs `git
-c gpg.ssh.allowedSignersFile=… verify-commit`. Keys are
`name:Ed25519:base64` and `parse_signing_key` (`security.rs:306`) **rejects any
algorithm but Ed25519**. There is **no inline signature on any file** — the root
is not independently verifiable outside a git clone.

### 2.4 Current vs target at a glance

| Aspect | CURRENT | TARGET (this workstream) |
|---|---|---|
| Root file | `registry.toml` (config) + `bundle-list.toml` (manifest) | single `registry.toml` (index + config) |
| Root serializable? | type derives `Serialize`, but lacks index fields | full index, written by `RegistryRoot::to_toml` |
| Bundle manifest writer | **none** (deserialize only) | `RegistryRoot` carries `[[bundles]]`; writer emits them |
| `creation_token` (producer) | never computed | computed at write time from the tag |
| `[latest]` pointer | derived by scanning | explicit signed field |
| `valid_until` | absent | signed expiry field |
| `[channels]` | absent | symbolic alias table (behavior in WS-04) |
| Signature | whole-commit `-S` only | whole-commit **plus** inline root signature |
| By-hash references | content-addressed nars only | every bundle referenced by `sha256` key |

---

## 3. TARGET schema: `registry.toml`

Per design brief §4.3, the root "carries at least" the fields below. This is the
authoritative schema for this workstream; the annotated reference example lives in
[docs/registry/registry-toml.md](../../registry/registry-toml.md) and the wire/object
layout in [docs/registry/http-layout.md](../../registry/http-layout.md).

### 3.1 Annotated example

```toml
# --- registry.toml (the single signed root) ----------------------------------

[meta]
schema      = 1                          # integer schema version; bump on breaking change
name        = "aos-core"
date        = "2026-06-03T12:00:00Z"     # when this root was signed
valid_until = "2026-07-03T12:00:00Z"     # APT-style freeze defense (§4.5, §6.1); ~30d default window

[meta.capabilities]
by_hash         = true                  # references are content-addressed (§6.2)
phased_rollouts = true                  # channel targets may carry rollout = N (§6.4)
nix_cache       = true                  # narinfo / nix-cache-info also served (WS-03)

# The one Ed25519 public key. Both encodings are derivable from this:
#   registry:Ed25519:<base64>   -> apm TOFU pinning (security.rs:306 grammar)
#   <name>:<base64>             -> Nix trusted-public-keys (WS-03)
pubkey = "aos-core:Ed25519:MC4CAQAwBQYDK2VwBCIEI...base64..."

# Signed freshness / anti-rollback anchor (§4.3, §4.4). Flipped LAST on publish.
[latest]
tag            = "v2026.06.3"
creation_token = 2026060003              # year*1_000_000 + month*10_000 + patch (patch<=9999)
head           = "9f3c1ab7e0d2c4f8a1b6e5d4c3b2a1908f7e6d5c"  # authentic git commit SHA

# Symbolic channels decoupled from tags (§4.3, §6.3). Behavior: WS-04 / WS-05.
# Subtable form (NOT inline tables). Each channel carries its own monotonic
# creation_token for per-channel anti-rollback.
[channels.stable]
tag            = "v2026.06.3"
creation_token = 2026060003
# omit rollout (or set 100) = fully rolled out

[channels.testing]
tag            = "v2026.06.4"
creation_token = 2026060004
rollout        = 25                      # phased rollout: 25% (§6.4)

# Optional intra-registry partitions (§4.3, §6.5). Behavior: WS-04.
# Subtable form keyed by name (NOT a [[components]] array).
[components.main]
description = "core packages"

# Binary cache mirrors for NAR blobs (carried over from CURRENT CacheEntry).
[[caches]]
url      = "https://cache.aos.dev"
priority = 100

# --- Bundle / delta index (by-hash), the former bundle-list.toml contents -----
# A SINGLE [[bundles]] array folds snapshots and deltas together, distinguished
# by `type`. There is no separate [[deltas]] array. `sha256` ALWAYS carries an
# explicit algorithm prefix ("sha256:<hex>"); parsers must tolerate other
# prefixes for future hash agility (see §3, §6.1).
#
# Snapshot bundle: full state at a tag.
[[bundles]]
uri            = "aos-core-v2026.06.bundle"   # object key/filename (authority is by-hash)
type           = "snapshot"
tag            = "v2026.06"
creation_token = 2026060000
sha256         = "sha256:aaaa1111...."        # by-hash key: also the object's identity
size           = 1048576

# Sequential delta: patch -> next patch. (skip-vs-sequential is DERIVED via
# classify_delta(from_tag), NOT a wire value.)
[[bundles]]
uri            = "aos-core-v2026.06.2..v2026.06.3.bundle"
type           = "delta"
from_tag       = "v2026.06.2"
to_tag         = "v2026.06.3"
creation_token = 2026060003
sha256         = "sha256:bbbb2222...."
size           = 4096

# Skip delta: minor base -> later patch (from_tag has <=2 dotted parts).
[[bundles]]
uri            = "aos-core-v2026.06..v2026.06.3.bundle"
type           = "delta"
from_tag       = "v2026.06"
to_tag         = "v2026.06.3"
creation_token = 2026060003
sha256         = "sha256:cccc3333...."
size           = 7168

# --- Inline signature (APT InRelease style) ----------------------------------
# Ed25519 signature over the canonical bytes of everything ABOVE this stanza.
[signature]
algorithm = "Ed25519"
keyid     = "aos-core"
value     = "base64-ed25519-signature-over-canonical-pre-signature-bytes"
```

### 3.2 Field reference

| Table / field | Type | Source | Notes |
|---|---|---|---|
| `meta.schema` | integer | §4.3, §6 | integer schema version (`1`); bump for breaking changes (open Q §7.7) |
| `meta.name` | string | §4.3 | registry name; matches `RegistryRootMeta.name` |
| `meta.date` | RFC 3339 | §4.3 | sign time; `valid_until` ~30d later by default |
| `meta.valid_until` | RFC 3339 | §4.5, §6.1 | **freeze defense**; client rejects expired root (WS-05) |
| `meta.capabilities.*` | bool flags | §4.3, §6.6 | graceful degradation + forward compat |
| `pubkey` | string | §4.2 | `name:Ed25519:base64`; same grammar as `security.rs:306` |
| `latest.tag` | string | §4.3 | symbolic latest tag |
| `latest.creation_token` | u64 | §2.5, §4.4 | monotonic; `check_monotonic` defends rollback |
| `latest.head` | hex | §4.3, §4.5 | authentic git commit SHA; **fail-closed** anchor |
| `channels.<name>` | subtable | §4.3, §6.3 | `{ tag, creation_token, rollout? }`; behavior in WS-04 |
| `components.<name>` | subtable | §4.3, §6.5 | `{ description? }`; optional partitions; behavior in WS-04 |
| `caches[]` | table | CURRENT | `{ url, priority }`; preserves `CacheEntry` (`types.rs:584`) |
| `bundles[]` | table | §2.4, §6.7 | single by-hash bundle/delta index; replaces `bundle-list.toml` |
| `signature` | table | §4.3 | inline Ed25519 (`value`) over canonical pre-signature bytes |

### 3.3 Bundle entry grammar (vs current `bundle-list.toml`)

The bundle entry preserves the wire shape `BundleEntryToml` already parses
(`bundle.rs:76-92`) so the consumer change is minimal: `uri` is the object
key/filename; `type` is `"snapshot"` or `"delta"`; snapshots carry `tag`, deltas
carry `from_tag` / `to_tag`; all carry `creation_token`, `sha256`, `size`. The
`sha256` value carries an explicit algorithm prefix (`"sha256:<hex>"`) and
parsers must tolerate other prefixes for future hash agility. Delta
classification stays *read-time* in the consumer (`classify_delta`,
`bundle.rs:238`, signature `fn classify_delta(from: &str, _to: &str) -> bool` —
the `to` arg is unused): a `from_tag` with ≤2 dotted parts is a `SkipDelta`,
otherwise `SequentialDelta`. **The producer does not need a new type field** — it
writes `type = "delta"` and lets the consumer classify. This keeps the two sides
decoupled.

The only structural difference from `bundle-list.toml` is the **header location**:
today the manifest has its own `[manifest]` header (`registry`, `version`,
`generated`); in the target those move to `[meta]` and the `[[bundles]]` array
lives in the same file as everything else.

---

## 4. The inline signature

### 4.1 What is signed

The `[signature]` stanza signs **the canonical serialization of every byte of the
root above it**. This mirrors APT `InRelease`: one file, the signature appended,
verifiable as a single object fetched in one request (design brief §4.3 "single
object … no race").

```
+--------------------------------------------------+
|  [meta] [meta.capabilities] ... pubkey           |
|  [latest] [channels.*] [components.*] [[caches]] |  <-- canonical bytes B
|  [[bundles]] ...                                 |      (the signed message)
+--------------------------------------------------+
|  [signature]  value = Ed25519_sign(secret, B)    |  <-- appended, NOT in B
+--------------------------------------------------+
```

### 4.2 Canonicalization rule (must be deterministic)

A signature is only verifiable if signer and verifier agree on the exact bytes.
The writer therefore produces a **canonical** pre-signature form:

1. Serialize the root struct *without* the `[signature]` table.
2. Emit tables in a fixed order: `[meta]`, `[meta.capabilities]`, top-level
   `pubkey`, `[latest]`, `[channels.<name>]`, `[components.<name>]`, `[[caches]]`,
   `[[bundles]]`.
3. `[[bundles]]` entries sorted by `creation_token` ascending, ties broken by
   `sha256` lexicographically (matches the consumer's existing
   `entries.sort_by_key(|e| e.creation_token)` at `bundle.rs:171`).
4. The signed message `B` = the UTF-8 bytes of that serialization, terminated by a
   single trailing `\n`.
5. `value = base64(Ed25519_sign(secret_key, B))`.

The verifier recomputes `B` by re-serializing the parsed root minus `[signature]`
under the same rules, then checks `Ed25519_verify(pubkey, B, value)`. Because TOML
round-trips are not guaranteed byte-stable across libraries, the verifier MUST
re-serialize via the *same* canonicalizer rather than hashing the raw fetched
bytes. (Open question §7.7 in the brief: schema-version bump strategy interacts
with canonicalization — record any deviation.)

### 4.3 One key, two signatures (brief §4.2)

The inline root signature uses the **same Ed25519 keypair** as the git commit
signature and (in WS-03) the narinfo signature. The *messages differ* (root bytes
vs commit object vs narinfo fingerprint) but the *secret is shared*. This
workstream consumes the key via the existing `parse_signing_key` grammar
(`security.rs:306`, `name:Ed25519:base64`) — it does **not** introduce a second
key or a new algorithm. SSH-format commit signing (`apr sign`,
`registry_ops.rs:1770`) is unchanged; the inline root signature is *additive*.

### 4.4 Trust still roots in the commit

Per brief §3 and §4.2, `apm`'s trust continues to root in the **signed git
commit** (the Merkle DAG transitively authenticates every TOML and every NAR
hash). The inline root signature exists to give a **dumb-HTTP client a verifiable
trust + freshness anchor without a git clone**, and to make omission attacks
fail-closed (brief §4.5: a client that cannot reach the signed `[latest].head`
refuses rather than silently using stale data). It is not a replacement for the
commit signature; both are present.

---

## 5. By-hash references (brief §4.3, §6.2)

The root references each bundle by its `sha256`, which is **also the object's
storage identity** under by-hash discipline. The practical effect, per brief §4.4:
during a publish the new immutable objects (nars, `*.narinfo`, `*.bundle`) are
uploaded *first*, and the root is flipped *last*; because every object the new
root names already exists and is addressed by content hash, a reader that fetched
root@T resolves a fully consistent set even if root@T+1 lands mid-fetch.

```
registry.toml@T  --sha256:bbbb2222-->  bundles/.../by-hash/sha256/bbbb2222...  (immutable)
registry.toml@T  --sha256:cccc3333-->  bundles/.../by-hash/sha256/cccc3333...  (immutable)
        (atomic flip)                          ^ never deleted while referenced
registry.toml@T+1 --sha256:dddd4444--> bundles/.../by-hash/sha256/dddd4444...  (new, pre-uploaded)
```

This is *mostly discipline atop existing content-addressing* (brief §6.2): NAR
blobs are already content-addressed (`nar_url` → `{mirror}/{nar_hash}.nar.zst`,
brief §2.8). What this workstream adds is **(a)** emitting the `sha256` as the
authoritative reference key in the root, and **(b)** the convention that bundle
objects are addressed by that hash so the consumer's existing SHA-256
verification (`download_bundle` + `verify_bundle`, `bundle.rs:251,305`) doubles as
the by-hash lookup check. The exact object-key grammar (e.g. `by-hash/sha256/<h>`
vs flat `<h>.bundle`) is specified in
[http-layout.md](../../registry/http-layout.md); this workstream only guarantees
the root carries the hash.

---

## 6. Concrete code changes

All paths are under `crates/aos-package/` unless noted.

### 6.1 New / changed types (`src/types.rs`)

Extend `RegistryRootConfig` (currently `types.rs:566-573`) into the full target
root. Two viable shapes — **(A)** grow `RegistryRootConfig` in place, or **(B)**
introduce a new `RegistryRoot` and keep `RegistryRootConfig` as a thin alias for
back-compat. (B) is recommended so the legacy `{ registry, caches, signing }`
config still parses during migration (brief open Q §7.7).

New/extended structs (all `#[derive(Debug, Clone, Serialize, Deserialize)]`):

| Struct | Fields | Maps to schema |
|---|---|---|
| `RegistryRoot` | `meta`, `capabilities`, `pubkey`, `latest`, `channels`, `components`, `caches`, `bundles`, `signature` | the whole root |
| `RegistryMeta` | `schema: u32`, `name: String`, `date: String`, `valid_until: Option<String>`, `capabilities` | `[meta]` |
| `Capabilities` | `by_hash`, `phased_rollouts`, `nix_cache: bool` (all `#[serde(default)]`) | `[meta.capabilities]` |
| `LatestPointer` | `tag: String`, `creation_token: u64`, `head: String` | `[latest]` |
| `ChannelTarget` | `tag: String`, `creation_token: u64`, `rollout: Option<u8>` | `[channels.<name>]` |
| `ComponentEntry` | `description: Option<String>` | `[components.<name>]` |
| `BundleRef` | `uri: String`, `type_: String` (`#[serde(rename="type")]`), `tag`/`from_tag`/`to_tag: Option<String>`, `creation_token: u64`, `sha256: String`, `size: u64` | `[[bundles]]` |
| `RootSignature` | `algorithm: String`, `keyid: String`, `value: String` | `[signature]` |

`CacheEntry` (`types.rs:584-589`) and `RegistryRootMeta` are **reused as-is** (or
`RegistryRootMeta` folded into `RegistryMeta`). `channels` is a
`std::collections::BTreeMap<String, ChannelTarget>` and `components` is a
`std::collections::BTreeMap<String, ComponentEntry>` (both subtable-keyed by name;
BTreeMap, not HashMap, for deterministic serialization order — required by §4.2
canonicalization). The `sha256` field on `BundleRef` carries an explicit
`"sha256:"` algorithm prefix; the parser must tolerate other prefixes for hash
agility (future algorithm migration).

`BundleRef` deliberately mirrors `BundleEntryToml` (`bundle.rs:76-92`) so the
consumer can be migrated to read `[[bundles]]` from the root with the same
classification logic (WS-05).

### 6.2 New module: `src/registry/root.rs` (the missing writer)

This is the **core deliverable**. A new module hosting:

```rust
impl RegistryRoot {
    /// Serialize to canonical pre-signature bytes (no [signature] table).
    /// Deterministic table order; bundles sorted by (creation_token, sha256).
    pub fn canonical_unsigned(&self) -> Result<String>;

    /// Produce the fully-signed registry.toml text:
    ///   canonical_unsigned() ++ "\n[signature]\n..."  with Ed25519 over the
    ///   canonical bytes. `secret` is the Ed25519 signing key.
    pub fn to_signed_toml(&self, secret: &Ed25519SecretKey) -> Result<String>;

    /// Parse a registry.toml (with or without [signature]).
    pub fn parse(text: &str) -> Result<Self>;

    /// Verify the inline signature: re-canonicalize (minus [signature]) and
    /// Ed25519_verify against `pubkey`. Returns Ok(()) on a good signature.
    pub fn verify_signature(&self) -> Result<()>;
}
```

Plus a builder that assembles a `RegistryRoot` from a landed git commit:

```rust
/// Build a root from the registry repo state at `head` plus the enumerated
/// bundle objects (produced by workstream-02). Computes [latest] (tag,
/// creation_token via version_to_token, head), fills [[bundles]] (sha256 + size
/// of each object), and stamps meta.date / meta.valid_until.
pub fn build_root(
    repo_dir: &Path,
    head: &str,
    latest_tag: &str,
    bundles: &[BundleRef],
    pubkey: &str,
    valid_for: Duration,
) -> Result<RegistryRoot>;
```

Key reuse:

- `latest.creation_token` via **`registry::state::version_to_token`**
  (`state.rs:131`) — finally exercised producer-side, closing the brief §2.11 gap.
- `parse_signing_key` (`security.rs:306`) to validate / split `pubkey` into
  `(name, "Ed25519", base64)` before signing or verifying.
- The Ed25519 primitive: reuse whatever crate `security.rs` already links for
  verification (confirm in implementation — see open question below) rather than
  adding a new dependency.

### 6.3 Wire `apr` to write the root (`src/registry_ops.rs`)

- Replace the dead `_update_manifest` parameter (`registry_ops.rs:1723`) with a
  real call path: when set, after `git bundle create`, build `BundleRef`s for the
  produced bundles (compute `sha256` + `size` of each file) and hand them to
  `build_root` → `to_signed_toml` → write `registry.toml`. The full ordering
  (generate → upload → **flip root last**) is owned by
  [workstream-02](./workstream-02-publish-pipeline.md); this workstream supplies
  the *writer* it calls.
- `apr sign` (`registry_ops.rs:1759`) keeps doing the git commit `-S`; the inline
  root signature is produced by `to_signed_toml`, not by `apr sign`. (Open
  question §7.6: whether a dedicated `apr release` subsumes both — that decision
  is WS-02's.)

### 6.4 Deprecate `bundle-list.toml` parsing path (coordinated with WS-05)

This workstream *introduces* `[[bundles]]` in the root; it does **not** remove the
`bundle-list.toml` reader (`bundle.rs:94-178`). Migration (clean break vs
compatibility shim) is brief open question §7.7 and is sequenced in
[workstream-05](./workstream-05-consumer.md). Until then both coexist: the new
writer emits `registry.toml` with `[[bundles]]`; the old reader still parses
legacy `bundle-list.toml` mirrors.

---

## 7. Tests to add

Co-locate unit tests in the new `registry/root.rs` (mirroring the existing
`bundle.rs` test style at `bundle.rs:427`), plus type tests in `types.rs`.

| Test | Asserts |
|---|---|
| `root_round_trips` | `parse(to_signed_toml(r)) == r` for a fully-populated root |
| `canonical_is_deterministic` | `canonical_unsigned` is byte-identical across repeated calls and across a `parse`→re-serialize round trip (the §4.2 invariant) |
| `bundles_sorted_by_token_then_hash` | `[[bundles]]` emitted in `(creation_token, sha256)` order regardless of input order |
| `signature_verifies` | `verify_signature` accepts a genuine signature |
| `signature_rejects_tamper` | flipping one byte of `[latest].head` or any `[[bundles]].sha256` makes `verify_signature` fail |
| `signature_excludes_signature_table` | adding/removing fields *inside* `[signature]` does not change the signed message |
| `latest_token_matches_tag` | `build_root` computes `creation_token` via `version_to_token` consistent with `latest.tag` |
| `rejects_non_ed25519_pubkey` | a `pubkey` with algorithm ≠ `Ed25519` is rejected (via `parse_signing_key`) |
| `parses_legacy_without_signature` | a root without `[signature]` parses (migration / unsigned dev registries) |
| `valid_until_optional` | omitted `valid_until` parses to `None` (enforcement is WS-04/05) |
| `bundleref_wire_matches_manifest` | a `BundleRef` serializes to the same field names `BundleEntryToml` (`bundle.rs:76`) deserializes — guards consumer compatibility |

---

## 8. Sequencing and dependencies

```
WS-01 (this)  ── RegistryRoot type + root.rs writer + inline signing + by-hash
   │
   ├──► WS-02 publish-pipeline : calls build_root / to_signed_toml as the LAST
   │       (flip-root-last) step; supplies the [[bundles]] objects + creation_token
   │
   ├──► WS-04 channels-rollouts : defines BEHAVIOR for [channels]/rollout/
   │       valid_until/components that WS-01 only declares in the schema
   │
   └──► WS-05 consumer : reads registry.toml [[bundles]] (replacing the
           bundle-list.toml path), verify_signature, valid_until/freeze checks,
           fail-closed on unreachable [latest].head
```

Deliverables of this workstream are **complete** when: (1) `RegistryRoot` carries
every §3 field and serializes deterministically; (2) `root.rs` can produce and
verify an inline-signed `registry.toml`; (3) `apr` can write that file from a
landed commit + bundle set; (4) the test matrix in §7 passes.

---

## 9. Cross-references

- Design intent: [design-brief.md](./design-brief.md) §4.3 (primary), §4.1, §4.2,
  §4.4, §4.5, §6.
- Reference (target) docs:
  [registry-toml.md](../../registry/registry-toml.md) (annotated schema),
  [http-layout.md](../../registry/http-layout.md) (object keys, by-hash grammar),
  [signing-and-trust.md](../../registry/signing-and-trust.md) (one-key model),
  [bundles-and-deltas.md](../../registry/bundles-and-deltas.md) (delta model),
  [architecture.md](../../registry/architecture.md),
  [current-state.md](../../registry/current-state.md).
- Plan docs:
  [README.md](./README.md), [gap-analysis.md](./gap-analysis.md),
  [workstream-02-publish-pipeline.md](./workstream-02-publish-pipeline.md),
  [workstream-03-nix-cache.md](./workstream-03-nix-cache.md),
  [workstream-04-channels-rollouts.md](./workstream-04-channels-rollouts.md),
  [workstream-05-consumer.md](./workstream-05-consumer.md),
  [open-questions.md](./open-questions.md).

---

## 10. Open questions for this workstream

1. **Canonicalization library choice.** Rust's `toml` crate does not guarantee
   byte-stable output across versions; the §4.2 canonicalizer must own table/array
   ordering explicitly (manual emission or `toml_edit` with a fixed document
   template). Pick one and pin it; the verifier must use the identical path.
2. **Ed25519 crate for signing.** `security.rs` currently verifies *git* SSH
   signatures by shelling out to `git verify-commit` (`security.rs:199`) — it does
   not appear to do in-process Ed25519. Producing/verifying the *inline* root
   signature needs an in-process Ed25519 implementation (e.g. an `ed25519`/
   `ed25519-dalek` equivalent built as an AOS crate per the hermetic-build rules).
   Confirm what is already vendored before adding a dependency.
3. **Schema-version migration** (brief §7.7): clean break vs compatibility shim for
   legacy `bundle-list.toml` and the anemic `RegistryRootConfig`. Affects whether
   §6.1 grows the type in place (A) or aliases (B).
