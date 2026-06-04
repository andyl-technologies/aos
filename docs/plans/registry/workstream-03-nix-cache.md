# Workstream 03 — Nix Binary-Cache Surface

> **Plan doc.** This is one of the five implementation workstreams that take the
> AOS package registry from its **current** state to the **target** design. It
> covers the **Nix binary-cache surface**: making the static, dumb-HTTP registry
> origin *also* answer the stock Nix substituter protocol so that a non-AOS
> dev-shell host can fetch AOS build artifacts with plain `nix`.
>
> **Grounding:** design brief [§4.1](design-brief.md#41-strict-superset-of-the-nix-binary-cache-protocol)
> and [§4.2](design-brief.md#42-one-ed25519-key-two-protocols). The brief wins
> for *intent*; the code wins for *current state*. Current-state claims below are
> cited as `path:line`.
>
> **Audience:** implementers, architects, engineers, and operators wiring AOS
> caches into Nix substituters.

---

## 1. Scope

What this workstream builds, per the brief
([§4.1, last paragraph](design-brief.md#41-strict-superset-of-the-nix-binary-cache-protocol)):

1. **A narinfo generator keyed by the store-path hash** — emits one
   `<storehash>.narinfo` per published store path.
2. **A `nix-cache-info` stub** — the fixed-name root file Nix probes first.
3. **References basename expansion** — turn the registry's bare dependency
   *hashes* into Nix's `<hash>-<name>` basenames.
4. **Per-narinfo Ed25519 `Sig:`** — generated with the *same* key that signs git
   commits (one secret, two signature forms; see brief
   [§4.2](design-brief.md#42-one-ed25519-key-two-protocols)).
5. **Co-located / served NAR blobs** — `.nar.zst` files under `nar/` (or pointed
   at an existing cache via the narinfo `URL:`).
6. **Dev-shell substituter wiring** — the `nix.conf` / `--extra-substituters`
   recipe a host uses to consume the registry origin as a binary cache.

What this workstream explicitly does **not** cover (handled elsewhere):

| Concern | Owner |
|---|---|
| `registry.toml` root schema, serializer, inline signing, by-hash | [workstream-01-registry-root.md](workstream-01-registry-root.md) |
| `apr release` ordering, bundle generation, upload backends, root flip | [workstream-02-publish-pipeline.md](workstream-02-publish-pipeline.md) |
| Channels, rollouts, `valid_until`, capability flags | [workstream-04-channels-rollouts.md](workstream-04-channels-rollouts.md) |
| Consumer (`apm`) root reading, expiry/freeze, fail-closed | [workstream-05-consumer.md](workstream-05-consumer.md) |

The Nix narinfo objects are **immutable, content-addressed artifacts**. They are
generated and uploaded by the publish pipeline (workstream-02) as part of step 3
("upload immutable objects first"), *before* the atomic root flip. This
workstream defines *what* those objects are and *how* they are produced; the
publish pipeline defines *when* and *in what order* they ship.

---

## 2. Why this is additive, not a rewrite

The brief's central claim
([§4.1](design-brief.md#41-strict-superset-of-the-nix-binary-cache-protocol),
[§3.1](design-brief.md#3-key-clarifications-established-in-conversation)) is that
the two protocols occupy **disjoint URL namespaces** on one HTTP origin, so Nix
support is a *strict superset* — purely additive:

```
{base}/                              <- registry HTTP origin (dumb HTTP)
├── registry.toml                    AOS  : single signed root  (workstream-01)
├── bundles/{name}/...               AOS  : git bundles of TOML  (consumer §2.4)
│
├── nix-cache-info                   NIX  : fixed-name stub        (THIS workstream)
├── <storehash>.narinfo              NIX  : per-store-path metadata (THIS workstream)
└── nar/<...>.nar.zst                BOTH : content-addressed blob  (shared)
```

Nothing an `apm` client fetches changes. A stock `nix` client only ever touches
`nix-cache-info`, `*.narinfo`, and `nar/`. The blob namespace (`nar/`) is shared
because **AOS already names blobs exactly the way Nix's narinfo indirection
expects** — a store-hash-keyed metadata file pointing at a content-addressed NAR.

### Field alignment (already 90% there)

The source fields live in the nested package TOML (`PackageToml` et al.,
`registry/parse.rs`), flattened into the in-memory `PackageMeta`
(`types.rs:43`–`77`), which carries nearly every narinfo field. From the brief's
mapping table
([§4.1](design-brief.md#41-strict-superset-of-the-nix-binary-cache-protocol)):

| narinfo field | Source (`PackageMeta`, `types.rs`) | Transform |
|---|---|---|
| `StorePath` | `store_path` (`:53`) | passthrough |
| `URL` | derived | `nar/<download_hash>.nar.zst`, relative |
| `Compression` | constant | always `zstd` |
| `FileHash` / `FileSize` | `download_hash` / `download_size` (`:58`,`:59`) | compressed `.nar.zst` |
| `NarHash` / `NarSize` | `nar_hash` / `nar_size` (`:54`,`:56`) | uncompressed |
| `References` | `references` (`:61`) | **expand bare hashes → `<hash>-<name>`** |
| `Deriver` | `source_drv` (`:64`) | basename, optional |
| `Sig` | — | **generate (Ed25519)** |

The only two non-trivial pieces are **References basename expansion** (§5) and the
**`Sig:` line** (§6). Everything else is a direct copy.

---

## 3. Current state (as-is)

> **Two distinct cache surfaces exist in the tree, and only one of them is the
> registry.** This is the single most important fact for this workstream.

### 3.1 The dynamic cache server (`aos-server`) — NOT the registry

A complete, working Nix binary-cache server already exists, but it is the
**`aos serve` dynamic, DB-backed cache** — not the static registry origin this
workstream targets.

- Route table (`aos-server/src/routes.rs`):
  - `GET /{view}/nix-cache-info` → `cache_info_handler` (`:78`), emitting
    `StoreDir: …`, `WantMassQuery: 1`, `Priority: 30`, plus an AOS-specific
    `Capabilities:` line (`:142`–`:145`).
  - `GET /{view}/<hash>.narinfo` → `narinfo_handler` (`:155`), which looks the
    path up in a SQLite store, runs a per-**view** visibility/auth check
    (`:168`–`:191`), and renders via `narinfo::format_narinfo(…)` (`:209`).
- narinfo rendering (`aos-server/src/narinfo.rs`):
  - `format_narinfo` (`:16`) builds the text from a `DbPathInfo`.
  - **References are already basename-expanded** here:
    `info.refs.iter().map(|r| basename(r))` (`:41`).
  - **Deriver** is basename-expanded (`:47`).
  - **Live Ed25519 signing** is wired: it computes the Nix fingerprint and
    appends a `Sig:` (`:56`–`:62`).
  - `URL:` is `nar/<path_hash>-<narhash>.nar.zst` (nix-serve style, `:26`).
- Signer (`aos-server/src/sign.rs`):
  - `NarInfoSigner` loads a `name:base64` secret (`:14`), signs with
    `ed25519_dalek` (`:44`–`:54`).
  - `NarInfoSigner::fingerprint` (`:57`) builds the canonical Nix fingerprint:
    `1;{store_path};{nar_hash};{nar_size};{refs_joined_by_comma}`.
- Shared narinfo primitives (`aos-core/src/nar/info.rs`):
  - `NarInfo` struct + `parse`/`format` round-trip (`:5`,`:19`,`:81`).
  - `from_path_info` constructor (`:129`).
  - `store_hash` (`:147`) and `basename` (`:153`) helpers.
- The cache push path (`aos-cache/src/push.rs`) *also* generates narinfos
  (`narinfo::from_path_info` `:163`, `narinfo::format` `:175`) and uploads them
  via `backend.put_narinfo` (`:187`).

**Implication for this workstream:** the *algorithms* — fingerprint, signing,
basename expansion, narinfo text format — already exist and are tested. They live
in `aos-core` (shared) and `aos-server` (server-private). The work is to **reuse
those primitives** to emit *static files* from the *registry* package TOMLs,
keyed under the registry origin's flat namespace, rather than serving them
dynamically from a SQLite-backed view.

### 3.2 The registry producer (`aos-package`) — has nothing

The registry side (`apr` / `apm`, all in `crates/aos-package/`) emits **no**
narinfo and **no** `nix-cache-info`:

- `registry_ops.rs` (1959 lines) contains zero references to `narinfo`,
  `nix-cache-info`, `format_narinfo`, or `fingerprint`.
- The producer-gaps table in the brief
  ([§2.11](design-brief.md#211-producer-side-gaps-the-asymmetry)) lists
  "narinfo / nix-cache-info" as **❌ (Producer)**.
- The registry's own NAR-download path (`download.rs`) constructs blob URLs as
  `{mirror_url}/{nar_hash}.nar.zst` where `nar_hash` is the **full
  `sha256:<hex>` string including the colon** (`nar_url`, `download.rs:57`–`:60`;
  test `:282`). This is the AOS-internal `apm` consumer convention and is
  **different** from the Nix narinfo `URL:` form (which is relative and
  store-hash-keyed). See [§7](#7-nar-url-and-blob-layout-discrepancy).

So `apm` already knows how to *fetch* a NAR; nothing in the registry yet *emits a
narinfo* that a stock `nix` client could read.

### 3.3 Signing key state

- The registry's signing key is the **same Ed25519 key** that signs git commits
  (brief [§2.10](design-brief.md#210-signing--trust--current),
  [§4.2](design-brief.md#42-one-ed25519-key-two-protocols)).
- `apm` parses the published public key in `registry:Ed25519:<base64>` form
  (`security.rs:306`, `parse_signing_key`; rejects any non-`Ed25519` algorithm,
  `:324`). Git-commit verification uses the SSH `ssh-ed25519` encoding
  (`verify_commit_signature`, `security.rs:199`–`:233`).
- The server-side narinfo signer expects a **secret** in `name:base64` form and
  emits `Sig: <name>:<base64sig>` (`sign.rs:53`). The Nix `trusted-public-keys`
  encoding is `<name>:<base64pub>`.
- Therefore the *one* key already yields the *two* published public-key
  encodings the brief calls for: `registry:Ed25519:<b64>` for `apm` TOFU, and
  `<name>:<b64>` for Nix. No new key material is introduced by this workstream.

| Capability | `aos-server` (dynamic) | `aos-package` registry (static) — TARGET |
|---|---|---|
| `nix-cache-info` | ✅ `routes.rs:78`/`:142` | ❌ → build static stub |
| `<hash>.narinfo` | ✅ `routes.rs:155` (DB-backed) | ❌ → generate from package TOML |
| References basename expansion | ✅ `narinfo.rs:41` | ❌ → reuse primitive |
| Ed25519 `Sig:` | ✅ `narinfo.rs:56`, `sign.rs` | ❌ → reuse `NarInfoSigner` |
| Fingerprint `1;…` | ✅ `sign.rs:57` | ❌ → reuse `NarInfoSigner::fingerprint` |
| Keyed by store-path hash | ✅ (view-scoped) | ❌ → flat `<hash>.narinfo` |

---

## 4. Target: the static narinfo generator

### 4.1 Object: `<storehash>.narinfo`

For every `(package, version, platform)` entry in `packages/<x>/<name>.toml`,
emit one file named `<storehash>.narinfo`, where `<storehash>` is the **32-char
base32 store-path hash** — i.e. `store_hash(store_path)`
(`aos-core/src/nar/info.rs:147`). Served at the origin root:

```
{base}/<storehash>.narinfo
```

This is exactly Nix's expectation: a substituter queries
`{cache}/<hash>.narinfo` for each wanted store path. Because `<storehash>` is
content-derived and immutable, the file is content-addressed in practice and
safe to upload before the root flip (workstream-02 step 3).

### 4.2 Field derivation (from `PackageMeta`)

```
StorePath:   {store_path}                          # types.rs:53, passthrough
URL:         nar/{download_hash}.nar.zst           # see §7 for the colon caveat
Compression: zstd                                  # constant
FileHash:    {download_hash}                       # types.rs:58  (sha256:<hex>)
FileSize:    {download_size}                        # types.rs:59
NarHash:     {nar_hash}                            # types.rs:54  (sha256:<hex>)
NarSize:     {nar_size}                            # types.rs:56
References:  {expanded basenames, space-separated} # types.rs:61  -> §5
Deriver:     {basename(source_drv)}                # types.rs:64, optional
Sig:         {name}:{base64}                       # generated   -> §6
```

Reuse `aos_core::nar::info::NarInfo` + `from_path_info` + `format`
(`info.rs:5`,`:129`,`:81`) for the text shaping so the registry static generator
and the dynamic server produce byte-identical narinfo text. The
`PathInfoParams` shape (`info.rs:115`) maps onto `PackageMeta` field-for-field.

> **CURRENT vs TARGET divergence — `URL:` form.** The existing dynamic server
> renders `URL: nar/<path_hash>-<narhash>.nar.zst` (`narinfo.rs:26`), while the
> registry's `apm` blob convention is `<nar_hash>.nar.zst`
> (`download.rs:57`). The static generator must pick **one** scheme and emit
> NAR blobs under matching keys. See [§7](#7-nar-url-and-blob-layout-discrepancy)
> for the recommendation and the open question.

### 4.3 Sysroot images

Sysroot packages carry extra `[[…images]]` entries (`SysrootImageEntry`,
`types.rs:606`–`614`) with their own `store_path` / `nar_hash` / `download_hash`.
Each image is itself a store path and **should also get a `<storehash>.narinfo`**
if it is to be substitutable by Nix. Whether to expose images over the Nix
surface at all is a deployment choice (they are AOS-specific); default to
emitting them so `nix copy` of a full sysroot closure works.

---

## 5. References basename expansion

This is the one field that is *not* a passthrough.

### 5.1 The mismatch

- The registry stores `references` as **bare store-path hashes**
  (`PackageMeta.references`, "Store path hashes of direct runtime references",
  `types.rs:60`–`61`; closures are likewise hash adjacency lists,
  `types.rs:83`–`105`).
- Nix narinfo `References:` requires **basenames**: `<hash>-<name>`
  (e.g. `r4q1m2kp8v3x…-glibc-2.39`), space-separated.

A bare hash is *not* a valid narinfo reference. Nix uses each reference to locate
the *next* `<hash>.narinfo` and to validate the closure; it parses the
`<hash>-<name>` form. A `Sig:` is also computed over the references string
([§6](#6-per-narinfo-ed25519-signature)), so getting this wrong breaks signature
verification too.

### 5.2 The expansion

For each dependency hash `h` in `references`, produce `<h>-<name>` by looking up
the basename of the store path whose hash is `h`. Sources, in priority order:

1. **The `store_path` field of the referenced package's own TOML.** Every
   published store path appears as a `store_path` somewhere in the registry;
   `basename(store_path)` (`info.rs:153`) gives exactly `<hash>-<name>`. Build a
   `hash → basename` index across all package TOMLs in the publish set.
2. **The closure file** (`closures/<hash>`, `types.rs:83`) enumerates the
   members of a closure but stores *hashes only*, so it cannot supply names on
   its own — it must be joined against the index from (1).

```
references (registry)        index lookup            References (narinfo)
─────────────────────        ────────────            ────────────────────
r4q1m2kp8v3x...        ──►   r4q...-glibc-2.39   ──►  r4q1m2kp8v3x...-glibc-2.39
xr5is7by89v3q...       ──►   xr5...-zlib-1.3      ──►  xr5is7by89v3q...-zlib-1.3
```

> **The dynamic server already does this**, but from a different input: it has
> full store paths in `DbPathInfo.refs` and just calls `basename`
> (`narinfo.rs:41`). The registry generator has only *hashes* and must
> reconstruct the basename via the cross-TOML index first, then it can reuse the
> same `basename` primitive.

### 5.3 Self-reference and missing-dependency handling

- If a dependency hash has no `store_path` in the publish set, the closure is
  **incomplete** — the generator must **fail the publish** (a narinfo that
  references an unpublishable path produces a broken cache). This mirrors the
  brief's fail-closed posture (brief
  [§4.5](design-brief.md#45-trust--threat-model-target)).
- Nix permits (and AOS store paths frequently include) self-references; emit them
  the same way — `<own-hash>-<own-name>`.

---

## 6. Per-narinfo Ed25519 signature

### 6.1 Fingerprint

Nix signs a canonical fingerprint string, **not** the narinfo text. Reuse the
existing implementation verbatim (`sign.rs:57`):

```
1;{StorePath};{NarHash};{NarSize};{ref1,ref2,...}
```

- `StorePath` = full `store_path` (with store dir).
- `NarHash` = `sha256:<hex>` exactly as stored (`nar_hash`, `types.rs:54`).
- `NarSize` = `nar_size` (`types.rs:56`).
- References = the **expanded basenames** from [§5](#5-references-basename-expansion),
  joined by **commas** (note: `,` in the fingerprint vs spaces in the
  `References:` line — `sign.rs:58` uses `refs.join(",")`).

Getting the reference *form* right matters twice: the `References:` line is
space-joined basenames; the fingerprint is comma-joined basenames. Both consume
the same expanded list from §5.

### 6.2 Signing

Reuse `NarInfoSigner` (`aos-server/src/sign.rs`):

- Load the secret in `name:base64` form (`sign.rs:14`–`:31`).
- `sign(fingerprint)` → `Some("{name}:{base64sig}")` (`sign.rs:44`–`:54`), using
  the 32-byte ed25519 seed (`sign.rs:49`).
- Append exactly one `Sig:` line per key (`info.rs:106`/`narinfo.rs:56`).

### 6.3 One key, two signatures (brief §4.2)

The secret used here is the **same Ed25519 secret** that signs the registry's git
commits. The brief is explicit
([§4.2](design-brief.md#42-one-ed25519-key-two-protocols)): *the signatures
differ (different signed messages); the key is shared (one secret to manage).*

```
                       ┌──────────────────────────┐
                       │  ONE Ed25519 secret key   │
                       └────────────┬─────────────┘
              ┌─────────────────────┴─────────────────────┐
        SSH-ed25519 sig                              Nix narinfo sig
   over the git commit object                over "1;path;narhash;size;refs"
   (apr sign; security.rs:199)               (NarInfoSigner; sign.rs:44)
              │                                            │
   published pubkey form:                       published pubkey form:
   registry:Ed25519:<b64>                       <name>:<b64>
   (apm TOFU; security.rs:306)         (nix trusted-public-keys; routes/sign)
```

- `apm`'s trust still roots in the **signed git commit** (transitive: signed
  commit → Merkle DAG → every TOML → every NAR hash). The per-narinfo `Sig:`
  exists **only** to satisfy stock `nix` without `require-sigs = false`
  (brief [§4.2](design-brief.md#42-one-ed25519-key-two-protocols),
  [§3.3](design-brief.md#3-key-clarifications-established-in-conversation)).
- See [signing-and-trust.md](../../registry/signing-and-trust.md) for the full
  trust model and key-encoding details.

---

## 7. NAR URL and blob layout (discrepancy)

There are **three** NAR-naming conventions live in the tree today, and the static
generator must reconcile them into one served layout:

| Producer | `URL:` / blob key | Citation |
|---|---|---|
| `apm` registry download | `{mirror}/{nar_hash}.nar.zst` — full `sha256:<hex>` incl. colon | `download.rs:57`–`:60`, test `:282` |
| dynamic server narinfo | `nar/{path_hash}-{narhash-with-dashes}.nar.zst` | `narinfo.rs:26` |
| local NAR cache filename | `{nar_hash with colon→dash}.nar.zst` | `download.rs:232` |

**Recommendation (TARGET):** key the served blob by the **compressed download
hash** and emit `URL: nar/<download_hash>.nar.zst` (matching the brief's mapping
table, which derives `URL` from `download_hash`,
[§4.1](design-brief.md#41-strict-superset-of-the-nix-binary-cache-protocol)). The
`URL:` is **relative** to the narinfo's base, so Nix resolves it against the same
origin. If NARs already live on a separate cache, point `URL:` at an absolute
cache URL instead (Nix accepts absolute `URL:`).

> **Colon-in-filename caveat (brief open question
> [§7.3](design-brief.md#7-open-questions--decisions-to-confirm-during-implementation)).**
> The `sha256:<hex>` form embeds a literal colon. S3 keys permit it; some CDN
> edges re-encode `:`. Preferring `download_hash` for the blob key still leaves
> the colon unless the generator rewrites `:`→`-` (as the local cache filename
> already does, `download.rs:232`). **Decide one canonical on-wire blob key and
> use it in both the `URL:` line and the upload step** — do not let the narinfo
> point somewhere the uploader did not write. This is recorded in
> [open-questions.md](open-questions.md).

NAR **co-location vs separate cache** is a per-deployment choice (brief open
question [§7.2](design-brief.md#7-open-questions--decisions-to-confirm-during-implementation)):
serve `nar/` from the registry origin, or keep blobs on a dedicated cache and
only point `URL:` there. Both are valid; the narinfo is identical except for the
`URL:` base.

---

## 8. `nix-cache-info` stub

A fixed-name file at the origin root (Nix hardcodes the name; brief
[§4.1](design-brief.md#41-strict-superset-of-the-nix-binary-cache-protocol),
[§4.3](design-brief.md#43-single-signed-root-registrytoml-kill-bundle-listtoml)):

```
{base}/nix-cache-info
```

Contents (a static stub, *not* a competing index):

```
StoreDir: /nix/store
WantMassQuery: 1
Priority: 41
```

- **`StoreDir`** must equal the store dir the NARs were built against. For a stock
  Nix host this is `/nix/store`. The dynamic server templates this from its own
  `state.store_dir` (`routes.rs:144`); the static stub bakes in the AOS store dir.
  If AOS store paths use a non-default store dir, **this value must match it
  exactly** or Nix rejects every narinfo.
- **`WantMassQuery: 1`** — allow Nix to query this cache during normal
  substitution (matches the dynamic server, `routes.rs:143`).
- **`Priority`** — lower = preferred. The `41` shown above is an **illustrative
  default**; the dynamic server's value is `30` (`routes.rs:143`). Treat it as an
  **operator policy knob**: pick a value that orders the registry origin sensibly
  relative to the official cache and the dynamic cache (a higher number
  deprioritizes it as a fallback substituter). The brief's mapping table calls out
  `Priority` as part of the stub
  ([§4.1](design-brief.md#41-strict-superset-of-the-nix-binary-cache-protocol))
  without fixing a number.
- The static stub omits the dynamic server's AOS-specific `Capabilities:` line
  (`routes.rs:143`) — that advertises push/SSE features irrelevant to a static
  dumb-HTTP origin.

The `nix-cache-info` file is **separate from `registry.toml`** (workstream-01) by
necessity: Nix hardcodes the filename, while `registry.toml` is the AOS root.
They never collide because their names are disjoint.

---

## 9. Dev-shell substituter wiring

The deliverable for a *consumer* (a non-AOS host that wants AOS artifacts via
plain `nix`): add the registry origin as a substituter and trust its public key.

### 9.1 `nix.conf` (system or per-user)

```ini
extra-substituters = https://registry.aos.dev/core
extra-trusted-public-keys = aos-core:base64pubkeyhere==
```

- The substituter URL is the **registry origin base** — the same `{base}` that
  serves `registry.toml` and bundles. Nix appends `/nix-cache-info` and
  `/<hash>.narinfo` itself.
- The trusted-public-key uses the **`<name>:<base64>`** encoding (one of the two
  forms derived from the single key — [§6.3](#63-one-key-two-signatures-brief-42)).
  The matching `apm` form is `registry:Ed25519:<base64>` (`security.rs:306`).

### 9.2 Flake / per-invocation

```sh
nix develop \
  --extra-substituters    https://registry.aos.dev/core \
  --extra-trusted-public-keys aos-core:base64pubkeyhere==
```

Or pinned in `flake.nix`:

```nix
{
  nixConfig = {
    extra-substituters = [ "https://registry.aos.dev/core" ];
    extra-trusted-public-keys = [ "aos-core:base64pubkeyhere==" ];
  };
}
```

### 9.3 What the host then does

```
nix build / nix develop
   │
   ├─ GET {base}/nix-cache-info        -> StoreDir match? Priority?     (§8)
   ├─ GET {base}/<hash>.narinfo        -> per wanted store path         (§4)
   │     └─ verify Sig: against extra-trusted-public-keys               (§6)
   │     └─ parse References: -> recurse to dependency narinfos         (§5)
   └─ GET {base}/nar/<...>.nar.zst     -> fetch + decompress + verify   (§7)
```

Because the closure is fully expressed by `References:` and every dependency has
its own signed narinfo, a stock `nix` client substitutes the entire AOS closure
with no AOS-specific tooling. See
[nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) for the
user-facing reference version of this recipe.

---

## 10. Implementation tasks

| # | Task | Reuse / new | Anchor |
|---|---|---|---|
| 1 | Cross-TOML `hash → basename` index over the publish set | new | §5.2 |
| 2 | References basename expansion (with fail-closed on missing deps) | new logic, `basename` primitive | §5, `info.rs:153` |
| 3 | Static narinfo generator from `PackageMeta` | reuse `NarInfo`/`from_path_info`/`format` | §4, `info.rs:5`,`:129`,`:81` |
| 4 | Per-narinfo `Sig:` via shared signer | reuse `NarInfoSigner` (lift to shared crate) | §6, `sign.rs` |
| 5 | `nix-cache-info` static stub emitter | new | §8 |
| 6 | Canonical blob key + `URL:` reconciliation | resolve discrepancy | §7 |
| 7 | Sysroot-image narinfos | extend (3) over `SysrootImageEntry` | §4.3, `types.rs:606` |
| 8 | Dev-shell wiring docs + example `nix.conf` | docs | §9 |
| 9 | Hook generation into `apr release` step 3 (pre-flip upload) | integration | [workstream-02](workstream-02-publish-pipeline.md) §4.4 |

> **Refactor note.** `NarInfoSigner` currently lives in `aos-server`
> (`aos-server/src/sign.rs`) and the narinfo text primitives live in `aos-core`
> (`aos-core/src/nar/info.rs`). To let the registry producer (`aos-package`)
> reuse the signer without depending on the whole server crate, lift
> `NarInfoSigner` (or its `sign` + `fingerprint` functions) down into `aos-core`
> alongside the existing `nar::info` module. Both consumers then share one
> implementation, guaranteeing byte-identical narinfos and signatures between the
> static registry surface and the dynamic cache server.

---

## 11. Acceptance criteria

A correct implementation satisfies:

1. **Round-trip parse.** Every generated narinfo parses cleanly via
   `aos_core::nar::info::parse` (`info.rs:19`) and re-serializes to identical
   bytes.
2. **Stock-`nix` substitution.** A host with only `extra-substituters` +
   `extra-trusted-public-keys` set ([§9](#9-dev-shell-substituter-wiring))
   substitutes a full AOS closure (leaf + all transitive deps) with
   `require-sigs = true` (the default) and **no** `--no-check-sigs`.
3. **Signature verifies.** The `Sig:` validates against the `<name>:<base64>`
   public key, proving the fingerprint (and therefore the basename-expanded
   references) is correct ([§6](#6-per-narinfo-ed25519-signature)).
4. **Closure completeness.** Publishing fails if any reference hash has no
   `store_path` in the publish set ([§5.3](#53-self-reference-and-missing-dependency-handling)).
5. **Namespace disjointness.** Adding the Nix surface changes no byte an `apm`
   client fetches; `registry.toml` and `bundles/` are untouched
   ([§2](#2-why-this-is-additive-not-a-rewrite)).
6. **One key.** No new key material: the narinfo `Sig:` and the git-commit
   signature are produced by the same Ed25519 secret
   ([§6.3](#63-one-key-two-signatures-brief-42)).

---

## 12. Cross-references

**Reference (target-state) docs:**
- [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) — the
  user-facing version of this surface.
- [signing-and-trust.md](../../registry/signing-and-trust.md) — one-key trust
  model, both public-key encodings.
- [http-layout.md](../../registry/http-layout.md) — the disjoint-namespace object
  layout.
- [architecture.md](../../registry/architecture.md) — layered model, strict
  superset.
- [current-state.md](../../registry/current-state.md) — as-is grounding.
- [registry-toml.md](../../registry/registry-toml.md),
  [bundles-and-deltas.md](../../registry/bundles-and-deltas.md),
  [publishing.md](../../registry/publishing.md),
  [versioning-and-channels.md](../../registry/versioning-and-channels.md),
  [apt-comparison.md](../../registry/apt-comparison.md),
  [README](../../registry/README.md).

**Plan docs:**
- [design-brief.md](design-brief.md) — grounding intent (§4.1, §4.2).
- [gap-analysis.md](gap-analysis.md) — producer/consumer gaps.
- [workstream-01-registry-root.md](workstream-01-registry-root.md),
  [workstream-02-publish-pipeline.md](workstream-02-publish-pipeline.md),
  [workstream-04-channels-rollouts.md](workstream-04-channels-rollouts.md),
  [workstream-05-consumer.md](workstream-05-consumer.md),
  [open-questions.md](open-questions.md),
  [README](README.md).
