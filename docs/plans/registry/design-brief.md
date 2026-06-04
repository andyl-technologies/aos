# AOS Registry — Design Brief & Decision Log

> **Status:** Design capture. This document is the verbatim-intent record of the
> design conversation that produced the `docs/registry/` reference set and the
> `docs/plans/registry/` implementation plan. It is the **grounding source** for
> every other registry document. When a reference or plan doc disagrees with the
> code, the code wins for *current state* and this brief wins for *intent*.
>
> **Audience:** implementers, architects, engineers, and the doc-authoring
> agents that derive the reference/plan docs from it.

---

## 0. How this brief came to be

This brief captures a working design conversation about the AOS package registry.
The conversation moved through, in order:

1. How the registry, `apr` commands, and git bundles work **today**.
2. The producer/consumer **asymmetry** (consumer is rich; producer is a stub).
3. A correction: the **registry HTTP server is self-contained** (git bundles +
   manifest only); it is **not** the NAR/binary-cache server.
4. Whether the registry could **also** be a Nix binary-cache substituter for
   non-AOS dev-shell hosts — and the conclusion that it can be a **strict
   superset** because the protocols occupy disjoint URL namespaces.
5. **Signing**: one Ed25519 key, SSH-format git commit signatures, transitive
   authentication of NARs via the signed commit, and reuse of the *same key* for
   Nix narinfo signatures.
6. **Publishing & concurrency**: `apr push` is just `git push`; the FF-only ref
   update is the only concurrency guard; there are no locks; "latest" is derived,
   not pointed to; `bundle-list.toml` is a poor name for a root.
7. The decision to **collapse to a single signed `registry.toml` root** and serve
   over **dumb HTTP as the lowest common denominator**, with **S3 as an optional
   admin fast-path**, keeping the index **inside the registry files**.
8. A structured comparison to the **APT repository format**, which the design
   converges on, and a prioritized list of **APT improvements to adopt**.

Everything below is the distilled, decision-level record of that conversation.

---

## 1. Glossary

- **AOS** — ANDYL OS. Hermetic-from-source Nix-based distribution.
- **`apm`** — the package-management CLI front-end. Same binary as `aos`,
  dispatched by `argv[0]`: `apm …` ⇒ implicit `package …`.
- **`apr`** — the AOS Package Registry CLI. Same binary; `apr …` ⇒ implicit
  `package registry …` (`crates/aos/src/main.rs`, argv[0] detection ~lines 37–61;
  binary alias declared in `crates/aos/Cargo.toml` `[[bin]] name = "apr"`).
- **Registry** — a **git repository of TOML metadata** (`packages/<x>/<name>.toml`
  + `closures/<hash>`), distributed over HTTP and consumed by `apm`. It is *not*
  the blob store.
- **Producer side** — `apr` operations that mutate and publish a registry.
- **Consumer side** — `apm update`/`apm upgrade` operations that sync and install.
- **NAR** — Nix ARchive, the serialized form of a store path; the actual build
  artifact. Stored content-addressed and zstd-compressed.
- **Bundle** — a `git bundle` file packing the registry git repo (or a delta of
  it) so it can be distributed over dumb HTTP.
- **`creation_token`** — a monotonic integer derived from a calendar version tag
  used to order bundles. `year*1_000_000 + month*10_000 + patch`.
- **Snapshot / sequential delta / skip delta** — the three bundle kinds.
- **narinfo** — the per-store-path text metadata file of the standard Nix binary
  cache HTTP protocol.

---

## 2. Current state (as-is) — grounded facts

All paths relative to repo root. Crate is `crates/aos-package/` unless noted.

### 2.1 CLI dispatch
- `crates/aos/Cargo.toml` declares two `[[bin]]` targets, `aos` and `apr`, both
  `path = "src/main.rs"`.
- `main.rs` (~37–61) inspects `argv[0]`'s file name (tolerating a `-unwrapped`
  suffix): `apr` ⇒ prepend `package registry`; `apm` ⇒ prepend `package`.
- All registry producer logic lives in `crates/aos-package/src/registry_ops.rs`
  (module doc: *"Registry management operations ('apr' / 'apm registry')"*).

### 2.2 Storage layout (local)
From `types.rs` (~466–513) and `registry_ops.rs:28` (`registry_dir`):

| Scope | Producer git repo (`apr` writes) | Consumer cache (`apm update` writes) |
|-------|----------------------------------|--------------------------------------|
| user  | `~/.local/share/apm/registries/{name}/` | `~/.local/share/apm/remote/{name}/` |
| system| `/var/lib/apm/registries/{name}/`       | `/var/lib/apm/remote/{name}/`        |

- Per-registry config: `~/.config/apm/registries.d/{name}.toml` (or `/etc/apm/…`).
- Trusted keys: `~/.config/apm/trusted-keys.d/{registry}.pub` (and system dirs);
  see `types.rs` `trusted_keys_dirs()` (~501–513).
- Registry repo root file: `registry.toml` inside the repo, schema
  `RegistryRootConfig { registry, caches: Vec<CacheEntry>, signing:
  Option<RegistrySigningConfig> }` (`types.rs` ~566–599). `[[caches]]` entries
  carry `url` + `priority`; `signing` carries `public_key`.

### 2.3 Registry git repo contents
- `packages/<x>/<name>.toml` — per-package metadata. Established fields from the
  conversation (implementers MUST confirm exact names against `types.rs`):
  `[package]` → name, description, license, maintainer, sysroot (bool),
  homepage. `[[versions]]` → version, previous.
  `[versions.platforms.<platform>]` → store_path, nar_hash, nar_size,
  download_hash, download_size, closure_size, source_drv, source_nar_hash,
  references (list of dependency **hashes**), and `[[…images]]` (format,
  store_path, nar_hash) for sysroot images.
- `closures/<hash>` — adjacency list: `<root-hash> <dep-hash> <dep-hash> …` per
  line; leaves have no deps.

### 2.4 Bundle distribution (HTTP transport) — consumer side
- `registry/bundle.rs`:
  - `BundleType { Snapshot, SequentialDelta, SkipDelta }` (~22–31).
  - `BundleEntry { uri, creation_token, sha256, size, bundle_type, base_tag,
    target_tag }` (~34–45).
  - `BundleManifest { registry, version, entries }` parsed from
    `bundle-list.toml` (`ManifestToml`/`BundleEntryToml` are **`Deserialize`
    only** — there is no serializer).
  - `BundleManifest::fetch` (~100) builds URL
    `{base_url}/bundles/{registry_name}/bundle-list.toml`.
  - `download_bundle` (~251) → `{base_url}/bundles/{registry_name}/{entry.uri}`,
    verified with SHA-256.
  - `verify_bundle` (~305) → SHA-256 match **and** `git bundle verify`.
  - `unbundle` (~376) → `git bundle unbundle` into the consumer cache repo.
  - `classify_delta(from,_to)` (~227–243) → a delta whose `from` tag has ≤2
    dotted parts (a minor base `vYYYY.MM`) is a **SkipDelta**; otherwise
    **SequentialDelta**.
  - Manifest helpers (~180–224): `entries_since(token)`, `latest_snapshot()`,
    `skip_delta_from(base_tag)`, `sequential_deltas_between(from,to)`.

### 2.5 Semver + version selection — consumer side
- Dependency: standard `semver` crate (`Cargo.toml`).
- `types.rs` `TrackingMode { Commit, Branch, Tag, Version(semver::VersionReq),
  Default }` (~277–305); `RegistryConfig::tracking_mode()` validates **at most
  one** of commit/branch/tag/version is set (~307–401).
- `update.rs`:
  - `parse_tag_as_semver` (~429–450): strip `v`, strip leading zeros, pad
    2-component tags to `.0`. `v2026.02` → `2026.2.0`, `v2026.02.3` → `2026.2.3`.
  - `find_best_version_tag_in_manifest` (~393–424): filter manifest tags by the
    `VersionReq`, pick the **highest** matching; non-semver tags skipped.
  - `pick_bundles` (~291–391): the incremental selection algorithm (see §2.6).
- `registry/state.rs`:
  - `version_to_token` (~123–166): `year*1_000_000 + month*10_000 + patch`;
    rejects non `vYYYY.MM[.P]`, month 1–12, patch ≤ 9999.
  - `token_to_version` (~168–184): inverse; patch 0 renders as a 2-part base tag.
  - `check_monotonic` (~101–117): rejects `new_token <= old_token` (downgrade /
    stale-mirror defense).

### 2.6 `pick_bundles` selection algorithm (consumer)
Given the manifest, persisted `RegistryState`, and `TrackingMode`:
1. **Tag mode** → snapshot with matching `target_tag`, else any delta targeting it.
2. **Commit mode** → bundle transport can't resolve arbitrary commits; falls
   through to default.
3. **Version mode** → `find_best_version_tag_in_manifest`, then snapshot/delta to it.
4. **No prior state** → `latest_snapshot()`.
5. **Up to date** (`entries_since(current)` empty) → `[]`.
6. **Incremental** (have state): (a) **skip delta** from current minor base if a
   newer one exists; else (b) **sequential delta chain** with
   `current < token <= latest`; else (c) **latest snapshot** fallback.

### 2.7 State persistence
- `RegistryState { last_commit, last_creation_token, last_update }`
  (`types.rs` ~253–262), serialized under `[registry.state]` in the per-registry
  config file. `sync_bundle` updates all three after a successful sync (~269–272).

### 2.8 NAR download (separate from the registry)
- `download.rs`: `nar_url(mirror_url, nar_hash)` → `{mirror_url}/{nar_hash}.nar.zst`
  where `nar_hash` is the full `sha256:<hex>` string (the filename literally
  contains a colon). `resolve_mirror` (~67–82) reads `[[caches]]` from the local
  registry clone (sorted by priority), falling back to `{registry.url}/nar`.
- NARs are verified by **SHA-256 content hash**, not by signature.

### 2.9 Git transport (alternative to bundles)
- `git://`, `git+https://`, `git+ssh://` URLs use `registry/git.rs`: `git fetch`,
  fast-forward enforcement, optional commit-signature verification, then extract
  TOMLs into the cache. URL scheme selects transport (`types.rs` ~315–323):
  `http(s)://` ⇒ HttpBundle, `git*` ⇒ Git.

### 2.10 Signing & trust — current
- `apr sign` = `git commit --amend --no-edit -S` (`registry_ops.rs:1770`).
- `apr tag` supports `--message`/`--key`; `apr push` = `git push [-u origin]
  [branch] [--force]` (`registry_ops.rs:1410–1442`).
- `security.rs`:
  - `verify_commit_signature` (~199–233): builds a temporary `allowed_signers`
    file (`registry ssh-ed25519 <pubkey>`) and runs `git -c
    gpg.ssh.allowedSignersFile=… verify-commit <commit>`. **SSH-format Ed25519**
    signatures.
  - `parse_signing_key` (~306+): key string format `registry:algorithm:base64key`;
    **rejects any algorithm but `Ed25519`**. Example `aos-core:Ed25519:base64…`.
  - TOFU: a key is either admin-provisioned in `…/trusted-keys.d/{registry}.pub`
    or accepted on first use from the registry's `signing.public_key`, then pinned.
  - `check_downgrade` (~256–296): `git merge-base --is-ancestor` →
    FastForward / SameCommit / Downgrade / Diverged.

### 2.11 Producer-side gaps (the asymmetry)
The producer is a thin wrapper over `git` plus `git bundle create`. **Absent:**
- No `bundle-list.toml` **writer** anywhere (manifest types are `Deserialize`-only).
- `apr bundle` (`registry_ops.rs:1718`) only runs `git bundle create` into a local
  `bundles/` dir; its `_update_manifest` parameter is **unused dead code**.
- No producer-side `creation_token` computation (the encode fn exists in
  `state.rs` but is only called consumer-side).
- No automatic delta-type classification on the producer (`--tag`/`--delta-from`
  are passed manually).
- No upload of bundles to a mirror/CDN/S3 (the only upload code in the tree is in
  `aos-cache`, and that's for NARs, not bundles).
- No narinfo / `nix-cache-info` emission.
- No locks/atomicity beyond git's own FF-rejection on push.
- No "latest" pointer (derived by scanning the manifest for max `creation_token`).

| Capability | Consumer | Producer |
|---|---|---|
| Parse `bundle-list.toml` | ✅ | — |
| **Write** `bundle-list.toml` | n/a | ❌ |
| `creation_token` encode/decode | ✅ | ❌ |
| Classify snapshot/sequential/skip | ✅ (read-time) | ❌ |
| Select minimal bundle set | ✅ | n/a |
| Upload bundles | — | ❌ |
| narinfo / nix-cache-info | n/a | ❌ |
| Persist `[registry.state]` | ✅ | n/a |

---

## 3. Key clarifications established in conversation

1. **The registry HTTP server is self-contained**: it serves only
   `{base}/bundles/{name}/bundle-list.toml` and `{base}/bundles/{name}/{uri}`
   (git bundles of TOML metadata). It is **not** the NAR server. NAR blobs live
   on a separate cache/mirror (`[[caches]]` or `{registry.url}/nar`).
2. The registry today is **not** a Nix binary cache and cannot be consumed by a
   stock `nix` substituter (git bundles ≠ narinfo; no `nix-cache-info`).
3. **NARs are authenticated transitively**: the Ed25519-signed git commit
   authenticates the whole tree (git is a Merkle DAG) → every TOML → every NAR
   SHA-256 recorded in those TOMLs. There is no per-NAR signature today, and the
   AOS client does not need one.

---

## 4. Target design (the decisions)

### 4.1 Strict superset of the Nix binary-cache protocol
The registry HTTP origin will serve **both** protocols, which occupy **disjoint
URL namespaces**, so adding Nix support is additive (a strict superset), not a
conflict:

- Nix protocol (consumed by stock `nix` for dev-shell substitution):
  - `{base}/nix-cache-info` (fixed name; `StoreDir`, `Priority`, `WantMassQuery`).
  - `{base}/<storehash>.narinfo` (keyed by 32-char base32 **store-path** hash).
  - `{base}/nar/<…>.nar.zst` (content-addressed blobs).
- AOS protocol (consumed by `apm`):
  - `{base}/registry.toml` (the single signed root — see §4.3).
  - `{base}/bundles/{name}/…` (git bundles, discovered via the root's index).

Nix's narinfo indirection (store-hash narinfo → content-addressed nar) is exactly
how AOS already names blobs, so the models align. The package TOMLs already carry
nearly every narinfo field:

| narinfo | AOS package TOML | notes |
|---|---|---|
| StorePath | store_path | |
| URL | derived (`nar/<download_hash>.nar.zst`, relative) | |
| Compression | constant `zstd` | |
| FileHash / FileSize | download_hash / download_size | compressed `.nar.zst` |
| NarHash / NarSize | nar_hash / nar_size | uncompressed |
| References | references | ⚠️ must expand bare hashes → `<hash>-<name>` basenames |
| Deriver | source_drv | optional |
| **Sig** | — | **must be generated (Ed25519)** |

What must be built: a narinfo generator keyed by store-path hash, a
`nix-cache-info` stub, co-located/served NAR blobs, references-basename
expansion, and per-narinfo Ed25519 signatures.

### 4.2 One Ed25519 key, two protocols
- **Same keypair** signs git commits (SSH signature) **and** narinfos (Nix
  `(StorePath,NarHash,NarSize,References)` fingerprint). The *signatures differ*
  (different signed messages); the *key is shared* (one secret to manage).
- **Two published public-key encodings** from that one key: `registry:Ed25519:
  <base64>` for `apm` TOFU, and `<name>:<base64>` for Nix `trusted-public-keys`.
- `apm`'s trust still roots in the signed commit (transitive). The per-narinfo
  `Sig:` exists **only** to satisfy stock `nix` without `require-sigs = false`.

### 4.3 Single signed root: `registry.toml` (kill `bundle-list.toml`)
- Collapse the root to **one** signed file, `registry.toml`. `bundle-list.toml`
  is removed; its bundle enumeration moves **into** `registry.toml`.
- `nix-cache-info` remains a separate file only because Nix hardcodes its name —
  it is a generated stub, not a competing index.
- **Dumb HTTP is the lowest common denominator.** Normal clients fetch the one
  known root file; they never rely on directory listing. **S3 `ListObjects` is an
  optional admin fast-path** (richer queries), never required for correctness.
  Therefore the enumerated index lives **inside the registry files**.
- The root must be **inline-signed** (single object, like APT `InRelease`) so a
  client fetches root+signature atomically with no race.
- The root references bundles/indices **by hash** (APT `by-hash` discipline) so a
  client that read root@T still resolves a consistent set even after root@T+1.

Proposed `registry.toml` (target) carries at least:
- `[meta]` schema/version, `name`, `date`, **`valid_until`** (freeze defense),
  `[capabilities]` feature flags.
- `pubkey` (Ed25519; both encodings derivable).
- **`[latest]`** signed pointer: `tag`, `token`, `head` (authentic git commit
  SHA) — the freshness / anti-rollback anchor a dumb-HTTP listing can't provide.
- **`[channels]`** symbolic aliases (`stable`, `testing`) → concrete tags, each
  optionally with a **rollout** percentage (phased updates).
- **`[components]`** optional intra-registry partitions (trust/license/stability).
- Bundle/delta tables (by-hash): per bundle `uri`/key, `creation_token`, `type`,
  `from`/`to` tags, `sha256`, `size` — the pdiff-style delta index.
- The inline signature line(s).

### 4.4 Publishing & concurrency model
- **Git ref CAS is the lock.** `apr push` is FF-only `git push`; the atomic ref
  update serializes publishes for free. Losers get non-FF rejection and
  `pull --rebase` + retry. No separate lock service.
- **Publish ordering** (the only safe order):
  1. `apr publish` → commit → `apr sign` (SSH-Ed25519) → `git push` (CAS winner).
  2. Only the winner generates artifacts from the landed commit: bundles,
     narinfos, `nix-cache-info`.
  3. Upload **immutable, content-addressed** objects first (nars, `*.narinfo`,
     `*.bundle`) — idempotent, any order.
  4. **Flip the root last, atomically** — `registry.toml` via conditional PUT
     (S3 `If-Match`/`If-None-Match` ETag CAS) to prevent lost updates. Readers see
     old-root or new-root, never torn, because everything the new root references
     already exists.
- "Latest" becomes an **explicit signed field** (`[latest]`), flipped atomically
  as the last step — not re-derived by scanning.

### 4.5 Trust / threat model (target)
- **Tamper / MITM**: signed root + signed commit + content hashes ⇒ bytes are
  pinned; a mirror cannot substitute content.
- **Rollback**: `check_monotonic` on `[latest].token` + git
  `merge-base --is-ancestor` (no ancestor regressions).
- **Freeze** (mirror stuck on a validly-signed-but-old root): add APT-style
  **`valid_until`** expiry to the signed root; a client rejects an expired root.
  Sequence-based `[latest]` alone can't see this.
- **Omission** (listing hides newer bundles): with the signed `[latest].head`,
  the client **fails closed** (can't reach the signed target) rather than
  silently using stale data; freeze degrades to DoS, not silent rollback.

---

## 5. APT comparison (why this design is well-precedented)

APT is the canonical proof that a **signed flat-file index over dumb HTTP** scales
to thousands of mirrors. The AOS design converges on it.

| APT | AOS registry (target) |
|---|---|
| `InRelease` (inline-signed root: indices + hashes + `Valid-Until`) | `registry.toml` (inline-signed root: bundle index + hashes + `valid_until` + `[latest]`) |
| OpenPGP/GPG signature | Ed25519 (one key: SSH-commit + narinfo forms) |
| `Packages` stanzas (`Filename`→pool, Size, SHA256, `Depends`) | bundle index in root; `*.narinfo` for Nix; deps as **explicit closures** not `Depends` |
| `pool/` content-organized `.deb`s | `nar/<…>.nar.zst` content-addressed + `bundles/*.bundle` |
| `dists/<suite>/<component>/binary-<arch>/` | registry name + component + platform |
| `by-hash/SHA256/<h>` (consistency) | content-addressed keys + atomic root flip (native) |
| `Packages.diff/Index` (pdiff) | snapshot/sequential/skip bundle deltas + `creation_token` |
| `Valid-Until` (time freshness) | `valid_until` + monotonic `[latest].token` |
| dumb-HTTP, static-mirror-friendly | dumb-HTTP LCD; S3 listing = admin bonus |

**Where AOS deliberately differs / improves:** git Merkle-DAG metadata (atomic
CAS push, signed history, rollback/fork detection) instead of regenerated flat
`Packages`; content-addressed store that *is* a Nix cache; explicit closures
instead of solver `Depends`; one Ed25519 key serving two protocols.

**Where AOS is already at parity or ahead:** per-repo key pinning (TOFU +
`trusted-keys.d` ≈ APT `signed-by=`); reproducible snapshots (git tags ≈/≥
snapshot.debian.org); incremental updates (bundle deltas ≈ pdiff); atomic publish
(git FF CAS ≥ APT rsync mirror races); single-file inline-signed root (`registry.
toml` ≈ `InRelease`).

---

## 6. APT improvements to adopt (prioritized feature list)

### Tier 1 — close real gaps
1. **`valid_until` signed expiry** — freeze defense the current sequence-based
   `[latest]` can't provide. Cheap. Re-sign each publish with expiry = publish + N.
2. **`by-hash` discipline for index references** — the root references bundles by
   their hashed key so a client mid-publish never tears. Mostly discipline atop
   existing content-addressing.
3. **Symbolic channels decoupled from tags** — `[channels] stable = "v2026.02.3"`;
   promotion is one atomic signed flip; clients track `channel = "stable"`.
4. **Phased / staged rollouts** — `rollout = N` on a channel target; clients gate
   on a deterministic hash of machine-id. Canary releases / blast-radius control
   for fleets. (APT `Phased-Update-Percentage`.)

### Tier 2 — worth it, lower urgency
5. **Components within a registry** (`main/contrib/non-free` analogue) — trust /
   license / stability tiers in one signed root.
6. **Capability flags in the signed root** — advertise optional features for
   graceful degradation + forward compat (APT `Acquire-By-Hash: yes`).
7. **Hash agility** — explicit algorithm prefixes everywhere (already `sha256:`);
   tolerate multiple so a future migration isn't a flag day.
8. **Provides / file-index** (APT `Contents-<arch>`) — "which package ships
   `/usr/bin/foo`"; a discoverability win Nix usually needs `nix-index` for.
9. **Bundle mirror list w/ priority + failover** — extend the `[[caches]]`
   priority model to bundle mirrors.

### Tier 3 — already covered or AOS ahead (do not re-add)
- Per-repo key pinning (have it), reproducible snapshots (git tags), pdiff
  (bundle deltas), atomic publish (git FF CAS), single-file inline-signed root
  (planned). Borrow only APT's *Index-file shape* (explicit from/to/hash per
  delta) for expressing deltas inside `registry.toml`.

**The four that change the product:** `valid_until` (freeze defense), `by-hash`
discipline (torn-publish safety), symbolic channels (promotion UX), phased
rollouts (fleet blast-radius control). The first two are correctness/security;
the last two are operational.

---

## 7. Open questions / decisions to confirm during implementation

1. Exact `packages/*.toml` field names/shape — confirm against `types.rs` before
   enshrining in the reference schema doc.
2. NAR co-location: serve NARs under `{base}/nar/` on the registry origin, or keep
   them on a separate cache and only point narinfo `URL:` at it? (Both work; pick
   per deployment.)
3. narinfo `URL:` colon-in-filename (`sha256:<hex>.nar.zst`) — confirm acceptable
   through the chosen CDN/edge (S3 allows colons; some edges re-encode).
4. Rollout gating function — exact deterministic hash (machine-id + channel/tag)
   and how clients learn their percentage bucket.
5. `valid_until` window length and re-sign cadence/automation.
6. Whether `apr` gains a real `apr publish-bundles`/`apr release` command that
   performs the §4.4 ordering end-to-end (generate → upload → flip), and whether
   upload backends are pluggable (S3, rsync, plain PUT).
7. Migration: do existing `bundle-list.toml` mirrors get a compatibility shim, or
   is this a clean break with a schema-version bump?

---

## 8. Document map (authoring specs)

The reference set (`docs/registry/`) describes the **target state** for users,
implementers, architects, engineers. The plan set (`docs/plans/registry/`)
describes **what must change** to reach it. Every doc must cross-link siblings
with relative links, cite current code as `path:line` where describing as-is
behavior, and clearly label **CURRENT** vs **TARGET** where both appear.

**`docs/registry/` (reference / target state):**
- `README.md` — purpose, audience map, glossary, doc index, one-paragraph overview.
- `architecture.md` — layered model (trust root / metadata / blobs), how `apm`
  and `nix` both consume, dumb-HTTP-LCD philosophy, the strict-superset idea.
- `current-state.md` — the as-is (§2), grounded in code, including the producer gaps.
- `http-layout.md` — wire/object layout (§4.1, §4.3): namespaces, dumb-HTTP vs S3,
  by-hash, object keys, bundle key grammar.
- `registry-toml.md` — the signed root schema (§4.3) with a full annotated example.
- `bundles-and-deltas.md` — bundle model, `creation_token`, snapshot/sequential/
  skip, `pick_bundles` selection, incremental update (§2.4–2.6).
- `nix-cache-compatibility.md` — strict superset (§4.1): narinfo mapping,
  `nix-cache-info`, nar layout, dev-shell substituter usage + example config.
- `signing-and-trust.md` — one Ed25519 key (§4.2), git + narinfo signatures, TOFU
  / trusted-keys, transitive authentication, threat model (§4.5).
- `publishing.md` — producer workflow & concurrency (§4.4): `apr` commands, git
  CAS lock, atomic publish ordering, conditional-PUT root flip.
- `versioning-and-channels.md` — calendar/semver versioning, tracking modes,
  symbolic channels, phased rollouts, components.
- `apt-comparison.md` — §5 comparison + §6 adopted improvements.

**`docs/plans/registry/` (implementation plan):**
- `README.md` — plan overview, target summary, milestone roadmap, sequencing,
  links to design-brief + workstreams.
- `design-brief.md` — **this file** (the captured conversation + decisions).
- `gap-analysis.md` — current vs target, enumerated producer/consumer gaps (§2.11),
  mapped to workstreams.
- `workstream-01-registry-root.md` — `registry.toml` schema, serializer (the
  missing writer), inline signing, by-hash references.
- `workstream-02-publish-pipeline.md` — `apr release` ordering, bundle + manifest
  generation, `creation_token` computation, upload backends, git CAS + conditional
  PUT.
- `workstream-03-nix-cache.md` — narinfo + `nix-cache-info` emission, references
  basename expansion, per-narinfo Ed25519 `Sig`, dev-shell substituter wiring.
- `workstream-04-channels-rollouts.md` — symbolic channels, phased rollouts,
  components, `valid_until`/freshness, capability flags.
- `workstream-05-consumer.md` — consumer changes: read `registry.toml` root,
  channel tracking, expiry/freeze checks, by-hash fetch, fail-closed omission.
- `open-questions.md` — §7 plus risks and migration strategy.
