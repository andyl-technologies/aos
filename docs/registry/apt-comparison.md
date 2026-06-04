# AOS Registry vs. APT — Comparison & Adopted Improvements

> **Audience:** users, implementers, architects, engineers.
>
> **Scope:** This document maps the AOS package registry design onto the
> Debian/Ubuntu **APT repository format**, explains where the two converge,
> where AOS deliberately differs, and which APT features the AOS design
> **adopts** — prioritized into Tier 1 / Tier 2 / Tier 3. It is the reference
> companion to the design brief's §5 (comparison) and §6 (improvements).
>
> **Grounding:** [`docs/plans/registry/design-brief.md`](../plans/registry/design-brief.md)
> §5–§6 is the authoritative intent source for this document.

This page describes **TARGET** state unless a row or note is explicitly marked
**CURRENT**. The as-is behavior of the code is documented in
[`current-state.md`](./current-state.md); the implementation work required to
reach the target is enumerated in
[`docs/plans/registry/gap-analysis.md`](../plans/registry/gap-analysis.md).

---

## 1. Why compare to APT at all?

APT is the canonical proof that a **signed flat-file index served over dumb
HTTP** scales to thousands of independent, untrusted mirrors. It needs no smart
server, no database, no per-request computation on the origin: a client fetches
one known, inline-signed root file, validates the signature, and from there
resolves every index and package by content hash.

The AOS registry design **converges on the same shape** — a single inline-signed
root (`registry.toml`) over dumb HTTP, with S3 listing as an *optional* admin
fast-path rather than a correctness requirement. Comparing to APT is therefore
not an academic exercise: it lets AOS borrow a battle-tested security and
distribution discipline (inline signing, `by-hash`, `Valid-Until`, pdiff,
components, phased rollouts) instead of reinventing it.

Where the two genuinely diverge, AOS is generally **ahead**, because its
metadata lives in a **git Merkle DAG** and its blob store **is** a Nix binary
cache. Those two structural facts give AOS atomic compare-and-swap publishes,
signed history, fork/rollback detection, and content-addressed deduplication for
free — properties APT bolts on (or lacks).

See [`architecture.md`](./architecture.md) for the layered model and the
dumb-HTTP-lowest-common-denominator philosophy, and
[`http-layout.md`](./http-layout.md) for the concrete object layout the
comparison below references.

---

## 2. Structure of an APT repository (quick reference)

For readers unfamiliar with APT, the relevant pieces are:

```
dists/
  <suite>/                         e.g. stable, bookworm
    InRelease                      inline-signed root: index list + hashes + Valid-Until
    Release / Release.gpg          detached-signature variant of the above
    <component>/                   e.g. main, contrib, non-free
      binary-<arch>/
        Packages[.gz/.xz]          stanzas: Package, Filename->pool, Size, SHA256, Depends
        Packages.diff/Index        pdiff: incremental Packages updates
      Contents-<arch>.gz           file index: which package ships which path
    by-hash/SHA256/<hash>          content-addressed copies of the index files
pool/
  <component>/<l>/<src>/<pkg>.deb  the actual packages, content-organized
```

The **trust root** is `InRelease`: one file that is signed *inline* (signature
and payload in one object, fetched atomically) and that enumerates every index
file together with its size and SHA-256. From a validated `InRelease`, every
other file is pinned by hash. `Valid-Until` bounds how long a signed root may be
trusted, which defends against a mirror **freezing** clients on an old (but
validly signed) snapshot.

---

## 3. Side-by-side comparison

The table below pairs each APT mechanism with its AOS (target) counterpart. The
AOS column links to the reference doc that specifies it in detail.

| APT mechanism | AOS registry (TARGET) | Reference |
|---|---|---|
| `InRelease` — inline-signed root: index list + hashes + `Valid-Until` | `registry.toml` — inline-signed root: bundle index + hashes + `valid_until` + signed `[latest]` pointer | [`registry-toml.md`](./registry-toml.md) |
| OpenPGP / GPG signature | Ed25519, **one key** producing two signature forms (SSH-commit signature + Nix narinfo signature) | [`signing-and-trust.md`](./signing-and-trust.md) |
| `Packages` stanzas (`Package`, `Filename`→pool, `Size`, `SHA256`, `Depends`) | Per-package TOML (`packages/<x>/<name>.toml`) + `*.narinfo` for Nix; dependencies expressed as **explicit closures**, not a `Depends` solver field | [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) |
| `pool/…/<pkg>.deb` — content-organized package files | `nar/<hash>.nar.zst` — content-addressed blobs + `bundles/<name>/*.bundle` git bundles | [`http-layout.md`](./http-layout.md) |
| `dists/<suite>/<component>/binary-<arch>/` partitioning | registry name + optional `[components]` + per-version `platforms.<platform>` | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `by-hash/SHA256/<h>` — consistency under concurrent publish | native content-addressed keys + atomic root flip; root references everything **by hash** | [`http-layout.md`](./http-layout.md) |
| `Packages.diff/Index` — pdiff incremental index | snapshot / sequential-delta / skip-delta git bundles, ordered by `creation_token`; delta index lives **inside** `registry.toml` | [`bundles-and-deltas.md`](./bundles-and-deltas.md) |
| `Valid-Until` — time-based freshness bound | `valid_until` (expiry) **plus** monotonic `[latest].token` (sequence) | [`registry-toml.md`](./registry-toml.md) |
| dumb-HTTP, static-mirror-friendly | dumb-HTTP as the lowest common denominator; **S3 `ListObjects` is an admin bonus**, never required | [`architecture.md`](./architecture.md) |
| `signed-by=` per-source key pinning | per-registry key pinning via TOFU + `trusted-keys.d/<registry>.pub` | [`signing-and-trust.md`](./signing-and-trust.md) |
| `snapshot.debian.org` reproducible archives | reproducible snapshots are intrinsic: git tags address immutable commits | [`bundles-and-deltas.md`](./bundles-and-deltas.md) |
| Phased updates (`Phased-Update-Percentage`) | `[channels]` target with `rollout = N`, gated on a deterministic machine-id hash | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `Components` (`main` / `contrib` / `non-free`) | `[components]` — optional intra-registry trust / license / stability partitions | [`versioning-and-channels.md`](./versioning-and-channels.md) |
| `Contents-<arch>` — file → package index | (target, Tier 2) `Provides` / file-index for "which package ships `/usr/bin/foo`" | §5 below |

---

## 4. Where AOS deliberately differs (and improves)

These are not gaps to close — they are structural choices that make AOS stronger
than APT on the same axis.

### 4.1 Git Merkle-DAG metadata instead of regenerated flat `Packages`

APT regenerates flat `Packages` / `Release` files on every publish and relies on
rsync mirror discipline to propagate them without tearing. AOS metadata is a
**git repository** distributed as bundles. Consequences:

- **Atomic compare-and-swap publish.** `apr push` is a fast-forward-only
  `git push`; the atomic ref update *is* the publish lock. There is no separate
  lock service and no rsync race window. See [`publishing.md`](./publishing.md).
- **Signed history.** The Ed25519-signed commit authenticates the entire tree as
  a Merkle DAG; every TOML and every NAR hash is transitively authenticated by
  one signature. See [`signing-and-trust.md`](./signing-and-trust.md).
- **Rollback / fork detection.** `git merge-base --is-ancestor` distinguishes
  fast-forward, same-commit, downgrade, and divergence — APT has no equivalent
  native history check.

### 4.2 A content-addressed store that *is* a Nix binary cache

APT's `pool/` holds `.deb` archives. AOS blobs are content-addressed
`nar/<hash>.nar.zst` objects that double as a stock Nix binary cache: the same
origin serves both the `apm` (AOS) protocol and the Nix narinfo protocol from
**disjoint URL namespaces**, making Nix support a strict superset rather than a
fork. See [`nix-cache-compatibility.md`](./nix-cache-compatibility.md).

### 4.3 Explicit closures instead of a `Depends` solver

APT ships `Depends` strings and resolves them with a SAT-style solver at install
time. AOS records **explicit, pre-computed dependency closures** (`closures/<hash>`
adjacency lists + `references` hash lists in each package TOML). There is no
runtime solver: the closure is exact, reproducible, and already authenticated.

### 4.4 One Ed25519 key serving two protocols

APT uses an OpenPGP key for the archive. AOS uses **one Ed25519 keypair** that
produces *two* signature forms from the same secret: an SSH-format signature over
the git commit (consumed by `apm` and transitively authenticating everything),
and a Nix narinfo `Sig:` over the `(StorePath, NarHash, NarSize, References)`
fingerprint (consumed by stock `nix` so substitution works without
`require-sigs = false`). One secret to manage, two published public-key
encodings. See [`signing-and-trust.md`](./signing-and-trust.md).

---

## 5. Where AOS is already at parity or ahead

These APT capabilities have direct AOS equivalents that already exist or are
already planned — they are **Tier 3** below ("do not re-add"):

| Capability | APT | AOS equivalent | Status |
|---|---|---|---|
| Per-repo key pinning | `signed-by=` | TOFU + `trusted-keys.d/<registry>.pub` | **CURRENT** (see [`current-state.md`](./current-state.md) §2.10) |
| Reproducible snapshots | `snapshot.debian.org` | git tags address immutable commits | **CURRENT** |
| Incremental updates | `Packages.diff` (pdiff) | snapshot / sequential / skip bundle deltas | **CURRENT** (consumer; producer writer is a gap) |
| Atomic publish | rsync mirror discipline | git fast-forward CAS push | **CURRENT** |
| Single-file inline-signed root | `InRelease` | `registry.toml` | **TARGET** (planned; today the root is `bundle-list.toml`, not inline-signed) |

> **CURRENT vs TARGET note.** Today the consumer reads a separate
> `bundle-list.toml` manifest, and there is **no producer-side writer** for it
> (the manifest types are deserialize-only). The single inline-signed
> `registry.toml` root is the **TARGET**. See
> [`current-state.md`](./current-state.md) and
> [`docs/plans/registry/workstream-01-registry-root.md`](../plans/registry/workstream-01-registry-root.md).

The only thing AOS borrows from APT in this row is the **Index-file *shape*** —
APT's explicit `from` / `to` / `hash` per delta — for expressing bundle deltas
inside `registry.toml`. It does **not** re-add APT's flat regenerated index.

---

## 6. APT improvements adopted (prioritized)

The design conversation produced a prioritized list of APT features to **adopt**
into AOS. They are grouped by urgency.

### Tier 1 — close real gaps

These four are the features that "change the product." The first two are
**correctness / security**; the last two are **operational**.

| # | Feature | What it buys | Cost / approach |
|---|---|---|---|
| 1 | **`valid_until` signed expiry** | Freeze defense. A mirror cannot pin clients on a validly-signed-but-stale root forever; the sequence-based `[latest].token` alone cannot detect freeze. | Cheap. Re-sign each publish with `valid_until = publish_time + N`. Client rejects an expired root. |
| 2 | **`by-hash` discipline for index references** | Torn-publish safety. A client that read `root@T` resolves a *consistent* set of bundles/indices even if `root@T+1` lands mid-fetch. | Mostly discipline atop existing content-addressing: the root references bundles **by their hashed key**. |
| 3 | **Symbolic channels decoupled from tags** | Promotion UX. `[channels] stable = "v2026.02.3"`; promotion is one atomic signed flip; clients track `channel = "stable"` instead of pinning a tag. | New `[channels]` table in the signed root + consumer tracking mode. |
| 4 | **Phased / staged rollouts** | Fleet blast-radius control. Canary a release to N% of machines before full rollout. (APT `Phased-Update-Percentage`.) | `rollout = N` on a channel target; clients gate on a deterministic hash of `machine-id` (+ channel/tag). |

```toml
# TARGET: the four Tier-1 features expressed in registry.toml (illustrative;
# registry-toml.md is authoritative for the full root schema).
[meta]
schema      = 1                          # integer schema version
valid_until = "2026-06-17T00:00:00Z"   # Tier 1.1 — freeze defense

[latest]
tag            = "v2026.02.3"
creation_token = 2026020003             # monotonic; anti-rollback anchor
head           = "…authentic git commit SHA…"

[channels.stable]                        # Tier 1.3 + 1.4 — subtable, not inline
tag            = "v2026.02.3"
creation_token = 2026020003             # per-channel monotonic anti-rollback
rollout        = 25                      # percent (omit or 100 = fully rolled out)

[channels.testing]
tag            = "v2026.03.0"
creation_token = 2026030000

[[bundles]]                              # Tier 1.2 — referenced by hash
uri            = "aos-core-v2026.02.3.bundle"
type           = "snapshot"
tag            = "v2026.02.3"
creation_token = 2026020003
sha256         = "sha256:…"              # the by-hash key (algo-prefixed)
size           = 4096
```

See [`registry-toml.md`](./registry-toml.md) for the full root schema and
[`versioning-and-channels.md`](./versioning-and-channels.md) for the channel and
rollout semantics.

### Tier 2 — worth it, lower urgency

| # | Feature | APT analogue | Notes |
|---|---|---|---|
| 5 | **Components within a registry** | `main` / `contrib` / `non-free` | Trust / license / stability tiers in one signed root, via `[components]`. |
| 6 | **Capability flags in the signed root** | `Acquire-By-Hash: yes` | Advertise optional features so clients can degrade gracefully and stay forward-compatible. |
| 7 | **Hash agility** | n/a | Explicit algorithm prefixes everywhere (already `sha256:`); tolerate multiple so a future hash migration is not a flag day. |
| 8 | **Provides / file-index** | `Contents-<arch>` | "Which package ships `/usr/bin/foo`" — a discoverability win Nix normally needs `nix-index` for. |
| 9 | **Bundle mirror list with priority + failover** | n/a | Extend the existing `[[caches]]` priority/failover model (today used for NAR mirrors) to bundle mirrors. |

### Tier 3 — already covered, or AOS ahead (do **not** re-add)

These are the parity/ahead items from §5: per-repo key pinning, reproducible
snapshots, pdiff-style incremental updates, atomic publish, and the single-file
inline-signed root. The **only** thing borrowed here is APT's Index-file shape
(explicit `from` / `to` / `hash` per delta) for expressing deltas inside
`registry.toml`. Re-adding APT's regenerated flat `Packages` index would be a
regression.

---

## 7. Summary

```
                 APT                          AOS registry (target)
        ┌─────────────────────┐        ┌──────────────────────────────┐
root    │ InRelease (signed)  │   ≈    │ registry.toml (inline-signed) │
        │  + Valid-Until      │        │  + valid_until + [latest]     │
sign    │ OpenPGP             │   →    │ Ed25519 (one key, two forms)  │
index   │ Packages (flat)     │   ↑    │ git Merkle-DAG bundles        │ AOS ahead
deltas  │ pdiff               │   ≈    │ snapshot/sequential/skip      │
blobs   │ pool/*.deb          │   ↑    │ nar/*.nar.zst (= Nix cache)   │ AOS ahead
deps    │ Depends (solver)    │   ↑    │ explicit closures             │ AOS ahead
consist │ by-hash             │   ≈    │ content-addressed + atomic flip│
chan    │ suites/components   │   ≈    │ [channels]/[components]       │
rollout │ Phased-Update-%     │   ≈    │ rollout = N (machine-id hash) │
trust   │ signed-by=          │   ≈    │ TOFU + trusted-keys.d/        │
fresh   │ snapshot.debian.org │   ↑    │ immutable git tags            │ AOS ahead
        └─────────────────────┘        └──────────────────────────────┘
          ≈ parity      ↑ AOS structurally ahead     → reuses APT idea
```

**Adopt:** `valid_until`, `by-hash` discipline, symbolic channels, phased
rollouts (Tier 1); components, capability flags, hash agility, file-index,
bundle mirror failover (Tier 2).
**Borrow only the shape of:** APT's per-delta `from`/`to`/`hash` index entry.
**Do not re-add:** regenerated flat `Packages`, OpenPGP, `Depends` solver,
rsync-mirror publish.

---

## See also

- [`README.md`](./README.md) — registry reference index and glossary.
- [`architecture.md`](./architecture.md) — layered model, dumb-HTTP-LCD, strict superset.
- [`current-state.md`](./current-state.md) — the as-is implementation and producer gaps.
- [`http-layout.md`](./http-layout.md) — wire/object layout, namespaces, by-hash.
- [`registry-toml.md`](./registry-toml.md) — the signed root schema.
- [`bundles-and-deltas.md`](./bundles-and-deltas.md) — bundle model and `creation_token`.
- [`nix-cache-compatibility.md`](./nix-cache-compatibility.md) — Nix strict-superset details.
- [`signing-and-trust.md`](./signing-and-trust.md) — one Ed25519 key, TOFU, threat model.
- [`publishing.md`](./publishing.md) — producer workflow and atomic publish ordering.
- [`versioning-and-channels.md`](./versioning-and-channels.md) — channels, rollouts, components.
- Plan: [`docs/plans/registry/design-brief.md`](../plans/registry/design-brief.md) §5–§6 (grounding),
  [`gap-analysis.md`](../plans/registry/gap-analysis.md),
  [`workstream-04-channels-rollouts.md`](../plans/registry/workstream-04-channels-rollouts.md).
