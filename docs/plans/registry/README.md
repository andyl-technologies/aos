# AOS Registry — Implementation Plan

> **Status:** Plan overview. This is the entry point for the registry
> implementation effort. It summarizes the **target state**, maps the
> **gaps** between today's code and that target, and sequences the work into
> five workstreams. It does **not** restate design rationale — that lives in
> the [design brief](./design-brief.md), which is the authoritative source of
> intent for every doc in this set.
>
> **Audience:** users, implementers, architects, and engineers.
>
> **Reading order:** start here, read the [design brief](./design-brief.md) in
> full, skim the [gap analysis](./gap-analysis.md), then dive into the
> workstream you own.

---

## 1. What this plan is

The AOS package registry already has a **rich consumer** (`apm update` /
`apm upgrade`: bundle selection, semver tracking, signature verification,
incremental deltas) and a **thin producer** (`apr` is little more than `git`
plus `git bundle create`). The registry HTTP origin today serves *only* git
bundles of TOML metadata — it is **not** a Nix binary cache and cannot be
consumed by a stock `nix` substituter.

This plan closes that asymmetry and lifts the registry to the **target design**
captured in the [design brief §4](./design-brief.md):

- A single **inline-signed `registry.toml` root** that replaces
  `bundle-list.toml`, carries the bundle/delta index by hash, and anchors
  freshness with a signed `[latest]` pointer and a `valid_until` expiry.
- The registry HTTP origin becomes a **strict superset of the Nix binary-cache
  protocol** — `apm` and stock `nix` consume disjoint URL namespaces from one
  origin, authenticated by **one Ed25519 key** in two encodings.
- A real **publish pipeline** (`apr release`) that generates bundles, narinfos,
  and `nix-cache-info` from a landed, signed commit, uploads immutable
  content-addressed objects first, and **flips the root last, atomically**.
- **Symbolic channels** (`stable`, `testing`) decoupled from tags, with
  **phased rollouts**, **components**, and **capability flags** — the
  operational features borrowed from APT.

> **CURRENT vs TARGET labeling.** Throughout this doc set, *as-is* code behavior
> is labeled **CURRENT** and cited as `path:line`; the design goal is labeled
> **TARGET**. Where the code contradicts the brief's current-state narrative,
> the code wins and the discrepancy is recorded in
> [open-questions.md](./open-questions.md).

---

## 2. Target-state summary

The target architecture is three layers served from one dumb-HTTP origin. Dumb
HTTP is the **lowest common denominator**; S3 `ListObjects` is an *optional*
admin fast-path, never required for correctness.

```
                    ┌──────────────────────────────────────────────┐
                    │            Registry HTTP origin               │
                    │      (dumb HTTP LCD; S3 listing = bonus)      │
                    └──────────────────────────────────────────────┘
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        │                                                              │
   AOS namespace (apm)                                  Nix namespace (stock nix)
        │                                                              │
  /registry.toml ◄── inline-signed root            /nix-cache-info ◄── generated stub
     ├─ [meta] valid_until                          /<storehash>.narinfo ◄── per-path,
     ├─ [latest] tag/token/head (signed)                                   Ed25519 Sig:
     ├─ [channels] stable/testing + rollout         /nar/<…>.nar.zst ◄── content-addressed
     ├─ [components]                                                   (shared blobs)
     └─ bundle/delta index (by-hash)
  /bundles/<name>/<uri> ◄── git bundles
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        │  Trust root: ONE Ed25519 key                                 │
        │   • SSH-format signature on the git commit (Merkle DAG)      │
        │   • narinfo (StorePath,NarHash,NarSize,References) signature │
        │   • two published pubkey encodings (registry:… and name:…)   │
        └──────────────────────────────────────────────────────────────┘
```

Key properties of the target (see [design brief §4](./design-brief.md)):

| Property | Mechanism | Brief |
|---|---|---|
| One signed root | `registry.toml`, inline-signed like APT `InRelease` | §4.3 |
| Strict superset | disjoint URL namespaces (`apm` vs `nix`) on one origin | §4.1 |
| One key, two protocols | Ed25519: SSH-commit sig + narinfo sig, two pubkey encodings | §4.2 |
| Atomic publish | git FF CAS lands the commit; conditional-PUT flips the root last | §4.4 |
| Freeze defense | `valid_until` expiry in the signed root | §4.5 / §6 |
| Torn-publish safety | `by-hash` references — root@T resolves a consistent set | §4.3 / §6 |
| Promotion UX | symbolic `[channels]` decoupled from tags | §6 |
| Fleet blast-radius | phased `rollout = N` gated on machine-id hash | §6 |

### The four features that change the product

From [design brief §6](./design-brief.md), the prioritized improvements that
matter most:

1. **`valid_until` signed expiry** (correctness/security — freeze defense).
2. **`by-hash` discipline** (correctness/security — torn-publish safety).
3. **Symbolic channels** (operational — promotion UX).
4. **Phased rollouts** (operational — fleet blast-radius control).

Everything else is either parity with existing behavior or a Tier-2/3 nice-to-have.

---

## 3. Where we are today (CURRENT, in brief)

The full as-is picture, grounded in code with `path:line` citations, lives in
[gap-analysis.md](./gap-analysis.md) and (reference form) in
[../../registry/current-state.md](../../registry/current-state.md). The
headline asymmetry from [design brief §2.11](./design-brief.md):

| Capability | Consumer | Producer |
|---|---|---|
| Parse `bundle-list.toml` | present | — |
| **Write** `bundle-list.toml` / `registry.toml` | n/a | **absent** |
| `creation_token` encode/decode | present | **absent** (encode unused on producer) |
| Classify snapshot/sequential/skip | present (read-time) | **absent** |
| Select minimal bundle set (`pick_bundles`) | present | n/a |
| Upload bundles to mirror/S3 | — | **absent** |
| narinfo / `nix-cache-info` emission | n/a | **absent** |
| Persist `[registry.state]` | present | n/a |
| Inline-signed `registry.toml` root | n/a | **absent** (today's root is unsigned `registry.toml`; index lives in `bundle-list.toml`) |

In short: the consumer can do almost everything the target requires of it; the
producer is a thin `git` wrapper with **no manifest writer, no token
computation, no upload, and no Nix-cache emission**.

---

## 4. Milestone roadmap

The work is staged so each milestone is independently shippable and leaves the
registry in a consistent, deployable state.

| Milestone | Theme | Delivers | Primary workstreams |
|---|---|---|---|
| **M0** | Grounding | Confirmed schemas, gap map, reference docs | [gap-analysis](./gap-analysis.md), `docs/registry/*` |
| **M1** | Signed root | `registry.toml` schema + serializer + inline signing + by-hash refs | [WS-01](./workstream-01-registry-root.md) |
| **M2** | Publish pipeline | `apr release` end-to-end (generate → upload → atomic flip) | [WS-02](./workstream-02-publish-pipeline.md) |
| **M3** | Nix cache | narinfo + `nix-cache-info` + per-narinfo `Sig` + substituter wiring | [WS-03](./workstream-03-nix-cache.md) |
| **M4** | Channels & rollouts | symbolic channels, phased rollouts, components, `valid_until` | [WS-04](./workstream-04-channels-rollouts.md) |
| **M5** | Consumer cutover | read `registry.toml` root, channel tracking, expiry/by-hash/fail-closed | [WS-05](./workstream-05-consumer.md) |

```
 M0 ──► M1 ──► M2 ──► M3
        │       │
        └──► M4 ─┘
                 │
                 ▼
                M5  (consumer reads the new root once it exists)
```

Notes on the dependency edges:

- **M1 → M2.** The publish pipeline cannot flip a root it cannot write; the
  serializer (WS-01) is the prerequisite for `apr release` (WS-02).
- **M1 → M4.** Channels, rollouts, components, and `valid_until` are *fields of*
  the signed root, so WS-04 extends the WS-01 schema rather than inventing a new
  surface.
- **M2/M4 → M5.** The consumer cutover (WS-05) should not read `registry.toml`
  as the authoritative root until a producer can publish one; M5 lands after the
  producer can emit the new root.
- **M3 is parallelizable.** Nix-cache emission shares the publish ordering of WS-02
  but touches a disjoint URL namespace, so it can proceed alongside M4 once the
  root and pipeline exist.

---

## 5. Workstreams

Each workstream is a self-contained design + task doc. They map onto the
authoring specs in [design brief §8](./design-brief.md).

| # | Workstream | Scope | Brief refs |
|---|---|---|---|
| 01 | [Registry root](./workstream-01-registry-root.md) | `registry.toml` schema, the missing serializer (writer), inline signing, by-hash references | §4.3 |
| 02 | [Publish pipeline](./workstream-02-publish-pipeline.md) | `apr release` ordering, bundle + manifest generation, `creation_token` computation, upload backends, git CAS + conditional PUT | §4.4 |
| 03 | [Nix cache](./workstream-03-nix-cache.md) | narinfo + `nix-cache-info` emission, references basename expansion, per-narinfo Ed25519 `Sig`, dev-shell substituter wiring | §4.1, §4.2 |
| 04 | [Channels & rollouts](./workstream-04-channels-rollouts.md) | symbolic channels, phased rollouts, components, `valid_until` / freshness, capability flags | §4.3, §4.5, §6 |
| 05 | [Consumer](./workstream-05-consumer.md) | read `registry.toml` root, channel tracking, expiry/freeze checks, by-hash fetch, fail-closed omission | §4.4, §4.5 |

### Workstream sequencing rationale

WS-01 is the keystone: the **single missing serializer** (today the manifest
types are `Deserialize`-only — [design brief §2.4, §2.11](./design-brief.md))
unblocks every producer capability. WS-02 turns that writer into an operational
pipeline with the safe publish ordering. WS-03 is the additive Nix-cache
superset, sharing WS-02's ordering but a disjoint namespace. WS-04 layers the
operational features onto the WS-01 schema. WS-05 flips the consumer to the new
root only after a producer can publish it, and is the last to land.

---

## 6. Cross-references

### Plan set (`docs/plans/registry/`)

- [design-brief.md](./design-brief.md) — the captured design conversation and
  decision log. **Authoritative for intent.** Read in full before implementing.
- [gap-analysis.md](./gap-analysis.md) — current vs target, enumerated
  producer/consumer gaps, mapped to workstreams.
- [open-questions.md](./open-questions.md) — unresolved decisions, risks, and
  migration strategy (including whether `bundle-list.toml` mirrors get a
  compatibility shim or a clean schema-version break).
- Workstreams [01](./workstream-01-registry-root.md) ·
  [02](./workstream-02-publish-pipeline.md) ·
  [03](./workstream-03-nix-cache.md) ·
  [04](./workstream-04-channels-rollouts.md) ·
  [05](./workstream-05-consumer.md).

### Reference set (`docs/registry/`, describes the **TARGET** state)

- [README](../../registry/README.md) — reference-set entry point, glossary, doc index.
- [architecture.md](../../registry/architecture.md) — layered model, dual
  consumption, dumb-HTTP-LCD philosophy, strict-superset idea.
- [current-state.md](../../registry/current-state.md) — the as-is, grounded in code.
- [http-layout.md](../../registry/http-layout.md) — wire/object layout, namespaces,
  by-hash, object keys, bundle key grammar.
- [registry-toml.md](../../registry/registry-toml.md) — the signed root schema with
  an annotated example.
- [bundles-and-deltas.md](../../registry/bundles-and-deltas.md) — bundle model,
  `creation_token`, snapshot/sequential/skip, `pick_bundles`.
- [nix-cache-compatibility.md](../../registry/nix-cache-compatibility.md) — strict
  superset, narinfo mapping, substituter usage.
- [signing-and-trust.md](../../registry/signing-and-trust.md) — one Ed25519 key,
  TOFU/trusted-keys, transitive authentication, threat model.
- [publishing.md](../../registry/publishing.md) — producer workflow & concurrency.
- [versioning-and-channels.md](../../registry/versioning-and-channels.md) —
  versioning, tracking modes, channels, rollouts, components.
- [apt-comparison.md](../../registry/apt-comparison.md) — the APT comparison and
  adopted improvements.

---

## 7. Glossary (quick reference)

Full definitions live in [design brief §1](./design-brief.md). The terms you
need to read this plan:

- **`apm`** — the package-management CLI front-end (`aos` dispatched by `argv[0]`).
- **`apr`** — the AOS Package Registry CLI (the producer side).
- **Registry** — a **git repository of TOML metadata** distributed over HTTP and
  consumed by `apm`. It is *not* the blob store.
- **NAR** — the serialized store-path build artifact; content-addressed,
  zstd-compressed.
- **Bundle** — a `git bundle` packing the registry repo (or a delta) for dumb HTTP.
- **`creation_token`** — monotonic integer ordering bundles:
  `year*1_000_000 + month*10_000 + patch`.
- **narinfo** — the per-store-path metadata file of the standard Nix binary-cache
  protocol.
- **Producer / Consumer** — the `apr` (mutate/publish) and `apm` (sync/install)
  sides; the asymmetry this plan closes.
