# AOS Package Registry — Reference Documentation

This directory is the **reference documentation set** for the AOS package
registry: the git-distributed metadata repository that `apm` (the AOS package
manager) consumes, and that `apr` (the AOS Package Registry CLI) publishes. The
reference docs describe the **target design**; where the current code differs,
each doc labels **CURRENT** vs **TARGET** and cites code as `path:line`. The
companion implementation plan that turns the current state into the target lives
under [`../plans/registry/`](../plans/registry/README.md).

> **Authoritative intent.** Every doc in this set is derived from, and must not
> contradict, the design brief:
> [`../plans/registry/design-brief.md`](../plans/registry/design-brief.md).
> Rule of precedence: **for current state, the code wins; for intent, the brief
> wins.**

---

## One-paragraph overview

An AOS registry is a **git repository of TOML metadata** (per-package files under
`packages/<x>/<name>.toml` plus a `closures/<hash>` adjacency index), distributed
over **dumb HTTP** as `git bundle` files and consumed by `apm update` /
`apm upgrade`. It is deliberately **not** the blob store: the actual build
artifacts (NARs — serialized, zstd-compressed Nix store paths) live on a separate
content-addressed cache referenced from the registry's `[[caches]]` list. Trust
roots in a **single Ed25519 key** that signs the git commit; because git is a
Merkle DAG, that one signature transitively authenticates every TOML and, through
the SHA-256 hashes recorded in them, every NAR. The target design collapses the
distribution root to **one inline-signed `registry.toml`** (replacing today's
`bundle-list.toml`), adds APT-style freshness (`valid_until`), symbolic channels,
and phased rollouts, and makes the same HTTP origin a **strict superset** of the
standard Nix binary-cache protocol — so a stock `nix` substituter can use it for
dev-shell builds without `require-sigs = false`. The two protocols coexist
because they occupy **disjoint URL namespaces**.

---

## Purpose & scope

This reference set answers, for the AOS registry's **target state**:

- *What is on the wire* — the HTTP object layout, URL namespaces, and the
  signed-root schema.
- *How clients consume it* — `apm`'s git-bundle sync and incremental update, and
  a stock `nix` substituter's narinfo/NAR path.
- *How it is trusted* — one Ed25519 key, two signature forms, TOFU + pinned keys,
  and the threat model it defends.
- *How it is published* — the producer (`apr`) workflow, git fast-forward CAS as
  the concurrency lock, and the atomic root flip.
- *How it relates to prior art* — a structured comparison to the APT repository
  format, whose well-precedented "signed flat-file index over dumb HTTP" the
  design converges on.

It does **not** specify the implementation tasks; those are enumerated in the
[plan set](../plans/registry/README.md).

---

## Audience map

| You are a… | Start here | Then read |
|---|---|---|
| **User** running `apm` / `apr` | [publishing.md](publishing.md), [versioning-and-channels.md](versioning-and-channels.md) | [signing-and-trust.md](signing-and-trust.md) |
| **Dev-shell user** wanting a Nix substituter | [nix-cache-compatibility.md](nix-cache-compatibility.md) | [http-layout.md](http-layout.md) |
| **Implementer** writing producer/consumer code | [current-state.md](current-state.md), [registry-toml.md](registry-toml.md) | [bundles-and-deltas.md](bundles-and-deltas.md), [http-layout.md](http-layout.md), the [plan workstreams](../plans/registry/README.md) |
| **Architect** evaluating the design | [architecture.md](architecture.md), [apt-comparison.md](apt-comparison.md) | [signing-and-trust.md](signing-and-trust.md), [design brief](../plans/registry/design-brief.md) |
| **Security engineer** assessing trust | [signing-and-trust.md](signing-and-trust.md) | [publishing.md](publishing.md), [registry-toml.md](registry-toml.md) |

---

## Document index

### Reference set (`docs/registry/`, target state)

| Document | What it covers |
|---|---|
| [README.md](README.md) | This file — purpose, audience map, glossary, doc index, overview. |
| [architecture.md](architecture.md) | Layered model (trust root / metadata / blobs), how `apm` and `nix` both consume, the dumb-HTTP lowest-common-denominator philosophy, and the strict-superset idea. |
| [current-state.md](current-state.md) | The as-is implementation, grounded in code (`crates/aos-package/`), including the producer-side gaps. |
| [http-layout.md](http-layout.md) | Wire/object layout: the AOS vs Nix URL namespaces, dumb-HTTP vs S3 `ListObjects`, by-hash references, object keys, and the bundle key grammar. |
| [registry-toml.md](registry-toml.md) | The single inline-signed root schema, with a full annotated example. |
| [bundles-and-deltas.md](bundles-and-deltas.md) | The bundle model, `creation_token`, snapshot / sequential / skip deltas, the `pick_bundles` selection algorithm, and incremental update. |
| [nix-cache-compatibility.md](nix-cache-compatibility.md) | The strict-superset design: narinfo field mapping, `nix-cache-info`, NAR layout, and an example dev-shell substituter config. |
| [signing-and-trust.md](signing-and-trust.md) | One Ed25519 key, git + narinfo signatures, TOFU / `trusted-keys.d`, transitive authentication, and the threat model. |
| [publishing.md](publishing.md) | Producer workflow & concurrency: `apr` commands, git fast-forward CAS lock, the atomic publish ordering, and conditional-PUT root flip. |
| [versioning-and-channels.md](versioning-and-channels.md) | Calendar/semver versioning, tracking modes, symbolic channels, phased rollouts, and components. |
| [apt-comparison.md](apt-comparison.md) | A structured APT-format comparison and the prioritized list of APT improvements the design adopts. |

### Plan set (`docs/plans/registry/`, implementation)

| Document | What it covers |
|---|---|
| [README.md](../plans/registry/README.md) | Plan overview, target summary, milestone roadmap, sequencing. |
| [design-brief.md](../plans/registry/design-brief.md) | The captured design conversation + decision log (the grounding source). |
| [gap-analysis.md](../plans/registry/gap-analysis.md) | Current vs target, enumerated producer/consumer gaps, mapped to workstreams. |
| [workstream-01-registry-root.md](../plans/registry/workstream-01-registry-root.md) | `registry.toml` schema, the missing serializer, inline signing, by-hash references. |
| [workstream-02-publish-pipeline.md](../plans/registry/workstream-02-publish-pipeline.md) | `apr release` ordering, bundle + manifest generation, `creation_token` computation, upload backends, git CAS + conditional PUT. |
| [workstream-03-nix-cache.md](../plans/registry/workstream-03-nix-cache.md) | narinfo + `nix-cache-info` emission, references basename expansion, per-narinfo Ed25519 `Sig`, dev-shell substituter wiring. |
| [workstream-04-channels-rollouts.md](../plans/registry/workstream-04-channels-rollouts.md) | Symbolic channels, phased rollouts, components, `valid_until` / freshness, capability flags. |
| [workstream-05-consumer.md](../plans/registry/workstream-05-consumer.md) | Consumer changes: read the `registry.toml` root, channel tracking, expiry/freeze checks, by-hash fetch, fail-closed omission. |
| [open-questions.md](../plans/registry/open-questions.md) | Open decisions, risks, and migration strategy. |

---

## How the pieces fit (orientation diagram)

The registry is one layer of three. The signed git metadata authenticates the
blobs but does not store them; clients of two different protocols read from the
same HTTP origin.

```
                         ┌──────────────────────────────────────────┐
                         │            HTTP origin (dumb HTTP)         │
                         │  disjoint URL namespaces on one host:      │
                         │                                            │
   apm (AOS) ───────────▶│  /registry.toml         (signed root)      │
   git bundle sync       │  /bundles/<name>/...    (git bundles)      │
                         │                                            │
   nix (substituter) ───▶│  /nix-cache-info        (stub)             │
   narinfo + NAR         │  /<storehash>.narinfo   (per store path)   │
                         │  /nar/<...>.nar.zst     (content-addressed)│
                         └──────────────────────────────────────────┘
                                          │
              trust roots in ONE Ed25519 key:
   signed git commit ──(Merkle DAG)──▶ every TOML ──(SHA-256)──▶ every NAR
              + per-narinfo Sig: (Nix form of the same key, for stock `nix`)
```

> **CURRENT vs TARGET.** Today only the AOS namespace exists, and its root is
> `bundle-list.toml`, not a single signed `registry.toml`; the Nix namespace and
> the inline-signed root are **TARGET**. See [current-state.md](current-state.md)
> for the grounded as-is and [architecture.md](architecture.md) for the target.

---

## Glossary

| Term | Definition |
|---|---|
| **AOS** | ANDYL OS. The hermetic-from-source, Nix-based distribution this registry serves. |
| **`apm`** | The package-management CLI front-end. The **same binary** as `aos`, dispatched by `argv[0]`: invoked as `apm …` it implicitly prepends `package …`. (`crates/aos/src/main.rs:37`–`68`.) |
| **`apr`** | The AOS Package Registry CLI. The same binary again; invoked as `apr …` it implicitly prepends `package registry …`. The `apr` bin alias is declared in `crates/aos/Cargo.toml` (`[[bin]] name = "apr"`). |
| **Registry** | A **git repository of TOML metadata** (`packages/<x>/<name>.toml` + `closures/<hash>`), distributed over HTTP and consumed by `apm`. It is *not* the blob store. |
| **Producer side** | The `apr` operations that mutate and publish a registry. |
| **Consumer side** | The `apm update` / `apm upgrade` operations that sync and install. |
| **NAR** | Nix ARchive — the serialized form of a store path; the actual build artifact. Stored content-addressed and zstd-compressed (`<hash>.nar.zst`). |
| **Bundle** | A `git bundle` file packing the registry git repo (or a delta of it) so it can be distributed over dumb HTTP. |
| **`creation_token`** | A monotonic integer derived from a calendar-version tag, used to order bundles: `year*1_000_000 + month*10_000 + patch`. |
| **Snapshot / sequential delta / skip delta** | The three bundle kinds. A snapshot packs the whole repo; a sequential delta carries one step; a skip delta jumps from a minor base tag to a later tag. |
| **narinfo** | The per-store-path text metadata file of the standard Nix binary-cache HTTP protocol (`StorePath`, `URL`, `NarHash`, `References`, `Sig`, …). |
| **`nix-cache-info`** | A fixed-name Nix stub file (`StoreDir`, `Priority`, `WantMassQuery`) that marks an HTTP origin as a binary cache. |
| **TOFU** | Trust On First Use — a registry's signing key is pinned the first time it is seen (from the root's `signing.public_key`) unless already admin-provisioned in `trusted-keys.d/`. |
| **`registry.toml`** | **TARGET** single inline-signed distribution root that replaces `bundle-list.toml`, carrying the bundle index, `[latest]` pointer, `[channels]`, `valid_until`, and the Ed25519 pubkey. |
| **`[latest]`** | **TARGET** signed pointer (`tag`, `token`, `head`) in `registry.toml` — the freshness / anti-rollback anchor a dumb-HTTP listing cannot provide. |
| **Channel** | **TARGET** symbolic alias (e.g. `stable`, `testing`) mapping to a concrete tag, optionally with a rollout percentage; clients track the channel name, not the tag. |
| **Rollout** | **TARGET** phased-update percentage on a channel target; clients gate on a deterministic hash of their machine-id (analogous to APT `Phased-Update-Percentage`). |
| **Component** | **TARGET** optional intra-registry partition (trust / license / stability tier), analogous to APT `main`/`contrib`/`non-free`. |
| **by-hash** | The discipline (from APT `by-hash`) of referencing index objects by their content hash so a client that read root@T resolves a consistent set even after the root advances to T+1. |
| **`valid_until`** | **TARGET** APT-style signed expiry in the root; a client rejects an expired root, defending against a mirror frozen on a validly-signed-but-old root. |
| **`[[caches]]`** | The list of NAR cache/mirror URLs (each with a `priority`) recorded in the registry root; consumers resolve NARs from these, falling back to `{registry.url}/nar`. |

---

## Conventions used across these docs

- **CURRENT** marks behavior that exists in the code today, cited as `path:line`
  (relative to repo root, crate `crates/aos-package/` unless noted).
- **TARGET** marks the intended design from the
  [design brief](../plans/registry/design-brief.md) that is not yet implemented.
- All inter-doc links are **relative** so the set is browsable from a checkout or
  a static site.
- Where the code contradicts a brief current-state claim, the docs describe the
  code's actual behavior and the discrepancy is recorded in the relevant doc's
  open-questions and in [`open-questions.md`](../plans/registry/open-questions.md).
