## Problem

An AOS registry is a SHA-256 git repository served as static files over
dumb-HTTP from an S3/R2 bucket behind a CDN
(`docs/registry/architecture.md`). The committed tree carries
`registry.toml`, `packages/<x>/<name>.toml`, `closures/`, and the
signing roster `keys.toml`; beside the git surface live release packs
and thin deltas (`releases/<M>/<m>/<P>/pack/`), 256-partition channel
pointers (`channels/<name>/00..ff`, each a signed tag object), and a
standard Nix binary cache (`nix-cache-info`, `*.narinfo`,
`nar/*.nar.zst`). Trust is entirely client-side: SSH-format Ed25519
signatures on tags and commits, in-band roster rotation, anti-rollback
floors, and staleness windows
(`crates/aos-package/src/registry/verify.rs`,
`docs/registry/signing-and-trust.md`).

This design deliberately requires no server to consume — and today it
offers no server to *manage*, either. Every interaction with a registry
goes through the CLIs:

- **Producers** (registry maintainers) drive the whole publish pipeline
  with `apr`: `publish`, `tag`, `channel advance`, `keys
  add`/`retire`, `cache generate`, `origin upload`, or the `apr
  release` orchestrator (`crates/aos-package/src/registry_ops.rs`).
- **Consumers** (AOS host operators) configure and sync with `apm`:
  `registries.d/<name>.toml`, `apm update`, `apm install`/`upgrade`
  (`crates/aos-package/src/types.rs`).

What is missing:

- **No human-readable view of a registry.** A consumer deciding whether
  to trust `https://cdn.aos.andyl.org/` sees raw object-store listings
  at best. Debian's plain APT directory indexes set a *floor* here; we
  currently sit below it — there is no way to browse packages,
  versions, channels, rollout state, or trust anchors without cloning
  the repo.
- **No multi-tenancy or identity anywhere.** The registry model has a
  single key roster per registry and no notion of organizations,
  projects, users, roles, or per-registry access control. Multiple
  maintainers share a roster; multiple teams must run disjoint
  registries with hand-managed credentials.
- **No managed write path.** Producers need direct S3 credentials (or
  an `aos-server` provisioning token) plus local signing keys; there is
  no way to grant a teammate "may publish to this registry" without
  handing over bucket access.
- **No operational visibility.** Channel rollout state (which of the
  256 partitions point where), freshness of the frontier, signature
  health, pack/delta availability, and **binary-cache completeness**
  (does every published package actually resolve in every advertised
  cache?) are observable only by running `apr channel status` /
  `apr validate` against a local clone.

Meanwhile the building blocks for a server-side surface already exist:
`aos-server` speaks ConnectRPC (`aos.{cache,build,gc,auth}.v1` in
`crates/aos-proto/`), has a proven two-tier token model (long-lived
hashed provisioning tokens exchanged at `/oauth2/token` for short-lived
JWTs — `crates/aos-server/src/tokens.rs`, `auth.rs`), and
`aos-cache`'s HTTP backend already knows how to authenticate and batch
uploads against that surface (`crates/aos-cache/src/backend/http.rs`).

## Goal

Ship an open-source registry management WebUI as a new crate,
**`aos-registry-hub`** ("the hub"), that:

1. is written in Rust targeting WASM, runs on Cloudflare Workers
   (D1 + R2) and as a native binary (axum) for self-hosting — operators
   or users of AOS can run their own instance easily, down to a fully
   functional local instance on sqlite + filesystem storage;
2. exposes the full registry feature set to both audiences — anonymous
   consumers get a verified, rich, no-JS-required browse surface (the
   Debian directory listing, done right); authenticated producers get
   publish, channel rollout, key roster, token, and configuration
   management;
3. is **multi-tenant** (organizations), **multi-project** (hierarchical
   teams), **multi-user** (full IAM), and **multi-registry** — with
   first-class models for storage buckets, CDN frontends, cache
   mirrors/stacks, and registry mirroring;
4. speaks buf-compliant protobuf over ConnectRPC, sharing one schema
   between browser, CLIs, and third parties;
5. remains **backwards-compatible as a plain Nix binary cache** and as
   a dumb-HTTP git origin — every registry URL the hub serves is
   simultaneously a substituter URL and an `apm` origin;
6. uses sqlite as the primary database (Cloudflare D1 is its
   sqlite-dialect twin), with postgres and mysql supported by phase 4;
7. integrates with `aos`/`apr`/`apm` "like magic": existing CLI
   pipelines work against the hub unchanged, and the hub never asks a
   human to do something the CLI already automates;
8. is **polished and self-contained**: every byte of every page —
   fonts, JS, CSS, WASM — is served from the page's own origin. No
   third-party font/script/style CDNs, no analytics beacons, ever.
   Open-source under the repository's license; English-only initially.

