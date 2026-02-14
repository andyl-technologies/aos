# AOS Remote Build & Binary Cache

`aos serve` turns a local Nix daemon into an authenticated, multi-tenant remote
build server and binary cache. Clients send derivation closures over HTTP, the
server builds them in a sandbox via the Nix daemon, and the signed outputs are
served as a standard Nix binary cache. There is no separate database, no object
storage, and no pre-built binary imports -- everything in the cache was built
locally from source by the daemon.

## AOS root layout

Nix is compiled with a custom store directory (`/var/lib/aos/store`) so that no
`/nix` prefix exists on the system. The `aos` binary has the AOS state root
baked in at compile time as `AOS_ROOT`.

```
/var/lib/aos/                          AOS_ROOT (compile-time constant)
├── store/                             Nix store (custom --store-dir)
├── var/nix/                           Nix state (custom --state-dir)
│   ├── db/db.sqlite                   Nix metadata (read-only by aos serve)
│   ├── gcroots/                       Nix GC roots
│   │   └── aos -> /var/lib/aos/gcroots  Indirect GC root into AOS tree
│   └── log/nix/drvs/                  Build logs persisted by the daemon
├── gcroots/                           AOS per-view GC root symlinks
│   ├── ci/
│   │   ├── bin/{hash} -> /var/lib/aos/store/{hash}-{name}
│   │   └── src/{hash} -> /var/lib/aos/store/{hash}-{name}.tar.xz
│   └── prod/
│       ├── bin/{hash} -> /var/lib/aos/store/{hash}-{name}
│       └── src/{hash} -> /var/lib/aos/store/{hash}-{name}.tar.xz
├── meta/                              Sidecar metadata
│   ├── ci/bin/{hash}.json             Per-path TTL / access tracking (binaries)
│   ├── ci/src/{hash}.json             Per-path TTL / access tracking (sources)
│   └── tokens.db                      Provisioning token database (SQLite)
└── views/                             Per-view runtime state
    └── ci/builds/{drv-hash}.json      In-flight build state for crash recovery
```

## Table of contents

| # | Section | Description |
|---|---------|-------------|
| 01 | [Architecture](01-architecture.md) | Executive summary, architecture diagram, store interface strategy |
| 02 | [Data model](02-data-model.md) | Views, GC roots, path metadata, visibility model, access tracking |
| 03 | [HTTP API](03-http-api.md) | Cache info, narinfo, NAR streaming, remote builds, SSE logs, pack uploads |
| 04 | [Authentication](04-authentication.md) | Two-layer token model, OAuth2, Unix socket bootstrap, token lifecycle |
| 05 | [Garbage collection](05-garbage-collection.md) | GC root lifecycle, TTL expiry, DAG-aware weighted closure eviction |
| 06 | [Configuration](06-configuration.md) | `AOS_ROOT` compile-time config, server TOML, view bounds |
| 07 | [CLI integration](07-cli.md) | `aos serve`, `aos build --remote`, `aos token`, Rust types |
| 08 | [Implementation](08-implementation.md) | Rust module structure, Cargo dependencies, `nix_compat` usage |
| 09 | [Workflows](09-workflows.md) | End-to-end build and read workflows, trust model |
| 10 | [Comparison](10-comparison.md) | vs attic, vs ssh-ng://, what we explicitly do not do |
| 11 | [Deployment](11-deployment.md) | Minimal and production setup, systemd unit, client substituter config |
| 12 | [Recovery](12-recovery.md) | Graceful restart, drain mode, crash recovery, daemon unavailability |
| 13 | [Phases](13-phases.md) | Implementation phases (1-6), future work |
| 14 | [Permissions](14-permissions.md) | Directory ownership, user/group model, filesystem security |
| 15 | [Security notes](15-security-notes.md) | Operational security considerations |

## Key design decisions

- **Build-only model.** The server never accepts pre-built binaries. Every
  store path is produced by `nix-store --realise` in a sandbox, hash-verified,
  and signed by the local daemon. This eliminates the class of supply-chain
  attacks where a compromised client pushes tampered outputs.

- **Custom store directory.** Nix is compiled with `--store-dir=/var/lib/aos/store`
  so the entire system lives under `/var/lib/aos`. There is no `/nix` on disk.
  `AOS_ROOT` is a compile-time constant (`env!("AOS_ROOT")` in Rust) baked
  into the `aos` binary by the Nix build harness, analogous to how Nix itself
  compiles in its store path.

- **Artifact namespaces.** Each view organises GC roots and metadata into
  namespaces: `bin/` for build outputs (runtime closures) and `src/` for
  source tarballs (fixed-output `fetchurl` inputs). Namespaces have independent
  TTLs, enabling long-lived source mirrors alongside shorter-lived binary
  caches -- analogous to Debian's `deb` / `deb-src` split. Additional
  namespaces (e.g. LLM chat logs) can be added later without schema changes.

- **Filesystem as the database.** GC root symlinks in `gcroots/{view}/{ns}/`
  serve double duty as both the visibility index (symlink exists = view can
  serve the path) and liveness markers (Nix GC follows the symlinks). Per-path
  metadata is a JSON sidecar file. The only SQLite the server touches is Nix's
  own `db.sqlite`, opened read-only in WAL mode for narinfo queries.

- **HTTP instead of SSH.** The same three daemon operations (`IsValidPath`,
  `AddToStore`, `BuildPaths`) are implemented over HTTP with parallel uploads,
  resumable transfers, structured SSE log streaming, and build deduplication --
  properties that SSH's single serial pipe cannot provide.

- **Zero data duplication.** NARs are streamed on demand from the Nix store via
  `nix store dump-path`. Metadata is queried from the daemon's SQLite. There is
  no secondary copy of store data, no PostgreSQL, and no S3 abstraction layer.
