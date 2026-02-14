# Architecture Overview

> **Note:** AOS compiles Nix with `/var/lib/aos` as its store root instead of
> the default `/nix`. The `/nix` directory does not exist on an AOS system. All
> Nix state — the store, the database, GC roots, and logs — lives under
> `/var/lib/aos/`.

## 1. Executive Summary

`aos serve` turns a local Nix daemon into an authenticated, multi-tenant
remote build server and binary cache. `aos build --remote` delegates builds
to it. The remote build functionality integrates directly into the existing
`aos` CLI — no separate subcommand group, just `--remote` flags on existing
commands.

### CLI Integration

```
aos serve [--config PATH]              Start the HTTP build server
aos build [pkg] --remote URL           Build remotely (same as local, but delegated)
aos gc --remote URL --view VIEW        Remote cache GC (extends existing gc)
aos token create --view ci             Provision tokens (local Unix socket)
```

### Why not attic?

Attic is architecturally over-engineered for single-node use:

| Attic                              | aos                                  |
|------------------------------------|--------------------------------------|
| Accepts pre-built NARs (untrusted) | **Builds locally via Nix daemon**    |
| PostgreSQL for metadata            | Filesystem + Nix's own SQLite DB     |
| S3 storage abstraction             | Serves directly from /var/lib/aos/store |
| Chunked NAR deduplication          | Nix store is already content-addressed|
| JWT token auth + OIDC              | OAuth2 + Unix socket bootstrap       |
| Distributed-first design           | Single-node, UNIX philosophy         |
| Separate data directory            | Zero duplication — uses Nix store    |
| 512MB+ RAM for basic operation     | Minimal memory — streams on demand   |

The server does **one thing well**: it turns a local Nix daemon into an
authenticated, multi-tenant build server. Clients send derivations, the
server builds them in a sandbox, the daemon signs the outputs, and the
results are served as a standard Nix binary cache. It uses the filesystem
for state, symlinks for GC roots, TOML for configuration, and the Nix
daemon for building and signing. No separate database. No object storage.
No pre-built binary imports.

---

## 2. Architecture Overview

```
                    ┌─────────────────────────────────────┐
                    │          aos serve             │
                    │         (axum HTTP server)           │
                    ├─────────────────────────────────────┤
                    │                                     │
   GET /:view/     │  ┌───────────┐    ┌──────────────┐  │
   {hash}.narinfo  │  │ Auth      │    │ View         │  │
   ─────────────►  │  │ Middleware │───►│ Resolution   │  │
                    │  │ (bearer)  │    │ (visibility) │  │
   GET /:view/     │  └───────────┘    └──────┬───────┘  │
   nar/{h}.nar.zst │                          │          │
   ─────────────►  │                          ▼          │
                    │  ┌──────────────────────────────┐   │
   PUT /:view/     │  │       Store Interface         │   │
   {hash}.drv      │  │                               │   │
   ─────────────►  │  │  SQLite read         (meta)   │   │
                    │  │  nix store dump-path (NAR)    │   │
   POST /:view/    │  │  nix-store --realise (build)  │   │
   build           │  │  nix_compat          (narinfo) │   │
   ─────────────►  │  │                               │   │
   ◄── SSE logs    │  │  Build → sign → GC root       │   │
                    │  └──────────────┬───────────────┘   │
                    │                 │                    │
                    └─────────────────┼────────────────────┘
                                      │
                    ┌─────────────────┼────────────────────┐
                    │  /var/lib/aos/                        │  ← AOS_ROOT
                    │  ├── store/                           │  (Nix store)
                    │  │   (store paths) ▼                  │
                    │  │                                    │
                    │  ├── var/nix/db/db.sqlite             │
                    │  │   (read-only; WAL allows concurrent│
                    │  │    reads while nix daemon writes)  │
                    │  │                                    │
                    │  ├── var/nix/gcroots/                 │  (Nix GC roots)
                    │  │   └── aos -> /var/lib/aos/gcroots  │
                    │  │                                    │
                    │  ├── gcroots/                         │  (AOS per-view GC roots)
                    │  │   ├── ci/                          │
                    │  │   │   ├── bin/{hash} -> …/store/…  │  (build outputs)
                    │  │   │   └── src/{hash} -> …/store/…  │  (source tarballs)
                    │  │   └── prod/                        │
                    │  │       ├── bin/{hash} -> …/store/…  │
                    │  │       └── src/{hash} -> …/store/…  │
                    │  │                                    │
                    │  ├── meta/                            │
                    │  │   ├── ci/bin/{hash}.json           │  (binary metadata)
                    │  │   ├── ci/src/{hash}.json           │  (source metadata)
                    │  │   └── tokens.db                   │
                    │  │                                    │
                    │  └── views/                           │
                    │      └── ci/                          │
                    │          └── builds/                  │
                    │                                       │
                    └───────────────────────────────────────┘
```

### Key Insight: Build, Don't Import

Unlike attic (which accepts pre-built NARs from clients), `aos serve` only
produces outputs via the local **Nix daemon**. The daemon builds derivations
in a sandbox, verifies output hashes, and signs the results. This means
every store path in the cache is **provably correct** — it was built from
its derivation on this machine, not uploaded as an opaque binary.

The Nix store already content-addresses every path. On a single node, we
serve directly from `/var/lib/aos/store` by spawning `nix store dump-path` to
produce NAR streams on demand. The Nix daemon's own SQLite database tracks
all metadata. We query it directly and format narinfo responses using tvix's
`nix_compat` crate. Zero data duplication.

### Store Interface Strategy (Hybrid)

The research team evaluated four approaches to interfacing with the Nix store:

| Approach | Pros | Cons | Use for |
|----------|------|------|---------|
| Direct SQLite reads | Fastest, batchable, no process spawn | Unsupported API, schema may change | **Metadata queries** |
| `nix path-info --json` | Stable CLI interface | Process spawn per query | Fallback for metadata |
| `nix store dump-path` | Streaming, no temp files | Process per NAR | **NAR serving** |
| `nix-store --import` | Standard import path | Process per upload | **Path imports** |

**Recommendation**: Open `/var/lib/aos/var/nix/db/db.sqlite` **read-only** in WAL mode
for metadata queries (fast, batchable). This avoids spawning a process per narinfo
request. Use `nix store dump-path` for NAR streaming and `nix-store --import` for
uploads. Use tvix's `nix_compat` crate for narinfo serialization and ed25519 signing.

### SQLite Contention Model

Since `aos serve` is a **single-process, multi-threaded** server (tokio + axum),
there is no multi-process contention on the Nix SQLite database:

- We open one read-only connection (or a small `r2d2` pool) for metadata queries
- WAL mode allows our reads to proceed concurrently with the Nix daemon's writes
- We **never write** to the Nix DB — only the Nix daemon does
- All our mutable state (GC roots, metadata JSON, token DB) is separate

This is fundamentally different from attic's PostgreSQL model, where multiple
worker processes compete for database connections. Our in-process threading
means a single `rusqlite::Connection` behind a `tokio::sync::Mutex` handles
all narinfo queries with zero contention overhead.

### Nix DB Schema (for SQLite reads)

```sql
-- ValidPaths: one row per registered store path
CREATE TABLE ValidPaths (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  path             TEXT UNIQUE NOT NULL,  -- /var/lib/aos/store/{hash}-{name}
  hash             TEXT NOT NULL,         -- sha256:{hex} (NAR hash)
  registrationTime INTEGER NOT NULL,      -- unix timestamp
  deriver          TEXT,                  -- /var/lib/aos/store/{hash}-{name}.drv
  narSize          INTEGER,              -- NAR size in bytes
  ultimate         INTEGER,              -- 1=built locally, 0=substituted
  sigs             TEXT,                  -- space-separated signatures
  ca               TEXT                   -- content-address (if applicable)
);

-- Refs: runtime dependency edges
CREATE TABLE Refs (
  referrer  INTEGER NOT NULL,  -- FK → ValidPaths.id
  reference INTEGER NOT NULL,  -- FK → ValidPaths.id
  PRIMARY KEY (referrer, reference)
);
```

Narinfo generation from a single query:
```sql
SELECT vp.path, vp.hash, vp.narSize, vp.deriver, vp.sigs, vp.ca,
       GROUP_CONCAT(ref_vp.path, ' ') AS references
FROM ValidPaths vp
LEFT JOIN Refs r ON r.referrer = vp.id
LEFT JOIN ValidPaths ref_vp ON ref_vp.id = r.reference
```
