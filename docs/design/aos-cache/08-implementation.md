# Rust Module Structure

> Part of the [AOS Cache Design](README.md)

```
src/
├── main.rs
├── cli.rs              (add Serve, Token variants; extend Build/Gc with --remote)
├── commands/
│   ├── mod.rs
│   ├── build.rs        (extended: local + remote build paths)
│   ├── gc.rs           (extended: local + remote GC paths)
│   ├── serve.rs        (HTTP server startup, AOS_ROOT subdirectory init)
│   ├── token.rs        (token create/list/revoke/rotate via Unix socket)
│   └── ... (existing)
├── server/
│   ├── mod.rs
│   ├── config.rs       (TOML config parsing)
│   ├── store.rs        (Nix store: path-info queries, dump, realise)
│   ├── build.rs        (BuildManager: dedup, log tee, SSE, subprocess)
│   ├── narinfo.rs      (narinfo serialization/parsing via nix_compat)
│   ├── views.rs        (view resolution, GC root management, visibility)
│   ├── auth.rs         (OAuth2 token endpoint, JWT validation middleware)
│   ├── sign.rs         (narinfo signing — delegates to daemon's key)
│   ├── compress.rs     (zstd/xz streaming compression)
│   ├── pack.rs         (pack upload format: parse, validate, import)
│   ├── evict.rs        (DAG-aware eviction: closure scoring, weighted LRU)
│   ├── access.rs       (per-view access tracking: last_accessed, count)
│   ├── drain.rs        (graceful shutdown: drain mode, build state persistence)
│   ├── bootstrap.rs    (Unix socket listener for token provisioning)
│   └── routes.rs       (axum route handlers: read + build + oauth2 endpoints)
├── client/
│   ├── mod.rs
│   ├── remote.rs       (HTTP client for remote builds: query-missing, upload, build)
│   ├── pack.rs         (client-side pack creation for .drv bundling)
│   └── sse.rs          (SSE client: log display, reconnection)
├── nix.rs              (existing NixRunner)
├── error.rs
└── output.rs
```

## Key Dependencies to Add

```toml
# Cargo.toml additions

# HTTP server
axum = "0.8"
axum-extra = { version = "0.10", features = ["typed-header"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["trace"] }
tokio-stream = "0.1"       # SSE build log streaming

# Async runtime (extend existing tokio features)
tokio = { version = "1", features = [
  "rt-multi-thread", "sync", "process", "io-util", "fs", "signal"
] }

# Nix format handling (from tvix — production-quality)
nix-compat = "0.1"          # narinfo parse/serialize, NAR format, nix-base32,
                             # ed25519 signing, store path parsing

# Store metadata (direct SQLite reads — fast path)
rusqlite = { version = "0.32", features = ["bundled"] }

# Compression
zstd = "0.13"               # streaming zstd compression
xz2 = "0.1"                 # xz support (compatibility)

# Configuration & time
toml = "0.8"                # TOML config parsing
humantime = "2"             # "7d", "24h" TTL parsing
humantime-serde = "1"       # serde integration for durations

# Token generation & auth
rand = "0.9"                # cryptographic random for tokens
jsonwebtoken = "9"          # JWT signing and verification (HMAC-SHA256)
uuid = { version = "1", features = ["v4", "serde"] }

# Unix socket bootstrap (SO_PEERCRED for local token provisioning)
nix = { version = "0.29", features = ["socket", "user"] }

# Already in Cargo.toml: sha2, base64, serde, serde_json, tokio, reqwest
```

**Note on `nix-compat`**: This is tvix's Nix compatibility crate. It provides:
- `narinfo::NarInfo` — parse and serialize narinfo files
- `narinfo::SigningKey` / `VerifyingKey` — ed25519 narinfo signing
- `nixhash` — NAR hash computation, nix-base32 encoding
- `store_path::StorePath` — store path parsing and validation
- `nar::writer` / `nar::reader` — NAR format handling

This avoids hand-rolling narinfo serialization and signing logic.
