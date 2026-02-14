# Implementation Phases

> Part of the [AOS Cache Design](README.md)

## Phase 1: Read-only cache server (`aos serve`)
- `aos serve` with axum — auto-create `AOS_ROOT` subdirectories on first run
- narinfo generation from SQLite + `nix_compat`
- NAR streaming via `nix store dump-path` + zstd
- Single view, no auth
- `GET /nix-cache-info`, `GET /{hash}.narinfo`, `GET /nar/...`
- Visibility: check GC root symlink existence before serving

## Phase 2: Multi-view + OAuth2 auth
- TOML config parsing (views, server settings)
- `/:view/` URL routing
- OAuth2 token endpoint (`POST /oauth2/token`)
- JWT access token validation middleware
- Unix socket bootstrap (`aos token create/list/revoke`)
- Anonymous read support per view
- Per-view GC root directories

## Phase 3: Build service + deduplication
- `PUT /:view/store/{hash}` — accept individual .drv / fixed-output paths
- `POST /:view/upload-pack` — pack upload for bundled .drv files
- `POST /:view/query-missing` — batch path existence check
- `POST /:view/build?drv=...` — trigger `nix-store --realise`
- `BuildManager` with deduplication (same drv → same build)
- Log tee: ring buffer + broadcast channel for multiple subscribers
- SSE log streaming with `Last-Event-ID` reconnection support
- GC root creation for output closures per view (with `is_root` tracking)
- Per-view build concurrency semaphore (`max_concurrent_builds`)

## Phase 4: Client remote build (`aos build --remote`)
- Extend `aos build` with `--remote`, `--view`, `--token` flags
- Capability negotiation from `nix-cache-info`
- Pack upload for .drv files, parallel PUT for large sources
- Resumable uploads via Content-Range
- SSE log display with progress indicators

## Phase 5: GC + TTL + Eviction
- Extend `aos gc` with `--remote`, `--view` flags
- TTL-based root expiry (Phase 1: remove expired symlinks)
- Size-bounded DAG-aware eviction (Phase 2: score push roots, evict greedily)
- Access tracking: update `last_accessed` / `access_count` on narinfo serve
- `--dry-run` with eviction plan output, `--pin` to protect roots
- systemd timer template

## Phase 6: Graceful restart + polish
- Drain mode (SIGTERM → stop new builds, wait for in-flight)
- Build state persistence to disk for crash recovery
- Daemon unavailability detection and SSE reporting
- Client reconnection with log replay after server restart
- systemd unit with `Type=notify`, `KillMode=mixed`
- NixOS module for deployment (including binfmt configuration)
- Logging, metrics (optional prometheus endpoint)

## Future (post-v1)
- `delta-drv` capability: delta-compressed .drv packs (git OFS_DELTA style)
- `negotiate-v2` capability: multi-round have/want for very large closures
- Frequency-weighted eviction scoring (`access_count` integration)
- Token rotation with grace periods
- Configurable eviction scoring functions per view
